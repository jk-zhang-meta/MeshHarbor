// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Userspace WireGuard device (boringtun) bridged to a pluggable
//! carrier.
//!
//! boringtun's [`Tunn`] is a pure packet transform — it owns neither a
//! socket nor a TUN. This module wires one `Tunn` per peer to a
//! [`Carrier`] (a direct UDP socket, or a coturn TURN allocation — the
//! DERP-equivalent), so the same WG ciphertext rides whichever path the
//! NAT-traversal tier selected, unchanged. Decrypted inbound IP packets
//! are delivered on an mpsc channel that the TUN bridge (Phase 3) — or
//! the Phase-2 tests — drains.
//!
//! Per-peer wiring:
//! * a **recv task** loops `carrier.recv()` → `Tunn::decapsulate` →
//!   either echoes handshake/cookie bytes back over the carrier or
//!   pushes a decrypted IP packet to `tun_tx`;
//! * a **timer task** ticks `Tunn::update_timers` (handshake retries +
//!   keepalives);
//! * `send_to_peer` / `send_ip_packet` `Tunn::encapsulate` an outbound
//!   IP packet and write the ciphertext over the carrier.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use bson::oid::ObjectId;
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::disco::derp_follow as follow;
use super::ingress::{dst_ip_of, parse_l4, rules_permit};
use super::router::{LocalScope, Router, RpfMode, RpfVerdict};
use crate::transport::quic::QuicPeer;
use crate::transport::relay::{RelayConn, RelayUdpSocket};
use roomler_ai_remote_control::models::OverlayRule;

/// Scratch buffer size for encap/decap + carrier I/O. The overlay MTU is
/// 1280; a WG datagram adds ~32 B of overhead, so 2048 is comfortable
/// headroom and equals the relay's `MAX_DATAGRAM` cap (no fragmentation
/// at this size).
pub(crate) const WG_BUF: usize = 2048;

/// WireGuard persistent-keepalive interval. Keeps a relayed/NAT mapping
/// warm so a mostly-idle overlay link stays reachable.
const KEEPALIVE_SECS: u16 = 25;

/// How often the timer task drives `update_timers` (handshake retries +
/// keepalive scheduling). WG's own timers are second-granular; 250 ms
/// keeps handshake setup snappy without busy-looping.
const TIMER_TICK_MS: u64 = 250;

/// Bytes a WG data message adds over the inner IP packet (16 B header +
/// 16 B Poly1305 tag). The QUIC datagram carrier's budget must fit
/// `overlay_mtu + WG_OVERHEAD`.
pub const WG_OVERHEAD: usize = 32;

/// How long to wait for the QUIC-over-TURN handshake before falling back to
/// the raw relay carrier. This is the rendezvous window: the QUIC server's
/// `accept()` and the client's `connect()` must overlap, but the two ends
/// install peers at slightly different times (sequential per-peer install +
/// staggered restarts), so a too-short window makes one side time out → raw
/// while the other lands on QUIC (a silent split). 8 s tolerates that skew;
/// residual skew self-heals via the health sweep (both sides see rx flat on a
/// split and re-request). Bounded so a dead relay still falls back promptly.
pub const QUIC_BUILD_TIMEOUT: Duration = Duration::from_secs(8);

/// W6 phase 3 — the BACKGROUND rendezvous window for the raw-first QUIC
/// upgrade. Long enough that two unsynchronized ~60 s retry clocks MUST
/// overlap: the server side holds one continuous `accept()` for the whole
/// window while the client side retries `connect()` attempts inside it.
/// The pair is never dark during this — its raw carrier committed first.
pub const QUIC_UPGRADE_DEADLINE: Duration = Duration::from_secs(90);

/// Gap between client-side connect attempts inside
/// [`QUIC_UPGRADE_DEADLINE`] (each attempt itself runs up to
/// [`QUIC_BUILD_TIMEOUT`], so the cycle is ~12 s).
pub const QUIC_UPGRADE_RETRY_GAP: Duration = Duration::from_secs(4);

/// Opt-in gate for the QUIC-over-TURN carrier (`ROOMLERD_OVERLAY_QUIC`;
/// the older `ROOMLER_NODE_OVERLAY_QUIC` still honoured — see
/// [`crate::env::node_env`]). **Default OFF** — the raw relay is the proven
/// path; QUIC is enabled per-host only after field-proving (mirrors the
/// direct-path arc). Truthy = `1`/`true`/`yes`/`on` (case-insensitive);
/// anything else (incl. unset) is off.
pub fn overlay_quic_enabled() -> bool {
    match crate::env::node_env("OVERLAY_QUIC") {
        Some(v) => {
            let t = v.trim();
            t.eq_ignore_ascii_case("1")
                || t.eq_ignore_ascii_case("true")
                || t.eq_ignore_ascii_case("yes")
                || t.eq_ignore_ascii_case("on")
        }
        None => false,
    }
}

/// W6 phase-2 — open the coturn permission toward `dst` and SAY what
/// happened. The turn client's `send_to` blocks on CreatePermission (with
/// retries), so this 1-byte stray's latency IS the permission round trip,
/// and its error means coturn drops EVERY inbound from that peer until a
/// later send re-asserts. This was `let _ = conn.send_to(…)` at three
/// sites — three silent drops (field 2026-08-15: every QUIC rendezvous on
/// winhost-a timed out with rx=0 on BOTH sides and nothing said why).
/// Returns (elapsed_ms, ok) so callers can fold it into their own logs.
pub(crate) async fn assert_relay_permission(
    conn: &Arc<dyn RelayConn>,
    dst: SocketAddr,
    context: &'static str,
) -> (u64, bool) {
    let t0 = std::time::Instant::now();
    let res = conn.send_to(b"\x00", dst).await;
    let ms = t0.elapsed().as_millis() as u64;
    match &res {
        Ok(_) if ms >= 500 => {
            info!(%dst, ms, context, "overlay relay: permission bootstrap SLOW");
        }
        Ok(_) => {
            debug!(%dst, ms, context, "overlay relay: permission bootstrap ok");
        }
        Err(e) => {
            warn!(%dst, ms, %e, context,
                  "overlay relay: permission bootstrap FAILED — coturn drops this \
                   peer's inbound until a later send re-asserts");
        }
    }
    (ms, res.is_ok())
}

/// How a peer's WG datagrams reach it. Both arms are "send bytes to a
/// dst / recv bytes"; boringtun output rides either unchanged.
pub enum Carrier {
    /// Tier 1: direct UDP to the peer's (possibly hole-punched) endpoint.
    Direct {
        sock: Arc<UdpSocket>,
        /// A3 (WG-style roaming) — interior-mutable so an AUTHENTICATED
        /// inbound from a new source can repoint our outbound in place
        /// ([`Carrier::set_direct_dst`]): every holder of this `Arc` (the
        /// send pump's `SendPeer` mirror, the timer task) follows instantly,
        /// with no channel round-trip through the runtime. Uncontended
        /// `RwLock` read per send — noise next to the syscall.
        dst: std::sync::RwLock<SocketAddr>,
        /// Latched when `send` reports that the LOCAL end is gone — the bound
        /// source address vanished, or its interface lost its route. See the
        /// errno filter in [`Carrier::send`]: an ordinary dropped datagram
        /// must never set this.
        dead: AtomicBool,
    },
    /// Tier 2/3: through a coturn TURN allocation (`RelayConn`), dialing
    /// the peer's relayed address. The DERP-equivalent carrier.
    Relay {
        conn: Arc<dyn RelayConn>,
        dst: SocketAddr,
        /// rc.181 — latched when `send` hard-errors (a TURNS/TCP reset: the
        /// `tcp-turn write: connection reset` the next send returns after a
        /// corp middlebox reaps the idle control TCP). The runtime's health
        /// sweep reads it via [`WgDevice::peer_carrier_dead`] and re-allocates
        /// on the next tick, instead of waiting out the ~20 s rx-flat heuristic.
        dead: AtomicBool,
    },
    /// Tier 2/3 + QUIC (opt-in): WG datagrams ride an unreliable QUIC
    /// datagram stream over a coturn allocation. QUIC's congestion control
    /// smooths the relay's buffer-bloat latency spikes and its keepalive holds
    /// the TURN permission fresh — the carrier stays healthier on a hostile
    /// (corp-VPN) relay path than raw fire-and-forget. `_peer` owns the QUIC
    /// endpoint (→ `RelayUdpSocket` → `RelayConn` → TURN allocation); it is
    /// held only to keep that stack alive for the connection's lifetime.
    QuicRelay {
        _peer: QuicPeer,
        conn: quinn::Connection,
        /// rc.181 — latched when `send_datagram` reports `ConnectionLost` (the
        /// QUIC-over-TURN carrier died). Same fast re-allocate signal as
        /// [`Carrier::Relay`]'s `dead`.
        dead: AtomicBool,
    },
}

impl Carrier {
    /// Logical end-to-end path key for authenticated disco correlation. For a
    /// relay this is the peer destination (possibly synthetic), NOT the relay
    /// server's address; the receiver verifies the expected peer's MAC.
    fn disco_endpoint(&self) -> SocketAddr {
        match self {
            Self::Direct { dst, .. } => *dst.read().unwrap_or_else(|e| e.into_inner()),
            Self::Relay { dst, .. } => *dst,
            Self::QuicRelay { conn, .. } => conn.remote_address(),
        }
    }

    /// Diagnostic probes must never set the carrier's data-plane dead latch.
    /// A refusal/lost reply is a sample, not authority to evict a live path.
    async fn send_disco(&self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Direct { sock, dst, .. } => {
                let dst = *dst.read().unwrap_or_else(|e| e.into_inner());
                sock.send_to(bytes, dst).await
            }
            Self::Relay { conn, dst, .. } => conn.send_to(bytes, *dst).await,
            Self::QuicRelay { conn, .. } => conn
                .send_datagram(Bytes::copy_from_slice(bytes))
                .map(|_| bytes.len())
                .map_err(io::Error::other),
        }
    }

    pub fn direct(sock: Arc<UdpSocket>, dst: SocketAddr) -> Arc<Self> {
        Arc::new(Carrier::Direct {
            sock,
            dst: std::sync::RwLock::new(dst),
            dead: AtomicBool::new(false),
        })
    }

    /// How this carrier's relay leg is reached, `None` when it is direct.
    ///
    /// `(transport, server)` — e.g. `(Udp, Some("5.9.157.221:3478"))`. The
    /// relay KIND (turn/derp) is an overlay decision already carried by
    /// `Installed::relay_kind`; this adds the transport-layer half so
    /// `roomler peers` can print `relay:turn/udp` rather than a bare `relay`
    /// — a 52 ms coturn/UDP hop and a 175 ms DERP/TCP hop used to look
    /// identical, as did a healthy PoP and a dead one (2026-08-12: a coturn
    /// worker was down 90 min while this column said nothing).
    pub fn relay_transport_info(
        &self,
    ) -> Option<(crate::transport::relay::RelayTransport, Option<String>)> {
        match self {
            Carrier::Relay { conn, .. } => Some((conn.relay_transport(), conn.relay_server())),
            // QUIC rides a coturn allocation; the QUIC framing is the payload,
            // the relay underneath is still TURN-over-UDP.
            Carrier::QuicRelay { .. } => Some((crate::transport::relay::RelayTransport::Udp, None)),
            Carrier::Direct { .. } => None,
        }
    }

    /// A3 — the current direct dst, `None` for relay/QUIC carriers.
    pub fn direct_dst(&self) -> Option<SocketAddr> {
        match self {
            Carrier::Direct { dst, .. } => Some(*dst.read().unwrap_or_else(|e| e.into_inner())),
            _ => None,
        }
    }

    /// A3 (WG-style roaming) — repoint a direct carrier's dst in place.
    /// Returns the previous dst; no-op `None` on non-direct carriers. Callers
    /// gate on CRYPTOGRAPHIC evidence (an inbound that decapsulated without
    /// error against this peer's session) — never on packet shape alone.
    pub fn set_direct_dst(&self, new: SocketAddr) -> Option<SocketAddr> {
        match self {
            Carrier::Direct { dst, .. } => {
                let mut d = dst.write().unwrap_or_else(|e| e.into_inner());
                Some(std::mem::replace(&mut *d, new))
            }
            _ => None,
        }
    }

    pub fn relay(conn: Arc<dyn RelayConn>, dst: SocketAddr) -> Arc<Self> {
        Arc::new(Carrier::Relay {
            conn,
            dst,
            dead: AtomicBool::new(false),
        })
    }

    /// Build a QUIC-over-TURN carrier over an existing TURN allocation `conn`,
    /// with the peer's relayed `dst`. `am_server` (deterministic — the
    /// lexicographically-smaller pubkey serves) picks the QUIC role; the client
    /// accepts any cert because WireGuard authenticates end-to-end INSIDE the
    /// datagrams. Returns `Err` (→ the caller falls back to the raw
    /// `Carrier::relay`) on a handshake timeout, or if the negotiated datagram
    /// budget can't hold a WG packet (`min_datagram`). Both ends install the
    /// coturn permission (stray `\x00`) before the bidirectional handshake.
    pub async fn quic_relay(
        conn: Arc<dyn RelayConn>,
        dst: SocketAddr,
        am_server: bool,
        min_datagram: usize,
        timeout: Duration,
    ) -> anyhow::Result<Arc<Self>> {
        use anyhow::{Context as _, bail};

        let (perm_ms, perm_ok) = assert_relay_permission(&conn, dst, "quic-build").await;
        let perm = if perm_ok {
            format!("perm={perm_ms}ms")
        } else {
            format!("perm=FAILED@{perm_ms}ms")
        };
        let sock = Arc::new(RelayUdpSocket::new(conn)?);
        // W6 — rendezvous instrumentation. Field 2026-08-14 (winhost-a): EVERY
        // relay build logged "accept timed out → raw relay", but the log
        // could not say WHY — dialer never dialed (rendezvous miss), dialer's
        // packets dropped at coturn (permission-IP mismatch), or handshake
        // broke mid-flight. The rx counters + the permission dst in the
        // failure text discriminate those; widen/retry decisions (W6 phase 2)
        // are made from this data, not blind.
        let rx_stats = sock.rx_stats();

        let (peer, quic) = if am_server {
            let peer = QuicPeer::server_over_relay_datagram(sock)?;
            let quic = tokio::time::timeout(timeout, peer.accept())
                .await
                .with_context(|| {
                    format!(
                        "QUIC-over-TURN server accept timed out ({}s window, permission_dst={dst}, {perm}, {})",
                        timeout.as_secs(),
                        rx_stats.describe()
                    )
                })?
                .with_context(|| {
                    format!(
                        "QUIC-over-TURN server: no incoming connection (permission_dst={dst}, {perm}, {})",
                        rx_stats.describe()
                    )
                })?
                .context("QUIC-over-TURN server handshake failed")?;
            // The dialer's source as coturn observed it vs what it advertised.
            // The permission is IP-scoped, so a different IP could never get
            // this far; a different PORT is the dialer's NAT allocating
            // per-destination mappings — symmetric-NAT evidence worth keeping
            // visible while the rendezvous field data accumulates.
            let observed = quic.remote_address();
            if observed == dst {
                debug!(%observed, "QUIC-over-TURN server: dialer arrived from its advertised srflx");
            } else {
                info!(%observed, advertised = %dst,
                      "QUIC-over-TURN server: dialer's observed source differs from its \
                       advertised srflx (per-destination NAT mapping)");
            }
            (peer, quic)
        } else {
            let peer = QuicPeer::client_over_relay_datagram(sock)?;
            let quic = tokio::time::timeout(timeout, peer.connect(dst))
                .await
                .with_context(|| {
                    format!(
                        "QUIC-over-TURN client connect timed out ({}s window, dst={dst}, {perm}, {})",
                        timeout.as_secs(),
                        rx_stats.describe()
                    )
                })?
                .with_context(|| {
                    format!(
                        "QUIC-over-TURN client handshake failed (dst={dst}, {perm}, {})",
                        rx_stats.describe()
                    )
                })?;
            (peer, quic)
        };

        let budget = quic.max_datagram_size().unwrap_or(0);
        if budget < min_datagram {
            bail!(
                "QUIC datagram budget {budget} < WG packet {min_datagram}; falling back to raw relay"
            );
        }
        Ok(Arc::new(Carrier::QuicRelay {
            _peer: peer,
            conn: quic,
            dead: AtomicBool::new(false),
        }))
    }

    /// The socket and current destination of a direct carrier — what a GSO
    /// batch send needs; `None` for relay carriers.
    fn direct_parts(&self) -> Option<(&Arc<UdpSocket>, SocketAddr)> {
        match self {
            Carrier::Direct { sock, dst, .. } => {
                Some((sock, *dst.read().unwrap_or_else(|e| e.into_inner())))
            }
            _ => None,
        }
    }

    /// A direct UDP carrier (vs a coturn relay). The runtime uses this to
    /// decide handshake direction: a direct carrier needs BOTH ends to
    /// initiate (bilateral hole-punch — see `install_ready`).
    pub fn is_direct(&self) -> bool {
        matches!(self, Carrier::Direct { .. })
    }

    /// rc.181 — a carrier whose `send` hard-errored (a TURNS/TCP reset, a lost
    /// QUIC-over-TURN connection, or — since the uplink work — a direct socket
    /// whose interface went away). The runtime's health sweep treats this as an
    /// immediate carrier death and rebuilds on the next tick, without waiting
    /// out the rx-staleness bound.
    pub fn is_dead(&self) -> bool {
        match self {
            Carrier::Direct { dead, .. }
            | Carrier::Relay { dead, .. }
            | Carrier::QuicRelay { dead, .. } => dead.load(Ordering::Relaxed),
        }
    }

    /// Latch dead from OUTSIDE the send path.
    ///
    /// For evidence that the session is over which does not arrive as a send
    /// error — specifically boringtun's `ConnectionExpired`, which the timer
    /// task sees when a rekey attempt finally gives up. That verdict is
    /// conclusive and was previously discarded, leaving the carrier to be
    /// rediscovered by the rx-staleness bound.
    pub fn mark_dead(&self) {
        match self {
            Carrier::Direct { dead, .. }
            | Carrier::Relay { dead, .. }
            | Carrier::QuicRelay { dead, .. } => dead.store(true, Ordering::Relaxed),
        }
    }

    async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match self {
            // A direct send failing is USUALLY just a dropped datagram (ICMP
            // port-unreachable surfacing as WSAECONNRESET, an MTU refusal) and
            // says nothing about the session — which is why this arm latched
            // nothing for years. But two errno classes are not about the
            // datagram at all, they are the LOCAL end reporting it no longer
            // exists:
            //
            //   AddrNotAvailable — the source address we bound is gone (the
            //     adapter was removed or renumbered);
            //   NetworkUnreachable — the pinned interface has no route.
            //
            // Both mean every subsequent send on this socket fails too, so
            // waiting out the rx-staleness bound is pure dead time. Latching
            // here turns "my dock/Wi-Fi/VPN adapter changed" into a sub-second
            // carrier death instead of a 60 s one. Deliberately NOT a catch-all
            // `is_err()`: that would kill a healthy carrier on the first
            // ICMP-induced error, which is exactly the trap the old
            // always-false behaviour was avoiding.
            Carrier::Direct { sock, dst, dead } => {
                let d = *dst.read().unwrap_or_else(|e| e.into_inner());
                let r = sock.send_to(buf, d).await;
                if let Err(e) = &r
                    && matches!(
                        e.kind(),
                        io::ErrorKind::AddrNotAvailable | io::ErrorKind::NetworkUnreachable
                    )
                {
                    dead.store(true, Ordering::Relaxed);
                }
                r
            }
            // A TURNS/TCP write error (`tcp-turn write: connection reset`) or a
            // dead UDP relay means the allocation is gone — latch `dead` so the
            // health sweep re-allocates promptly (next ≤5 s tick) instead of
            // waiting out the ~20 s rx-flat heuristic.
            Carrier::Relay { conn, dst, dead } => {
                let r = conn.send_to(buf, *dst).await;
                if r.is_err() {
                    dead.store(true, Ordering::Relaxed);
                }
                r
            }
            // send_datagram queues on the connection (quinn's driver flushes it
            // over the RelayUdpSocket). `ConnectionLost` = the carrier died →
            // latch `dead`; `TooLarge`/`Disabled`/`UnsupportedByPeer` are a
            // healthy conn refusing THIS datagram, so the WG layer just treats
            // them like any dropped datagram.
            Carrier::QuicRelay { conn, dead, .. } => {
                match conn.send_datagram(Bytes::copy_from_slice(buf)) {
                    Ok(()) => Ok(buf.len()),
                    Err(e) => {
                        if matches!(e, quinn::SendDatagramError::ConnectionLost(_)) {
                            dead.store(true, Ordering::Relaxed);
                        }
                        Err(io::Error::other(e))
                    }
                }
            }
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Carrier::Direct { sock, .. } => Ok(sock.recv_from(buf).await?.0),
            Carrier::Relay { conn, .. } => Ok(conn.recv_from(buf).await?.0),
            // A dead QUIC connection errors here → the recv task exits → the
            // runtime's health sweep sees rx go flat and rebuilds the carrier.
            Carrier::QuicRelay { conn, .. } => {
                let d = conn.read_datagram().await.map_err(io::Error::other)?;
                let n = d.len().min(buf.len());
                buf[..n].copy_from_slice(&d[..n]);
                Ok(n)
            }
        }
    }
}

/// rc.137 — lock-free per-peer traffic counters. `tx` = IP packets we
/// encapsulated + sent; `rx` = inbound IP packets we decapsulated to the TUN.
/// The runtime's direct→relay fallback reads these WITHOUT locking the `Tunn`
/// (locking it on a timer inside the packet loop is what added a ~660 ms
/// latency spike every sweep in rc.136), and uses "tx climbing while rx is
/// flat" as a fast, lock-free "this carrier is one-way / dead" signal.
/// F2 — one peer's standby tee: while armed, every WG data datagram the peer's
/// carrier sends is ALSO sent as a STANDBY copy over the node's DERP mux, so
/// the stream rides out a suspected direct carrier. Lock-free while disarmed.
#[derive(Default)]
pub(crate) struct StandbyTee {
    armed: AtomicBool,
    /// A standby sink is attached for this peer instance.
    sink: AtomicBool,
    to: std::sync::Mutex<Option<(Arc<crate::transport::derp::DerpMux>, [u8; 32])>>,
}

impl StandbyTee {
    fn set(&self, to: Option<(Arc<crate::transport::derp::DerpMux>, [u8; 32])>) {
        let mut slot = self.to.lock().unwrap_or_else(|e| e.into_inner());
        self.armed.store(to.is_some(), Ordering::Relaxed);
        *slot = to;
    }

    fn armed(&self) -> bool {
        self.armed.load(Ordering::Relaxed)
    }

    /// Copy `datagram` when armed and it is WG data (type 4); a handshake or a
    /// cookie stays on its own carrier.
    fn copy(&self, datagram: &[u8]) {
        if !self.armed() || datagram.first() != Some(&4) {
            return;
        }
        if let Some((mux, pk)) = self.to.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            mux.send_standby(pk, datagram);
        }
    }
}

#[derive(Default)]
pub struct PeerStats {
    /// F2 — see [`StandbyTee`].
    standby: StandbyTee,
    // Carrier role is set by the runtime on this exact owner, never inherited
    // by a replacement Peer. The send mirror additionally fences Tunn/carrier.
    derp_role: AtomicBool,
    recovery_hold: Arc<AtomicU64>,
    org_role: AtomicBool,
    sent_inits: std::sync::Mutex<std::collections::VecDeque<[u8; 32]>>,
    follow_init: std::sync::Mutex<Option<([u8; 32], Instant)>>,
    follow_ack: std::sync::Mutex<Option<follow::Frame>>,
    follow_proof: std::sync::Mutex<Option<follow::Frame>>,
    follow_reply_at: AtomicU64,
    tx: AtomicU64,
    /// Encapsulated business sends submitted to the carrier, including errors.
    /// Only SendPeer::send advances this; handshake/keepalive timer sends do not.
    tx_attempted: AtomicU64,
    rx: AtomicU64,
    /// rc.206 — count of authenticated inbound packets from this peer since the
    /// health sweep last drained it (`peer_take_rx_any`): data, a handshake step,
    /// OR a content-free persistent-keepalive. A keepalive decapsulates to
    /// `TunnResult::Done` and never touches `rx`, so this — not `rx` — is the
    /// LIVENESS signal the sweep drives `last_rx_at` off. A mostly-idle-but-alive
    /// carrier's only inbound is keepalives; keying "last heard" on the IP-data
    /// `rx` would freeze it and the rx-staleness watchdog would reap a healthy
    /// link. Single-consumer: only the sweep reads (and zeroes) it.
    rx_any: AtomicU64,
    /// #22 — authenticated handshake INITIATIONS received from this peer
    /// since the sweep last drained it (`peer_take_reinits`). A healthy peer
    /// initiates a rekey about every 2 minutes; a peer that cannot hear our
    /// responses retries its initiation every ~5 s (boringtun's rekey
    /// timeout), so a BURST of these against an established session is
    /// one-way evidence: our inbound works, our outbound does not — the
    /// exact signature the 08-18 zombie-leg wedge broadcast unheard for 30
    /// minutes (a rebirthing DERP floor re-initiating every ~70 s). The
    /// sweep turns sustained pressure into an immediate revalidation poke.
    reinit_seen: AtomicU64,
    /// Phase C — latched `true` the moment a WG handshake to this peer
    /// completes (a session exists), for EITHER role (the responder establishes
    /// on receiving the init, the initiator on receiving the response). The
    /// srflx / public-direct health deadline reads this LOCK-FREE to tell a live
    /// punch from a pre-handshake zombie — whose `tx`/`rx` counters stay flat
    /// (handshake packets touch neither), so the rx-flat heuristic can't see it
    /// and boringtun stops even keepalives once the attempt expires at ~90 s.
    handshake: AtomicBool,
    /// P3 PR-B — mono-ms (against [`wg_epoch`]) when `handshake` first
    /// latched; 0 = not yet (stamps are `max(1)`-floored so 0 stays the unset
    /// sentinel). Stamped in `process_inbound` — the RECV path, the instant
    /// the session appears — so the PathMonitor's probe-latch quality credit
    /// gets a REAL latency; the health sweep only observes the latch at its
    /// 5 s tick, and that quantization would be worse than no number at all
    /// (why PR-A passed `None`).
    handshake_at: AtomicU64,
    /// Stage 2 — mono-ms (against [`wg_epoch`]) when we last processed a valid
    /// handshake RESPONSE from this peer, i.e. when a handshake WE INITIATED
    /// last completed; 0 = never (stamps are `max(1)`-floored). Unlike the
    /// set-once [`handshake`](Self::handshake) latch this ADVANCES on every
    /// initiator-role completion — it is the active-revalidation poke's
    /// answer signal. Initiator-role only, deliberately: a responder-role
    /// session (we answered THEIR init) proves the peer can reach us but says
    /// nothing about our own outbound — and in the exact failure this exists
    /// to catch (our tx dead, field 2026-08-08 winhost-a→devbox), the peer
    /// hammers initiations at us every ~5 s, so an either-role stamp would
    /// read permanently alive.
    hs_response_at: AtomicU64,
    /// P4 — inbound IP packets from this peer whose SOURCE address it does not
    /// own ([`Router::rpf_check`]). Counted in `warn` AND `enforce` (only
    /// `enforce` also drops), so a fleet read of this counter is exactly the
    /// blast radius of flipping the mode. Monotonic — never drained.
    rx_denied: AtomicU64,
    /// The subset of [`Self::rx_denied`] whose reason was `Rpf(NoRoute)` — a
    /// source NO installed peer owns. Split out because this class is worse
    /// than a plain denial even in `warn`: the packet is delivered, but any
    /// reply to that source is unroutable from this node, so the flow fails
    /// silently (field 2026-08-09: a multi-org sender's OS picking the wrong
    /// org's overlay address). Monotonic.
    rx_denied_noroute: AtomicU64,
    /// P4 — mono-ms (against [`wg_epoch`]) of the last reverse-path log line
    /// emitted for this peer; 0 = never. Throttles the warning to ≤1 per peer
    /// per [`RPF_LOG_THROTTLE_MS`] so neither a spoofing flood nor a
    /// misconfigured subnet router turns a per-packet check into a log flood.
    rpf_logged_at: AtomicU64,
    /// Passive loss of the WG stream this peer sends us, from the counters of
    /// the transport packets that authenticated ([`Self::note_rx_counter`]).
    /// `rx_ctr_span` grows by how far a session's highest counter advanced,
    /// `rx_ctr_accepted` by one per packet; boringtun's replay window accepts
    /// each counter once, so a standby copy of a delivered packet never counts.
    /// Written only under the peer's `Tunn` lock, read as deltas by the health
    /// sweep ([`WgDevice::peer_rx_loss`]). Monotonic.
    rx_ctr_session: AtomicU64,
    rx_ctr_hi: AtomicU64,
    rx_ctr_span: AtomicU64,
    rx_ctr_accepted: AtomicU64,
}

impl PeerStats {
    /// Book one authenticated datagram toward the passive loss counters if it
    /// is a transport packet (type 4: data or keepalive, each one counter).
    /// Its receiver index names the session (counters restart with each), its
    /// counter its place there. A late, reordered packet adds to `accepted`
    /// only, so a short window can read slightly negative; a session change
    /// starts over without booking the gap as loss.
    fn note_rx_counter(&self, datagram: &[u8]) {
        if datagram.len() < 16 || datagram[..4] != [4, 0, 0, 0] {
            return;
        }
        // The receiver index (+1, so 0 means no session yet), then the counter.
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&datagram[4..8]);
        let session = u64::from_le_bytes(b) + 1;
        b.copy_from_slice(&datagram[8..16]);
        let ctr = u64::from_le_bytes(b);
        self.rx_ctr_accepted.fetch_add(1, Ordering::Relaxed);
        if self.rx_ctr_session.load(Ordering::Relaxed) != session {
            self.rx_ctr_session.store(session, Ordering::Relaxed);
            self.rx_ctr_hi.store(ctr, Ordering::Relaxed);
            self.rx_ctr_span.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let hi = self.rx_ctr_hi.load(Ordering::Relaxed);
        if ctr > hi {
            self.rx_ctr_hi.store(ctr, Ordering::Relaxed);
            self.rx_ctr_span.fetch_add(ctr - hi, Ordering::Relaxed);
        }
    }
}

/// P3 PR-B — process-monotonic epoch for [`PeerStats::handshake_at`] stamps.
/// Initialized when the first [`WgDevice`] is built — before any probe can
/// start — so every stamp and every probe-start `Instant` is ≥ the epoch and
/// `latch_ms − start_ms` can never wrap.
static WG_EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

fn wg_epoch() -> Instant {
    *WG_EPOCH.get_or_init(Instant::now)
}

/// Milliseconds of `wg_epoch()` elapsed — the `handshake_at` clock.
fn mono_ms_now() -> u64 {
    wg_epoch().elapsed().as_millis() as u64
}

/// P4 — min interval between reverse-path warnings for the SAME peer.
const RPF_LOG_THROTTLE_MS: u64 = 60_000;

/// Short hex prefix of a WG public key, for logs.
pub(crate) fn short_key(k: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", k[0], k[1], k[2], k[3])
}

/// P4 — everything the INGRESS path needs to authorize one peer's decapsulated
/// packets: **who** is sending (its WG public key), the shared routing table
/// that says which source addresses that peer owns, the mode, and the peer's
/// counters.
///
/// Bundled into one parameter rather than four more arguments to
/// [`process_inbound`] — and it is the seam the per-peer L4 ACL (server-compiled
/// ingress rules on `NetmapPeer`) slots into, since it is already threaded to
/// every inbound call site and already carries peer identity.
/// Why an inbound packet was refused. Distinguishes the two ingress tiers in
/// logs and field reports: a forged SOURCE (the peer lying about who it is) vs.
/// an out-of-scope DESTINATION (the peer aiming past us at something we never
/// advertised).
#[derive(Debug, Clone, Copy)]
enum IngressDeny {
    /// `NoRoute` = a source nobody here owns (reply-unroutable — see
    /// [`PeerStats::rx_denied_noroute`]); `OtherPeer` = an actual forgery.
    Rpf(super::router::RpfDeny),
    OutOfScope,
    /// The destination is inside this node's scope, but the tenant's ACL grants
    /// this particular peer no rule covering it (or its port/protocol).
    NotPermitted,
}

#[derive(Clone)]
pub(crate) struct Ingress {
    peer: [u8; 32],
    /// Read-only here: the routing table doubles as the allowed-IPs table.
    send: WgSender,
    stats: Arc<PeerStats>,
    mode: RpfMode,
}

impl Ingress {
    /// May this peer deliver this packet? Two independent questions, answered
    /// from ONE lock acquisition:
    ///
    /// 1. **Source** — does `src` route back to this peer? (address forgery)
    /// 2. **Destination** — is the packet addressed inside this node's own
    ///    scope? (a peer aiming *past* a subnet router at something the router
    ///    never advertised)
    ///
    /// Counts and throttled-logs every failure; returns `false` (drop) ONLY in
    /// [`RpfMode::Enforce`].
    fn permits(&self, src: IpAddr, packet: &[u8]) -> bool {
        // ONE tight sync block for every check. `SendState`'s guard is a std
        // (!Send) one, so the compiler rejects holding it across the
        // `tun_tx.send().await` below.
        let routing_dst = Router::dst_of_ip_packet(packet);
        let off = self.mode == RpfMode::Off;
        let (verdict, in_scope, rules, reply) = {
            let g = self.send.0.read().unwrap();
            let rules = g.ingress_acls.get(&self.peer).cloned();
            if off && rules.is_none() {
                return true;
            }
            // #18 — a packet addressed to THIS node is judged by the rules too,
            // unless it belongs to a flow already admitted (a reply).
            let reply = rules.is_some()
                && g.scope.is_self_dst(routing_dst)
                && super::ingress::admitted_reply(packet, &g.flows, mono_ms_now());
            (
                if off {
                    RpfVerdict::Allow
                } else {
                    g.router.rpf_check(&self.peer, src)
                },
                off || g.scope.permits_dst(routing_dst),
                rules,
                reply,
            )
        };
        // Per-source rules govern what a peer may reach through us AND on us
        // (#18: the tenant's ACL narrows node-to-node traffic by protocol and
        // port, not only by visibility). Parsing is deferred to here so the
        // common in-scope, no-ACL packet never touches the L4 path.
        let rule_denied = match rules {
            Some(rules) if in_scope && !reply => {
                let dst = dst_ip_of(packet);
                match dst {
                    Some(dst) => !rules_permit(&rules, dst, parse_l4(packet).as_ref()),
                    // No parseable destination but it passed the scope check —
                    // fail closed, the same stance the rules take on a packet
                    // that hides its port.
                    None => true,
                }
            }
            _ => false,
        };
        // Same counter + throttle as a reverse-path failure, distinct reasons so
        // a field report separates "forged its source" from "aimed past us"
        // from "not granted this destination".
        let reason = match verdict {
            _ if !in_scope => IngressDeny::OutOfScope,
            _ if rule_denied => IngressDeny::NotPermitted,
            RpfVerdict::Deny(r) => IngressDeny::Rpf(r),
            RpfVerdict::Allow => return true,
        };
        // The precedence above makes this subset exact: OutOfScope and
        // NotPermitted win over Rpf, so `noroute` counts ONLY packets whose
        // final verdict was "a source nobody owns".
        let noroute = matches!(reason, IngressDeny::Rpf(super::router::RpfDeny::NoRoute));
        if noroute {
            self.stats.rx_denied_noroute.fetch_add(1, Ordering::Relaxed);
        }
        // The tenant's ACL is enforced whatever `overlay_rpf` says: the server
        // ships rules only when the tenant enforces it. The reverse-path and
        // scope checks keep their own warn/enforce switch.
        let drop = matches!(reason, IngressDeny::NotPermitted) || self.mode == RpfMode::Enforce;
        let denied = self.stats.rx_denied.fetch_add(1, Ordering::Relaxed) + 1;
        let now = mono_ms_now();
        let last = self.stats.rpf_logged_at.load(Ordering::Relaxed);
        // `last == 0` ⇒ never logged, so the FIRST denial always surfaces even
        // when the process is younger than the throttle window. CAS so N
        // concurrent recv tasks emit one line, not N.
        if (last == 0 || now.saturating_sub(last) >= RPF_LOG_THROTTLE_MS)
            && self
                .stats
                .rpf_logged_at
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let peer = short_key(&self.peer);
            if drop {
                let (dst, l4) = (dst_ip_of(packet), parse_l4(packet));
                warn!(
                    %src, ?dst, ?l4, ?reason, %peer, denied,
                    "overlay: DROPPED an inbound packet the sending peer is not entitled to send"
                );
            } else if noroute {
                // The delivery is a trap here: replies to a source nobody owns
                // are unroutable from this node, so the flow fails silently
                // whatever we do — say so instead of implying warn is harmless.
                warn!(
                    %src, %peer, denied,
                    "overlay: inbound packet from a source NO installed peer owns — \
                     delivered (overlay_rpf=warn), but replies to this source cannot be \
                     routed back from this node, so the flow will fail silently. If the \
                     sender is a multi-org host, its OS likely picked the wrong org's \
                     overlay address as source"
                );
            } else {
                warn!(
                    %src, ?reason, %peer, denied,
                    "overlay: inbound packet the sending peer is not entitled to send — \
                     delivered anyway (overlay_rpf=warn; set `enforce` to drop, `off` to stop checking)"
                );
            }
        }
        !drop
    }
}

/// Demux routing table: a direct peer's source address → its `Tunn` + ingress
/// context. One shared map drives the single direct-socket recv loop (rc.134).
type DemuxRoutes = HashMap<SocketAddr, (Arc<Mutex<Tunn>>, Ingress)>;

/// Phase A — a WireGuard **handshake initiation** that arrived on a shared
/// direct socket from a source address NO demux route matches. Two real cases
/// produce this: a NAT'd peer dialling our advertised PUBLIC endpoint (its
/// NAT'd source can't be known in advance — the direct-to-public accept), and
/// an already-known peer that restarted/roamed onto a new ephemeral port (the
/// field-observed stale-port race: its 148-byte init arrived and was silently
/// dropped, so the handshake died until the "restart the exit last" workaround).
/// The demux can't act on it — it has no `&mut WgDevice` — so it forwards the
/// packet to the runtime's select loop, which authenticates it (a probe `Tunn`
/// performs the full Noise-IK validation; `parse_handshake_anon` alone is NOT
/// proof of identity) and only then installs/re-points the peer.
pub struct DirectInbound {
    pub src: SocketAddr,
    pub sock: Arc<UdpSocket>,
    pub packet: Vec<u8>,
}

/// Phase A — min interval between forwarded unknown-source initiations from
/// the SAME source, and the cap on tracked sources. WG retransmits an
/// unanswered init every ~5 s, so 2 s forwards every genuine attempt while a
/// junk flood collapses to ≤1 event per source per 2 s (and ≤64 sources).
pub(crate) const UNKNOWN_INIT_MIN_INTERVAL: Duration = Duration::from_secs(2);
pub(crate) const UNKNOWN_INIT_MAX_SOURCES: usize = 64;

/// One installed peer: its `Tunn`, its carrier, and the background tasks
/// that pump it. Dropping aborts the tasks.
struct Peer {
    tunn: Arc<Mutex<Tunn>>,
    carrier: Arc<Carrier>,
    overlay_ip: Ipv4Addr,
    tasks: Vec<JoinHandle<()>>,
    stats: Arc<PeerStats>,
    /// rc.134 — for a SHARED-direct peer, the source address it sends from
    /// (== the carrier dst). `Some` ⇒ its inbound is handled by the device's
    /// shared demux loop (no per-peer recv task), and `remove_peer` must
    /// un-register it from the demux routing table. `None` for relay /
    /// dedicated-socket carriers (those own a per-peer recv task).
    direct_src: Option<SocketAddr>,
    /// Multi-org v2 — the plane-registered session index, when this peer's
    /// route lives on the shared [`CarrierPlane`](super::carrier_plane)
    /// instead of the device demux. Removal/replacement unregisters by THIS
    /// key (indices never alias; source addresses can).
    plane_idx: Option<u32>,
    /// A3 — the session index in the DEVICE demux's roaming side-map
    /// ([`DirectDemux::index_routes`]), for device-mode direct peers. After a
    /// roam the source-keyed entry lives under the ADOPTED source, so removal
    /// resolves the current key through this index (the stale `direct_src`
    /// would miss it). `None` for plane-mode (plane_idx covers it) and
    /// relay peers.
    direct_index: Option<u32>,
}

/// A3 — one session's roaming state in the device demux's index side-map:
/// the CURRENT source key of its `DemuxRoutes` entry, the peer's carrier (to
/// repoint outbound in place), and the last adoption instant (rate limit).
struct IndexSlot {
    src: SocketAddr,
    carrier: std::sync::Weak<Carrier>,
    last_roam: Option<Instant>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// rc.134/143 — shared-routes demux for N direct-LAN peers. One UDP socket
/// **per usable LAN interface** (each bound to its interface IP, not `0.0.0.0`
/// — rc.143), and one recv loop per socket, all routing into a single shared
/// `routes` map that dispatches each datagram to the peer whose endpoint matches
/// the source address (the WireGuard model). Many same-subnet peers can be
/// direct at once (lifting the rc.131 "one direct peer" cap), and each peer is
/// sent/received on the socket bound to the interface it shares a subnet with —
/// so a full-tunnel VPN can't hijack the egress (a single `0.0.0.0` socket let
/// the OS route the reply out the VPN, breaking direct on VPN'd hosts).
struct DirectDemux {
    routes: Arc<Mutex<DemuxRoutes>>,
    /// The per-interface sockets that have a live demux recv loop (deduped by
    /// local address so `ensure_direct_demux` is idempotent per interface).
    socks: Vec<Arc<UdpSocket>>,
    tasks: Vec<JoinHandle<()>>,
    /// PR-B1 — per-socket receive liveness, in lockstep with `socks`/`tasks`
    /// (snapshotted into `NodeStatus.direct_socks`).
    stats: Vec<Arc<super::direct::SockStat>>,
    /// A3 — session index → roaming slot, shared with every recv loop: lets
    /// an AUTHENTICATED sessionful datagram from an unexpected source find
    /// its session (the wire receiver index survives a source change; the
    /// source key doesn't) and be adopted. Keyed `receiver_idx >> 8`.
    /// `std::sync` mutex: never held across an await, and the sync
    /// replacement paths (`promote_direct_probe`) must purge slots too.
    index_routes: Arc<std::sync::Mutex<HashMap<u32, IndexSlot>>>,
}

/// P1 (S6) — the send-relevant triple of one routed peer, mirrored from
/// [`Peer`] into the shared [`SendState`] so the outbound pump task can
/// encapsulate + send without touching the loop-owned [`WgDevice`].
#[derive(Clone)]
struct SendPeer {
    tunn: Arc<Mutex<Tunn>>,
    carrier: Arc<Carrier>,
    stats: Arc<PeerStats>,
}

/// P1 (S6) — everything the outbound data path needs, shared between the
/// loop-owned [`WgDevice`] (sole writer, via its `&mut self` mutators) and
/// the outbound pump task (reader). The [`Router`] lives HERE — single
/// source of truth; the device reaches it through the lock.
struct SendState {
    router: Router,
    /// P4 — this node's own destination scope (its overlay IP + the subnets it
    /// advertises). Lives HERE so the ingress check reads it under the SAME
    /// lock it already takes for the reverse-path lookup: no extra
    /// synchronisation on the per-packet path.
    scope: LocalScope,
    /// P4 — server-compiled per-source ingress rules, keyed by the sending
    /// peer's WG public key. Present only for peers whose netmap entry carried
    /// `ingress_rules` (i.e. the tenant is ENFORCING); an absent key means the
    /// ACL compiled nothing for that peer and only [`scope`](Self::scope)
    /// applies. `Arc` so the per-packet path clones a pointer, not the rules.
    ingress_acls: HashMap<[u8; 32], Arc<Vec<OverlayRule>>>,
    /// #18 — the UDP flows and ICMP echoes this node sent toward peers in
    /// `ingress_acls`, so their replies pass those peers' rules.
    flows: super::ingress::ReplyFlows,
    /// Mirror of `WgDevice::peers`' send triples, maintained at the same
    /// mutation choke points ([`WgDevice::send_install`] /
    /// [`WgDevice::send_uninstall`]). Key-set equality with `peers` is
    /// debug-asserted after every mutator.
    peers: HashMap<[u8; 32], SendPeer>,
}

/// P1 (S6) — cloneable send half of the WG device, handed to the runtime's
/// dedicated outbound pump task so the select! loop carries NO data-plane
/// work (the structural fix behind the rc.206→rc.218 inline-await arc).
///
/// Lock discipline: this is a **std** `RwLock` deliberately (not tokio, not
/// ArcSwap) — the std guard is `!Send`, so holding it across an `.await`
/// inside the spawned (hence `Send`) pump future is a COMPILE ERROR. Guards
/// live in tight sync blocks, always dropped before the encapsulate/send
/// awaits. Lock poisoning ⇒ panic ⇒ the pump's JoinHandle resolves ⇒ the
/// runtime loop exits ⇒ the agent's WS lifecycle rebuilds the session (the
/// same disposition as a TUN death).
///
/// Accepted micro-race (by design): the pump may clone a [`SendPeer`]
/// immediately before the loop removes/replaces that peer and send ≤1 packet
/// into the just-torn-down carrier — indistinguishable from the existing
/// best-effort drop semantics, and the `Arc`s keep the socket alive for the
/// in-flight send. On an MBB promote the whole triple is swapped under one
/// write lock, so the pump sees the complete old carrier or the complete new
/// one, never a mix.
#[derive(Clone)]
pub struct WgSender(Arc<std::sync::RwLock<SendState>>);

impl WgSender {
    /// Send the same authenticated, out-of-tunnel disco frame over the
    /// CURRENT carrier, direct or relay. The runtime still treats these as
    /// diagnostics; a response is not a quality-based promotion grant.
    pub(crate) async fn send_disco_raw(
        &self,
        peer_public: &[u8; 32],
        bytes: &[u8],
    ) -> Option<SocketAddr> {
        let carrier = {
            let g = self.0.read().unwrap();
            g.peers.get(peer_public)?.carrier.clone()
        };
        let dst = carrier.disco_endpoint();
        tokio::time::timeout(Duration::from_millis(100), carrier.send_disco(bytes))
            .await
            .ok()?
            .ok()
            .map(|_| dst)
    }

    /// The relay transport + server for `pk`'s carrier, `None` when direct or
    /// unknown. Reads the same send-side mirror `send_disco_raw` uses.
    pub(crate) fn relay_transport_info(
        &self,
        peer_public: &[u8; 32],
    ) -> Option<(crate::transport::relay::RelayTransport, Option<String>)> {
        let g = self.0.read().unwrap();
        g.peers.get(peer_public)?.carrier.relay_transport_info()
    }

    /// C1 (disco) — is `pk` an installed peer? Reuses the send-side mirror
    /// (kept key-for-key with `WgDevice::peers`, debug-asserted) so the disco
    /// responder can reject an unknown sender BEFORE spending an X25519.
    pub(crate) fn has_peer(&self, pk: &[u8; 32]) -> bool {
        self.0.read().unwrap().peers.contains_key(pk)
    }

    fn attest_active_derp(&self, public: &[u8; 32], tunn: &Arc<Mutex<Tunn>>, carrier: &Arc<Carrier>, init: &[u8; 32]) -> bool {
        let g = self.0.read().unwrap();
        let Some(p) = g.peers.get(public) else { return false; };
        if !Arc::ptr_eq(&p.tunn, tunn) || !Arc::ptr_eq(&p.carrier, carrier)
            || !p.stats.derp_role.load(Ordering::Relaxed)
            || !p.stats.sent_inits.lock().unwrap_or_else(|e|e.into_inner()).contains(init)
        { return false; }
        p.stats.recovery_hold.fetch_max(mono_ms_now().saturating_add(60_000), Ordering::Relaxed);
        true
    }

    fn same_owner(&self, public: &[u8; 32], tunn: &Arc<Mutex<Tunn>>, carrier: &Arc<Carrier>, derp: bool) -> bool {
        self.0.read().unwrap().peers.get(public).is_some_and(|p| {
            Arc::ptr_eq(&p.tunn, tunn) && Arc::ptr_eq(&p.carrier, carrier)
                && (!derp || p.stats.derp_role.load(Ordering::Relaxed))
        })
    }

    pub(crate) fn new() -> Self {
        Self(Arc::new(std::sync::RwLock::new(SendState {
            router: Router::new(),
            scope: LocalScope::default(),
            ingress_acls: HashMap::new(),
            flows: Default::default(),
            peers: HashMap::new(),
        })))
    }

    /// Encapsulate + send a raw IP packet to whichever peer owns its
    /// destination. v4 (or an overlay-internal derived-ULA v6 — see
    /// [`Router::dst_of_ip_packet`]) routes on the v4 table. P5/S3b — a GLOBAL
    /// v6 destination ([`Router::is_global_v6_dst`]) routes to the configured
    /// v6-exit peer if set, else is dropped (fail-closed, no leak). `false` if
    /// no route or no session.
    pub async fn send_ip_packet(&self, packet: &[u8]) -> bool {
        // Route lookup + triple clone in ONE tight read-guard block; the
        // guard is dropped before any await (enforced by !Send — see above).
        let sp = {
            let g = self.0.read().unwrap();
            Self::route(&g, packet).and_then(|pk| {
                g.note_outbound(&pk, packet);
                g.peers.get(&pk).cloned()
            })
        };
        match sp {
            Some(sp) => sp.send(packet).await,
            None => false,
        }
    }

    /// The peer owning `packet`'s destination: v4 or derived-ULA v6 → the v4
    /// routing table (a miss is final — no fall-through to the v6 exit); a
    /// global v6 destination → the configured v6 exit.
    fn route(g: &SendState, packet: &[u8]) -> Option<[u8; 32]> {
        if let Some(dst) = Router::dst_of_ip_packet(packet) {
            g.router.route(&dst)
        } else if Router::is_global_v6_dst(packet).is_some() {
            g.router.v6_exit()
        } else {
            None
        }
    }

    /// Send a burst of outbound IP packets — what the outbound pump has
    /// queued at once. One routing pass under one read guard; each peer's
    /// share is then encapsulated under ONE Tunn lock and, on a direct
    /// carrier, sent as GSO runs ([`SendPeer::send_batch`]). Per-peer packet
    /// order is preserved. Returns how many were handed to a carrier.
    pub async fn send_ip_batch(&self, packets: &[Vec<u8>]) -> usize {
        let mut groups: Vec<(SendPeer, Vec<usize>)> = Vec::new();
        {
            let g = self.0.read().unwrap();
            for (i, p) in packets.iter().enumerate() {
                let Some(pk) = Self::route(&g, p) else {
                    continue;
                };
                let Some(sp) = g.peers.get(&pk) else { continue };
                g.note_outbound(&pk, p);
                match groups.iter_mut().find(|(s, _)| Arc::ptr_eq(&s.tunn, &sp.tunn)) {
                    Some((_, idxs)) => idxs.push(i),
                    None => groups.push((sp.clone(), vec![i])),
                }
            }
        }
        let mut sent = 0;
        for (sp, idxs) in groups {
            sent += sp.send_batch(packets, &idxs).await;
        }
        sent
    }

    /// Encapsulate + send `packet` to a specific peer. `false` if the peer is
    /// unknown, the handshake hasn't completed (boringtun queues the packet
    /// and emits a handshake initiation instead), or the carrier send failed.
    pub async fn send_to_peer(&self, peer_public: &[u8; 32], packet: &[u8]) -> bool {
        let sp = {
            let g = self.0.read().unwrap();
            g.note_outbound(peer_public, packet);
            g.peers.get(peer_public).cloned()
        };
        match sp {
            Some(sp) => sp.send(packet).await,
            None => false,
        }
    }
}

impl SendState {
    /// #18 — remember a flow this node starts toward a peer whose ingress the
    /// tenant's ACL governs, so that peer's replies pass its rules.
    fn note_outbound(&self, peer: &[u8; 32], packet: &[u8]) {
        if self.ingress_acls.contains_key(peer) {
            self.flows.note_outbound(packet, mono_ms_now());
        }
    }
}

impl SendPeer {
    /// The single encapsulate-and-send implementation (moved verbatim from
    /// the pre-P1 `WgDevice::send_to_peer`).
    async fn send(&self, packet: &[u8]) -> bool {
        let mut buf = vec![0u8; WG_BUF];
        // rc.211 — encapsulate UNDER the lock, send AFTER releasing it (see
        // the timer tasks): never hold the Tunn lock across a carrier send.
        let len = {
            let mut t = self.tunn.lock().await;
            encapsulate_into(&mut t, packet, &mut buf)
        };
        match len {
            Some(n) => {
                self.stats.tx_attempted.fetch_add(1, Ordering::Relaxed);
                let ok = send_wg_recorded(&self.carrier, &self.stats, &buf[..n]).await.is_ok();
                if ok {
                    self.stats.tx.fetch_add(1, Ordering::Relaxed);
                }
                self.stats.standby.copy(&buf[..n]);
                ok
            }
            None => false,
        }
    }

    /// [`Self::send`] for several packets to this peer, in order. All are
    /// encapsulated under ONE Tunn lock straight into one buffer; on a direct
    /// carrier each run of equal-size WG data datagrams then leaves as one
    /// GSO `sendmsg`. Handshake/cookie output (no session yet) keeps the
    /// recorded single send; a refused GSO send is retried datagram by
    /// datagram, so every path still ends in [`Carrier::send`]'s semantics.
    async fn send_batch(&self, packets: &[Vec<u8>], idxs: &[usize]) -> usize {
        let direct = self.carrier.direct_parts();
        let max_segs = super::udp_batch::max_send_segments();
        if idxs.len() < 2 || max_segs < 2 || direct.is_none() {
            let mut sent = 0;
            for &i in idxs {
                if self.send(&packets[i]).await {
                    sent += 1;
                }
            }
            return sent;
        }
        let mut wire: Vec<u8> = Vec::with_capacity(idxs.len() * WG_BUF);
        let mut lens: Vec<usize> = Vec::with_capacity(idxs.len());
        let mut control: Vec<Vec<u8>> = Vec::new();
        {
            let mut t = self.tunn.lock().await;
            for &i in idxs {
                let off = wire.len();
                wire.resize(off + WG_BUF, 0);
                match encapsulate_into(&mut t, &packets[i], &mut wire[off..]) {
                    // Type 4 = transport data; anything else is a handshake step.
                    Some(n) if wire[off] == 4 => {
                        wire.truncate(off + n);
                        lens.push(n);
                    }
                    Some(n) => {
                        control.push(wire[off..off + n].to_vec());
                        wire.truncate(off);
                    }
                    None => wire.truncate(off),
                }
            }
        }
        let stats = &self.stats;
        stats
            .tx_attempted
            .fetch_add((lens.len() + control.len()) as u64, Ordering::Relaxed);
        let mut sent = 0;
        for c in &control {
            if send_wg_recorded(&self.carrier, stats, c).await.is_ok() {
                sent += 1;
            }
        }
        let (sock, dst) = direct.expect("checked above");
        let mut start = 0;
        let mut i = 0;
        while i < lens.len() {
            // A GSO run: equal-size datagrams, the last possibly shorter, at
            // most `max_segs` of them and within one UDP datagram's length.
            let seg = lens[i];
            let cap = max_segs.min((u16::MAX as usize - 512) / seg).max(1);
            let mut j = i + 1;
            while j < lens.len() && j - i < cap && lens[j] <= seg {
                let last = lens[j] < seg;
                j += 1;
                if last {
                    break;
                }
            }
            let end = start + lens[i..j].iter().sum::<usize>();
            let ok = if j - i == 1 {
                send_wg_recorded(&self.carrier, stats, &wire[start..end]).await.is_ok()
            } else {
                super::udp_batch::send_segments(sock, dst, &wire[start..end], seg).await.is_ok()
            };
            if ok {
                sent += j - i;
            } else if j - i > 1 {
                let mut off = start;
                for &n in &lens[i..j] {
                    if self.carrier.send(&wire[off..off + n]).await.is_ok() {
                        sent += 1;
                    }
                    off += n;
                }
            }
            start = end;
            i = j;
        }
        stats.tx.fetch_add(sent as u64, Ordering::Relaxed);
        if stats.standby.armed() {
            let mut off = 0;
            for &n in &lens {
                stats.standby.copy(&wire[off..off + n]);
                off += n;
            }
        }
        sent
    }
}

/// Encapsulate `packet` into the front of `out`; the datagram length when
/// boringtun produced one (data, or a handshake initiation while no session
/// exists). boringtun writes from the start of `out`; the copy covers any
/// other layout so callers can always send `out[..n]`.
fn encapsulate_into(t: &mut Tunn, packet: &[u8], out: &mut [u8]) -> Option<usize> {
    let base = out.as_ptr() as usize;
    let (off, n) = match t.encapsulate(packet, out) {
        TunnResult::WriteToNetwork(b) => (b.as_ptr() as usize - base, b.len()),
        TunnResult::Done => return None,
        TunnResult::Err(e) => {
            warn!(?e, "wg encapsulate error");
            return None;
        }
        _ => return None,
    };
    if off != 0 {
        out.copy_within(off..off + n, 0);
    }
    Some(n)
}

/// A candidate owns a private receive/timer/crypto session without changing
/// the active sender. After commit, the incumbent stays receiving until both
/// peers acknowledge and the coordinator finalizes this exact trial.
struct FollowRound {
    nonce: [u8; 16],
    init: [u8; 32],
    started: Instant,
    sent: u8,
    last_sent: Option<Instant>,
}
struct DerpFollowState {
    org: std::sync::Weak<Mutex<Tunn>>,
    floor: std::sync::Weak<Mutex<Tunn>>,
    hello: FollowRound,
    capable: bool,
    pending: Option<FollowRound>,
    next_round: Instant,
}
impl FollowRound {
    fn new(init: [u8; 32]) -> Self {
        Self { nonce: follow::nonce(), init, started: Instant::now(), sent: 0, last_sent: None }
    }
    fn fresh(&self) -> bool { self.started.elapsed() < Duration::from_secs(3) }
    fn due(&self) -> bool {
        self.fresh() && self.sent < 3
            && self.last_sent.is_none_or(|at| at.elapsed() >= Duration::from_secs(1))
    }
}

struct OrgUpgradePeer {
    candidate: Peer,
    incumbent_tunn: std::sync::Weak<Mutex<Tunn>>,
}

struct PathTrialPeer {
    public_key: [u8; 32],
    candidate: Option<Peer>,
    incumbent: Option<Peer>,
    incumbent_tunn: std::sync::Weak<Mutex<Tunn>>,
    committed_tunn: Option<std::sync::Weak<Mutex<Tunn>>>,
    pongs: mpsc::Receiver<super::disco::DiscoInbound>,
    committed: bool,
    returned: bool,
}

/// A node's userspace WireGuard device: one static keypair, N peers,
/// and the `overlay_ip → pubkey` routing table.
pub struct WgDevice {
    secret: StaticSecret,
    public: PublicKey,
    peers: HashMap<[u8; 32], Peer>,
    /// Make-before-break (rc.208) — shadow direct-carrier probes. A relay→direct
    /// UPGRADE installs the candidate direct carrier HERE (its own `Tunn`, keyed
    /// by the same pubkey as its active relay peer in `peers`), so routing stays
    /// on the working relay until the probe's handshake latches. Promoted into
    /// `peers` on success, dropped on the deadline — the active carrier never
    /// stalls (the freeze the destructive break-before-make upgrade caused on a
    /// peer that can only relay). Empty unless the feature is on + an upgrade is
    /// in flight.
    probes: HashMap<[u8; 32], Peer>,
    path_trials: HashMap<ObjectId, PathTrialPeer>,
    /// Authorized DERP-to-ORG upgrades keep a private WG candidate until an
    /// actual response to our own initiation proves both directions.
    org_upgrades: HashMap<[u8; 32], OrgUpgradePeer>,
    /// Receive-only incumbent ownership prevents delayed floor ciphertext
    /// from becoming a false Unrouted/demote-follow signal after cutover.
    /// Removed with the active peer; its counters never prove ORG health.
    org_floor_receivers: HashMap<[u8; 32], Peer>,
    derp_follow: HashMap<[u8; 32], DerpFollowState>,
    recovery: HashMap<[u8; 32], (Ipv4Addr, Arc<AtomicU64>)>,
    /// Brief receive-only drain after a coordinated rollback. Still owned by
    /// this device and removed immediately on peer removal/rekey.
    path_trial_drains: HashMap<ObjectId, ([u8; 32], Instant, Peer)>,
    /// P1 (S6) — the shared send half (Router + send-triple mirror). This
    /// device is the SOLE writer; the outbound pump reads. See [`WgSender`].
    send: WgSender,
    tun_tx: mpsc::Sender<Vec<u8>>,
    next_index: u32,
    /// rc.134 — the shared direct-LAN socket + demux loop, lazily created on
    /// the first direct peer (`ensure_direct_demux`). `None` until then.
    direct: Option<DirectDemux>,
    /// Phase A — unknown-source handshake initiations forwarded by the demux
    /// loops. The sender is cloned into each demux loop; the receiver is taken
    /// once by the runtime ([`take_direct_events`](Self::take_direct_events)).
    direct_events_tx: mpsc::Sender<DirectInbound>,
    direct_events_rx: Option<mpsc::Receiver<DirectInbound>>,
    /// C2 — this engine's disco-pong sink (per-engine; see `take_disco_events`).
    disco_events_tx: mpsc::Sender<super::disco::DiscoInbound>,
    disco_events_rx: Option<mpsc::Receiver<super::disco::DiscoInbound>>,
    /// Phase C — STUN Binding responses forwarded by the demux loops (a
    /// datagram carrying the STUN cookie that is not WG-shaped). The srflx
    /// keepalive task's query rides a shared direct socket whose `recv_from`
    /// the demux owns, so the response can't be read directly; it arrives here.
    /// Cloned into each demux loop; the receiver is taken once by the runtime
    /// ([`take_stun_events`](Self::take_stun_events)). Dropped harmlessly if
    /// nobody took it (the srflx tier is off).
    stun_events_tx: mpsc::Sender<crate::transport::stun::StunInbound>,
    stun_events_rx: Option<mpsc::Receiver<crate::transport::stun::StunInbound>>,
    /// P4 — reverse-path filtering mode, resolved once at construction and
    /// copied into every peer's [`Ingress`]. Process-lifetime by design: a
    /// data-plane gate that could change under a live session would make a
    /// field report ("which packets did this node drop?") unanswerable.
    rpf: RpfMode,
    /// Multi-org v2 — when attached to the process-wide
    /// [`CarrierPlane`](super::carrier_plane::CarrierPlane): session indices
    /// come from the plane (unique across every attached engine — they key
    /// its receiver-index demux) and direct-session routes register THERE;
    /// the plane's recv loops replace this device's own source-keyed demux.
    plane: Option<super::carrier_plane::PlaneHandle>,
}

impl Drop for WgDevice {
    fn drop(&mut self) {
        if let Some(d) = &self.direct {
            for t in &d.tasks {
                t.abort();
            }
        }
    }
}

impl WgDevice {
    /// Build a device from a static secret. Returns the device plus the
    /// receiver for decrypted inbound IP packets (the TUN bridge / tests
    /// drain it).
    pub fn new(secret: StaticSecret) -> (Self, mpsc::Receiver<Vec<u8>>) {
        // P3 PR-B — pin the handshake_at epoch before any probe can exist.
        wg_epoch();
        let public = PublicKey::from(&secret);
        let (tun_tx, tun_rx) = mpsc::channel(256);
        let (direct_events_tx, direct_events_rx) = mpsc::channel(16);
        let (disco_events_tx, disco_events_rx) = mpsc::channel(64);
        let (stun_events_tx, stun_events_rx) = mpsc::channel(16);
        let rpf = RpfMode::parse(crate::env::node_env("OVERLAY_RPF").as_deref());
        tracing::info!(
            mode = rpf.as_str(),
            "overlay: reverse-path filtering (inbound source validation)"
        );
        (
            Self {
                secret,
                public,
                peers: HashMap::new(),
                probes: HashMap::new(),
                path_trials: HashMap::new(),
                org_upgrades: HashMap::new(),
                org_floor_receivers: HashMap::new(),
                derp_follow: HashMap::new(),
                recovery: HashMap::new(),
                path_trial_drains: HashMap::new(),
                send: WgSender::new(),
                tun_tx,
                next_index: 1,
                direct: None,
                direct_events_tx,
                disco_events_tx,
                disco_events_rx: Some(disco_events_rx),
                direct_events_rx: Some(direct_events_rx),
                stun_events_tx,
                stun_events_rx: Some(stun_events_rx),
                rpf,
                plane: None,
            },
            tun_rx,
        )
    }

    /// Multi-org v2 — attach this device to the shared carrier plane. Must be
    /// called BEFORE any peer is installed; direct sessions then register on
    /// the plane and demux by receiver index on its shared sockets.
    pub fn set_plane(&mut self, handle: super::carrier_plane::PlaneHandle) {
        self.plane = Some(handle);
    }

    /// Multi-org v2 — the hook bundle the embedder hands to
    /// [`CarrierPlane::attach`](super::carrier_plane::CarrierPlane::attach)
    /// for this device (unknown-source inits and decrypted inbound flow
    /// through the same channels the device's own demux used).
    pub fn plane_hooks(&self) -> super::carrier_plane::EngineHooks {
        super::carrier_plane::EngineHooks {
            secret: self.secret.clone(),
            public: self.public,
            send: self.send.clone(),
            direct_events: self.direct_events_tx.clone(),
            disco_events: self.disco_events_tx.clone(),
            tun_tx: self.tun_tx.clone(),
        }
    }

    /// Session index for a new `Tunn` — plane-allocated when attached (the
    /// index keys the plane's cross-engine receiver-index demux), else the
    /// device-local counter (sessions are per-socket; no cross-device demux).
    fn alloc_index(&mut self) -> u32 {
        match &self.plane {
            Some(h) => h.alloc_index(),
            None => {
                let i = self.next_index;
                self.next_index = self.next_index.wrapping_add(1);
                i
            }
        }
    }

    /// Sync half of demux cleanup: drop a replaced/removed peer's PLANE route
    /// (index-keyed, so a replacement never aliases it). The source-keyed
    /// legacy entry is NOT touched here — a same-`dst` replacement already
    /// overwrote it in place, and removing by source would kill the new
    /// peer's route.
    fn unregister_plane_route(&self, p: &Peer) {
        if let (Some(idx), Some(h)) = (p.plane_idx, &self.plane) {
            h.unregister_route(idx);
        }
        // A3 — the device-mode twin: drop the replaced peer's roaming slot
        // (index-keyed, never aliases the replacement's). If the old session
        // ROAMED, its source-keyed entry no longer sits under the key the
        // replacement overwrote — best-effort remove it (`try_lock`: the
        // rare contended miss leaves a dead-Tunn entry whose inbound
        // decap-fails harmlessly).
        if let (Some(idx), Some(demux)) = (p.direct_index, &self.direct) {
            let slot = demux
                .index_routes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&idx);
            if let Some(slot) = slot
                && Some(slot.src) != p.direct_src
            {
                match demux.routes.try_lock() {
                    Ok(mut routes) => {
                        routes.remove(&slot.src);
                    }
                    Err(_) => debug!(
                        src = %slot.src,
                        "wg: roamed source entry left behind on contended replacement"
                    ),
                }
            }
        }
    }

    /// Full demux cleanup for a peer leaving entirely (no replacement):
    /// plane route by index, or the device-local source-keyed entry.
    /// (`unregister_plane_route` above already dropped the A3 roaming slot
    /// and any roamed-away source entry; the original-key remove below is a
    /// harmless miss when the session had roamed.)
    async fn unregister_direct(&self, p: &Peer) {
        self.unregister_plane_route(p);
        if p.plane_idx.is_none()
            && let (Some(src), Some(demux)) = (p.direct_src, &self.direct)
        {
            demux.routes.lock().await.remove(&src);
        }
    }

    /// P4 — the [`Ingress`] context for one peer's inbound path: its identity,
    /// the shared routing table, its counters, and this device's mode.
    fn ingress_for(&self, peer_public: [u8; 32], stats: Arc<PeerStats>) -> Ingress {
        Ingress {
            peer: peer_public,
            send: self.send.clone(),
            stats,
            mode: self.rpf,
        }
    }

    /// C2 — take THIS device.s disco-pong receiver (per-engine: N org
    /// engines share one plane, so a plane-wide sink would blind all but the
    /// first taker). `None` after the first take.
    pub(crate) fn take_disco_events(
        &mut self,
    ) -> Option<mpsc::Receiver<super::disco::DiscoInbound>> {
        self.disco_events_rx.take()
    }

    /// Phase A — take the receiver for unknown-source handshake initiations
    /// (see [`DirectInbound`]). `None` after the first take. A device whose
    /// receiver is never taken just drops events once the small channel fills
    /// (`try_send` in the demux) — harmless for tests that don't care.
    pub fn take_direct_events(&mut self) -> Option<mpsc::Receiver<DirectInbound>> {
        self.direct_events_rx.take()
    }

    /// Phase C — take the receiver for demux-routed STUN Binding responses (see
    /// [`stun_events_tx`](Self::stun_events_tx) and
    /// [`crate::transport::stun::StunInbound`]). `None` after the first take.
    /// The srflx keepalive task owns it and matches responses to its own
    /// queries by source + transaction id.
    pub fn take_stun_events(
        &mut self,
    ) -> Option<mpsc::Receiver<crate::transport::stun::StunInbound>> {
        self.stun_events_rx.take()
    }

    /// R3 — mint a FRESH stun-events channel and return its receiver. The
    /// take above is once-only, and the srflx keepalive task OWNS the taken
    /// receiver — so after a direct-plane rebuild aborts that task, the old
    /// receiver is gone with it and a respawned keepalive would have no
    /// event source. Call AFTER retiring the old demux slots and BEFORE
    /// registering the new ones: retired loops still hold the OLD sender
    /// (their sends now go nowhere, which is exactly right for loops being
    /// torn down), and every loop registered after this clones the NEW one.
    pub fn replace_stun_events(&mut self) -> mpsc::Receiver<crate::transport::stun::StunInbound> {
        let (tx, rx) = mpsc::channel(16);
        self.stun_events_tx = tx;
        self.stun_events_rx = None;
        rx
    }

    /// Phase A — the demux source address a SHARED-direct peer is currently
    /// registered under (`None` for relay/dedicated-socket peers or unknown
    /// pubkeys). Lets the runtime tell a duplicate event for an
    /// already-current source from a genuine roam to a new one.
    pub fn direct_src_of(&self, peer_public: &[u8; 32]) -> Option<SocketAddr> {
        self.peers.get(peer_public)?.direct_src
    }

    /// Re-assert a plane-registered peer's `(engine, src)` reverse entry from
    /// an AUTHENTICATED inbound init (the ForwardInit livelock breaker): a
    /// session whose reverse entry was clobbered by a replacement's
    /// register-then-unregister, or moved by a roam the device's `direct_src`
    /// never learned about, cycles auth → Drop → ForwardInit → feed → auth
    /// forever, each pass costing a DH and terminating nowhere. Same-`src`
    /// heals the entry in place; a differing `src` commits a full roam.
    /// No-op off the plane or for unknown/relay-only peers.
    pub fn reassert_plane_src(&self, peer_public: &[u8; 32], src: SocketAddr) {
        if let (Some(h), Some(p)) = (&self.plane, self.peers.get(peer_public))
            && let Some(idx) = p.plane_idx
        {
            h.reassert_src(idx, src);
        }
    }

    /// Phase A — EXTRACT + AUTHENTICATE a WireGuard handshake INITIATION with
    /// no per-peer state, returning the initiator's static public key **only if
    /// the init is cryptographically genuine**. Used by the runtime before it
    /// acts on a [`DirectInbound`] (installs / re-points a peer's carrier to the
    /// packet's source), so a forger can't hijack a peer's route.
    ///
    /// Two steps, because they prove different things:
    /// 1. `parse_handshake_anon` decrypts the *claimed* static — but a forger
    ///    who copies a victim's PUBLIC key (public data) can craft an init that
    ///    parses to that key (the encrypted-static key derives from the
    ///    initiator's own ephemeral + our public static, both attacker-known).
    ///    So the parsed key is a CLAIM, not proof.
    /// 2. A throwaway [`Tunn`] built with that claimed key decapsulates the
    ///    init: WireGuard also AEAD-seals the timestamp under a key derived from
    ///    `DH(our_static_priv, initiator_static_pub)`. Only the holder of the
    ///    claimed key's PRIVATE half computes the matching
    ///    `DH(initiator_static_priv, our_static_pub)`; a forger cannot, so the
    ///    timestamp open fails and `decapsulate` returns `Done`/`Err`. A genuine
    ///    init yields a `WriteToNetwork` handshake RESPONSE ⇒ authenticated.
    ///
    /// The probe Tunn's response is discarded; the real installed Tunn re-runs
    /// the same init and emits the response that reaches the peer (each Tunn has
    /// independent anti-replay state, so the re-run isn't rejected).
    pub fn authenticate_init(&self, init: &[u8]) -> Option<[u8; 32]> {
        authenticate_init_with(&self.secret, &self.public, init)
    }

    /// This node's public key.
    pub fn public(&self) -> PublicKey {
        self.public
    }

    /// P1 (S6) — clone the send half for the runtime's outbound pump task.
    pub fn sender(&self) -> WgSender {
        self.send.clone()
    }

    /// P1 (S6) — install/replace a peer's send triple + host route in the
    /// shared [`SendState`], under ONE write lock so the pump sees either the
    /// complete old entry or the complete new one, never a mix (the MBB
    /// promote swaps Tunn + carrier together). One of the two choke points
    /// every routing mutator must go through (with [`send_uninstall`]) — the
    /// ONLY code allowed to touch both `peers` and the mirror.
    fn send_install(
        &mut self,
        peer_public: [u8; 32],
        overlay_ip: Ipv4Addr,
        tunn: Arc<Mutex<Tunn>>,
        carrier: Arc<Carrier>,
        stats: Arc<PeerStats>,
    ) {
        let mut g = self.send.0.write().unwrap();
        Self::send_install_locked(&mut g, peer_public, overlay_ip, tunn, carrier, stats);
    }
    fn send_install_locked(
        g: &mut SendState, peer_public: [u8; 32], overlay_ip: Ipv4Addr,
        tunn: Arc<Mutex<Tunn>>, carrier: Arc<Carrier>, stats: Arc<PeerStats>,
    ) {
        if let Some(prev) = g.router.upsert(overlay_ip, peer_public) {
            // Expected once, right after the server recycled a removed device's
            // address to a new machine and we haven't reaped the old peer yet.
            // If it repeats, two live peers are claiming one overlay address.
            let short = |k: &[u8; 32]| format!("{:02x}{:02x}{:02x}{:02x}", k[0], k[1], k[2], k[3]);
            tracing::warn!(
                %overlay_ip,
                prev = %short(&prev),
                now = %short(&peer_public),
                "overlay: overlay IP reassigned to a different peer"
            );
        }
        g.peers.insert(
            peer_public,
            SendPeer {
                tunn,
                carrier,
                stats,
            },
        );
    }

    /// P1 (S6) — remove a peer's send triple + host route (+ clear the
    /// v6-exit pin if it pointed at this peer), under one write lock. The
    /// second mutation choke point (see [`send_install`]).
    ///
    /// Routes are dropped BY PUBKEY, not by the peer's address: overlay IPs are
    /// recycled between machines, so `by_ip[overlay_ip]` may already belong to
    /// the address's new owner by the time this peer is reaped.
    fn send_uninstall(&mut self, peer_public: &[u8; 32]) {
        let mut g = self.send.0.write().unwrap();
        g.router.remove_by_pubkey(peer_public);
        g.peers.remove(peer_public);
        // P5/S3b — if this was the global-v6 exit peer, stop routing v6 to a
        // now-dead pubkey (defensive; the reconcile re-asserts on its next
        // pass if the peer is still the valid, reachable exit).
        if g.router.v6_exit() == Some(*peer_public) {
            g.router.set_v6_exit(None);
        }
    }

    /// P1 (S6) — the send mirror must track `peers` key-for-key; a mutator
    /// that forgets its choke-point call would silently route the pump on
    /// stale state. No-op in release builds.
    fn debug_assert_send_synced(&self) {
        #[cfg(debug_assertions)]
        {
            let g = self.send.0.read().unwrap();
            debug_assert_eq!(
                g.peers.len(),
                self.peers.len(),
                "send mirror out of sync with peers (len)"
            );
            debug_assert!(
                self.peers.keys().all(|k| g.peers.contains_key(k)),
                "send mirror out of sync with peers (keys)"
            );
        }
    }

    /// Install a peer and spawn its recv + timer tasks. `initiate` ⇒
    /// proactively send a handshake initiation now (the dialing side);
    /// the other end reacts to the inbound init.
    pub fn add_peer(
        &mut self,
        peer_public: [u8; 32],
        overlay_ip: Ipv4Addr,
        carrier: Arc<Carrier>,
        initiate: bool,
    ) {
        self.cancel_org_upgrade(&peer_public);
        self.drop_org_floor_receiver(&peer_public);
        let peer = self.make_carrier_peer(
            peer_public,
            overlay_ip,
            carrier,
            initiate,
            self.disco_events_tx.clone(),
        );
        let (tunn, carrier, stats) = (peer.tunn.clone(), peer.carrier.clone(), peer.stats.clone());
        if let Some(old) = self.peers.insert(peer_public, peer) {
            self.unregister_plane_route(&old);
        }
        self.send_install(peer_public, overlay_ip, tunn, carrier, stats);
        self.debug_assert_send_synced();
    }

    /// Builds a fully live but UNROUTED carrier/Tunn pair. Used both by normal
    /// installs and path-trial shadows, so crypto/timers/ingress stay identical.
    fn make_carrier_peer(
        &mut self,
        peer_public: [u8; 32],
        overlay_ip: Ipv4Addr,
        carrier: Arc<Carrier>,
        initiate: bool,
        disco_sink: mpsc::Sender<super::disco::DiscoInbound>,
    ) -> Peer {
        let index = self.alloc_index();

        let tunn = Tunn::new(
            self.secret.clone(),
            PublicKey::from(peer_public),
            None,
            Some(KEEPALIVE_SECS),
            index,
            None,
        );
        let tunn = Arc::new(Mutex::new(tunn));

        let stats = Arc::new(PeerStats { recovery_hold: self.recovery_for(peer_public, overlay_ip), ..PeerStats::default() });

        // Multi-org v2 — register this session on the plane's receiver-index
        // demux even though it is NOT a direct install.
        //
        // Only `add_direct_peer` used to register, so a peer installed on a
        // RELAY carrier had a live session whose receiver index the plane did
        // not know. When the FAR end held a direct carrier and sent WG data
        // straight to the shared socket, `route_by_index` found nothing and
        // dropped it — silently, pre-decrypt. Carriers are negotiated per
        // side, so this asymmetry is normal, not exotic.
        //
        // Field 2026-08-12 (winhost-a, dual-org): the org whose peers sat on
        // relay was unreachable inbound from EVERY peer while the other org
        // was fine, and a restart flipped which one — whichever org happened
        // to get direct on both ends won. Its carrier socket rx climbed the
        // whole time (packets arriving) while its TUN rx stayed at idle
        // (nothing decrypted), and disco kept answering at 39 ms because disco
        // is demuxed by SHAPE before WG and needs no route at all.
        //
        // `expected_src` is UNSPECIFIED: a relay session has no direct source
        // to expect, so the first authenticated direct inbound takes the A3
        // roam path, which commits only after the payload authenticates and
        // then repoints the carrier in place. Strictly additive — these
        // datagrams were dropped before. Indices are unique process-wide
        // (`index_alloc`, locked by a test), so this cannot capture another
        // engine's traffic.
        if let Some(h) = &self.plane {
            let ingress = self.ingress_for(peer_public, stats.clone());
            h.register_route(
                index,
                tunn.clone(),
                ingress,
                SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                Arc::downgrade(&carrier),
            );
        }

        // recv task: carrier → decapsulate → tun / network echo.
        let recv_tunn = tunn.clone();
        let recv_carrier = carrier.clone();
        let recv_sender = self.sender();
        let recv_stats = stats.clone();
        let follow_shared = super::disco::shared_secret(&self.secret, &PublicKey::from(peer_public));
        let tun_tx = self.tun_tx.clone();
        let recv_ingress = self.ingress_for(peer_public, stats.clone());
        let disco_secret = self.secret.clone();
        let disco_public = self.public;
        let disco_replies = Arc::new(Semaphore::new(1));
        let recv_task = tokio::spawn(async move {
            let mut buf = vec![0u8; WG_BUF];
            loop {
                let n = match recv_carrier.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        debug!(%e, "wg carrier recv ended; peer recv task exiting");
                        break;
                    }
                };
                if follow::shaped(&buf[..n]) {
                    if let Some(frame) = follow::decode(&buf[..n], &peer_public, disco_public.as_bytes(), &follow_shared) {
                        match frame.kind {
                            follow::Kind::HelloAck => {
                                *recv_stats.follow_ack.lock().unwrap_or_else(|e|e.into_inner()) = Some(frame);
                            }
                            follow::Kind::Proof => {
                                *recv_stats.follow_proof.lock().unwrap_or_else(|e|e.into_inner()) = Some(frame);
                            }
                            follow::Kind::Hello | follow::Kind::Challenge => {
                                let challenge = frame.kind == follow::Kind::Challenge;
                                let allowed = if challenge {
                                    recv_sender.same_owner(&peer_public, &recv_tunn, &recv_carrier, true)
                                        && recv_stats.sent_inits.lock().unwrap_or_else(|e|e.into_inner()).contains(&frame.init)
                                } else {
                                    recv_stats.org_role.load(Ordering::Relaxed)
                                        && recv_sender.same_owner(&peer_public, &recv_tunn, &recv_carrier, false)
                                };
                                let now = mono_ms_now().max(1);
                                let last = recv_stats.follow_reply_at.load(Ordering::Relaxed);
                                if allowed && (last == 0 || now.saturating_sub(last) >= 1_000)
                                    && recv_stats.follow_reply_at.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_ok()
                                    && let Ok(permit) = disco_replies.clone().try_acquire_owned()
                                {
                                    let reply = follow::Frame { kind: if challenge { follow::Kind::Proof } else { follow::Kind::HelloAck }, ..frame };
                                    if let Some(bytes) = follow::encode(&reply, disco_public.as_bytes(), &peer_public, &follow_shared) {
                                        let (sender, tunn, carrier, stats) = (recv_sender.clone(), recv_tunn.clone(), recv_carrier.clone(), recv_stats.clone());
                                        tokio::spawn(async move {
                                            let _permit = permit;
                                            // Recheck after queueing: a stale owner never attests DERP.
                                            if challenge {
                                                if !sender.attest_active_derp(&peer_public, &tunn, &carrier, &reply.init) { return; }
                                            } else if !stats.org_role.load(Ordering::Relaxed)
                                                || !sender.same_owner(&peer_public, &tunn, &carrier, false) { return; }
                                            let _ = tokio::time::timeout(Duration::from_millis(100), carrier.send(&bytes)).await;
                                        });
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }
                // Authenticated end-to-end echo rides the SAME carrier as
                // WG, but never enters Tunn or refreshes WG liveness counters.
                // Exact expected peer matching rejects another tenant member.
                if super::disco::is_disco_shaped(&buf[..n]) {
                    match super::disco::classify(
                        &buf[..n],
                        recv_carrier.disco_endpoint(),
                        &disco_secret,
                        &disco_public,
                        |pk| pk == &peer_public,
                    ) {
                        super::disco::Verdict::Answer(pong) => {
                            if super::direct::disco_respond_enabled()
                                && let Ok(permit) = disco_replies.clone().try_acquire_owned()
                            {
                                // Never await a congested relay's reply write
                                // on the WG receive loop; one bounded reply
                                // task per peer, with no Tunn/route lock held.
                                let carrier = recv_carrier.clone();
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    let _ = tokio::time::timeout(
                                        Duration::from_millis(100),
                                        carrier.send_disco(&pong),
                                    )
                                    .await;
                                });
                            }
                        }
                        super::disco::Verdict::Pong(pong) => {
                            let _ = disco_sink.try_send(pong);
                        }
                        super::disco::Verdict::Ignore => {}
                    }
                    continue;
                }
                let mut t = recv_tunn.lock().await;
                process_inbound(&mut t, n, &mut buf, &recv_carrier, &tun_tx, &recv_ingress).await;
            }
        });

        let timer_task = Self::spawn_carrier_timer(tunn.clone(), carrier.clone(), stats.clone());

        let peer = Peer {
            tunn: tunn.clone(),
            carrier: carrier.clone(),
            overlay_ip,
            tasks: vec![recv_task, timer_task],
            stats: stats.clone(),
            direct_src: None,
            plane_idx: self.plane.as_ref().map(|_| index),
            direct_index: None,
        };
        if initiate {
            let init_stats = stats.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; WG_BUF];
                // rc.211 — same lock-then-send split as the timer tasks.
                let out = {
                    let mut t = tunn.lock().await;
                    match t.format_handshake_initiation(&mut buf, false) {
                        TunnResult::WriteToNetwork(b) => Some(b.to_vec()),
                        _ => None,
                    }
                };
                if let Some(b) = out {
                    let _ = send_wg_recorded(&carrier, &init_stats, &b).await;
                }
            });
        }
        peer
    }

    fn spawn_carrier_timer(
        tunn: Arc<Mutex<Tunn>>, carrier: Arc<Carrier>, stats: Arc<PeerStats>,
    ) -> JoinHandle<()> {
        // timer task: drive handshake retries + keepalives.
        let timer_tunn = tunn;
        let timer_carrier = carrier;
        tokio::spawn(async move {
            let mut buf = vec![0u8; WG_BUF];
            let mut tick = tokio::time::interval(Duration::from_millis(TIMER_TICK_MS));
            loop {
                tick.tick().await;
                // rc.211 — capture the handshake/keepalive bytes UNDER the
                // lock, then RELEASE it before the carrier send. Holding the
                // per-peer Tunn lock across `carrier.send().await` (a slow
                // relay/QUIC send under churn) stalls every other task that
                // needs the same Tunn — including the SHARED direct recv loop,
                // which then stops reading the socket and the OS drops inbound
                // UDP for ALL direct peers.
                let out = {
                    let mut t = timer_tunn.lock().await;
                    match t.update_timers(&mut buf) {
                        TunnResult::WriteToNetwork(b) => Some(b.to_vec()),
                        // boringtun gives up re-handshaking once a rekey
                        // attempt expires and reports the session over. That
                        // verdict is conclusive, and dropping it (as this arm
                        // did) left the carrier to be rediscovered the slow
                        // way, by the rx-staleness bound.
                        TunnResult::Err(WireGuardError::ConnectionExpired) => {
                            timer_carrier.mark_dead();
                            None
                        }
                        _ => None,
                    }
                };
                if let Some(b) = out {
                    let _ = send_wg_recorded(&timer_carrier, &stats, &b).await;
                }
            }
        })
    }

    /// Start only over the exact current non-direct incumbent. Both ends
    /// initiate: a responder-only session is insufficient promotion proof.
    pub(crate) fn start_org_upgrade(
        &mut self, public: [u8; 32], ip: Ipv4Addr, carrier: Arc<Carrier>,
    ) -> bool {
        if self.org_recovery_held(&public) { return false; }
        let Some(active) = self.peers.get(&public) else { return false; };
        if active.carrier.is_direct() || active.overlay_ip != ip { return false; }
        if self.org_upgrades.get(&public).is_some_and(|u| Arc::ptr_eq(&u.candidate.carrier, &carrier)) {
            return false; // an identical completion never re-arms its handshake
        }
        let incumbent_tunn = Arc::downgrade(&active.tunn);
        self.cancel_org_upgrade(&public);
        let mut candidate = self.make_carrier_peer(
            public, ip, carrier, true, self.disco_events_tx.clone(),
        );
        candidate.stats.org_role.store(true, Ordering::Relaxed);
        Self::drive_initiator_proof(&mut candidate);
        self.org_upgrades.insert(public, OrgUpgradePeer { candidate, incumbent_tunn });
        true
    }

    fn recovery_for(&mut self, public: [u8; 32], ip: Ipv4Addr) -> Arc<AtomicU64> {
        self.recovery.retain(|_, (_, hold)| hold.load(Ordering::Relaxed) > mono_ms_now() || Arc::strong_count(hold) > 1);
        let entry = self.recovery.entry(public).or_insert_with(|| (ip, Arc::new(AtomicU64::new(0))));
        if entry.0 != ip { *entry = (ip, Arc::new(AtomicU64::new(0))); }
        entry.1.clone()
    }
    pub(crate) fn org_recovery_until(&self, public: &[u8; 32]) -> Option<Instant> {
        let at = self.recovery.get(public)?.1.load(Ordering::Relaxed);
        (at != 0).then(|| wg_epoch() + Duration::from_millis(at))
    }
    pub(crate) fn finish_org_recovery_query(&self, public: &[u8;32]) -> bool {
        let Some((_,hold))=self.recovery.get(public) else {return true;};
        let at=hold.load(Ordering::Relaxed);
        if at>mono_ms_now() {return false;}
        hold.compare_exchange(at,0,Ordering::Relaxed,Ordering::Relaxed).is_ok()
    }
    pub(crate) fn org_recovery_held(&self, public: &[u8; 32]) -> bool {
        self.org_recovery_until(public).is_some_and(|until| Instant::now() < until)
    }

    #[cfg(test)]
    pub(crate) fn test_follow_capable(&self, public: &[u8;32]) -> bool {
        self.derp_follow.get(public).is_some_and(|s|s.capable)
    }
    #[cfg(test)]
    pub(crate) fn test_expire_recovery_hold(&self, public: &[u8;32]) {
        // Clock-boundary fixture only; never creates an INIT, proof or authorization.
        if let Some((_,at))=self.recovery.get(public) {at.store(mono_ms_now().saturating_sub(1).max(1),Ordering::Relaxed);}
    }
    pub(crate) fn set_peer_relay_role(&self, public: &[u8; 32], derp: bool, org: bool) {
        if let Some(p) = self.peers.get(public) {
            p.stats.derp_role.store(derp, Ordering::Relaxed);
            p.stats.org_role.store(org, Ordering::Relaxed);
        }
    }

    pub(crate) fn cancel_derp_follow(&mut self, public: &[u8; 32]) {
        self.derp_follow.remove(public);
        if let Some(p) = self.org_floor_receivers.get(public) {
            *p.stats.follow_init.lock().unwrap_or_else(|e|e.into_inner()) = None;
            *p.stats.follow_proof.lock().unwrap_or_else(|e|e.into_inner()) = None;
        }
    }

    pub(crate) fn peer_relay_addrs(&self, public: &[u8; 32]) -> (Option<SocketAddr>, Option<SocketAddr>) {
        match self.peers.get(public).map(|p| p.carrier.as_ref()) {
            Some(Carrier::Relay { conn, dst, .. }) => (conn.local_addr().ok(), Some(*dst)),
            _ => (None, None),
        }
    }

    /// Cheap control-loop poll. It never changes routing for an unanswered
    /// capability exchange, challenge, late packet, or bad authentication.
    pub(crate) fn poll_derp_follow(&mut self, public: &[u8; 32]) -> bool {
        let Some(active) = self.peers.get(public) else { return false; };
        let Some(floor) = self.org_floor_receivers.get(public) else { return false; };
        let Some(state) = self.derp_follow.get_mut(public) else { return false; };
        if !active.stats.org_role.load(Ordering::Relaxed)
            || !floor.stats.derp_role.load(Ordering::Relaxed)
            || !std::sync::Weak::ptr_eq(&state.org, &Arc::downgrade(&active.tunn))
            || !std::sync::Weak::ptr_eq(&state.floor, &Arc::downgrade(&floor.tunn))
        { return false; }
        if let Some(ack) = active.stats.follow_ack.lock().unwrap_or_else(|e|e.into_inner()).take()
            && state.hello.fresh() && state.hello.sent > 0
            && ack.kind == follow::Kind::HelloAck && ack.nonce == state.hello.nonce
            && ack.init == [0; 32]
        { state.capable = true; }

        let shared = super::disco::shared_secret(&self.secret, &PublicKey::from(*public));
        let send = self.send.clone();
        let self_public = self.public.to_bytes();
        let emit = |frame: follow::Frame, carrier: Arc<Carrier>, org: Arc<Mutex<Tunn>>, org_carrier: Arc<Carrier>| {
            if let Some(bytes) = follow::encode(&frame, &self_public, public, &shared) {
                let send = send.clone(); let public = *public;
                tokio::spawn(async move {
                    if !send.same_owner(&public, &org, &org_carrier, false) { return; }
                    let _ = tokio::time::timeout(Duration::from_millis(100), carrier.send(&bytes)).await;
                });
            }
        };
        if !state.capable {
            if state.hello.started.elapsed() >= Duration::from_secs(5) {
                state.hello = FollowRound::new([0; 32]);
            }
            if state.hello.due() {
                let frame = follow::Frame { kind: follow::Kind::Hello, nonce: state.hello.nonce, init: [0; 32] };
                state.hello.sent += 1; state.hello.last_sent = Some(Instant::now());
                emit(frame, active.carrier.clone(), active.tunn.clone(), active.carrier.clone());
            }
            // Unknown/old peer: no new packet is ever sent on DERP. Ordinary
            // carrier health remains solely responsible for fallback.
            return false;
        }
        let proof = floor.stats.follow_proof.lock().unwrap_or_else(|e|e.into_inner()).take();
        if let Some(proof) = proof
            && let Some(round) = state.pending.as_ref()
            && round.fresh() && round.sent > 0
            && proof.kind == follow::Kind::Proof && proof.nonce == round.nonce && proof.init == round.init
        {
            // Exclusive device owner; neither current Tunn can change between
            // the exact-owner check above and this atomic sender restoration.
            return self.restore_org_floor(public);
        }
        if state.pending.as_ref().is_some_and(|r| !r.fresh()) { state.pending = None; }
        if state.pending.is_none() && Instant::now() >= state.next_round
            && let Some((digest, at)) = floor.stats.follow_init.lock().unwrap_or_else(|e|e.into_inner()).take()
            && at.elapsed() < Duration::from_secs(5)
        {
            state.pending = Some(FollowRound::new(digest));
            state.next_round = Instant::now() + Duration::from_secs(5);
        }
        if let Some(round) = state.pending.as_mut() && round.due() {
            let frame = follow::Frame { kind: follow::Kind::Challenge, nonce: round.nonce, init: round.init };
            round.sent += 1; round.last_sent = Some(Instant::now());
            emit(frame, floor.carrier.clone(), active.tunn.clone(), active.carrier.clone());
        }
        false
    }

    fn restore_org_floor(&mut self, public: &[u8; 32]) -> bool {
        let Some(mut floor) = self.org_floor_receivers.remove(public) else { return false; };
        floor.stats.recovery_hold.fetch_max(mono_ms_now().saturating_add(60_000), Ordering::Relaxed);
        self.derp_follow.remove(public); // consume nonce before any new owner
        self.cancel_org_upgrade(public);
        floor.tasks.push(Self::spawn_carrier_timer(floor.tunn.clone(), floor.carrier.clone(), floor.stats.clone()));
        let (ip, tunn, carrier, stats) = (floor.overlay_ip, floor.tunn.clone(), floor.carrier.clone(), floor.stats.clone());
        if let Some(old_org) = self.peers.insert(*public, floor) { self.unregister_plane_route(&old_org); }
        self.send_install(*public, ip, tunn, carrier, stats);
        self.debug_assert_send_synced();
        true
    }


    pub(crate) fn org_upgrade_ready(&self, public: &[u8; 32]) -> bool {
        self.org_upgrades.get(public).is_some_and(|u| {
            !u.candidate.carrier.is_dead()
                && u.candidate.stats.hs_response_at.load(Ordering::Relaxed) != 0
                && self.peers.get(public).is_some_and(|p| {
                    p.overlay_ip == u.candidate.overlay_ip
                        && p.stats.recovery_hold.load(Ordering::Relaxed) <= mono_ms_now()
                        && std::sync::Weak::ptr_eq(&u.incumbent_tunn, &Arc::downgrade(&p.tunn))
                })
        })
    }

    pub(crate) fn cancel_org_upgrade(&mut self, public: &[u8; 32]) {
        if let Some(u) = self.org_upgrades.remove(public) {
            self.unregister_plane_route(&u.candidate);
        }
    }

    fn drop_org_floor_receiver(&mut self, public: &[u8; 32]) {
        self.derp_follow.remove(public);
        if let Some(p) = self.org_floor_receivers.remove(public) {
            self.unregister_plane_route(&p);
        }
    }

    pub(crate) fn promote_org_upgrade(&mut self, public: &[u8; 32]) -> bool {
        let sender = self.send.clone();
        let mut locked = sender.0.write().unwrap();
        if !self.org_upgrade_ready(public) { return false; }
        let u = self.org_upgrades.remove(public).expect("ready candidate");
        let candidate = u.candidate;
        let (ip, tunn, carrier, stats) = (candidate.overlay_ip,
            candidate.tunn.clone(), candidate.carrier.clone(), candidate.stats.clone());
        if let Some(mut old) = self.peers.insert(*public, candidate) {
            // make_carrier_peer owns [receive, timer]. Retain receive only;
            // old keepalives/retries must not imply that DERP remains active.
            for timer in old.tasks.drain(1..) { timer.abort(); }
            self.drop_org_floor_receiver(public);
            *old.stats.follow_init.lock().unwrap_or_else(|e| e.into_inner()) = None;
            *old.stats.follow_proof.lock().unwrap_or_else(|e| e.into_inner()) = None;
            self.derp_follow.insert(*public, DerpFollowState {
                org: Arc::downgrade(&tunn), floor: Arc::downgrade(&old.tunn),
                hello: FollowRound::new([0; 32]), capable: false, pending: None,
                next_round: Instant::now(),
            });
            self.org_floor_receivers.insert(*public, old);
        }
        Self::send_install_locked(&mut locked, *public, ip, tunn, carrier, stats);
        drop(locked);
        self.debug_assert_send_synced();
        true
    }

    fn drive_initiator_proof(candidate: &mut Peer) {
        // A candidate can establish as RESPONDER after its own initial init
        // was lost (e.g. before the peer bound). Boringtun then has a session
        // and need not retry our init, but promotion deliberately still needs
        // a response to OUR initiation. Recover that proof, never replace it
        // with the weaker responder latch or authenticated stateless echo.
        // This task owns only cloneable candidate fields, NOT Peer itself;
        // Peer::drop aborts it on retire/remove/rekey, with no ownership cycle.
        let (proof_tunn, proof_carrier, proof_stats) = (
            candidate.tunn.clone(),
            candidate.carrier.clone(),
            candidate.stats.clone(),
        );
        candidate.tasks.push(tokio::spawn(async move {
            let mut sent = 0u8;
            for _ in 0..8 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if proof_carrier.is_dead()
                    || proof_stats.hs_response_at.load(Ordering::Relaxed) != 0
                {
                    return;
                }
                if !proof_stats.handshake.load(Ordering::Relaxed) {
                    continue;
                }
                let out = {
                    let Ok(mut t) =
                        tokio::time::timeout(Duration::from_millis(100), proof_tunn.lock()).await
                    else {
                        continue;
                    };
                    if proof_stats.hs_response_at.load(Ordering::Relaxed) != 0 {
                        return;
                    }
                    let mut buf = vec![0u8; WG_BUF];
                    match t.format_handshake_initiation(&mut buf, true) {
                        TunnResult::WriteToNetwork(bytes) => Some(bytes.to_vec()),
                        _ => None,
                    }
                };
                if let Some(bytes) = out {
                    sent += 1;
                    if !proof_carrier.is_dead() {
                        let _ = tokio::time::timeout(
                            Duration::from_millis(100),
                            send_wg_recorded(&proof_carrier, &proof_stats, &bytes),
                        )
                        .await;
                    }
                    if sent >= 3 {
                        return;
                    }
                }
            }
        }));
    }

    /// Start a bilateral-protocol candidate. No router/send entry is changed.
    /// Only one trial per peer, and never start without a direct incumbent.
    pub(crate) fn start_path_trial(
        &mut self,
        trial: ObjectId,
        public: [u8; 32],
        ip: Ipv4Addr,
        carrier: Arc<Carrier>,
    ) -> bool {
        if self.path_trials.contains_key(&trial)
            || self.path_trials.values().any(|p| p.public_key == public)
        {
            return false;
        }
        let Some(active) = self.peers.get(&public) else {
            return false;
        };
        if !matches!(&*active.carrier, Carrier::Direct { .. }) || active.overlay_ip != ip {
            return false;
        }
        let incumbent_tunn = Arc::downgrade(&active.tunn);
        let (tx, pongs) = mpsc::channel(32);
        let mut candidate = self.make_carrier_peer(public, ip, carrier, true, tx);
        Self::drive_initiator_proof(&mut candidate);
        self.path_trials.insert(
            trial,
            PathTrialPeer {
                public_key: public,
                candidate: Some(candidate),
                incumbent: None,
                incumbent_tunn,
                committed_tunn: None,
                pongs,
                committed: false,
                returned: false,
            },
        );
        true
    }

    pub(crate) fn path_trial_handshake_done(&self, trial: ObjectId) -> bool {
        let Some(t) = self.path_trials.get(&trial) else {
            return false;
        };
        let peer = if t.committed {
            self.peers.get(&t.public_key).filter(|p| {
                t.committed_tunn.as_ref().is_some_and(|committed| {
                    std::sync::Weak::ptr_eq(committed, &Arc::downgrade(&p.tunn))
                })
            })
        } else {
            t.candidate.as_ref()
        };
        peer.is_some_and(|p| {
            !p.carrier.is_dead() && p.stats.hs_response_at.load(Ordering::Relaxed) != 0
        })
    }

    pub(crate) async fn send_path_trial_disco(
        &self,
        trial: ObjectId,
        bytes: &[u8],
    ) -> Option<SocketAddr> {
        let t = self.path_trials.get(&trial)?;
        let peer = if t.returned {
            t.incumbent.as_ref()?
        } else if t.committed {
            self.peers.get(&t.public_key)?
        } else {
            t.candidate.as_ref()?
        };
        let carrier = peer.carrier.clone();
        let dst = carrier.disco_endpoint();
        tokio::time::timeout(Duration::from_millis(100), carrier.send_disco(bytes))
            .await
            .ok()?
            .ok()
            .map(|_| dst)
    }

    /// The standing P2P endpoint has a separate Tunn and receive ownership;
    /// active relay probes must never be credited as P2P measurements.
    pub(crate) async fn send_path_trial_direct_disco(
        &self,
        trial: ObjectId,
        bytes: &[u8],
    ) -> Option<SocketAddr> {
        let t = self.path_trials.get(&trial)?;
        let p = if !t.committed || t.returned {
            self.peers.get(&t.public_key)?
        } else {
            t.incumbent.as_ref()?
        };
        if !p.carrier.is_direct() {
            return None;
        }
        let carrier = p.carrier.clone();
        let dst = carrier.disco_endpoint();
        tokio::time::timeout(Duration::from_millis(100), carrier.send_disco(bytes))
            .await
            .ok()?
            .ok()
            .map(|_| dst)
    }
    pub(crate) fn path_trial_direct_ready(&self, trial: ObjectId) -> bool {
        let Some(t) = self.path_trials.get(&trial) else {
            return false;
        };
        let direct = if !t.committed || t.returned {
            self.peers
                .get(&t.public_key)
                .filter(|p| std::sync::Weak::ptr_eq(&t.incumbent_tunn, &Arc::downgrade(&p.tunn)))
        } else {
            t.incumbent.as_ref()
        };
        direct.is_some_and(|p| {
            p.carrier.is_direct()
                && !p.carrier.is_dead()
                && p.stats.handshake.load(Ordering::Relaxed)
        })
    }
    /// Repair ONLY a retained direct shadow. The active relay/send triple and
    /// its authorization lifetime are untouched. Fresh Tunn/index/stats replace
    /// a conclusively dead or never-established session; no dead flag is reset.
    /// The caller still requires fresh paired quality and bilateral Return2PC.
    pub(crate) async fn rebuild_path_trial_direct(&mut self, trial: ObjectId) -> bool {
        if self.path_trial_direct_ready(trial) {
            return false;
        }
        let Some(t) = self.path_trials.get(&trial) else {
            return false;
        };
        if !t.committed || t.returned {
            return false;
        }
        let Some(active) = self.peers.get(&t.public_key) else {
            return false;
        };
        if active.carrier.is_direct()
            || active.carrier.is_dead()
            || !t
                .committed_tunn
                .as_ref()
                .is_some_and(|w| std::sync::Weak::ptr_eq(w, &Arc::downgrade(&active.tunn)))
        {
            return false;
        }
        let Some(old) = t.incumbent.as_ref() else {
            return false;
        };
        let Carrier::Direct { sock, dst, .. } = old.carrier.as_ref() else {
            return false;
        };
        // Reuse the CURRENT authenticated/roamed endpoint and its existing
        // interface socket. Socket/NIC rebuild belongs to the existing direct
        // plane executor, not a second network scheduler here.
        let (sock, dst, public, ip) = (
            sock.clone(),
            *dst.read().unwrap_or_else(|e| e.into_inner()),
            t.public_key,
            old.overlay_ip,
        );
        let Some(fresh) = self.make_direct_peer(sock, public, ip, dst, true).await else {
            return false;
        };
        let t = self
            .path_trials
            .get_mut(&trial)
            .expect("exclusive device owner");
        t.incumbent_tunn = Arc::downgrade(&fresh.tunn);
        let old = t
            .incumbent
            .replace(fresh)
            .expect("retained shadow checked above");
        // make_direct_peer may register the SAME source first. Exact Tunn/index
        // ownership prevents old cleanup deleting the new receiver registration.
        self.unregister_trial_owned(&old).await;
        drop(old);
        true
    }

    pub(crate) fn path_trial_direct_endpoint(&self, trial: ObjectId) -> Option<SocketAddr> {
        let t = self.path_trials.get(&trial)?;
        if t.returned || !t.committed {
            return None;
        }
        t.incumbent.as_ref()?.carrier.direct_dst()
    }

    #[cfg(any(test, feature = "path-trial-test-support"))]
    pub(crate) fn fail_retained_path_trial_direct(&self, trial: ObjectId) -> bool {
        let Some(t) = self.path_trials.get(&trial) else {
            return false;
        };
        if !t.committed || t.returned {
            return false;
        }
        let Some(p) = t.incumbent.as_ref() else {
            return false;
        };
        p.carrier.mark_dead();
        true
    }

    pub(crate) fn commit_path_trial_return(&mut self, trial: ObjectId) -> bool {
        // Echo quality cannot revive a dead/never-established retained Tunn.
        // Recheck at the actual atomic sender convergence, not just Ready.
        if !self.path_trial_direct_ready(trial) {
            return false;
        }
        let Some(t) = self.path_trials.get_mut(&trial) else {
            return false;
        };
        if !t.committed {
            return false;
        }
        let Some(current) = self.peers.get(&t.public_key) else {
            return false;
        };
        if t.returned {
            return std::sync::Weak::ptr_eq(&t.incumbent_tunn, &Arc::downgrade(&current.tunn));
        }
        if !t
            .committed_tunn
            .as_ref()
            .is_some_and(|w| std::sync::Weak::ptr_eq(w, &Arc::downgrade(&current.tunn)))
        {
            return false;
        }
        let Some(direct) = t.incumbent.take() else {
            return false;
        };
        let (ip, tunn, carrier, stats) = (
            direct.overlay_ip,
            direct.tunn.clone(),
            direct.carrier.clone(),
            direct.stats.clone(),
        );
        t.incumbent = self.peers.insert(t.public_key, direct);
        t.returned = true;
        let public = t.public_key;
        self.send_install(public, ip, tunn, carrier, stats);
        self.debug_assert_send_synced();
        true
    }
    pub(crate) fn abort_path_trial_return(&mut self, trial: ObjectId) -> bool {
        let Some(t) = self.path_trials.get_mut(&trial) else {
            return false;
        };
        if !t.returned {
            return true;
        }
        let Some(current) = self.peers.get(&t.public_key) else {
            return false;
        };
        if !std::sync::Weak::ptr_eq(&t.incumbent_tunn, &Arc::downgrade(&current.tunn)) {
            return false;
        }
        let Some(relay) = t.incumbent.take() else {
            return false;
        };
        if !t
            .committed_tunn
            .as_ref()
            .is_some_and(|w| std::sync::Weak::ptr_eq(w, &Arc::downgrade(&relay.tunn)))
        {
            t.incumbent = Some(relay);
            return false;
        }
        let (ip, tunn, carrier, stats) = (
            relay.overlay_ip,
            relay.tunn.clone(),
            relay.carrier.clone(),
            relay.stats.clone(),
        );
        t.incumbent = self.peers.insert(t.public_key, relay);
        t.returned = false;
        let public = t.public_key;
        self.send_install(public, ip, tunn, carrier, stats);
        self.debug_assert_send_synced();
        true
    }
    pub(crate) fn finalize_path_trial_return(&mut self, trial: ObjectId) -> bool {
        let Some(t) = self.path_trials.get(&trial) else {
            return false;
        };
        if !t.returned
            || !self.peers.get(&t.public_key).is_some_and(|p| {
                std::sync::Weak::ptr_eq(&t.incumbent_tunn, &Arc::downgrade(&p.tunn))
            })
        {
            return false;
        }
        let mut t = self.path_trials.remove(&trial).unwrap();
        if let Some(relay) = t.incumbent.take() {
            self.unregister_plane_route(&relay);
        }
        true
    }

    /// Separate sink means a candidate pong can never be mistaken for an
    /// active-path pong, even if physical/synthetic endpoint numbers coincide.
    pub(crate) fn drain_path_trial_disco(
        &mut self,
        trial: ObjectId,
    ) -> Vec<super::disco::DiscoInbound> {
        let Some(t) = self.path_trials.get_mut(&trial) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        while let Ok(p) = t.pongs.try_recv() {
            out.push(p);
        }
        out
    }

    /// Called ONLY after the runtime validates a fresh bilateral Commit.
    /// Exact incumbent Tunn identity prevents a late commit overwriting a
    /// recovered/rekeyed/reinstalled path; handshake alone never authorizes it.
    pub(crate) fn commit_path_trial(&mut self, trial: ObjectId) -> bool {
        if !self.path_trial_handshake_done(trial) {
            return false;
        }
        let Some(t) = self.path_trials.get_mut(&trial) else {
            return false;
        };
        if t.committed {
            return true;
        }
        let Some(current) = self.peers.get(&t.public_key) else {
            return false;
        };
        if !std::sync::Weak::ptr_eq(&t.incumbent_tunn, &Arc::downgrade(&current.tunn)) {
            return false;
        }
        let Some(candidate) = t.candidate.take() else {
            return false;
        };
        let (ip, tunn, carrier, stats) = (
            candidate.overlay_ip,
            candidate.tunn.clone(),
            candidate.carrier.clone(),
            candidate.stats.clone(),
        );
        t.committed_tunn = Some(Arc::downgrade(&tunn));
        t.incumbent = self.peers.insert(t.public_key, candidate);
        t.committed = true;
        let public = t.public_key;
        // DO NOT unregister/drop the incumbent. Its receive path must remain
        // valid while the other end is still prepared and sends over direct.
        self.send_install(public, ip, tunn, carrier, stats);
        self.debug_assert_send_synced();
        true
    }

    pub(crate) fn finalize_path_trial(&mut self, trial: ObjectId) -> bool {
        if !self.path_trials.get(&trial).is_some_and(|t| t.committed) {
            return false;
        }
        // Preserve incumbent receiver/identity until negotiated return or revoke.
        true
    }

    /// Strict authorization/identity retirement. Never rolls the old peer back.
    /// Returns true only if this trial owned and removed the active sender.
    async fn unregister_trial_owned(&self, p: &Peer) {
        if let (Some(index), Some(plane)) = (p.plane_idx, &self.plane) {
            plane.unregister_route(index);
        }
        if p.plane_idx.is_some() {
            return;
        }
        if p.direct_src.is_none() && p.direct_index.is_none() {
            return;
        }
        let Some(demux) = &self.direct else { return };
        let roam = p.direct_index.and_then(|idx| {
            demux
                .index_routes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&idx)
                .map(|s| s.src)
        });
        let mut routes = demux.routes.lock().await;
        for src in [p.direct_src, roam].into_iter().flatten() {
            if routes
                .get(&src)
                .is_some_and(|(tunn, _)| Arc::ptr_eq(tunn, &p.tunn))
            {
                routes.remove(&src);
            }
        }
    }

    pub(crate) async fn retire_path_trial(&mut self, trial: ObjectId) -> bool {
        let Some(mut t) = self.path_trials.remove(&trial) else {
            return false;
        };
        let owned = t.committed
            && self.peers.get(&t.public_key).is_some_and(|p| {
                if t.returned {
                    std::sync::Weak::ptr_eq(&t.incumbent_tunn, &Arc::downgrade(&p.tunn))
                } else {
                    t.committed_tunn
                        .as_ref()
                        .is_some_and(|x| std::sync::Weak::ptr_eq(x, &Arc::downgrade(&p.tunn)))
                }
            });
        // Remove the send route before awaiting demux cleanup. Exact Tunn
        // ownership prevents a stale trial from touching a newer same-key peer.
        let active = if owned {
            let p = self.peers.remove(&t.public_key);
            self.send_uninstall(&t.public_key);
            p
        } else {
            None
        };
        if let Some(p) = t.candidate.take() {
            self.unregister_trial_owned(&p).await;
        }
        if let Some(p) = t.incumbent.take() {
            self.unregister_trial_owned(&p).await;
        }
        if let Some(p) = active {
            self.unregister_trial_owned(&p).await;
        }
        owned
    }

    pub(crate) fn abort_path_trial(&mut self, trial: ObjectId) -> bool {
        let Some(mut t) = self.path_trials.remove(&trial) else {
            return false;
        };
        if !t.committed {
            if let Some(candidate) = t.candidate.take() {
                self.unregister_plane_route(&candidate);
            }
            return true;
        }
        let current_matches = self.peers.get(&t.public_key).is_some_and(|p| {
            t.committed_tunn.as_ref().is_some_and(|committed| {
                std::sync::Weak::ptr_eq(committed, &Arc::downgrade(&p.tunn))
            })
        });
        if !current_matches {
            if let Some(old) = t.incumbent.take() {
                self.unregister_plane_route(&old);
            }
            return false; // never restore over an unrelated newer install
        }
        let Some(old) = t.incumbent.take() else {
            return false;
        };
        let (ip, tunn, carrier, stats) = (
            old.overlay_ip,
            old.tunn.clone(),
            old.carrier.clone(),
            old.stats.clone(),
        );
        if let Some(candidate) = self.peers.insert(t.public_key, old) {
            self.unregister_plane_route(&candidate);
            self.path_trial_drains.insert(
                trial,
                (
                    t.public_key,
                    Instant::now() + Duration::from_secs(10),
                    candidate,
                ),
            );
        }
        self.send_install(t.public_key, ip, tunn, carrier, stats);
        self.debug_assert_send_synced();
        true
    }

    pub(crate) fn reap_path_trial_drains(&mut self, now: Instant) {
        self.path_trial_drains
            .retain(|_, (_, until, _)| now < *until);
    }

    async fn discard_path_trials_for(&mut self, public: &[u8; 32]) {
        let ids: Vec<_> = self
            .path_trials
            .iter()
            .filter(|(_, t)| &t.public_key == public)
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            if let Some(t) = self.path_trials.remove(&id) {
                if let Some(p) = t.candidate {
                    self.unregister_trial_owned(&p).await;
                }
                if let Some(p) = t.incumbent {
                    self.unregister_trial_owned(&p).await;
                }
            }
        }
        self.path_trial_drains.retain(|_, (p, _, _)| p != public);
    }

    /// rc.134 — ensure the shared direct-LAN socket + its demux loop exist.
    /// Idempotent; the first direct peer triggers it. The demux loop reads the
    /// socket forever and routes each datagram to the peer matching its source
    /// address (replacing the per-peer recv loop for direct carriers).
    pub fn ensure_direct_demux(&mut self, sock: Arc<UdpSocket>) {
        if self.plane.is_some() {
            // Multi-org v2 — the plane owns the recv loops on its shared
            // sockets; a per-device source-keyed loop double-reading them
            // would steal datagrams from every other attached engine.
            return;
        }
        let local = match sock.local_addr() {
            Ok(a) => a,
            Err(e) => {
                warn!(%e, "wg: direct socket has no local_addr; skipping demux loop");
                return;
            }
        };
        let tun_tx = self.tun_tx.clone();
        // C1 — captured BEFORE the `&mut self` demux borrow below.
        let secret_for_disco = self.secret.clone();
        let public_for_disco = self.public;
        let send_for_disco = self.send.clone();
        let demux = self.direct.get_or_insert_with(|| DirectDemux {
            routes: Arc::new(Mutex::new(HashMap::new())),
            socks: Vec::new(),
            tasks: Vec::new(),
            stats: Vec::new(),
            index_routes: Arc::new(std::sync::Mutex::new(HashMap::new())),
        });
        // One recv loop per interface socket, all feeding the shared `routes`.
        // Idempotent per interface so repeated installs don't spawn duplicates.
        if demux
            .socks
            .iter()
            .any(|s| s.local_addr().map(|a| a == local).unwrap_or(false))
        {
            return;
        }
        let stat = super::direct::SockStat::new(local.to_string());
        let task = tokio::spawn(run_direct_demux(
            sock.clone(),
            demux.routes.clone(),
            demux.index_routes.clone(),
            secret_for_disco,
            public_for_disco,
            send_for_disco,
            self.disco_events_tx.clone(),
            tun_tx,
            self.direct_events_tx.clone(),
            self.stun_events_tx.clone(),
            stat.clone(),
        ));
        demux.socks.push(sock);
        demux.tasks.push(task);
        demux.stats.push(stat);
    }

    /// R2 — retire one direct socket's demux slot: abort its recv loop and
    /// drop the slot's socket Arc. Without this, a direct-plane rebuild that
    /// re-binds the SAME stable `ip:port` is silently defeated by
    /// [`ensure_direct_demux`]'s local-addr dedupe — the rebuilt socket is
    /// treated as already-demuxed while the DEAD socket keeps the slot (and
    /// the port, until every Arc holder is gone). Per-peer `routes` entries
    /// are NOT touched here: they belong to carriers, and the rebuild tears
    /// those down via `remove_peer` (which unregisters its own route) before
    /// retiring sockets. `true` when a slot was found.
    pub fn retire_direct_socket(&mut self, local: SocketAddr) -> bool {
        let Some(demux) = &mut self.direct else {
            return false;
        };
        let Some(i) = demux
            .socks
            .iter()
            .position(|s| s.local_addr().map(|a| a == local).unwrap_or(false))
        else {
            return false;
        };
        // `socks`/`tasks`/`stats` are pushed in lockstep (above), so index
        // `i` names every half of the slot.
        demux.socks.remove(i);
        demux.tasks.remove(i).abort();
        demux.stats.remove(i);
        true
    }

    /// PR-B1 — per-socket receive liveness for `NodeStatus.direct_socks`
    /// (device mode; the plane twin is `CarrierPlane::socket_stats`).
    pub fn direct_sock_stats(&self) -> Vec<crate::localapi::DirectSockStatus> {
        self.direct
            .as_ref()
            .map(|d| d.stats.iter().map(|s| s.status()).collect())
            .unwrap_or_default()
    }

    /// Phase A — process ONE datagram for an already-registered direct route
    /// (the runtime calls this right after installing/re-pointing a peer from a
    /// [`DirectInbound`] event, so the very initiation that triggered the event
    /// is answered immediately instead of waiting ~5 s for the initiator's
    /// retransmit). No-op if `src` has no route (nothing was installed).
    pub async fn feed_direct(&self, src: SocketAddr, sock: Arc<UdpSocket>, packet: &[u8]) {
        if let Some(h) = &self.plane {
            h.feed(src, sock, packet).await;
            return;
        }
        let Some(demux) = &self.direct else {
            return;
        };
        let entry = demux.routes.lock().await.get(&src).cloned();
        let Some((tunn, ingress)) = entry else {
            return;
        };
        let reply = Carrier::direct(sock, src);
        let mut buf = packet.to_vec();
        let n = buf.len();
        let mut t = tunn.lock().await;
        process_inbound(&mut t, n, &mut buf, &reply, &self.tun_tx, &ingress).await;
    }

    /// rc.134 — install a peer reached over the SHARED direct socket. Its
    /// inbound is handled by the device's single demux loop (routed by source
    /// address), so N direct peers share one socket without racing — unlike
    /// `add_peer`, which spawns a per-peer recv loop. `ensure_direct_demux`
    /// must have run. `initiate` ⇒ send a handshake init now (direct carriers
    /// initiate bilaterally so both firewalls open — rc.133).
    pub async fn add_direct_peer(
        &mut self,
        sock: Arc<UdpSocket>,
        peer_public: [u8; 32],
        overlay_ip: Ipv4Addr,
        dst: SocketAddr,
        initiate: bool,
    ) {
        self.cancel_org_upgrade(&peer_public);
        self.drop_org_floor_receiver(&peer_public);
        if let Some(peer) = self
            .make_direct_peer(sock, peer_public, overlay_ip, dst, initiate)
            .await
        {
            let (tunn, carrier, stats) =
                (peer.tunn.clone(), peer.carrier.clone(), peer.stats.clone());
            if let Some(old) = self.peers.insert(peer_public, peer) {
                self.unregister_plane_route(&old);
            }
            self.send_install(peer_public, overlay_ip, tunn, carrier, stats);
            self.debug_assert_send_synced();
        }
    }

    /// Build a direct-carrier [`Peer`] (fresh `Tunn` + demux registration +
    /// keepalive/retransmit timer task; a handshake init when `initiate`).
    /// Shared by [`add_direct_peer`] (installs into the routing `peers` map) and
    /// [`start_direct_probe`] (installs into the shadow `probes` map). `None` if
    /// the direct demux hasn't been set up — `ensure_direct_demux` must precede.
    async fn make_direct_peer(
        &mut self,
        sock: Arc<UdpSocket>,
        peer_public: [u8; 32],
        overlay_ip: Ipv4Addr,
        dst: SocketAddr,
        initiate: bool,
    ) -> Option<Peer> {
        if self.plane.is_none() && self.direct.is_none() {
            warn!("wg: make_direct_peer before ensure_direct_demux; ignoring");
            return None;
        }
        // Send from the interface-bound socket that shares the peer's subnet
        // (rc.143) — forces egress out the right NIC past a full-tunnel VPN.
        let carrier = Carrier::direct(sock, dst);

        let index = self.alloc_index();
        let tunn = Arc::new(Mutex::new(Tunn::new(
            self.secret.clone(),
            PublicKey::from(peer_public),
            None,
            Some(KEEPALIVE_SECS),
            index,
            None,
        )));

        let stats = Arc::new(PeerStats { recovery_hold: self.recovery_for(peer_public, overlay_ip), ..PeerStats::default() });
        let ingress = self.ingress_for(peer_public, stats.clone());
        // Register for demux BEFORE the handshake so inbound is routed —
        // on the plane by session index (unique across every attached
        // engine), else in the device's source-keyed table. Both register
        // the carrier weakly (A3) so an authenticated roam can repoint the
        // outbound in place without a runtime round-trip.
        let (plane_idx, direct_index) = match &self.plane {
            Some(h) => {
                h.register_route(index, tunn.clone(), ingress, dst, Arc::downgrade(&carrier));
                (Some(index), None)
            }
            None => {
                let demux = self.direct.as_ref().expect("checked above");
                demux
                    .routes
                    .lock()
                    .await
                    .insert(dst, (tunn.clone(), ingress));
                demux
                    .index_routes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        index,
                        IndexSlot {
                            src: dst,
                            carrier: Arc::downgrade(&carrier),
                            last_roam: None,
                        },
                    );
                (None, Some(index))
            }
        };

        // Timer task only — no recv task; the shared demux loop delivers
        // this peer's inbound.
        let timer_tunn = tunn.clone();
        let timer_carrier = carrier.clone();
        let timer_stats = stats.clone();
        let timer_task = tokio::spawn(async move {
            let mut buf = vec![0u8; WG_BUF];
            let mut tick = tokio::time::interval(Duration::from_millis(TIMER_TICK_MS));
            loop {
                tick.tick().await;
                // rc.211 — capture the handshake/keepalive bytes UNDER the
                // lock, then RELEASE it before the carrier send. Holding the
                // per-peer Tunn lock across `carrier.send().await` (a slow
                // relay/QUIC send under churn) stalls every other task that
                // needs the same Tunn — including the SHARED direct recv loop,
                // which then stops reading the socket and the OS drops inbound
                // UDP for ALL direct peers.
                let out = {
                    let mut t = timer_tunn.lock().await;
                    match t.update_timers(&mut buf) {
                        TunnResult::WriteToNetwork(b) => Some(b.to_vec()),
                        // boringtun gives up re-handshaking once a rekey
                        // attempt expires and reports the session over. That
                        // verdict is conclusive, and dropping it (as this arm
                        // did) left the carrier to be rediscovered the slow
                        // way, by the rx-staleness bound.
                        TunnResult::Err(WireGuardError::ConnectionExpired) => {
                            timer_carrier.mark_dead();
                            None
                        }
                        _ => None,
                    }
                };
                if let Some(b) = out {
                    let _ = send_wg_recorded(&timer_carrier, &timer_stats, &b).await;
                }
            }
        });

        if initiate {
            let it = tunn.clone();
            let ic = carrier.clone();
            let init_stats = stats.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; WG_BUF];
                // rc.211 — same lock-then-send split as the timer tasks.
                let out = {
                    let mut t = it.lock().await;
                    match t.format_handshake_initiation(&mut buf, false) {
                        TunnResult::WriteToNetwork(b) => Some(b.to_vec()),
                        _ => None,
                    }
                };
                if let Some(b) = out {
                    let _ = send_wg_recorded(&ic, &init_stats, &b).await;
                }
            });
        }

        Some(Peer {
            tunn,
            carrier,
            overlay_ip,
            tasks: vec![timer_task],
            stats,
            direct_src: Some(dst),
            plane_idx,
            direct_index,
        })
    }

    /// Make-before-break (rc.208) — start a shadow direct-carrier PROBE for a
    /// peer that currently has an ACTIVE carrier (typically relay). The probe
    /// gets its own `Tunn` toward `dst`, but is held in `probes` (NOT the routing
    /// `peers` map), so the peer's traffic keeps flowing over its active carrier,
    /// untouched. Promote with [`promote_direct_probe`] once
    /// [`probe_handshake_done`] latches (proof the direct path works BOTH ways),
    /// or drop it with [`drop_direct_probe`] on the tier deadline — the active
    /// carrier never stalls. Idempotent: replaces any prior probe for this peer.
    ///
    /// `initiate` ⇒ send a handshake init now (the OUTBOUND upgrade — we dial the
    /// peer). `false` ⇒ don't initiate (the INBOUND accept — the peer already
    /// sent us an init; the caller answers it via [`feed_direct`] on the probe's
    /// `dst`, which the probe registered in the demux).
    pub async fn start_direct_probe(
        &mut self,
        sock: Arc<UdpSocket>,
        peer_public: [u8; 32],
        overlay_ip: Ipv4Addr,
        dst: SocketAddr,
        initiate: bool,
    ) {
        self.drop_direct_probe(&peer_public).await;
        if let Some(peer) = self
            .make_direct_peer(sock, peer_public, overlay_ip, dst, initiate)
            .await
        {
            // Deliberately NOT added to the router — routing stays on the active
            // (relay) peer in `peers` until this probe is promoted.
            self.probes.insert(peer_public, peer);
        }
    }

    /// Make-before-break — has the shadow probe for `peer_public` completed its
    /// WG handshake? A latched handshake means our INIT reached the peer AND its
    /// response reached us, so the direct path is proven BIDIRECTIONAL. `None`
    /// when no probe is in flight.
    pub fn probe_handshake_done(&self, peer_public: &[u8; 32]) -> Option<bool> {
        Some(
            self.probes
                .get(peer_public)?
                .stats
                .handshake
                .load(Ordering::Relaxed),
        )
    }

    /// Make-before-break — is a shadow probe in flight for `peer_public`?
    pub fn has_direct_probe(&self, peer_public: &[u8; 32]) -> bool {
        self.probes.contains_key(peer_public)
    }

    /// P3 PR-B — the probe's REAL latch latency: ms between `since` (the
    /// probe start the runtime recorded) and the instant `process_inbound`
    /// latched its handshake. `None` while unlatched or with no probe in
    /// flight. Read BEFORE [`promote_direct_probe`](Self::promote_direct_probe)
    /// — the promote moves the probe out of the probes map.
    pub fn probe_handshake_latency_ms(
        &self,
        peer_public: &[u8; 32],
        since: Instant,
    ) -> Option<u64> {
        let at = self
            .probes
            .get(peer_public)?
            .stats
            .handshake_at
            .load(Ordering::Relaxed);
        if at == 0 {
            return None;
        }
        let since_ms = since.saturating_duration_since(wg_epoch()).as_millis() as u64;
        Some(at.saturating_sub(since_ms))
    }

    /// Make-before-break — promote a latched probe to the ACTIVE carrier: the
    /// probe `Tunn` replaces the peer's current carrier in the routing `peers`
    /// map, and the old carrier is dropped (its `Peer::drop` aborts the recv/
    /// timer tasks). The probe's demux registration stays — it is the active
    /// carrier's inbound now. `false` if there was no probe. The caller updates
    /// its own per-peer bookkeeping and forgets the now-unused relay allocation.
    pub fn promote_direct_probe(&mut self, peer_public: &[u8; 32]) -> bool {
        if let Some(probe) = self.probes.remove(peer_public) {
            self.cancel_org_upgrade(peer_public);
            self.drop_org_floor_receiver(peer_public);
            let overlay_ip = probe.overlay_ip;
            let (tunn, carrier, stats) = (
                probe.tunn.clone(),
                probe.carrier.clone(),
                probe.stats.clone(),
            );
            // Insert replaces + drops the old (relay) peer; Drop aborts its task.
            if let Some(old) = self.peers.insert(*peer_public, probe) {
                self.unregister_plane_route(&old);
            }
            // P1 (S6) — swap the pump's view atomically: the whole triple
            // replaces the old one under a single write lock.
            self.send_install(*peer_public, overlay_ip, tunn, carrier, stats);
            self.debug_assert_send_synced();
            true
        } else {
            false
        }
    }

    /// Make-before-break — discard the shadow probe for `peer_public` (handshake
    /// never latched within the deadline ⇒ the direct path is unreachable).
    /// Un-registers its demux entry and aborts its timer task; the ACTIVE carrier
    /// is untouched, so there is no stall. No-op if there is no probe.
    pub async fn drop_direct_probe(&mut self, peer_public: &[u8; 32]) {
        if let Some(probe) = self.probes.remove(peer_public) {
            self.unregister_direct(&probe).await;
        }
    }

    /// Did an MBB upgrade probe hear ANYTHING back from the far end?
    ///
    /// Non-draining, unlike `peer_take_rx_any` (single-consumer, owned by the
    /// health sweep). This is the field that splits a probe failure into the
    /// two cases that imply DIFFERENT fixes: nothing heard ⇒ the two ends'
    /// probe windows are not aligned; something heard but no session ⇒ the
    /// handshake deadline is too tight. `did not handshake within deadline`
    /// alone cannot tell them apart, which is why a 4.7-minute convergence on
    /// a 4 ms LAN path could not be explained from the log (2026-08-13).
    pub fn probe_saw_inbound(&self, peer_public: &[u8; 32]) -> bool {
        self.probes.get(peer_public).is_some_and(|p| {
            p.stats.rx_any.load(Ordering::Relaxed) > 0
                || p.stats.rx.load(Ordering::Relaxed) > 0
                || p.stats.handshake.load(Ordering::Relaxed)
        })
    }

    /// Test-only: latch a probe's handshake-done flag without a live two-device
    /// session (mirrors [`test_latch_handshake_done`] for the shadow map).
    #[cfg(test)]
    pub fn test_latch_probe_handshake_done(&self, peer_public: &[u8; 32]) {
        if let Some(p) = self.probes.get(peer_public) {
            p.stats.handshake.store(true, Ordering::Relaxed);
            p.stats
                .handshake_at
                .store(mono_ms_now().max(1), Ordering::Relaxed);
        }
    }

    /// Test-only: number of shadow probes currently in flight.
    #[cfg(test)]
    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }

    /// Which peer the crypto-router currently resolves `ip` to — so the
    /// recycled-address tests can assert the routing table directly.
    #[cfg(test)]
    pub fn test_route(&self, ip: &Ipv4Addr) -> Option<[u8; 32]> {
        self.send.0.read().unwrap().router.route(ip)
    }

    /// Remove a peer (drops its `Tunn` + aborts its tasks + clears its
    /// route). Used when the netmap drops a peer (ACL change / leave) or to
    /// re-install it with a different carrier (relay→direct upgrade, rc.134).
    /// `async` because un-registering a shared-direct peer locks the demux
    /// routing table.
    pub async fn remove_peer(&mut self, peer_public: &[u8; 32]) {
        self.cancel_org_upgrade(peer_public);
        self.drop_org_floor_receiver(peer_public);
        // Withdraw the sender before any asynchronous backup demux cleanup.
        let active = self.peers.remove(peer_public);
        if active.is_some() {
            self.send_uninstall(peer_public);
            self.debug_assert_send_synced();
        }
        self.discard_path_trials_for(peer_public).await;
        if let Some(p) = active {
            self.unregister_direct(&p).await;
        }
    }

    /// Phase 1 — set the subnet routes a peer is a router for, so packets to
    /// those CIDRs are encapsulated to it (longest-prefix after the host `/32`s).
    /// Replaces any previously-set subnets for the peer; empty clears them.
    ///
    /// Passes through [`set_subnets`](super::router::Router::set_subnets)'s
    /// duplicate-claim report — CIDRs
    /// another peer also claims. Callers must log it (never a silent drop):
    /// the router keeps both claims and tie-breaks deterministically, but a
    /// duplicate claim means one claimant's traffic is being RPF-denied.
    pub fn set_peer_subnets(
        &mut self,
        peer_public: [u8; 32],
        subnets: &[super::router::Cidr],
    ) -> Vec<(super::router::Cidr, [u8; 32])> {
        self.send
            .0
            .write()
            .unwrap()
            .router
            .set_subnets(peer_public, subnets)
    }

    /// P5/S3b exit-node — route this node's GLOBAL IPv6 egress through `pubkey`
    /// (or `None` to clear → global v6 drops fail-closed). Set by the exit-routing
    /// reconcile once the v6 carrier exemptions are pinned.
    pub fn set_v6_exit(&mut self, pubkey: Option<[u8; 32]>) {
        self.send.0.write().unwrap().router.set_v6_exit(pubkey);
    }

    /// The current global-v6 exit peer's pubkey, if any — lets the reconcile
    /// re-assert it (idempotent) after a `remove_peer` may have cleared it.
    pub fn v6_exit(&self) -> Option<[u8; 32]> {
        self.send.0.read().unwrap().router.v6_exit()
    }

    /// The subnet routes a peer holds right now — lets the exit reconcile see
    /// that a re-install replaced the split-default it set (FR-97).
    pub fn peer_subnets(&self, peer_public: &[u8; 32]) -> Vec<super::router::Cidr> {
        self.send.0.read().unwrap().router.subnets_of(peer_public)
    }

    /// Number of installed peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Encapsulate + send a raw IP packet to whichever peer owns its destination.
    /// P1 (S6) — delegates to the shared [`WgSender`] so this is structurally
    /// the SAME implementation the outbound pump runs (one send path).
    pub async fn send_ip_packet(&self, packet: &[u8]) -> bool {
        self.send.send_ip_packet(packet).await
    }

    /// A burst of outbound IP packets through the shared [`WgSender`].
    pub async fn send_ip_batch(&self, packets: &[Vec<u8>]) -> usize {
        self.send.send_ip_batch(packets).await
    }

    /// Encapsulate + send `packet` to a specific peer. `false` if the
    /// peer is unknown, the handshake hasn't completed, or the carrier send
    /// failed. P1 (S6) — delegates to the shared [`WgSender`].
    pub async fn send_to_peer(&self, peer_public: &[u8; 32], packet: &[u8]) -> bool {
        self.send.send_to_peer(peer_public, packet).await
    }

    /// Whether a WG session to `peer_public` has completed a handshake.
    /// Tests poll this to know when data will flow.
    pub async fn is_connected(&self, peer_public: &[u8; 32]) -> bool {
        let Some(peer) = self.peers.get(peer_public) else {
            return false;
        };
        peer.tunn.lock().await.time_since_last_handshake().is_some()
    }

    /// rc.137 — LOCK-FREE `(tx, rx)` IP-packet counts for `peer_public`
    /// (`None` if unknown). Read by the runtime's fallback sweep WITHOUT
    /// locking the `Tunn`, so the periodic health check can't stall the packet
    /// path (the rc.136 regression). `tx` climbing while `rx` is flat ⇒ the
    /// carrier is one-way / dead ⇒ fall back to relay.
    pub fn peer_traffic(&self, peer_public: &[u8; 32]) -> Option<(u64, u64)> {
        let peer = self.peers.get(peer_public)?;
        Some((
            peer.stats.tx.load(Ordering::Relaxed),
            peer.stats.rx.load(Ordering::Relaxed),
        ))
    }

    /// rc.206 — consume and return how many authenticated inbound packets we've
    /// heard from this peer since the last call (see `PeerStats::rx_any`),
    /// resetting the counter to 0. The health sweep calls this once per peer per
    /// tick: a non-zero result means the carrier is genuinely alive — even if the
    /// only inbound was content-free keepalives — so it advances `last_rx_at`
    /// (which the rx-staleness watchdog reads). Returns 0 for an unknown peer.
    /// Single-consumer by contract: only the sweep calls it (the swap resets it).
    /// P4 — how many inbound packets from `peer_public` failed the reverse-path
    /// check since it was installed (see [`PeerStats::rx_denied`]). Monotonic,
    /// never drained: a non-zero read means this peer has sourced addresses it
    /// does not own, whether or not the mode actually dropped them. 0 for an
    /// unknown peer.
    pub fn peer_rx_denied(&self, peer_public: &[u8; 32]) -> u64 {
        self.peers
            .get(peer_public)
            .map(|p| p.stats.rx_denied.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// The peer's passive WG loss counters ([`PeerStats::note_rx_counter`]):
    /// `(counter span, packets accepted)`, both monotonic. Over an interval,
    /// `span − accepted` is what the peer sent that never authenticated here.
    /// `None` for an unknown peer.
    pub fn peer_rx_loss(&self, peer_public: &[u8; 32]) -> Option<(u64, u64)> {
        self.peers.get(peer_public).map(|p| {
            (
                p.stats.rx_ctr_span.load(Ordering::Relaxed),
                p.stats.rx_ctr_accepted.load(Ordering::Relaxed),
            )
        })
    }

    /// The subset of [`Self::peer_rx_denied`] whose reason was `Rpf(NoRoute)`:
    /// packets from a source NO installed peer owns, i.e. flows whose replies
    /// this node cannot route back — they fail silently even in `warn`. The
    /// signature of a multi-org sender whose OS picked the wrong org's
    /// overlay address (field 2026-08-09). Monotonic; 0 for an unknown peer.
    pub fn peer_rx_denied_noroute(&self, peer_public: &[u8; 32]) -> u64 {
        self.peers
            .get(peer_public)
            .map(|p| p.stats.rx_denied_noroute.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// P4 — the device's reverse-path mode, for status/diagnostics.
    pub fn rpf_mode(&self) -> RpfMode {
        self.rpf
    }

    /// P4 — publish this node's own destination scope: its overlay address plus
    /// the subnets it advertises. Called once at overlay bring-up, from the same
    /// `advertised_routes` that `overlay::nat::enable` provisions forwarding for
    /// — so the filter and the forwarding it guards can never disagree.
    ///
    /// Before this runs the scope is [`LocalScope::default`], which is
    /// UNCONSTRAINED — the bring-up window fails open rather than blackholing
    /// every destination while the node's own address is still unknown.
    pub fn set_local_scope(&mut self, self_ip: Option<Ipv4Addr>, advertised_routes: &[String]) {
        let scope = LocalScope::new(self_ip, advertised_routes);
        tracing::info!(
            ?self_ip,
            routes = advertised_routes.len(),
            unconstrained = scope.is_unconstrained(),
            "overlay: ingress destination scope set"
        );
        self.send.0.write().unwrap().scope = scope;
    }

    /// P4 — replace the per-source ingress rule table from the current netmap.
    ///
    /// Rebuilt WHOLESALE on every netmap/delta rather than patched per install,
    /// which is what keeps it correct: the table is keyed by pubkey, and a peer
    /// whose grant was revoked must lose its entry even though no install or
    /// removal happened for it. Rebuilding is O(peers) on a control-plane
    /// event, never on the packet path.
    ///
    /// A peer whose entry carries `ingress_rules: None` (the ACL compiled
    /// nothing — pre-P4 server, or the tenant isn't enforcing) gets NO entry, so
    /// only the coarse [`LocalScope`] applies to it. `Some(vec![])` DOES get an
    /// entry, and denies everything it forwards — that distinction is the whole
    /// reason the wire field is an `Option`.
    pub fn sync_peer_ingress(
        &mut self,
        peers: &HashMap<bson::oid::ObjectId, roomler_ai_remote_control::signaling::NetmapPeer>,
    ) {
        let mut table: HashMap<[u8; 32], Arc<Vec<OverlayRule>>> = HashMap::new();
        for p in peers.values() {
            let (Some(rules), Some(pk)) = (
                p.ingress_rules.as_ref(),
                super::decode_public(&p.wg_public_key),
            ) else {
                continue;
            };
            table.insert(pk, Arc::new(rules.clone()));
        }
        let mut g = self.send.0.write().unwrap();
        if g.ingress_acls.len() != table.len() {
            tracing::info!(
                peers_with_rules = table.len(),
                "overlay: per-source ingress rules updated"
            );
        }
        g.ingress_acls = table;
    }

    /// Test-only — override the reverse-path mode. Must run BEFORE `add_peer`:
    /// each peer's [`Ingress`] copies the mode once, at install. Exists so the
    /// enforce path is provable without mutating process-wide env (which would
    /// race every other test in the binary).
    #[cfg(test)]
    pub(crate) fn set_rpf_mode(&mut self, mode: RpfMode) {
        self.rpf = mode;
    }

    /// Lock-free business activity for the fast scout. Keep the public traffic
    /// counters' successful-send meaning unchanged when a local send fails.
    /// F2 — arm (`Some(mux)`) or disarm (`None`) `peer_public`'s standby tee.
    pub(crate) fn set_standby_tee(
        &self,
        peer_public: &[u8; 32],
        mux: Option<Arc<crate::transport::derp::DerpMux>>,
    ) -> bool {
        let Some(p) = self.peers.get(peer_public) else {
            return false;
        };
        p.stats.standby.set(mux.map(|m| (m, *peer_public)));
        true
    }

    /// F2 — take `peer_public`'s STANDBY copies (`rx`, from
    /// `DerpMux::standby_route`) into its WG session via [`decap_standby`]:
    /// the ingress gate of any inbound packet, no rx stat. The task is the
    /// peer's, so it ends with the peer; a rebuilt peer needs a new sink.
    pub(crate) fn attach_standby_sink(
        &mut self,
        peer_public: &[u8; 32],
        mut rx: mpsc::Receiver<Vec<u8>>,
    ) -> bool {
        let Some(stats) = self.peers.get(peer_public).map(|p| p.stats.clone()) else {
            return false;
        };
        let ingress = self.ingress_for(*peer_public, stats);
        let tun_tx = self.tun_tx.clone();
        let Some(p) = self.peers.get_mut(peer_public) else {
            return false;
        };
        let tunn = p.tunn.clone();
        p.stats.standby.sink.store(true, Ordering::Relaxed);
        p.tasks.push(tokio::spawn(async move {
            while let Some(copy) = rx.recv().await {
                let packet = {
                    let mut t = tunn.lock().await;
                    decap_standby(&mut t, &copy, &ingress)
                };
                if let Some(packet) = packet
                    && tun_tx.send(packet).await.is_err()
                {
                    break;
                }
            }
        }));
        true
    }

    /// F2 — is a standby sink attached for `peer_public`'s current session?
    pub(crate) fn has_standby_sink(&self, peer_public: &[u8; 32]) -> bool {
        self.peers
            .get(peer_public)
            .is_some_and(|p| p.stats.standby.sink.load(Ordering::Relaxed))
    }

    pub(crate) fn peer_business_traffic(&self, peer_public: &[u8; 32]) -> Option<(u64, u64)> {
        let p = self.peers.get(peer_public)?;
        Some((p.stats.tx_attempted.load(Ordering::Relaxed),
            p.stats.rx.load(Ordering::Relaxed)))
    }

    pub fn peer_take_rx_any(&self, peer_public: &[u8; 32]) -> u64 {
        match self.peers.get(peer_public) {
            Some(p) => p.stats.rx_any.swap(0, Ordering::Relaxed),
            None => 0,
        }
    }

    /// #22 — authenticated handshake INITIATIONS from this peer since the
    /// last call (single-consumer drain, same discipline as
    /// [`peer_take_rx_any`](Self::peer_take_rx_any)). The sweep accumulates
    /// these into a re-init-pressure window; see `PeerStats::reinit_seen`.
    pub fn peer_take_reinits(&self, peer_public: &[u8; 32]) -> u64 {
        match self.peers.get(peer_public) {
            Some(p) => p.stats.reinit_seen.swap(0, Ordering::Relaxed),
            None => 0,
        }
    }

    /// rc.181 — `true` if `peer_public`'s carrier has latched a hard send error
    /// (a TURNS/TCP reset or a lost QUIC-over-TURN connection); `false` for a
    /// healthy or direct carrier; `None` if the peer is unknown. Lock-free. The
    /// health sweep uses this as a FAST carrier-death signal — re-allocate on
    /// the next tick instead of waiting for the multi-sweep rx-flat heuristic.
    pub fn peer_carrier_dead(&self, peer_public: &[u8; 32]) -> Option<bool> {
        Some(self.peers.get(peer_public)?.carrier.is_dead())
    }

    /// Phase C — LOCK-FREE: has the WG handshake to `peer_public` completed (a
    /// session exists)? `None` if the peer is unknown. The health sweep reads
    /// this to time out a srflx / public-direct punch carrier that NEVER
    /// established — its `tx`/`rx` counters stay flat pre-handshake, so the
    /// rx-flat heuristic can't detect it. Latched by `process_inbound` the
    /// instant a session appears; never cleared for the carrier's life (a fresh
    /// carrier gets a fresh `PeerStats`).
    pub fn peer_handshake_done(&self, peer_public: &[u8; 32]) -> Option<bool> {
        Some(
            self.peers
                .get(peer_public)?
                .stats
                .handshake
                .load(Ordering::Relaxed),
        )
    }

    /// Stage 2 — did an INITIATOR-role handshake to `peer_public` complete
    /// at-or-after `since`? Lock-free (reads the recv-path
    /// [`PeerStats::hs_response_at`] stamp). This is the poke's answer check:
    /// only a response WE processed proves our own outbound works — see the
    /// field note on the stats field for why responder-role handshakes must
    /// not count. `false` for an unknown peer or if never stamped.
    pub fn peer_initiator_hs_answered(&self, peer_public: &[u8; 32], since: Instant) -> bool {
        let Some(p) = self.peers.get(peer_public) else {
            return false;
        };
        let at = p.stats.hs_response_at.load(Ordering::Relaxed);
        at != 0 && at >= since.saturating_duration_since(wg_epoch()).as_millis() as u64
    }

    /// Stage 2 — how long since the last INITIATOR-role handshake completion
    /// for `peer_public` (`None` = never, or unknown peer). Drives the
    /// stale-proof poke trigger (`lifecycle::should_poke`).
    pub fn peer_initiator_hs_age(&self, peer_public: &[u8; 32]) -> Option<Duration> {
        let at = self
            .peers
            .get(peer_public)?
            .stats
            .hs_response_at
            .load(Ordering::Relaxed);
        (at != 0).then(|| Duration::from_millis(mono_ms_now().saturating_sub(at)))
    }

    /// Stage 2 — force a WG rekey toward `peer_public` NOW
    /// (`format_handshake_initiation(force_resend: true)`), off this call path.
    /// The active-revalidation poke: a healthy peer MUST answer a valid
    /// initiation, so the (lock-free) [`Self::peer_initiator_hs_answered`]
    /// stamp advancing is proof the round trip works, and its silence past the
    /// tier's handshake deadline is proof it doesn't — boringtun auto-retries
    /// the in-flight initiation every ~5 s either way. `false` if the peer is
    /// unknown. Same lock-then-send split as the timer tasks (rc.211): the
    /// `Tunn` lock is never held across a carrier send, and never touched by
    /// the sweep itself (rc.137).
    pub fn poke_handshake(&self, peer_public: &[u8; 32]) -> bool {
        let Some(p) = self.peers.get(peer_public) else {
            return false;
        };
        let (tunn, carrier, stats) = (p.tunn.clone(), p.carrier.clone(), p.stats.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; WG_BUF];
            let out = {
                let mut t = tunn.lock().await;
                match t.format_handshake_initiation(&mut buf, true) {
                    TunnResult::WriteToNetwork(b) => Some(b.to_vec()),
                    _ => None,
                }
            };
            if let Some(b) = out {
                let _ = send_wg_recorded(&carrier, &stats, &b).await;
            }
        });
        true
    }

    /// Test fixture for the carrier sweep's lock-free IP traffic inputs.
    #[cfg(test)]
    pub fn test_set_ip_traffic(&self, peer_public: &[u8; 32], tx: u64, rx: u64) {
        let p = self.peers.get(peer_public).expect("installed test peer");
        p.stats.tx.store(tx, Ordering::Relaxed);
        p.stats.tx_attempted.store(tx, Ordering::Relaxed);
        p.stats.rx.store(rx, Ordering::Relaxed);
    }

    /// Test-only: stamp `peer_public`'s initiator-handshake instant to NOW, as
    /// if a poke had just been answered (mirrors the recv-path stamp without a
    /// live two-device session).
    #[cfg(test)]
    pub fn test_stamp_initiator_hs(&self, peer_public: &[u8; 32]) {
        if let Some(p) = self.peers.get(peer_public) {
            p.stats
                .hs_response_at
                .store(mono_ms_now().max(1), Ordering::Relaxed);
        }
    }

    /// Test-only: latch `peer_public`'s handshake-done flag true without a live
    /// two-device session. The health-sweep tests that exercise the
    /// ESTABLISHED-carrier paths (rc.206 rx-staleness) need `peer_handshake_done`
    /// to read `Some(true)`, which otherwise requires a full handshake dance over
    /// real sockets (see `peer_handshake_done_latches_on_session_establish`).
    /// This flips only the latch the sweep reads; nothing else about the peer.
    #[cfg(test)]
    pub fn test_latch_handshake_done(&self, peer_public: &[u8; 32]) {
        if let Some(p) = self.peers.get(peer_public) {
            p.stats.handshake.store(true, Ordering::Relaxed);
            p.stats
                .handshake_at
                .store(mono_ms_now().max(1), Ordering::Relaxed);
        }
    }

    /// Test-only: simulate an authenticated inbound packet (e.g. a keepalive)
    /// from `peer_public` by bumping its `rx_any` liveness counter, so the sweep
    /// tests can exercise the "heard-within-deadline → survives" path (rc.206)
    /// without driving a live session's keepalive traffic.
    #[cfg(test)]
    pub fn test_bump_rx_any(&self, peer_public: &[u8; 32]) {
        if let Some(p) = self.peers.get(peer_public) {
            p.stats.rx_any.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// #22 test hook — simulate authenticated handshake initiations from
    /// `peer_public` (the re-init-pressure input; see `peer_take_reinits`).
    pub fn test_bump_reinits(&self, peer_public: &[u8; 32], n: u64) {
        if let Some(p) = self.peers.get(peer_public) {
            p.stats.reinit_seen.fetch_add(n, Ordering::Relaxed);
        }
    }
}

async fn send_wg_recorded(carrier: &Arc<Carrier>, stats: &PeerStats, bytes: &[u8]) -> io::Result<usize> {
    let n = carrier.send(bytes).await?;
    if n == bytes.len() && let Some(digest) = follow::init_digest(bytes) {
        let mut sent = stats.sent_inits.lock().unwrap_or_else(|e|e.into_inner());
        if !sent.contains(&digest) {
            if sent.len() == 4 { sent.pop_front(); }
            sent.push_back(digest);
        }
    }
    Ok(n)
}

/// Handle one inbound carrier datagram: decapsulate, echo any
/// handshake/cookie/queued bytes back over the carrier, and deliver a
/// decrypted IP packet to the TUN channel.
///
/// A3 — returns `true` iff the datagram AUTHENTICATED: non-empty and
/// decapsulated without error against this session (data, a handshake step,
/// or a keepalive — the same predicate `rx_any` liveness keys on). This is
/// the roaming gate: an endpoint is adopted only on cryptographic proof,
/// never on packet shape.
pub(crate) async fn process_inbound(
    t: &mut Tunn,
    n: usize,
    buf: &mut [u8],
    carrier: &Arc<Carrier>,
    tun_tx: &mpsc::Sender<Vec<u8>>,
    ingress: &Ingress,
) -> bool {
    let (authenticated, packet) = decap_inbound(t, n, buf, carrier, ingress);
    if let Some(p) = packet {
        let _ = tun_tx.send(p).await;
    }
    authenticated
}

/// [`process_inbound`] without the delivery: whether the datagram
/// authenticated, and the decrypted IP packet it carried (a WireGuard
/// datagram carries at most one) for the caller to hand to the TUN channel.
/// A batched receive path decrypts a whole run of datagrams this way under one
/// `Tunn` lock, then delivers the packets back to back once the lock is
/// released.
/// F2 — decapsulate one STANDBY copy into the peer's session: WG data only,
/// through the same ingress gate as [`decap_inbound`], and counted in NO rx
/// stat. A copy is not evidence that the direct carrier works, so the business
/// scout and the health sweep keep judging that carrier by what it delivers
/// itself. A replay (its direct original got here first), a handshake or a
/// cookie is dropped, and nothing is ever sent in reply.
pub(crate) fn decap_standby(t: &mut Tunn, datagram: &[u8], ingress: &Ingress) -> Option<Vec<u8>> {
    if datagram.len() < 16 || datagram[..4] != [4, 0, 0, 0] {
        return None;
    }
    let mut out = vec![0u8; WG_BUF];
    let (src, pkt) = match t.decapsulate(None, datagram, &mut out) {
        TunnResult::WriteToTunnelV4(pkt, src) => (IpAddr::V4(src), pkt),
        TunnResult::WriteToTunnelV6(pkt, src) => (IpAddr::V6(src), pkt),
        _ => return None,
    };
    // The packet arrived, whichever carrier delivered it: it is not loss.
    ingress.stats.note_rx_counter(datagram);
    if !ingress.permits(src, pkt) {
        return None;
    }
    let (at, len) = (pkt.as_ptr() as usize, pkt.len());
    let span = (at - out.as_ptr() as usize, len);
    Some(into_packet(out, span))
}

pub(crate) fn decap_inbound(
    t: &mut Tunn,
    n: usize,
    buf: &mut [u8],
    carrier: &Arc<Carrier>,
    ingress: &Ingress,
) -> (bool, Option<Vec<u8>>) {
    let stats = &ingress.stats;
    let mut delivered = None;
    // Decapsulate writes into a separate scratch buffer so the borrow on
    // the result doesn't alias the inbound `buf`.
    let mut out = vec![0u8; WG_BUF];
    let res = t.decapsulate(None, &buf[..n], &mut out);
    let authenticated_init = matches!(&res, TunnResult::WriteToNetwork(p)
        if p.len() == 92 && p[..4] == [2, 0, 0, 0]);
    if authenticated_init && let Some(digest) = follow::init_digest(&buf[..n]) {
        *stats.follow_init.lock().unwrap_or_else(|e|e.into_inner()) = Some((digest, Instant::now()));
    }
    let authenticated = n > 0 && !matches!(res, TunnResult::Err(_));
    // rc.206 — a non-empty inbound datagram that passed WG decapsulation (data, a
    // handshake step, OR a content-free persistent-keepalive → `Done`) proves we
    // HEARD from this peer: the liveness signal the health sweep keys rx-staleness
    // on. `rx` (below) advances only on delivered IP DATA, so a keepalive-only
    // idle link would look silent. Guard on `n > 0`: an EMPTY datagram also
    // decapsulates to `Done` (boringtun's poll-for-queued-output shape — what the
    // flush loop below relies on), but a 0-byte UDP payload is never a real WG
    // packet, so it must not count as liveness. `Err` (replay / garbage) isn't.
    if authenticated {
        stats.rx_any.fetch_add(1, Ordering::Relaxed);
        stats.note_rx_counter(&buf[..n]);
        // #22 — a HANDSHAKE INITIATION (type 1) from the peer: counted so
        // the sweep can spot re-init PRESSURE (a ~5 s retry cadence means
        // the peer cannot hear our responses — see `PeerStats::reinit_seen`).
        // boringtun authenticated it (mac1/cookie), so a spoofed flood
        // cannot bump this.
        if n >= 4 && buf[0] == 1 && buf[1..4] == [0, 0, 0] {
            stats.reinit_seen.fetch_add(1, Ordering::Relaxed);
        }
        // Stage 2 — a HANDSHAKE RESPONSE (type 2) that decapsulated without
        // error means a handshake WE initiated just completed: boringtun only
        // accepts a response against our own outstanding initiator state, so
        // this proves our init reached the peer AND its reply reached us —
        // the round-trip evidence the active-revalidation poke waits for.
        // (boringtun rejects any size ≠ 92 or crypto/state mismatch as `Err`,
        // so the byte-shape check alone can't be spoofed into a stamp.)
        if n >= 4 && buf[0] == 2 && buf[1..4] == [0, 0, 0] {
            stats
                .hs_response_at
                .store(mono_ms_now().max(1), Ordering::Relaxed);
        }
    }
    match res {
        TunnResult::WriteToNetwork(b) => {
            // rc.211 — collect the handshake response + any flushed follow-ups
            // (each needs `t` to decapsulate; a handshake step can complete a
            // session with queued data, which boringtun signals by returning
            // WriteToNetwork on empty-datagram decapsulate calls — drain until
            // Done), then SEND them OFF this call path. Sending inline held the
            // caller (the SHARED direct recv loop, or a per-peer recv task) and
            // this peer's Tunn lock across a possibly-slow carrier send, so the
            // recv loop stopped reading the socket and the OS dropped inbound
            // UDP for every direct peer.
            let mut outs: Vec<Vec<u8>> = vec![b.to_vec()];
            loop {
                let mut flush = vec![0u8; WG_BUF];
                match t.decapsulate(None, &[], &mut flush) {
                    TunnResult::WriteToNetwork(b2) => outs.push(b2.to_vec()),
                    _ => break,
                }
            }
            let c = carrier.clone();
            let send_stats = stats.clone();
            tokio::spawn(async move {
                for b in outs {
                    let _ = send_wg_recorded(&c, &send_stats, &b).await;
                }
            });
        }
        // P4 — the second field is boringtun's own parse of the decapsulated
        // packet's SOURCE address (already validated against the IP header's
        // length), handed to the caller precisely so cryptokey routing can be
        // enforced on ingress. It was discarded until P4, which is what let any
        // peer with a live session write an arbitrary source into our TUN.
        TunnResult::WriteToTunnelV4(pkt, src) => {
            if ingress.permits(IpAddr::V4(src), pkt) {
                stats.rx.fetch_add(1, Ordering::Relaxed);
                let (at, len) = (pkt.as_ptr() as usize, pkt.len());
                let span = (at - out.as_ptr() as usize, len);
                delivered = Some(into_packet(out, span));
            }
        }
        TunnResult::WriteToTunnelV6(pkt, src) => {
            if ingress.permits(IpAddr::V6(src), pkt) {
                stats.rx.fetch_add(1, Ordering::Relaxed);
                let (at, len) = (pkt.as_ptr() as usize, pkt.len());
                let span = (at - out.as_ptr() as usize, len);
                delivered = Some(into_packet(out, span));
            }
        }
        TunnResult::Done => {}
        TunnResult::Err(e) => debug!(?e, "wg decapsulate error"),
    }
    // Phase C — latch "handshake completed" the moment this peer's session is
    // live. `process_inbound` only runs on a packet FROM the peer, so a set flag
    // means the peer reached us AND a session exists (the responder establishes
    // on the init it just answered; the initiator on the response it just got) —
    // exactly the "punch succeeded" signal the health deadline needs. Set-once;
    // the Tunn lock is already held here (rc.137: never lock it from the sweep).
    if !stats.handshake.load(Ordering::Relaxed) && t.time_since_last_handshake().is_some() {
        stats.handshake.store(true, Ordering::Relaxed);
        // P3 PR-B — stamp the latch instant (recv-path precision; the sweep's
        // 5 s tick only OBSERVES it later). `max(1)`: 0 is the unset sentinel.
        stats
            .handshake_at
            .store(mono_ms_now().max(1), Ordering::Relaxed);
    }
    (authenticated, delivered)
}

/// The decrypted packet at `(offset, len)` of the decapsulation buffer, as an
/// owned packet without a second allocation (boringtun writes it at offset 0).
fn into_packet(mut out: Vec<u8>, (off, len): (usize, usize)) -> Vec<u8> {
    if off != 0 {
        out.copy_within(off..off + len, 0);
    }
    out.truncate(len);
    out
}

/// Phase C — the WireGuard datagram shape: a 4-byte little-endian message type
/// in `1..=4` (Init / Response / Cookie / Data), so bytes `1..4` are always
/// zero. Used to EXCLUDE WG traffic from the STUN-cookie demux check — a WG data
/// packet whose receiver-index bytes happen to equal the STUN magic cookie must
/// still route as WG. A real STUN Binding message can never satisfy this (its
/// big-endian 16-bit type puts `0x01` in byte 1), so the two classes are
/// disjoint. Intentionally does NOT validate length/contents — it's only the
/// exclusion half of the STUN discriminator.
pub(crate) fn is_wg_shaped(pkt: &[u8]) -> bool {
    pkt.len() >= 4 && matches!(pkt[0], 1..=4) && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 0
}

/// A handshake INITIATION's mac1 covers everything before its own offset:
/// 4 type/reserved + 4 sender_idx + 32 ephemeral + 48 enc_static + 28
/// enc_timestamp = 116 bytes; mac1 is the 16 bytes at 116..132 (mac2 fills
/// 132..148).
const INIT_MAC1_OFFSET: usize = 116;

/// Precompute the mac1 verification key for a responder static:
/// `Blake2s256("mac1----" || responder_pub)` — WireGuard's LABEL_MAC1
/// construction. Derived from PUBLIC data, so a matching mac1 proves only
/// "addressed to this key", never authenticity — it is a ROUTER's
/// pre-filter (which engine should spend the DH), not an authenticator.
pub(crate) fn mac1_key_for(public: &PublicKey) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    let mut h = Blake2s256::new();
    h.update(b"mac1----");
    h.update(public.as_bytes());
    h.finalize().into()
}

/// Verify a type-1 packet's mac1 against a precomputed [`mac1_key_for`]
/// key. ~1 µs of keyed Blake2s vs the X25519 that
/// [`authenticate_init_with`] spends — run per candidate engine BEFORE the
/// DH, so a spoofed or foreign initiation costs no asymmetric crypto.
/// Plain (non-constant-time) compare is fine: the key derives from a
/// public key, so timing leaks nothing secret.
pub(crate) fn init_mac1_matches(mac1_key: &[u8; 32], packet: &[u8]) -> bool {
    use blake2::digest::Mac;
    type Mac1 = blake2::Blake2sMac<blake2::digest::consts::U16>;
    if packet.len() < INIT_MAC1_OFFSET + 16 {
        return false;
    }
    let Ok(mut m) = <Mac1 as Mac>::new_from_slice(mac1_key) else {
        return false;
    };
    m.update(&packet[..INIT_MAC1_OFFSET]);
    m.finalize().into_bytes().as_slice() == &packet[INIT_MAC1_OFFSET..INIT_MAC1_OFFSET + 16]
}

/// Phase A / carrier plane — the keypair-parameterized core of
/// [`WgDevice::authenticate_init`], so the shared carrier plane can trial a
/// handshake initiation against EACH attached engine's static (an init is
/// sealed to exactly one) without borrowing a device. See the method's doc
/// for why BOTH steps (anon parse, then a throwaway-`Tunn` decapsulate) are
/// required — the parsed key alone is a claim, not proof.
pub(crate) fn authenticate_init_with(
    secret: &StaticSecret,
    public: &PublicKey,
    init: &[u8],
) -> Option<[u8; 32]> {
    let claimed = {
        let Ok(Packet::HandshakeInit(hi)) = Tunn::parse_incoming_packet(init) else {
            return None;
        };
        boringtun::noise::handshake::parse_handshake_anon(secret, public, &hi)
            .ok()?
            .peer_static_public
    };
    let mut probe = Tunn::new(
        secret.clone(),
        PublicKey::from(claimed),
        None,
        None,
        0,
        None,
    );
    let mut out = vec![0u8; WG_BUF];
    match probe.decapsulate(None, init, &mut out) {
        TunnResult::WriteToNetwork(_) => Some(claimed),
        _ => None,
    }
}

/// rc.134 — the shared direct-socket recv loop. Reads every datagram and
/// routes it to the peer registered for its SOURCE address (a direct peer
/// sends from the same address we send to), processing it with that peer's
/// `Tunn` and replying over the same socket. One loop serves all direct peers,
/// so N same-subnet peers share one socket without racing. Exits when the
/// socket itself errors (device gone / dropped); an error about an earlier
/// datagram is read past (#2220).
#[allow(clippy::too_many_arguments)] // C1 — plus the disco responder identity
async fn run_direct_demux(
    sock: Arc<UdpSocket>,
    routes: Arc<Mutex<DemuxRoutes>>,
    index_routes: Arc<std::sync::Mutex<HashMap<u32, IndexSlot>>>,
    // C1 — disco responder identity + the installed-peer mirror.
    disco_secret: StaticSecret,
    disco_public: PublicKey,
    disco_routes: WgSender,
    // C2 — where a verified PONG goes. This seam used to answer pings via
    // `disco::respond` and DROP pongs on the floor, so any path whose carrier
    // socket was served here measured 100 % loss while carrying WG data fine.
    disco_events: mpsc::Sender<super::disco::DiscoInbound>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    events: mpsc::Sender<DirectInbound>,
    stun_events: mpsc::Sender<crate::transport::stun::StunInbound>,
    stat: Arc<super::direct::SockStat>,
) {
    let mut buf = vec![0u8; WG_BUF];
    // Phase A — per-source rate limit for forwarded unknown-source initiations
    // (local to this loop task: no lock needed, one map per interface socket).
    let mut recent_unknown: HashMap<SocketAddr, Instant> = HashMap::new();
    loop {
        // #2220 — read on past the errors about an EARLIER datagram (Windows
        // reports a peer's ICMP port-unreachable as 10054 on the next
        // receive), as the carrier plane's loop does.
        let (n, src) = match super::udp_recv::recv_from(&sock, &mut buf).await {
            Ok(v) => v,
            Err(e) => {
                // PR-B1 tripwire — a dead recv loop leaves the socket bound +
                // advertised but reader-less; WARN, not a DEBUG nobody sees.
                warn!(%e, local = %stat.local, "wg direct demux recv ended; loop exiting");
                break;
            }
        };
        stat.bump();
        // Phase C — demux-routed STUN. A datagram carrying the STUN magic
        // cookie that is NOT WireGuard-shaped is a Binding response for the
        // srflx keepalive task, whose query rides this shared socket (which the
        // task can't `recv_from` itself). Forward it to the STUN sink and skip
        // WG routing. The two shapes are DISJOINT — WG's 4-byte LE type header
        // leaves bytes 1..4 == 0 while a real STUN Binding message always has
        // 0x01 in byte 1 — so this never steals a WG datagram (and a WG data
        // packet whose index bytes happen to equal the cookie is kept by the
        // `is_wg_shaped` exclusion). Checked BEFORE the routes lookup so a STUN
        // reply is never mistaken for peer traffic. `try_send` drops it if
        // nobody took the receiver (srflx tier off) — harmless.
        if crate::transport::stun::has_stun_cookie(&buf[..n]) && !is_wg_shaped(&buf[..n]) {
            let _ = stun_events.try_send(crate::transport::stun::StunInbound {
                src,
                packet: buf[..n].to_vec(),
            });
            continue;
        }
        // C1 — disco: an out-of-tunnel carrier echo, answered unconditionally
        // by the daemon (no OS, no firewall, no tunnel session). Its shape is
        // disjoint from WG and STUN by construction (see `overlay::disco`), so
        // this can never steal a live datagram.
        if super::disco::is_disco_shaped(&buf[..n]) {
            // Use `classify`, NOT `respond`. `respond` only yields a value for
            // a PING; a PONG arriving here returned `None` and fell through to
            // `continue`, i.e. it was dropped. That broke C2's measurement for
            // every path whose carrier socket is served by this seam rather
            // than the carrier plane: the peer answered (its DISCO_ANSWERED
            // climbed), the reply arrived, and the prober never saw it — so a
            // healthy carrier read `loss=100%`. Field 2026-08-12: fleet-host-2→fleet-host-1
            // and fleet-host-2→devbox-wsl on grox, both 0 % by ping, both 100 % by
            // disco, while the SAME fleet-host-1 measured correctly on the other
            // org's engine. `classify`'s own doc already promised the two
            // seams could not diverge; now they don't.
            match super::disco::classify(&buf[..n], src, &disco_secret, &disco_public, |pk| {
                disco_routes.has_peer(pk)
            }) {
                super::disco::Verdict::Answer(pong) => {
                    if super::direct::disco_respond_enabled() {
                        let s = sock.clone();
                        tokio::spawn(async move {
                            let _ = s.send_to(&pong, src).await;
                        });
                        crate::evidence::DISCO_ANSWERED.fetch_add(1, Ordering::Relaxed);
                    }
                }
                super::disco::Verdict::Pong(p) => {
                    let _ = disco_events.try_send(p);
                }
                super::disco::Verdict::Ignore => {}
            }
            continue;
        }
        // Clone the Arcs out under the routes lock, then release it before the
        // (potentially awaiting) process_inbound so the demux map stays
        // contended only briefly.
        let entry = routes.lock().await.get(&src).cloned();
        let Some((tunn, ingress)) = entry else {
            // A3 (WG-style roaming, `OVERLAY_ROAM`) — a SESSIONFUL datagram
            // (response / data / cookie) from an unknown source still names
            // its session by RECEIVER INDEX; adopt the observed source iff
            // the payload AUTHENTICATES against that session (rate-limited
            // per session). This is what completes a punch from a
            // symmetric-NAT peer: its real per-destination mapping differs
            // from its advert, so its packets arrive from a source nobody
            // registered — and what follows a mid-session NAT rebind.
            if super::direct::roam_enabled()
                && let Ok(pkt) = Tunn::parse_incoming_packet(&buf[..n])
                && let Some(idx) = match &pkt {
                    Packet::HandshakeResponse(p) => Some(p.receiver_idx >> 8),
                    Packet::PacketCookieReply(p) => Some(p.receiver_idx >> 8),
                    Packet::PacketData(p) => Some(p.receiver_idx >> 8),
                    Packet::HandshakeInit(_) => None,
                }
            {
                let slot = {
                    let m = index_routes.lock().unwrap_or_else(|e| e.into_inner());
                    m.get(&idx).map(|s| (s.src, s.carrier.clone(), s.last_roam))
                };
                if let Some((old_src, weak, last)) = slot
                    && old_src != src
                    && last.is_none_or(|t| t.elapsed() >= super::direct::ROAM_MIN_INTERVAL)
                {
                    let sess = routes.lock().await.get(&old_src).cloned();
                    if let Some((tunn, ingress)) = sess {
                        let reply = Carrier::direct(sock.clone(), src);
                        let authenticated = {
                            let mut t = tunn.lock().await;
                            process_inbound(&mut t, n, &mut buf, &reply, &tun_tx, &ingress).await
                        };
                        if authenticated {
                            {
                                let mut r = routes.lock().await;
                                if let Some(e) = r.remove(&old_src) {
                                    r.insert(src, e);
                                }
                            }
                            {
                                let mut m = index_routes.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(s) = m.get_mut(&idx) {
                                    s.src = src;
                                    s.last_roam = Some(Instant::now());
                                }
                            }
                            if let Some(c) = weak.upgrade() {
                                c.set_direct_dst(src);
                            }
                            crate::evidence::ROAM_ADOPTIONS.fetch_add(1, Ordering::Relaxed);
                            info!(
                                %old_src, new_src = %src, idx,
                                "wg: peer endpoint ROAMED — authenticated inbound from a new \
                                 source adopted (outbound repointed)"
                            );
                        }
                        continue;
                    }
                }
            }
            // Phase A — an UNKNOWN source is no longer unconditionally dropped:
            // if the datagram is a well-formed WG handshake INITIATION, forward
            // it to the runtime (a NAT'd peer dialling our public endpoint, or
            // a known peer that restarted onto a new port — the stale-port
            // race). The runtime authenticates before acting; rate-limited so
            // a junk flood can't churn the channel. Anything else from an
            // unknown source stays dropped.
            if matches!(
                Tunn::parse_incoming_packet(&buf[..n]),
                Ok(Packet::HandshakeInit(_))
            ) {
                if recent_unknown.len() >= UNKNOWN_INIT_MAX_SOURCES {
                    recent_unknown.retain(|_, t| t.elapsed() < UNKNOWN_INIT_MIN_INTERVAL);
                }
                let fresh = recent_unknown
                    .get(&src)
                    .is_none_or(|t| t.elapsed() >= UNKNOWN_INIT_MIN_INTERVAL);
                if fresh && recent_unknown.len() < UNKNOWN_INIT_MAX_SOURCES {
                    recent_unknown.insert(src, Instant::now());
                    if events
                        .try_send(DirectInbound {
                            src,
                            sock: sock.clone(),
                            packet: buf[..n].to_vec(),
                        })
                        .is_err()
                    {
                        crate::evidence::DIRECT_INBOUND_DROPS.fetch_add(1, Ordering::Relaxed);
                        debug!(%src, "wg demux: accept channel full — initiation dropped");
                    }
                }
            }
            continue;
        };
        let reply = Carrier::direct(sock.clone(), src);
        let mut t = tunn.lock().await;
        process_inbound(&mut t, n, &mut buf, &reply, &tun_tx, &ingress).await;
    }
}

/// Test-only: build a genuine WG handshake INITIATION from `initiator_secret`,
/// sealed to `responder_public`, so a [`WgDevice`] holding that responder key
/// `authenticate_init`s it (recovering the initiator's public key). Used by the
/// runtime's inbound-accept tests, which live in `runtime.rs` and can't reach
/// boringtun's `Tunn` directly.
#[cfg(test)]
pub(crate) fn test_genuine_init(
    initiator_secret: &StaticSecret,
    responder_public: [u8; 32],
) -> Vec<u8> {
    let mut tunn = Tunn::new(
        initiator_secret.clone(),
        PublicKey::from(responder_public),
        None,
        None,
        1,
        None,
    );
    let mut buf = vec![0u8; WG_BUF];
    match tunn.format_handshake_initiation(&mut buf, false) {
        TunnResult::WriteToNetwork(b) => b.to_vec(),
        _ => panic!("expected a handshake initiation"),
    }
}

#[cfg(test)]
mod tests {
    //! Phase 2 proof: two userspace WG devices complete a handshake and
    //! round-trip a synthetic IP packet over **both** carriers — a
    //! direct UDP socket and the [`RelayConn`] bridge — terminating at
    //! the device's `tun_rx` (no real TUN). Mirrors the structure of the
    //! QUIC two-allocation tests in [`crate::transport::relay`].

    use super::*;
    use crate::overlay::WgKeypair;
    use std::time::Duration;

    /// The passive loss counters read the gaps in a WG transport stream as
    /// loss, and neither a reordered packet nor a new session.
    #[test]
    fn rx_counters_read_gaps_as_loss_not_reorder_or_a_new_session() {
        let s = PeerStats::default();
        let pkt = |session: u32, ctr: u64| {
            let mut d = vec![4u8, 0, 0, 0];
            d.extend_from_slice(&session.to_le_bytes());
            d.extend_from_slice(&ctr.to_le_bytes());
            d.extend_from_slice(&[0u8; 16]);
            d
        };
        let read = |s: &PeerStats| {
            (
                s.rx_ctr_span.load(Ordering::Relaxed),
                s.rx_ctr_accepted.load(Ordering::Relaxed),
            )
        };
        // Counters 0..=9 of one session: 3 and 6 lost, 9 ahead of 8.
        for c in [0, 1, 2, 4, 5, 7, 9, 8] {
            s.note_rx_counter(&pkt(7, c));
        }
        let (span, acc) = read(&s);
        assert_eq!((span, acc), (10, 8), "two of ten lost");
        // A rekey: the next session starts again at 0.
        for c in 0..5 {
            s.note_rx_counter(&pkt(8, c));
        }
        let (span2, acc2) = read(&s);
        assert_eq!(span2 - span, acc2 - acc, "a new session is no loss");
        // Handshake messages and runts are not transport packets.
        s.note_rx_counter(&[1, 0, 0, 0, 9, 9, 9, 9, 0, 0, 0, 0, 0, 0, 0, 0]);
        s.note_rx_counter(&[4, 0, 0, 0]);
        assert_eq!(read(&s), (span2, acc2));
    }

    /// The mac1 pre-filter against boringtun ground truth: a genuine
    /// initiation's mac1 matches ONLY the responder static it is sealed
    /// to, breaks on any covered-byte tamper, and short inputs never
    /// match. This is what lets the plane pick the one engine worth an
    /// X25519 for ~1 µs.
    #[test]
    fn init_mac1_binds_to_the_sealed_responder_only() {
        let (initiator, r1, r2) = (
            WgKeypair::generate(),
            WgKeypair::generate(),
            WgKeypair::generate(),
        );
        let init = test_genuine_init(&initiator.secret, r1.public.to_bytes());
        let k1 = mac1_key_for(&r1.public);
        let k2 = mac1_key_for(&r2.public);
        assert!(
            init_mac1_matches(&k1, &init),
            "mac1 must match the responder the init is sealed to"
        );
        assert!(
            !init_mac1_matches(&k2, &init),
            "mac1 must not match any other responder"
        );
        assert!(!init_mac1_matches(&k1, &init[..100]), "short input");
        let mut tampered = init.clone();
        tampered[10] ^= 1;
        assert!(
            !init_mac1_matches(&k1, &tampered),
            "a covered-byte tamper must break the mac"
        );
    }

    /// A3 — a direct carrier's dst is interior-mutable so an authenticated
    /// roam repoints it in place for every `Arc` holder; relay/QUIC carriers
    /// have no direct dst.
    #[tokio::test]
    async fn carrier_direct_dst_roundtrips() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let a: SocketAddr = "203.0.113.9:41000".parse().unwrap();
        let b: SocketAddr = "198.51.100.5:52000".parse().unwrap();
        let c = Carrier::direct(sock, a);
        assert_eq!(c.direct_dst(), Some(a));
        assert_eq!(c.set_direct_dst(b), Some(a)); // returns the previous dst
        assert_eq!(c.direct_dst(), Some(b)); // every Arc holder now sees b
    }

    /// Minimal well-formed IPv4 packet so boringtun routes it to
    /// `WriteToTunnelV4` (correct version nibble + total-length field +
    /// dst at bytes 16..20).
    fn synthetic_ipv4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45; // IPv4, IHL=5
        p[2] = (total >> 8) as u8;
        p[3] = (total & 0xff) as u8;
        p[8] = 64; // TTL
        p[9] = 17; // UDP
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20..].copy_from_slice(payload);
        p
    }

    /// rc.208 make-before-break primitives — a shadow probe is isolated from the
    /// routing `peers` map until PROMOTED, and dropping a probe never disturbs
    /// the active carrier.
    #[tokio::test(flavor = "multi_thread")]
    async fn direct_probe_is_isolated_from_routing_until_promoted() {
        let kp = WgKeypair::generate();
        let peer = WgKeypair::generate();
        let (mut dev, _rx) = WgDevice::new(kp.secret.clone());
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        dev.ensure_direct_demux(sock.clone());
        let pk = peer.public.to_bytes();
        let overlay_ip = Ipv4Addr::new(100, 64, 0, 3);
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();

        dev.start_direct_probe(sock, pk, overlay_ip, dst, true)
            .await;
        assert!(dev.has_direct_probe(&pk));
        assert_eq!(dev.probe_count(), 1);
        assert_eq!(dev.probe_handshake_done(&pk), Some(false));
        // The probe is NOT in the routing map — traffic still can't reach the
        // peer over it (routing stays on the active/relay carrier).
        assert!(
            dev.peer_traffic(&pk).is_none(),
            "a probe must not join routing before it is promoted"
        );

        // The direct handshake completes → promote to the ACTIVE carrier.
        dev.test_latch_probe_handshake_done(&pk);
        assert_eq!(dev.probe_handshake_done(&pk), Some(true));
        assert!(dev.promote_direct_probe(&pk));
        assert_eq!(dev.probe_count(), 0, "promoted out of the shadow map");
        assert!(!dev.has_direct_probe(&pk));
        assert!(
            dev.peer_traffic(&pk).is_some(),
            "the promoted probe is now the active routing carrier"
        );

        // A later probe that fails is dropped WITHOUT disturbing the active
        // carrier (distinct dst so the demux keys don't alias).
        let sock2 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dst2: SocketAddr = "127.0.0.1:10".parse().unwrap();
        dev.start_direct_probe(sock2, pk, overlay_ip, dst2, true)
            .await;
        assert_eq!(dev.probe_count(), 1);
        dev.drop_direct_probe(&pk).await;
        assert_eq!(dev.probe_count(), 0);
        assert!(
            dev.peer_traffic(&pk).is_some(),
            "the active carrier survives an unrelated probe drop"
        );
    }

    /// P1 (S6) — the shared send half must track every routing mutation:
    /// add routes, promote swaps the pump's view to the probe's carrier
    /// atomically, remove unroutes. Observed from the OUTSIDE via a
    /// [`WgSender`] clone (exactly what the outbound pump holds) and real
    /// loopback sockets — bytes land where the CURRENT carrier points.
    #[tokio::test(flavor = "multi_thread")]
    async fn send_table_tracks_add_remove_and_promote() {
        let kp = WgKeypair::generate();
        let peer = WgKeypair::generate();
        let (mut dev, _rx) = WgDevice::new(kp.secret.clone());
        let sender = dev.sender();
        let pk = peer.public.to_bytes();
        let ip = Ipv4Addr::new(100, 64, 0, 7);
        let pkt = synthetic_ipv4(Ipv4Addr::new(100, 64, 0, 1), ip, b"send-table");
        let mut buf = [0u8; 2048];

        // No route yet — the sender drops.
        assert!(
            !sender.send_ip_packet(&pkt).await,
            "unrouted before add_peer"
        );

        // add_peer → routed. The first send emits the handshake INIT (boringtun
        // queues the data packet pre-session), observed at the old carrier dst.
        let old_listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let old_dst = old_listener.local_addr().unwrap();
        let out_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        dev.add_peer(pk, ip, Carrier::direct(out_sock, old_dst), false);
        assert!(
            sender.send_ip_packet(&pkt).await,
            "routed after add_peer (emits the init)"
        );
        let n = tokio::time::timeout(Duration::from_secs(5), old_listener.recv(&mut buf))
            .await
            .expect("old carrier dst must receive the sender's emission")
            .unwrap();
        assert!(n > 0);

        // Shadow probe → latch → promote: the pump's view swaps to the probe's
        // carrier under one write lock — the next emission lands at the PROBE
        // dst (fresh Tunn ⇒ a fresh init), not the old one.
        let probe_listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let probe_dst = probe_listener.local_addr().unwrap();
        let demux_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        dev.ensure_direct_demux(demux_sock.clone());
        dev.start_direct_probe(demux_sock, pk, ip, probe_dst, false)
            .await;
        dev.test_latch_probe_handshake_done(&pk);
        assert!(dev.promote_direct_probe(&pk));
        assert!(
            sender.send_ip_packet(&pkt).await,
            "still routed after promote"
        );
        let n = tokio::time::timeout(Duration::from_secs(5), probe_listener.recv(&mut buf))
            .await
            .expect("post-promote emission must land at the probe dst")
            .unwrap();
        assert!(n > 0);

        // remove_peer → unrouted again (route + triple gone in one uninstall).
        dev.remove_peer(&pk).await;
        assert!(
            !sender.send_ip_packet(&pkt).await,
            "unrouted after remove_peer"
        );
    }

    /// Poll `is_connected` until the handshake completes or we give up.
    /// Generous budget so heavy parallel CI load (these are
    /// `multi_thread` tests sharing cores) can't starve the handshake
    /// tasks into a false failure.
    async fn wait_connected(dev: &WgDevice, peer: &[u8; 32]) {
        for _ in 0..300 {
            if dev.is_connected(peer).await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("WG handshake did not complete in time");
    }

    /// Encapsulate-send with retry (the first packet right after the
    /// handshake occasionally races the session install).
    async fn send_until_ok(dev: &WgDevice, peer: &[u8; 32], pkt: &[u8]) {
        for _ in 0..100 {
            if dev.send_to_peer(peer, pkt).await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("WG encapsulate never produced a network packet");
    }

    const IP_A: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
    const IP_B: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

    /// Minimal well-formed IPv4 + TCP packet with a real destination port, so
    /// the P4 rule matcher sees a parseable L4 header. Payload starts at 24.
    fn synthetic_tcp(src: Ipv4Addr, dst: Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let total = 24 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2] = (total >> 8) as u8;
        p[3] = (total & 0xff) as u8;
        p[8] = 64;
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[22..24].copy_from_slice(&dst_port.to_be_bytes());
        p[24..].copy_from_slice(payload);
        p
    }

    /// A netmap entry for `kp` at `ip`, with no ingress rules compiled.
    fn netmap_peer_for(
        kp: &WgKeypair,
        ip: Ipv4Addr,
    ) -> roomler_ai_remote_control::signaling::NetmapPeer {
        use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
        roomler_ai_remote_control::signaling::NetmapPeer {
            node_id: bson::oid::ObjectId::new(),
            overlay_ip: ip.to_string(),
            name: String::new(),
            wg_public_key: B64.encode(kp.public.to_bytes()),
            endpoints: vec![],
            lan_endpoints: vec![],
            srflx_endpoints: vec![],
            srflx_nat: None,
            udp_dialer_ok: None,
            relay_home: None,
            warm_relay_endpoint: None,
            reachable: true,
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
            supports_forced_derp: false,
            supports_derp_floor: false,
            supports_org_relay: false,
            caps: None,
            supports_overlay_echo: false,
            relay_strategy: None,
            routes: vec![],
            agent_id: None,
            ingress_rules: None,
            backbone_only: false,
        }
    }

    // -----------------------------------------------------------------------
    // P4 — reverse-path filtering, end to end over a real carrier
    // -----------------------------------------------------------------------

    /// Two handshaked devices over loopback UDP. `mode` is the RECEIVER's
    /// (`dev_b`) reverse-path mode. Returns both devices (dropping either kills
    /// its tasks), B's TUN receiver, and A's pubkey.
    async fn rpf_pair(mode: RpfMode) -> (WgDevice, WgDevice, mpsc::Receiver<Vec<u8>>, [u8; 32]) {
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let (mut dev_a, _rx_a) = WgDevice::new(a.secret.clone());
        let (mut dev_b, mut rx_b) = WgDevice::new(b.secret.clone());
        dev_b.set_rpf_mode(mode);

        dev_a.add_peer(
            b.public.to_bytes(),
            IP_B,
            Carrier::direct(sock_a.clone(), addr_b),
            true,
        );
        dev_b.add_peer(
            a.public.to_bytes(),
            IP_A,
            Carrier::direct(sock_b.clone(), addr_a),
            false,
        );
        wait_connected(&dev_a, &b.public.to_bytes()).await;

        // A packet A legitimately sources from its OWN overlay IP must arrive
        // in every mode — the false-deny guard. (It also flushes anything
        // boringtun queued during the handshake, so the assertions below see
        // only what they sent.)
        send_until_ok(
            &dev_a,
            &b.public.to_bytes(),
            &synthetic_ipv4(IP_A, IP_B, b"ok"),
        )
        .await;
        let got = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("a peer's own source address must never be filtered")
            .unwrap();
        assert_eq!(&got[20..], b"ok");
        while tokio::time::timeout(Duration::from_millis(200), rx_b.recv())
            .await
            .is_ok()
        {}
        assert_eq!(
            dev_b.peer_rx_denied(&a.public.to_bytes()),
            0,
            "legitimate traffic must not be counted as a reverse-path failure"
        );
        (dev_a, dev_b, rx_b, a.public.to_bytes())
    }

    /// The spoofing hole this filter closes: a peer holding a live WG session
    /// forges a THIRD party's source address. Under `enforce` the packet never
    /// reaches the TUN.
    #[tokio::test(flavor = "multi_thread")]
    async fn rpf_enforce_drops_a_forged_source_address() {
        let (dev_a, dev_b, mut rx_b, pk_a) = rpf_pair(RpfMode::Enforce).await;
        let forged = Ipv4Addr::new(10, 66, 51, 147);
        send_until_ok(
            &dev_a,
            &dev_b.public().to_bytes(),
            &synthetic_ipv4(forged, IP_B, b"spoof"),
        )
        .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(500), rx_b.recv())
                .await
                .is_err(),
            "a forged source must never reach the TUN under enforce"
        );
        assert_eq!(dev_b.peer_rx_denied(&pk_a), 1);
    }

    /// `warn` (the built-in default) is non-destructive: it counts the same
    /// packet and DELIVERS it, so a fleet can measure the blast radius of
    /// `enforce` before flipping. A regression here would silently blackhole
    /// every node on upgrade.
    #[tokio::test(flavor = "multi_thread")]
    async fn rpf_warn_counts_a_forged_source_but_still_delivers_it() {
        let (dev_a, dev_b, mut rx_b, pk_a) = rpf_pair(RpfMode::Warn).await;
        let forged = Ipv4Addr::new(10, 66, 51, 147);
        send_until_ok(
            &dev_a,
            &dev_b.public().to_bytes(),
            &synthetic_ipv4(forged, IP_B, b"spoof"),
        )
        .await;
        let got = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("warn mode must not drop")
            .unwrap();
        assert_eq!(&got[20..], b"spoof");
        assert_eq!(dev_b.peer_rx_denied(&pk_a), 1);
    }

    /// The `NoRoute` subset counter splits exactly: a source NOBODY owns
    /// counts in both `rx_denied` and `rx_denied_noroute` (its replies are
    /// unroutable from this node — the multi-org wrong-source signature),
    /// while forging ANOTHER installed peer's address (`OtherPeer`) counts
    /// only in the total. Both delivered — this is `warn`.
    #[tokio::test(flavor = "multi_thread")]
    async fn rpf_warn_splits_the_noroute_counter() {
        let (dev_a, mut dev_b, mut rx_b, pk_a) = rpf_pair(RpfMode::Warn).await;
        let pk_b = dev_b.public().to_bytes();

        let nobody = Ipv4Addr::new(10, 66, 51, 147);
        send_until_ok(&dev_a, &pk_b, &synthetic_ipv4(nobody, IP_B, b"lost")).await;
        let got = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("warn mode must not drop")
            .unwrap();
        assert_eq!(&got[20..], b"lost");
        assert_eq!(dev_b.peer_rx_denied(&pk_a), 1);
        assert_eq!(dev_b.peer_rx_denied_noroute(&pk_a), 1);

        // A third identity B has installed: forging ITS address is OtherPeer —
        // total climbs, the NoRoute subset does not.
        let c = WgKeypair::generate();
        let sock_c = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_c = sock_c.local_addr().unwrap();
        let ip_c = Ipv4Addr::new(100, 64, 0, 9);
        dev_b.add_peer(
            c.public.to_bytes(),
            ip_c,
            Carrier::direct(sock_c, addr_c),
            false,
        );
        send_until_ok(&dev_a, &pk_b, &synthetic_ipv4(ip_c, IP_B, b"forge")).await;
        let got = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("warn mode must not drop")
            .unwrap();
        assert_eq!(&got[20..], b"forge");
        assert_eq!(dev_b.peer_rx_denied(&pk_a), 2);
        assert_eq!(
            dev_b.peer_rx_denied_noroute(&pk_a),
            1,
            "OtherPeer must not count as NoRoute"
        );
    }

    /// The destination half: a peer with a perfectly legitimate SOURCE aims
    /// past us at a LAN address this node never advertised. Before P4 the
    /// packet went to the TUN and the OS forwarded it if it had any route —
    /// which is how "approved for one subnet" became "reaches everything".
    #[tokio::test(flavor = "multi_thread")]
    async fn ingress_scope_drops_a_destination_this_node_never_advertised() {
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let (mut dev_a, _rx_a) = WgDevice::new(a.secret.clone());
        let (mut dev_b, mut rx_b) = WgDevice::new(b.secret.clone());
        dev_b.set_rpf_mode(RpfMode::Enforce);
        // B is a subnet router for 10.66.0.0/16 and nothing else.
        dev_b.set_local_scope(Some(IP_B), &["10.66.0.0/16".to_string()]);

        dev_a.add_peer(
            b.public.to_bytes(),
            IP_B,
            Carrier::direct(sock_a.clone(), addr_b),
            true,
        );
        dev_b.add_peer(
            a.public.to_bytes(),
            IP_A,
            Carrier::direct(sock_b.clone(), addr_a),
            false,
        );
        wait_connected(&dev_a, &b.public.to_bytes()).await;
        let pk_b = dev_b.public().to_bytes();

        // In scope: addressed into the advertised LAN. Honest source throughout.
        send_until_ok(
            &dev_a,
            &pk_b,
            &synthetic_ipv4(IP_A, Ipv4Addr::new(10, 66, 51, 147), b"lan"),
        )
        .await;
        let got = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("an advertised destination must be delivered")
            .unwrap();
        assert_eq!(&got[20..], b"lan");
        assert_eq!(dev_b.peer_rx_denied(&a.public.to_bytes()), 0);

        // Out of scope: a different RFC1918 range B never advertised.
        send_until_ok(
            &dev_a,
            &pk_b,
            &synthetic_ipv4(IP_A, Ipv4Addr::new(10, 84, 6, 5), b"past"),
        )
        .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(500), rx_b.recv())
                .await
                .is_err(),
            "a destination outside the node's advertised scope must not reach the TUN"
        );
        assert_eq!(dev_b.peer_rx_denied(&a.public.to_bytes()), 1);

        // Traffic addressed to B ITSELF is always in scope.
        send_until_ok(&dev_a, &pk_b, &synthetic_ipv4(IP_A, IP_B, b"self")).await;
        let got = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("traffic to the node's own overlay IP must be delivered")
            .unwrap();
        assert_eq!(&got[20..], b"self");
    }

    /// P4 per-source narrowing: two peers, identical honest traffic into the
    /// same advertised subnet, but only one is granted :22 — the tier neither
    /// the netmap `routes` list nor `LocalScope` can express.
    #[tokio::test(flavor = "multi_thread")]
    async fn per_source_rules_narrow_one_peer_without_touching_another() {
        use roomler_ai_remote_control::models::{PortRange, ProtocolKind};

        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let (mut dev_a, _rx_a) = WgDevice::new(a.secret.clone());
        let (mut dev_b, mut rx_b) = WgDevice::new(b.secret.clone());
        dev_b.set_rpf_mode(RpfMode::Enforce);
        dev_b.set_local_scope(Some(IP_B), &["10.66.0.0/16".to_string()]);

        // The server granted A only TCP/22 into the LAN B fronts.
        let mut np = netmap_peer_for(&a, IP_A);
        np.ingress_rules = Some(vec![OverlayRule {
            cidr: "10.66.0.0/16".into(),
            port_range: PortRange { low: 22, high: 22 },
            proto: ProtocolKind::Tcp,
        }]);
        let mut peers = HashMap::new();
        peers.insert(np.node_id, np);
        dev_b.sync_peer_ingress(&peers);

        dev_a.add_peer(
            b.public.to_bytes(),
            IP_B,
            Carrier::direct(sock_a.clone(), addr_b),
            true,
        );
        dev_b.add_peer(
            a.public.to_bytes(),
            IP_A,
            Carrier::direct(sock_b.clone(), addr_a),
            false,
        );
        wait_connected(&dev_a, &b.public.to_bytes()).await;
        let pk_b = dev_b.public().to_bytes();
        let lan = Ipv4Addr::new(10, 66, 51, 147);

        // Granted: TCP/22 into the advertised LAN.
        send_until_ok(&dev_a, &pk_b, &synthetic_tcp(IP_A, lan, 22, b"ssh")).await;
        let got = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("a granted destination+port must be delivered")
            .unwrap();
        assert_eq!(&got[24..], b"ssh");

        // Same peer, same subnet, NOT granted port — this is what LocalScope
        // alone could never have stopped.
        send_until_ok(&dev_a, &pk_b, &synthetic_tcp(IP_A, lan, 443, b"web")).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(500), rx_b.recv())
                .await
                .is_err(),
            "a port the ACL did not grant must not reach the TUN"
        );

        // #18 — traffic addressed to B ITSELF is narrowed too: the grant covers
        // only the LAN, so a new flow to B's own address is refused.
        send_until_ok(&dev_a, &pk_b, &synthetic_tcp(IP_A, IP_B, 443, b"self")).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(500), rx_b.recv())
                .await
                .is_err(),
            "a new flow to the node's own address is judged by the rules"
        );
    }

    /// A TCP segment with real flags, or a UDP datagram, for the #18 tests.
    fn synthetic_l4(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        udp: bool,
        ports: (u16, u16),
        flags: u8,
    ) -> Vec<u8> {
        let hl = if udp { 8 } else { 20 };
        let mut p = vec![0u8; 20 + hl];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + hl) as u16).to_be_bytes());
        p[8] = 64;
        p[9] = if udp { 17 } else { 6 };
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20..22].copy_from_slice(&ports.0.to_be_bytes());
        p[22..24].copy_from_slice(&ports.1.to_be_bytes());
        if !udp {
            p[32] = 0x50;
            p[33] = flags;
        }
        p
    }

    /// #18 — the tenant's rules decide whatever `overlay_rpf` says (here its
    /// default, warn), and they narrow traffic to the node itself statefully:
    /// a new connection or datagram is judged, a reply to a flow the node
    /// started is not.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_acl_narrows_traffic_to_the_node_itself_and_admits_its_replies() {
        use roomler_ai_remote_control::models::{PortRange, ProtocolKind};

        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        let (mut dev_a, _rx_a) = WgDevice::new(a.secret.clone());
        let (mut dev_b, mut rx_b) = WgDevice::new(b.secret.clone());
        assert_eq!(dev_b.rpf_mode(), RpfMode::Warn, "the default posture");
        dev_b.set_local_scope(Some(IP_B), &[]);
        // The server granted A only TCP/22 on B.
        let mut np = netmap_peer_for(&a, IP_A);
        np.ingress_rules = Some(vec![OverlayRule {
            cidr: format!("{IP_B}/32"),
            port_range: PortRange { low: 22, high: 22 },
            proto: ProtocolKind::Tcp,
        }]);
        let mut peers = HashMap::new();
        peers.insert(np.node_id, np);
        dev_b.sync_peer_ingress(&peers);
        dev_a.add_peer(
            b.public.to_bytes(),
            IP_B,
            Carrier::direct(sock_a.clone(), addr_b),
            true,
        );
        dev_b.add_peer(
            a.public.to_bytes(),
            IP_A,
            Carrier::direct(sock_b.clone(), addr_a),
            false,
        );
        wait_connected(&dev_a, &b.public.to_bytes()).await;
        let (pk_a, pk_b) = (a.public.to_bytes(), dev_b.public().to_bytes());
        async fn delivered(rx: &mut mpsc::Receiver<Vec<u8>>) -> Option<Vec<u8>> {
            tokio::time::timeout(Duration::from_millis(600), rx.recv())
                .await
                .ok()
                .flatten()
        }

        send_until_ok(
            &dev_a,
            &pk_b,
            &synthetic_l4(IP_A, IP_B, false, (40000, 22), 0x02),
        )
        .await;
        assert!(delivered(&mut rx_b).await.is_some(), "a granted SYN");
        send_until_ok(
            &dev_a,
            &pk_b,
            &synthetic_l4(IP_A, IP_B, false, (40001, 443), 0x02),
        )
        .await;
        assert!(
            delivered(&mut rx_b).await.is_none(),
            "a SYN to a port not granted, under warn"
        );
        send_until_ok(
            &dev_a,
            &pk_b,
            &synthetic_l4(IP_A, IP_B, true, (5353, 4000), 0),
        )
        .await;
        assert!(
            delivered(&mut rx_b).await.is_none(),
            "an unsolicited datagram"
        );

        // B starts a UDP flow to A; A's answer is a reply, not new traffic.
        send_until_ok(
            &dev_b,
            &pk_a,
            &synthetic_l4(IP_B, IP_A, true, (4000, 5353), 0),
        )
        .await;
        send_until_ok(
            &dev_a,
            &pk_b,
            &synthetic_l4(IP_A, IP_B, true, (5353, 4000), 0),
        )
        .await;
        assert!(
            delivered(&mut rx_b).await.is_some(),
            "the reply to B's own flow"
        );
        // An established TCP segment (B's own connection to A:443).
        send_until_ok(
            &dev_a,
            &pk_b,
            &synthetic_l4(IP_A, IP_B, false, (443, 40002), 0x10),
        )
        .await;
        assert!(
            delivered(&mut rx_b).await.is_some(),
            "an ACK segment of an established connection"
        );
    }

    /// A peer with NO compiled rules keeps the pre-P4 behaviour: only the coarse
    /// scope applies. This is the compatibility guarantee for a pre-P4 server
    /// and for any tenant that isn't enforcing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_without_compiled_rules_is_governed_only_by_scope() {
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let (mut dev_a, _rx_a) = WgDevice::new(a.secret.clone());
        let (mut dev_b, mut rx_b) = WgDevice::new(b.secret.clone());
        dev_b.set_rpf_mode(RpfMode::Enforce);
        dev_b.set_local_scope(Some(IP_B), &["10.66.0.0/16".to_string()]);

        // Netmap entry with ingress_rules = None ⇒ no table entry at all.
        let mut peers = HashMap::new();
        let np = netmap_peer_for(&a, IP_A);
        peers.insert(np.node_id, np);
        dev_b.sync_peer_ingress(&peers);

        dev_a.add_peer(
            b.public.to_bytes(),
            IP_B,
            Carrier::direct(sock_a.clone(), addr_b),
            true,
        );
        dev_b.add_peer(
            a.public.to_bytes(),
            IP_A,
            Carrier::direct(sock_b.clone(), addr_a),
            false,
        );
        wait_connected(&dev_a, &b.public.to_bytes()).await;
        let pk_b = dev_b.public().to_bytes();

        // Any port into the advertised LAN is fine — nothing narrowed it.
        send_until_ok(
            &dev_a,
            &pk_b,
            &synthetic_tcp(IP_A, Ipv4Addr::new(10, 66, 51, 147), 443, b"web"),
        )
        .await;
        assert!(
            tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
                .await
                .is_ok(),
            "with no compiled rules only the coarse scope applies"
        );
    }

    /// `off` restores the pre-P4 behaviour exactly: delivered AND not counted.
    #[tokio::test(flavor = "multi_thread")]
    async fn rpf_off_does_not_even_count() {
        let (dev_a, dev_b, mut rx_b, pk_a) = rpf_pair(RpfMode::Off).await;
        send_until_ok(
            &dev_a,
            &dev_b.public().to_bytes(),
            &synthetic_ipv4(Ipv4Addr::new(10, 66, 51, 147), IP_B, b"spoof"),
        )
        .await;
        assert!(
            tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
                .await
                .is_ok(),
            "off mode must deliver"
        );
        assert_eq!(dev_b.peer_rx_denied(&pk_a), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wg_handshake_and_data_over_direct_udp() {
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();

        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let (mut dev_a, _rx_a) = WgDevice::new(a.secret.clone());
        let (mut dev_b, mut rx_b) = WgDevice::new(b.secret.clone());

        dev_a.add_peer(
            b.public.to_bytes(),
            IP_B,
            Carrier::direct(sock_a.clone(), addr_b),
            true,
        );
        dev_b.add_peer(
            a.public.to_bytes(),
            IP_A,
            Carrier::direct(sock_b.clone(), addr_a),
            false,
        );

        wait_connected(&dev_a, &b.public.to_bytes()).await;

        let pkt = synthetic_ipv4(IP_A, IP_B, b"hello-over-direct-wg");
        send_until_ok(&dev_a, &b.public.to_bytes(), &pkt).await;

        let got = tokio::time::timeout(Duration::from_secs(15), rx_b.recv())
            .await
            .expect("B did not receive a decrypted packet in time")
            .expect("tun channel closed");
        assert_eq!(got, pkt, "decrypted IP packet must arrive intact");
    }

    /// Phase C — `peer_handshake_done` latches once the WG session establishes
    /// (the lock-free signal the srflx/public health deadline reads). Unknown
    /// peers report `None`; a fresh peer reports `Some(false)` until the
    /// handshake completes, then `Some(true)` on BOTH the initiator and the
    /// responder (each sets it from an inbound packet).
    /// F2 — a STANDBY copy is taken into the peer's session through the ingress
    /// gate and reaches the TUN, while the data rx counter the business scout
    /// reads stays untouched; the same copy again (a replay) is dropped.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_standby_copy_reaches_the_tun_without_counting_as_carrier_rx() {
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let (pk_a, pk_b) = (a.public.to_bytes(), b.public.to_bytes());
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (addr_a, addr_b) = (sock_a.local_addr().unwrap(), sock_b.local_addr().unwrap());
        let (mut dev_a, _rx_a) = WgDevice::new(a.secret.clone());
        let (mut dev_b, mut rx_b) = WgDevice::new(b.secret.clone());
        dev_a.add_peer(pk_b, IP_B, Carrier::direct(sock_a.clone(), addr_b), true);
        dev_b.add_peer(pk_a, IP_A, Carrier::direct(sock_b.clone(), addr_a), false);
        wait_connected(&dev_a, &pk_b).await;

        let mux_b = crate::transport::derp::DerpMux::new(pk_b).0;
        assert!(dev_b.attach_standby_sink(&pk_a, mux_b.standby_route(pk_a)));
        // One packet A's session seals that travels ONLY as a standby copy.
        let pkt = synthetic_ipv4(IP_A, IP_B, b"standby-copy");
        let mut wire = vec![0u8; WG_BUF];
        let n = {
            let mut t = dev_a.peers[&pk_b].tunn.lock().await;
            encapsulate_into(&mut t, &pkt, &mut wire).expect("a session exists")
        };
        assert_eq!(wire[0], 4, "WG data");
        let rx_before = dev_b.peers[&pk_a].stats.rx.load(Ordering::Relaxed);
        let mut frame = pk_a.to_vec();
        frame.extend_from_slice(crate::transport::derp::STANDBY_MAGIC);
        frame.extend_from_slice(&wire[..n]);

        mux_b.deliver(&frame);
        let got = tokio::time::timeout(Duration::from_secs(5), rx_b.recv())
            .await
            .expect("the copy reaches B's TUN")
            .expect("tun channel open");
        assert_eq!(got, pkt);
        assert_eq!(
            dev_b.peers[&pk_a].stats.rx.load(Ordering::Relaxed),
            rx_before,
            "a copy is not carrier rx"
        );
        mux_b.deliver(&frame);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), rx_b.recv()).await.is_err(),
            "a replayed copy is dropped"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn peer_handshake_done_latches_on_session_establish() {
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let (mut dev_a, _rx_a) = WgDevice::new(a.secret.clone());
        let (mut dev_b, _rx_b) = WgDevice::new(b.secret.clone());

        // Unknown peer → None.
        assert_eq!(dev_a.peer_handshake_done(&b.public.to_bytes()), None);

        dev_a.add_peer(
            b.public.to_bytes(),
            IP_B,
            Carrier::direct(sock_a.clone(), addr_b),
            true,
        );
        dev_b.add_peer(
            a.public.to_bytes(),
            IP_A,
            Carrier::direct(sock_b.clone(), addr_a),
            false,
        );

        // Freshly added, pre-handshake → Some(false).
        assert_eq!(dev_a.peer_handshake_done(&b.public.to_bytes()), Some(false));

        wait_connected(&dev_a, &b.public.to_bytes()).await;
        wait_connected(&dev_b, &a.public.to_bytes()).await;

        // Both ends latch true (each established via an inbound packet).
        assert_eq!(dev_a.peer_handshake_done(&b.public.to_bytes()), Some(true));
        assert_eq!(dev_b.peer_handshake_done(&a.public.to_bytes()), Some(true));
    }

    /// rc.134 — one HUB device serves TWO peers over a SINGLE shared socket
    /// (the source-address demux). Proves N direct peers coexist without the
    /// per-peer-recv-loop race the old "one direct peer" cap worked around:
    /// both handshakes complete and the hub's data reaches the correct peer.
    #[tokio::test(flavor = "multi_thread")]
    async fn shared_direct_socket_demuxes_multiple_peers() {
        const IP_C: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 3);
        let hub = WgKeypair::generate();
        let b = WgKeypair::generate();
        let c = WgKeypair::generate();

        let hub_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_c = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let hub_addr = hub_sock.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        let addr_c = sock_c.local_addr().unwrap();

        let (mut dev_hub, _rx_hub) = WgDevice::new(hub.secret.clone());
        let (mut dev_b, mut rx_b) = WgDevice::new(b.secret.clone());
        let (mut dev_c, mut rx_c) = WgDevice::new(c.secret.clone());

        // Hub: BOTH peers over the ONE shared socket (inbound demuxed by src).
        dev_hub.ensure_direct_demux(hub_sock.clone());
        dev_hub
            .add_direct_peer(hub_sock.clone(), b.public.to_bytes(), IP_B, addr_b, true)
            .await;
        dev_hub
            .add_direct_peer(hub_sock.clone(), c.public.to_bytes(), IP_C, addr_c, true)
            .await;

        // Peers: dedicated sockets, respond to the hub's initiation.
        dev_b.add_peer(
            hub.public.to_bytes(),
            IP_A,
            Carrier::direct(sock_b.clone(), hub_addr),
            false,
        );
        dev_c.add_peer(
            hub.public.to_bytes(),
            IP_A,
            Carrier::direct(sock_c.clone(), hub_addr),
            false,
        );

        // Both handshakes complete THROUGH the one shared socket — the hub's
        // demux routed each peer's response to the right Tunn.
        wait_connected(&dev_hub, &b.public.to_bytes()).await;
        wait_connected(&dev_hub, &c.public.to_bytes()).await;

        // And the hub's data reaches the correct peer (no cross-talk).
        let pkt_b = synthetic_ipv4(IP_A, IP_B, b"hub-to-b");
        send_until_ok(&dev_hub, &b.public.to_bytes(), &pkt_b).await;
        let got_b = tokio::time::timeout(Duration::from_secs(15), rx_b.recv())
            .await
            .expect("B did not receive its packet")
            .expect("tun channel closed");
        assert_eq!(got_b, pkt_b);

        let pkt_c = synthetic_ipv4(IP_A, IP_C, b"hub-to-c");
        send_until_ok(&dev_hub, &c.public.to_bytes(), &pkt_c).await;
        let got_c = tokio::time::timeout(Duration::from_secs(15), rx_c.recv())
            .await
            .expect("C did not receive its packet")
            .expect("tun channel closed");
        assert_eq!(got_c, pkt_c);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wg_handshake_and_data_over_relay_conn() {
        use crate::transport::relay::UdpRelayConn;

        let a = WgKeypair::generate();
        let b = WgKeypair::generate();

        // Drive the carrier through the `RelayConn` trait (the same trait
        // a coturn `TurnRelayConn` implements) to prove boringtun rides
        // it directly — no `RelayUdpSocket` quinn wrapper.
        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        let conn_a: Arc<dyn RelayConn> = Arc::new(UdpRelayConn(sock_a));
        let conn_b: Arc<dyn RelayConn> = Arc::new(UdpRelayConn(sock_b));

        let (mut dev_a, _rx_a) = WgDevice::new(a.secret.clone());
        let (mut dev_b, mut rx_b) = WgDevice::new(b.secret.clone());

        dev_a.add_peer(
            b.public.to_bytes(),
            IP_B,
            Carrier::relay(conn_a, addr_b),
            true,
        );
        dev_b.add_peer(
            a.public.to_bytes(),
            IP_A,
            Carrier::relay(conn_b, addr_a),
            false,
        );

        wait_connected(&dev_a, &b.public.to_bytes()).await;

        let pkt = synthetic_ipv4(IP_A, IP_B, b"hello-over-relay-wg");
        send_until_ok(&dev_a, &b.public.to_bytes(), &pkt).await;

        let got = tokio::time::timeout(Duration::from_secs(15), rx_b.recv())
            .await
            .expect("B did not receive a decrypted packet in time")
            .expect("tun channel closed");
        assert_eq!(
            got, pkt,
            "decrypted IP packet must arrive over the relay carrier"
        );
    }

    /// DERP carrier: two nodes carry WG over a pubkey-addressed relay with NO
    /// UDP anywhere (the both-UDP-blocked tier). Mirrors
    /// `wg_handshake_and_data_over_relay_conn`, but each side's `RelayConn` is a
    /// `DerpConn` fed by a `DerpMux`, and a mock in-process relay plays the
    /// server (`crate::ws::derp`): read a node's outbound `[dst||payload]`,
    /// deliver `[src||payload]` to the dst's mux. Proves RAW WG rides DERP both
    /// ways — the pubkey pinning makes the recv-source discard harmless.
    #[tokio::test(flavor = "multi_thread")]
    async fn wg_handshake_and_data_over_derp() {
        use crate::transport::derp::DerpMux;

        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let a_pk = a.public.to_bytes();
        let b_pk = b.public.to_bytes();

        let (mux_a, mut a_out) = DerpMux::new(a_pk);
        let (mux_b, mut b_out) = DerpMux::new(b_pk);

        // Mock relay A→B: A frames [B||payload]; deliver to B as [A||payload].
        {
            let mux_b = Arc::clone(&mux_b);
            tokio::spawn(async move {
                while let Some((_queued_at, frame)) = a_out.recv().await {
                    let mut out = a_pk.to_vec();
                    out.extend_from_slice(&frame[32..]);
                    mux_b.deliver(&out);
                }
            });
        }
        // Mock relay B→A.
        {
            let mux_a = Arc::clone(&mux_a);
            tokio::spawn(async move {
                while let Some((_queued_at, frame)) = b_out.recv().await {
                    let mut out = b_pk.to_vec();
                    out.extend_from_slice(&frame[32..]);
                    mux_a.deliver(&out);
                }
            });
        }

        let conn_a: Arc<dyn RelayConn> = Arc::new(mux_a.conn_for(b_pk));
        let conn_b: Arc<dyn RelayConn> = Arc::new(mux_b.conn_for(a_pk));

        let (mut dev_a, _rx_a) = WgDevice::new(a.secret.clone());
        let (mut dev_b, mut rx_b) = WgDevice::new(b.secret.clone());

        // Synthetic dsts — `DerpConn` is pubkey-addressed and ignores them.
        let dst_b: SocketAddr = "100.64.0.2:51820".parse().unwrap();
        let dst_a: SocketAddr = "100.64.0.1:51820".parse().unwrap();

        dev_a.add_peer(b_pk, IP_B, Carrier::relay(conn_a, dst_b), true);
        dev_b.add_peer(a_pk, IP_A, Carrier::relay(conn_b, dst_a), false);

        wait_connected(&dev_a, &b_pk).await;

        let pkt = synthetic_ipv4(IP_A, IP_B, b"hello-over-derp");
        send_until_ok(&dev_a, &b_pk, &pkt).await;

        let got = tokio::time::timeout(Duration::from_secs(15), rx_b.recv())
            .await
            .expect("B did not receive a decrypted packet over DERP in time")
            .expect("tun channel closed");
        assert_eq!(
            got, pkt,
            "decrypted IP packet must arrive over the DERP carrier"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wg_handshake_and_data_over_quic_relay() {
        use crate::transport::relay::UdpRelayConn;

        let a = WgKeypair::generate();
        let b = WgKeypair::generate();

        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        let conn_a: Arc<dyn RelayConn> = Arc::new(UdpRelayConn(sock_a));
        let conn_b: Arc<dyn RelayConn> = Arc::new(UdpRelayConn(sock_b));

        // Same deterministic role rule as `install_ready`: the smaller pubkey is
        // BOTH the WG initiator AND the QUIC server. Build both carriers
        // CONCURRENTLY — the server's `accept()` blocks on the client's dial.
        let a_is_server = a.public.to_bytes() < b.public.to_bytes();
        let (car_a, car_b) = tokio::join!(
            Carrier::quic_relay(conn_a, addr_b, a_is_server, 1312, Duration::from_secs(10)),
            Carrier::quic_relay(conn_b, addr_a, !a_is_server, 1312, Duration::from_secs(10)),
        );
        let car_a = car_a.expect("A: QUIC-over-relay carrier");
        let car_b = car_b.expect("B: QUIC-over-relay carrier");

        let (mut dev_a, mut rx_a) = WgDevice::new(a.secret.clone());
        let (mut dev_b, mut rx_b) = WgDevice::new(b.secret.clone());

        dev_a.add_peer(b.public.to_bytes(), IP_B, car_a, a_is_server);
        dev_b.add_peer(a.public.to_bytes(), IP_A, car_b, !a_is_server);

        wait_connected(&dev_a, &b.public.to_bytes()).await;

        // A → B
        let pkt_ab = synthetic_ipv4(IP_A, IP_B, b"hello-over-quic-relay");
        send_until_ok(&dev_a, &b.public.to_bytes(), &pkt_ab).await;
        let got_b = tokio::time::timeout(Duration::from_secs(15), rx_b.recv())
            .await
            .expect("B did not receive a decrypted packet over QUIC")
            .expect("tun channel closed");
        assert_eq!(got_b, pkt_ab);

        // B → A (bidirectional over the same QUIC datagram carrier)
        let pkt_ba = synthetic_ipv4(IP_B, IP_A, b"reply-over-quic-relay");
        send_until_ok(&dev_b, &a.public.to_bytes(), &pkt_ba).await;
        let got_a = tokio::time::timeout(Duration::from_secs(15), rx_a.recv())
            .await
            .expect("A did not receive a decrypted packet over QUIC")
            .expect("tun channel closed");
        assert_eq!(got_a, pkt_ba);
    }

    /// A `RelayConn` that models **coturn's PERMISSION rule**: an allocation
    /// only receives datagrams from a peer **IP** it has previously SENT to
    /// (coturn installs a permission on send, then drops inbound from any peer
    /// it has no permission for). A plain [`UdpRelayConn`] can't reproduce the
    /// cross-NAT relay deadlock because it has no such gate — this can.
    ///
    /// **Permissions are IP-only** (RFC 8656 §9 — the port is ignored; verified
    /// in webrtc-rs `turn` client `permission.rs` + server `allocation/mod.rs`).
    /// This is load-bearing for Phase D single-relay: a symmetric-NAT dialer's
    /// source PORT varies per destination, but the anchor's permission (keyed by
    /// the dialer's IP) still matches — so a permit installed by sending to one
    /// port accepts inbound from the SAME IP on a DIFFERENT port. Keying by full
    /// `SocketAddr` (the pre-fix bug) would wrongly drop it.
    struct PermissionedRelayConn {
        sock: UdpSocket,
        permitted: std::sync::Mutex<std::collections::HashSet<std::net::IpAddr>>,
    }
    impl PermissionedRelayConn {
        fn new(sock: UdpSocket) -> Self {
            Self {
                sock,
                permitted: std::sync::Mutex::new(std::collections::HashSet::new()),
            }
        }
    }
    #[async_trait::async_trait]
    impl RelayConn for PermissionedRelayConn {
        async fn send_to(&self, buf: &[u8], dst: std::net::SocketAddr) -> std::io::Result<usize> {
            // Sending to a peer opens (permits) its IP — exactly coturn's
            // CreatePermission-on-send behaviour (IP-only, port ignored).
            self.permitted.lock().unwrap().insert(dst.ip());
            self.sock.send_to(buf, dst).await
        }
        async fn recv_from(
            &self,
            buf: &mut [u8],
        ) -> std::io::Result<(usize, std::net::SocketAddr)> {
            loop {
                let (n, src) = self.sock.recv_from(buf).await?;
                if self.permitted.lock().unwrap().contains(&src.ip()) {
                    return Ok((n, src));
                }
                // Unpermitted peer IP → coturn drops it. Keep waiting.
            }
        }
        fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            self.sock.local_addr()
        }
    }

    /// rc.199 regression — reproduces the cross-NAT relay deadlock and proves
    /// the mutual permission bootstrap fixes it. With coturn's permission model
    /// (`PermissionedRelayConn`) and a SINGLE WG initiator (the relay's rule),
    /// the passive responder never sends first → never permits the initiator →
    /// coturn drops the INIT → `HANDSHAKE(REKEY_TIMEOUT)` forever. `install_ready`
    /// now sends a stray `\x00` from BOTH ends before the handshake; here we
    /// prove (1) it deadlocks WITHOUT the bootstrap and (2) completes WITH it.
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_wg_deadlocks_without_permission_bootstrap_and_works_with_it() {
        // ── (1) WITHOUT the bootstrap: single initiator deadlocks. ──
        {
            let a = WgKeypair::generate();
            let b = WgKeypair::generate();
            let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr_a = sock_a.local_addr().unwrap();
            let addr_b = sock_b.local_addr().unwrap();
            let conn_a: Arc<dyn RelayConn> = Arc::new(PermissionedRelayConn::new(sock_a));
            let conn_b: Arc<dyn RelayConn> = Arc::new(PermissionedRelayConn::new(sock_b));
            let a_init = a.public.to_bytes() < b.public.to_bytes();
            let (mut dev_a, _rx_a) = WgDevice::new(a.secret.clone());
            let (mut dev_b, _rx_b) = WgDevice::new(b.secret.clone());
            // Single initiator (the smaller pubkey), exactly like install_ready.
            dev_a.add_peer(
                b.public.to_bytes(),
                IP_B,
                Carrier::relay(conn_a, addr_b),
                a_init,
            );
            dev_b.add_peer(
                a.public.to_bytes(),
                IP_A,
                Carrier::relay(conn_b, addr_a),
                !a_init,
            );
            let initiator = if a_init { &dev_a } else { &dev_b };
            let peer = if a_init {
                b.public.to_bytes()
            } else {
                a.public.to_bytes()
            };
            // Must NOT connect: the responder's allocation never permits the
            // initiator, so coturn drops every INIT.
            let connected =
                tokio::time::timeout(Duration::from_secs(3), wait_connected(initiator, &peer))
                    .await
                    .is_ok();
            assert!(
                !connected,
                "single-initiator relay must DEADLOCK without the permission bootstrap"
            );
        }
        // ── (2) WITH the mutual bootstrap: the handshake completes. ──
        {
            let a = WgKeypair::generate();
            let b = WgKeypair::generate();
            let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr_a = sock_a.local_addr().unwrap();
            let addr_b = sock_b.local_addr().unwrap();
            let conn_a: Arc<dyn RelayConn> = Arc::new(PermissionedRelayConn::new(sock_a));
            let conn_b: Arc<dyn RelayConn> = Arc::new(PermissionedRelayConn::new(sock_b));
            // The rc.199 fix: BOTH ends bootstrap their coturn permission before
            // the handshake (what install_ready now does for every relay carrier).
            conn_a.send_to(b"\x00", addr_b).await.unwrap();
            conn_b.send_to(b"\x00", addr_a).await.unwrap();
            let a_init = a.public.to_bytes() < b.public.to_bytes();
            let (mut dev_a, _rx_a) = WgDevice::new(a.secret.clone());
            let (mut dev_b, mut rx_b) = WgDevice::new(b.secret.clone());
            // Register both, single initiator (exactly install_ready's rule).
            dev_a.add_peer(
                b.public.to_bytes(),
                IP_B,
                Carrier::relay(conn_a, addr_b),
                a_init,
            );
            dev_b.add_peer(
                a.public.to_bytes(),
                IP_A,
                Carrier::relay(conn_b, addr_a),
                !a_init,
            );
            // A → B completes now that both permissions are open.
            wait_connected(&dev_a, &b.public.to_bytes()).await;
            let pkt = synthetic_ipv4(IP_A, IP_B, b"relay-after-bootstrap");
            send_until_ok(&dev_a, &b.public.to_bytes(), &pkt).await;
            let got = tokio::time::timeout(Duration::from_secs(15), rx_b.recv())
                .await
                .expect("B did not receive a decrypted packet after the bootstrap")
                .expect("tun channel closed");
            assert_eq!(
                got, pkt,
                "handshake + data must flow once both ends bootstrap"
            );
        }
    }

    /// Phase D single-relay — WG completes over ONE coturn allocation with a RAW
    /// dialer whose source PORT differs from the port the anchor permitted (the
    /// symmetric-NAT-safe path). The ANCHOR (smaller pubkey) is the QUIC server
    /// over a `PermissionedRelayConn` (its "allocation"), permitting only the
    /// dialer's IP via a send to a DIFFERENT port (9); the DIALER (larger pubkey)
    /// is the QUIC client over a plain `UdpRelayConn` (no allocation) dialing the
    /// anchor's relayed addr. IP-only permission ⇒ the dialer's real-port traffic
    /// is accepted and WG handshakes + data flows both ways — no both-allocate
    /// hairpin, one permission. This is the wg-level guard for V-D1 (which proved
    /// the same live over coturn).
    #[tokio::test(flavor = "multi_thread")]
    async fn wg_single_relay_symmetric_over_quic() {
        use crate::transport::relay::UdpRelayConn;

        // Anchor = smaller pubkey, dialer = larger (the single-relay role rule,
        // which == install_ready's existing am_server/initiate rule, so v1 needs
        // no role decoupling).
        let (anchor, dialer) = {
            let k1 = WgKeypair::generate();
            let k2 = WgKeypair::generate();
            if k1.public.to_bytes() < k2.public.to_bytes() {
                (k1, k2)
            } else {
                (k2, k1)
            }
        };

        let sock_anchor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_dialer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let r_anchor = sock_anchor.local_addr().unwrap(); // relayed addr the dialer dials
        let addr_dialer = sock_dialer.local_addr().unwrap();

        // Anchor's "allocation" enforces IP-only permissions; the dialer is a
        // plain raw socket (no allocation).
        let conn_anchor: Arc<dyn RelayConn> = Arc::new(PermissionedRelayConn::new(sock_anchor));
        let conn_dialer: Arc<dyn RelayConn> = Arc::new(UdpRelayConn(sock_dialer));

        // The anchor permits the dialer's IP by sending its \x00 bootstrap to a
        // DIFFERENT port than the dialer's real one (a live dummy socket, so no
        // ICMP-unreachable poisons the anchor's recv on Windows) — modelling a
        // symmetric NAT where coturn observes a port the advertised srflx didn't
        // name. IP-only permission ⇒ the dialer's real-port traffic is still
        // accepted (permit port ≠ accept port, same IP).
        let _permit_dummy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let permit_target = _permit_dummy.local_addr().unwrap();
        assert_ne!(
            permit_target.port(),
            addr_dialer.port(),
            "permit port must differ from the dialer's real port to prove IP-only"
        );

        // Anchor = QUIC server + WG initiator; dialer = QUIC client + responder.
        // Build concurrently — the server's accept() blocks on the client's dial.
        let (car_anchor, car_dialer) = tokio::join!(
            Carrier::quic_relay(
                conn_anchor,
                permit_target,
                true,
                1312,
                Duration::from_secs(10)
            ),
            Carrier::quic_relay(conn_dialer, r_anchor, false, 1312, Duration::from_secs(10)),
        );
        let car_anchor = car_anchor.expect("anchor: QUIC-over-single-relay carrier");
        let car_dialer = car_dialer.expect("dialer: QUIC-over-single-relay carrier");

        let (mut dev_anchor, mut rx_anchor) = WgDevice::new(anchor.secret.clone());
        let (mut dev_dialer, mut rx_dialer) = WgDevice::new(dialer.secret.clone());

        dev_anchor.add_peer(dialer.public.to_bytes(), IP_B, car_anchor, true);
        dev_dialer.add_peer(anchor.public.to_bytes(), IP_A, car_dialer, false);

        wait_connected(&dev_anchor, &dialer.public.to_bytes()).await;

        // anchor → dialer
        let pkt_ad = synthetic_ipv4(IP_A, IP_B, b"hello-single-relay");
        send_until_ok(&dev_anchor, &dialer.public.to_bytes(), &pkt_ad).await;
        let got_d = tokio::time::timeout(Duration::from_secs(15), rx_dialer.recv())
            .await
            .expect("dialer received no decrypted packet")
            .expect("tun channel closed");
        assert_eq!(got_d, pkt_ad);

        // dialer → anchor (bidirectional over the single-relay carrier)
        let pkt_da = synthetic_ipv4(IP_B, IP_A, b"reply-single-relay");
        send_until_ok(&dev_dialer, &anchor.public.to_bytes(), &pkt_da).await;
        let got_a = tokio::time::timeout(Duration::from_secs(15), rx_anchor.recv())
            .await
            .expect("anchor received no decrypted packet")
            .expect("tun channel closed");
        assert_eq!(got_a, pkt_da);
    }

    // ───────────── LIVE coturn smoke (two real TURN allocations) ─────────────
    //
    // Mirrors `relay::turn_tests::relay_against_real_coturn_udp`: two WG
    // devices, each riding its own coturn allocation, complete a
    // handshake + round-trip a packet over the live cluster. `#[ignore]`
    // + env-gated. Provide:
    //   ROOMLER_TEST_TURN_HOST   = coturn.roomler.ai
    //   ROOMLER_TEST_TURN_SECRET = coturn's static-auth-secret
    // and run on a host with outbound UDP/3478 (or TCP/443 for the TURNS
    // variant) to coturn:
    //   cargo test -p roomler-ai-tunnel-core --features overlay --ignored wg_against_real_coturn

    fn live_coturn_creds(
        url_fmt: impl Fn(&str) -> Vec<String>,
    ) -> Option<(Vec<String>, String, String)> {
        let host = std::env::var("ROOMLER_TEST_TURN_HOST").ok()?;
        let secret = std::env::var("ROOMLER_TEST_TURN_SECRET").ok()?;
        let cfg = roomler_ai_remote_control::turn_creds::TurnConfig {
            workers: vec![],
            urls: url_fmt(&host),
            shared_secret: secret,
            ttl_secs: 600,
        };
        let ice = cfg.issue("wg-coturn-smoke");
        Some((ice.urls, ice.username?, ice.credential?))
    }

    async fn wg_over_two_live_allocations(urls: &[String], user: &str, cred: &str) {
        use crate::transport::relay::allocate_relay_from_ice;

        let a = WgKeypair::generate();
        let b = WgKeypair::generate();

        let relay_a = allocate_relay_from_ice(urls, user, cred)
            .await
            .expect("device A relay allocate (live coturn)");
        let relay_b = allocate_relay_from_ice(urls, user, cred)
            .await
            .expect("device B relay allocate (live coturn)");
        let r_a = relay_a.local_addr().unwrap();
        let r_b = relay_b.local_addr().unwrap();
        assert_ne!(r_a, r_b, "two allocations get distinct relay addrs");

        // Mutual TURN-permission bootstrap (one stray datagram each way).
        relay_a.send_to(b"\x00", r_b).await.unwrap();
        relay_b.send_to(b"\x00", r_a).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        let (mut dev_a, _rx_a) = WgDevice::new(a.secret.clone());
        let (mut dev_b, mut rx_b) = WgDevice::new(b.secret.clone());
        dev_a.add_peer(
            b.public.to_bytes(),
            IP_B,
            Carrier::relay(Arc::new(relay_a), r_b),
            true,
        );
        dev_b.add_peer(
            a.public.to_bytes(),
            IP_A,
            Carrier::relay(Arc::new(relay_b), r_a),
            false,
        );

        wait_connected(&dev_a, &b.public.to_bytes()).await;
        let pkt = synthetic_ipv4(IP_A, IP_B, b"hello-over-coturn-wg");
        send_until_ok(&dev_a, &b.public.to_bytes(), &pkt).await;

        let got = tokio::time::timeout(Duration::from_secs(30), rx_b.recv())
            .await
            .expect("B did not receive a decrypted packet over coturn in time")
            .expect("tun channel closed");
        assert_eq!(got, pkt, "WG packet must round-trip over live coturn");
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "hits live coturn; set ROOMLER_TEST_TURN_HOST + ROOMLER_TEST_TURN_SECRET"]
    async fn wg_against_real_coturn_udp() {
        let Some((urls, user, cred)) =
            live_coturn_creds(|h| vec![format!("turn:{h}:3478?transport=udp")])
        else {
            eprintln!("SKIP wg_against_real_coturn_udp: env unset");
            return;
        };
        wg_over_two_live_allocations(&urls, &user, &cred).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "hits live coturn over TLS/TCP; set ROOMLER_TEST_TURN_HOST + ROOMLER_TEST_TURN_SECRET"]
    async fn wg_against_real_coturn_turns_tcp() {
        let Some((urls, user, cred)) =
            live_coturn_creds(|h| vec![format!("turns:{h}:443?transport=tcp")])
        else {
            eprintln!("SKIP wg_against_real_coturn_turns_tcp: env unset");
            return;
        };
        wg_over_two_live_allocations(&urls, &user, &cred).await;
    }

    /// ROOT-CAUSE DIAG for the both-allocate `REKEY_TIMEOUT`: full WG over TWO
    /// allocations pinned to the SAME worker (`ROOMLER_TEST_TURN_WORKER`). The
    /// raw relay-to-relay hairpin already flows (see relay.rs
    /// `relay_to_relay_hairpin_against_real_coturn`), so if THIS passes the
    /// both-allocate CARRIER is sound when both allocations co-locate — meaning
    /// the field REKEY is the two ends landing on DIFFERENT workers (worker-pin
    /// miss / cross-worker drop), not a carrier bug. If it REKEYs even pinned,
    /// there's a WG-layer both-allocate bug the single-allocation single-relay
    /// path sidesteps. Set HOST/SECRET + WORKER (off-host).
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "hits live coturn; set ROOMLER_TEST_TURN_HOST/SECRET + ROOMLER_TEST_TURN_WORKER"]
    async fn wg_both_allocate_pinned_against_real_coturn() {
        let Some(worker) = std::env::var("ROOMLER_TEST_TURN_WORKER").ok() else {
            eprintln!("SKIP wg_both_allocate_pinned: ROOMLER_TEST_TURN_WORKER unset");
            return;
        };
        let Some((urls, user, cred)) =
            live_coturn_creds(|_h| vec![format!("turn:{worker}:3478?transport=udp")])
        else {
            eprintln!("SKIP wg_both_allocate_pinned: env unset");
            return;
        };
        eprintln!("wg_both_allocate_pinned: both allocations pinned to {worker}");
        wg_over_two_live_allocations(&urls, &user, &cred).await;
        eprintln!("wg_both_allocate_pinned: WG round-tripped over two SAME-worker allocations OK");
    }

    /// Phase D single-relay LIVE — WG completes over ONE real coturn allocation
    /// (the anchor) + a RAW-UDP dialer with NO allocation: the production
    /// single-relay carrier, end to end over prod coturn. The anchor allocates on
    /// a REMOTE worker (`ROOMLER_TEST_TURN_WORKER` — a worker that is NOT a local
    /// IP of this host, so the dialer's packet crosses the real network + coturn's
    /// PREROUTING DNAT rather than hair-pinning on loopback, the same-host artifact
    /// V-D1 hit). The dialer STUN-discovers its own public srflx so the anchor can
    /// install the IP-only coturn permission; both ends build QUIC-over-relay
    /// carriers (anchor server, dialer client) and WG handshakes + round-trips a
    /// packet BOTH ways. This is V-D1 (the raw-dialer QUIC round-trip, proven live
    /// 2026-07-20) PLUS the WG layer — exactly the leg the both-allocate relay
    /// carrier deadlocked on (`HANDSHAKE(REKEY_TIMEOUT)`), now over a single
    /// allocation with one IP-only permission.
    ///
    /// Run on a host with UDP/3478 to the worker (e.g. buildhost → fleet-host-1's worker):
    ///   ROOMLER_TEST_TURN_HOST=coturn.roomler.ai \
    ///   ROOMLER_TEST_TURN_SECRET=<coturn static-auth-secret> \
    ///   ROOMLER_TEST_TURN_WORKER=5.9.157.221 \
    ///   cargo test -p roomler-ai-tunnel-core --features overlay-l3 \
    ///     --lib wg_single_relay_against_real_coturn_udp -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "hits live coturn; set ROOMLER_TEST_TURN_HOST/SECRET + ROOMLER_TEST_TURN_WORKER"]
    async fn wg_single_relay_against_real_coturn_udp() {
        use crate::transport::relay::{UdpRelayConn, allocate_relay_from_ice};
        use crate::transport::stun::srflx_query;

        let Some(worker) = std::env::var("ROOMLER_TEST_TURN_WORKER").ok() else {
            eprintln!(
                "SKIP wg_single_relay_against_real_coturn_udp: ROOMLER_TEST_TURN_WORKER unset"
            );
            return;
        };
        // Creds are host-independent HMAC; pin the URL to the remote worker.
        let Some((urls, user, cred)) =
            live_coturn_creds(|_h| vec![format!("turn:{worker}:3478?transport=udp")])
        else {
            eprintln!("SKIP wg_single_relay_against_real_coturn_udp: TURN env unset");
            return;
        };
        let worker_ip: std::net::IpAddr =
            worker.parse().expect("ROOMLER_TEST_TURN_WORKER is an IP");
        let stun_server = SocketAddr::new(worker_ip, 3478);

        // Anchor = smaller pubkey (QUIC server + WG initiator, install_ready's
        // rule); dialer = larger (QUIC client + WG responder).
        let (anchor, dialer) = {
            let k1 = WgKeypair::generate();
            let k2 = WgKeypair::generate();
            if k1.public.to_bytes() < k2.public.to_bytes() {
                (k1, k2)
            } else {
                (k2, k1)
            }
        };

        // Anchor: the SOLE real coturn allocation, on the remote worker.
        let alloc = allocate_relay_from_ice(&urls, &user, &cred)
            .await
            .expect("anchor: live coturn allocation");
        let r_anchor = alloc.local_addr().unwrap();
        eprintln!("single-relay-wg: anchor R={r_anchor}");

        // Dialer: a raw socket (NO allocation). Discover its public srflx so the
        // anchor can permit its IP (IP-only); the QUIC dial reuses this same
        // socket, so coturn observes the same source.
        let dialer_sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let dialer_srflx = srflx_query(&dialer_sock, stun_server, Duration::from_secs(3))
            .await
            .expect("dialer: srflx via STUN on the worker");
        eprintln!("single-relay-wg: dialer srflx={dialer_srflx}");

        let conn_anchor: Arc<dyn RelayConn> = Arc::new(alloc);
        let conn_dialer: Arc<dyn RelayConn> = Arc::new(UdpRelayConn(dialer_sock));

        // Build concurrently (the server's accept() blocks on the client dial).
        // The anchor's quic_relay sends its own `\x00` to dialer_srflx →
        // installs the IP-only permission before the handshake; the dialer's
        // sends `\x00` to R → opens its path + reaches coturn (rc.199 bootstrap).
        // min_datagram = 1312 = OVERLAY_MTU(1280) + WG_OVERHEAD(32) — the exact
        // budget install_ready demands, so a pass here proves the live coturn
        // QUIC datagram budget suffices for the production carrier.
        let (car_anchor, car_dialer) = tokio::join!(
            Carrier::quic_relay(
                conn_anchor,
                dialer_srflx,
                true,
                1312,
                Duration::from_secs(15)
            ),
            Carrier::quic_relay(conn_dialer, r_anchor, false, 1312, Duration::from_secs(15)),
        );
        let car_anchor = car_anchor.expect("anchor: single-relay QUIC carrier over live coturn");
        let car_dialer = car_dialer.expect("dialer: single-relay QUIC carrier over live coturn");

        let (mut dev_anchor, mut rx_anchor) = WgDevice::new(anchor.secret.clone());
        let (mut dev_dialer, mut rx_dialer) = WgDevice::new(dialer.secret.clone());
        dev_anchor.add_peer(dialer.public.to_bytes(), IP_B, car_anchor, true);
        dev_dialer.add_peer(anchor.public.to_bytes(), IP_A, car_dialer, false);

        wait_connected(&dev_anchor, &dialer.public.to_bytes()).await;

        // anchor → dialer
        let pkt_ad = synthetic_ipv4(IP_A, IP_B, b"hello-single-relay-live");
        send_until_ok(&dev_anchor, &dialer.public.to_bytes(), &pkt_ad).await;
        let got_d = tokio::time::timeout(Duration::from_secs(30), rx_dialer.recv())
            .await
            .expect("dialer received no packet over live coturn")
            .expect("tun channel closed");
        assert_eq!(got_d, pkt_ad);

        // dialer → anchor (bidirectional over the single allocation)
        let pkt_da = synthetic_ipv4(IP_B, IP_A, b"reply-single-relay-live");
        send_until_ok(&dev_dialer, &anchor.public.to_bytes(), &pkt_da).await;
        let got_a = tokio::time::timeout(Duration::from_secs(30), rx_anchor.recv())
            .await
            .expect("anchor received no packet over live coturn")
            .expect("tun channel closed");
        assert_eq!(got_a, pkt_da);
        eprintln!("single-relay-wg: bidirectional WG over ONE live coturn allocation OK");
    }

    // rc.181 — a `RelayConn` whose `send_to` always hard-errors, mirroring a
    // TURNS/TCP `tcp-turn write: connection reset` after a corp middlebox reaps
    // the idle control TCP. `recv_from` parks forever; `local_addr` is a stub.
    struct FailingRelay;
    #[async_trait::async_trait]
    impl RelayConn for FailingRelay {
        async fn send_to(&self, _buf: &[u8], _dst: SocketAddr) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "tcp-turn write: connection reset (os error 10054)",
            ))
        }
        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
    }

    /// A `RelayConn` whose `send_to` always succeeds.
    struct OkRelay;
    #[async_trait::async_trait]
    impl RelayConn for OkRelay {
        async fn send_to(&self, buf: &[u8], _dst: SocketAddr) -> io::Result<usize> {
            Ok(buf.len())
        }
        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
    }

    #[tokio::test]
    async fn relay_send_error_latches_carrier_dead() {
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let carrier = Carrier::relay(Arc::new(FailingRelay), dst);
        assert!(!carrier.is_dead(), "a fresh relay carrier is alive");
        let r = carrier.send(b"wg-datagram").await;
        assert!(r.is_err(), "the mock relay hard-errors on send");
        assert!(
            carrier.is_dead(),
            "a hard send error must latch the carrier dead so the sweep re-allocates on the next tick"
        );
    }

    #[tokio::test]
    async fn healthy_relay_send_keeps_carrier_alive() {
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let carrier = Carrier::relay(Arc::new(OkRelay), dst);
        carrier.send(b"wg-datagram").await.expect("send ok");
        assert!(
            !carrier.is_dead(),
            "a successful send must not mark the carrier dead"
        );
    }

    /// A direct carrier dies ONLY when the local end reports it is gone.
    ///
    /// The old contract was "never dead", on the reasoning that a failed
    /// datagram is a drop and not a session death. That is still true for the
    /// ordinary failures — and this test's first half keeps pinning it, because
    /// a catch-all `is_err()` here would kill healthy carriers on the first
    /// ICMP-induced `ConnectionReset`. What changed is that
    /// `AddrNotAvailable` / `NetworkUnreachable` are not statements about the
    /// datagram at all: the bound source address is gone, so every later send
    /// fails too, and waiting out the rx-staleness bound is dead time.
    #[tokio::test]
    async fn direct_carrier_dies_only_on_local_end_gone() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let carrier = Carrier::direct(sock, dst);
        // An ordinary send (or an ordinary failure) leaves it alive.
        let _ = carrier.send(b"x").await;
        assert!(
            !carrier.is_dead(),
            "a dropped datagram must not kill a direct carrier"
        );

        // The latch itself: only the two local-end errno classes set it.
        let Carrier::Direct { dead, .. } = &*carrier else {
            unreachable!("constructed as Direct")
        };
        for kind in [
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::WouldBlock,
        ] {
            assert!(
                !matches!(
                    kind,
                    std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::NetworkUnreachable
                ),
                "{kind:?} must not be treated as a dead local end"
            );
        }
        dead.store(true, Ordering::Relaxed);
        assert!(
            carrier.is_dead(),
            "a latched local-end failure must surface to the health sweep"
        );
    }

    /// Phase A — `authenticate_init` extracts + AUTHENTICATES an inbound
    /// handshake initiation with no per-peer state: it must accept a genuine
    /// init (yielding the initiator's real key), and reject one sealed to a
    /// DIFFERENT responder (a forger can't have produced it) plus any garbage.
    #[tokio::test(flavor = "multi_thread")]
    async fn authenticate_init_accepts_genuine_rejects_misaddressed_and_garbage() {
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let c = WgKeypair::generate();
        let (dev_b, _rx_b) = WgDevice::new(b.secret.clone());
        let (dev_c, _rx_c) = WgDevice::new(c.secret.clone());

        // A genuine init from A, sealed to B's static public key.
        let mut tunn_ab = Tunn::new(a.secret.clone(), b.public, None, None, 1, None);
        let mut buf = vec![0u8; WG_BUF];
        let init = match tunn_ab.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(bytes) => bytes.to_vec(),
            _ => panic!("expected a handshake initiation"),
        };

        // B is the intended responder → authenticates it, recovering A's key.
        assert_eq!(dev_b.authenticate_init(&init), Some(a.public.to_bytes()));
        // C is NOT the intended responder → the init's DHs don't resolve under
        // C's secret, so the timestamp AEAD fails ⇒ rejected.
        assert_eq!(dev_c.authenticate_init(&init), None);
        // Garbage (right-length + short) is rejected, never panics.
        assert_eq!(dev_b.authenticate_init(&[0u8; 148]), None);
        assert_eq!(dev_b.authenticate_init(b"short"), None);
    }

    /// Phase A CORE — a CLIENT dials a HUB's endpoint and the HUB, which never
    /// dials back (`initiate=false`), completes the handshake purely by
    /// ACCEPTING the inbound init its demux forwarded as a [`DirectInbound`]
    /// event (the exit-side accept: the HUB can't know a NAT'd client's source
    /// ahead of time). Proves single-initiator direct works + data flows.
    #[tokio::test(flavor = "multi_thread")]
    async fn public_direct_single_initiator_accept_via_inbound_event() {
        let hub = WgKeypair::generate();
        let client = WgKeypair::generate();
        let sock_hub = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let hub_addr = sock_hub.local_addr().unwrap();
        let client_addr = sock_client.local_addr().unwrap();

        let (mut dev_hub, mut rx_hub) = WgDevice::new(hub.secret.clone());
        let (mut dev_client, _rx_client) = WgDevice::new(client.secret.clone());

        // HUB: start the demux loop eagerly (as the runtime does when the tier
        // is on) and take the inbound-init receiver.
        dev_hub.ensure_direct_demux(sock_hub.clone());
        let mut events = dev_hub.take_direct_events().unwrap();

        // CLIENT dials HUB (initiate=true), keyed by HUB's addr (IP_B = hub).
        dev_client.ensure_direct_demux(sock_client.clone());
        dev_client
            .add_direct_peer(
                sock_client.clone(),
                hub.public.to_bytes(),
                IP_B,
                hub_addr,
                true,
            )
            .await;

        // HUB receives the init as an event from CLIENT's (unregistered) source.
        let inb = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("no inbound-init event")
            .expect("event channel closed");
        assert_eq!(inb.src, client_addr, "event carries the client's source");
        assert_eq!(
            dev_hub.authenticate_init(&inb.packet),
            Some(client.public.to_bytes()),
            "the forwarded init authenticates to the client's key"
        );

        // HUB installs the client direct (initiate=false — it only responds),
        // keyed by the init's source, then feeds the init so the response goes
        // out immediately (IP_A = client).
        dev_hub
            .add_direct_peer(
                inb.sock.clone(),
                client.public.to_bytes(),
                IP_A,
                inb.src,
                false,
            )
            .await;
        dev_hub
            .feed_direct(inb.src, inb.sock.clone(), &inb.packet)
            .await;

        // Both ends complete the handshake single-initiator.
        wait_connected(&dev_client, &hub.public.to_bytes()).await;
        wait_connected(&dev_hub, &client.public.to_bytes()).await;

        // CLIENT → HUB data arrives decrypted.
        let pkt = synthetic_ipv4(IP_A, IP_B, b"hello-public-direct");
        send_until_ok(&dev_client, &hub.public.to_bytes(), &pkt).await;
        let got = tokio::time::timeout(Duration::from_secs(15), rx_hub.recv())
            .await
            .expect("HUB never received the decrypted packet")
            .expect("tun channel closed");
        assert_eq!(got, pkt, "decrypted IP packet must arrive intact");
    }

    /// Phase C — the demux discriminates STUN Binding messages (→ the STUN
    /// sink, for the srflx keepalive) from WireGuard traffic (unknown-source
    /// inits → `direct_events`; everything else dropped), and a WG datagram
    /// whose receiver-index bytes collide with the STUN magic cookie is NOT
    /// mis-forwarded to the sink.
    #[tokio::test(flavor = "multi_thread")]
    async fn demux_routes_stun_to_sink_and_wg_to_events() {
        let hub = WgKeypair::generate();
        let client = WgKeypair::generate();
        let sock_hub = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let hub_addr = sock_hub.local_addr().unwrap();

        let (mut dev_hub, _rx_hub) = WgDevice::new(hub.secret.clone());
        dev_hub.ensure_direct_demux(sock_hub.clone());
        let mut direct_events = dev_hub.take_direct_events().unwrap();
        let mut stun_events = dev_hub.take_stun_events().unwrap();

        // An external socket standing in for the STUN server / a peer.
        let ext = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ext_addr = ext.local_addr().unwrap();

        // (1) A STUN Binding message → the STUN sink, carrying its source.
        let stun_msg = crate::transport::stun::encode_binding_request([7u8; 12]);
        ext.send_to(&stun_msg, hub_addr).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), stun_events.recv())
            .await
            .expect("STUN datagram never reached the sink")
            .expect("stun sink closed");
        assert_eq!(got.src, ext_addr, "sink item carries the STUN source");
        assert_eq!(
            got.packet,
            stun_msg.to_vec(),
            "sink item is the STUN datagram"
        );
        assert!(
            direct_events.try_recv().is_err(),
            "a STUN datagram must NOT reach direct_events"
        );

        // (2) A WG-shaped datagram whose index bytes equal the STUN cookie is
        // kept as WG (dropped here — unknown source, not an init), NOT sent to
        // the sink. Follow it with a sentinel STUN; FIFO per socket guarantees
        // the lookalike was handled first, so receiving the sentinel proves the
        // lookalike went nowhere.
        let mut wg_lookalike = vec![0u8; 48];
        wg_lookalike[0] = 4; // Data type (LE 4-byte type → bytes 1..4 == 0)
        wg_lookalike[4..8].copy_from_slice(&0x2112_A442u32.to_be_bytes()); // STUN cookie
        ext.send_to(&wg_lookalike, hub_addr).await.unwrap();
        let sentinel = crate::transport::stun::encode_binding_request([9u8; 12]);
        ext.send_to(&sentinel, hub_addr).await.unwrap();
        let got2 = tokio::time::timeout(Duration::from_secs(5), stun_events.recv())
            .await
            .expect("sentinel STUN never reached the sink")
            .expect("stun sink closed");
        assert_eq!(
            got2.packet,
            sentinel.to_vec(),
            "sink got the sentinel, not the WG-cookie-lookalike"
        );
        assert!(
            direct_events.try_recv().is_err(),
            "a WG-shaped datagram must NOT reach direct_events from an unknown source"
        );

        // (3) A genuine unknown-source WG handshake init → direct_events, and
        // NOT the STUN sink.
        let (mut dev_client, _rx_client) = WgDevice::new(client.secret.clone());
        let sock_client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        dev_client.ensure_direct_demux(sock_client.clone());
        dev_client
            .add_direct_peer(
                sock_client.clone(),
                hub.public.to_bytes(),
                IP_B,
                hub_addr,
                true,
            )
            .await;
        let inb = tokio::time::timeout(Duration::from_secs(5), direct_events.recv())
            .await
            .expect("WG init never reached direct_events")
            .expect("direct_events closed");
        assert_eq!(
            dev_hub.authenticate_init(&inb.packet),
            Some(client.public.to_bytes()),
            "the forwarded init authenticates to the client's key"
        );
        assert!(
            stun_events.try_recv().is_err(),
            "a WG init must NOT reach the STUN sink"
        );
    }

    /// R2 — retiring a demux slot aborts its recv loop and frees the
    /// local-addr dedupe, so a direct-plane rebuild's re-ensure for the SAME
    /// `ip:port` spawns a FRESH loop instead of being silently absorbed by
    /// the dead slot (the trap that would defeat a same-stable-port
    /// rebuild).
    #[tokio::test(flavor = "multi_thread")]
    async fn retire_direct_socket_frees_the_slot_for_reensure() {
        let kp = WgKeypair::generate();
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local = sock.local_addr().unwrap();
        let (mut dev, _rx) = WgDevice::new(kp.secret.clone());
        dev.ensure_direct_demux(sock.clone());
        let mut stun_events = dev.take_stun_events().unwrap();

        let ext = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ping = crate::transport::stun::encode_binding_request([1u8; 12]);
        ext.send_to(&ping, local).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), stun_events.recv())
            .await
            .expect("the first loop reads")
            .expect("sink open");

        assert!(dev.retire_direct_socket(local), "slot found and retired");
        assert!(
            !dev.retire_direct_socket(local),
            "a second retire finds nothing"
        );

        // The dedupe no longer blocks: a re-ensure spawns a fresh loop that
        // reads the same socket again.
        dev.ensure_direct_demux(sock.clone());
        let ping2 = crate::transport::stun::encode_binding_request([2u8; 12]);
        ext.send_to(&ping2, local).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), stun_events.recv())
            .await
            .expect("the fresh loop reads after retire + re-ensure")
            .expect("sink open");
        assert_eq!(got.packet, ping2.to_vec());
    }

    /// #2220 — the per-device demux loop (the plane off) reads on past the
    /// port-unreachables Windows reports as `WSAECONNRESET` on the NEXT
    /// receive, as the plane's loop does. It used to END on the first,
    /// leaving the socket bound and unread. Linux never reports the ICMP on an
    /// unconnected socket, so this passes there either way.
    #[tokio::test(flavor = "multi_thread")]
    async fn port_unreachables_do_not_end_the_direct_demux() {
        let kp = WgKeypair::generate();
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local = sock.local_addr().unwrap();
        let (mut dev, _rx) = WgDevice::new(kp.secret.clone());
        dev.ensure_direct_demux(sock.clone());
        let mut stun_events = dev.take_stun_events().unwrap();
        for _ in 0..3 {
            let gone = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let closed = gone.local_addr().unwrap();
            drop(gone);
            sock.send_to(b"to nobody", closed).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;

        let ext = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ping = crate::transport::stun::encode_binding_request([3u8; 12]);
        ext.send_to(&ping, local).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), stun_events.recv())
            .await
            .expect("the demux loop must still read after the port-unreachables")
            .expect("sink open");
        assert_eq!(got.packet, ping.to_vec());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn carrier_disco_authenticated_echo_over_relay_keeps_wg_data_working() {
        use crate::transport::relay::UdpRelayConn;
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let sa = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let aa = sa.local_addr().unwrap();
        let ab = sb.local_addr().unwrap();
        let (mut da, _ra) = WgDevice::new(a.secret.clone());
        let (mut db, mut rb) = WgDevice::new(b.secret.clone());
        let mut echoes = da.take_disco_events().unwrap();
        da.add_peer(
            b.public.to_bytes(),
            IP_B,
            Carrier::relay(Arc::new(UdpRelayConn(sa)), ab),
            true,
        );
        db.add_peer(
            a.public.to_bytes(),
            IP_A,
            Carrier::relay(Arc::new(UdpRelayConn(sb)), aa),
            false,
        );
        wait_connected(&da, &b.public.to_bytes()).await;
        let nonce = [17; 8];
        let frame = super::super::disco::build(
            super::super::disco::KIND_PING,
            nonce,
            a.public.as_bytes(),
            None,
            &super::super::disco::shared_secret(&a.secret, &b.public),
        );
        assert_eq!(
            da.sender()
                .send_disco_raw(&b.public.to_bytes(), &frame)
                .await,
            Some(ab)
        );
        let echo = tokio::time::timeout(Duration::from_secs(2), echoes.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echo.sender, b.public.to_bytes());
        assert_eq!(echo.nonce, nonce);
        assert_eq!(
            echo.src, ab,
            "measurement is keyed by this installed end-to-end path"
        );
        let pkt = synthetic_ipv4(IP_A, IP_B, b"WG data survives authenticated carrier echo");
        send_until_ok(&da, &b.public.to_bytes(), &pkt).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), rb.recv())
                .await
                .unwrap()
                .unwrap(),
            pkt
        );
        assert_eq!(da.peer_count(), 1);
        assert_eq!(db.peer_count(), 1);
        da.remove_peer(&b.public.to_bytes()).await;
        db.remove_peer(&a.public.to_bytes()).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn carrier_disco_rejects_valid_frame_from_wrong_peer_without_wg_liveness_credit() {
        use crate::transport::relay::UdpRelayConn;
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let c = WgKeypair::generate();
        let sa = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let aa = sa.local_addr().unwrap();
        let ab = sb.local_addr().unwrap();
        let (mut da, _rx) = WgDevice::new(a.secret.clone());
        let mut echoes = da.take_disco_events().unwrap();
        da.add_peer(
            b.public.to_bytes(),
            IP_B,
            Carrier::relay(Arc::new(UdpRelayConn(sa)), ab),
            false,
        );
        let forged = super::super::disco::build(
            super::super::disco::KIND_PONG,
            [23; 8],
            c.public.as_bytes(),
            Some(ab),
            &super::super::disco::shared_secret(&c.secret, &a.public),
        );
        sb.send_to(&forged, aa).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), echoes.recv())
                .await
                .is_err()
        );
        assert_eq!(
            da.peer_take_rx_any(&b.public.to_bytes()),
            0,
            "disco cannot fake WG health"
        );
        da.remove_peer(&b.public.to_bytes()).await;
    }

    /// Real candidate-carrier fault: drop outgoing handshake initiations,
    /// while still delivering the other peer's initiation and our response.
    /// No Tunn state, nonce, key, liveness stamp, or time is fabricated.
    struct CandidateInitLoss {
        socket: UdpSocket,
        block_initiations: std::sync::atomic::AtomicBool,
        dropped: std::sync::atomic::AtomicUsize,
    }
    #[async_trait::async_trait]
    impl crate::transport::relay::RelayConn for CandidateInitLoss {
        async fn send_to(&self, bytes: &[u8], dst: SocketAddr) -> std::io::Result<usize> {
            if bytes.starts_with(&[1, 0, 0, 0]) && self.block_initiations.load(Ordering::Relaxed) {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return Ok(bytes.len());
            }
            self.socket.send_to(bytes, dst).await
        }
        async fn recv_from(&self, bytes: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            self.socket.recv_from(bytes).await
        }
        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            self.socket.local_addr()
        }
    }
    struct CandidateProofFixture {
        a: WgDevice,
        b: WgDevice,
        a_key: [u8; 32],
        b_key: [u8; 32],
        old_a: Arc<Mutex<Tunn>>,
        old_b: Arc<Mutex<Tunn>>,
        trial: ObjectId,
        fault: Arc<CandidateInitLoss>,
        a_inbox: mpsc::Receiver<Vec<u8>>,
        b_inbox: mpsc::Receiver<Vec<u8>>,
    }
    impl CandidateProofFixture {
        async fn new() -> Self {
            use crate::transport::relay::UdpRelayConn;
            let a = WgKeypair::generate();
            let b = WgKeypair::generate();
            let sa = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let sb = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let (mut da, a_inbox) = WgDevice::new(a.secret.clone());
            let (mut db, b_inbox) = WgDevice::new(b.secret.clone());
            da.ensure_direct_demux(sa.clone());
            db.ensure_direct_demux(sb.clone());
            da.add_direct_peer(
                sa.clone(),
                b.public.to_bytes(),
                IP_B,
                sb.local_addr().unwrap(),
                true,
            )
            .await;
            db.add_direct_peer(
                sb.clone(),
                a.public.to_bytes(),
                IP_A,
                sa.local_addr().unwrap(),
                false,
            )
            .await;
            wait_connected(&da, &b.public.to_bytes()).await;
            let old_a = da.peers[&b.public.to_bytes()].tunn.clone();
            let old_b = db.peers[&a.public.to_bytes()].tunn.clone();
            let ca = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let cb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let aa = ca.local_addr().unwrap();
            let ab = cb.local_addr().unwrap();
            let fault = Arc::new(CandidateInitLoss {
                socket: cb,
                block_initiations: std::sync::atomic::AtomicBool::new(true),
                dropped: std::sync::atomic::AtomicUsize::new(0),
            });
            let trial = ObjectId::new();
            assert!(db.start_path_trial(
                trial,
                a.public.to_bytes(),
                IP_A,
                Carrier::relay(fault.clone(), aa)
            ));
            tokio::time::timeout(Duration::from_secs(1), async {
                while fault.dropped.load(Ordering::Relaxed) == 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the first real candidate initiation must actually be dropped");
            assert!(!db.path_trial_handshake_done(trial));
            assert!(da.start_path_trial(
                trial,
                b.public.to_bytes(),
                IP_B,
                Carrier::relay(Arc::new(UdpRelayConn(ca)), ab)
            ));
            tokio::time::timeout(Duration::from_secs(1), async {
                while !da.path_trial_handshake_done(trial)
                    || !db.path_trials[&trial]
                        .candidate
                        .as_ref()
                        .unwrap()
                        .stats
                        .handshake
                        .load(Ordering::Relaxed)
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("B must establish a REAL responder session from A's delivered initiation");
            assert!(
                !db.path_trial_handshake_done(trial),
                "responder-only session cannot fake our strict initiator proof"
            );
            assert!(Arc::ptr_eq(&old_a, &da.peers[&b.public.to_bytes()].tunn));
            assert!(Arc::ptr_eq(&old_b, &db.peers[&a.public.to_bytes()].tunn));
            Self {
                a: da,
                b: db,
                a_key: a.public.to_bytes(),
                b_key: b.public.to_bytes(),
                old_a,
                old_b,
                trial,
                fault,
                a_inbox,
                b_inbox,
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn path_trial_candidate_proof_recovers_real_responder_after_lost_initial_init() {
        tokio::time::timeout(Duration::from_secs(8), async {
            let mut f = CandidateProofFixture::new().await;
            // Removing a packet fault cannot itself satisfy crypto readiness.
            f.fault.block_initiations.store(false, Ordering::Relaxed);
            tokio::time::timeout(Duration::from_secs(4), async {
                while !f.b.path_trial_handshake_done(f.trial) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("candidate-owned bounded poke must obtain a REAL WG response");
            assert!(Arc::ptr_eq(&f.old_a, &f.a.peers[&f.b_key].tunn));
            assert!(
                Arc::ptr_eq(&f.old_b, &f.b.peers[&f.a_key].tunn),
                "proof must not promote or replace the incumbent"
            );
            assert!(f.a.commit_path_trial(f.trial));
            assert!(f.b.commit_path_trial(f.trial));
            let packet = synthetic_ipv4(
                IP_A,
                IP_B,
                b"real cryptographic candidate proof, not a responder latch substitution",
            );
            send_until_ok(&f.a, &f.b_key, &packet).await;
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), f.b_inbox.recv())
                    .await
                    .unwrap()
                    .unwrap(),
                packet
            );
            let packet = synthetic_ipv4(
                IP_B,
                IP_A,
                b"candidate response proof supports real reverse WG payload",
            );
            send_until_ok(&f.b, &f.a_key, &packet).await;
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), f.a_inbox.recv())
                    .await
                    .unwrap()
                    .unwrap(),
                packet
            );
        })
        .await
        .expect("bounded candidate initiator-proof regression");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn path_trial_candidate_proof_pokes_are_bounded_and_abort_stops_owned_tasks() {
        let mut f = CandidateProofFixture::new().await;
        tokio::time::sleep(Duration::from_millis(6500)).await;
        assert!(
            !f.b.path_trial_handshake_done(f.trial),
            "dropped initiations never become a successful response"
        );
        assert_eq!(
            f.fault.dropped.load(Ordering::Relaxed),
            4,
            "one initial initiation plus at most THREE candidate proof pokes"
        );
        assert!(Arc::ptr_eq(&f.old_b, &f.b.peers[&f.a_key].tunn));
        assert!(
            !f.b.retire_path_trial(f.trial).await,
            "retiring an unpromoted candidate must not remove active direct"
        );
        let before = f.fault.dropped.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(2200)).await;
        assert_eq!(
            f.fault.dropped.load(Ordering::Relaxed),
            before,
            "no candidate task may outlive exact owner retirement"
        );
        assert!(Arc::ptr_eq(&f.old_b, &f.b.peers[&f.a_key].tunn));
        assert!(!f.b.path_trial_handshake_done(f.trial));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn path_trial_shadow_bilateral_commit_keeps_both_old_receivers_until_finalize() {
        use crate::transport::relay::UdpRelayConn;
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let sa = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sb = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (mut da, mut ra) = WgDevice::new(a.secret.clone());
        let (mut db, mut rb) = WgDevice::new(b.secret.clone());
        da.ensure_direct_demux(sa.clone());
        db.ensure_direct_demux(sb.clone());
        da.add_direct_peer(
            sa.clone(),
            b.public.to_bytes(),
            IP_B,
            sb.local_addr().unwrap(),
            true,
        )
        .await;
        db.add_direct_peer(
            sb.clone(),
            a.public.to_bytes(),
            IP_A,
            sa.local_addr().unwrap(),
            false,
        )
        .await;
        wait_connected(&da, &b.public.to_bytes()).await;
        let old_a = da.peers[&b.public.to_bytes()].tunn.clone();
        let old_b = db.peers[&a.public.to_bytes()].tunn.clone();
        let ca = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let aa = ca.local_addr().unwrap();
        let ab = cb.local_addr().unwrap();
        let trial = ObjectId::new();
        assert!(da.start_path_trial(
            trial,
            b.public.to_bytes(),
            IP_B,
            Carrier::relay(Arc::new(UdpRelayConn(ca)), ab)
        ));
        assert!(db.start_path_trial(
            trial,
            a.public.to_bytes(),
            IP_A,
            Carrier::relay(Arc::new(UdpRelayConn(cb)), aa)
        ));
        for _ in 0..200 {
            if da.path_trial_handshake_done(trial) && db.path_trial_handshake_done(trial) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(da.path_trial_handshake_done(trial) && db.path_trial_handshake_done(trial));
        assert!(
            Arc::ptr_eq(&old_a, &da.peers[&b.public.to_bytes()].tunn),
            "shadow never moves sender"
        );
        assert!(Arc::ptr_eq(&old_b, &db.peers[&a.public.to_bytes()].tunn));
        let frame = super::super::disco::build(
            super::super::disco::KIND_PING,
            [31; 8],
            a.public.as_bytes(),
            None,
            &super::super::disco::shared_secret(&a.secret, &b.public),
        );
        assert_eq!(da.send_path_trial_disco(trial, &frame).await, Some(ab));
        let mut candidate_echo = Vec::new();
        for _ in 0..100 {
            candidate_echo = da.drain_path_trial_disco(trial);
            if !candidate_echo.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(candidate_echo.len(), 1);
        assert_eq!(candidate_echo[0].sender, b.public.to_bytes());
        assert!(da.commit_path_trial(trial)); // B is still prepared/direct
        let ab_pkt = synthetic_ipv4(IP_A, IP_B, b"A trial -> B prepared");
        send_until_ok(&da, &b.public.to_bytes(), &ab_pkt).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), rb.recv())
                .await
                .unwrap()
                .unwrap(),
            ab_pkt
        );
        let ba_pkt = synthetic_ipv4(IP_B, IP_A, b"B old direct -> A retained old receiver");
        send_until_ok(&db, &a.public.to_bytes(), &ba_pkt).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), ra.recv())
                .await
                .unwrap()
                .unwrap(),
            ba_pkt
        );
        assert!(db.commit_path_trial(trial));
        assert!(da.finalize_path_trial(trial));
        assert!(db.finalize_path_trial(trial));
        assert!(da.path_trials.contains_key(&trial));
        assert!(da.path_trials[&trial].incumbent.is_some());
        assert!(
            da.peers[&b.public.to_bytes()]
                .carrier
                .relay_transport_info()
                .is_some()
        );
        assert!(da.path_trial_direct_ready(trial));
        let retained_stats = da.path_trials[&trial]
            .incumbent
            .as_ref()
            .unwrap()
            .stats
            .clone();
        retained_stats.handshake.store(false, Ordering::Relaxed);
        assert!(!da.path_trial_direct_ready(trial));
        assert!(!da.commit_path_trial_return(trial));
        retained_stats.handshake.store(true, Ordering::Relaxed);
        let retained_carrier = da.path_trials[&trial]
            .incumbent
            .as_ref()
            .unwrap()
            .carrier
            .clone();
        retained_carrier.mark_dead();
        assert!(!da.path_trial_direct_ready(trial));
        assert!(!da.commit_path_trial_return(trial));
        assert!(
            !da.peers[&b.public.to_bytes()].carrier.is_direct(),
            "refused return preserves the healthy relay sender"
        );
        let relay_a = da.peers[&b.public.to_bytes()].tunn.clone();
        assert!(da.rebuild_path_trial_direct(trial).await);
        assert!(
            retained_carrier.is_dead(),
            "old sticky-dead carrier never revives"
        );
        assert!(
            Arc::ptr_eq(&relay_a, &da.peers[&b.public.to_bytes()].tunn),
            "fresh direct preparation cannot touch active relay sender"
        );
        assert!(
            !std::sync::Weak::ptr_eq(
                &da.path_trials[&trial].incumbent_tunn,
                &Arc::downgrade(&old_a)
            ),
            "fresh independent Tunn, not a dead-flag reset"
        );
        tokio::time::timeout(Duration::from_secs(6), async {
            while !da.path_trial_direct_ready(trial) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            !da.rebuild_path_trial_direct(trial).await,
            "healthy repaired shadow is reused, not endlessly replaced"
        );
        let held = synthetic_ipv4(
            IP_A,
            IP_B,
            b"fresh shadow ready but relay still owns sender",
        );
        send_until_ok(&da, &b.public.to_bytes(), &held).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), rb.recv())
                .await
                .unwrap()
                .unwrap(),
            held
        );
        assert!(da.commit_path_trial_return(trial)); // B remains relay sender
        assert!(da.peers[&b.public.to_bytes()].carrier.is_direct());
        let d_to_r = synthetic_ipv4(IP_A, IP_B, b"return direct -> retained B direct");
        send_until_ok(&da, &b.public.to_bytes(), &d_to_r).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), rb.recv())
                .await
                .unwrap()
                .unwrap(),
            d_to_r
        );
        let r_to_d = synthetic_ipv4(IP_B, IP_A, b"B relay -> retained A relay");
        send_until_ok(&db, &a.public.to_bytes(), &r_to_d).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), ra.recv())
                .await
                .unwrap()
                .unwrap(),
            r_to_d
        );
        // A dedicated ReturnAbort rolls back partial return without destroying
        // either receive path or reusing an old candidate Tunn/index.
        assert!(da.abort_path_trial_return(trial));
        assert!(!da.peers[&b.public.to_bytes()].carrier.is_direct());
        assert!(da.commit_path_trial_return(trial));
        assert!(db.commit_path_trial_return(trial));
        assert!(da.finalize_path_trial_return(trial));
        assert!(db.finalize_path_trial_return(trial));
        assert!(!da.path_trials.contains_key(&trial));
        assert!(!da.commit_path_trial(trial)); // late initial Commit cannot revive
        assert!(!da.abort_path_trial_return(trial)); // late abort cannot revive relay
        let done = synthetic_ipv4(IP_A, IP_B, b"both returned direct payload");
        send_until_ok(&da, &b.public.to_bytes(), &done).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), rb.recv())
                .await
                .unwrap()
                .unwrap(),
            done
        );
        let ca = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let aa = ca.local_addr().unwrap();
        let ab = cb.local_addr().unwrap();
        let late = ObjectId::new();
        assert!(da.start_path_trial(
            late,
            b.public.to_bytes(),
            IP_B,
            Carrier::relay(Arc::new(UdpRelayConn(ca)), ab)
        ));
        assert!(db.start_path_trial(
            late,
            a.public.to_bytes(),
            IP_A,
            Carrier::relay(Arc::new(UdpRelayConn(cb)), aa)
        ));
        for _ in 0..200 {
            if da.path_trial_handshake_done(late) && db.path_trial_handshake_done(late) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(da.commit_path_trial(late));
        assert!(db.commit_path_trial(late));
        // An actual task-owned silent endpoint prevents the repaired Tunn
        // establishing. Probe timeout must leave both working relay senders,
        // not revive the dead retained session or unilaterally return direct.
        let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let old = da.path_trials[&late]
            .incumbent
            .as_ref()
            .unwrap()
            .carrier
            .clone();
        old.set_direct_dst(blackhole.local_addr().unwrap());
        old.mark_dead();
        let active_relay = da.peers[&b.public.to_bytes()].tunn.clone();
        assert!(da.rebuild_path_trial_direct(late).await);
        let fresh = da.path_trials[&late]
            .incumbent
            .as_ref()
            .unwrap()
            .tunn
            .clone();
        assert!(
            tokio::time::timeout(Duration::from_millis(150), async {
                while !da.path_trial_direct_ready(late) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .is_err(),
            "silent endpoint must not produce a fresh handshake"
        );
        assert!(old.is_dead());
        assert!(!da.commit_path_trial_return(late));
        assert!(Arc::ptr_eq(
            &active_relay,
            &da.peers[&b.public.to_bytes()].tunn
        ));
        let held = synthetic_ipv4(IP_A, IP_B, b"fresh direct timeout keeps working relay");
        send_until_ok(&da, &b.public.to_bytes(), &held).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), rb.recv())
                .await
                .unwrap()
                .unwrap(),
            held
        );
        da.remove_peer(&b.public.to_bytes()).await;
        db.remove_peer(&a.public.to_bytes()).await;
        assert!(
            !da.rebuild_path_trial_direct(late).await,
            "late repair cannot resurrect removed/rekeyed trial identity"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while Arc::strong_count(&fresh) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("removed shadow tasks and demux entries must release its Tunn");
        assert!(
            da.direct
                .as_ref()
                .unwrap()
                .index_routes
                .lock()
                .unwrap()
                .is_empty()
        );
        assert!(
            da.direct.as_ref().unwrap().routes.lock().await.is_empty(),
            "removed committed trial cannot leave authorized direct Tunn behind"
        );
        assert!(db.direct.as_ref().unwrap().routes.lock().await.is_empty());
        assert!(!da.commit_path_trial(late));
        assert!(!da.commit_path_trial_return(late));
    }

    /// Process CPU seconds (user + system) from `/proc/self/stat`; benches only.
    fn process_cpu_secs() -> f64 {
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
        let tail = stat.rsplit_once(')').map(|(_, t)| t).unwrap_or("");
        let f: Vec<&str> = tail.split_whitespace().collect();
        let ticks = |i: usize| f.get(i).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
        (ticks(11) + ticks(12)) / 100.0
    }

    /// Data-plane throughput baseline (not a correctness test; `--ignored`).
    /// Two handshaked devices over real UDP: one task pushes packets through
    /// `send_to_peer` as fast as it returns; the receiver counts what the TUN
    /// channel delivers. Env: MH_BENCH_PACKETS (200000), MH_BENCH_SIZE (1280),
    /// MH_BENCH_A / MH_BENCH_B bind addresses (127.0.0.1).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn bench_direct_udp_throughput() {
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        let n: usize = env("MH_BENCH_PACKETS", "200000").parse().unwrap();
        let size: usize = env("MH_BENCH_SIZE", "1280").parse().unwrap();
        let (bind_a, bind_b) = (env("MH_BENCH_A", "127.0.0.1"), env("MH_BENCH_B", "127.0.0.1"));
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let sock_a = Arc::new(UdpSocket::bind(format!("{bind_a}:0")).await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind(format!("{bind_b}:0")).await.unwrap());
        for s in [&sock_a, &sock_b] {
            super::super::sockbuf::tune_carrier(s, "bench");
        }
        let (addr_a, addr_b) = (sock_a.local_addr().unwrap(), sock_b.local_addr().unwrap());
        let (mut dev_a, _rx_a) = WgDevice::new(a.secret.clone());
        let (mut dev_b, mut rx_b) = WgDevice::new(b.secret.clone());
        dev_a.add_peer(b.public.to_bytes(), IP_B, Carrier::direct(sock_a.clone(), addr_b), true);
        dev_b.add_peer(a.public.to_bytes(), IP_A, Carrier::direct(sock_b.clone(), addr_a), false);
        let pk_b = b.public.to_bytes();
        wait_connected(&dev_a, &pk_b).await;
        let pkt = synthetic_ipv4(IP_A, IP_B, &vec![0x5a; size.saturating_sub(20)]);
        send_until_ok(&dev_a, &pk_b, &pkt).await;
        while tokio::time::timeout(Duration::from_millis(200), rx_b.recv()).await.is_ok() {}

        let counter = tokio::spawn(async move {
            let (mut got, mut bytes, mut last) = (0usize, 0usize, Instant::now());
            while let Ok(Some(p)) = tokio::time::timeout(Duration::from_secs(2), rx_b.recv()).await {
                got += 1;
                bytes += p.len();
                last = Instant::now();
            }
            (got, bytes, last)
        });
        let (cpu0, t0) = (process_cpu_secs(), Instant::now());
        let mut sent_ok = 0usize;
        for _ in 0..n {
            if dev_a.send_to_peer(&pk_b, &pkt).await {
                sent_ok += 1;
            }
        }
        let send_secs = t0.elapsed().as_secs_f64();
        let (got, bytes, last) = counter.await.unwrap();
        let secs = last.duration_since(t0).as_secs_f64().max(1e-9);
        let cpu = process_cpu_secs() - cpu0;
        println!(
            "BENCH direct-udp size={size} sent={n} encap_ok={sent_ok} delivered={got} loss={:.2}% \
             send_pps={:.0} delivered_pps={:.0} delivered_mbps={:.1} wall={secs:.2}s cpu={cpu:.2}s cpu_per_gbit={:.2}s",
            100.0 * (n - got.min(n)) as f64 / n as f64,
            n as f64 / send_secs,
            got as f64 / secs,
            bytes as f64 * 8.0 / secs / 1e6,
            cpu / (bytes as f64 * 8.0 / 1e9).max(1e-9),
        );
        drop((dev_a, dev_b));
    }
}
