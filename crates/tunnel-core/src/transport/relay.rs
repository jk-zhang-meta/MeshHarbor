// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Phase 3 core: run a quinn QUIC endpoint over an **arbitrary relayed
//! datagram connection** instead of a real UDP socket.
//!
//! quinn lets an endpoint be backed by any [`quinn::AsyncUdpSocket`].
//! This module provides [`RelayUdpSocket`], an `AsyncUdpSocket` that
//! bridges quinn's poll-based send/recv onto an async datagram channel
//! described by the [`RelayConn`] trait (`send_to` / `recv_from` /
//! `local_addr` — the shape of a TURN-relayed `util::Conn`). That lets
//! QUIC traffic ride a **TURN allocation** (peer → coturn → peer) for
//! symmetric-NAT / UDP-restricted corp nets where direct hole-punch
//! fails — QUIC's TLS stays end-to-end; coturn only ever sees ciphertext.
//!
//! Phase 3b wires `RelayConn` to the `turn` crate's relayed
//! `util::Conn` (Tier 2 = UDP relay; Tier 3 = TURNS/TCP via the vendored
//! `webrtc-ice` tcp-turn conn). This module is transport-agnostic + has
//! NO TURN/webrtc-util dependency, so it's unit-testable over a plain
//! loopback UDP pair (see tests).
//!
//! **Bridging shape.** `try_send` (sync, must not block) pushes
//! `(dest, bytes)` onto an unbounded channel; a drain task awaits the
//! `RelayConn::send_to`. A fill task loops `RelayConn::recv_from` and
//! pushes `(bytes, src)` onto another channel that `poll_recv` drains.
//! `max_{transmit,receive}_segments = 1` (no GSO/GRO over a relay).

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::task::{Context, Poll};

use async_trait::async_trait;
use quinn::AsyncUdpSocket;
use quinn::udp::{RecvMeta, Transmit};
use tokio::sync::mpsc;
// Phase 3b: the `turn` client + the `webrtc-util` `Conn` trait its
// allocation yields. Aliased `UtilConn` so it never collides with this
// module's own [`RelayConn`] trait (the names rhyme; the types don't).
// `webrtc-util`'s lib name is `webrtc_util` (the `turn` crate imports it
// renamed to `util`; we use the real name here).
use turn::client::{Client, ClientConfig};
use webrtc_util::conn::Conn as UtilConn;
// Tier 3 (TURNS/TCP): the field-proven `util::Conn` adapter over
// TLS-over-TCP to coturn. P5 — lives in the workspace `tcp-turn-conn`
// crate (extracted from the vendored `webrtc-ice`; tunnel-core no longer
// depends on the fork). Its `util` is the SAME `webrtc-util 0.10` `turn`
// 0.9 uses — so a `TcpTurnConn` is accepted as `ClientConfig.conn` with
// no type bridging.
use tcp_turn_conn::TcpTurnConn;

/// A relayed datagram connection — the subset of a TURN-relayed
/// `util::Conn` that [`RelayUdpSocket`] needs. Phase 3b implements this
/// for the `turn` crate's allocated `Arc<dyn util::Conn>`; the tests
/// implement it over a tokio `UdpSocket`.
#[async_trait]
pub trait RelayConn: Send + Sync + 'static {
    /// Send one datagram to `dst` through the relay.
    async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> io::Result<usize>;
    /// Receive one datagram, returning its length + the peer source.
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    /// The relay-side local address (the allocated relay address for a
    /// TURN conn) — what quinn reports as its `local_addr` and what the
    /// peer dials.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// How this relay leg is reached — operator-facing.
    ///
    /// `meshharbor peers` printed a bare `relay` for every relayed carrier, so a
    /// 52 ms coturn/UDP hop and a 175 ms DERP/TCP hop were indistinguishable.
    /// The relay *kind* is an overlay-layer decision and already exists as
    /// [`crate::overlay::relay_link::RelayKind`]; only the transport is a
    /// transport-layer fact, so only it lives here. Defaulted so test doubles
    /// and future impls need not care.
    fn relay_transport(&self) -> RelayTransport {
        RelayTransport::Udp
    }
    /// The relay server / PoP this leg goes through, when known — the thing
    /// you would check `kubectl -n coturn get pods` for.
    fn relay_server(&self) -> Option<String> {
        None
    }
}

/// How a relay leg is reached. Load-bearing for latency expectations and for
/// corporate paths, where only 443 survives. Orthogonal to
/// [`crate::overlay::relay_link::RelayKind`]: DERP is always TCP/WS, a coturn
/// allocation can be either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayTransport {
    Udp,
    Tcp,
}

impl RelayTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            RelayTransport::Udp => "udp",
            RelayTransport::Tcp => "tcp",
        }
    }
}

/// Max datagram we'll relay. QUIC keeps datagrams ≤ the path MTU
/// (~1200–1452); 2 KiB is comfortable headroom and bounds the recv buf.
const MAX_DATAGRAM: usize = 2048;

/// W6 — rendezvous instrumentation: what actually ARRIVED on this relay
/// socket. Read at QUIC accept/connect failure time to discriminate "the
/// peer's packets never reached this allocation" (a rendezvous miss, or a
/// coturn permission-IP mismatch silently dropping them) from "packets
/// flowed but the handshake itself failed". A `stray` is the 1-byte `\x00`
/// permission bootstrap both ends fire — strays WITHOUT quic-sized frames
/// mean the relay path delivers and the QUIC end simply never dialed.
#[derive(Debug, Default)]
pub struct RelayRxStats {
    /// Datagrams big enough to be QUIC frames (≥ 32 B).
    pub quic: std::sync::atomic::AtomicU64,
    /// Tiny datagrams — the `\x00` permission bootstraps and other noise.
    pub stray: std::sync::atomic::AtomicU64,
    /// The most recent datagram's relayed source.
    pub last_src: Mutex<Option<SocketAddr>>,
}

impl RelayRxStats {
    /// Render for error contexts / log lines:
    /// `rx_quic=3 rx_stray=1 last_src=Some(1.2.3.4:56789)`.
    pub fn describe(&self) -> String {
        use std::sync::atomic::Ordering;
        let last = *self.last_src.lock().unwrap_or_else(|e| e.into_inner());
        format!(
            "rx_quic={} rx_stray={} last_src={:?}",
            self.quic.load(Ordering::Relaxed),
            self.stray.load(Ordering::Relaxed),
            last
        )
    }
}

/// quinn `AsyncUdpSocket` backed by a [`RelayConn`]. See module docs.
pub struct RelayUdpSocket {
    local_addr: SocketAddr,
    /// `try_send` pushes here; the drain task awaits `send_to`.
    send_tx: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    /// `poll_recv` drains here; the fill task feeds it from `recv_from`.
    recv_rx: Mutex<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,
    /// W6 — inbound counters, shared with the fill task.
    rx_stats: Arc<RelayRxStats>,
    send_task: tokio::task::JoinHandle<()>,
    recv_task: tokio::task::JoinHandle<()>,
}

impl fmt::Debug for RelayUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayUdpSocket")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl RelayUdpSocket {
    /// Wrap `conn` as a quinn-compatible socket. Spawns the send-drain
    /// + recv-fill tasks (aborted on drop).
    pub fn new(conn: Arc<dyn RelayConn>) -> io::Result<Self> {
        let local_addr = conn.local_addr()?;
        let (send_tx, mut send_rx) = mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();
        let (recv_tx, recv_rx) = mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();

        let send_conn = Arc::clone(&conn);
        let send_task = tokio::spawn(async move {
            while let Some((dst, data)) = send_rx.recv().await {
                if let Err(e) = send_conn.send_to(&data, dst).await {
                    tracing::debug!(%dst, %e, "relay send_to failed; dropping datagram");
                }
            }
        });

        let rx_stats = Arc::new(RelayRxStats::default());
        let fill_stats = Arc::clone(&rx_stats);
        let recv_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                match conn.recv_from(&mut buf).await {
                    Ok((n, src)) => {
                        use std::sync::atomic::Ordering;
                        if n >= 32 {
                            fill_stats.quic.fetch_add(1, Ordering::Relaxed);
                        } else {
                            fill_stats.stray.fetch_add(1, Ordering::Relaxed);
                        }
                        *fill_stats
                            .last_src
                            .lock()
                            .unwrap_or_else(|e| e.into_inner()) = Some(src);
                        // Channel closed = the socket was dropped; stop.
                        if recv_tx.send((buf[..n].to_vec(), src)).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(%e, "relay recv_from ended; recv task exiting");
                        break;
                    }
                }
            }
        });

        Ok(Self {
            local_addr,
            send_tx,
            recv_rx: Mutex::new(recv_rx),
            rx_stats,
            send_task,
            recv_task,
        })
    }

    /// W6 — the inbound counters (shared handle; live-updated by the fill
    /// task for as long as this socket exists).
    pub fn rx_stats(&self) -> Arc<RelayRxStats> {
        Arc::clone(&self.rx_stats)
    }
}

impl Drop for RelayUdpSocket {
    fn drop(&mut self) {
        self.send_task.abort();
        self.recv_task.abort();
    }
}

/// A [`quinn::UdpPoller`] that is always writable — the send path is an
/// unbounded channel, so `try_send` never returns `WouldBlock`.
#[derive(Debug)]
struct AlwaysWritable;

impl quinn::UdpPoller for AlwaysWritable {
    fn poll_writable(self: std::pin::Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for RelayUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // No GSO over a relay (max_transmit_segments == 1), so `contents`
        // is exactly one datagram. Hand it to the drain task.
        self.send_tx
            .send((transmit.destination, transmit.contents.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "relay send task gone"))
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut rx = self
            .recv_rx
            .lock()
            .map_err(|_| io::Error::other("relay recv mutex poisoned"))?;
        match rx.poll_recv(cx) {
            Poll::Ready(Some((data, src))) => {
                let n = data.len().min(bufs[0].len());
                bufs[0][..n].copy_from_slice(&data[..n]);
                meta[0] = RecvMeta {
                    addr: src,
                    len: n,
                    stride: n,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            // Sender dropped (recv task ended) — surface as a read error
            // so quinn tears the endpoint down rather than spinning.
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "relay closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

// ───────────────────────── Phase 3b: TURN-backed RelayConn ─────────────
//
// Bridge a real TURN allocation — the `turn` crate's relayed
// `util::Conn` — onto the [`RelayConn`] trait above, so that a
// [`RelayUdpSocket`] (and thus a quinn endpoint) can ride a coturn
// allocation. This is the concrete Tier-2 (UDP relay) / Tier-3
// (TURNS-over-TCP, same client, TCP underlay) datagram path.
//
// The wiring is intentionally thin: `send_to` / `recv_from` forward to
// the relayed conn (mapping `util::Error` → `io::Error`), and
// `local_addr` returns the **relayed transport address** coturn handed
// out — that's what quinn reports as its local address and what the
// remote peer dials (delivered to the peer over signaling in Phase 3c).

/// A [`RelayConn`] backed by a live TURN allocation. Owns the
/// [`turn::client::Client`] so the allocation + the background
/// `listen()` loop that demuxes inbound TURN messages onto the relay
/// stay alive for the relay's lifetime — dropping the client tears the
/// allocation down.
pub struct TurnRelayConn {
    /// How this allocation was reached (udp `turn:` vs tcp/tls `turns:`) and
    /// which PoP served it — surfaced in `meshharbor peers` so a dead relay is
    /// distinguishable from a healthy one.
    transport: RelayTransport,
    server: String,
    /// Kept alive on purpose: the client's `listen()` task is what feeds
    /// `relay`'s `recv_from`.
    ///
    /// ⚠️ **Dropping this closes NOTHING** — the comment here used to claim it
    /// closed the allocation, and that was false in the way that leaks: `turn`
    /// has no `Drop` impl anywhere, and `listen()` spawned a task that owns a
    /// clone of the underlay socket `Arc` and exits only when `close_notify` is
    /// cancelled, which only [`Client::close`] does. So the socket outlives the
    /// struct, forever. The [`Drop`] below is what actually frees it, and every
    /// early return after `listen()` must close too (FR-48 / #1086).
    ///
    /// Same ownership trap as `TunnelPeer` (2026-08-22): the sockets belong to
    /// tasks the client spawned, not to the value you are holding.
    client: Arc<Client>,
    relay: Arc<dyn UtilConn + Send + Sync>,
    /// Cached relayed address (fixed for the allocation's life) so the
    /// sync [`RelayConn::local_addr`] needn't re-query + re-map errors.
    relayed_addr: SocketAddr,
}

impl fmt::Debug for TurnRelayConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TurnRelayConn")
            .field("relayed_addr", &self.relayed_addr)
            .finish_non_exhaustive()
    }
}

/// FR-48 — closes a TURN client on **every** way out of an allocation attempt,
/// including the one that matters most: **cancellation**.
///
/// Every caller wraps `allocate_turn_relay_*` in `tokio::time::timeout`
/// (`UDP_ALLOC_TIMEOUT` / `TLS_ALLOC_TIMEOUT`), so the common failure is not an
/// `Err` that a `?` can catch — it is the whole future being **dropped**
/// mid-`allocate()`. Closing only on the error paths would leave exactly that
/// case leaking, which on a node that cannot reach coturn is *most* attempts.
/// A guard held across the awaits turns cancellation into a close, because drop
/// runs whether the future completed or was thrown away.
///
/// `disarm()` on success hands the client to [`TurnRelayConn`], whose own `Drop`
/// takes over.
struct ClientCloseGuard(Option<Arc<Client>>);

impl ClientCloseGuard {
    fn disarm(mut self) -> Arc<Client> {
        self.0.take().expect("guard armed exactly once")
    }
}

impl Drop for ClientCloseGuard {
    fn drop(&mut self) {
        if let Some(client) = self.0.take()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            handle.spawn(async move {
                let _ = client.close().await;
            });
        }
    }
}

/// FR-48 — the only thing that actually frees the underlay socket.
///
/// `turn`'s `Client` has no `Drop`, and the task `listen()` spawned owns a clone
/// of the underlay `Arc`, so letting this struct fall out of scope leaves the
/// socket bound for the life of the process. `close()` is async and `drop` is
/// not, so the close is spawned — mirroring `TunnelPeer`'s net, for the same
/// reason and after the same class of field leak.
///
/// ⚠️ Off a runtime (`try_current` fails) there is nothing to spawn onto and the
/// socket is released by process exit instead; that is the teardown path, not a
/// live-fleet one.
impl Drop for TurnRelayConn {
    fn drop(&mut self) {
        let client = Arc::clone(&self.client);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = client.close().await;
            });
        }
    }
}

#[async_trait]
impl RelayConn for TurnRelayConn {
    fn relay_transport(&self) -> RelayTransport {
        self.transport
    }
    fn relay_server(&self) -> Option<String> {
        Some(self.server.clone())
    }

    async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> io::Result<usize> {
        self.relay.send_to(buf, dst).await.map_err(util_to_io)
    }
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.relay.recv_from(buf).await.map_err(util_to_io)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.relayed_addr)
    }
}

/// Map a `webrtc-util` conn error to `io::Error` — quinn's socket layer
/// speaks `io::Error`. The text is preserved; the variant collapses to
/// `Other` because the relay never returns `WouldBlock` (`recv_from`
/// blocks until a datagram or a hard error), which is the only error
/// kind quinn's `AsyncUdpSocket` path treats specially.
fn util_to_io(e: webrtc_util::Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// Allocate a TURN relay on `turn_server` with long-term credentials and
/// return a [`TurnRelayConn`] ready to wrap in a [`RelayUdpSocket`].
///
/// The local UDP socket that talks to the TURN server (the underlay) is
/// bound to an ephemeral port and is **not** the one quinn rides — quinn
/// rides the *relayed* conn, whose address is
/// [`RelayConn::local_addr`]. `username`/`password` are the short-lived
/// HMAC creds coturn issues (server-side `turn_creds::ice_servers_for`);
/// `realm` must match coturn's configured realm.
///
/// Validated against an in-process `turn::server` on loopback in the
/// tests (the full quinn-over-two-allocations path); exercised against
/// the live coturn cluster in Phase 3d.
pub async fn allocate_turn_relay(
    turn_server: SocketAddr,
    username: String,
    password: String,
    realm: String,
) -> anyhow::Result<TurnRelayConn> {
    allocate_turn_relay_from(turn_server, username, password, realm, None).await
}

/// [`allocate_turn_relay`] with an explicit underlay egress: `Some((ip,
/// ifindex))` binds the TURN client socket to that source IP (and pins
/// `IP_UNICAST_IF` to the interface when the index is known) instead of
/// `UNSPECIFIED`. This is the corp-VPN rescue: on a host whose default
/// route was captured by a full-tunnel VPN, an unbound underlay
/// source-selects the VPN adapter and the allocate dies in the tunnel —
/// while the overlay's direct socks, bound to the physical NIC, reach
/// the SAME coturn host fine. Field 2026-08-15 winhost-b: srflx `cone via
/// 5.9.157.221:3478` from the bound direct sock, warm TURN/UDP allocate
/// to 5.9.157.221 "all attempted candidates failed" from the unbound
/// one — same machine, same minute.
pub async fn allocate_turn_relay_from(
    turn_server: SocketAddr,
    username: String,
    password: String,
    realm: String,
    egress: Option<(Ipv4Addr, Option<u32>)>,
) -> anyhow::Result<TurnRelayConn> {
    use anyhow::Context as _;

    // The underlay socket the TURN *client* uses to reach coturn. quinn
    // never sees this — it sends/receives through the relayed conn.
    let bind_ip = egress.map(|(ip, _)| ip).unwrap_or(Ipv4Addr::UNSPECIFIED);
    let underlay_sock = tokio::net::UdpSocket::bind((bind_ip, 0))
        .await
        .with_context(|| format!("bind TURN client underlay socket to {bind_ip}"))?;
    // Source-IP binding alone is the rc.143 half; when the caller knows the
    // interface, add the rc.144 `IP_UNICAST_IF` pin (Windows; no-op elsewhere)
    // — same two-part recipe the direct socks use to escape a captured route.
    #[cfg(feature = "overlay-l3")]
    if let Some((_, Some(ifindex))) = egress {
        crate::overlay::direct::force_egress_interface(&underlay_sock, ifindex);
    }
    // VPN-bypass: pin the coturn underlay's egress to the physical uplink so
    // TURN traffic leaves the real NIC instead of a full-tunnel corp VPN's
    // captured default — pinned HERE, the only moment before the socket is
    // moved into (and hidden by) the `turn` client. `overlay-l3`-gated so the
    // non-overlay tunnel-core build (which lacks `crate::overlay`) still
    // compiles; `force_egress_interface` is itself a no-op off Windows / the
    // gate is off unless `OVERLAY_VPN_BYPASS` + an uplink ifindex are set.
    #[cfg(feature = "overlay-l3")]
    if egress.is_none()
        && let Some(ix) = crate::overlay::direct::vpn_bypass_ifindex()
    {
        crate::overlay::direct::force_egress_interface(&underlay_sock, ix);
        tracing::info!(ifindex = ix, %turn_server, "overlay: VPN-bypass — coturn underlay egress pinned to the physical uplink");
    }
    let underlay = Arc::new(underlay_sock);

    let client = Client::new(ClientConfig {
        stun_serv_addr: String::new(),
        turn_serv_addr: turn_server.to_string(),
        username,
        password,
        realm,
        software: String::new(),
        rto_in_ms: 0,
        conn: underlay,
        vnet: None,
    })
    .await
    .context("TURN client::new")?;

    // Spawns the background read loop that demuxes inbound TURN messages
    // onto the allocation — must run before `allocate()`.
    let client = Arc::new(client);
    // FR-48 — armed BEFORE `listen()` spawns the read loop that owns a clone of
    // `underlay`. From here every exit closes: `?`, a panic, and above all the
    // caller's `timeout` dropping this future mid-allocate. Field-traced on
    // 0.4.71 — every leaked socket on a quiet overlay node came from here.
    let guard = ClientCloseGuard(Some(Arc::clone(&client)));

    client.listen().await.context("TURN client listen")?;
    let relay = client.allocate().await.context("TURN allocate")?;
    let relayed_addr = relay
        .local_addr()
        .map_err(util_to_io)
        .context("TURN relayed local_addr")?;
    tracing::info!(%turn_server, %relayed_addr, "TURN allocation established");

    Ok(TurnRelayConn {
        transport: RelayTransport::Udp,
        server: turn_server.to_string(),
        client: guard.disarm(),
        relay: Arc::new(relay),
        relayed_addr,
    })
}

/// A [`RelayConn`] over a plain tokio `UdpSocket` — the datagrams are NOT
/// actually relayed (`send_to`/`recv_from` hit the wire directly), i.e.
/// the "relay" is just a socket. Two uses: (1) a directly-reachable /
/// same-host path can still drive a [`QuicPeer`](crate::transport::quic::QuicPeer)
/// through the same [`RelayUdpSocket`] abstraction the TURN path uses,
/// and (2) tests exercise the bridge + the agent/client relay
/// orchestration (Phase 3d) without standing up coturn.
pub struct UdpRelayConn(pub tokio::net::UdpSocket);

#[async_trait]
impl RelayConn for UdpRelayConn {
    async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> io::Result<usize> {
        self.0.send_to(buf, dst).await
    }
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

/// ALL plain-UDP TURN servers (`turn:HOST:PORT?transport=udp`, or
/// `turn:HOST:PORT` with no transport — UDP default) from an ICE-server URL
/// list, in list order, as `HOST:PORT` (de-duped). `stun:` / `turns:` (TLS)
/// / `?transport=tcp` are skipped: this feeds the webrtc-rs `turn` client's
/// UDP underlay (Tier 2); Tier 3 (TURNS/TCP) rides the vendored
/// `tcp_turn_conn` instead. Returns ALL so the allocator can try each —
/// e.g. `:3478` then `:443` (some corp nets drop UDP/3478 but pass UDP/443,
/// which "looks like QUIC").
pub fn turn_udp_servers(urls: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for url in urls {
        // Only `turn:` (plain). `turns:` (trailing s) is TLS and
        // `strip_prefix("turn:")` correctly rejects it.
        let Some(rest) = url.strip_prefix("turn:") else {
            continue;
        };
        let (hostport, query) = match rest.split_once('?') {
            Some((hp, q)) => (hp, Some(q)),
            None => (rest, None),
        };
        let is_udp = match query {
            None => true, // no transport param ⇒ UDP per RFC 7065 default
            Some(q) => q
                .split('&')
                .any(|kv| kv.eq_ignore_ascii_case("transport=udp")),
        };
        if is_udp && !hostport.is_empty() && !out.iter().any(|h| h == hostport) {
            out.push(hostport.to_string());
        }
    }
    out
}

/// First plain-UDP TURN server, or `None`. A non-empty result also doubles
/// as "this ICE-server entry carries a usable TURN url" (used to pick the
/// TURN server out of an ICE list that leads with credential-less STUN).
pub fn turn_udp_server(urls: &[String]) -> Option<String> {
    turn_udp_servers(urls).into_iter().next()
}

/// ALL `turns:HOST:PORT?transport=tcp` (TLS-over-TCP) TURN servers from an
/// ICE-server URL list, as `(host, port)` — host kept UNRESOLVED for TLS
/// SNI + cert verification ([`TcpTurnConn`] connects + handshakes to it).
/// **Sorted with `:443` first.** coturn exposes TLS on both `:5349` (the
/// default `tls-listening-port`) and `:443` (`alt-tls-listening-port`);
/// corporate firewalls that block ALL outbound UDP *and* odd TCP ports
/// (like 5349) typically still allow TCP/443 ("HTTPS"), so `:443` is the
/// path most likely to traverse — try it before `:5349`. `turn:` (plain) +
/// TURNS-over-UDP (DTLS) are skipped (the adapter rides TCP only).
/// De-duped.
pub fn turn_tls_servers(urls: &[String]) -> Vec<(String, u16, Option<IpAddr>)> {
    let mut out: Vec<(String, u16, Option<IpAddr>)> = Vec::new();
    for url in urls {
        let Some(rest) = url.strip_prefix("turns:") else {
            continue; // skip stun: / plain turn:
        };
        let (hostport, query) = match rest.split_once('?') {
            Some((hp, q)) => (hp, Some(q)),
            None => (rest, None),
        };
        let is_tcp = matches!(
            query,
            Some(q) if q.split('&').any(|kv| kv.eq_ignore_ascii_case("transport=tcp"))
        );
        if !is_tcp {
            continue; // no transport=tcp ⇒ DTLS/UDP, which the adapter can't ride
        }
        // rc.140: an optional `&pin=<ip>` names the coturn worker to DIAL while
        // the URL host stays the hostname for TLS SNI + cert verification — so
        // the deterministic same-worker hairpin survives TURNS on UDP-blocked
        // corp VPNs. Dialing the IP AS the host would verify coturn's DNS-only
        // cert against an IP literal → NotValidForName → handshake failure.
        let pin = query.and_then(|q| {
            q.split('&')
                .find_map(|kv| kv.strip_prefix("pin="))
                .and_then(|v| v.parse::<IpAddr>().ok())
        });
        // rsplit so a bare hostname:port splits correctly (coturn URLs use a
        // hostname, never a bracketed IPv6 literal, so this is safe).
        if let Some((host, port_str)) = hostport.rsplit_once(':')
            && let Ok(port) = port_str.parse::<u16>()
            && !host.is_empty()
            && !out.iter().any(|(h, p, _)| h == host && *p == port)
        {
            out.push((host.to_string(), port, pin));
        }
    }
    // :443 (alt-tls, corp-friendly) first; stable otherwise (keeps list order).
    out.sort_by_key(|(_, p, _)| u16::from(*p != 443));
    out
}

/// First TLS-over-TCP TURN server (`:443`-preferred). Back-compat wrapper
/// over [`turn_tls_servers`].
pub fn turn_tls_server(urls: &[String]) -> Option<(String, u16, Option<IpAddr>)> {
    turn_tls_servers(urls).into_iter().next()
}

/// Initial realm handed to the `turn` client. coturn in `use-auth-secret`
/// (REST) mode returns its own realm in the 401 challenge and the
/// webrtc-rs client OVERWRITES this with the challenge realm before
/// computing MESSAGE-INTEGRITY (`turn-0.9.0` `client/mod.rs:542`), so the
/// value only has to be non-empty; the live realm wins regardless. We use
/// the production realm for tidiness.
const DEFAULT_TURN_REALM: &str = "roomler.ai";

/// Cap on the UDP TURN-allocate attempt before falling back to TURNS/TCP.
/// On a UDP-OK net the allocate completes in ~1 RTT; on a net that blocks
/// outbound UDP to coturn the `turn` client would otherwise retransmit for
/// ~tens of seconds before erroring, so we bound it and switch to Tier 3.
const UDP_ALLOC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Cap on the TURNS/TCP TCP-connect to coturn. A firewalled port (e.g.
/// `:5349` on a corp net) otherwise hangs in `connect()` for the OS SYN
/// timeout (~20 s+), which blows the controller's `quic.ready` window
/// before we can try the next candidate (`:443`). Fail fast + move on.
const TLS_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(6);

/// Cap on ONE DNS resolution during the ladder walk. `lookup_host` used to
/// run UNBOUNDED before each candidate's own timeout even started — and a
/// resolver gone stale across a VPN transition blocks, not NXDOMAINs
/// (field 2026-08-21 on the corp laptop: a ~40 s theoretical walk measured
/// at ~280 s, mostly here). Combined with the per-walk cache below, a walk
/// now spends at most one bounded lookup per unique host.
const DNS_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Cap on ONE WHOLE Tier-3 allocate (TCP connect + TLS handshake + TURN
/// listen/allocate). [`TLS_CONNECT_TIMEOUT`] bounds only the connect — a
/// middlebox that completes the SYN and then stalls the TLS handshake used
/// to hang Tier 3 with NO cap at all, past the controller's 30 s
/// `quic.ready` window with no way for this side to give up and move on.
const TLS_ALLOC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Split a `host:port` candidate (v6 hosts may be bracketed). `None` on a
/// malformed pair — the caller logs and skips the candidate.
fn split_host_port(server: &str) -> Option<(&str, u16)> {
    let (h, p) = server.rsplit_once(':')?;
    let port: u16 = p.parse().ok()?;
    let host = h
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(h);
    Some((host, port))
}

/// Resolve one UDP candidate, IP literals short-circuiting and hostname
/// lookups bounded by [`DNS_RESOLVE_TIMEOUT`] + cached per ladder walk in
/// `dns` (candidates mostly share hosts: worker + generic × two ports). A
/// cached `None` is remembered too — a dead resolver costs ONE bounded
/// wait per unique host, not one per candidate.
async fn resolve_udp_candidate(
    dns: &mut std::collections::HashMap<String, Option<IpAddr>>,
    server: &str,
) -> Option<SocketAddr> {
    let (host, port) = split_host_port(server)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    if let Some(cached) = dns.get(host) {
        return cached.map(|ip| SocketAddr::new(ip, port));
    }
    let looked = match tokio::time::timeout(
        DNS_RESOLVE_TIMEOUT,
        tokio::net::lookup_host((host, port)),
    )
    .await
    {
        Ok(Ok(mut addrs)) => addrs.next().map(|sa| sa.ip()),
        Ok(Err(_)) | Err(_) => None,
    };
    dns.insert(host.to_string(), looked);
    looked.map(|ip| SocketAddr::new(ip, port))
}

/// Allocate a TURN relay from coturn ICE-server credentials, walking the
/// connectivity tiers and trying EVERY candidate in each until one wins:
/// * **Tier 2** — UDP relay (`turn:…?transport=udp`), each bounded by
///   [`UDP_ALLOC_TIMEOUT`] (`:3478` then `:443`).
/// * **Tier 3** — TURNS/TCP relay (`turns:…?transport=tcp`) via the
///   vendored [`TcpTurnConn`], `:443` first then `:5349` (corp nets block
///   UDP + odd TCP ports but allow TCP/443). For UDP-blocked nets.
///
/// `username` + `credential` are the short-lived REST-API creds the server
/// minted (`turn_creds::ice_servers_for`). **The relay tier is independent
/// per peer** — coturn hands each side a public relayed address that
/// interoperates regardless of how the *other* peer reached coturn — so the
/// agent + tunnel-client need not agree on a tier. This is the Phase-3
/// entry both call once they hold their per-session creds.
pub async fn allocate_relay_from_ice(
    urls: &[String],
    username: &str,
    credential: &str,
) -> anyhow::Result<TurnRelayConn> {
    allocate_relay_from_ice_tiered(urls, username, credential, false).await
}

/// [`allocate_relay_from_ice`] with an explicit tier policy. `tls_only = true`
/// skips Tier 2 entirely and drives the TURNS/TCP candidates directly —
/// rc.276 (B-probe): on corp-endpoint-VPN hosts the UDP allocate *succeeds*
/// and then runs silently one-way, so falling through to Tier 3 never
/// happens on its own; the overlay's `OVERLAY_RELAY_TLS` force-knob and the
/// planned strike-driven demotion both land here. Every attempt outcome logs
/// at INFO with its tier label so a field grep answers "which tier did this
/// host actually allocate on" in one shot.
pub async fn allocate_relay_from_ice_tiered(
    urls: &[String],
    username: &str,
    credential: &str,
    tls_only: bool,
) -> anyhow::Result<TurnRelayConn> {
    // Tier 2: each UDP relay candidate (bounded; some corp nets drop
    // UDP/3478 but pass UDP/443).
    if tls_only {
        tracing::info!("TURN allocate: tier2-udp SKIPPED (TLS-first forced)");
    } else {
        let mut dns: std::collections::HashMap<String, Option<IpAddr>> = Default::default();
        for server in turn_udp_servers(urls) {
            let Some(resolved) = resolve_udp_candidate(&mut dns, &server).await else {
                tracing::warn!(
                    %server,
                    "UDP TURN server unresolvable (or DNS exceeded its bound); trying next"
                );
                continue;
            };
            match tokio::time::timeout(
                UDP_ALLOC_TIMEOUT,
                allocate_turn_relay(
                    resolved,
                    username.to_string(),
                    credential.to_string(),
                    DEFAULT_TURN_REALM.to_string(),
                ),
            )
            .await
            {
                Ok(Ok(relay)) => {
                    tracing::info!(%server, "TURN relay allocated (tier2-udp)");
                    return Ok(relay);
                }
                Ok(Err(e)) => tracing::warn!(%server, %e, "UDP TURN allocate failed; trying next"),
                Err(_) => tracing::warn!(%server, "UDP TURN allocate timed out; trying next"),
            }
            // Corp-VPN rescue: the unbound attempt source-selects a captured
            // default route into the tunnel, where UDP dies — retry ONCE
            // bound to the first non-VPN uplink (the deny-listed LAN gather
            // the direct socks bind), which escapes the capture on a
            // strong-host stack. Strictly additive: runs only after the
            // unbound attempt already failed, costs ≤ one more
            // UDP_ALLOC_TIMEOUT, and hosts without overlay-l3 (or with an
            // empty gather, e.g. a WSL-mirrored guest) skip it entirely.
            #[cfg(feature = "overlay-l3")]
            if let Some((ip, ifindex)) = crate::overlay::direct::first_non_vpn_uplink() {
                tracing::info!(
                    %server, %ip, ?ifindex,
                    "UDP TURN allocate: retrying pinned to the physical uplink (corp-VPN rescue)"
                );
                match tokio::time::timeout(
                    UDP_ALLOC_TIMEOUT,
                    allocate_turn_relay_from(
                        resolved,
                        username.to_string(),
                        credential.to_string(),
                        DEFAULT_TURN_REALM.to_string(),
                        Some((ip, ifindex)),
                    ),
                )
                .await
                {
                    Ok(Ok(relay)) => {
                        tracing::info!(%server, %ip, "TURN relay allocated (tier2-udp, pinned egress)");
                        return Ok(relay);
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(%server, %ip, %e, "pinned UDP TURN allocate failed; trying next")
                    }
                    Err(_) => {
                        tracing::warn!(%server, %ip, "pinned UDP TURN allocate timed out; trying next")
                    }
                }
            }
        }
    }

    // Tier 3: each TURNS/TCP relay candidate (:443 first; UDP-blocked nets).
    // The WHOLE attempt is bounded by TLS_ALLOC_TIMEOUT — TLS_CONNECT_TIMEOUT
    // inside covers only the TCP connect, and a middlebox that ACKs the SYN
    // then stalls the TLS handshake (or the TURN allocate) otherwise hangs
    // this loop unboundedly.
    for (host, port, pin) in turn_tls_servers(urls) {
        match tokio::time::timeout(
            TLS_ALLOC_TIMEOUT,
            allocate_turn_relay_tls(
                &host,
                port,
                pin,
                username.to_string(),
                credential.to_string(),
                DEFAULT_TURN_REALM.to_string(),
            ),
        )
        .await
        {
            Ok(Ok(relay)) => {
                tracing::info!(%host, port, ?pin, "TURN relay allocated (tier3-tls)");
                return Ok(relay);
            }
            Ok(Err(e)) => {
                // `{:#}` surfaces the full anyhow chain incl. the underlying
                // rustls error (e.g. "invalid peer certificate: NotValidForName"
                // = SNI/cert-name mismatch, vs "UnknownIssuer"/handshake reset =
                // a genuine middlebox block) — the signal that gates the fix.
                tracing::warn!(%host, port, ?pin, e = format!("{e:#}"), "TURNS/TCP TURN allocate failed; trying next")
            }
            Err(_) => {
                tracing::warn!(
                    %host, port, ?pin,
                    "TURNS/TCP TURN allocate deadline exceeded (stalled past connect); trying next"
                )
            }
        }
    }

    anyhow::bail!(
        "no TURN relay could be allocated from {urls:?} (tls_only={tls_only}; all attempted candidates failed)"
    )
}

/// Tier 3: allocate a TURN relay over **TURNS (TLS-over-TCP)** for nets
/// that block outbound UDP. Connects TCP → drives the TLS handshake (SNI =
/// `host`) via the vendored [`TcpTurnConn`] → feeds that as the `turn`
/// client's underlay → allocates. The relayed address coturn returns is
/// what the peer dials (delivered over signaling like the UDP path); QUIC
/// rides the allocation exactly as in Tier 2 — only the client→coturn leg
/// differs (TLS/TCP instead of UDP).
///
/// `realm` is a don't-care (coturn returns its own in the 401 challenge,
/// which the `turn` client adopts before computing MESSAGE-INTEGRITY). The
/// `TcpTurnConn` is field-proven for the WebRTC relay-gather path; this is
/// its first QUIC use.
pub async fn allocate_turn_relay_tls(
    host: &str,
    port: u16,
    pin: Option<IpAddr>,
    username: String,
    password: String,
    realm: String,
) -> anyhow::Result<TurnRelayConn> {
    use anyhow::Context as _;

    // Dial the pinned worker IP when the server named one (`&pin=`), else
    // resolve the hostname (DNS round-robin). EITHER path uses `host` (the
    // coturn hostname) for TLS SNI + cert verification below, so an IP-pinned
    // dial still presents a name coturn's DNS-only cert matches — the fix that
    // lets the deterministic same-worker hairpin survive TURNS on UDP-blocked
    // corp VPNs. `turn_serv_addr` is set to this dialed addr, so the client's
    // STUN addressing agrees with the socket.
    let resolved = match pin {
        Some(ip) => SocketAddr::new(ip, port),
        None => tokio::net::lookup_host((host, port))
            .await
            .with_context(|| format!("resolve TURNS server {host}:{port}"))?
            .next()
            .with_context(|| format!("TURNS server {host}:{port} resolved to no addresses"))?,
    };

    let tcp = tokio::time::timeout(
        TLS_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect(resolved),
    )
    .await
    .with_context(|| format!("TCP connect to TURNS server {resolved} timed out"))?
    .with_context(|| format!("TCP connect to TURNS server {resolved}"))?;
    // Keep the long-lived TURNS/TCP control connection warm. The `turn` client
    // only writes on it at the sparse allocation-refresh (~10 min) + permission-
    // refresh (~5 min) cadence; between those it's idle, and a corporate
    // middlebox reaps an idle TCP → the next refresh hits a dead socket (os
    // error 10054 "connection reset") → the relay carrier dies + churns + the
    // overlay peer flaps to Blocked (fleet diag 2026-07-13: 870× "refresh
    // allocation failed" on the corp host winhost-a, while it kept re-allocating
    // TURNS/TCP fine — a persistence, not a reachability, failure). A ~30 s TCP
    // keepalive holds the 5-tuple open across the refresh gap AND surfaces a
    // genuinely-dead path fast. Best-effort: a keepalive-set failure must never
    // fail the allocation. `with_time`+`with_interval` are supported on Windows
    // (SIO_KEEPALIVE_VALS) + Linux; `with_retries` is not portable, so omitted.
    if let Err(e) = socket2::SockRef::from(&tcp).set_tcp_keepalive(
        &socket2::TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(30))
            .with_interval(std::time::Duration::from_secs(15)),
    ) {
        tracing::debug!(%e, "TURNS/TCP: could not set TCP keepalive (non-fatal)");
    }
    let adapter = TcpTurnConn::connect_tls(tcp, host)
        .await
        .with_context(|| format!("TLS handshake to TURNS server {host}"))?;
    let conn: Arc<dyn UtilConn + Send + Sync> = Arc::new(adapter);

    let client = Client::new(ClientConfig {
        stun_serv_addr: String::new(),
        turn_serv_addr: resolved.to_string(),
        username,
        password,
        realm,
        software: String::new(),
        rto_in_ms: 0,
        // Over TCP every byte rides the one TLS connection — no vnet (which
        // would try to open side sockets for keepalives).
        conn,
        vnet: None,
    })
    .await
    .context("TURNS client::new")?;

    let client = Arc::new(client);
    // Same FR-48 guard as the UDP path. The underlay here is the TLS connection
    // rather than a UDP socket, so a stranded attempt costs a TCP connection and
    // its read task instead of an ephemeral port — invisible to `ss -uanp`, same
    // ownership bug, and this path has a timeout over it too.
    let guard = ClientCloseGuard(Some(Arc::clone(&client)));

    client.listen().await.context("TURNS client listen")?;
    let relay = client.allocate().await.context("TURNS allocate")?;
    let relayed_addr = relay
        .local_addr()
        .map_err(util_to_io)
        .context("TURNS relayed local_addr")?;
    tracing::info!(%host, port, %relayed_addr, "TURNS/TCP TURN allocation established");

    Ok(TurnRelayConn {
        transport: RelayTransport::Tcp,
        server: format!("{host}:{port}"),
        client: guard.disarm(),
        relay: Arc::new(relay),
        relayed_addr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    async fn udp_relay() -> (Arc<dyn RelayConn>, SocketAddr) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        (Arc::new(UdpRelayConn(sock)), addr)
    }

    #[test]
    fn split_host_port_handles_names_v6_and_garbage() {
        assert_eq!(
            split_host_port("coturn.roomler.ai:3478"),
            Some(("coturn.roomler.ai", 3478))
        );
        assert_eq!(split_host_port("[::1]:443"), Some(("::1", 443)));
        assert_eq!(
            split_host_port("94.130.141.74:443"),
            Some(("94.130.141.74", 443))
        );
        assert_eq!(split_host_port("no-port"), None);
        // rsplit takes the LAST colon: ("bad:port", "x") → port parse fails.
        assert_eq!(split_host_port("bad:port:x"), None);
    }

    /// IP literals never touch the resolver, and a per-walk cache entry —
    /// including a cached FAILURE — is honored without a second lookup (the
    /// resolve-once-per-walk contract: a dead resolver costs one bounded
    /// wait per unique host, not one per candidate).
    #[tokio::test]
    async fn resolve_udp_candidate_uses_literals_and_cache() {
        let mut dns = std::collections::HashMap::new();
        let got = resolve_udp_candidate(&mut dns, "127.0.0.1:3478")
            .await
            .unwrap();
        assert_eq!(got, "127.0.0.1:3478".parse::<SocketAddr>().unwrap());
        assert!(dns.is_empty(), "literals must not populate the DNS cache");

        dns.insert(
            "cached.example".to_string(),
            Some(IpAddr::from([10, 1, 2, 3])),
        );
        let got = resolve_udp_candidate(&mut dns, "cached.example:443")
            .await
            .unwrap();
        assert_eq!(got, SocketAddr::from(([10, 1, 2, 3], 443)));

        dns.insert("dead.example".to_string(), None);
        assert!(
            resolve_udp_candidate(&mut dns, "dead.example:3478")
                .await
                .is_none()
        );
    }

    /// The HAZARD the outer `TLS_ALLOC_TIMEOUT` exists for: a listener that
    /// completes the TCP connect and then stalls forever (a TLS-stalling
    /// middlebox). The inner `TLS_CONNECT_TIMEOUT` does NOT fire — connect
    /// succeeded — so without the outer bound the tiered walk hangs
    /// unboundedly right here. If this test ever FAILS, an inner bound was
    /// added to `allocate_turn_relay_tls`; re-examine whether the outer
    /// bound in the tiered walk is still needed before deleting either.
    #[tokio::test]
    async fn tls_allocate_stalls_on_an_accept_only_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock); // hold open, never speak TLS
            }
        });
        let attempt = allocate_turn_relay_tls(
            "stall.test",
            addr.port(),
            Some(addr.ip()),
            "u".into(),
            "p".into(),
            "r".into(),
        );
        // 400 ms is far above a loopback connect, far below the 10 s
        // production bound — the attempt must still be running.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(400), attempt)
                .await
                .is_err(),
            "allocate returned early — the stall hazard no longer reproduces"
        );
    }

    /// `turn_udp_server` must pick the plain-UDP TURN url out of the
    /// production 6-url ICE list (which leads with STUN + interleaves
    /// TCP/TLS flavours) and skip everything the UDP `turn` client can't
    /// use.
    #[test]
    fn turn_udp_server_picks_the_udp_url() {
        let prod = vec![
            "stun:stun.l.google.com:19302".to_string(),
            "turns:coturn.roomler.ai:5349?transport=tcp".to_string(),
            "turn:coturn.roomler.ai:3478?transport=udp".to_string(),
            "turn:coturn.roomler.ai:3478?transport=tcp".to_string(),
        ];
        assert_eq!(
            turn_udp_server(&prod).as_deref(),
            Some("coturn.roomler.ai:3478")
        );
        // No `?transport` ⇒ UDP default.
        assert_eq!(
            turn_udp_server(&["turn:host.example:3478".to_string()]).as_deref(),
            Some("host.example:3478")
        );
        // Only TLS / TCP flavours ⇒ nothing the Tier-2 UDP client can use.
        assert_eq!(
            turn_udp_server(&["turns:host:5349?transport=tcp".to_string()]),
            None
        );
        assert_eq!(turn_udp_server(&["stun:host:3478".to_string()]), None);
        assert_eq!(turn_udp_server(&[]), None);
    }

    /// Tier 3 (corp-net fix): from the EXACT `build_turn_config` URL order —
    /// which emits `turns:…:5349?transport=tcp` BEFORE `turns:…:443?…tcp` —
    /// the picker must prefer **:443** (the alt-tls port corp firewalls
    /// allow), not the first-listed `:5349` (frequently blocked). Locks the
    /// fix for the 2026-06-02 field timeout. Also covers the plural UDP/TLS
    /// enumerators (so the allocator can walk every candidate).
    #[test]
    fn turn_tls_server_prefers_443_over_5349() {
        // Mirrors crates/api/src/state.rs::build_turn_config emission order.
        let prod = vec![
            "turn:coturn.roomler.ai:3478".to_string(), // base (udp default)
            "turn:coturn.roomler.ai:443?transport=udp".to_string(),
            "turn:coturn.roomler.ai:3478?transport=tcp".to_string(), // plain turn-tcp (unusable)
            "turns:coturn.roomler.ai:5349?transport=tcp".to_string(), // :5349 listed FIRST
            "turns:coturn.roomler.ai:443?transport=udp".to_string(), // turns-udp (DTLS, skipped)
            "turns:coturn.roomler.ai:443?transport=tcp".to_string(), // :443 listed LATER
        ];
        assert_eq!(
            turn_tls_server(&prod),
            Some(("coturn.roomler.ai".to_string(), 443, None)),
            ":443 must win over :5349 even though :5349 is listed first"
        );
        assert_eq!(
            turn_tls_servers(&prod),
            vec![
                ("coturn.roomler.ai".to_string(), 443, None),
                ("coturn.roomler.ai".to_string(), 5349, None),
            ],
            "plural returns all turns:tcp, :443 first"
        );
        // UDP enumerator returns both the base (:3478, udp default) + :443?udp,
        // and skips the plain turn:tcp + all turns:.
        assert_eq!(
            turn_udp_servers(&prod),
            vec![
                "coturn.roomler.ai:3478".to_string(),
                "coturn.roomler.ai:443".to_string(),
            ]
        );
        // turns: without transport=tcp ⇒ DTLS/UDP, unusable by the adapter.
        assert!(turn_tls_servers(&["turns:host:5349".to_string()]).is_empty());
        // Plain turn:tcp is NOT turns: — never a TLS candidate.
        assert!(turn_tls_servers(&["turn:host:3478?transport=tcp".to_string()]).is_empty());
        assert_eq!(turn_tls_server(&["stun:host:3478".to_string()]), None);
        assert_eq!(turn_tls_server(&[]), None);
    }

    /// rc.140: `&pin=<ip>` names the coturn worker to DIAL while the URL host
    /// stays the hostname for TLS SNI + cert verification. turn_tls_servers must
    /// surface the pin (and yield None for a garbage/absent pin), and the UDP
    /// enumerator must ignore a stray `&pin=`.
    #[test]
    fn turn_tls_servers_extracts_pin_but_keeps_hostname() {
        assert_eq!(
            turn_tls_servers(&[
                "turns:coturn.roomler.ai:443?transport=tcp&pin=94.130.141.74".to_string()
            ]),
            vec![(
                "coturn.roomler.ai".to_string(),
                443,
                Some("94.130.141.74".parse::<IpAddr>().unwrap())
            )],
            "SNI host stays the hostname; the dial target is the pin"
        );
        // Unparseable pin ⇒ None (fall back to hostname DNS resolution).
        assert_eq!(
            turn_tls_servers(&[
                "turns:coturn.roomler.ai:443?transport=tcp&pin=not-an-ip".to_string()
            ]),
            vec![("coturn.roomler.ai".to_string(), 443, None)]
        );
        // A stray `&pin=` on a UDP url must not confuse the UDP enumerator.
        assert_eq!(
            turn_udp_servers(&["turn:1.2.3.4:3478?transport=udp&pin=1.2.3.4".to_string()]),
            vec!["1.2.3.4:3478".to_string()]
        );
    }

    /// The adapter must faithfully carry datagrams both ways: send via
    /// quinn's `try_send` shape (through the channel + drain task) and
    /// receive via `poll_recv` (through the fill task). We drive it with
    /// raw datagrams (no quinn) to isolate the bridge logic.
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_socket_round_trips_datagrams() {
        use std::future::poll_fn;

        let (conn_a, addr_a) = udp_relay().await;
        let (conn_b, addr_b) = udp_relay().await;
        let sock_a = RelayUdpSocket::new(conn_a).unwrap();
        let sock_b = RelayUdpSocket::new(conn_b).unwrap();
        assert_eq!(sock_a.local_addr().unwrap(), addr_a);

        // A → B via try_send.
        let payload = b"relayed quic datagram";
        sock_a
            .try_send(&Transmit {
                destination: addr_b,
                ecn: None,
                contents: payload,
                segment_size: None,
                src_ip: None,
            })
            .unwrap();

        // B receives it via poll_recv.
        let mut buf = [0u8; MAX_DATAGRAM];
        let (n, src) = poll_fn(|cx| {
            let mut bufs = [IoSliceMut::new(&mut buf)];
            let mut meta = [RecvMeta::default()];
            match sock_b.poll_recv(cx, &mut bufs, &mut meta) {
                Poll::Ready(Ok(_)) => Poll::Ready((meta[0].len, meta[0].addr)),
                Poll::Ready(Err(e)) => panic!("poll_recv error: {e}"),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
        assert_eq!(&buf[..n], payload, "datagram must arrive intact");
        assert_eq!(src, addr_a, "recv meta must report the real source");
    }

    /// Full proof: a quinn server + client, each backed by a
    /// `RelayUdpSocket` over a loopback UDP relay, complete the TLS
    /// handshake + round-trip a flow. This is what Phase 3 does over a
    /// TURN allocation instead of loopback UDP.
    #[tokio::test(flavor = "multi_thread")]
    async fn quinn_runs_over_relay_socket() {
        use crate::transport::quic::{QuicPeer, accept_flow, open_flow};

        let (conn_s, addr_s) = udp_relay().await;
        let (conn_c, _addr_c) = udp_relay().await;
        let server_sock = Arc::new(RelayUdpSocket::new(conn_s).unwrap());
        let client_sock = Arc::new(RelayUdpSocket::new(conn_c).unwrap());

        let (server, fp) =
            QuicPeer::server_over_abstract_socket(server_sock).expect("server over relay");
        let client =
            QuicPeer::client_over_abstract_socket(client_sock, &fp).expect("client over relay");

        let srv = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").expect("handshake");
            let (flow_id, mut send, mut recv) = accept_flow(&conn).await.expect("accept_flow");
            assert_eq!(flow_id, 11);
            let got = recv.read_to_end(64 * 1024).await.unwrap();
            assert_eq!(&got, b"ping-over-relay");
            send.write_all(b"pong-over-relay").await.unwrap();
            send.finish().unwrap();
            conn.closed().await;
        });

        // The client dials the server's relay address.
        let conn = client.connect(addr_s).await.expect("connect over relay");
        let (mut send, mut recv) = open_flow(&conn, 11).await.expect("open_flow");
        send.write_all(b"ping-over-relay").await.unwrap();
        send.finish().unwrap();
        let reply = recv.read_to_end(64 * 1024).await.unwrap();
        assert_eq!(
            &reply, b"pong-over-relay",
            "quinn round-trip over the relay socket"
        );
        conn.close(0u32.into(), b"done");
        let _ = srv.await;
    }

    /// Overlay carrier (Phase 1): WG-over-QUIC **datagrams** ride a
    /// `RelayUdpSocket`. Asserts both ends' datagram budget fits a 1280-MTU WG
    /// packet (≈1312 B) and round-trips one each way — the raw material the
    /// `Carrier::QuicRelay` carrier is built from.
    #[tokio::test(flavor = "multi_thread")]
    async fn quinn_datagrams_over_relay_socket() {
        use crate::transport::quic::QuicPeer;
        use bytes::Bytes;

        let (conn_s, addr_s) = udp_relay().await;
        let (conn_c, _addr_c) = udp_relay().await;
        let server_sock = Arc::new(RelayUdpSocket::new(conn_s).unwrap());
        let client_sock = Arc::new(RelayUdpSocket::new(conn_c).unwrap());

        let server =
            QuicPeer::server_over_relay_datagram(server_sock).expect("datagram server over relay");
        let client =
            QuicPeer::client_over_relay_datagram(client_sock).expect("datagram client over relay");

        let srv = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").expect("handshake");
            assert!(
                conn.max_datagram_size().unwrap_or(0) >= 1312,
                "server datagram budget must fit a 1280-MTU WG packet"
            );
            let d = conn.read_datagram().await.expect("read datagram");
            assert_eq!(d.len(), 1312);
            assert!(d.iter().all(|&b| b == 0x42), "payload intact");
            conn.send_datagram(Bytes::from(vec![0x24u8; 1312]))
                .expect("send reply datagram");
            conn.closed().await;
        });

        let conn = client.connect(addr_s).await.expect("connect over relay");
        assert!(
            conn.max_datagram_size().unwrap_or(0) >= 1312,
            "client datagram budget must fit a 1280-MTU WG packet"
        );
        conn.send_datagram(Bytes::from(vec![0x42u8; 1312]))
            .expect("send datagram");
        let reply = conn.read_datagram().await.expect("read reply");
        assert_eq!(reply.len(), 1312);
        assert!(reply.iter().all(|&b| b == 0x24), "reply payload intact");
        conn.close(0u32.into(), b"done");
        let _ = srv.await;
    }
}

#[cfg(test)]
mod turn_tests {
    //! Phase 3b validation: prove the full **Tier-2** path — a quinn
    //! server + client, each riding a [`RelayUdpSocket`] over a *real*
    //! TURN allocation on an in-process [`turn::server::Server`] —
    //! complete the handshake and round-trip a flow. This is exactly
    //! what Phase 3d does against the live coturn cluster, minus coturn:
    //! two allocations on one server relay to each other (peer → server
    //! → peer), exercising [`allocate_turn_relay`], [`TurnRelayConn`],
    //! the permission bootstrap, and quinn-over-relay end to end.

    use super::*;
    use crate::transport::quic::{QuicPeer, accept_flow, open_flow};
    use std::net::IpAddr;
    use std::time::Duration;
    use turn::auth::{AuthHandler, generate_auth_key};
    use turn::relay::relay_static::RelayAddressGeneratorStatic;
    use turn::server::Server;
    use turn::server::config::{ConnConfig, ServerConfig};
    use webrtc_util::vnet::net::Net;

    const REALM: &str = "roomler.test";
    const USER: &str = "quic-tester";
    const PASS: &str = "turn-secret";

    /// Long-term-credential auth accepting the one test user. The server
    /// derives the expected HMAC key from `(user, realm, pass)`; the
    /// client derives the same from its configured creds, so they match.
    struct StaticAuth;
    impl AuthHandler for StaticAuth {
        fn auth_handle(
            &self,
            _username: &str,
            realm: &str,
            _src: SocketAddr,
        ) -> Result<Vec<u8>, turn::Error> {
            Ok(generate_auth_key(USER, realm, PASS))
        }
    }

    /// In-process TURN server on loopback; relay addresses are handed out
    /// on 127.0.0.1 too, so two allocations can relay to each other.
    /// Returns the server (keep it alive for the test) and its addr.
    async fn loopback_turn_server() -> (Server, SocketAddr) {
        let conn = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let turn_addr = conn.local_addr().unwrap();
        let server = Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn,
                relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                    relay_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    address: "127.0.0.1".to_owned(),
                    net: Arc::new(Net::new(None)),
                }),
            }],
            realm: REALM.to_owned(),
            auth_handler: Arc::new(StaticAuth),
            channel_bind_timeout: Duration::from_secs(0),
            alloc_close_notify: None,
        })
        .await
        .expect("in-process turn server");
        (server, turn_addr)
    }

    /// FR-48 (#1086) — a TURN allocate that is **cancelled by its caller's
    /// timeout** must not strand its underlay socket.
    ///
    /// This is the shape the field leak actually had: `listen()` spawns a read
    /// loop owning a clone of the underlay `Arc`, `turn::Client` has no `Drop`,
    /// and every caller wraps the allocate in `tokio::time::timeout` — so the
    /// dominant path is the future being *dropped*, not returning `Err`. A fix
    /// that only closed on the error paths passes a happy-path test and leaks
    /// exactly here.
    ///
    /// ⚠️ Counts `/proc/self/fd`, so Linux only — this asserts about process
    /// file descriptors, which is the property that broke (ephemeral-port
    /// exhaustion), not a proxy for it.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_cancelled_turn_allocate_does_not_strand_its_underlay_socket() {
        fn open_fds() -> usize {
            std::fs::read_dir("/proc/self/fd")
                .map(|d| d.count())
                .unwrap_or(0)
        }
        // Discard port: reachable enough to bind/send toward, never answers, so
        // `allocate()` is still in flight when the timeout fires.
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let attempt = || async move {
            let _ = tokio::time::timeout(
                Duration::from_millis(250),
                allocate_turn_relay_from(
                    dead,
                    "u".to_string(),
                    "p".to_string(),
                    "r".to_string(),
                    None,
                ),
            )
            .await;
        };
        // Warm up first: the first attempt can open lazily-initialised state
        // (resolver, runtime bits) that never closes and is not the leak.
        attempt().await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        let before = open_fds();

        for _ in 0..6 {
            attempt().await;
        }
        // The close is spawned (drop is sync, close is async) — give it a turn.
        tokio::time::sleep(Duration::from_millis(800)).await;
        let after = open_fds();

        assert!(
            after <= before + 1,
            "cancelled TURN allocates stranded file descriptors: {before} -> {after} \
             (6 attempts; each leaked underlay socket shows up here)"
        );
    }

    /// Corp-VPN rescue contract: an explicit egress binds the TURN client
    /// underlay to that source (here loopback, so the in-process server
    /// sees the client from 127.0.0.1) and the allocation still completes
    /// end-to-end. On a captured-default host the same mechanism swaps the
    /// VPN-selected source for the physical NIC's.
    #[tokio::test(flavor = "multi_thread")]
    async fn pinned_egress_allocates_from_the_requested_source() {
        let (_server, turn_addr) = loopback_turn_server().await;
        let relay = allocate_turn_relay_from(
            turn_addr,
            USER.into(),
            PASS.into(),
            REALM.into(),
            Some((Ipv4Addr::LOCALHOST, None)),
        )
        .await
        .expect("pinned TURN allocate");
        let relayed = relay.local_addr().expect("relayed addr");
        assert!(
            relayed.ip().is_loopback(),
            "allocation completed via the pinned source: {relayed}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn quinn_runs_over_two_turn_allocations() {
        let (_server, turn_addr) = loopback_turn_server().await;

        // Agent side + client side each allocate a relay on the server.
        let agent_relay = allocate_turn_relay(turn_addr, USER.into(), PASS.into(), REALM.into())
            .await
            .expect("agent TURN allocate");
        let client_relay = allocate_turn_relay(turn_addr, USER.into(), PASS.into(), REALM.into())
            .await
            .expect("client TURN allocate");

        let r_agent = agent_relay.local_addr().unwrap();
        let r_client = client_relay.local_addr().unwrap();
        assert_ne!(r_agent, r_client, "allocations get distinct relay addrs");
        assert!(r_agent.ip().is_loopback(), "loopback relay addr: {r_agent}");

        // Permission bootstrap: each allocation must install a TURN
        // permission for the other's relay addr before the server will
        // relay inbound from it. One datagram each way installs it (the
        // stray byte is discarded by quinn as a too-short packet). Phase
        // 3d does this after exchanging relay addrs over signaling;
        // QUIC's Initial retransmission covers any race between the
        // permission install and the first handshake packet.
        agent_relay.send_to(b"\x00", r_client).await.unwrap();
        client_relay.send_to(b"\x00", r_agent).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let agent_sock = Arc::new(RelayUdpSocket::new(Arc::new(agent_relay)).unwrap());
        let client_sock = Arc::new(RelayUdpSocket::new(Arc::new(client_relay)).unwrap());

        let (server, fp) =
            QuicPeer::server_over_abstract_socket(agent_sock).expect("quic server over TURN");
        let client =
            QuicPeer::client_over_abstract_socket(client_sock, &fp).expect("quic client over TURN");

        let srv = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").expect("handshake");
            let (flow_id, mut send, mut recv) = accept_flow(&conn).await.expect("accept_flow");
            assert_eq!(flow_id, 42);
            let got = recv.read_to_end(64 * 1024).await.unwrap();
            assert_eq!(&got, b"ping-over-turn");
            send.write_all(b"pong-over-turn").await.unwrap();
            send.finish().unwrap();
            conn.closed().await;
        });

        // Bound the e2e so a relay/permission misfire fails fast rather
        // than hanging the runner.
        let outcome = tokio::time::timeout(Duration::from_secs(15), async {
            let conn = client.connect(r_agent).await.expect("connect over TURN");
            let (mut send, mut recv) = open_flow(&conn, 42).await.expect("open_flow");
            send.write_all(b"ping-over-turn").await.unwrap();
            send.finish().unwrap();
            let reply = recv.read_to_end(64 * 1024).await.unwrap();
            assert_eq!(
                &reply, b"pong-over-turn",
                "quinn round-trip over TURN relay"
            );
            conn.close(0u32.into(), b"done");
        })
        .await;
        outcome.expect("quinn-over-TURN round-trip timed out");
        let _ = srv.await;
    }

    /// Phase-0 spike for the **loopback-TURN corp-relay** plan
    /// (`~/.claude/plans/roomler-loopback-turn-corp-relay.md`).
    ///
    /// The make-or-break unknown: will TWO **webrtc-rs** peers (the browser
    /// and the remote agent both speak webrtc-rs' TURN client) converge on a
    /// RELAY path through a TURN server WE host in-process — auto-handling the
    /// relay-to-relay TURN permission dance — the way Option 2 needs? The QUIC
    /// test above proves a hosted TURN + two raw allocations relay end-to-end
    /// (with a MANUAL `\x00` permission bootstrap); this proves the same over
    /// webrtc-rs' ICE agent, which must install those permissions itself.
    ///
    /// `ice_transport_policy = Relay` forces BOTH peers to use only the TURN,
    /// so a DataChannel message arriving == the self-hosted relay path worked.
    /// A loopback relay address stands in for the agent's overlay IP (routing
    /// to the overlay IP is proven separately by the netstack UDP mesh).
    #[tokio::test(flavor = "multi_thread")]
    async fn webrtc_peers_relay_through_self_hosted_turn() {
        use tokio::sync::mpsc;
        use webrtc::api::APIBuilder;
        use webrtc::api::interceptor_registry::register_default_interceptors;
        use webrtc::api::media_engine::MediaEngine;
        use webrtc::data_channel::data_channel_message::DataChannelMessage;
        use webrtc::ice_transport::ice_candidate::RTCIceCandidate;
        use webrtc::ice_transport::ice_server::RTCIceServer;
        use webrtc::peer_connection::configuration::RTCConfiguration;
        use webrtc::peer_connection::policy::ice_transport_policy::RTCIceTransportPolicy;

        let (_server, turn_addr) = loopback_turn_server().await;

        // Build a fresh webrtc-rs API (same recipe as the agent's peer.rs).
        let build_pc = || async {
            let mut engine = MediaEngine::default();
            engine.register_default_codecs().unwrap();
            let mut registry = webrtc::interceptor::registry::Registry::new();
            registry = register_default_interceptors(registry, &mut engine).unwrap();
            let api = APIBuilder::new()
                .with_media_engine(engine)
                .with_interceptor_registry(registry)
                .build();
            let config = RTCConfiguration {
                ice_servers: vec![RTCIceServer {
                    // Plain `turn:` UDP only — webrtc-rs silently drops
                    // turns:/?transport=tcp (memory: webrtc-rs TURN-URL gap).
                    urls: vec![format!("turn:{turn_addr}")],
                    username: USER.to_owned(),
                    credential: PASS.to_owned(),
                }],
                // Force the relay path so success == the hosted TURN carried it.
                ice_transport_policy: RTCIceTransportPolicy::Relay,
                ..Default::default()
            };
            Arc::new(api.new_peer_connection(config).await.unwrap())
        };

        let pc_a = build_pc().await;
        let pc_b = build_pc().await;

        // In-process trickle ICE both directions.
        let pc_b_ice = pc_b.clone();
        pc_a.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
            let pc_b = pc_b_ice.clone();
            Box::pin(async move {
                if let Some(c) = c
                    && let Ok(init) = c.to_json()
                {
                    let _ = pc_b.add_ice_candidate(init).await;
                }
            })
        }));
        let pc_a_ice = pc_a.clone();
        pc_b.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
            let pc_a = pc_a_ice.clone();
            Box::pin(async move {
                if let Some(c) = c
                    && let Ok(init) = c.to_json()
                {
                    let _ = pc_a.add_ice_candidate(init).await;
                }
            })
        }));

        // B receives the inbound DataChannel and forwards its first message.
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        pc_b.on_data_channel(Box::new(
            move |dc: Arc<webrtc::data_channel::RTCDataChannel>| {
                let tx = tx.clone();
                Box::pin(async move {
                    dc.on_message(Box::new(move |msg: DataChannelMessage| {
                        let tx = tx.clone();
                        let s = String::from_utf8_lossy(&msg.data).to_string();
                        Box::pin(async move {
                            let _ = tx.send(s);
                        })
                    }));
                })
            },
        ));

        // A opens the DataChannel (before the offer, so it's in the SDP) and
        // sends once it's open.
        let dc_a = pc_a.create_data_channel("spike", None).await.unwrap();
        let dc_send = dc_a.clone();
        dc_a.on_open(Box::new(move || {
            let dc = dc_send.clone();
            Box::pin(async move {
                let _ = dc.send_text("relay-spike".to_owned()).await;
            })
        }));

        // Offer / answer.
        let offer = pc_a.create_offer(None).await.unwrap();
        pc_a.set_local_description(offer.clone()).await.unwrap();
        pc_b.set_remote_description(offer).await.unwrap();
        let answer = pc_b.create_answer(None).await.unwrap();
        pc_b.set_local_description(answer.clone()).await.unwrap();
        pc_a.set_remote_description(answer).await.unwrap();

        // The whole point: does the relay-to-relay pair converge + carry data
        // through OUR hosted TURN, with webrtc-rs installing the permissions?
        let got = tokio::time::timeout(Duration::from_secs(25), rx.recv())
            .await
            .expect("webrtc-rs relay-through-self-hosted-TURN TIMED OUT (permission dance or pair selection failed — the spike's kill signal)")
            .expect("data channel closed before the message arrived");
        assert_eq!(
            got, "relay-spike",
            "DataChannel message round-tripped over the self-hosted TURN relay"
        );

        // Teardown is CLEANUP, not the subject — and it must not be able to fail
        // this test. Everything the test exists to prove was asserted above: the
        // relay-to-relay pair converged and carried a DataChannel message through
        // our own TURN. `close()` afterwards says nothing about that.
        //
        // #855 recorded this failing in CI as
        //   `data_channels: sending reset packet in non-Established state`
        // on a PR whose entire diff was a `println!` in another crate. That is
        // webrtc-rs resetting a channel whose SCTP association is no longer (or
        // not yet) Established — a teardown race on a loaded runner, arriving
        // AFTER the round trip already succeeded. Unwrapping it turned a passed
        // test into a red lane that gates every PR.
        //
        // Reported rather than swallowed (visible under `--nocapture`), because a
        // close error that stops mattering silently is how a real teardown
        // regression would hide here later.
        if let Err(e) = pc_a.close().await {
            eprintln!("pc_a.close() after a successful round trip: {e} (not a failure — see #855)");
        }
        if let Err(e) = pc_b.close().await {
            eprintln!("pc_b.close() after a successful round trip: {e} (not a failure — see #855)");
        }
    }

    // ───────────── LIVE coturn smokes (Phase 3 e2e, ignored) ─────────────
    //
    // These exercise the REAL [`allocate_relay_from_ice`] entry against the
    // production coturn cluster — the same allocate → mutual-permission →
    // quinn-handshake path as `quinn_runs_over_two_turn_allocations`, minus
    // the in-process server. They prove Tier 2 (UDP) and Tier 3 (TURNS/TCP)
    // work against live coturn, isolating the relay primitives from the
    // agent/client signaling (which is covered by the wire-lock + glue
    // tests). `#[ignore]` + env-gated so they never run in CI: provide
    //   ROOMLER_TEST_TURN_HOST   = coturn.roomler.ai
    //   ROOMLER_TEST_TURN_SECRET = coturn's static-auth-secret (from the
    //                              k8s secret / ROOMLER__TURN__SHARED_SECRET)
    // and run on a host with outbound UDP/3478 (UDP smoke) or TCP/443
    // (TURNS/TCP smoke) to coturn. The secret stays in the env — never in
    // source. Run e.g.:
    //   cargo test -p roomler-ai-tunnel-core --ignored relay_against_real_coturn

    /// Allocate TWO relays via the real [`allocate_relay_from_ice`] entry,
    /// mutually permission them, and run a full quinn handshake + flow
    /// round-trip between them over the live cluster.
    async fn two_relay_quinn_roundtrip(urls: &[String], user: &str, cred: &str) {
        let agent_relay = allocate_relay_from_ice(urls, user, cred)
            .await
            .expect("agent relay allocate (live coturn)");
        let client_relay = allocate_relay_from_ice(urls, user, cred)
            .await
            .expect("client relay allocate (live coturn)");
        let r_agent = agent_relay.local_addr().unwrap();
        let r_client = client_relay.local_addr().unwrap();
        eprintln!("live coturn relays: agent={r_agent} client={r_client}");
        assert_ne!(
            r_agent, r_client,
            "two allocations get distinct relay addrs"
        );

        // Mutual permission bootstrap (one stray datagram each way).
        agent_relay.send_to(b"\x00", r_client).await.unwrap();
        client_relay.send_to(b"\x00", r_agent).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;

        let agent_sock = Arc::new(RelayUdpSocket::new(Arc::new(agent_relay)).unwrap());
        let client_sock = Arc::new(RelayUdpSocket::new(Arc::new(client_relay)).unwrap());
        let (server, fp) =
            QuicPeer::server_over_abstract_socket(agent_sock).expect("quic server over coturn");
        let client = QuicPeer::client_over_abstract_socket(client_sock, &fp)
            .expect("quic client over coturn");

        let srv = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").expect("handshake");
            let (flow_id, mut send, mut recv) = accept_flow(&conn).await.expect("accept_flow");
            assert_eq!(flow_id, 77);
            let got = recv.read_to_end(64 * 1024).await.unwrap();
            assert_eq!(&got, b"ping-over-coturn");
            send.write_all(b"pong-over-coturn").await.unwrap();
            send.finish().unwrap();
            conn.closed().await;
        });

        let outcome = tokio::time::timeout(Duration::from_secs(30), async {
            let conn = client
                .connect(r_agent)
                .await
                .expect("connect over live coturn relay");
            let (mut send, mut recv) = open_flow(&conn, 77).await.expect("open_flow");
            send.write_all(b"ping-over-coturn").await.unwrap();
            send.finish().unwrap();
            let reply = recv.read_to_end(64 * 1024).await.unwrap();
            assert_eq!(
                &reply, b"pong-over-coturn",
                "quinn round-trip over live coturn relay"
            );
            conn.close(0u32.into(), b"done");
        })
        .await;
        outcome.expect("quinn-over-coturn round-trip timed out");
        let _ = srv.await;
    }

    /// Mint live REST creds from env, or `None` to skip (env unset).
    fn live_coturn_creds(
        urls_for: impl Fn(&str) -> Vec<String>,
    ) -> Option<(Vec<String>, String, String)> {
        let host = std::env::var("ROOMLER_TEST_TURN_HOST").ok()?;
        let secret = std::env::var("ROOMLER_TEST_TURN_SECRET").ok()?;
        let cfg = roomler_ai_remote_control::turn_creds::TurnConfig {
            workers: vec![],
            urls: urls_for(&host),
            shared_secret: secret,
            ttl_secs: 600,
        };
        let ice = cfg.issue("quic-coturn-smoke");
        Some((ice.urls, ice.username?, ice.credential?))
    }

    /// LIVE Tier-2: UDP relay against the production coturn cluster.
    /// `ROOMLER_TEST_TURN_UDP_PORT=443` points it at the udp/443 DNAT
    /// (the corp-escape tier the fleet + relay PoPs expose) instead of 3478.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "hits live coturn; set ROOMLER_TEST_TURN_HOST + ROOMLER_TEST_TURN_SECRET"]
    async fn relay_against_real_coturn_udp() {
        let port = std::env::var("ROOMLER_TEST_TURN_UDP_PORT").unwrap_or_else(|_| "3478".into());
        let Some((urls, user, cred)) =
            live_coturn_creds(|h| vec![format!("turn:{h}:{port}?transport=udp")])
        else {
            eprintln!("SKIP relay_against_real_coturn_udp: env unset");
            return;
        };
        two_relay_quinn_roundtrip(&urls, &user, &cred).await;
    }

    /// LIVE Tier-3: TURNS/TCP relay (TLS over TCP/443 — the UDP-blocked-net
    /// path). The url list has no `turn:…udp` entry, so
    /// `allocate_relay_from_ice` falls through to the TURNS/TCP tier.
    /// `ROOMLER_TEST_TURN_TLS_PORT=5349` targets coturn's own TLS listener
    /// directly — isolates a PoP's nginx SNI hop from coturn itself.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "hits live coturn over TLS/TCP; set ROOMLER_TEST_TURN_HOST + ROOMLER_TEST_TURN_SECRET"]
    async fn relay_against_real_coturn_turns_tcp() {
        let port = std::env::var("ROOMLER_TEST_TURN_TLS_PORT").unwrap_or_else(|_| "443".into());
        let Some((urls, user, cred)) =
            live_coturn_creds(|h| vec![format!("turns:{h}:{port}?transport=tcp")])
        else {
            eprintln!("SKIP relay_against_real_coturn_turns_tcp: env unset");
            return;
        };
        two_relay_quinn_roundtrip(&urls, &user, &cred).await;
    }

    /// ROOT-CAUSE DIAG for the both-allocate `REKEY_TIMEOUT`: does coturn relay
    /// data between TWO of its OWN allocations on the SAME worker (the
    /// intra-worker "relay-to-relay hairpin")? both-allocate needs A's
    /// allocation to relay a datagram to B's allocation; single-relay never does
    /// (one allocation + a raw dialer), which is why single-relay carries where
    /// both-allocate deadlocks. Pins BOTH allocations to `ROOMLER_TEST_TURN_WORKER`
    /// (an off-host worker, else the sender hairpins on the local host DNAT) and
    /// sends RAW datagrams both ways — no QUIC/WG, so a failure is coturn's, not
    /// a handshake-timing artifact.
    ///
    ///   ROOMLER_TEST_TURN_HOST=coturn.roomler.ai \
    ///   ROOMLER_TEST_TURN_SECRET=<secret> ROOMLER_TEST_TURN_WORKER=5.9.157.221 \
    ///   cargo test -p roomler-ai-tunnel-core --features overlay-l3 \
    ///     --lib relay_to_relay_hairpin_against_real_coturn -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "hits live coturn; set ROOMLER_TEST_TURN_HOST/SECRET + ROOMLER_TEST_TURN_WORKER"]
    async fn relay_to_relay_hairpin_against_real_coturn() {
        let Some(worker) = std::env::var("ROOMLER_TEST_TURN_WORKER").ok() else {
            eprintln!("SKIP relay_to_relay_hairpin: ROOMLER_TEST_TURN_WORKER unset");
            return;
        };
        let Some((urls, user, cred)) =
            live_coturn_creds(|_h| vec![format!("turn:{worker}:3478?transport=udp")])
        else {
            eprintln!("SKIP relay_to_relay_hairpin: TURN env unset");
            return;
        };

        let a = allocate_relay_from_ice(&urls, &user, &cred)
            .await
            .expect("alloc A (live coturn)");
        let b = allocate_relay_from_ice(&urls, &user, &cred)
            .await
            .expect("alloc B (live coturn)");
        let r_a = a.local_addr().unwrap();
        let r_b = b.local_addr().unwrap();
        eprintln!("hairpin: worker={worker} R_a={r_a} R_b={r_b}");
        assert_ne!(r_a, r_b, "two allocations get distinct relay addrs");

        // Mutual permission: each permits the other's relayed IP (the worker's
        // own IP). This is exactly what both-allocate's `\x00` bootstrap does.
        a.send_to(b"\x00", r_b).await.unwrap();
        b.send_to(b"\x00", r_a).await.unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;

        // A's allocation → B's allocation (the hairpin). Retry a few times since
        // the permission may still be settling on the worker.
        let mut buf = [0u8; 128];
        let mut ab_ok = false;
        for _ in 0..5 {
            a.send_to(b"hairpin-A-to-B", r_b).await.unwrap();
            if let Ok(Ok((n, src))) =
                tokio::time::timeout(Duration::from_secs(2), b.recv_from(&mut buf)).await
            {
                eprintln!(
                    "A->B OK: {n}B from {src}: {:?}",
                    std::str::from_utf8(&buf[..n])
                );
                ab_ok = true;
                break;
            }
        }
        if !ab_ok {
            eprintln!("A->B FAIL: coturn did NOT relay from allocation A to allocation B");
        }

        let mut buf2 = [0u8; 128];
        let mut ba_ok = false;
        for _ in 0..5 {
            b.send_to(b"hairpin-B-to-A", r_a).await.unwrap();
            if let Ok(Ok((n, src))) =
                tokio::time::timeout(Duration::from_secs(2), a.recv_from(&mut buf2)).await
            {
                eprintln!("B->A OK: {n}B from {src}");
                ba_ok = true;
                break;
            }
        }
        if !ba_ok {
            eprintln!("B->A FAIL: coturn did NOT relay from allocation B to allocation A");
        }

        eprintln!(
            "VERDICT: relay-to-relay hairpin A->B={ab_ok} B->A={ba_ok} — \
             if false, coturn blocks self-allocation relay ⇒ both-allocate can't \
             carry on one worker (single-relay is the only single-coturn path)"
        );
        assert!(
            ab_ok && ba_ok,
            "coturn relay-to-relay hairpin must flow both ways for both-allocate to work"
        );
    }
}
