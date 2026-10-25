// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Userspace TCP/IP stack (netstack) — the overlay's OS-free twin.
//!
//! [`SystemTun`](super::tun::SystemTun) hands the overlay's IP packets to the
//! OS kernel via a real TUN device, which means the OS routing table decides
//! where overlay traffic goes — and on a full-tunnel corporate VPN (Check
//! Point) that table is exactly what the VPN captures. The netstack removes the
//! OS from the overlay data path entirely: it terminates the overlay CIDR's
//! TCP/UDP/ICMP **in userspace** with [smoltcp], so there is no OS route for the
//! VPN to hijack and no TUN device it can see.
//!
//! ```text
//!            app (SOCKS front)                overlay peers
//!                  │  connect(100.64.0.5:3389)      ▲
//!                  ▼                                 │ WG ciphertext
//!         ┌──────────────────┐  IP pkts   ┌──────────┴─────────┐
//!         │  Netstack        │───────────▶│ NetstackTun(TunIo) │──▶ run_bridge
//!         │  (smoltcp poll   │◀───────────│  out_rx / in_tx    │◀── WgDevice
//!         │   loop actor)    │  IP pkts   └────────────────────┘
//!         └──────────────────┘
//! ```
//!
//! The [`NetstackTun`] is a drop-in [`TunIo`](super::tun::TunIo): the WG
//! [`bridge`](super::bridge) pumps it exactly like the real device
//! (`read_packet` = "the next IP packet the stack wants to send into the mesh";
//! `write_packet` = "an IP packet that arrived from the mesh, feed it to the
//! stack"). Apps reach the mesh through [`NetstackHandle::connect`], which opens
//! a smoltcp TCP socket to an overlay address; the SYN rides the WG carriers to
//! the owning peer and the established stream is surfaced as an
//! [`AsyncRead`]+[`AsyncWrite`] [`NsTcpStream`] a SOCKS front can
//! [`copy_bidirectional`](tokio::io::copy_bidirectional) against.
//!
//! **Concurrency model.** smoltcp is sans-I/O and not `Sync`, so a single
//! **poll-loop task** owns the [`Interface`] + [`SocketSet`] + the
//! [`NetstackDevice`] and is the sole mutator of stack state. Everything else —
//! the TUN read/write halves, the app-facing sockets — talks to it over
//! channels, and a shared [`Notify`] wakes it whenever there is new work
//! (an inbound packet, an app write, a control request). This is the standard
//! "netstack actor" shape.
//!
//! Scope: TCP `connect` (the SOCKS-CONNECT backend) + `listen`, UDP via
//! [`NetstackHandle::udp_bind`] (the SOCKS UDP-ASSOCIATE backend — one socket
//! per association, sending to arbitrary overlay peers), and ICMP
//! [`NetstackHandle::ping`] (an OS-free reachability probe). The iface also
//! auto-answers inbound echo requests, so a netstack host is itself pingable.
//! All three ride the same device + poll loop.
//!
//! [smoltcp]: https://docs.rs/smoltcp

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::task::AtomicWaker;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{icmp, tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpAddress, IpCidr,
    IpEndpoint, IpListenEndpoint,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tracing::{debug, trace};

use super::tun::TunIo;

/// Per-socket smoltcp RECEIVE buffer: the window this stack advertises.
/// smoltcp derives window scaling from it, and the old 64 KiB held every
/// download to 64 KiB per round trip (about 10 Mbit/s at 50 ms). The sender on
/// the far side is normally a kernel TCP with real congestion control, so a
/// wide window is safe here: 2 MiB carries about 330 Mbit/s at 50 ms. Pages
/// are touched only as data flows, so an idle socket stays cheap.
/// `OVERLAY_NETSTACK_TCP_RX_BUF` overrides it ([`TCP_BUF_MIN`]..=[`TCP_BUF_MAX`]).
const TCP_RX_BUF: usize = 2 * 1024 * 1024;
/// Per-socket smoltcp SEND buffer: the most this stack can have in flight.
/// The congestion window ([`tcp_cc`], the vendored smoltcp's NewReno-lite, whose
/// cwnd really bounds bytes in flight) is what paces a sender below it. Upstream
/// smoltcp's never did, and its go-back-N recovery resent everything past the
/// bottleneck queue: a 1 MiB send window put 3.2x the delivered bytes on the
/// wire at 50 ms behind a 256 KiB queue, so this was held at 128 KiB. With the
/// controller, 512 KiB (`netstack_tcp_buffer_matrix`, 10/50/100 ms x 64 KiB/
/// 256 KiB/1 MiB queues) beats that old default in every cell, at most 1.18x
/// wire per delivered byte even behind a 64 KiB queue; it reaches 79 Mbit/s at
/// 50 ms (was 20) and loses only to 256 KiB on a long, shallow path (100 ms /
/// 64 KiB queue: 7.6 vs 20 Mbit/s, still above the old 4). With SACK recovery
/// and pacing (both on by default) a bigger window no longer costs a resend
/// of it: paced+SACK at 1–4 MiB is never below 512 KiB in that matrix, and on
/// the real HK↔Tokyo path (43 ms) 512 KiB is the cap (~89 Mbit/s) where 4 MiB
/// carried 179–268. Hence 2 MiB. `OVERLAY_NETSTACK_TCP_TX_BUF` overrides it.
const TCP_TX_BUF: usize = 2 * 1024 * 1024;
const TCP_BUF_MIN: usize = 16 * 1024;
const TCP_BUF_MAX: usize = 16 * 1024 * 1024;
/// Max bytes moved between a smoltcp socket buffer and an app channel in one
/// chunk — bounds per-copy allocation and keeps chunks SCTP-friendly.
const CHUNK: usize = 16 * 1024;
/// Depth of each app⇄stack byte channel (in chunks). Backpressure kicks in
/// past this; the smoltcp window then closes and the peer slows.
const CHAN_CAP: usize = 32;
/// First ephemeral local port handed to outbound connects (IANA dynamic range).
const EPHEMERAL_BASE: u16 = 49152;
/// Backstop cap on the poll-loop sleep. smoltcp's own `poll_delay` drives
/// timers precisely; this only guarantees liveness if a wake is ever missed.
const SLEEP_BACKSTOP: Duration = Duration::from_millis(50);
/// Default connect timeout — smoltcp will retransmit SYNs for far longer, but
/// an app expects a bounded failure when the peer is unreachable.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Per-UDP-socket payload ring (each direction). A UDP association funnels every
/// datagram the app addresses through one socket, so give it a healthy buffer;
/// datagrams past it are dropped at the IP layer (UDP is lossy).
const UDP_BUF: usize = 64 * 1024;
/// Per-UDP-socket datagram-metadata slots (each direction).
const UDP_META: usize = 64;
/// Depth of each app⇄stack UDP datagram channel. Backpressures (not drops) past
/// this — a full channel just stalls delivery until the app drains it.
const UDP_CHAN_CAP: usize = 256;
/// ICMP socket buffers — `ping` is low-volume, so a few packets suffice.
const ICMP_BUF: usize = 4 * 1024;
const ICMP_META: usize = 8;
/// Payload carried in each echo request (the peer echoes it back verbatim).
const PING_PAYLOAD: &[u8] = b"roomler-netstack-ping";

use super::router::OVERLAY_V6_ONLINK_PREFIX;
/// Overlay-v6 derivation lives in [`super::router`] (compiled under plain
/// `overlay`, where the crypto-router unmaps derived-v6 destinations); this
/// re-export keeps `netstack::derive_overlay_v6` working for existing callers.
pub use super::router::derive_overlay_v6;

// ===========================================================================
// Device — a smoltcp `phy::Device` backed by two packet queues.
// ===========================================================================

/// smoltcp's link layer, wired to the overlay instead of a NIC. Owned solely by
/// the poll loop, so it needs no interior locking: inbound packets (from the
/// mesh) are pushed onto `rx` before each poll; outbound packets smoltcp emits
/// are handed to `out_tx` (drained by [`NetstackTun::read_packet`]).
struct NetstackDevice {
    rx: VecDeque<Vec<u8>>,
    out_tx: mpsc::UnboundedSender<Vec<u8>>,
    mtu: usize,
}

/// Owns one received packet; smoltcp borrows it immutably to parse.
struct NsRxToken(Vec<u8>);
/// Carries a clone of the outbound sender so smoltcp can emit a packet (a data
/// segment from `transmit`, or a reply like a RST from `receive`).
struct NsTxToken(mpsc::UnboundedSender<Vec<u8>>);

impl RxToken for NsRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for NsTxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        // Best-effort: a closed receiver means the bridge/overlay is gone; the
        // packet is dropped exactly like a NIC dropping toward a down link.
        let _ = self.0.send(buf);
        r
    }
}

impl Device for NetstackDevice {
    type RxToken<'a> = NsRxToken;
    type TxToken<'a> = NsTxToken;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((NsRxToken(pkt), NsTxToken(self.out_tx.clone())))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(NsTxToken(self.out_tx.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

// ===========================================================================
// TUN seam — the `TunIo` the WG bridge pumps.
// ===========================================================================

/// The netstack presented as a [`TunIo`]. `read_packet` yields packets the
/// stack wants on the wire (overlay-bound); `write_packet` injects packets that
/// arrived from the mesh and nudges the poll loop to process them.
pub struct NetstackTun {
    out_rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    in_tx: mpsc::UnboundedSender<Vec<u8>>,
    wake: Arc<Notify>,
}

#[async_trait]
impl TunIo for NetstackTun {
    async fn read_packet(&self) -> io::Result<Vec<u8>> {
        self.out_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::other("netstack outbound channel closed"))
    }

    async fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
        self.in_tx
            .send(packet.to_vec())
            .map_err(|_| io::Error::other("netstack inbound channel closed"))?;
        self.wake.notify_one();
        Ok(())
    }
}

// ===========================================================================
// Control plane — app requests to the poll loop.
// ===========================================================================

enum Control {
    Connect {
        dst: SocketAddr,
        resp: oneshot::Sender<io::Result<NsTcpStream>>,
    },
    Listen {
        port: u16,
        accepted: mpsc::Sender<NsTcpStream>,
    },
    UdpBind {
        resp: oneshot::Sender<io::Result<NsUdpSocket>>,
    },
    Ping {
        dst: IpAddr,
        /// Fires with the measured round-trip time when the echo reply lands.
        resp: oneshot::Sender<Duration>,
    },
}

/// App-facing handle to a running netstack. Cheap to clone; each clone can open
/// connections concurrently (all serialised through the one poll loop).
#[derive(Clone)]
pub struct NetstackHandle {
    ctl: mpsc::Sender<Control>,
}

impl NetstackHandle {
    /// Open a TCP connection to an overlay address. Resolves once the smoltcp
    /// handshake completes (or errors / times out). This is the SOCKS-CONNECT
    /// backend: the returned [`NsTcpStream`] is [`AsyncRead`]+[`AsyncWrite`].
    pub async fn connect(&self, dst: SocketAddr) -> io::Result<NsTcpStream> {
        let (resp, rx) = oneshot::channel();
        self.ctl
            .send(Control::Connect { dst, resp })
            .await
            .map_err(|_| io::Error::other("netstack poll loop gone"))?;
        match tokio::time::timeout(CONNECT_TIMEOUT, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(io::Error::other("netstack dropped the connect request")),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("netstack connect to {dst} timed out"),
            )),
        }
    }

    /// Listen on an overlay TCP port and accept connections. Primarily exercises
    /// the inbound path in tests; a real deployment mostly uses [`connect`].
    ///
    /// [`connect`]: NetstackHandle::connect
    pub async fn listen(&self, port: u16) -> io::Result<NsListener> {
        let (accepted, rx) = mpsc::channel(CHAN_CAP);
        self.ctl
            .send(Control::Listen { port, accepted })
            .await
            .map_err(|_| io::Error::other("netstack poll loop gone"))?;
        Ok(NsListener { rx })
    }

    /// Bind a UDP socket on an ephemeral overlay port. The returned
    /// [`NsUdpSocket`] can `send_to` any overlay address and `recv_from`
    /// whoever replies — the datagram backend for a SOCKS5 UDP ASSOCIATE.
    pub async fn udp_bind(&self) -> io::Result<NsUdpSocket> {
        let (resp, rx) = oneshot::channel();
        self.ctl
            .send(Control::UdpBind { resp })
            .await
            .map_err(|_| io::Error::other("netstack poll loop gone"))?;
        rx.await
            .map_err(|_| io::Error::other("netstack dropped the udp_bind request"))?
    }

    /// Send an ICMP echo request to an overlay address and resolve with the
    /// round-trip time once the reply lands. `Err(TimedOut)` if no reply arrives
    /// within `timeout`. The OS-free reachability probe for a netstack host,
    /// which can't use the OS `ping` (there's no OS route to the overlay).
    pub async fn ping(&self, dst: IpAddr, timeout: Duration) -> io::Result<Duration> {
        let (resp, rx) = oneshot::channel();
        self.ctl
            .send(Control::Ping { dst, resp })
            .await
            .map_err(|_| io::Error::other("netstack poll loop gone"))?;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(rtt)) => Ok(rtt),
            // Sender dropped ⇒ the request couldn't be emitted (unaddressable).
            Ok(Err(_)) => Err(io::Error::new(
                io::ErrorKind::HostUnreachable,
                format!("netstack could not send ping to {dst}"),
            )),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("ping to {dst} timed out"),
            )),
        }
    }
}

/// Yields inbound connections to a listened port, in arrival order.
pub struct NsListener {
    rx: mpsc::Receiver<NsTcpStream>,
}

impl NsListener {
    /// Next accepted connection, or `None` once the netstack shuts down.
    pub async fn accept(&mut self) -> Option<NsTcpStream> {
        self.rx.recv().await
    }
}

// ===========================================================================
// UDP socket — the datagram backend for SOCKS5 UDP ASSOCIATE.
// ===========================================================================

/// The send half of an [`NsUdpSocket`], cheaply cloneable so a relay loop can
/// hold it to `send_to` while `recv_from` borrows the socket in the same
/// `select!`.
#[derive(Clone)]
pub struct NsUdpSender {
    to_stack: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    wake: Arc<Notify>,
}

impl NsUdpSender {
    /// Queue `data` for delivery to `dst` over the overlay. Applies
    /// backpressure once the channel to the stack is full (rather than
    /// silently dropping), then nudges the poll loop to flush it.
    pub async fn send_to(&self, data: &[u8], dst: SocketAddr) -> io::Result<()> {
        self.to_stack
            .send((dst, data.to_vec()))
            .await
            .map_err(|_| io::Error::other("netstack udp socket closed"))?;
        self.wake.notify_one();
        Ok(())
    }
}

/// A UDP socket inside the netstack. Datagrams shuttle to/from the poll loop
/// over bounded channels: the stack sends them to arbitrary overlay peers and
/// delivers replies back with their source address. One socket backs one SOCKS
/// UDP association (it is connectionless — every datagram carries its own dst).
pub struct NsUdpSocket {
    tx: NsUdpSender,
    from_stack: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    local_port: u16,
}

impl NsUdpSocket {
    /// A cloneable send handle (see [`NsUdpSender`]).
    pub fn sender(&self) -> NsUdpSender {
        self.tx.clone()
    }

    /// Send a datagram to `dst` (convenience for `self.sender().send_to`).
    pub async fn send_to(&self, data: &[u8], dst: SocketAddr) -> io::Result<()> {
        self.tx.send_to(data, dst).await
    }

    /// The next datagram delivered from the overlay, with its source address.
    /// `Err` once the netstack shuts down.
    pub async fn recv_from(&mut self) -> io::Result<(Vec<u8>, SocketAddr)> {
        self.from_stack
            .recv()
            .await
            .map(|(src, data)| (data, src))
            .ok_or_else(|| io::Error::other("netstack udp socket closed"))
    }

    /// The ephemeral overlay port this socket is bound to.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }
}

// ===========================================================================
// Stream — the AsyncRead/AsyncWrite the app drives.
// ===========================================================================

/// One established TCP connection inside the netstack, as an
/// [`AsyncRead`]+[`AsyncWrite`] handle. Bytes shuttle to/from the poll loop over
/// bounded channels: reads pull chunks the stack delivered; writes push chunks
/// the stack will segment onto the wire. Dropping the stream aborts the socket;
/// [`poll_shutdown`](AsyncWrite::poll_shutdown) half-closes it (FIN).
pub struct NsTcpStream {
    /// Stack → app. `None`/closed ⇒ EOF (peer FIN or socket gone).
    from_stack: mpsc::Receiver<Vec<u8>>,
    /// Leftover of a delivered chunk not yet fully copied into a read buffer.
    read_rem: Vec<u8>,
    read_off: usize,
    /// App → stack. `None` after shutdown (its drop tells the stack to FIN).
    to_stack: Option<mpsc::Sender<Vec<u8>>>,
    /// Woken by the stack when `to_stack` drains, so a backpressured writer
    /// re-polls.
    write_waker: Arc<AtomicWaker>,
    /// Nudge the poll loop after an app read/write so it refills/flushes.
    wake: Arc<Notify>,
    peer: SocketAddr,
}

impl NsTcpStream {
    /// The overlay address this stream is connected to (or accepted from).
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
}

impl AsyncRead for NsTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Drain any leftover from a previous chunk first.
        if this.read_off < this.read_rem.len() {
            let n = (this.read_rem.len() - this.read_off).min(buf.remaining());
            buf.put_slice(&this.read_rem[this.read_off..this.read_off + n]);
            this.read_off += n;
            this.wake.notify_one();
            return Poll::Ready(Ok(()));
        }

        match this.from_stack.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                this.read_rem = chunk;
                this.read_off = n;
                this.wake.notify_one();
                Poll::Ready(Ok(()))
            }
            // Channel closed ⇒ clean EOF (0 bytes filled).
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for NsTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let Some(tx) = this.to_stack.as_ref() else {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        };
        let n = buf.len().min(CHUNK);
        match tx.try_send(buf[..n].to_vec()) {
            Ok(()) => {
                this.wake.notify_one();
                Poll::Ready(Ok(n))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Register for a wake when the stack drains a slot, then retry.
                this.write_waker.register(cx.waker());
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        // Bytes are queued to the stack; the wire flush is the stack's job.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Dropping the sender signals the stack to FIN once its queue drains.
        this.to_stack = None;
        this.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

// ===========================================================================
// Poll loop — the single owner of smoltcp state.
// ===========================================================================

/// Stack-side bookkeeping for one established connection (keyed by its
/// [`SocketHandle`] in [`PollLoop::conns`]).
struct Conn {
    /// Stack → app. `None` after we've signalled EOF (dropped to close it).
    to_app: Option<mpsc::Sender<Vec<u8>>>,
    /// App → stack.
    from_app: mpsc::Receiver<Vec<u8>>,
    /// A chunk pulled from `from_app` but not yet fully written into smoltcp.
    pending: Option<Vec<u8>>,
    pending_off: usize,
    write_waker: Arc<AtomicWaker>,
    app_write_closed: bool,
    fin_sent: bool,
}

/// A connect awaiting its handshake; fires `resp` on Established / failure.
/// Keyed by its [`SocketHandle`] in [`PollLoop::pending_connect`].
struct PendingConnect {
    resp: Option<oneshot::Sender<io::Result<NsTcpStream>>>,
    dst: SocketAddr,
}

/// A listening socket; each accepted connection is sent on `accepted`, then a
/// fresh listening socket is armed for the same port (single-backlog accept).
/// Keyed by its [`SocketHandle`] in [`PollLoop::pending_listen`].
struct PendingListen {
    port: u16,
    accepted: mpsc::Sender<NsTcpStream>,
}

/// Stack-side bookkeeping for one UDP socket (keyed by its [`SocketHandle`] in
/// [`PollLoop::udp_conns`]).
struct UdpConn {
    /// Stack → app: `(source addr, datagram)`.
    to_app: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    /// App → stack: `(destination addr, datagram)`.
    from_app: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    /// A datagram pulled from `from_app` but not yet accepted by smoltcp's tx
    /// buffer (transient backpressure); retried next pass.
    pending: Option<(SocketAddr, Vec<u8>)>,
    app_send_closed: bool,
}

struct PollLoop {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: NetstackDevice,
    in_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    ctl_rx: mpsc::Receiver<Control>,
    wake: Arc<Notify>,
    conns: HashMap<SocketHandle, Conn>,
    pending_connect: HashMap<SocketHandle, PendingConnect>,
    pending_listen: HashMap<SocketHandle, PendingListen>,
    udp_conns: HashMap<SocketHandle, UdpConn>,
    /// The one ICMP socket (bound to `ping_ident`) that all pings ride.
    icmp: SocketHandle,
    /// ICMP echo identifier for our outgoing pings — a per-instance random value
    /// so a peer's own ping socket never intercepts our request (and vice-versa;
    /// its iface auto-answers instead).
    ping_ident: u16,
    /// In-flight pings: echo `seq_no` → (send time, waiter). Resolved with the
    /// RTT when the matching echo reply arrives.
    pending_pings: HashMap<u16, (Instant, oneshot::Sender<Duration>)>,
    next_ping_seq: u16,
    next_port: u16,
    base: Instant,
    /// This iface's derived overlay v6 (`fd72:6f6f:6d6c::<self-v4>`), the source
    /// address for the ICMPv6 echo pseudo-header checksum.
    self_v6: Ipv6Addr,
}

/// `name`'s byte count within the TCP buffer bounds; an unparseable or
/// out-of-range value keeps `default`.
/// The netstack TCP congestion controller: CUBIC (RFC 9438, rewritten in the
/// vendored smoltcp), unless `OVERLAY_NETSTACK_TCP_CC` says `reno` (its
/// NewReno-lite) or `none` (the kill switch: the send buffer alone bounds bytes
/// in flight). Paced with SACK, CUBIC beat NewReno-lite in 9 matrix cells and
/// lost none (`netstack_tcp_buffer_matrix`): behind a 64 KiB queue 82 → 96
/// Mbit/s at 10 ms, 62 → 86 at 50 ms, 46 → 79 at 100 ms; behind the 40 Mbit/s
/// policer 27.6 → 30.0.
fn tcp_cc() -> tcp::CongestionControl {
    match crate::env::node_env("OVERLAY_NETSTACK_TCP_CC")
        .as_deref()
        .map(str::trim)
    {
        Some(v) if v.eq_ignore_ascii_case("none") => tcp::CongestionControl::None,
        Some(v) if v.eq_ignore_ascii_case("reno") => tcp::CongestionControl::Reno,
        _ => tcp::CongestionControl::Cubic,
    }
}

/// The netstack TCP sender's pacing (the vendored smoltcp's
/// `set_pacing_enabled`): data leaves at gain × cwnd / srtt instead of a whole
/// window at once. ON unless `OVERLAY_NETSTACK_TCP_PACING=0` (the kill switch).
/// Alone (with go-back-N) it did not help in the field: a resend of the whole
/// window still collapsed at a policer. With SACK recovery (`tcp_sack`) it is
/// the pair that rides one: in simulation 2.6 → 27.7 Mbit/s behind a 40 Mbit/s
/// policer with a 16 KiB bucket (`pacing_and_sack_ride_a_policer`), and on the
/// real HK↔Tokyo path (2026-10-25, 4 MiB buffers) 179–181 up / 205–268 down
/// against 116–130 / 82–110 for SACK alone. Its cost is ~8% on a 10 ms path
/// behind a 64 KiB queue.
fn tcp_pacing() -> bool {
    crate::env::flag("OVERLAY_NETSTACK_TCP_PACING", true)
}

/// The netstack TCP SACK loss recovery (the vendored smoltcp's
/// `set_sack_recovery_enabled`): a loss resends only the holes the peer's SACK
/// blocks reveal instead of everything after it (go-back-N), and the receiver
/// reports three blocks instead of one. ON unless `OVERLAY_NETSTACK_TCP_SACK=0`
/// (the kill switch): in simulation it matches or beats go-back-N in every
/// case measured (see `sack_recovery_resends_holes_not_the_window`). It is
/// inert against a peer that does not negotiate SACK.
fn tcp_sack() -> bool {
    crate::env::flag("OVERLAY_NETSTACK_TCP_SACK", true)
}

fn tcp_buf(name: &str, default: usize) -> usize {
    crate::env::node_env(name)
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| (TCP_BUF_MIN..=TCP_BUF_MAX).contains(n))
        .unwrap_or(default)
}

impl PollLoop {
    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.base.elapsed().as_micros() as i64)
    }

    fn ephemeral_port(&mut self) -> u16 {
        let p = self.next_port;
        self.next_port = self.next_port.checked_add(1).unwrap_or(EPHEMERAL_BASE);
        p
    }

    fn new_tcp_socket() -> tcp::Socket<'static> {
        Self::new_tcp_socket_with(
            tcp_buf("OVERLAY_NETSTACK_TCP_RX_BUF", TCP_RX_BUF),
            tcp_buf("OVERLAY_NETSTACK_TCP_TX_BUF", TCP_TX_BUF),
            tcp_cc(),
            tcp_pacing(),
            tcp_sack(),
        )
    }

    fn new_tcp_socket_with(
        rx: usize,
        tx: usize,
        cc: tcp::CongestionControl,
        pacing: bool,
        sack: bool,
    ) -> tcp::Socket<'static> {
        // A buffer's pages are touched only as data flows through it, so an
        // idle socket stays cheap whatever the window.
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; rx]),
            tcp::SocketBuffer::new(vec![0u8; tx]),
        );
        // Small SSH/SOCKS writes must keep reaching a recovered path while
        // older data is in flight, allowing normal ACK-driven TCP recovery.
        sock.set_nagle_enabled(false);
        sock.set_congestion_control(cc);
        sock.set_pacing_enabled(pacing);
        sock.set_sack_recovery_enabled(sack);
        sock
    }

    fn do_connect(&mut self, dst: SocketAddr, resp: oneshot::Sender<io::Result<NsTcpStream>>) {
        let mut sock = Self::new_tcp_socket();
        let local = IpListenEndpoint {
            addr: None,
            port: self.ephemeral_port(),
        };
        let remote = (IpAddress::from(dst.ip()), dst.port());
        let handle = self.sockets.add(sock_taken(&mut sock));
        let cx = self.iface.context();
        match self
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(cx, remote, local)
        {
            Ok(()) => {
                self.pending_connect.insert(
                    handle,
                    PendingConnect {
                        resp: Some(resp),
                        dst,
                    },
                );
            }
            Err(e) => {
                self.sockets.remove(handle);
                let _ = resp.send(Err(io::Error::other(format!("connect: {e}"))));
            }
        }
    }

    fn do_listen(&mut self, port: u16, accepted: mpsc::Sender<NsTcpStream>) {
        self.arm_listener(port, accepted);
    }

    fn arm_listener(&mut self, port: u16, accepted: mpsc::Sender<NsTcpStream>) {
        let mut sock = Self::new_tcp_socket();
        if let Err(e) = sock.listen(port) {
            debug!(%port, error = %e, "netstack: listen failed");
            return;
        }
        let handle = self.sockets.add(sock);
        self.pending_listen
            .insert(handle, PendingListen { port, accepted });
    }

    fn do_udp_bind(&mut self, resp: oneshot::Sender<io::Result<NsUdpSocket>>) {
        let mut sock = udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_META],
                vec![0u8; UDP_BUF],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_META],
                vec![0u8; UDP_BUF],
            ),
        );
        // Bind to a non-zero ephemeral port (smoltcp requires a bound local
        // port to send) on any of our addresses.
        let port = self.ephemeral_port();
        if let Err(e) = sock.bind(port) {
            let _ = resp.send(Err(io::Error::other(format!("udp bind: {e}"))));
            return;
        }
        let handle = self.sockets.add(sock);
        let (to_app, from_stack) = mpsc::channel(UDP_CHAN_CAP);
        let (to_stack, from_app) = mpsc::channel(UDP_CHAN_CAP);
        self.udp_conns.insert(
            handle,
            UdpConn {
                to_app,
                from_app,
                pending: None,
                app_send_closed: false,
            },
        );
        let socket = NsUdpSocket {
            tx: NsUdpSender {
                to_stack,
                wake: self.wake.clone(),
            },
            from_stack,
            local_port: port,
        };
        let _ = resp.send(Ok(socket));
    }

    fn do_ping(&mut self, dst: IpAddr, resp: oneshot::Sender<Duration>) {
        let seq = self.next_ping_seq;
        self.next_ping_seq = self.next_ping_seq.wrapping_add(1);
        let Some(buf) = self.emit_echo_request(dst, seq) else {
            // Family not yet wired (v6 lands in the next commit) ⇒ drop `resp`
            // so `ping()` fails fast instead of hanging to the timeout.
            return;
        };
        let sock = self.sockets.get_mut::<icmp::Socket>(self.icmp);
        match sock.send_slice(&buf, IpAddress::from(dst)) {
            // Record the send time; `service_icmp` fires `resp` with the RTT when
            // the matching reply arrives.
            Ok(()) => {
                self.pending_pings.insert(seq, (Instant::now(), resp));
            }
            // Unaddressable / buffer full ⇒ drop `resp`; `ping()` errors at once.
            Err(e) => debug!(%dst, error = %e, "netstack: ping send failed"),
        }
    }

    /// Serialise an ICMP echo request (`seq`, our `ping_ident`, [`PING_PAYLOAD`])
    /// for `dst`'s address family into a fresh buffer. `None` if the family is
    /// not wired yet — v6 arrives with the dual-address iface in a follow-up.
    fn emit_echo_request(&self, dst: IpAddr, seq: u16) -> Option<Vec<u8>> {
        match dst {
            IpAddr::V4(_) => {
                let repr = Icmpv4Repr::EchoRequest {
                    ident: self.ping_ident,
                    seq_no: seq,
                    data: PING_PAYLOAD,
                };
                let mut buf = vec![0u8; repr.buffer_len()];
                repr.emit(
                    &mut Icmpv4Packet::new_unchecked(&mut buf),
                    &ChecksumCapabilities::default(),
                );
                Some(buf)
            }
            IpAddr::V6(dst6) => {
                let repr = Icmpv6Repr::EchoRequest {
                    ident: self.ping_ident,
                    seq_no: seq,
                    data: PING_PAYLOAD,
                };
                let mut buf = vec![0u8; repr.buffer_len()];
                // ICMPv6's checksum covers a pseudo-header (src + dst), unlike
                // v4. Emit with our derived v6 as source; the iface recomputes
                // the checksum on dispatch with the source it selects — the same
                // single v6 — so the two always agree.
                repr.emit(
                    &self.self_v6,
                    &dst6,
                    &mut Icmpv6Packet::new_unchecked(&mut buf),
                    &ChecksumCapabilities::default(),
                );
                Some(buf)
            }
        }
    }

    /// Build the paired stack-side [`Conn`] + app-side [`NsTcpStream`] for a
    /// freshly established socket.
    fn make_pair(&self, peer: SocketAddr) -> (Conn, NsTcpStream) {
        let (to_app, from_stack) = mpsc::channel(CHAN_CAP);
        let (to_stack, from_app) = mpsc::channel(CHAN_CAP);
        let write_waker = Arc::new(AtomicWaker::new());
        let conn = Conn {
            to_app: Some(to_app),
            from_app,
            pending: None,
            pending_off: 0,
            write_waker: write_waker.clone(),
            app_write_closed: false,
            fin_sent: false,
        };
        let stream = NsTcpStream {
            from_stack,
            read_rem: Vec::new(),
            read_off: 0,
            to_stack: Some(to_stack),
            write_waker,
            wake: self.wake.clone(),
            peer,
        };
        (conn, stream)
    }

    /// Promote pending connects/listens whose sockets have established, and fail
    /// connects whose sockets died during the handshake.
    fn promote_pending(&mut self) {
        // Connects.
        let mut established = Vec::new();
        let mut failed = Vec::new();
        for (h, pc) in self.pending_connect.iter() {
            let s = self.sockets.get::<tcp::Socket>(*h);
            match s.state() {
                tcp::State::Established => established.push(*h),
                tcp::State::Closed => failed.push((*h, pc.dst)),
                _ => {}
            }
        }
        for h in established {
            let mut pc = self.pending_connect.remove(&h).unwrap();
            let (conn, stream) = self.make_pair(pc.dst);
            self.conns.insert(h, conn);
            if let Some(resp) = pc.resp.take() {
                let _ = resp.send(Ok(stream));
            }
            trace!(peer = %pc.dst, "netstack: connect established");
        }
        for (h, dst) in failed {
            let mut pc = self.pending_connect.remove(&h).unwrap();
            self.sockets.remove(h);
            if let Some(resp) = pc.resp.take() {
                let _ = resp.send(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("netstack connect to {dst} failed"),
                )));
            }
        }

        // Listens.
        let ready: Vec<SocketHandle> = self
            .pending_listen
            .iter()
            .filter(|(h, _)| {
                self.sockets.get::<tcp::Socket>(**h).state() == tcp::State::Established
            })
            .map(|(h, _)| *h)
            .collect();
        for h in ready {
            let pl = self.pending_listen.remove(&h).unwrap();
            let peer = self
                .sockets
                .get::<tcp::Socket>(h)
                .remote_endpoint()
                .and_then(sockaddr_of)
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), pl.port));
            let (conn, stream) = self.make_pair(peer);
            self.conns.insert(h, conn);
            // Re-arm a fresh listener for the next connection before delivering.
            self.arm_listener(pl.port, pl.accepted.clone());
            if pl.accepted.try_send(stream).is_err() {
                debug!(
                    port = pl.port,
                    "netstack: accept queue full/closed; dropping conn"
                );
            }
        }
    }

    /// Move bytes between smoltcp sockets and the app channels for every live
    /// connection. Returns `true` if it made progress (⇒ poll again).
    fn service_conns(&mut self) -> bool {
        let mut progressed = false;
        let mut dead = Vec::new();

        let handles: Vec<SocketHandle> = self.conns.keys().copied().collect();
        for h in handles {
            let sock = self.sockets.get_mut::<tcp::Socket>(h);
            let conn = self.conns.get_mut(&h).unwrap();

            // App dropped the whole stream (both halves gone) ⇒ abort.
            let app_gone = conn.to_app.as_ref().is_none_or(mpsc::Sender::is_closed)
                && conn.from_app.is_closed()
                && conn.pending.is_none();
            if app_gone && sock.is_open() {
                sock.abort();
            }

            // Stack → app.
            while sock.can_recv() {
                let Some(tx) = conn.to_app.as_ref() else {
                    break;
                };
                let Ok(permit) = tx.try_reserve() else { break }; // app slow ⇒ window closes
                let chunk = sock
                    .recv(|data| {
                        let n = data.len().min(CHUNK);
                        (n, data[..n].to_vec())
                    })
                    .unwrap_or_default();
                if chunk.is_empty() {
                    break;
                }
                permit.send(chunk);
                progressed = true;
            }
            // Peer half-closed and the buffer is drained ⇒ signal EOF to the app.
            if conn.to_app.is_some() && !sock.may_recv() && !sock.can_recv() {
                conn.to_app = None; // dropping the sender = EOF for the reader
                progressed = true;
            }

            // App → stack.
            loop {
                if conn.pending.is_none() {
                    match conn.from_app.try_recv() {
                        Ok(chunk) => {
                            conn.pending = Some(chunk);
                            conn.pending_off = 0;
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            conn.app_write_closed = true;
                            break;
                        }
                    }
                }
                let Some(chunk) = conn.pending.as_ref() else {
                    break;
                };
                if !sock.can_send() {
                    break;
                }
                match sock.send_slice(&chunk[conn.pending_off..]) {
                    Ok(0) => break, // no room
                    Ok(sent) => {
                        conn.pending_off += sent;
                        progressed = true;
                        if conn.pending_off >= chunk.len() {
                            conn.pending = None;
                            conn.pending_off = 0;
                        }
                    }
                    Err(_) => {
                        conn.pending = None;
                        break;
                    }
                }
            }
            // A drained queue may unblock a backpressured writer.
            conn.write_waker.wake();

            // App finished writing and we've flushed everything ⇒ FIN.
            if conn.app_write_closed && conn.pending.is_none() && !conn.fin_sent && sock.may_send()
            {
                sock.close();
                conn.fin_sent = true;
                progressed = true;
            }

            // Fully closed both ways ⇒ reap.
            if matches!(sock.state(), tcp::State::Closed) && !sock.is_active() {
                dead.push(h);
            }
        }

        for h in dead {
            self.conns.remove(&h);
            self.sockets.remove(h);
            progressed = true;
        }
        progressed
    }

    /// Move datagrams between the UDP sockets and their app channels. Returns
    /// `true` if it made progress.
    fn service_udp(&mut self) -> bool {
        let mut progressed = false;
        let mut dead = Vec::new();
        let handles: Vec<SocketHandle> = self.udp_conns.keys().copied().collect();
        for h in handles {
            let sock = self.sockets.get_mut::<udp::Socket>(h);
            let conn = self.udp_conns.get_mut(&h).unwrap();

            // Stack → app: deliver each buffered datagram with its source. A
            // slow app (no channel capacity) leaves datagrams in smoltcp's rx
            // buffer, which back-pressures the IP layer rather than dropping.
            while sock.can_recv() {
                let Ok(permit) = conn.to_app.try_reserve() else {
                    break;
                };
                match sock.recv() {
                    Ok((data, meta)) => {
                        let datav = data.to_vec();
                        if let Some(src) = sockaddr_of(meta.endpoint) {
                            permit.send((src, datav));
                            progressed = true;
                        }
                    }
                    Err(_) => break,
                }
            }

            // App → stack: send queued datagrams to their targets.
            loop {
                if conn.pending.is_none() {
                    match conn.from_app.try_recv() {
                        Ok(d) => conn.pending = Some(d),
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            conn.app_send_closed = true;
                            break;
                        }
                    }
                }
                let Some((dst, payload)) = conn.pending.as_ref() else {
                    break;
                };
                if !sock.can_send() {
                    break;
                }
                let meta = IpEndpoint::from((IpAddress::from(dst.ip()), dst.port()));
                match sock.send_slice(payload, meta) {
                    Ok(()) => {
                        conn.pending = None;
                        progressed = true;
                    }
                    // Unaddressable / buffer full ⇒ drop this datagram (lossy).
                    Err(_) => {
                        conn.pending = None;
                        break;
                    }
                }
            }

            // App dropped both halves of the socket ⇒ reap.
            if conn.to_app.is_closed() && conn.app_send_closed {
                dead.push(h);
            }
        }
        for h in dead {
            self.udp_conns.remove(&h);
            self.sockets.remove(h);
            progressed = true;
        }
        progressed
    }

    /// Match inbound ICMP echo replies to in-flight pings and resolve each
    /// waiter with its round-trip time. Returns `true` if a ping resolved.
    /// (Inbound echo *requests* are auto-answered by the iface — feature
    /// `auto-icmp-echo-reply` — so a netstack host is pingable without a socket.)
    fn service_icmp(&mut self) -> bool {
        let mut matched: Vec<u16> = Vec::new();
        {
            let ident = self.ping_ident;
            let self_v6 = self.self_v6;
            let sock = self.sockets.get_mut::<icmp::Socket>(self.icmp);
            while sock.can_recv() {
                let Ok((data, src)) = sock.recv() else { break };
                // One ident-bound icmp socket receives both families; pick the
                // parser by the reply's source-address family.
                let seq = match src {
                    IpAddress::Ipv4(_) => echo_reply_seq(data, ident),
                    IpAddress::Ipv6(peer6) => echo_reply_seq6(data, peer6, self_v6, ident),
                };
                if let Some(seq) = seq {
                    matched.push(seq);
                }
            }
        }
        let mut progressed = false;
        for seq in matched {
            if let Some((sent, resp)) = self.pending_pings.remove(&seq) {
                let _ = resp.send(sent.elapsed());
                progressed = true;
            }
        }
        progressed
    }

    /// One settle pass: poll smoltcp, promote handshakes, shuttle bytes —
    /// repeated until it quiesces (bounded), so an inbound packet and the app
    /// I/O it unblocks flush in the same wake.
    fn run_stack(&mut self) {
        for _ in 0..8 {
            let now = self.now();
            let _ = self.iface.poll(now, &mut self.device, &mut self.sockets);
            self.promote_pending();
            let tcp = self.service_conns();
            let udp = self.service_udp();
            let icmp = self.service_icmp();
            if !tcp && !udp && !icmp && self.device.rx.is_empty() {
                break;
            }
        }
    }

    fn sleep_delay(&mut self) -> Duration {
        let now = self.now();
        self.iface
            .poll_delay(now, &self.sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(SLEEP_BACKSTOP)
            .min(SLEEP_BACKSTOP)
    }

    async fn run(mut self) {
        loop {
            self.run_stack();
            let delay = self.sleep_delay();
            tokio::select! {
                biased;
                ctl = self.ctl_rx.recv() => match ctl {
                    Some(Control::Connect { dst, resp }) => self.do_connect(dst, resp),
                    Some(Control::Listen { port, accepted }) => self.do_listen(port, accepted),
                    Some(Control::UdpBind { resp }) => self.do_udp_bind(resp),
                    Some(Control::Ping { dst, resp }) => self.do_ping(dst, resp),
                    None => break, // handle dropped ⇒ shut down
                },
                pkt = self.in_rx.recv() => {
                    // `None` ⇒ the TUN write half is gone; keep serving app-side.
                    if let Some(p) = pkt {
                        self.device.rx.push_back(p);
                    }
                }
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(delay) => {}
            }
        }
        debug!("netstack: poll loop exiting");
    }
}

/// Move a socket out by value (smoltcp `Socket::new` gives an owned socket; this
/// keeps [`PollLoop::do_connect`] readable where a temporary is needed).
fn sock_taken(s: &mut tcp::Socket<'static>) -> tcp::Socket<'static> {
    std::mem::replace(
        s,
        tcp::Socket::new(
            tcp::SocketBuffer::new(vec![]),
            tcp::SocketBuffer::new(vec![]),
        ),
    )
}

/// Parse an ICMPv4 packet; return the echo-reply `seq_no` iff it's an
/// `EchoReply` whose identifier matches `ident` (our ping socket's). `None` for
/// a malformed packet or any other ICMP message.
fn echo_reply_seq(data: &[u8], ident: u16) -> Option<u16> {
    let pkt = Icmpv4Packet::new_checked(data).ok()?;
    match Icmpv4Repr::parse(&pkt, &ChecksumCapabilities::default()).ok()? {
        Icmpv4Repr::EchoReply {
            ident: id, seq_no, ..
        } if id == ident => Some(seq_no),
        _ => None,
    }
}

/// Parse an ICMPv6 packet; return the echo-reply `seq_no` iff it's an
/// `EchoReply` whose identifier matches `ident`. `src`/`dst` are the reply's
/// addresses (smoltcp's parser wants them for the pseudo-header); the checksum
/// is not re-verified (`ignored()`) — the iface already validated it inbound and
/// we only need the ident + seq. `None` for a malformed / non-echo-reply packet.
fn echo_reply_seq6(data: &[u8], src: Ipv6Addr, dst: Ipv6Addr, ident: u16) -> Option<u16> {
    let pkt = Icmpv6Packet::new_checked(data).ok()?;
    match Icmpv6Repr::parse(&src, &dst, &pkt, &ChecksumCapabilities::ignored()).ok()? {
        Icmpv6Repr::EchoReply {
            ident: id, seq_no, ..
        } if id == ident => Some(seq_no),
        _ => None,
    }
}

/// smoltcp `IpEndpoint` → `std::net::SocketAddr`, either family. smoltcp 0.12+
/// carries `std::net` addresses directly, so this is a straight rewrap; the
/// `Option` mirrors the callers' existing `and_then`/`if let` shape (an
/// `IpEndpoint` addr is always a concrete v4/v6, so it is in practice `Some`).
fn sockaddr_of(ep: smoltcp::wire::IpEndpoint) -> Option<SocketAddr> {
    match ep.addr {
        IpAddress::Ipv4(v4) => Some(SocketAddr::from((v4, ep.port))),
        IpAddress::Ipv6(v6) => Some(SocketAddr::from((v6, ep.port))),
    }
}

// ===========================================================================
// Constructor.
// ===========================================================================

/// A running netstack: the [`TunIo`] the bridge pumps + the app-facing handle.
pub struct Netstack {
    /// Plug into [`run_bridge`](super::bridge::run_bridge) as the `tun`.
    pub tun: Arc<NetstackTun>,
    /// Open connections / listeners against the mesh.
    pub handle: NetstackHandle,
}

impl Netstack {
    /// Start a netstack that owns `self_ip` on a `prefix`-length overlay network
    /// (e.g. `/10` for `100.64.0.0/10`), with the given `mtu`. Spawns the poll
    /// loop on the current Tokio runtime. Assigning the network prefix makes
    /// every overlay peer on-link, so no route table is needed for peer-to-peer
    /// traffic (LAN-subnet routing via the netstack is a follow-up).
    ///
    /// Dual-stack: the iface also gets this node's *derived* overlay IPv6
    /// ([`derive_overlay_v6`]) on the ULA `/96`, so a v6 peer address routes and
    /// answers ICMPv6 with no server allocation — inert until a surface targets
    /// it (see `docs/overlay-communication.md`).
    pub fn start(self_ip: Ipv4Addr, prefix: u8, mtu: u16) -> Self {
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        let (ctl_tx, ctl_rx) = mpsc::channel(CHAN_CAP);
        let wake = Arc::new(Notify::new());

        let mut device = NetstackDevice {
            rx: VecDeque::new(),
            out_tx,
            mtu: mtu as usize,
        };

        let base = Instant::now();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut iface = Interface::new(
            config,
            &mut device,
            SmolInstant::from_micros(base.elapsed().as_micros() as i64),
        );
        // Dual-stack: the server-assigned v4 CIDR, plus this node's derived
        // overlay v6 on the ULA /96 so every peer's `fd72:6f6f:6d6c::<their-v4>`
        // is on-link (the v6 mirror of the v4 network prefix — no route table).
        let self_v6 = derive_overlay_v6(self_ip);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::from(self_ip), prefix));
            let _ = addrs.push(IpCidr::new(
                IpAddress::Ipv6(self_v6),
                OVERLAY_V6_ONLINK_PREFIX,
            ));
        });

        // The single ICMP socket every ping rides, bound to a per-instance
        // random identifier (so a peer's own ping socket never intercepts our
        // requests — its iface auto-answers them instead).
        let mut sockets = SocketSet::new(Vec::new());
        let mut icmp_sock = icmp::Socket::new(
            icmp::PacketBuffer::new(
                vec![icmp::PacketMetadata::EMPTY; ICMP_META],
                vec![0u8; ICMP_BUF],
            ),
            icmp::PacketBuffer::new(
                vec![icmp::PacketMetadata::EMPTY; ICMP_META],
                vec![0u8; ICMP_BUF],
            ),
        );
        let ping_ident: u16 = rand::random();
        let _ = icmp_sock.bind(icmp::Endpoint::Ident(ping_ident));
        let icmp = sockets.add(icmp_sock);

        let poll_loop = PollLoop {
            iface,
            sockets,
            device,
            in_rx,
            ctl_rx,
            wake: wake.clone(),
            conns: HashMap::new(),
            pending_connect: HashMap::new(),
            pending_listen: HashMap::new(),
            udp_conns: HashMap::new(),
            icmp,
            ping_ident,
            pending_pings: HashMap::new(),
            next_ping_seq: 0,
            next_port: EPHEMERAL_BASE,
            base,
            self_v6,
        };
        tokio::spawn(poll_loop.run());

        Self {
            tun: Arc::new(NetstackTun {
                out_rx: Mutex::new(out_rx),
                in_tx,
                wake,
            }),
            handle: NetstackHandle { ctl: ctl_tx },
        }
    }
}

#[cfg(test)]
mod tests {
    //! Two proofs of the userspace path:
    //! * `direct_pair_tcp_echo` — two netstacks cross-linked at L3 (no WG): the
    //!   smoltcp wrapper alone carries a TCP echo.
    //! * `bridge_tcp_echo_over_wireguard` — two netstacks bridged through a real
    //!   [`WgDevice`] pair (mirrors [`super::super::bridge`]'s loopback test):
    //!   the full `app → smoltcp → WG → carrier → WG → smoltcp → app` path
    //!   carries a TCP echo entirely in userspace, no OS device, no privilege.

    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Echo everything received back to the sender until EOF.
    async fn echo(stream: NsTcpStream) {
        let (mut r, mut w) = tokio::io::split(stream);
        let _ = tokio::io::copy(&mut r, &mut w).await;
        let _ = w.shutdown().await;
    }

    /// Drive an app request/echo round-trip against a connected stack.
    async fn round_trip(handle: &NetstackHandle, dst: SocketAddr, msg: &[u8]) {
        let mut s = handle.connect(dst).await.expect("connect");
        s.write_all(msg).await.expect("write");
        s.flush().await.expect("flush");
        let mut got = vec![0u8; msg.len()];
        s.read_exact(&mut got).await.expect("read echo");
        assert_eq!(got, msg, "echo must round-trip through the netstack");
    }


    #[test]
    fn small_stream_recovers_via_real_duplicate_acks_after_carrier_loss() {
        fn node(ip: Ipv4Addr) -> (NetstackDevice, Interface, SocketSet<'static>,
            mpsc::UnboundedReceiver<Vec<u8>>)
        {
            let (out_tx, out_rx) = mpsc::unbounded_channel();
            let mut dev = NetstackDevice { rx: VecDeque::new(), out_tx, mtu: 1280 };
            let mut cfg = Config::new(HardwareAddress::Ip);
            cfg.random_seed = 7;
            let mut iface = Interface::new(cfg, &mut dev, SmolInstant::from_millis(0));
            iface.update_ip_addrs(|a| {
                a.push(IpCidr::new(IpAddress::from(ip), 24)).unwrap();
            });
            (dev, iface, SocketSet::new(vec![]), out_rx)
        }
        let a_ip = Ipv4Addr::new(100, 64, 0, 1);
        let b_ip = Ipv4Addr::new(100, 64, 0, 2);
        let (mut ad, mut ai, mut sockets_a, mut a_out) = node(a_ip);
        let (mut bd, mut bi, mut sockets_b, mut b_out) = node(b_ip);
        // The exact production helper serves both connect() and listen().
        let mut server = PollLoop::new_tcp_socket();
        server.listen(2222).unwrap();
        let sh = sockets_b.add(server);
        let mut client = PollLoop::new_tcp_socket();
        client.connect(ai.context(), (IpAddress::from(b_ip), 2222), 49152).unwrap();
        let ch = sockets_a.add(client);
        let mut expected = Vec::new();
        let mut received = Vec::new();
        let mut first_after_recovery = None;
        let mut original_seq = None;
        let mut duplicate_acks = 0;
        // Virtual interface time only: this test runs without wall-clock sleeps.
        // Drop real IP packets at 5 s; the carrier returns at 13.5 s, between
        // the sender's exponentially backed-off 12 s and 20 s retransmissions.
        for ms in 0..30_000 {
            let now = SmolInstant::from_millis(ms);
            let lost = (5_000..13_500).contains(&ms);
            if (1_000..20_000).contains(&ms) && ms % 500 == 0 {
                let payload = format!("record_{:03}:abcdefghijklmnopqrstuvwxyz012345\n", ms / 500);
                sockets_b.get_mut::<tcp::Socket>(sh).send_slice(payload.as_bytes()).unwrap();
                expected.extend_from_slice(payload.as_bytes());
            }
            for _ in 0..8 {
                let _ = ai.poll(now, &mut ad, &mut sockets_a);
                while let Ok(pkt) = a_out.try_recv() {
                    if ms >= 13_500 {
                        let ip = smoltcp::wire::Ipv4Packet::new_checked(pkt.as_slice()).unwrap();
                        let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).unwrap();
                        if original_seq.is_some_and(|seq| tcp.ack_number() == seq) {
                            duplicate_acks += 1;
                        }
                    }
                    if !lost { bd.rx.push_back(pkt); }
                }
                let _ = bi.poll(now, &mut bd, &mut sockets_b);
                while let Ok(pkt) = b_out.try_recv() {
                    if original_seq.is_none() && ms >= 5_000 {
                        let ip = smoltcp::wire::Ipv4Packet::new_checked(pkt.as_slice()).unwrap();
                        let tcp = smoltcp::wire::TcpPacket::new_checked(ip.payload()).unwrap();
                        if !tcp.payload().is_empty() { original_seq = Some(tcp.seq_number()); }
                    }
                    if !lost { ad.rx.push_back(pkt); }
                }
            }
            if sockets_a.get::<tcp::Socket>(ch).can_recv() {
                sockets_a.get_mut::<tcp::Socket>(ch).recv(|b| {
                    received.extend_from_slice(b);
                    (b.len(), ())
                }).unwrap();
                if ms >= 13_500 && first_after_recovery.is_none() {
                    first_after_recovery = Some(ms);
                }
            }
        }
        assert_eq!(received, expected, "the same TCP socket must deliver every byte");
        assert!(duplicate_acks >= 3, "only real peer-generated duplicate ACKs accelerate recovery");
        assert!(first_after_recovery.is_some_and(|ms| ms <= 14_550),
            "small ongoing writes should recover shortly after the carrier, not wait for 20 s RTO: {first_after_recovery:?}");
    }

    /// One direction of a simulated carrier: serialization at `bytes_per_ms`
    /// behind a drop-tail queue of `queue_bytes`, then `delay_ms` in flight.
    /// `batch_ms > 0` releases arrivals only on that period (ACK compression:
    /// a relay, a WG batch or a poll loop handing a burst of ACKs over at once).
    struct SimLink {
        delay_ms: i64,
        bytes_per_ms: i64,
        queue_bytes: i64,
        busy_until_us: i64,
        flight: VecDeque<(i64, Vec<u8>)>,
        dropped: usize,
        batch_ms: i64,
        /// A token-bucket policer ahead of the queue: (bytes per ms, bucket
        /// bytes). Over-rate packets are dropped, not queued (a provider's
        /// UDP policer, as on the field's relay leg).
        police: Option<(i64, i64)>,
        tokens: i64,
        tokens_at_us: i64,
    }

    impl SimLink {
        fn new(delay_ms: i64, mbit_per_s: i64, queue_bytes: i64) -> Self {
            Self {
                delay_ms,
                bytes_per_ms: mbit_per_s * 1000 / 8,
                queue_bytes,
                busy_until_us: 0,
                flight: VecDeque::new(),
                dropped: 0,
                batch_ms: 0,
                police: None,
                tokens: 0,
                tokens_at_us: 0,
            }
        }
        fn send(&mut self, now_us: i64, pkt: Vec<u8>) {
            if let Some((rate, bucket)) = self.police {
                self.tokens =
                    (self.tokens + (now_us - self.tokens_at_us) * rate / 1000).min(bucket);
                self.tokens_at_us = now_us;
                if self.tokens < pkt.len() as i64 {
                    self.dropped += 1;
                    return;
                }
                self.tokens -= pkt.len() as i64;
            }
            let start = self.busy_until_us.max(now_us);
            if (start - now_us) * self.bytes_per_ms / 1000 + pkt.len() as i64 > self.queue_bytes {
                self.dropped += 1;
                return;
            }
            self.busy_until_us = start + pkt.len() as i64 * 1000 / self.bytes_per_ms;
            self.flight
                .push_back((self.busy_until_us + self.delay_ms * 1000, pkt));
        }
        fn deliver(&mut self, now_us: i64, into: &mut VecDeque<Vec<u8>>) {
            if self.batch_ms > 0 && (now_us / 1000) % self.batch_ms != 0 {
                return;
            }
            while self.flight.front().is_some_and(|(at, _)| *at <= now_us) {
                into.push_back(self.flight.pop_front().unwrap().1);
            }
        }
    }

    /// One bulk TCP stream between two production-built smoltcp sockets over
    /// a [`SimLink`] pair, in virtual time (deterministic, no wall clock):
    /// (goodput Mbit/s after `warm_ms`, data-link drops, bytes the sender put
    /// on the wire per byte delivered).
    fn sim_bulk(
        bufs: (usize, usize),
        cc: (tcp::CongestionControl, bool, bool),
        one_way_ms: i64,
        queue_bytes: i64,
        sim_ms: i64,
        warm_ms: i64,
    ) -> (f64, usize, f64) {
        sim_bulk_acks(bufs, cc, one_way_ms, queue_bytes, sim_ms, warm_ms, 0, None)
    }

    /// [`sim_bulk`] with the ACK direction released every `ack_batch_ms`, and
    /// the data direction optionally policed at (Mbit/s, bucket bytes).
    #[allow(clippy::too_many_arguments)]
    fn sim_bulk_acks(
        (rx, tx): (usize, usize),
        (cc, pacing, sack): (tcp::CongestionControl, bool, bool),
        one_way_ms: i64,
        queue_bytes: i64,
        sim_ms: i64,
        warm_ms: i64,
        ack_batch_ms: i64,
        police: Option<(i64, i64)>,
    ) -> (f64, usize, f64) {
        fn node(ip: Ipv4Addr) -> (NetstackDevice, Interface, SocketSet<'static>,
            mpsc::UnboundedReceiver<Vec<u8>>)
        {
            let (out_tx, out_rx) = mpsc::unbounded_channel();
            let mut dev = NetstackDevice { rx: VecDeque::new(), out_tx, mtu: 1280 };
            let mut cfg = Config::new(HardwareAddress::Ip);
            cfg.random_seed = 7;
            let mut iface = Interface::new(cfg, &mut dev, SmolInstant::from_millis(0));
            iface.update_ip_addrs(|a| {
                a.push(IpCidr::new(IpAddress::from(ip), 24)).unwrap();
            });
            (dev, iface, SocketSet::new(vec![]), out_rx)
        }
        let a_ip = Ipv4Addr::new(100, 64, 0, 1);
        let b_ip = Ipv4Addr::new(100, 64, 0, 2);
        let (mut ad, mut ai, mut sockets_a, mut a_out) = node(a_ip);
        let (mut bd, mut bi, mut sockets_b, mut b_out) = node(b_ip);
        let mut server = PollLoop::new_tcp_socket_with(rx, tx, cc, pacing, sack);
        server.listen(2222).unwrap();
        let sh = sockets_b.add(server);
        let mut client = PollLoop::new_tcp_socket_with(rx, tx, cc, pacing, sack);
        client.connect(ai.context(), (IpAddress::from(b_ip), 2222), 49152).unwrap();
        let ch = sockets_a.add(client);
        // A 100 Mbit/s bottleneck both ways.
        let mut a_to_b = SimLink::new(one_way_ms, 100, queue_bytes);
        let mut b_to_a = SimLink::new(one_way_ms, 100, queue_bytes);
        // a receives and acknowledges; b sends the bulk data.
        a_to_b.batch_ms = ack_batch_ms;
        if let Some((mbit, bucket)) = police {
            b_to_a.police = Some((mbit * 1000 / 8, bucket));
            b_to_a.tokens = bucket;
        }
        let chunk = vec![0x5au8; 64 * 1024];
        let (mut received, mut at_warm, mut wire) = (0usize, 0usize, 0usize);
        for ms in 0..sim_ms {
            let (now, now_us) = (SmolInstant::from_millis(ms), ms * 1000);
            let sender = sockets_b.get_mut::<tcp::Socket>(sh);
            while sender.can_send() {
                if sender.send_slice(&chunk).unwrap() == 0 {
                    break;
                }
            }
            a_to_b.deliver(now_us, &mut bd.rx);
            b_to_a.deliver(now_us, &mut ad.rx);
            for _ in 0..256 {
                let mut moved = false;
                let _ = ai.poll(now, &mut ad, &mut sockets_a);
                while let Ok(pkt) = a_out.try_recv() {
                    a_to_b.send(now_us, pkt);
                    moved = true;
                }
                let _ = bi.poll(now, &mut bd, &mut sockets_b);
                while let Ok(pkt) = b_out.try_recv() {
                    wire += pkt.len();
                    b_to_a.send(now_us, pkt);
                    moved = true;
                }
                if !moved && ad.rx.is_empty() && bd.rx.is_empty() {
                    break;
                }
            }
            let receiver = sockets_a.get_mut::<tcp::Socket>(ch);
            while receiver.can_recv() {
                received += receiver.recv(|b| (b.len(), b.len())).unwrap();
            }
            if ms == warm_ms {
                at_warm = received;
            }
        }
        (
            (received - at_warm) as f64 * 8.0 / ((sim_ms - warm_ms) as f64 / 1000.0) / 1e6,
            b_to_a.dropped,
            wire as f64 / received.max(1) as f64,
        )
    }

    /// MeshHarbor §6 item 5. On a 50 ms, 100 Mbit/s path behind a moderate
    /// 256 KiB queue, the old 64 KiB buffers are window-bound near 9 Mbit/s;
    /// the production defaults (buffers, congestion control, SACK recovery and
    /// pacing) must reach far past that with little resend waste.
    #[test]
    fn the_default_buffers_lift_a_50ms_path_with_little_waste() {
        use tcp::CongestionControl::None as NoCc;
        let (old, old_drops, _) = sim_bulk(
            (64 * 1024, 64 * 1024),
            (NoCc, false, false),
            25,
            256 * 1024,
            6_000,
            2_000,
        );
        let (new, drops, amp) = sim_bulk(
            (TCP_RX_BUF, TCP_TX_BUF),
            (tcp_cc(), true, true),
            25,
            256 * 1024,
            6_000,
            2_000,
        );
        eprintln!(
            "OBSERVED netstack 50ms/100Mbit/256KiB-queue: old {old:.1} Mbit/s ({old_drops} drops), default {new:.1} Mbit/s ({drops} drops, wire/delivered {amp:.2})"
        );
        assert!(old < 12.0, "the old window is the bound: {old:.1}");
        assert!(
            new > 5.0 * old,
            "the defaults lift it: {new:.1} vs {old:.1}"
        );
        assert!(amp < 1.1, "with little resend waste: {amp:.2}");
    }

    /// The 2 MiB defaults with paced SACK against the previous defaults (1 MiB
    /// receive, 512 KiB send, unpaced go-back-N) at 10/50/100 ms behind a
    /// 64 KiB and a 256 KiB queue: never worse, so the bigger window is only a
    /// gain. (Without pacing and SACK it is not: 50 ms / 256 KiB fell 79 → 50.)
    #[test]
    fn the_defaults_never_lose_to_the_previous_defaults() {
        use tcp::CongestionControl::Reno;
        for one_way in [5i64, 25, 50] {
            for queue in [64 * 1024i64, 256 * 1024] {
                let (old, _, _) = sim_bulk(
                    (1024 * 1024, 512 * 1024),
                    (Reno, false, false),
                    one_way,
                    queue,
                    6_000,
                    2_000,
                );
                let (new, _, amp) = sim_bulk(
                    (TCP_RX_BUF, TCP_TX_BUF),
                    (tcp_cc(), true, true),
                    one_way,
                    queue,
                    6_000,
                    2_000,
                );
                eprintln!(
                    "OBSERVED defaults {}ms behind a {} KiB queue: previous {old:.1} Mbit/s, now {new:.1} amp {amp:.2}",
                    one_way * 2,
                    queue / 1024
                );
                assert!(new >= 0.95 * old, "never worse: {new:.1} vs {old:.1}");
                assert!(amp < 1.12, "little waste: {amp:.2}");
            }
        }
    }

    /// The vendored smoltcp's cwnd bounds bytes in flight. A send window far
    /// past the path (1 MiB at 50 ms behind a 256 KiB queue) floods the queue
    /// with no controller and is resent go-back-N; Reno keeps the waste small.
    /// A shallow 64 KiB queue at the production default stays bounded too.
    #[test]
    fn reno_bounds_bytes_in_flight_where_none_floods_the_queue() {
        use tcp::CongestionControl::{None as NoCc, Reno};
        let (_, none_drops, none_amp) = sim_bulk(
            (TCP_RX_BUF, 1024 * 1024),
            (NoCc, false, false),
            25,
            256 * 1024,
            6_000,
            2_000,
        );
        let (reno, reno_drops, reno_amp) = sim_bulk(
            (TCP_RX_BUF, 1024 * 1024),
            (Reno, false, false),
            25,
            256 * 1024,
            6_000,
            2_000,
        );
        eprintln!(
            "OBSERVED 1MiB send window: none {none_drops} drops amp {none_amp:.2}; reno {reno:.1} Mbit/s {reno_drops} drops amp {reno_amp:.2}"
        );
        assert!(
            none_amp > 2.5,
            "without cwnd the window floods the queue: {none_amp:.2}"
        );
        assert!(reno_amp < 1.2, "reno resends little: {reno_amp:.2}");
        assert!(
            reno_drops * 10 < none_drops,
            "and drops a tenth as much: {reno_drops} vs {none_drops}"
        );
        for one_way in [5i64, 25] {
            let (mbps, _, amp) = sim_bulk(
                (TCP_RX_BUF, TCP_TX_BUF),
                (Reno, false, false),
                one_way,
                64 * 1024,
                6_000,
                2_000,
            );
            eprintln!(
                "OBSERVED default, {}ms behind a 64 KiB queue: {mbps:.1} Mbit/s amp {amp:.2}",
                one_way * 2
            );
            assert!(
                amp < 1.15,
                "a shallow queue costs little at the default: {amp:.2}"
            );
        }
    }

    /// Pacing: a window far past a shallow bottleneck queue (the field's
    /// policed relay leg, 2.5 Mbit/s unpaced) goes out at gain × cwnd / srtt.
    /// Measured here: with ACKs released every 5/10 ms, 24.0/20.7 Mbit/s
    /// unpaced vs 64.4/52.0 paced; on a smooth ACK clock 24.7 vs 22.0.
    #[test]
    fn pacing_lets_a_big_window_ride_a_shallow_queue() {
        use tcp::CongestionControl::Reno;
        let big = (4096 * 1024, 4096 * 1024);
        for batch in [0i64, 5, 10] {
            let (burst, burst_drops, burst_amp) = sim_bulk_acks(
                big,
                (Reno, false, false),
                25,
                64 * 1024,
                8_000,
                3_000,
                batch,
                None,
            );
            let (paced, paced_drops, paced_amp) = sim_bulk_acks(
                big,
                (Reno, true, false),
                25,
                64 * 1024,
                8_000,
                3_000,
                batch,
                None,
            );
            eprintln!(
                "OBSERVED 4MiB window, 50ms behind a 64 KiB queue, ACKs every {batch}ms: unpaced {burst:.1} Mbit/s {burst_drops} drops amp {burst_amp:.2}; paced {paced:.1} Mbit/s {paced_drops} drops amp {paced_amp:.2}"
            );
            if batch == 0 {
                // A perfectly smooth ACK clock already spaces the sender.
                assert!(paced >= 0.85 * burst, "pacing costs little: {paced:.1} vs {burst:.1}");
            } else {
                // Compressed ACKs release a window-sized burst; pacing spreads it.
                assert!(paced >= 1.8 * burst, "pacing rides it: {paced:.1} vs {burst:.1}");
            }
        }
    }

    /// SACK recovery: a window far past a shallow bottleneck queue overshoots
    /// it, and go-back-N then resends everything after the first drop. With
    /// SACK only the holes go again. Measured here (go-back-N → SACK, Mbit/s):
    /// 4 MiB unpaced 24.7 → 51.9, ACKs every 5 ms 24.0 → 33.4, paced 22.0 →
    /// 61.8; default buffers at 10 ms / 64 KiB 77.7 → 90.0, at 50 ms / 64 KiB
    /// 19.3 → 28.3; deep queues tie.
    #[test]
    fn sack_recovery_resends_holes_not_the_window() {
        use tcp::CongestionControl::Reno;
        let big = (4096 * 1024, 4096 * 1024);
        for (pacing, batch) in [(false, 0i64), (false, 5), (true, 0), (true, 5)] {
            let (gbn, gbn_drops, gbn_amp) = sim_bulk_acks(
                big,
                (Reno, pacing, false),
                25,
                64 * 1024,
                8_000,
                3_000,
                batch,
                None,
            );
            let (sack, sack_drops, sack_amp) = sim_bulk_acks(
                big,
                (Reno, pacing, true),
                25,
                64 * 1024,
                8_000,
                3_000,
                batch,
                None,
            );
            eprintln!(
                "OBSERVED 4MiB window, 50ms behind a 64 KiB queue, pacing={pacing}, ACKs every {batch}ms: go-back-N {gbn:.1} Mbit/s {gbn_drops} drops amp {gbn_amp:.2}; SACK {sack:.1} Mbit/s {sack_drops} drops amp {sack_amp:.2}"
            );
            assert!(
                sack >= 0.95 * gbn,
                "SACK never costs goodput: {sack:.1} vs {gbn:.1}"
            );
            assert!(
                sack_amp <= gbn_amp + 0.02,
                "nor wire: {sack_amp:.2} vs {gbn_amp:.2}"
            );
            if !pacing && batch == 0 {
                // The unpaced burst overshoots hardest; go-back-N resent it.
                assert!(sack >= 1.5 * gbn, "SACK recovers it: {sack:.1} vs {gbn:.1}");
            }
        }
        for one_way in [5i64, 25] {
            for queue in [64 * 1024i64, 256 * 1024] {
                let d = (TCP_RX_BUF, TCP_TX_BUF);
                let (gbn, _, gbn_amp) =
                    sim_bulk(d, (Reno, false, false), one_way, queue, 6_000, 2_000);
                let (sack, _, sack_amp) =
                    sim_bulk(d, (Reno, false, true), one_way, queue, 6_000, 2_000);
                eprintln!(
                    "OBSERVED default buffers, {}ms behind a {} KiB queue: go-back-N {gbn:.1} Mbit/s amp {gbn_amp:.2}; SACK {sack:.1} Mbit/s amp {sack_amp:.2}",
                    one_way * 2,
                    queue / 1024
                );
                assert!(
                    sack >= 0.95 * gbn,
                    "SACK never costs goodput: {sack:.1} vs {gbn:.1}"
                );
                assert!(
                    sack_amp <= gbn_amp + 0.02,
                    "nor wire: {sack_amp:.2} vs {gbn_amp:.2}"
                );
                if one_way == 25 && queue == 64 * 1024 {
                    assert!(
                        sack >= 1.3 * gbn,
                        "a 50 ms shallow path gains: {sack:.1} vs {gbn:.1}"
                    );
                }
            }
        }
    }

    /// A provider policer (40 Mbit/s, a 16 KiB bucket, no queue) on a 50 ms
    /// path: the field's relay leg, where unpaced windows collapsed to 2–3
    /// Mbit/s. Paced with SACK the defaults ride it; and a big window behind a
    /// moderate queue, where a lost resend once stalled SACK recovery into an
    /// RTO, stays far ahead of go-back-N.
    #[test]
    fn pacing_and_sack_ride_a_policer() {
        use tcp::CongestionControl::Reno;
        let d = (TCP_RX_BUF, TCP_TX_BUF);
        let police = Some((40, 16 * 1024));
        let (gbn, _, _) = sim_bulk_acks(
            d,
            (Reno, false, false),
            25,
            1024 * 1024,
            10_000,
            3_000,
            0,
            police,
        );
        let (ps, _, amp) = sim_bulk_acks(
            d,
            (Reno, true, true),
            25,
            1024 * 1024,
            10_000,
            3_000,
            0,
            police,
        );
        eprintln!(
            "OBSERVED policer 40 Mbit/s 16 KiB: go-back-N {gbn:.1}; paced+SACK {ps:.1} amp {amp:.2}"
        );
        assert!(
            ps >= 5.0 * gbn && ps >= 20.0,
            "paced SACK rides the policer: {ps:.1} vs {gbn:.1}"
        );
        assert!(amp < 1.1, "with little waste: {amp:.2}");
        let big = (4096 * 1024, 4096 * 1024);
        let (gbn, _, _) = sim_bulk(big, (Reno, false, false), 25, 256 * 1024, 8_000, 3_000);
        let (sack, _, _) = sim_bulk(big, (Reno, false, true), 25, 256 * 1024, 8_000, 3_000);
        let (ps, _, _) = sim_bulk(big, (Reno, true, true), 25, 256 * 1024, 8_000, 3_000);
        eprintln!(
            "OBSERVED 4 MiB, 50 ms, 256 KiB queue: go-back-N {gbn:.1}; SACK {sack:.1}; paced+SACK {ps:.1}"
        );
        assert!(
            sack >= 0.9 * gbn,
            "a lost resend no longer stalls SACK: {sack:.1} vs {gbn:.1}"
        );
        assert!(ps >= 1.5 * gbn, "paced SACK: {ps:.1} vs {gbn:.1}");
    }

    /// A provider policer (no queue: over-rate packets drop) on a 50 ms path:
    /// the field's relay leg. Measures go-back-N vs SACK, unpaced vs paced.
    #[test]
    #[ignore = "netstack TCP policer matrix; run with --ignored --nocapture"]
    fn netstack_tcp_policer_matrix() {
        use tcp::CongestionControl::Reno;
        for bufs in [(TCP_RX_BUF, TCP_TX_BUF), (4096 * 1024, 4096 * 1024)] {
            for bucket in [16 * 1024i64, 64 * 1024] {
                for (cc, pacing, sack) in [
                    (Reno, false, false),
                    (Reno, false, true),
                    (Reno, true, false),
                    (Reno, true, true),
                    (tcp::CongestionControl::Cubic, true, true),
                ] {
                    let (mbps, drops, amp) = sim_bulk_acks(
                        bufs,
                        (cc, pacing, sack),
                        25,
                        1024 * 1024,
                        10_000,
                        3_000,
                        0,
                        Some((40, bucket)),
                    );
                    eprintln!(
                        "OBSERVED policer 40 Mbit/s bucket {}KiB tx={}KiB cc={cc:?} pacing={pacing} sack={sack}: {mbps:.1} Mbit/s {drops} drops amp {amp:.2}",
                        bucket / 1024,
                        bufs.1 / 1024
                    );
                }
            }
        }
    }

    /// CUBIC against NewReno-lite, both paced with SACK, where Reno's halving
    /// and linear regrowth leave a long path behind a shallow queue idle:
    /// 100 ms behind a 64 KiB queue, and 50 ms behind one.
    #[test]
    fn cubic_fills_a_long_shallow_path_reno_leaves_idle() {
        use tcp::CongestionControl::{Cubic, Reno};
        let d = (TCP_RX_BUF, TCP_TX_BUF);
        for one_way in [25i64, 50] {
            let (reno, _, _) = sim_bulk(d, (Reno, true, true), one_way, 64 * 1024, 8_000, 3_000);
            let (cubic, _, amp) =
                sim_bulk(d, (Cubic, true, true), one_way, 64 * 1024, 8_000, 3_000);
            eprintln!(
                "OBSERVED {}ms behind a 64 KiB queue, paced SACK: reno {reno:.1} Mbit/s, cubic {cubic:.1} amp {amp:.2}",
                one_way * 2
            );
            assert!(
                cubic >= 1.25 * reno,
                "cubic fills it: {cubic:.1} vs {reno:.1}"
            );
            assert!(amp < 1.1, "with little waste: {amp:.2}");
        }
    }

    /// The measurement behind the defaults: goodput, drops and wire
    /// amplification per congestion controller, send bound, RTT and
    /// bottleneck queue depth.
    #[test]
    #[ignore = "netstack TCP buffer matrix; run with --ignored --nocapture"]
    fn netstack_tcp_buffer_matrix() {
        for (cc, pacing, sack) in [
            (tcp::CongestionControl::None, false, false),
            (tcp::CongestionControl::Reno, false, false),
            (tcp::CongestionControl::Reno, true, false),
            (tcp::CongestionControl::Reno, false, true),
            (tcp::CongestionControl::Reno, true, true),
            (tcp::CongestionControl::Cubic, true, true),
        ] {
            for one_way in [5i64, 25, 50] {
                for queue in [64 * 1024i64, 256 * 1024, 1024 * 1024] {
                    for tx in [
                        64 * 1024,
                        128 * 1024,
                        256 * 1024,
                        512 * 1024,
                        1024 * 1024,
                        4096 * 1024,
                    ] {
                        let rx = if tx == 64 * 1024 {
                            64 * 1024
                        } else {
                            TCP_RX_BUF.max(tx)
                        };
                        let (mbps, drops, amp) =
                            sim_bulk((rx, tx), (cc, pacing, sack), one_way, queue, 8_000, 3_000);
                        eprintln!(
                            "OBSERVED cc={cc:?} pacing={pacing} sack={sack} rtt={}ms queue={}KiB rx={}KiB tx={}KiB goodput={mbps:.1} drops={drops} wire/delivered={amp:.2}",
                            one_way * 2,
                            queue / 1024,
                            rx / 1024,
                            tx / 1024
                        );
                    }
                }
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn direct_pair_tcp_echo() {
        // Two stacks on the same /24, cross-linked packet-for-packet.
        let a_ip = Ipv4Addr::new(10, 9, 0, 1);
        let b_ip = Ipv4Addr::new(10, 9, 0, 2);
        let a = Netstack::start(a_ip, 24, 1280);
        let b = Netstack::start(b_ip, 24, 1280);

        // a.out → b.in  and  b.out → a.in.
        let (a_tun, b_tun) = (a.tun.clone(), b.tun.clone());
        tokio::spawn(async move {
            while let Ok(pkt) = a_tun.read_packet().await {
                if b_tun.write_packet(&pkt).await.is_err() {
                    break;
                }
            }
        });
        let (a_tun2, b_tun2) = (a.tun.clone(), b.tun.clone());
        tokio::spawn(async move {
            while let Ok(pkt) = b_tun2.read_packet().await {
                if a_tun2.write_packet(&pkt).await.is_err() {
                    break;
                }
            }
        });

        // B listens + echoes.
        let mut listener = b.handle.listen(9000).await.unwrap();
        tokio::spawn(async move {
            if let Some(s) = listener.accept().await {
                echo(s).await;
            }
        });

        let dst = SocketAddr::from((b_ip, 9000));
        tokio::time::timeout(
            Duration::from_secs(10),
            round_trip(&a.handle, dst, b"hello-netstack"),
        )
        .await
        .expect("round trip in time");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_tcp_echo_over_wireguard() {
        use crate::overlay::WgKeypair;
        use crate::overlay::bridge::run_bridge;
        use crate::overlay::wg::{Carrier, WgDevice};
        use tokio::net::UdpSocket;

        let a_ip = Ipv4Addr::new(100, 64, 0, 1);
        let b_ip = Ipv4Addr::new(100, 64, 0, 2);

        // WG carrier pair over loopback UDP (as in the bridge module test).
        let ka = WgKeypair::generate();
        let kb = WgKeypair::generate();
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        let (mut dev_a, rx_a) = WgDevice::new(ka.secret.clone());
        let (mut dev_b, rx_b) = WgDevice::new(kb.secret.clone());
        dev_a.add_peer(
            kb.public.to_bytes(),
            b_ip,
            Carrier::direct(sock_a.clone(), addr_b),
            true,
        );
        dev_b.add_peer(
            ka.public.to_bytes(),
            a_ip,
            Carrier::direct(sock_b.clone(), addr_a),
            false,
        );
        let (dev_a, dev_b) = (Arc::new(dev_a), Arc::new(dev_b));

        // A netstack ↔ dev_a bridge; B netstack ↔ dev_b bridge. /10 = overlay CIDR.
        let a = Netstack::start(a_ip, 10, 1280);
        let b = Netstack::start(b_ip, 10, 1280);
        tokio::spawn(run_bridge(a.tun.clone() as Arc<dyn TunIo>, dev_a, rx_a));
        tokio::spawn(run_bridge(b.tun.clone() as Arc<dyn TunIo>, dev_b, rx_b));

        let mut listener = b.handle.listen(3389).await.unwrap();
        tokio::spawn(async move {
            if let Some(s) = listener.accept().await {
                echo(s).await;
            }
        });

        // WG handshake + SYN retransmit can take a beat; connect() retries via
        // smoltcp until the session is up, bounded by CONNECT_TIMEOUT.
        let dst = SocketAddr::from((b_ip, 3389));
        tokio::time::timeout(
            Duration::from_secs(20),
            round_trip(&a.handle, dst, b"rdp-over-userspace-wireguard"),
        )
        .await
        .expect("round trip over the WG bridge in time");
    }

    /// The Phase B proof: **IPv6 rides the same WG mesh with no v6 routing
    /// state**. A dials B's *derived* overlay v6; the outbound path unmaps the
    /// ULA destination to B's embedded v4 ([`Router::dst_of_ip_packet`]) and
    /// routes on the ordinary v4 table; B's decapsulate delivers the v6 packet
    /// (`WriteToTunnelV6`) to its dual-addressed netstack. TCP echo + ICMPv6
    /// ping both round-trip — the peers were installed with v4 ONLY.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bridge_v6_tcp_echo_and_ping_over_wireguard() {
        use crate::overlay::WgKeypair;
        use crate::overlay::bridge::run_bridge;
        use crate::overlay::router::Router;
        use crate::overlay::wg::{Carrier, WgDevice};
        use tokio::net::UdpSocket;

        let a_ip = Ipv4Addr::new(100, 64, 0, 1);
        let b_ip = Ipv4Addr::new(100, 64, 0, 2);

        let ka = WgKeypair::generate();
        let kb = WgKeypair::generate();
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();
        let (mut dev_a, rx_a) = WgDevice::new(ka.secret.clone());
        let (mut dev_b, rx_b) = WgDevice::new(kb.secret.clone());
        // v4-only peer install — exactly what the runtime does today.
        dev_a.add_peer(
            kb.public.to_bytes(),
            b_ip,
            Carrier::direct(sock_a.clone(), addr_b),
            true,
        );
        dev_b.add_peer(
            ka.public.to_bytes(),
            a_ip,
            Carrier::direct(sock_b.clone(), addr_a),
            false,
        );
        let (dev_a, dev_b) = (Arc::new(dev_a), Arc::new(dev_b));

        let a = Netstack::start(a_ip, 10, 1280);
        let b = Netstack::start(b_ip, 10, 1280);
        tokio::spawn(run_bridge(a.tun.clone() as Arc<dyn TunIo>, dev_a, rx_a));
        tokio::spawn(run_bridge(b.tun.clone() as Arc<dyn TunIo>, dev_b, rx_b));

        let b_v6 = derive_overlay_v6(b_ip);
        // Sanity: the routing key a v6 packet resolves to is B's v4.
        let mut probe = [0u8; 40];
        probe[0] = 0x60;
        probe[24..40].copy_from_slice(&b_v6.octets());
        assert_eq!(Router::dst_of_ip_packet(&probe), Some(b_ip));

        let mut listener = b.handle.listen(3389).await.unwrap();
        tokio::spawn(async move {
            if let Some(s) = listener.accept().await {
                echo(s).await;
            }
        });

        // TCP echo over the derived v6, through the real WG pair.
        let dst = SocketAddr::new(IpAddr::V6(b_v6), 3389);
        tokio::time::timeout(
            Duration::from_secs(20),
            round_trip(&a.handle, dst, b"v6-over-userspace-wireguard"),
        )
        .await
        .expect("v6 round trip over the WG bridge in time");

        // ICMPv6 ping over the same path — B's iface auto-answers.
        let rtt = tokio::time::timeout(
            Duration::from_secs(10),
            a.handle.ping(IpAddr::V6(b_v6), Duration::from_secs(8)),
        )
        .await
        .expect("v6 ping over the WG bridge completes in time")
        .expect("v6 ping over the WG bridge succeeds");
        assert!(rtt < Duration::from_secs(8), "rtt within the timeout");
        let _keep = b;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn direct_pair_udp_echo() {
        // Two stacks on the same /24, cross-linked packet-for-packet.
        let a_ip = Ipv4Addr::new(10, 8, 0, 1);
        let b_ip = Ipv4Addr::new(10, 8, 0, 2);
        let a = Netstack::start(a_ip, 24, 1280);
        let b = Netstack::start(b_ip, 24, 1280);

        let (a_tun, b_tun) = (a.tun.clone(), b.tun.clone());
        tokio::spawn(async move {
            while let Ok(pkt) = a_tun.read_packet().await {
                if b_tun.write_packet(&pkt).await.is_err() {
                    break;
                }
            }
        });
        let (a_tun2, b_tun2) = (a.tun.clone(), b.tun.clone());
        tokio::spawn(async move {
            while let Ok(pkt) = b_tun2.read_packet().await {
                if a_tun2.write_packet(&pkt).await.is_err() {
                    break;
                }
            }
        });

        // B: a UDP echo — bounce each datagram back to its source.
        let mut b_udp = b.handle.udp_bind().await.unwrap();
        let b_port = b_udp.local_port();
        let b_tx = b_udp.sender();
        tokio::spawn(async move {
            while let Ok((data, src)) = b_udp.recv_from().await {
                let _ = b_tx.send_to(&data, src).await;
            }
        });

        // A: send a datagram to B's port and read the echo back.
        let mut a_udp = a.handle.udp_bind().await.unwrap();
        let dst = SocketAddr::from((b_ip, b_port));
        let body = async {
            a_udp.send_to(b"udp-over-netstack", dst).await.unwrap();
            let (data, src) = a_udp.recv_from().await.unwrap();
            assert_eq!(&data, b"udp-over-netstack");
            assert_eq!(src, dst, "reply's source is B's bound port");
        };
        tokio::time::timeout(Duration::from_secs(10), body)
            .await
            .expect("udp round trip in time");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn direct_pair_icmp_ping() {
        // Two stacks on the same /24, cross-linked packet-for-packet.
        let a_ip = Ipv4Addr::new(10, 7, 0, 1);
        let b_ip = Ipv4Addr::new(10, 7, 0, 2);
        let a = Netstack::start(a_ip, 24, 1280);
        let b = Netstack::start(b_ip, 24, 1280);

        let (a_tun, b_tun) = (a.tun.clone(), b.tun.clone());
        tokio::spawn(async move {
            while let Ok(pkt) = a_tun.read_packet().await {
                if b_tun.write_packet(&pkt).await.is_err() {
                    break;
                }
            }
        });
        let (a_tun2, b_tun2) = (a.tun.clone(), b.tun.clone());
        tokio::spawn(async move {
            while let Ok(pkt) = b_tun2.read_packet().await {
                if a_tun2.write_packet(&pkt).await.is_err() {
                    break;
                }
            }
        });

        // A pings B — B's iface auto-answers the echo request (no app socket on
        // B), A's icmp socket matches the reply and reports the RTT. B needs no
        // task at all: `auto-icmp-echo-reply` replies inside its poll loop.
        let rtt = tokio::time::timeout(
            Duration::from_secs(5),
            a.handle.ping(IpAddr::V4(b_ip), Duration::from_secs(3)),
        )
        .await
        .expect("ping completes in time")
        .expect("ping succeeds");
        assert!(rtt < Duration::from_secs(3), "rtt within the timeout");
        let _keep = b; // keep B's netstack alive for the ping
    }

    /// Cross-link two netstacks packet-for-packet at L3 (no WG), both directions.
    fn cross_link(a: &Netstack, b: &Netstack) {
        let (a_tun, b_tun) = (a.tun.clone(), b.tun.clone());
        tokio::spawn(async move {
            while let Ok(pkt) = a_tun.read_packet().await {
                if b_tun.write_packet(&pkt).await.is_err() {
                    break;
                }
            }
        });
        let (a_tun2, b_tun2) = (a.tun.clone(), b.tun.clone());
        tokio::spawn(async move {
            while let Ok(pkt) = b_tun2.read_packet().await {
                if a_tun2.write_packet(&pkt).await.is_err() {
                    break;
                }
            }
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn direct_pair_tcp_echo_v6() {
        // Two stacks cross-linked; talk over the DERIVED overlay v6 (ULA /96).
        let a_v4 = Ipv4Addr::new(10, 6, 0, 1);
        let b_v4 = Ipv4Addr::new(10, 6, 0, 2);
        let a = Netstack::start(a_v4, 24, 1280);
        let b = Netstack::start(b_v4, 24, 1280);
        cross_link(&a, &b);

        let mut listener = b.handle.listen(9000).await.unwrap();
        tokio::spawn(async move {
            if let Some(s) = listener.accept().await {
                echo(s).await;
            }
        });

        let dst = SocketAddr::new(IpAddr::V6(derive_overlay_v6(b_v4)), 9000);
        tokio::time::timeout(
            Duration::from_secs(10),
            round_trip(&a.handle, dst, b"hello-netstack-v6"),
        )
        .await
        .expect("v6 round trip in time");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn direct_pair_udp_echo_v6() {
        let a_v4 = Ipv4Addr::new(10, 5, 0, 1);
        let b_v4 = Ipv4Addr::new(10, 5, 0, 2);
        let a = Netstack::start(a_v4, 24, 1280);
        let b = Netstack::start(b_v4, 24, 1280);
        cross_link(&a, &b);

        // B: bounce each datagram back to its source, over v6.
        let mut b_udp = b.handle.udp_bind().await.unwrap();
        let b_port = b_udp.local_port();
        let b_tx = b_udp.sender();
        tokio::spawn(async move {
            while let Ok((data, src)) = b_udp.recv_from().await {
                let _ = b_tx.send_to(&data, src).await;
            }
        });

        let mut a_udp = a.handle.udp_bind().await.unwrap();
        let dst = SocketAddr::new(IpAddr::V6(derive_overlay_v6(b_v4)), b_port);
        let body = async {
            a_udp.send_to(b"udp-over-netstack-v6", dst).await.unwrap();
            let (data, src) = a_udp.recv_from().await.unwrap();
            assert_eq!(&data, b"udp-over-netstack-v6");
            assert_eq!(src, dst, "reply's source is B's bound v6 port");
        };
        tokio::time::timeout(Duration::from_secs(10), body)
            .await
            .expect("v6 udp round trip in time");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn direct_pair_icmp_ping_v6() {
        let a_v4 = Ipv4Addr::new(10, 4, 0, 1);
        let b_v4 = Ipv4Addr::new(10, 4, 0, 2);
        let a = Netstack::start(a_v4, 24, 1280);
        let b = Netstack::start(b_v4, 24, 1280);
        cross_link(&a, &b);

        // A pings B's derived v6 — B's iface auto-answers the ICMPv6 echo
        // (`auto-icmp-echo-reply`); A matches the reply by ident and reports RTT.
        let dst = derive_overlay_v6(b_v4);
        let rtt = tokio::time::timeout(
            Duration::from_secs(5),
            a.handle.ping(IpAddr::V6(dst), Duration::from_secs(3)),
        )
        .await
        .expect("v6 ping completes in time")
        .expect("v6 ping succeeds");
        assert!(rtt < Duration::from_secs(3), "rtt within the timeout");
        let _keep = b;
    }
}
