// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Port-intercept TUN shim — lets an in-process service own a TCP port on this
//! node's overlay address **without binding an OS socket**.
//!
//! # Why this exists
//!
//! MeshHarbor SSH (and any future in-daemon overlay service) has to answer on
//! `<self overlay ip>:<port>`. The obvious implementation — bind a listener on
//! that address — fails on most of the fleet, as the 2026-08-19 survey showed:
//!
//! * `buildhost` / `fleet-host-2` / `fleet-host-1` run `sshd` on `0.0.0.0:22`, which *covers* the
//!   overlay address. A second bind is impossible.
//! * `devbox` runs `sshd` bound to `100.65.4.2:22` — the overlay address itself.
//! * `corplap-3` has no `sshd` at all (the OpenSSH capability is `NotPresent`
//!   and corp policy owns the box) AND its loopback `:22` is held by WSL's
//!   `wslrelay`. It also runs with all three firewall profiles enabled, so a new
//!   listener would need a rule an unprivileged corp user cannot add.
//!
//! So we do what Tailscale does, one layer lower: **intercept the packets before
//! the OS ever sees them.** [`super::bridge::run_bridge`] is device-agnostic —
//! it pumps an [`Arc<dyn TunIo>`] — and [`super::netstack::Netstack`] is a
//! complete userspace TCP/IP stack that already implements `TunIo`. [`SplitTun`]
//! sits between them:
//!
//! ```text
//!                                  ┌── dst == self_ip && tcp && dport == port
//!   mesh ─▶ WgDevice ─decrypt─▶ SplitTun ──┤        → Netstack (smoltcp) → service
//!                                  └── everything else → SystemTun → OS stack
//! ```
//!
//! What that buys, in order of how much it matters here:
//!
//! * **No port conflict.** `sshd` keeps `0.0.0.0:22`; we answer for overlay-
//!   addressed packets we peel off first. Both can coexist on one host.
//! * **No firewall rule.** Nothing binds, so there is no listener for a host
//!   firewall to permit or an EDR agent to object to. (Kaspersky terminating
//!   `sshd.exe` as a *service* is what parked `regal` outbound-only in 2026-07.)
//! * **Off-mesh unreachable by construction.** The only way into this stack is a
//!   packet that already passed WireGuard authentication and decryption. That is
//!   a property of the topology, not a policy someone can misconfigure.
//! * **Same code path on a locked-down laptop.** In netstack mode the inner
//!   device is itself a [`NetstackTun`](super::netstack::NetstackTun) and the
//!   split still works, so a host with no winnable routing table behaves
//!   identically to a server.
//!
//! # What this module is NOT
//!
//! It does not authenticate, authorize or audit anything — it is a packet
//! demultiplexer. Every gate lives above it in the service that accepts from
//! [`SplitTun::listen`]. Interception is also **opt-in per node** (`ssh_enabled`,
//! default off): switching it on for a port an OS daemon already serves on the
//! overlay address silently changes who answers, which is exactly why the agent
//! logs a warning when it detects that case.
//!
//! # Teardown
//!
//! Both pump tasks are aborted in [`Drop`], which cancels the in-flight
//! `read_packet` on the inner device. That is the same cancellation the runtime
//! already performs when it drops a session's bridge, and it matters here
//! because the OS TUN is cached for the process lifetime: without the abort, a
//! previous session's pump would still be reading the shared device and would
//! steal the next session's first packet.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::netstack::{Netstack, NetstackHandle, NsListener};
use super::tun::TunIo;

/// Depth of the merged outbound queue. Deep enough that a busy interactive
/// session never head-of-line blocks the bulk path, shallow enough that a
/// stalled bridge applies backpressure instead of growing without bound —
/// the same contract a real NIC ring gives.
const OUTBOUND_QUEUE: usize = 1024;

/// IPv4 protocol number for TCP.
const IPPROTO_TCP: u8 = 6;

/// A [`TunIo`] that diverts a few TCP ports on `self_ip` into an in-process
/// [`Netstack`] and passes everything else through to `inner`.
///
/// Build it with [`SplitTun::wrap`] (one port) or [`SplitTun::wrap_ports`];
/// accept the diverted connections with [`SplitTun::listen`] or
/// [`SplitTun::listen_on`].
pub struct SplitTun {
    /// The real device (OS TUN, or a netstack in OS-free mode).
    inner: Arc<dyn TunIo>,
    /// The userspace stack that terminates the intercepted ports.
    ns: Arc<Netstack>,
    /// This node's overlay address — the only destination we intercept for.
    self_ip: Ipv4Addr,
    /// The intercepted TCP ports; the first is [`SplitTun::listen`]'s. A
    /// handful at most (FR-105: meshharbor SSH's 2222 and the Windows SYSTEM
    /// service's 2223), so a scan beats a set.
    ports: Vec<u16>,
    /// Merged outbound queue fed by both pumps.
    out_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// Pump join handles, aborted on drop.
    pumps: [JoinHandle<()>; 2],
    /// Packets diverted into the netstack.
    intercepted: AtomicU64,
    /// Set once we log the first diverted packet, so the log is a signal and
    /// not a per-packet flood.
    announced: std::sync::atomic::AtomicBool,
}

impl SplitTun {
    /// Wrap `inner` so TCP traffic to `self_ip:port` terminates in-process.
    ///
    /// `prefix` is the overlay block's prefix length and `mtu` the overlay MTU —
    /// both are handed to the inner [`Netstack`] so it agrees with the real
    /// device about what is on-link and how big a segment may be.
    ///
    /// Must be called from within a Tokio runtime (it spawns the pumps and the
    /// netstack poll loop).
    pub fn wrap(
        inner: Arc<dyn TunIo>,
        self_ip: Ipv4Addr,
        prefix: u8,
        mtu: u16,
        port: u16,
    ) -> Arc<Self> {
        Self::wrap_ports(inner, self_ip, prefix, mtu, &[port])
    }

    /// [`SplitTun::wrap`] for several ports at once, served by the one
    /// in-process stack. The first is [`SplitTun::listen`]'s; every port is
    /// [`SplitTun::listen_on`]'s.
    pub fn wrap_ports(
        inner: Arc<dyn TunIo>,
        self_ip: Ipv4Addr,
        prefix: u8,
        mtu: u16,
        ports: &[u16],
    ) -> Arc<Self> {
        assert!(!ports.is_empty(), "split-tun: nothing to intercept");
        let ports = ports.to_vec();
        let ns = Arc::new(Netstack::start(self_ip, prefix, mtu));
        let (out_tx, out_rx) = mpsc::channel(OUTBOUND_QUEUE);

        // Pump A — the real device's egress. This is the bulk path.
        let a_dev = inner.clone();
        let a_tx = out_tx.clone();
        let pump_a = tokio::spawn(async move {
            loop {
                match a_dev.read_packet().await {
                    Ok(pkt) => {
                        if a_tx.send(pkt).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!(%e, "split-tun: inner device read ended; egress pump exiting");
                        break;
                    }
                }
            }
        });

        // Pump B — what the userspace stack wants on the wire (the intercepted
        // service's replies). Low rate by construction.
        let b_ns = ns.clone();
        let pump_b = tokio::spawn(async move {
            loop {
                match b_ns.tun.read_packet().await {
                    Ok(pkt) => {
                        if out_tx.send(pkt).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        debug!(%e, "split-tun: netstack read ended; egress pump exiting");
                        break;
                    }
                }
            }
        });

        info!(
            %self_ip, ?ports,
            "split-tun: intercepting overlay TCP — the service answers in-process, no OS socket"
        );

        Arc::new(Self {
            inner,
            ns,
            self_ip,
            ports,
            out_rx: Mutex::new(out_rx),
            pumps: [pump_a, pump_b],
            intercepted: AtomicU64::new(0),
            announced: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Accept connections to the intercepted port. Each yielded stream is an
    /// ordinary `AsyncRead + AsyncWrite` whose peer address is the overlay
    /// address of the calling node — which is the caller's *authenticated*
    /// identity, since nothing reaches this stack without clearing WireGuard.
    pub async fn listen(&self) -> std::io::Result<NsListener> {
        self.ns.handle.listen(self.ports[0]).await
    }

    /// Accept connections to `port`, one of the intercepted ports. Any other
    /// port is refused: nothing would ever reach a listener on it.
    pub async fn listen_on(&self, port: u16) -> std::io::Result<NsListener> {
        if !self.ports.contains(&port) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("split-tun: port {port} is not intercepted"),
            ));
        }
        self.ns.handle.listen(port).await
    }

    /// The netstack handle, for callers that need to originate as well as
    /// accept (the SSH client's loopback path in a later slice).
    pub fn netstack(&self) -> NetstackHandle {
        self.ns.handle.clone()
    }

    /// Count of packets diverted into the in-process stack. Surfaced in
    /// diagnostics so "is the intercept live?" is answerable without a capture.
    pub fn intercepted(&self) -> u64 {
        self.intercepted.load(Ordering::Relaxed)
    }
}

impl Drop for SplitTun {
    fn drop(&mut self) {
        for p in &self.pumps {
            p.abort();
        }
    }
}

/// Does this packet belong to the service on `port`? The tests' view of
/// [`tcp_dport_to`].
#[cfg(test)]
fn is_intercepted(pkt: &[u8], self_ip: Ipv4Addr, port: u16) -> bool {
    tcp_dport_to(pkt, self_ip) == Some(port)
}

/// The TCP destination port of a packet that may belong to an intercepted
/// service: a complete, unfragmented IPv4/TCP packet addressed to `self_ip`.
/// Everything else — v6, other protocols, other destinations, non-initial
/// fragments, truncated or malformed headers — is `None`, and is passed to
/// the OS, which is both the safe default and the correct one.
///
/// This parses attacker-influenced bytes (a peer that cleared WireGuard is
/// authenticated, not trusted), so every field access is bounds-checked and the
/// function is total: it returns `None` rather than panicking on any input.
fn tcp_dport_to(pkt: &[u8], self_ip: Ipv4Addr) -> Option<u16> {
    // IPv4 fixed header is 20 bytes.
    if pkt.len() < 20 {
        return None;
    }
    // Version must be 4. (IPv6 overlay traffic is never intercepted: the
    // service is reached over the v4 overlay address today.)
    if pkt[0] >> 4 != 4 {
        return None;
    }
    if pkt[9] != IPPROTO_TCP {
        return None;
    }
    // Only the first fragment carries the TCP header; later ones must go to the
    // OS so it can reassemble. Overlay MTU makes this vanishingly rare for TCP.
    let frag_offset = u16::from_be_bytes([pkt[6] & 0x1f, pkt[7]]);
    if frag_offset != 0 {
        return None;
    }
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    if dst != self_ip {
        return None;
    }
    // IHL is in 32-bit words and must be at least 5; the TCP destination port
    // sits at bytes 2..4 of the TCP header.
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    if ihl < 20 || pkt.len() < ihl + 4 {
        return None;
    }
    Some(u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]))
}

#[async_trait]
impl TunIo for SplitTun {
    async fn read_packet(&self) -> std::io::Result<Vec<u8>> {
        self.out_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| std::io::Error::other("split-tun: both egress pumps ended"))
    }

    async fn write_packet(&self, packet: &[u8]) -> std::io::Result<()> {
        if let Some(port) = tcp_dport_to(packet, self.self_ip).filter(|p| self.ports.contains(p)) {
            self.intercepted.fetch_add(1, Ordering::Relaxed);
            if !self.announced.swap(true, Ordering::Relaxed) {
                info!(
                    self_ip = %self.self_ip, port,
                    "split-tun: first intercepted connection — serving it in-process"
                );
            }
            return self.ns.tun.write_packet(packet).await;
        }
        self.inner.write_packet(packet).await
    }

    // ── Everything below is pure delegation. The route guard, the block-floor
    // defence and the peer-path checks all reason about the REAL device; a
    // shim that swallowed them would silently disable them. ──

    fn os_name(&self) -> Option<String> {
        self.inner.os_name()
    }

    async fn add_peer_route(&self, peer: Ipv4Addr) -> std::io::Result<()> {
        self.inner.add_peer_route(peer).await
    }

    async fn del_peer_route(&self, peer: Ipv4Addr) {
        self.inner.del_peer_route(peer).await
    }

    async fn defend_self_route(&self, self_ip: Ipv4Addr) {
        self.inner.defend_self_route(self_ip).await
    }

    async fn add_cidr_route(&self, cidr: &str) -> std::io::Result<()> {
        self.inner.add_cidr_route(cidr).await
    }

    async fn del_cidr_route(&self, cidr: &str) {
        self.inner.del_cidr_route(cidr).await
    }

    async fn defend_block_floor(&self) {
        self.inner.defend_block_floor().await
    }

    async fn defend_block_floor_of(&self, net: Ipv4Addr, plen: u8) {
        self.inner.defend_block_floor_of(net, plen).await
    }

    async fn verify_peer_path_ownership(&self, peers: &[Ipv4Addr]) {
        self.inner.verify_peer_path_ownership(peers).await
    }

    async fn add_host_exemption(&self, ip: std::net::IpAddr) -> std::io::Result<()> {
        self.inner.add_host_exemption(ip).await
    }

    async fn del_host_exemption(&self, ip: std::net::IpAddr) {
        self.inner.del_host_exemption(ip).await
    }

    async fn stale_host_exemptions(&self, pinned: &[std::net::IpAddr]) -> Vec<std::net::IpAddr> {
        self.inner.stale_host_exemptions(pinned).await
    }
}

/// Warn when an OS daemon already answers on the address+port we are about to
/// take over, so flipping `ssh_enabled` on `devbox` (sshd bound to the overlay
/// IP) or `buildhost` (sshd on `0.0.0.0:22`) is a logged decision rather than a
/// silent change of who serves SSH.
///
/// Best-effort and non-fatal: a bind probe that fails for any other reason must
/// not stop the overlay from coming up.
pub fn warn_if_os_listener(self_ip: Ipv4Addr, port: u16) {
    use std::net::{SocketAddr, TcpListener};
    // If we can bind it, nothing else holds it — the common case.
    match TcpListener::bind(SocketAddr::from((self_ip, port))) {
        Ok(l) => drop(l),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            warn!(
                %self_ip, port,
                "split-tun: an OS listener already serves this overlay address and port. \
                 Interception takes precedence for MESH traffic, so peers now reach the \
                 in-process service instead of that daemon. Set a different `ssh_port` \
                 if both must stay reachable over the overlay."
            );
        }
        Err(e) => debug!(%e, "split-tun: listener probe inconclusive; continuing"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SELF_IP: Ipv4Addr = Ipv4Addr::new(100, 65, 4, 30);
    const PORT: u16 = 2222;

    /// Minimal IPv4+TCP packet builder: 20-byte IP header, `ihl_words * 4` total
    /// header, then a TCP header whose destination port is `dport`.
    fn ipv4_tcp(dst: Ipv4Addr, dport: u16, proto: u8, ihl_words: u8, frag_offset: u16) -> Vec<u8> {
        let ihl = usize::from(ihl_words) * 4;
        let mut p = vec![0u8; ihl + 20];
        p[0] = 0x40 | ihl_words;
        p[9] = proto;
        let frag = frag_offset & 0x1fff;
        p[6] = (frag >> 8) as u8;
        p[7] = (frag & 0xff) as u8;
        p[16..20].copy_from_slice(&dst.octets());
        p[ihl + 2..ihl + 4].copy_from_slice(&dport.to_be_bytes());
        p
    }

    #[test]
    fn intercepts_tcp_to_self_on_the_service_port() {
        let p = ipv4_tcp(SELF_IP, PORT, IPPROTO_TCP, 5, 0);
        assert!(is_intercepted(&p, SELF_IP, PORT));
    }

    #[test]
    fn honours_a_longer_options_header() {
        // IHL 8 words = 12 bytes of IP options before the TCP header. Reading the
        // port at a fixed offset would find zeros here and pass it to the OS.
        let p = ipv4_tcp(SELF_IP, PORT, IPPROTO_TCP, 8, 0);
        assert!(is_intercepted(&p, SELF_IP, PORT));
    }

    #[test]
    fn passes_through_other_ports_hosts_and_protocols() {
        assert!(!is_intercepted(
            &ipv4_tcp(SELF_IP, 22, IPPROTO_TCP, 5, 0),
            SELF_IP,
            PORT
        ));
        assert!(!is_intercepted(
            &ipv4_tcp(Ipv4Addr::new(100, 65, 4, 2), PORT, IPPROTO_TCP, 5, 0),
            SELF_IP,
            PORT
        ));
        // UDP to the same address+port stays with the OS.
        assert!(!is_intercepted(
            &ipv4_tcp(SELF_IP, PORT, 17, 5, 0),
            SELF_IP,
            PORT
        ));
    }

    #[test]
    fn passes_through_non_initial_fragments() {
        let p = ipv4_tcp(SELF_IP, PORT, IPPROTO_TCP, 5, 185);
        assert!(!is_intercepted(&p, SELF_IP, PORT));
    }

    // ── Behavioural tests: the demux, and the whole path over real WireGuard ──

    /// Stands in for the OS TUN. Records everything the shim decided the kernel
    /// should see, and never originates traffic of its own.
    struct MockOsTun {
        seen: mpsc::UnboundedSender<Vec<u8>>,
        /// Kept so `read_packet` parks forever instead of erroring, which is how
        /// a real idle device behaves (an immediate `Err` would let the egress
        /// pump exit and mask a bug).
        idle: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    }

    #[async_trait]
    impl TunIo for MockOsTun {
        async fn read_packet(&self) -> std::io::Result<Vec<u8>> {
            self.idle
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| std::io::Error::other("mock closed"))
        }
        async fn write_packet(&self, packet: &[u8]) -> std::io::Result<()> {
            let _ = self.seen.send(packet.to_vec());
            Ok(())
        }
        /// Everything is stale, so a shim that kept the trait's empty default
        /// shows up as an empty answer.
        async fn stale_host_exemptions(
            &self,
            pinned: &[std::net::IpAddr],
        ) -> Vec<std::net::IpAddr> {
            pinned.to_vec()
        }
    }

    /// FR-97 P1a — the stale-exemption check reaches the real device. Keeping
    /// the trait's empty default here would quietly switch off the re-pin on
    /// every host that serves SSH, which is when the OS device sits under
    /// this shim.
    #[tokio::test]
    async fn the_stale_exemption_check_reaches_the_os_device() {
        let (mock, _seen) = mock_os_tun();
        let split = SplitTun::wrap(mock, SELF_IP, 10, 1280, PORT);
        let pinned = [std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))];
        assert_eq!(split.stale_host_exemptions(&pinned).await, pinned.to_vec());
    }

    fn mock_os_tun() -> (Arc<MockOsTun>, mpsc::UnboundedReceiver<Vec<u8>>) {
        let (seen, seen_rx) = mpsc::unbounded_channel();
        let (_idle_tx, idle_rx) = mpsc::unbounded_channel();
        (
            Arc::new(MockOsTun {
                seen,
                idle: Mutex::new(idle_rx),
            }),
            seen_rx,
        )
    }

    /// The load-bearing property: the service port is peeled off, and
    /// **everything else still reaches the OS**. A shim that swallowed the rest
    /// would take the host off the overlay while looking perfectly healthy.
    #[tokio::test]
    async fn diverts_only_the_service_port_and_passes_the_rest_to_the_os() {
        let (mock, mut seen) = mock_os_tun();
        let split = SplitTun::wrap(mock, SELF_IP, 10, 1280, PORT);

        // Service port → in-process stack; the OS must not see it.
        split
            .write_packet(&ipv4_tcp(SELF_IP, PORT, IPPROTO_TCP, 5, 0))
            .await
            .unwrap();
        assert_eq!(split.intercepted(), 1);
        assert!(
            seen.try_recv().is_err(),
            "an intercepted packet must never reach the OS device"
        );

        // Another port on the same address → straight through, unmodified.
        let passthru = ipv4_tcp(SELF_IP, 3389, IPPROTO_TCP, 5, 0);
        split.write_packet(&passthru).await.unwrap();
        assert_eq!(split.intercepted(), 1, "pass-through must not be counted");
        assert_eq!(
            seen.try_recv().expect("the OS device receives it"),
            passthru
        );
    }

    /// FR-105 — two services on one stack: meshharbor SSH's port and the Windows
    /// SYSTEM service's. Each is diverted, a third port is not, and only an
    /// intercepted port can be listened on.
    #[tokio::test]
    async fn diverts_every_listed_port_and_only_those() {
        const SERVICE: u16 = 2223;
        let (mock, mut seen) = mock_os_tun();
        let split = SplitTun::wrap_ports(mock, SELF_IP, 10, 1280, &[PORT, SERVICE]);

        for port in [PORT, SERVICE] {
            split
                .write_packet(&ipv4_tcp(SELF_IP, port, IPPROTO_TCP, 5, 0))
                .await
                .unwrap();
        }
        assert_eq!(split.intercepted(), 2);
        assert!(seen.try_recv().is_err(), "neither reached the OS device");

        let passthru = ipv4_tcp(SELF_IP, 2224, IPPROTO_TCP, 5, 0);
        split.write_packet(&passthru).await.unwrap();
        assert_eq!(split.intercepted(), 2);
        assert_eq!(seen.try_recv().unwrap(), passthru);

        assert!(split.listen_on(SERVICE).await.is_ok());
        assert!(matches!(
            split.listen_on(2224).await,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidInput
        ));
    }

    /// End-to-end over a real WireGuard pair: peer A dials peer B's overlay
    /// address on the intercepted port and is served by B's in-process stack,
    /// while B's "OS" device never sees the traffic. This is the P1 claim in one
    /// test — encryption, routing, interception, termination.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn peer_reaches_the_intercepted_port_over_wireguard() {
        use std::net::SocketAddr;
        use std::time::Duration;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UdpSocket;

        use crate::overlay::WgKeypair;
        use crate::overlay::bridge::run_bridge;
        use crate::overlay::netstack::NsTcpStream;
        use crate::overlay::wg::{Carrier, WgDevice};

        let a_ip = Ipv4Addr::new(100, 65, 4, 2);
        let b_ip = SELF_IP;

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

        // A is an ordinary netstack node. B is an OS-TUN node whose service port
        // is intercepted — the shape a real fleet host has.
        let a = Netstack::start(a_ip, 10, 1280);
        let (mock, mut seen) = mock_os_tun();
        let split = SplitTun::wrap(mock, b_ip, 10, 1280, PORT);

        tokio::spawn(run_bridge(a.tun.clone() as Arc<dyn TunIo>, dev_a, rx_a));
        tokio::spawn(run_bridge(split.clone() as Arc<dyn TunIo>, dev_b, rx_b));

        let mut listener = split.listen().await.unwrap();
        tokio::spawn(async move {
            if let Some(mut s) = listener.accept().await {
                let mut buf = [0u8; 256];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        });

        let dst = SocketAddr::from((b_ip, PORT));
        let payload = b"ssh-p1-over-wireguard";
        let echoed = tokio::time::timeout(Duration::from_secs(20), async {
            let mut s: NsTcpStream = a.handle.connect(dst).await.expect("connect");
            s.write_all(payload).await.expect("write");
            let mut got = vec![0u8; payload.len()];
            s.read_exact(&mut got).await.expect("read");
            got
        })
        .await
        .expect("round trip over the WG bridge in time");

        assert_eq!(echoed, payload);
        assert!(split.intercepted() > 0, "the shim recorded the diversion");
        assert!(
            seen.try_recv().is_err(),
            "B's OS device must never see the intercepted session"
        );
    }

    #[test]
    fn never_panics_on_malformed_input() {
        // Truncations at every length, a v6 packet, and a bogus IHL must all be
        // answered with "not ours" rather than an index panic.
        let full = ipv4_tcp(SELF_IP, PORT, IPPROTO_TCP, 5, 0);
        for n in 0..full.len() {
            assert!(!is_intercepted(&full[..n], SELF_IP, PORT) || n >= 24);
        }
        let mut v6 = full.clone();
        v6[0] = 0x60;
        assert!(!is_intercepted(&v6, SELF_IP, PORT));

        let mut bad_ihl = full.clone();
        bad_ihl[0] = 0x41; // IHL 1 word — shorter than the fixed header
        assert!(!is_intercepted(&bad_ihl, SELF_IP, PORT));

        // IHL points past the end of the buffer.
        let mut long_ihl = full.clone();
        long_ihl[0] = 0x4f;
        assert!(!is_intercepted(&long_ihl, SELF_IP, PORT));

        assert!(!is_intercepted(&[], SELF_IP, PORT));
    }
}
