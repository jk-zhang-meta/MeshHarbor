// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! SOCKS5 front for the [netstack](super::netstack) — CONNECT + UDP ASSOCIATE.
//!
//! The app-facing half of the OS-free path: a localhost SOCKS5 proxy backed by
//! the userspace [`netstack`](super::netstack). Apps point at `127.0.0.1:<port>`
//! and reach overlay peers by **IP or by name** with **no OS routing** — nothing
//! touches the routing table a full-tunnel VPN captures.
//!
//! * **CONNECT** opens a smoltcp TCP socket to the target
//!   ([`NetstackHandle::connect`]) and splices the client stream to it (RDP /
//!   SSH / SQL / HTTP).
//! * **UDP ASSOCIATE** (RFC 1928 §7) binds a loopback relay socket, returns its
//!   address, and relays SOCKS-UDP-framed datagrams to/from a netstack UDP
//!   socket ([`NetstackHandle::udp_bind`]) for the association's lifetime (DNS /
//!   QUIC / game & VoIP traffic). The association lives as long as the app's TCP
//!   control connection.
//!
//! Target addressing (all three SOCKS5 `ATYP`, and the UDP header's):
//! * **IPv4** — a literal overlay address (`100.64.0.5`).
//! * **DOMAIN** — a peer **name** or MagicDNS FQDN (`devbox` /
//!   `devbox.myorg.roomler.net`), resolved to an overlay IPv4 from the live mesh
//!   view ([`resolve_overlay_host`]). MagicDNS-independent: it reads the
//!   netmap's `name → overlay-IP` directly, no DNS server / magic-domain needed.
//! * **IPv6** — a **derived overlay v6** (`fd72:6f6f:6d6c::<v4>`) dials over
//!   IPv6 end-to-end; an **IPv4-mapped** IPv6 (`::ffff:a.b.c.d`) is unwrapped to
//!   its embedded IPv4; any other IPv6 is not an overlay address and is
//!   rejected immediately (host-unreachable) rather than left to time out.
//!
//! The SOCKS5 request parse + UDP framing are shared with the tunnel's
//! [`crate::socks5`]; only the data plane (netstack vs tunnel transport)
//! differs. BIND is not supported.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tracing::{debug, warn};

use super::netstack::NetstackHandle;
use crate::localapi::OverlayView;
use crate::socks5::{self, Socks5Request};

// SOCKS5 reply-frame constants (RFC 1928). The request parse + UDP framing live
// in `crate::socks5`; these are just what our own success/failure replies need.
const VER: u8 = 0x05;
const ATYP_IPV4: u8 = 0x01;
const REP_SUCCESS: u8 = 0x00;
const REP_HOST_UNREACHABLE: u8 = 0x04;

/// Max SOCKS-UDP datagram we buffer off the relay socket (payload + header
/// slack). Datagrams larger than the overlay MTU fragment at the IP layer.
const UDP_RELAY_BUF: usize = 64 * 1024 + 512;

/// Resolve a SOCKS5 target host to an **overlay address** using the live mesh
/// `view`. Resolution order:
///
/// 1. a literal IPv4 string (`"100.64.0.2"`) — used as-is;
/// 2. a literal IPv6:
///    * **IPv4-mapped** (`"::ffff:a.b.c.d"`) — unwrapped to its embedded IPv4;
///    * a **derived overlay v6** (`"fd72:6f6f:6d6c::<v4>"`,
///      [`embedded_v4_of_overlay_v6`](super::router::embedded_v4_of_overlay_v6))
///      — kept as v6, so the dial exercises IPv6 end-to-end;
///    * anything else is not an overlay address ⇒ `None` — an instant
///      host-unreachable instead of a doomed connect that times out;
/// 3. an exact, case-insensitive match against a peer's name (`"devbox"`) — its
///    IPv4 (universal; every peer has one, v6 is derived from it);
/// 4. the first DNS label, so a MagicDNS FQDN (`"devbox.myorg.roomler.net"`)
///    resolves to the same peer as its bare label.
///
/// `None` if nothing matches. Names come straight from the netmap the runtime
/// already publishes, so this needs no DNS server and no magic-domain config.
fn resolve_overlay_host(view: &OverlayView, host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Some(IpAddr::V4(ip));
    }
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        if let Some(mapped) = v6.to_ipv4_mapped() {
            return Some(IpAddr::V4(mapped));
        }
        return super::router::embedded_v4_of_overlay_v6(v6)
            .is_some()
            .then_some(IpAddr::V6(v6));
    }
    let host_lc = host.to_ascii_lowercase();
    let bare = host_lc.split('.').next().unwrap_or(host_lc.as_str());
    view.peers.iter().find_map(|p| {
        if p.name.is_empty() {
            return None;
        }
        let name_lc = p.name.to_ascii_lowercase();
        if name_lc == host_lc || name_lc == bare {
            p.overlay_ip
                .as_deref()
                .and_then(|s| s.parse::<Ipv4Addr>().ok())
                .map(IpAddr::V4)
        } else {
            None
        }
    })
}

/// Serve SOCKS5 on `listener`, backed by **the current** netstack. `handles`
/// tracks the live [`NetstackHandle`] — `None` before the first netmap and
/// re-published on overlay reconnect (a fresh stack) — so the front outlives the
/// runtime's connect/reconnect cycle without rebinding the port. `view` is the
/// live mesh view (from the runtime's `peer_view`), used to resolve DOMAIN
/// targets to overlay IPs. Runs until the listener errors fatally; per-connection
/// failures are logged and dropped. Bind the listener to **loopback only** — the
/// proxy is never exposed on the overlay/LAN.
pub async fn serve_socks5(
    handles: watch::Receiver<Option<NetstackHandle>>,
    view: watch::Receiver<OverlayView>,
    listener: TcpListener,
) {
    loop {
        match listener.accept().await {
            Ok((client, _peer)) => {
                // Snapshot the current netstack; a client that arrives before
                // the mesh is up (or mid-reconnect) is simply dropped.
                let Some(h) = handles.borrow().clone() else {
                    debug!("netstack socks: no netstack up yet; dropping client");
                    continue;
                };
                // Snapshot the mesh view so name resolution reflects the netmap
                // at accept time (cheap: a small Vec of peers).
                let snapshot = view.borrow().clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(h, snapshot, client).await {
                        debug!(error = %e, "netstack socks: connection ended");
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "netstack socks: accept failed; stopping");
                break;
            }
        }
    }
}

/// One SOCKS5 client: shared method-negotiation + request parse
/// ([`crate::socks5::accept_request`]) → dispatch CONNECT vs UDP ASSOCIATE.
async fn handle_connection(
    handle: NetstackHandle,
    view: OverlayView,
    mut client: TcpStream,
) -> std::io::Result<()> {
    match socks5::accept_request(&mut client).await {
        Ok(Socks5Request::Connect { host, port }) => {
            connect_and_splice(handle, &view, client, &host, port).await
        }
        Ok(Socks5Request::UdpAssociate) => handle_udp_associate(handle, view, client).await,
        // `accept_request` already wrote the protocol-level failure reply.
        Err(e) => Err(std::io::Error::other(e.to_string())),
    }
}

/// CONNECT: resolve the target → open a netstack TCP stream → splice.
async fn connect_and_splice(
    handle: NetstackHandle,
    view: &OverlayView,
    mut client: TcpStream,
    host: &str,
    port: u16,
) -> std::io::Result<()> {
    let Some(ip) = resolve_overlay_host(view, host) else {
        debug!(%host, "netstack socks: no overlay peer for CONNECT target");
        reply(&mut client, REP_HOST_UNREACHABLE).await;
        return Err(std::io::Error::other("unknown overlay host"));
    };
    let dst = SocketAddr::new(ip, port);
    let mut upstream = match handle.connect(dst).await {
        Ok(s) => s,
        Err(e) => {
            reply(&mut client, REP_HOST_UNREACHABLE).await;
            return Err(e);
        }
    };
    reply(&mut client, REP_SUCCESS).await;
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map(|_| ())
}

/// UDP ASSOCIATE (RFC 1928 §7): bind a loopback relay socket, reply with its
/// address, then relay SOCKS-UDP datagrams between the app and a netstack UDP
/// socket until the app's TCP control connection closes.
async fn handle_udp_associate(
    handle: NetstackHandle,
    view: OverlayView,
    mut client: TcpStream,
) -> std::io::Result<()> {
    // One netstack UDP socket backs the whole association (connectionless — each
    // datagram carries its own overlay destination).
    let mut ns_udp = handle.udp_bind().await?;
    let ns_tx = ns_udp.sender();

    // The loopback socket the app sends its SOCKS-UDP-framed datagrams to.
    let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let relay_addr = relay.local_addr()?;
    socks5::reply_bound(&mut client, socks5::REP_SUCCESS, relay_addr).await;
    debug!(%relay_addr, "netstack socks: UDP ASSOCIATE relay bound");

    // The app's source addr, latched on the first datagram (RFC 1928): return
    // datagrams go here; datagrams from other sources are dropped.
    let mut app_src: Option<SocketAddr> = None;
    let mut buf = vec![0u8; UDP_RELAY_BUF];

    loop {
        tokio::select! {
            // The TCP control connection closing ends the association.
            r = drain_control(&mut client) => {
                debug!(?r, "netstack socks: UDP control closed; ending association");
                break;
            }
            // app → overlay
            recvd = relay.recv_from(&mut buf) => {
                let (n, from) = match recvd {
                    Ok(x) => x,
                    Err(e) => { warn!(%e, "netstack socks: udp relay recv failed"); break; }
                };
                let src = *app_src.get_or_insert(from);
                if from != src {
                    continue; // a stray sender — ignore
                }
                let (host, port, off) = match socks5::parse_udp_datagram(&buf[..n]) {
                    Ok(x) => x,
                    Err(e) => { debug!(%e, "netstack socks: malformed udp datagram — dropping"); continue; }
                };
                let Some(ip) = resolve_overlay_host(&view, &host) else {
                    debug!(%host, "netstack socks: udp target not an overlay peer — dropping");
                    continue;
                };
                let _ = ns_tx.send_to(&buf[off..n], SocketAddr::new(ip, port)).await;
            }
            // overlay → app
            got = ns_udp.recv_from() => {
                let (data, src) = match got {
                    Ok(x) => x,
                    Err(_) => break, // netstack gone
                };
                if let Some(app) = app_src {
                    let framed = socks5::encode_udp_datagram(&src.ip().to_string(), src.port(), &data);
                    let _ = relay.send_to(&framed, app).await;
                }
            }
        }
    }
    // Dropping `ns_udp` + `ns_tx` closes the netstack UDP socket (the poll loop
    // reaps it); dropping `relay` frees the loopback port.
    Ok(())
}

/// Read + discard the SOCKS control connection until EOF/error. RFC 1928 says
/// nothing meaningful flows on it after the ASSOCIATE reply; its close is the
/// association's teardown signal.
async fn drain_control(tcp: &mut TcpStream) -> std::io::Result<()> {
    let mut b = [0u8; 256];
    loop {
        match tcp.read(&mut b).await {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(e) => return Err(e),
        }
    }
}

/// SOCKS5 reply with a zero BND.ADDR/PORT (`IPv4 0.0.0.0:0`, which every client
/// accepts). Best-effort — a write failure just means the client vanished.
async fn reply(client: &mut TcpStream, rep: u8) {
    let _ = client
        .write_all(&[VER, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await;
}

#[cfg(test)]
mod tests {
    //! End-to-end over an L3 cross-link between two netstacks (the WG-bridge leg
    //! is covered by `netstack::tests::bridge_tcp_echo_over_wireguard`):
    //! * CONNECT by literal IP and by resolved peer name → TCP echo.
    //! * UDP ASSOCIATE addressing a peer by name → UDP echo.

    use super::*;
    use crate::localapi::{ConnectionType, PeerInfo};
    use crate::overlay::netstack::{Netstack, NsTcpStream};
    use crate::overlay::tun::TunIo;
    use crate::socks5::CMD_UDP_ASSOCIATE;
    use std::time::Duration;

    const CMD_CONNECT: u8 = 0x01;
    const ATYP_DOMAIN: u8 = 0x03;
    const ATYP_IPV6: u8 = 0x04;

    /// Pump every packet A emits into B and vice-versa (L3 loopback, no WG).
    fn crosslink(a: &Netstack, b: &Netstack) {
        let (a1, b1) = (a.tun.clone(), b.tun.clone());
        tokio::spawn(async move {
            while let Ok(p) = a1.read_packet().await {
                if b1.write_packet(&p).await.is_err() {
                    break;
                }
            }
        });
        let (a2, b2) = (a.tun.clone(), b.tun.clone());
        tokio::spawn(async move {
            while let Ok(p) = b2.read_packet().await {
                if a2.write_packet(&p).await.is_err() {
                    break;
                }
            }
        });
    }

    async fn echo(stream: NsTcpStream) {
        let (mut r, mut w) = tokio::io::split(stream);
        let _ = tokio::io::copy(&mut r, &mut w).await;
        let _ = w.shutdown().await;
    }

    fn peer(name: &str, ip: &str) -> PeerInfo {
        PeerInfo {
            node_id: "0".repeat(24),
            name: name.into(),
            org: String::new(),
            overlay_ip: Some(ip.into()),
            overlay_ip6: None,
            online: true,
            connection: ConnectionType::Direct,
            upgrading: false,
            stalled: false,
            rtt_ms: None,
            last_seen_ms: None,
            agent_id: None,
            relay_local: None,
            relay_dst: None,
            relay_kind: None,
            relay_transport: None,
            relay_server: None,
            why: None,
            probes: Vec::new(),
            debug: None,
        }
    }

    #[test]
    fn resolves_ip_name_fqdn_and_v6_forms() {
        use crate::overlay::router::derive_overlay_v6;

        let view = OverlayView {
            path_trials: None,
            self_ip: Some("100.64.0.1".into()),
            self_ip6: None,
            peers: vec![
                peer("DEVBOX", "100.64.0.2"),
                peer("winhost-a", "100.64.0.4"),
            ],
            exit_node: None,
            route_offer_withheld: None,
            host_firewall: None,
            dns: None,
            srflx: None,
            warm_relay: None,
            direct_socks: Vec::new(),
            derp_inbound_drops: None,
        };
        assert_eq!(
            resolve_overlay_host(&view, "100.64.0.9"),
            Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)))
        );
        assert_eq!(
            resolve_overlay_host(&view, "devbox"),
            Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)))
        );
        assert_eq!(
            resolve_overlay_host(&view, "WINHOST-A.myorg.roomler.net"),
            Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 4)))
        );
        // IPv4-mapped IPv6 literal → embedded overlay IPv4.
        assert_eq!(
            resolve_overlay_host(&view, "::ffff:100.64.0.7"),
            Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 7)))
        );
        // A DERIVED overlay v6 literal stays v6 (dials over IPv6 end-to-end).
        let d6 = derive_overlay_v6(Ipv4Addr::new(100, 64, 0, 2));
        assert_eq!(
            resolve_overlay_host(&view, &d6.to_string()),
            Some(IpAddr::V6(d6))
        );
        // A non-overlay IPv6 → instant unreachable; unknown name → miss.
        assert_eq!(resolve_overlay_host(&view, "2001:db8::1"), None);
        assert_eq!(resolve_overlay_host(&view, "ghost"), None);
    }

    async fn socks_greet(c: &mut TcpStream) {
        c.write_all(&[VER, 0x01, 0x00]).await.unwrap();
        let mut mr = [0u8; 2];
        c.read_exact(&mut mr).await.unwrap();
        assert_eq!(mr, [VER, 0x00], "server must select no-auth");
    }

    /// Drive one SOCKS5 CONNECT (by the given ATYP frame) and assert the echo
    /// round-trips. `addr_frame` is everything from ATYP through DST.PORT.
    async fn connect_round_trip(socks_addr: std::net::SocketAddr, addr_frame: &[u8]) {
        let mut c = TcpStream::connect(socks_addr).await.unwrap();
        socks_greet(&mut c).await;
        let mut req = vec![VER, CMD_CONNECT, 0x00];
        req.extend_from_slice(addr_frame);
        c.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        c.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], REP_SUCCESS, "CONNECT must succeed");
        c.write_all(b"socks-over-netstack").await.unwrap();
        let mut got = vec![0u8; b"socks-over-netstack".len()];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"socks-over-netstack");
    }

    /// A + B netstacks cross-linked, B's SOCKS front on a loopback port, a view
    /// that names B as "peerb". Returns (A, B, socks_addr) and keeps the stacks
    /// + watch senders alive via the returned tuple.
    async fn setup(
        a_ip: Ipv4Addr,
        b_ip: Ipv4Addr,
    ) -> (Netstack, Netstack, std::net::SocketAddr, impl Sized) {
        let a = Netstack::start(a_ip, 24, 1280);
        let b = Netstack::start(b_ip, 24, 1280);
        crosslink(&a, &b);
        let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks.local_addr().unwrap();
        let (handle_tx, handle_rx) = watch::channel(Some(a.handle.clone()));
        let (view_tx, view_rx) = watch::channel(OverlayView {
            path_trials: None,
            self_ip: Some(a_ip.to_string()),
            self_ip6: None,
            peers: vec![peer("peerb", &b_ip.to_string())],
            exit_node: None,
            route_offer_withheld: None,
            host_firewall: None,
            dns: None,
            srflx: None,
            warm_relay: None,
            direct_socks: Vec::new(),
            derp_inbound_drops: None,
        });
        tokio::spawn(serve_socks5(handle_rx, view_rx, socks));
        (a, b, socks_addr, (handle_tx, view_tx))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn socks5_connect_by_ip_and_by_name() {
        let a_ip = Ipv4Addr::new(10, 20, 0, 1);
        let b_ip = Ipv4Addr::new(10, 20, 0, 2);
        let (_a, b, socks_addr, _keep) = setup(a_ip, b_ip).await;

        // B echoes on 4000 (accepts repeatedly for the two CONNECTs below).
        let mut listener = b.handle.listen(4000).await.unwrap();
        tokio::spawn(async move {
            while let Some(s) = listener.accept().await {
                tokio::spawn(echo(s));
            }
        });
        let _b = b;

        // (1) by literal IPv4.
        let ip = b_ip.octets();
        let by_ip = [ATYP_IPV4, ip[0], ip[1], ip[2], ip[3], 0x0f, 0xa0]; // :4000
        // (2) by name "peerb" (ATYP_DOMAIN).
        let name = b"peerb";
        let mut by_name = vec![ATYP_DOMAIN, name.len() as u8];
        by_name.extend_from_slice(name);
        by_name.extend_from_slice(&4000u16.to_be_bytes());
        // (3) by B's DERIVED overlay v6 (a genuine ATYP_IPV6 frame) — the
        // whole splice runs over IPv6 inside the netstack.
        let d6 = crate::overlay::router::derive_overlay_v6(b_ip).octets();
        let mut by_v6 = vec![ATYP_IPV6];
        by_v6.extend_from_slice(&d6);
        by_v6.extend_from_slice(&4000u16.to_be_bytes());

        tokio::time::timeout(Duration::from_secs(15), async {
            connect_round_trip(socks_addr, &by_ip).await;
            connect_round_trip(socks_addr, &by_name).await;
            connect_round_trip(socks_addr, &by_v6).await;
        })
        .await
        .expect("all three socks round trips in time");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn socks5_udp_associate_by_name() {
        let a_ip = Ipv4Addr::new(10, 22, 0, 1);
        let b_ip = Ipv4Addr::new(10, 22, 0, 2);
        let (_a, b, socks_addr, _keep) = setup(a_ip, b_ip).await;

        // B: a UDP echo — bounce each datagram back to its source.
        let mut b_udp = b.handle.udp_bind().await.unwrap();
        let b_port = b_udp.local_port();
        let b_tx = b_udp.sender();
        tokio::spawn(async move {
            while let Ok((data, src)) = b_udp.recv_from().await {
                let _ = b_tx.send_to(&data, src).await;
            }
        });
        let _b = b;

        let body = async {
            // TCP control: greet + UDP ASSOCIATE, read the relay bind addr.
            let mut ctl = TcpStream::connect(socks_addr).await.unwrap();
            socks_greet(&mut ctl).await;
            ctl.write_all(&[VER, CMD_UDP_ASSOCIATE, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut rep = [0u8; 10];
            ctl.read_exact(&mut rep).await.unwrap();
            assert_eq!(rep[1], REP_SUCCESS, "UDP ASSOCIATE must succeed");
            let relay = SocketAddr::from((
                Ipv4Addr::new(rep[4], rep[5], rep[6], rep[7]),
                u16::from_be_bytes([rep[8], rep[9]]),
            ));

            // App UDP socket → send a SOCKS-UDP datagram addressing B by NAME.
            let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let framed = socks5::encode_udp_datagram("peerb", b_port, b"ping-udp");
            app.send_to(&framed, relay).await.unwrap();

            // Read the echoed datagram back (SOCKS-UDP framed).
            let mut rbuf = vec![0u8; 2048];
            let (n, _) = app.recv_from(&mut rbuf).await.unwrap();
            let (_h, _p, off) = socks5::parse_udp_datagram(&rbuf[..n]).unwrap();
            assert_eq!(&rbuf[off..n], b"ping-udp");
            drop(ctl); // closing control ends the association
        };
        tokio::time::timeout(Duration::from_secs(10), body)
            .await
            .expect("udp associate round trip in time");
    }
}
