// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! MeshHarbor §6 item 5 — UDP port mapping on the local gateway: PCP
//! (RFC 6887) first, NAT-PMP (RFC 6886) as the fallback.
//!
//! A mapped port is an inbound-reachable `public_ip:port` for one of this
//! node's direct sockets. Hole punching needs one end whose NAT does not care
//! which remote it talks to; a mapping is exactly that by construction, so a
//! peer behind a symmetric NAT can still reach this node directly. The
//! reference is Tailscale's portmapper; UPnP IGD is not implemented here.
//!
//! Scope: the two wire protocols, one request/response exchange each, and the
//! checks that make a result safe to advertise. Nothing here is long-lived:
//! the caller owns refresh (at half the granted lifetime, passing the old
//! [`Mapping`] back to [`map_udp`]) and release ([`unmap_udp`]).
//!
//! Rails:
//! * the external address must be public ([`is_public_v4`]). A gateway behind
//!   a second NAT or a CGNAT hands out a private one that no peer can dial, so
//!   that mapping is released and refused;
//! * a response must echo its request (PCP: nonce, protocol and internal port;
//!   NAT-PMP: opcode and internal port) and come from the gateway itself (the
//!   socket is connected), so a stray datagram cannot install an endpoint;
//! * waits are short: a gateway that speaks neither protocol costs at most
//!   2 × `wait`, and an ICMP port-unreachable ends an attempt at once.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;
use tracing::debug;

use super::direct::is_public_v4;

/// The gateway port both protocols listen on.
pub const SERVER_PORT: u16 = 5351;
/// Requested mapping lifetime; RFC 6886 recommends 7200 s.
pub const DEFAULT_LIFETIME_SECS: u32 = 7200;

const PCP_VERSION: u8 = 2;
const PCP_OP_MAP: u8 = 1;
const PCP_RESPONSE_BIT: u8 = 0x80;
const PCP_MAP_RESPONSE: u8 = PCP_RESPONSE_BIT | PCP_OP_MAP;
const PCP_MAP_LEN: usize = 60;
const PCP_UNSUPP_VERSION: u8 = 1;
const NATPMP_VERSION: u8 = 0;
const NATPMP_OP_ADDR: u8 = 0;
const NATPMP_OP_MAP_UDP: u8 = 1;
const IPPROTO_UDP: u8 = 17;
/// Largest PCP message (RFC 6887 §7); NAT-PMP replies are far smaller.
const MAX_REPLY: usize = 1100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Pcp,
    NatPmp,
}

/// A granted mapping: `external` on the gateway forwards to `internal_port`
/// on the address the request came from. Pass it back to [`map_udp`] to
/// refresh it and to [`unmap_udp`] to release it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub proto: Proto,
    pub internal_port: u16,
    pub external: SocketAddrV4,
    pub lifetime: Duration,
    /// PCP ties a mapping to its nonce: a refresh or a delete must repeat it
    /// (RFC 6887 §11.2, §15). Zero for NAT-PMP.
    nonce: [u8; 12],
}

/// Map `internal_port` (a UDP socket this host bound on `local`) on
/// `gateway`: PCP first, then NAT-PMP when PCP gets no usable answer. `prev`
/// refreshes an existing mapping (same protocol and nonce, its external port
/// suggested). `None` means no gateway support, a refusal, or an external
/// address no peer could dial.
pub async fn map_udp(
    gateway: SocketAddrV4,
    local: Ipv4Addr,
    internal_port: u16,
    prev: Option<&Mapping>,
    lifetime: u32,
    wait: Duration,
) -> Option<Mapping> {
    let (sock, client) = gateway_socket(gateway, local).await?;
    let pcp = match prev.map(|p| p.proto) {
        Some(Proto::NatPmp) => None,
        _ => pcp_map(&sock, client, internal_port, prev, lifetime, wait).await,
    };
    let m = match pcp {
        Some(m) => m,
        None => natpmp_map(&sock, internal_port, prev, lifetime, wait).await?,
    };
    if !is_public_v4(*m.external.ip()) || m.external.port() == 0 {
        debug!(
            external = %m.external,
            "portmap: the gateway mapped to an address no peer can dial (a second NAT?); releasing it"
        );
        unmap_on(&sock, client, &m, wait).await;
        return None;
    }
    Some(m)
}

/// Release `m` (a lifetime-0 request). Best effort: a lost release only leaves
/// the gateway to expire the mapping at the end of its lifetime.
pub async fn unmap_udp(gateway: SocketAddrV4, local: Ipv4Addr, m: &Mapping, wait: Duration) -> bool {
    match gateway_socket(gateway, local).await {
        Some((sock, client)) => unmap_on(&sock, client, m, wait).await,
        None => false,
    }
}

/// A socket connected to the gateway, and the source address the gateway
/// sees, which PCP's client-address field must repeat (else
/// `ADDRESS_MISMATCH`).
async fn gateway_socket(gateway: SocketAddrV4, local: Ipv4Addr) -> Option<(UdpSocket, Ipv4Addr)> {
    let sock = UdpSocket::bind(SocketAddrV4::new(local, 0)).await.ok()?;
    sock.connect(gateway).await.ok()?;
    match sock.local_addr().ok()? {
        SocketAddr::V4(a) => Some((sock, *a.ip())),
        SocketAddr::V6(_) => None,
    }
}

async fn pcp_map(
    sock: &UdpSocket,
    client: Ipv4Addr,
    internal_port: u16,
    prev: Option<&Mapping>,
    lifetime: u32,
    wait: Duration,
) -> Option<Mapping> {
    let nonce = prev
        .filter(|p| p.proto == Proto::Pcp)
        .map(|p| p.nonce)
        .unwrap_or_else(rand::random);
    let suggested = SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        prev.map_or(internal_port, |p| p.external.port()),
    );
    let req = pcp_map_request(client, nonce, internal_port, suggested, lifetime);
    match attempts(sock, &req, wait, |b| parse_pcp_map_response(b, &nonce, internal_port)).await? {
        PcpReply::Mapped { external, lifetime } => Some(Mapping {
            proto: Proto::Pcp,
            internal_port,
            external,
            lifetime: Duration::from_secs(lifetime.into()),
            nonce,
        }),
        PcpReply::TryNatPmp => None,
        PcpReply::Refused(code) => {
            debug!(code, "portmap: PCP refused the mapping");
            None
        }
    }
}

async fn natpmp_map(
    sock: &UdpSocket,
    internal_port: u16,
    prev: Option<&Mapping>,
    lifetime: u32,
    wait: Duration,
) -> Option<Mapping> {
    // A NAT-PMP mapping reply carries no address; ask for it first.
    let ip = attempts(sock, &[NATPMP_VERSION, NATPMP_OP_ADDR], wait, parse_natpmp_addr_response).await?;
    let suggested = prev.map_or(internal_port, |p| p.external.port());
    let req = natpmp_map_request(internal_port, suggested, lifetime);
    let (port, granted) =
        attempts(sock, &req, wait, |b| parse_natpmp_map_response(b, internal_port)).await?;
    Some(Mapping {
        proto: Proto::NatPmp,
        internal_port,
        external: SocketAddrV4::new(ip, port),
        lifetime: Duration::from_secs(granted.into()),
        nonce: [0; 12],
    })
}

async fn unmap_on(sock: &UdpSocket, client: Ipv4Addr, m: &Mapping, wait: Duration) -> bool {
    match m.proto {
        // RFC 6887 §15: a MAP with lifetime 0 and the mapping's nonce.
        Proto::Pcp => {
            let any = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
            let req = pcp_map_request(client, m.nonce, m.internal_port, any, 0);
            matches!(
                attempts(sock, &req, wait, |b| parse_pcp_map_response(b, &m.nonce, m.internal_port)).await,
                Some(PcpReply::Mapped { .. })
            )
        }
        // RFC 6886 §3.4: lifetime 0 and suggested external port 0.
        Proto::NatPmp => {
            let req = natpmp_map_request(m.internal_port, 0, 0);
            attempts(sock, &req, wait, |b| parse_natpmp_map_response(b, m.internal_port))
                .await
                .is_some()
        }
    }
}

/// Up to two sends of `req`, each followed by up to `wait / 2` for a datagram
/// that `parse` accepts. An ICMP port-unreachable surfaces as a recv error on
/// the connected socket and ends that attempt early.
async fn attempts<T>(
    sock: &UdpSocket,
    req: &[u8],
    wait: Duration,
    mut parse: impl FnMut(&[u8]) -> Option<T>,
) -> Option<T> {
    let mut buf = [0u8; MAX_REPLY];
    for _ in 0..2 {
        sock.send(req).await.ok()?;
        let got = tokio::time::timeout(wait / 2, async {
            loop {
                let n = sock.recv(&mut buf).await.ok()?;
                if let Some(v) = parse(&buf[..n]) {
                    return Some(v);
                }
            }
        })
        .await;
        if let Ok(Some(v)) = got {
            return Some(v);
        }
    }
    None
}

/// RFC 6887 §7.1 common header + §11.1 MAP payload. `suggested` with an
/// unspecified address means "no address preference".
fn pcp_map_request(
    client: Ipv4Addr,
    nonce: [u8; 12],
    internal_port: u16,
    suggested: SocketAddrV4,
    lifetime: u32,
) -> [u8; PCP_MAP_LEN] {
    let mut b = [0u8; PCP_MAP_LEN];
    b[0] = PCP_VERSION;
    b[1] = PCP_OP_MAP;
    b[4..8].copy_from_slice(&lifetime.to_be_bytes());
    b[8..24].copy_from_slice(&client.to_ipv6_mapped().octets());
    b[24..36].copy_from_slice(&nonce);
    b[36] = IPPROTO_UDP;
    b[40..42].copy_from_slice(&internal_port.to_be_bytes());
    b[42..44].copy_from_slice(&suggested.port().to_be_bytes());
    b[44..60].copy_from_slice(&suggested.ip().to_ipv6_mapped().octets());
    b
}

#[derive(Debug, PartialEq, Eq)]
enum PcpReply {
    Mapped { external: SocketAddrV4, lifetime: u32 },
    /// A NAT-PMP-only gateway (it answers version 0) or a PCP
    /// `UNSUPP_VERSION`: NAT-PMP is the next thing to try.
    TryNatPmp,
    Refused(u8),
}

/// `None` discards the datagram: not a MAP response, or not the answer to
/// THIS request (RFC 6887 §11.3 matches on nonce, protocol and internal port).
fn parse_pcp_map_response(b: &[u8], nonce: &[u8; 12], internal_port: u16) -> Option<PcpReply> {
    // Version negotiation (RFC 6887 §9) answers with a header only, before
    // the server has parsed anything it could echo.
    if b.len() >= 4 && (b[0] == NATPMP_VERSION || b[3] == PCP_UNSUPP_VERSION) {
        return (b[1] == PCP_MAP_RESPONSE).then_some(PcpReply::TryNatPmp);
    }
    if b.len() < PCP_MAP_LEN || b[0] != PCP_VERSION || b[1] != PCP_MAP_RESPONSE {
        return None;
    }
    if b[24..36] != nonce[..] || b[36] != IPPROTO_UDP || u16::from_be_bytes([b[40], b[41]]) != internal_port {
        return None;
    }
    if b[3] != 0 {
        return Some(PcpReply::Refused(b[3]));
    }
    let mut ip = [0u8; 16];
    ip.copy_from_slice(&b[44..60]);
    // A delete's reply may carry no address; `map_udp`'s public check
    // refuses an unspecified one anyway.
    let ip = Ipv6Addr::from(ip).to_ipv4_mapped().unwrap_or(Ipv4Addr::UNSPECIFIED);
    Some(PcpReply::Mapped {
        external: SocketAddrV4::new(ip, u16::from_be_bytes([b[42], b[43]])),
        lifetime: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
    })
}

/// RFC 6886 §3.3: version, opcode 1 (UDP), reserved, internal port,
/// suggested external port, lifetime.
fn natpmp_map_request(internal_port: u16, suggested_port: u16, lifetime: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0] = NATPMP_VERSION;
    b[1] = NATPMP_OP_MAP_UDP;
    b[4..6].copy_from_slice(&internal_port.to_be_bytes());
    b[6..8].copy_from_slice(&suggested_port.to_be_bytes());
    b[8..12].copy_from_slice(&lifetime.to_be_bytes());
    b
}

/// RFC 6886 §3.2: `[0, 128, result(2), epoch(4), address(4)]`.
fn parse_natpmp_addr_response(b: &[u8]) -> Option<Ipv4Addr> {
    (b.len() >= 12
        && b[0] == NATPMP_VERSION
        && b[1] == 128 + NATPMP_OP_ADDR
        && b[2..4] == [0, 0])
        .then(|| Ipv4Addr::new(b[8], b[9], b[10], b[11]))
}

/// RFC 6886 §3.3: `[0, 129, result(2), epoch(4), internal(2), external(2),
/// lifetime(4)]`, for THIS internal port.
fn parse_natpmp_map_response(b: &[u8], internal_port: u16) -> Option<(u16, u32)> {
    (b.len() >= 16
        && b[0] == NATPMP_VERSION
        && b[1] == 128 + NATPMP_OP_MAP_UDP
        && b[2..4] == [0, 0]
        && u16::from_be_bytes([b[8], b[9]]) == internal_port)
        .then(|| {
            (
                u16::from_be_bytes([b[10], b[11]]),
                u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    const WAIT: Duration = Duration::from_millis(400);
    const PUBLIC: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 41641);

    #[derive(Clone, Copy)]
    enum Gw {
        /// Answers PCP; ignores NAT-PMP.
        Pcp(SocketAddrV4),
        /// Answers PCP with NAT-PMP "unsupported version", then NAT-PMP.
        NatPmp(SocketAddrV4),
        /// Answers PCP, but with another request's nonce.
        WrongNonce,
        Silent,
    }

    fn answer(kind: Gw, req: &[u8]) -> Option<Vec<u8>> {
        let epoch = 1234u32.to_be_bytes();
        match (kind, req.first()) {
            (Gw::Pcp(_) | Gw::WrongNonce, Some(&PCP_VERSION)) => {
                let ext = if let Gw::Pcp(e) = kind { e } else { PUBLIC };
                let mut b = req[..PCP_MAP_LEN].to_vec();
                b[1] = PCP_MAP_RESPONSE;
                b[3] = 0;
                b[8..12].copy_from_slice(&epoch);
                b[12..24].fill(0);
                b[42..44].copy_from_slice(&ext.port().to_be_bytes());
                b[44..60].copy_from_slice(&ext.ip().to_ipv6_mapped().octets());
                if matches!(kind, Gw::WrongNonce) {
                    b[24] ^= 0xff;
                }
                Some(b)
            }
            (Gw::NatPmp(_), Some(&PCP_VERSION)) => {
                let mut b = vec![NATPMP_VERSION, req[1] | PCP_RESPONSE_BIT, 0, 1];
                b.extend_from_slice(&epoch);
                Some(b)
            }
            (Gw::NatPmp(ext), Some(&NATPMP_VERSION)) if req.len() == 2 => {
                let mut b = vec![0, 128, 0, 0];
                b.extend_from_slice(&epoch);
                b.extend_from_slice(&ext.ip().octets());
                Some(b)
            }
            (Gw::NatPmp(ext), Some(&NATPMP_VERSION)) if req.len() == 12 => {
                let lifetime = &req[8..12];
                let port = if lifetime == [0, 0, 0, 0] { 0 } else { ext.port() };
                let mut b = vec![0, 129, 0, 0];
                b.extend_from_slice(&epoch);
                b.extend_from_slice(&req[4..6]);
                b.extend_from_slice(&port.to_be_bytes());
                b.extend_from_slice(lifetime);
                Some(b)
            }
            _ => None,
        }
    }

    /// A fake gateway on loopback; returns its address and every request it saw.
    async fn gateway(kind: Gw) -> (SocketAddrV4, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let SocketAddr::V4(addr) = sock.local_addr().unwrap() else {
            unreachable!()
        };
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; MAX_REPLY];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                log.lock().unwrap().push(buf[..n].to_vec());
                if let Some(reply) = answer(kind, &buf[..n]) {
                    let _ = sock.send_to(&reply, from).await;
                }
            }
        });
        (addr, seen)
    }

    #[test]
    fn a_pcp_map_request_has_the_rfc_layout() {
        let nonce = [7u8; 12];
        let b = pcp_map_request(
            Ipv4Addr::new(192, 168, 1, 20),
            nonce,
            43648,
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 43648),
            7200,
        );
        assert_eq!(&b[..4], &[2, 1, 0, 0]);
        assert_eq!(&b[4..8], &7200u32.to_be_bytes());
        assert_eq!(&b[8..24], &Ipv4Addr::new(192, 168, 1, 20).to_ipv6_mapped().octets());
        assert_eq!(&b[24..36], &nonce);
        assert_eq!(&b[36..40], &[17, 0, 0, 0]);
        assert_eq!(&b[40..44], &[0xaa, 0x80, 0xaa, 0x80]);
        assert_eq!(&b[44..60], &Ipv4Addr::UNSPECIFIED.to_ipv6_mapped().octets());
    }

    #[tokio::test]
    async fn a_pcp_gateway_grants_a_public_mapping() {
        let (gw, seen) = gateway(Gw::Pcp(PUBLIC)).await;
        let m = map_udp(gw, Ipv4Addr::LOCALHOST, 43648, None, DEFAULT_LIFETIME_SECS, WAIT)
            .await
            .expect("mapped");
        assert_eq!((m.proto, m.external, m.internal_port), (Proto::Pcp, PUBLIC, 43648));
        assert_eq!(m.lifetime, Duration::from_secs(7200));
        let req = seen.lock().unwrap()[0].clone();
        assert_eq!(&req[8..24], &Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets(), "client address = source");
        assert_eq!(&req[24..36], &m.nonce);
    }

    #[tokio::test]
    async fn a_natpmp_only_gateway_is_used_after_pcp_is_refused_by_version() {
        let (gw, seen) = gateway(Gw::NatPmp(PUBLIC)).await;
        let m = map_udp(gw, Ipv4Addr::LOCALHOST, 43648, None, DEFAULT_LIFETIME_SECS, WAIT)
            .await
            .expect("mapped");
        assert_eq!((m.proto, m.external), (Proto::NatPmp, PUBLIC));
        let firsts: Vec<u8> = seen.lock().unwrap().iter().map(|r| r[0]).collect();
        assert_eq!(firsts, [PCP_VERSION, NATPMP_VERSION, NATPMP_VERSION], "PCP once, then address + map");
    }

    #[tokio::test]
    async fn a_private_external_address_is_released_and_refused() {
        let inner = SocketAddrV4::new(Ipv4Addr::new(192, 168, 100, 2), 41641);
        let (gw, seen) = gateway(Gw::Pcp(inner)).await;
        assert_eq!(map_udp(gw, Ipv4Addr::LOCALHOST, 43648, None, DEFAULT_LIFETIME_SECS, WAIT).await, None);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "the map, then its release");
        assert_eq!(&seen[1][4..8], &[0, 0, 0, 0], "the release asks for lifetime 0");
        assert_eq!(&seen[1][24..36], &seen[0][24..36], "with the mapping's nonce");
    }

    #[tokio::test]
    async fn a_reply_for_another_nonce_installs_nothing() {
        let (gw, _) = gateway(Gw::WrongNonce).await;
        let wait = Duration::from_millis(200);
        assert_eq!(map_udp(gw, Ipv4Addr::LOCALHOST, 43648, None, DEFAULT_LIFETIME_SECS, wait).await, None);
    }

    #[tokio::test]
    async fn a_silent_gateway_costs_at_most_two_waits() {
        let (gw, seen) = gateway(Gw::Silent).await;
        let wait = Duration::from_millis(200);
        let t = Instant::now();
        assert_eq!(map_udp(gw, Ipv4Addr::LOCALHOST, 43648, None, DEFAULT_LIFETIME_SECS, wait).await, None);
        assert!(t.elapsed() < 2 * wait + Duration::from_millis(150), "took {:?}", t.elapsed());
        assert_eq!(seen.lock().unwrap().len(), 4, "two PCP sends, two NAT-PMP address sends");
    }

    #[tokio::test]
    async fn a_refresh_repeats_the_nonce_and_suggests_the_granted_port() {
        let (gw, seen) = gateway(Gw::Pcp(PUBLIC)).await;
        let first = map_udp(gw, Ipv4Addr::LOCALHOST, 43648, None, DEFAULT_LIFETIME_SECS, WAIT).await.unwrap();
        let again = map_udp(gw, Ipv4Addr::LOCALHOST, 43648, Some(&first), DEFAULT_LIFETIME_SECS, WAIT)
            .await
            .unwrap();
        assert_eq!(again, first);
        let seen = seen.lock().unwrap();
        assert_eq!(&seen[1][24..36], &seen[0][24..36], "same nonce");
        assert_eq!(&seen[1][42..44], &PUBLIC.port().to_be_bytes(), "suggests the granted port");
    }

    #[tokio::test]
    async fn unmap_releases_either_protocol() {
        for kind in [Gw::Pcp(PUBLIC), Gw::NatPmp(PUBLIC)] {
            let (gw, seen) = gateway(kind).await;
            let m = map_udp(gw, Ipv4Addr::LOCALHOST, 43648, None, DEFAULT_LIFETIME_SECS, WAIT).await.unwrap();
            assert!(unmap_udp(gw, Ipv4Addr::LOCALHOST, &m, WAIT).await, "{:?}", m.proto);
            let last = seen.lock().unwrap().last().cloned().unwrap();
            let lifetime = if m.proto == Proto::Pcp { &last[4..8] } else { &last[8..12] };
            assert_eq!(lifetime, &[0, 0, 0, 0], "{:?} release asks for lifetime 0", m.proto);
        }
    }
}
