// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! MeshHarbor §6 item 5 — UDP port mapping on the local gateway: PCP
//! (RFC 6887) first, NAT-PMP (RFC 6886) next, UPnP IGD ([`upnp`]) last.
//!
//! A mapped port is an inbound-reachable `public_ip:port` for one of this
//! node's direct sockets. Hole punching needs one end whose NAT does not care
//! which remote it talks to; a mapping is exactly that by construction, so a
//! peer behind a symmetric NAT can still reach this node directly. The
//! reference is Tailscale's portmapper, which tries the same three.
//!
//! Scope: the two wire protocols, one request/response exchange each, the
//! checks that make a result safe to advertise, and [`PortMapper`], the
//! long-lived holder the srflx keepalive owns (refresh at half the granted
//! lifetime, retry after a loss, release on a clean exit). [`advert`] and
//! [`advert_nat`] turn a held mapping into what the srflx advert carries.
//!
//! Rails:
//! * the external address must be public ([`is_public_v4`]). A gateway behind
//!   a second NAT or a CGNAT hands out a private one that no peer can dial, so
//!   that mapping is released and refused;
//! * a response must echo its request (PCP: nonce, protocol and internal port;
//!   NAT-PMP: opcode and internal port) and come from the gateway itself (the
//!   socket is connected), so a stray datagram cannot install an endpoint;
//! * waits are short: a gateway that speaks neither protocol costs at most
//!   2 × `wait`, and an ICMP port-unreachable ends an attempt at once;
//! * the PCP nonce is keyed, not random ([`nonce_for`]). The direct port is
//!   stable across restarts, and a gateway refuses a MAP for a port it already
//!   maps under another nonce (`NOT_AUTHORIZED`, for the rest of the old
//!   mapping's lifetime). With the same nonce, a restart or a plane rebuild
//!   re-requesting the port is a refresh.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::net::UdpSocket;
use tracing::{debug, info};

use super::direct::is_public_v4;

mod upnp;

/// The gateway port both protocols listen on.
pub const SERVER_PORT: u16 = 5351;
/// Requested mapping lifetime; RFC 6886 recommends 7200 s.
pub const DEFAULT_LIFETIME_SECS: u32 = 7200;
/// Per-attempt wait. A silent gateway costs at most 2 × this (PCP, then
/// NAT-PMP), and the gather runs it alongside the NAT-type probe.
pub const WAIT: Duration = Duration::from_millis(500);
/// After a held mapping is lost, how long before asking the gateway again.
const RETRY_AFTER_LOSS: Duration = Duration::from_secs(300);

/// `OVERLAY_PORTMAP` (default on): ask the gateway to map the punch socket's
/// port, and advertise the mapping first among the srflx candidates.
pub fn enabled() -> bool {
    crate::env::flag("OVERLAY_PORTMAP", true)
}

/// The PCP nonce for `local:internal_port`, keyed by this node's secret so it
/// is the same across restarts and unguessable to anyone else (RFC 6887 §11.2
/// only needs it unpredictable).
pub fn nonce_for(key: &[u8], local: Ipv4Addr, internal_port: u16) -> [u8; 12] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(b"meshharbor-pcp-nonce-v1");
    m.update(&local.octets());
    m.update(&internal_port.to_be_bytes());
    let tag = m.finalize().into_bytes();
    let mut n = [0u8; 12];
    n.copy_from_slice(&tag[..12]);
    n
}

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
    Upnp,
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
    /// (RFC 6887 §11.2, §15). Zero for NAT-PMP and UPnP.
    nonce: [u8; 12],
    /// UPnP: the IGD service that holds it (refresh and delete go there).
    upnp: Option<upnp::Ctl>,
}

/// Map `internal_port` (a UDP socket this host bound on `local`) on
/// `gateway`: PCP first, then NAT-PMP when PCP gets no usable answer. `prev`
/// refreshes an existing mapping (same protocol and nonce, its external port
/// suggested). `nonce` is the PCP nonce for a new mapping (random when
/// `None`). `None` means no gateway support, a refusal, or an external
/// address no peer could dial.
pub async fn map_udp(
    gateway: SocketAddrV4,
    local: Ipv4Addr,
    internal_port: u16,
    prev: Option<&Mapping>,
    nonce: Option<[u8; 12]>,
    lifetime: u32,
    wait: Duration,
) -> Option<Mapping> {
    let (sock, client) = gateway_socket(gateway, local).await?;
    let pcp = match prev.map(|p| p.proto) {
        Some(Proto::NatPmp) => None,
        _ => pcp_map(&sock, client, internal_port, prev, nonce, lifetime, wait).await,
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
    if m.proto == Proto::Upnp {
        return upnp::unmap(m).await;
    }
    match gateway_socket(gateway, local).await {
        Some((sock, client)) => unmap_on(&sock, client, m, wait).await,
        None => false,
    }
}

/// A mapping held for the punch socket's port, owned by the srflx keepalive
/// (legacy runtime or carrier plane). It exists only once a gateway has
/// granted one: a host whose gateway never answers (most cloud VMs) gets no
/// mapper and pays no further probes.
pub struct PortMapper {
    gateway: SocketAddrV4,
    ssdp: upnp::Ssdp,
    local: Ipv4Addr,
    port: u16,
    nonce: [u8; 12],
    mapping: Option<Mapping>,
    /// When [`poll`](Self::poll) next talks to the gateway: half the granted
    /// lifetime, or [`RETRY_AFTER_LOSS`] after a loss.
    next: Instant,
}

impl PortMapper {
    /// Map `sock`'s port on the default IPv4 gateway. `None` when
    /// [`enabled`] is off, there is no gateway, nothing was granted, or the
    /// external IP is not one STUN saw in `srflx` (the gateway is not the
    /// NAT the peers would reach, e.g. it sits behind another one).
    pub async fn start(sock: &UdpSocket, srflx: &[String], key: &[u8]) -> Option<PortMapper> {
        if !enabled() {
            return None;
        }
        let gw = tokio::task::spawn_blocking(super::netstate::default_gateway_v4)
            .await
            .ok()
            .flatten()?;
        let ssdp = upnp::Ssdp {
            to: SocketAddrV4::new(gw, upnp::SSDP_PORT),
            multicast: true,
        };
        Self::start_at(SocketAddrV4::new(gw, SERVER_PORT), ssdp, sock, srflx, key).await
    }

    async fn start_at(
        gateway: SocketAddrV4,
        ssdp: upnp::Ssdp,
        sock: &UdpSocket,
        srflx: &[String],
        key: &[u8],
    ) -> Option<PortMapper> {
        let SocketAddr::V4(at) = sock.local_addr().ok()? else {
            return None;
        };
        let mut pm = PortMapper {
            gateway,
            ssdp,
            local: *at.ip(),
            port: at.port(),
            nonce: nonce_for(key, *at.ip(), at.port()),
            mapping: None,
            next: Instant::now(),
        };
        pm.poll(srflx).await;
        let m = pm.mapping.as_ref()?;
        info!(external = %m.external, proto = ?m.proto, internal_port = pm.port, %gateway,
            "overlay: gateway port mapping granted — advertised first among srflx candidates");
        Some(pm)
    }

    /// The external address peers can dial, while a mapping is held.
    pub fn external(&self) -> Option<SocketAddrV4> {
        self.mapping.as_ref().map(|m| m.external)
    }

    /// `"pcp 203.0.113.7:41641"` for the LocalAPI, while a mapping is held.
    pub fn describe(&self) -> Option<String> {
        self.mapping.as_ref().map(|m| {
            let p = match m.proto {
                Proto::Pcp => "pcp",
                Proto::NatPmp => "nat-pmp",
                Proto::Upnp => "upnp",
            };
            format!("{p} {}", m.external)
        })
    }

    /// Make the next [`poll`](Self::poll) talk to the gateway at once: the
    /// STUN mapping moved, so the gateway's external address may have too.
    pub fn recheck(&mut self) {
        self.next = Instant::now();
    }

    /// Talk to the gateway when due: refresh a held mapping, or ask again
    /// after a loss. `true` when the advertised external address changed
    /// (gained, lost or moved), so the caller re-advertises.
    pub async fn poll(&mut self, srflx: &[String]) -> bool {
        if Instant::now() < self.next {
            return false;
        }
        let before = self.external();
        let prev = self.mapping.as_ref();
        let got = if prev.is_some_and(|m| m.proto == Proto::Upnp) {
            upnp::map(self.ssdp, self.local, self.port, prev, DEFAULT_LIFETIME_SECS, WAIT).await
        } else {
            let pmp = map_udp(
                self.gateway,
                self.local,
                self.port,
                prev,
                Some(self.nonce),
                DEFAULT_LIFETIME_SECS,
                WAIT,
            )
            .await;
            match pmp {
                // UPnP only on a fresh ask: a PCP/NAT-PMP mapping that fails
                // to refresh is a loss, and the retry walks all three.
                None if prev.is_none() => {
                    upnp::map(self.ssdp, self.local, self.port, None, DEFAULT_LIFETIME_SECS, WAIT).await
                }
                other => other,
            }
        };
        self.mapping = match got {
            Some(m) if srflx_ip(srflx, *m.external.ip()) => {
                self.next = Instant::now() + m.lifetime / 2;
                Some(m)
            }
            Some(m) => {
                debug!(external = %m.external, ?srflx,
                    "portmap: the gateway's external IP is not the one STUN sees; releasing it");
                unmap_udp(self.gateway, self.local, &m, WAIT).await;
                self.next = Instant::now() + RETRY_AFTER_LOSS;
                None
            }
            None => {
                self.next = Instant::now() + RETRY_AFTER_LOSS;
                None
            }
        };
        if before.is_some() && self.mapping.is_none() {
            info!(old = ?before, "overlay: gateway port mapping lost — re-advertising without it");
        }
        self.external() != before
    }

    /// Release the held mapping (best effort, see [`unmap_udp`]).
    pub async fn release(&mut self) {
        if let Some(m) = self.mapping.take() {
            unmap_udp(self.gateway, self.local, &m, WAIT).await;
        }
    }
}

/// Where an srflx keepalive gets its gateway mapping.
pub enum Source {
    /// Map nothing (unit tests that do not exercise mapping).
    Off,
    /// The default IPv4 gateway, the PCP nonce keyed by this node's secret.
    DefaultGateway(Vec<u8>),
    /// A fixed gateway (tests).
    #[cfg(test)]
    At(SocketAddrV4, Vec<u8>),
}

impl Source {
    pub async fn start(&self, sock: &UdpSocket, srflx: &[String]) -> Option<PortMapper> {
        match self {
            Source::Off => None,
            Source::DefaultGateway(key) => PortMapper::start(sock, srflx, key).await,
            #[cfg(test)]
            Source::At(gw, key) => {
                // The fake PCP gateway ignores SSDP: no UPnP in these tests.
                let ssdp = upnp::Ssdp { to: *gw, multicast: false };
                PortMapper::start_at(*gw, ssdp, sock, srflx, key).await
            }
        }
    }
}

/// A fake PCP gateway on loopback that grants every MAP at `external`; for
/// the keepalive wiring tests elsewhere in the crate.
#[cfg(test)]
pub(crate) async fn fake_pcp_gateway(external: SocketAddrV4) -> SocketAddrV4 {
    tests::gateway(tests::Gw::Pcp(external)).await.0
}

/// Does `ip` appear among the srflx `ip:port` candidates?
fn srflx_ip(srflx: &[String], ip: Ipv4Addr) -> bool {
    srflx
        .iter()
        .filter_map(|c| c.parse::<SocketAddrV4>().ok())
        .any(|c| *c.ip() == ip)
}

/// The srflx advert: the held mapping first (peers dial index 0 first,
/// `direct::pick_public_endpoint`), then the STUN candidates, deduplicated.
pub fn advert(stun: &[String], pm: Option<&PortMapper>) -> Vec<String> {
    let mut out: Vec<String> = pm.and_then(PortMapper::external).map(|e| e.to_string()).into_iter().collect();
    for c in stun {
        if !out.contains(c) {
            out.push(c.clone());
        }
    }
    out
}

/// The NAT class to advertise: `cone` while a mapping is held. The mapping
/// accepts any remote, so a symmetric peer can reach us and the
/// both-symmetric punch skip must not fire.
pub fn advert_nat(nat: Option<String>, pm: Option<&PortMapper>) -> Option<String> {
    if pm.and_then(PortMapper::external).is_some() {
        Some("cone".to_string())
    } else {
        nat
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
    nonce: Option<[u8; 12]>,
    lifetime: u32,
    wait: Duration,
) -> Option<Mapping> {
    let nonce = prev
        .filter(|p| p.proto == Proto::Pcp)
        .map(|p| p.nonce)
        .or(nonce)
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
            upnp: None,
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
        upnp: None,
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
        Proto::Upnp => upnp::unmap(m).await,
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
    pub(super) enum Gw {
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
    pub(super) async fn gateway(kind: Gw) -> (SocketAddrV4, Arc<Mutex<Vec<Vec<u8>>>>) {
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
        let m = map_udp(gw, Ipv4Addr::LOCALHOST, 43648, None, None, DEFAULT_LIFETIME_SECS, WAIT)
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
        let m = map_udp(gw, Ipv4Addr::LOCALHOST, 43648, None, None, DEFAULT_LIFETIME_SECS, WAIT)
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
        assert_eq!(map_udp(gw, Ipv4Addr::LOCALHOST, 43648, None, None, DEFAULT_LIFETIME_SECS, WAIT).await, None);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "the map, then its release");
        assert_eq!(&seen[1][4..8], &[0, 0, 0, 0], "the release asks for lifetime 0");
        assert_eq!(&seen[1][24..36], &seen[0][24..36], "with the mapping's nonce");
    }

    #[tokio::test]
    async fn a_reply_for_another_nonce_installs_nothing() {
        let (gw, _) = gateway(Gw::WrongNonce).await;
        let wait = Duration::from_millis(200);
        assert_eq!(map_udp(gw, Ipv4Addr::LOCALHOST, 43648, None, None, DEFAULT_LIFETIME_SECS, wait).await, None);
    }

    #[tokio::test]
    async fn a_silent_gateway_costs_at_most_two_waits() {
        let (gw, seen) = gateway(Gw::Silent).await;
        let wait = Duration::from_millis(200);
        let t = Instant::now();
        assert_eq!(map_udp(gw, Ipv4Addr::LOCALHOST, 43648, None, None, DEFAULT_LIFETIME_SECS, wait).await, None);
        assert!(t.elapsed() < 2 * wait + Duration::from_millis(150), "took {:?}", t.elapsed());
        assert_eq!(seen.lock().unwrap().len(), 4, "two PCP sends, two NAT-PMP address sends");
    }

    #[tokio::test]
    async fn a_refresh_repeats_the_nonce_and_suggests_the_granted_port() {
        let (gw, seen) = gateway(Gw::Pcp(PUBLIC)).await;
        let first = map_udp(gw, Ipv4Addr::LOCALHOST, 43648, None, None, DEFAULT_LIFETIME_SECS, WAIT).await.unwrap();
        let again = map_udp(gw, Ipv4Addr::LOCALHOST, 43648, Some(&first), None, DEFAULT_LIFETIME_SECS, WAIT)
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
            let m = map_udp(gw, Ipv4Addr::LOCALHOST, 43648, None, None, DEFAULT_LIFETIME_SECS, WAIT).await.unwrap();
            assert!(unmap_udp(gw, Ipv4Addr::LOCALHOST, &m, WAIT).await, "{:?}", m.proto);
            let last = seen.lock().unwrap().last().cloned().unwrap();
            let lifetime = if m.proto == Proto::Pcp { &last[4..8] } else { &last[8..12] };
            assert_eq!(lifetime, &[0, 0, 0, 0], "{:?} release asks for lifetime 0", m.proto);
        }
    }

    const KEY: &[u8] = b"node-secret-for-tests";

    /// SSDP aimed at the fake PCP gateway, which ignores it: no UPnP.
    fn no_igd(gw: SocketAddrV4) -> upnp::Ssdp {
        upnp::Ssdp { to: gw, multicast: false }
    }

    #[tokio::test]
    async fn a_mapper_falls_back_to_upnp_when_pcp_and_natpmp_are_silent() {
        let (gw, _) = gateway(Gw::Silent).await;
        let (ssdp, seen) = upnp::tests::igd(upnp::tests::Igd::Grants).await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun = stun_at(upnp::tests::EXTERNAL);
        let mut pm = PortMapper::start_at(gw, ssdp, &sock, &stun, KEY).await.expect("mapped by UPnP");
        let port = sock.local_addr().unwrap().port();
        assert_eq!(pm.describe(), Some(format!("upnp {}:{port}", upnp::tests::EXTERNAL)));
        assert_eq!(advert(&stun, Some(&pm))[0], format!("{}:{port}", upnp::tests::EXTERNAL));
        pm.release().await;
        assert!(seen.lock().unwrap().last().unwrap().contains("#DeletePortMapping"));
    }

    fn stun_at(ip: Ipv4Addr) -> Vec<String> {
        vec![SocketAddrV4::new(ip, 5000).to_string()]
    }

    #[test]
    fn the_pcp_nonce_is_stable_per_port_and_keyed() {
        let ip = Ipv4Addr::new(192, 168, 1, 20);
        assert_eq!(nonce_for(KEY, ip, 45200), nonce_for(KEY, ip, 45200), "a restart repeats it");
        assert_ne!(nonce_for(KEY, ip, 45200), nonce_for(KEY, ip, 45201));
        assert_ne!(nonce_for(KEY, ip, 45200), nonce_for(b"another node", ip, 45200));
    }

    #[tokio::test]
    async fn a_mapper_advertises_its_mapping_first_and_as_cone() {
        let (gw, seen) = gateway(Gw::Pcp(PUBLIC)).await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun = stun_at(*PUBLIC.ip());
        let pm = PortMapper::start_at(gw, no_igd(gw), &sock, &stun, KEY).await.expect("mapped");
        assert_eq!(pm.external(), Some(PUBLIC));
        assert_eq!(pm.describe().as_deref(), Some("pcp 203.0.113.7:41641"));
        let port = sock.local_addr().unwrap().port();
        assert_eq!(&seen.lock().unwrap()[0][24..36], &nonce_for(KEY, Ipv4Addr::LOCALHOST, port));
        assert_eq!(advert(&stun, Some(&pm)), vec![PUBLIC.to_string(), stun[0].clone()]);
        let same = vec![stun[0].clone(), PUBLIC.to_string()];
        assert_eq!(advert(&same, Some(&pm)), vec![PUBLIC.to_string(), stun[0].clone()], "deduplicated");
        assert_eq!(advert(&stun, None), stun);
        assert_eq!(advert_nat(Some("symmetric".into()), Some(&pm)).as_deref(), Some("cone"));
        assert_eq!(advert_nat(Some("symmetric".into()), None).as_deref(), Some("symmetric"));
    }

    #[tokio::test]
    async fn a_mapping_on_an_ip_stun_does_not_see_is_released() {
        let (gw, seen) = gateway(Gw::Pcp(PUBLIC)).await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let other = stun_at(Ipv4Addr::new(198, 51, 100, 9));
        assert!(PortMapper::start_at(gw, no_igd(gw), &sock, &other, KEY).await.is_none());
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "the map, then its release");
        assert_eq!(&seen[1][4..8], &[0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn a_silent_gateway_yields_no_mapper() {
        let (gw, _) = gateway(Gw::Silent).await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(PortMapper::start_at(gw, no_igd(gw), &sock, &stun_at(*PUBLIC.ip()), KEY).await.is_none());
    }

    #[tokio::test]
    async fn poll_refreshes_when_due_and_reports_a_loss() {
        let (gw, seen) = gateway(Gw::Pcp(PUBLIC)).await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun = stun_at(*PUBLIC.ip());
        let mut pm = PortMapper::start_at(gw, no_igd(gw), &sock, &stun, KEY).await.unwrap();
        assert!(pm.next > Instant::now() + Duration::from_secs(3500), "refresh at half of 7200 s");
        assert!(!pm.poll(&stun).await, "not due: no change");
        assert_eq!(seen.lock().unwrap().len(), 1, "and no request");
        pm.next = Instant::now();
        assert!(!pm.poll(&stun).await, "a refresh to the same address is no change");
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 2);
            assert_eq!(&seen[1][24..36], &seen[0][24..36], "the refresh repeats the nonce");
        }
        let (silent, _) = gateway(Gw::Silent).await;
        pm.gateway = silent;
        pm.next = Instant::now();
        assert!(pm.poll(&stun).await, "a lost mapping is a change");
        assert_eq!((pm.external(), advert(&stun, Some(&pm))), (None, stun.clone()));
        assert!(pm.next > Instant::now() + Duration::from_secs(250), "retry later, not every tick");
    }

    /// Field check against the REAL default gateway (a miniupnpd lab, or a
    /// home router): map a fresh socket's port, print the result, wait for
    /// one datagram sent from outside to the external address, then release.
    /// `MH_PM_EXPECT_IP` is the gateway's external IP (it stands in for the
    /// STUN-seen srflx IP).
    #[tokio::test]
    #[ignore]
    async fn portmap_live_gateway() {
        let ip: Ipv4Addr = std::env::var("MH_PM_EXPECT_IP").expect("MH_PM_EXPECT_IP").parse().unwrap();
        let sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let t = Instant::now();
        let pm = PortMapper::start(&sock, &[format!("{ip}:1")], b"live-test").await;
        let took = t.elapsed().as_millis();
        let Some(mut pm) = pm else {
            println!("PORTMAP-LIVE none after {took} ms");
            return;
        };
        println!("PORTMAP-LIVE mapped {} after {took} ms", pm.describe().unwrap());
        let mut buf = [0u8; 256];
        match tokio::time::timeout(Duration::from_secs(10), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => println!(
                "PORTMAP-LIVE inbound {n} bytes from {from}: {}",
                String::from_utf8_lossy(&buf[..n])
            ),
            other => println!("PORTMAP-LIVE no inbound datagram ({other:?})"),
        }
        if std::env::var("MH_PM_RESTART").is_ok() {
            // A crash: no release. The restarted node binds the same port
            // and asks with the same keyed nonce (a refresh), while a random
            // nonce for that port is the case the key exists to avoid.
            let port = sock.local_addr().unwrap().port();
            drop((pm, sock));
            let sock = UdpSocket::bind(("0.0.0.0", port)).await.unwrap();
            let again = PortMapper::start(&sock, &[format!("{ip}:1")], b"live-test").await;
            println!("PORTMAP-LIVE restart same key: {:?}", again.as_ref().and_then(PortMapper::describe));
            let gw = SocketAddrV4::new(crate::overlay::netstate::default_gateway_v4().unwrap(), SERVER_PORT);
            let local = Ipv4Addr::UNSPECIFIED;
            let random = map_udp(gw, local, port, None, None, DEFAULT_LIFETIME_SECS, WAIT).await;
            println!("PORTMAP-LIVE restart random nonce: {:?}", random.as_ref().map(|m| (m.proto, m.external)));
            // miniupnpd 2.3.9 lets the random nonce take the mapping over and
            // then refuses a delete under any other nonce, so release with it.
            let released = match &random {
                Some(m) => unmap_udp(gw, local, m, WAIT).await,
                None => match again {
                    Some(mut pm) => {
                        pm.release().await;
                        true
                    }
                    None => false,
                },
            };
            println!("PORTMAP-LIVE released {released}");
            return;
        }
        pm.release().await;
        println!("PORTMAP-LIVE released");
    }
}
