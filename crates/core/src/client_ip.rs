// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Client-IP extraction that survives our reverse-proxy chain — the server's
//! ONE notion of "the client's address".
//!
//! `X-Forwarded-For` is append-only and anyone may seed it. A client that
//! sends `X-Forwarded-For: 1.2.3.4` makes the header arrive as
//! `1.2.3.4, <real client>, <our hop>`, so trusting the **left-most** entry —
//! which is what `tower_governor`'s `SmartIpKeyExtractor` does — hands every
//! caller a free rate-limit bypass with one header. Verified against prod on
//! 2026-07-28: a throttled `POST /api/auth/login` went straight back to 401
//! simply by adding `-H 'X-Forwarded-For: 203.0.113.77'`.
//!
//! Only the right-most entries are evidence, because only our own proxies
//! appended them. The prod chain is
//! `client → docker-nginx (records the client) → pod-nginx (appends its peer)`,
//! i.e. one hop is ours, so the client sits at `len - 2`.
//!
//! Every reader of a client address goes through here: the per-IP governor
//! and the credential gate (the api crate's `middleware::client_ip`, which
//! re-exports these), the `/ws` analytics session, and since FR-102 P3c the
//! install trace's internal-network check in `fleet` — which is why this
//! lives in core (FR-69: a module never names the api crate). Two rules for
//! one question would let a client be "internal" to one reader and someone
//! else to another.

use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, Request, request::Parts},
};

const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// Pick the client address out of `X-Forwarded-For`.
///
/// `trusted_hops` is how many entries our own proxies appended. Those are
/// dropped from the right and the next one is taken: the address the
/// outermost proxy *we control* actually observed.
///
/// Returns `None` — meaning "fall back to the peer address" — when the header
/// is missing, unparseable, or shorter than the trusted suffix. A short header
/// means the request did not traverse the expected chain, so nothing in it has
/// been vouched for. `trusted_hops == 0` (direct exposure, e.g. integration
/// tests) ignores the header outright.
pub fn client_ip_from_headers(headers: &HeaderMap, trusted_hops: usize) -> Option<IpAddr> {
    if trusted_hops == 0 {
        return None;
    }
    let raw = headers.get(X_FORWARDED_FOR)?.to_str().ok()?;
    let hops: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    // Drop our own hops, then take the last remaining entry.
    let idx = hops.len().checked_sub(trusted_hops + 1)?;
    hops.get(idx)?.parse().ok()
}

/// The vouched-for forwarded entry, else the socket peer the listener
/// recorded (`None` when neither exists — a request built in-process).
pub fn client_ip_or_peer(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    trusted_hops: usize,
) -> Option<IpAddr> {
    client_ip_from_headers(headers, trusted_hops).or_else(|| peer.map(|p| p.ip()))
}

/// Resolve the client address for a request, preferring the vouched-for
/// forwarded entry and falling back to the socket peer.
pub fn client_ip<T>(req: &Request<T>, trusted_hops: usize) -> Option<IpAddr> {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| *addr);
    client_ip_or_peer(req.headers(), peer, trusted_hops)
}

/// The socket peer the listener recorded (`into_make_service_with_connect_info`),
/// or `None` — an extractor that never refuses, so a handler that only
/// *counts* something cannot fail a request over a missing extension.
/// Pair it with the request's headers through [`client_ip_or_peer`].
#[derive(Debug, Clone, Copy)]
pub struct PeerAddr(pub Option<SocketAddr>);

impl<S> FromRequestParts<S> for PeerAddr
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(PeerAddr(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| *addr),
        ))
    }
}

/// How a business-policy source was established. This is deliberately separate
/// from the legacy analytics/rate-limit header helper above: a hop count alone
/// does not authenticate the socket peer or the header's trusted suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionOriginSource {
    SocketPeer,
    TrustedProxyChain,
    MissingPeer,
    InvalidProxyConfiguration,
    AmbiguousHeader,
    InvalidTrustedChain,
}

impl ConnectionOriginSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SocketPeer => "socket_peer",
            Self::TrustedProxyChain => "trusted_proxy_chain",
            Self::MissingPeer => "missing_peer",
            Self::InvalidProxyConfiguration => "invalid_proxy_configuration",
            Self::AmbiguousHeader => "ambiguous_header",
            Self::InvalidTrustedChain => "invalid_trusted_chain",
        }
    }
}

/// An immutable, server-captured connection observation, NOT a wire DTO or an
/// authorization grant. Owners pass it through upgrade/authentication; an agent
/// message cannot replace it. Only the security producer may persist its fields.
#[derive(Debug, Clone)]
pub struct ConnectionOrigin {
    transport_peer: Option<IpAddr>,
    client_ip: Option<IpAddr>,
    source: ConnectionOriginSource,
    captured_at: bson::DateTime,
}

impl ConnectionOrigin {
    const MAX_XFF_BYTES: usize = 8192;
    const MAX_XFF_ENTRIES: usize = 64;
    const MAX_TRUSTED_PROXIES: usize = 64;
    const MAX_TRUSTED_HOPS: usize = 32;

    pub fn capture(
        headers: &HeaderMap,
        peer: Option<SocketAddr>,
        trusted_proxy_cidrs: &[String],
        trusted_hops: usize,
    ) -> Self {
        use ipnet::IpNet;
        let transport_peer = peer.map(|p| canonical_ip(p.ip()));
        let mut result = Self {
            transport_peer,
            client_ip: None,
            source: ConnectionOriginSource::MissingPeer,
            captured_at: bson::DateTime::now(),
        };
        let Some(peer) = transport_peer else {
            return result;
        };
        if trusted_hops > Self::MAX_TRUSTED_HOPS
            || trusted_proxy_cidrs.len() > Self::MAX_TRUSTED_PROXIES
        {
            result.source = ConnectionOriginSource::InvalidProxyConfiguration;
            return result;
        }
        let mut proxies = Vec::with_capacity(trusted_proxy_cidrs.len());
        for raw in trusted_proxy_cidrs {
            let Ok(net) = raw.trim().parse::<IpNet>() else {
                result.source = ConnectionOriginSource::InvalidProxyConfiguration;
                return result;
            };
            // A global wildcard makes an attacker a trusted proxy. Operators
            // use canonical IPv4 CIDRs rather than mapped-IPv6 CIDR ambiguity.
            if net.prefix_len() == 0
                || matches!(net.network(), IpAddr::V6(v) if v.to_ipv4_mapped().is_some())
            {
                result.source = ConnectionOriginSource::InvalidProxyConfiguration;
                return result;
            }
            proxies.push(net);
        }
        let values: Vec<_> = headers.get_all(X_FORWARDED_FOR).iter().take(2).collect();
        if values.len() > 1
            || values
                .first()
                .is_some_and(|v| v.as_bytes().len() > Self::MAX_XFF_BYTES)
        {
            result.source = ConnectionOriginSource::AmbiguousHeader;
            return result;
        }
        let trusted = |ip: IpAddr| proxies.iter().any(|net| net.contains(&canonical_ip(ip)));
        if trusted_hops == 0 || !trusted(peer) {
            // An untrusted direct caller's forwarded claim cannot move it.
            result.client_ip = Some(peer);
            result.source = ConnectionOriginSource::SocketPeer;
            return result;
        }
        result.source = ConnectionOriginSource::InvalidTrustedChain;
        let Some(raw) = values.first().and_then(|v| v.to_str().ok()) else {
            return result;
        };
        let entries: Vec<_> = raw.split(',').map(str::trim).collect();
        if entries.len() > Self::MAX_XFF_ENTRIES
            || entries.iter().any(|s| s.is_empty())
            || entries.len() <= trusted_hops
        {
            return result;
        }
        let client_index = entries.len() - trusted_hops - 1;
        // Both the actual immediate peer AND every claimed trusted suffix hop
        // must be configured. Never fall back to a proxy's own address here.
        if !entries[client_index + 1..].iter().all(|s| {
            s.parse::<IpAddr>()
                .is_ok_and(|ip| trusted(canonical_ip(ip)))
        }) {
            return result;
        }
        let Ok(client) = entries[client_index].parse::<IpAddr>() else {
            return result;
        };
        result.client_ip = Some(canonical_ip(client));
        result.source = ConnectionOriginSource::TrustedProxyChain;
        result
    }

    pub fn client_ip(&self) -> Option<IpAddr> {
        self.client_ip
    }
    pub fn transport_peer(&self) -> Option<IpAddr> {
        self.transport_peer
    }
    pub fn source(&self) -> ConnectionOriginSource {
        self.source
    }
    pub fn captured_at(&self) -> bson::DateTime {
        self.captured_at
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(xff: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(X_FORWARDED_FOR, xff.parse().unwrap());
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The prod shape: docker-nginx recorded the client, pod-nginx appended
    /// itself.
    #[test]
    fn picks_client_behind_one_trusted_hop() {
        assert_eq!(
            client_ip_from_headers(&headers("203.0.113.9, 10.10.0.1"), 1),
            Some(ip("203.0.113.9"))
        );
    }

    /// The bug this module exists for: a spoofed left-most entry must be
    /// ignored, and the caller must land on their real address.
    #[test]
    fn spoofed_prefix_is_ignored() {
        let h = headers("1.2.3.4, 203.0.113.9, 10.10.0.1");
        assert_eq!(client_ip_from_headers(&h, 1), Some(ip("203.0.113.9")));

        // However many entries the attacker stuffs in, the answer is stable.
        let h = headers("9.9.9.9, 8.8.8.8, 1.1.1.1, 203.0.113.9, 10.10.0.1");
        assert_eq!(client_ip_from_headers(&h, 1), Some(ip("203.0.113.9")));
    }

    /// A header with only our own hop carries no client evidence, so the
    /// caller must fall through to the peer address rather than key everyone
    /// onto the proxy's IP (which would be one shared bucket for the world).
    #[test]
    fn header_without_client_entry_falls_back() {
        assert_eq!(client_ip_from_headers(&headers("10.10.0.1"), 1), None);
        assert_eq!(client_ip_from_headers(&HeaderMap::new(), 1), None);
    }

    /// Direct exposure: nothing in the header was added by us.
    #[test]
    fn zero_trusted_hops_ignores_header() {
        assert_eq!(client_ip_from_headers(&headers("1.2.3.4"), 0), None);
    }

    #[test]
    fn deeper_chains_and_junk() {
        // Two of our own hops.
        let h = headers("203.0.113.9, 172.17.0.2, 10.10.0.1");
        assert_eq!(client_ip_from_headers(&h, 2), Some(ip("203.0.113.9")));
        // Padding and IPv6 survive the round trip.
        let h = headers("  2001:db8::1 ,  10.10.0.1 ");
        assert_eq!(client_ip_from_headers(&h, 1), Some(ip("2001:db8::1")));
        // A non-address in the client slot is not usable.
        assert_eq!(
            client_ip_from_headers(&headers("unknown, 10.10.0.1"), 1),
            None
        );
    }

    /// The fallback both the limiter and the install trace take: the
    /// vouched-for entry when there is one, the peer otherwise.
    #[test]
    fn the_peer_is_the_fallback_and_never_overrides_the_forwarded_entry() {
        let peer: SocketAddr = "127.0.0.1:5555".parse().unwrap();
        assert_eq!(
            client_ip_or_peer(&headers("203.0.113.9, 10.10.0.1"), Some(peer), 1),
            Some(ip("203.0.113.9"))
        );
        assert_eq!(
            client_ip_or_peer(&HeaderMap::new(), Some(peer), 1),
            Some(ip("127.0.0.1"))
        );
        assert_eq!(
            client_ip_or_peer(&headers("203.0.113.9"), Some(peer), 1),
            Some(ip("127.0.0.1")),
            "a lone entry is the client's own claim, not our hop's record"
        );
        assert_eq!(client_ip_or_peer(&HeaderMap::new(), None, 1), None);
        // `client_ip` over a request reads the same two inputs.
        let mut req = Request::builder()
            .header(X_FORWARDED_FOR, "1.2.3.4, 198.51.100.7, 10.10.0.1")
            .body(())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        assert_eq!(client_ip(&req, 1), Some(ip("198.51.100.7")));
    }

    fn captured(xff: &str, peer: &str, cidrs: &[&str], hops: usize) -> ConnectionOrigin {
        ConnectionOrigin::capture(
            &headers(xff),
            Some(peer.parse().unwrap()),
            &cidrs.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            hops,
        )
    }

    #[test]
    fn security_origin_ignores_forged_header_from_untrusted_direct_peer() {
        let o = captured("1.2.3.4, 10.10.0.1", "198.51.100.9:443", &["10.0.0.0/8"], 1);
        assert_eq!(o.client_ip(), Some(ip("198.51.100.9")));
        assert_eq!(o.source(), ConnectionOriginSource::SocketPeer);
    }

    #[test]
    fn security_origin_requires_real_peer_even_with_plausible_header() {
        let o = ConnectionOrigin::capture(
            &headers("203.0.113.9, 10.10.0.1"),
            None,
            &["10.0.0.0/8".into()],
            1,
        );
        assert_eq!(o.client_ip(), None);
        assert_eq!(o.source(), ConnectionOriginSource::MissingPeer);
    }

    #[test]
    fn security_origin_validates_immediate_and_suffix_proxies() {
        let o = captured(
            "spoof, 203.0.113.9, 10.10.0.1",
            "10.10.0.2:443",
            &["10.0.0.0/8"],
            1,
        );
        assert_eq!(o.client_ip(), Some(ip("203.0.113.9")));
        assert_eq!(o.source(), ConnectionOriginSource::TrustedProxyChain);
        assert_eq!(o.transport_peer(), Some(ip("10.10.0.2")));
    }

    #[test]
    fn security_origin_unknown_when_trusted_chain_is_short_missing_or_invalid() {
        for xff in [
            "10.10.0.1",
            "",
            "unknown, 10.10.0.1",
            "203.0.113.9, 198.51.100.2",
            "203.0.113.9, , 10.10.0.1",
        ] {
            assert_eq!(
                captured(xff, "10.10.0.2:443", &["10.0.0.0/8"], 1).client_ip(),
                None,
                "{xff}"
            );
        }
        let o = ConnectionOrigin::capture(
            &HeaderMap::new(),
            Some("10.10.0.2:443".parse().unwrap()),
            &["10.0.0.0/8".into()],
            1,
        );
        assert_eq!(o.client_ip(), None, "proxy itself is not client authority");
    }

    #[test]
    fn security_origin_rejects_duplicate_header_and_resource_overflow() {
        let mut h = headers("203.0.113.9, 10.10.0.1");
        h.append(X_FORWARDED_FOR, "1.2.3.4, 10.10.0.1".parse().unwrap());
        let peer = Some("10.10.0.2:443".parse().unwrap());
        assert_eq!(
            ConnectionOrigin::capture(&h, peer, &["10.0.0.0/8".into()], 1).source(),
            ConnectionOriginSource::AmbiguousHeader
        );
        assert_eq!(
            captured(&"1".repeat(8193), "10.10.0.2:443", &["10.0.0.0/8"], 1).client_ip(),
            None
        );
        assert_eq!(
            captured(
                &vec!["10.1.1.1"; 65].join(","),
                "10.10.0.2:443",
                &["10.0.0.0/8"],
                1
            )
            .client_ip(),
            None
        );
        assert_eq!(
            captured("203.0.113.9", "10.10.0.2:443", &["10.0.0.0/8"], 33).client_ip(),
            None
        );
    }

    #[test]
    fn security_origin_never_invents_automatic_proxy_trust() {
        let o = captured("1.2.3.4, 10.10.0.1", "10.10.0.2:443", &[], 1);
        assert_eq!(o.client_ip(), Some(ip("10.10.0.2")));
        assert_eq!(o.source(), ConnectionOriginSource::SocketPeer);
        for cidr in ["0.0.0.0/0", "::/0", "not-a-cidr", "::ffff:10.0.0.0/104"] {
            assert_eq!(
                captured("203.0.113.9, 10.10.0.1", "10.10.0.2:443", &[cidr], 1).source(),
                ConnectionOriginSource::InvalidProxyConfiguration
            );
        }
    }

    #[test]
    fn security_origin_normalizes_mapped_addresses_and_supports_ipv6_chain() {
        let o = captured(
            "::ffff:203.0.113.9, ::ffff:10.10.0.1",
            "[::ffff:10.10.0.2]:443",
            &["10.0.0.0/8"],
            1,
        );
        assert_eq!(o.client_ip(), Some(ip("203.0.113.9")));
        assert_eq!(o.transport_peer(), Some(ip("10.10.0.2")));
        let o = captured("2001:db8::9, fd00::1", "[fd00::2]:443", &["fd00::/64"], 1);
        assert_eq!(o.client_ip(), Some(ip("2001:db8::9")));
    }

    #[test]
    fn security_origin_direct_mode_uses_socket_not_forwarded_claim() {
        let o = captured("203.0.113.9", "198.51.100.7:443", &["10.0.0.0/8"], 0);
        assert_eq!(o.client_ip(), Some(ip("198.51.100.7")));
    }
}
