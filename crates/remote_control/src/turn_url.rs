// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Port-correct TURN URL parsing + transport-variant expansion.
//!
//! One implementation for every place that fans a single `turn:host[:port]`
//! base into its UDP/TCP/TLS variants: the remote-control cred path
//! (`api/state.rs::build_turn_config`), the media-join path
//! (`api/ws/handler.rs`), and per-region relay PoPs whose capability set
//! differs from the fleet's (a regional PoP hands TCP/443 to its DERP relay,
//! so it must NOT advertise `turns::443?transport=tcp`).
//!
//! The legacy expansions string-replaced the literal `":3478"`, which silently
//! mis-expands any base on a non-default port (the `:443` "variant" keeps the
//! original port but claims the corp-escape role). This module parses instead.

/// Which transport variants a coturn deployment actually serves. The server
/// advertises only what a PoP really listens on, so clients never burn their
/// per-candidate allocate timeout (5–6 s each on a hostile corp path) dialing
/// a port that routes elsewhere.
///
/// Deserializes from a region spec's `caps` object; every ABSENT field is
/// `true` (a partial `{"tls_443_tcp":false}` turns off exactly one variant),
/// matching [`VariantCaps::default`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VariantCaps {
    /// `turn:host:443?transport=udp` — coturn behind a UDP/443 DNAT (or
    /// `alt-listening-port=443`); looks like QUIC to corp firewalls.
    #[serde(default = "d_true")]
    pub udp_443: bool,
    /// `turn:host:<base-port>?transport=tcp`.
    #[serde(default = "d_true")]
    pub tcp: bool,
    /// `turns:host:5349?transport=tcp` — coturn's standard TLS port.
    #[serde(default = "d_true")]
    pub tls_5349: bool,
    /// `turns:host:443?transport=udp` (DTLS). webrtc-rs silently drops it
    /// (upstream NOT_PLANNED, webrtc-rs/webrtc#690); browsers use it.
    #[serde(default = "d_true")]
    pub tls_443_udp: bool,
    /// `turns:host:443?transport=tcp`. Corp-escape over TLS. Regional PoPs
    /// serve it too — their nginx SNI-splits TCP/443 between the coturn name
    /// (passthrough to the TLS listener) and the DERP name — so this stays on
    /// everywhere; PoPs disable only `tls_443_udp` (DTLS, structurally dead
    /// behind the plain-3478 UDP/443 DNAT).
    #[serde(default = "d_true")]
    pub tls_443_tcp: bool,
}

fn d_true() -> bool {
    true
}

impl Default for VariantCaps {
    /// The fleet coturn's full historical set — all six variants.
    fn default() -> Self {
        Self {
            udp_443: true,
            tcp: true,
            tls_5349: true,
            tls_443_udp: true,
            tls_443_tcp: true,
        }
    }
}

impl VariantCaps {
    /// The media-join path's historical subset: no `turns::443` variants.
    pub fn media() -> Self {
        Self {
            tls_443_udp: false,
            tls_443_tcp: false,
            ..Self::default()
        }
    }
}

/// Host + port of a `turn:`/`turns:`/`stun:`/`stuns:` URL, query stripped.
/// The host comes back WITHOUT `[]` brackets (DNS/dial-friendly); the port
/// defaults to 3478 when absent or unparsable.
pub fn host_port(url: &str) -> Option<(String, u16)> {
    let rest = url
        .strip_prefix("turns:")
        .or_else(|| url.strip_prefix("turn:"))
        .or_else(|| url.strip_prefix("stuns:"))
        .or_else(|| url.strip_prefix("stun:"))?;
    let rest = rest.split('?').next().unwrap_or(rest);
    if let Some(v6) = rest.strip_prefix('[') {
        let end = v6.find(']')?;
        let host = &v6[..end];
        let port = v6[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(3478);
        (!host.is_empty()).then(|| (host.to_string(), port))
    } else {
        let mut it = rest.splitn(2, ':');
        let host = it.next().filter(|h| !h.is_empty())?;
        let port = it.next().and_then(|p| p.parse().ok()).unwrap_or(3478);
        Some((host.to_string(), port))
    }
}

/// Port of the first plain `turn:` (UDP, non-TCP) URL in a granted list — the
/// port a worker-pinned Tier-2 allocate should dial on the pinned IP. Falls
/// back to 3478 when the list carries no such URL (the historical constant).
pub fn first_udp_port<'a, I: IntoIterator<Item = &'a str>>(urls: I) -> u16 {
    urls.into_iter()
        .find_map(|u| {
            if !u.starts_with("turn:") || u.contains("transport=tcp") {
                return None;
            }
            host_port(u).map(|(_, p)| p)
        })
        .unwrap_or(3478)
}

/// Re-bracket a host for URL embedding when it's a bare IPv6 literal.
fn fmt_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Expand a plain `turn:host[:port]` base (no explicit `?transport=`) into the
/// transport variants `caps` allows, base first. Any other shape — `turns:`,
/// `stun:`, or a transport-suffixed URL — passes through as `[base]`, exactly
/// the legacy gate.
pub fn expand_turn_url(base: &str, caps: &VariantCaps) -> Vec<String> {
    // A blank URL expands to NOTHING, not to one blank URL.
    //
    // `turn.url` is an Option, so `Some("")` reads as "configured" at every
    // call site while meaning "not configured" to a human. Returning [""] from
    // here put an empty string into the ICE server list, and a browser rejects
    // the whole thing:
    //   Failed to construct 'RTCPeerConnection': '' is not a valid URL
    // — which makes EVERY call unjoinable, with the failure surfacing only as
    // a snackbar that fades. Field-diagnosed 2026-08-29 on the e2e stack,
    // where it had been the real cause of "conference specs fail" for months.
    if base.trim().is_empty() {
        return Vec::new();
    }
    let mut urls = vec![base.to_string()];
    if !base.starts_with("turn:") || base.contains("?transport=") {
        return urls;
    }
    let Some((host, port)) = host_port(base) else {
        return urls;
    };
    let host = fmt_host(&host);
    if caps.udp_443 {
        urls.push(format!("turn:{host}:443?transport=udp"));
    }
    if caps.tcp {
        urls.push(format!("turn:{host}:{port}?transport=tcp"));
    }
    if caps.tls_5349 {
        urls.push(format!("turns:{host}:5349?transport=tcp"));
    }
    if caps.tls_443_udp {
        urls.push(format!("turns:{host}:443?transport=udp"));
    }
    if caps.tls_443_tcp {
        urls.push(format!("turns:{host}:443?transport=tcp"));
    }
    urls
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A blank URL expands to NOTHING.
    ///
    /// `turn.url` is an `Option<String>`, so `Some("")` looks configured to
    /// every call site and means "unset" to the operator who left it empty.
    /// Returning `[""]` here put an empty string in the ICE server list and a
    /// browser rejects the whole peer connection —
    /// `Failed to construct 'RTCPeerConnection': '' is not a valid URL` —
    /// so NOBODY can join a call. Field-diagnosed 2026-08-29 on the e2e stack,
    /// where it had quietly been the real cause of "the conference specs fail"
    /// for months while we blamed the network.
    #[test]
    fn blank_url_expands_to_nothing() {
        for blank in ["", "   ", "\t", "\n"] {
            assert!(
                expand_turn_url(blank, &VariantCaps::default()).is_empty(),
                "blank TURN url {blank:?} must expand to no urls at all"
            );
            assert!(expand_turn_url(blank, &VariantCaps::media()).is_empty());
        }
    }

    /// The exact six-variant list the legacy string-replace expansion emitted
    /// for the deployed base shape — byte-identical, order included. This is
    /// the flag-off no-op guarantee for every config in the field.
    #[test]
    fn legacy_six_variant_golden() {
        assert_eq!(
            expand_turn_url(
                "turn:coturn.meshharbor.itachi.fans:3478",
                &VariantCaps::default()
            ),
            vec![
                "turn:coturn.meshharbor.itachi.fans:3478",
                "turn:coturn.meshharbor.itachi.fans:443?transport=udp",
                "turn:coturn.meshharbor.itachi.fans:3478?transport=tcp",
                "turns:coturn.meshharbor.itachi.fans:5349?transport=tcp",
                "turns:coturn.meshharbor.itachi.fans:443?transport=udp",
                "turns:coturn.meshharbor.itachi.fans:443?transport=tcp",
            ]
        );
    }

    /// The media-join path's exact historical four-variant list.
    #[test]
    fn media_subset_golden() {
        assert_eq!(
            expand_turn_url(
                "turn:coturn.meshharbor.itachi.fans:3478",
                &VariantCaps::media()
            ),
            vec![
                "turn:coturn.meshharbor.itachi.fans:3478",
                "turn:coturn.meshharbor.itachi.fans:443?transport=udp",
                "turn:coturn.meshharbor.itachi.fans:3478?transport=tcp",
                "turns:coturn.meshharbor.itachi.fans:5349?transport=tcp",
            ]
        );
    }

    /// The fix the module exists for: a non-3478 base keeps its own port on
    /// the TCP variant while the well-known 443/5349 variants get their REAL
    /// ports (legacy `.replace(":3478", …)` left them on the base port).
    #[test]
    fn nonstandard_port_expands_correctly() {
        assert_eq!(
            expand_turn_url("turn:pop.example.com:3479", &VariantCaps::default()),
            vec![
                "turn:pop.example.com:3479",
                "turn:pop.example.com:443?transport=udp",
                "turn:pop.example.com:3479?transport=tcp",
                "turns:pop.example.com:5349?transport=tcp",
                "turns:pop.example.com:443?transport=udp",
                "turns:pop.example.com:443?transport=tcp",
            ]
        );
    }

    #[test]
    fn portless_base_gets_default_port() {
        let urls = expand_turn_url("turn:pop.example.com", &VariantCaps::default());
        assert_eq!(urls[0], "turn:pop.example.com");
        assert!(urls.contains(&"turn:pop.example.com:3478?transport=tcp".to_string()));
    }

    #[test]
    fn non_expandable_shapes_pass_through() {
        for base in [
            "turn:host:3478?transport=udp",
            "turns:host:5349?transport=tcp",
            "stun:stun.l.google.com:19302",
        ] {
            assert_eq!(expand_turn_url(base, &VariantCaps::default()), vec![base]);
        }
    }

    #[test]
    fn caps_gate_each_variant() {
        let none = VariantCaps {
            udp_443: false,
            tcp: false,
            tls_5349: false,
            tls_443_udp: false,
            tls_443_tcp: false,
        };
        assert_eq!(
            expand_turn_url("turn:pop.example.com:3478", &none),
            vec!["turn:pop.example.com:3478"]
        );
    }

    #[test]
    fn caps_deserialize_partial_defaults_true() {
        let caps: VariantCaps = serde_json::from_str(r#"{"tls_443_tcp":false}"#).unwrap();
        assert_eq!(
            caps,
            VariantCaps {
                tls_443_tcp: false,
                ..VariantCaps::default()
            }
        );
        let empty: VariantCaps = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, VariantCaps::default());
    }

    #[test]
    fn host_port_parses_all_shapes() {
        assert_eq!(
            host_port("turn:coturn.meshharbor.itachi.fans:3478?transport=udp"),
            Some(("coturn.meshharbor.itachi.fans".into(), 3478))
        );
        assert_eq!(
            host_port("turns:coturn.meshharbor.itachi.fans:5349?transport=tcp"),
            Some(("coturn.meshharbor.itachi.fans".into(), 5349))
        );
        assert_eq!(
            host_port("turn:pop.example.com"),
            Some(("pop.example.com".into(), 3478))
        );
        assert_eq!(
            host_port("stun:stun.l.google.com:19302"),
            Some(("stun.l.google.com".into(), 19302))
        );
        assert_eq!(
            host_port("turn:[2001:db8::1]:3479"),
            Some(("2001:db8::1".into(), 3479))
        );
        assert_eq!(
            host_port("turn:[2001:db8::1]"),
            Some(("2001:db8::1".into(), 3478))
        );
        assert_eq!(host_port("http://not-a-turn-url"), None);
        assert_eq!(host_port("turn:"), None);
    }

    #[test]
    fn first_udp_port_skips_stun_and_tcp() {
        let urls = [
            "stun:stun.l.google.com:19302",
            "turns:coturn.meshharbor.itachi.fans:5349?transport=tcp",
            "turn:coturn.meshharbor.itachi.fans:3479",
            "turn:coturn.meshharbor.itachi.fans:443?transport=udp",
        ];
        assert_eq!(first_udp_port(urls), 3479);
        assert_eq!(first_udp_port(["stun:s.example:19302"]), 3478);
        assert_eq!(first_udp_port(std::iter::empty::<&str>()), 3478);
    }

    #[test]
    fn v6_literal_hosts_rebracket_in_variants() {
        let urls = expand_turn_url("turn:[2001:db8::1]:3478", &VariantCaps::default());
        assert!(urls.contains(&"turn:[2001:db8::1]:443?transport=udp".to_string()));
        assert!(urls.contains(&"turns:[2001:db8::1]:5349?transport=tcp".to_string()));
    }
}
