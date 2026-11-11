// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! MeshHarbor #21 — relay locality for ICE servers.
//!
//! The isolation rule is that a mainland node connects only to mainland nodes
//! (and non-mainland only to non-mainland), through ANY hop. A STUN/TURN server
//! handed to a device is a hop the device itself connects to, so under
//! `app.business_isolation = enforce` a device is handed only the ICE servers
//! that sit in its own business zone.
//!
//! A server's zone is what its address geolocates to, under the same GeoIP
//! dataset rule every other zone decision uses
//! ([`crate::business_authority::address_zone`]). Hostnames are resolved off the
//! hot path, by [`spawn_refresh`], into [`IceServerZones`]. A host is in a zone
//! only when EVERY address it resolves to is in that zone. An unresolved host,
//! a mixed answer, a stale dataset or an unknown country is no zone, and no
//! zone is never kept: fail closed. A device left with no ICE server keeps its
//! host candidates, so a direct path still connects.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use meshharbor_remote_control::signaling::IceServer;
use meshharbor_remote_control::turn_creds::{TurnMap, default_stun_servers};

use crate::Core;
use crate::business_authority::{BusinessZone, address_zone};

/// How the gate acts, derived from `app.business_isolation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceGateMode {
    /// Log what `Enforce` would withhold; hand everything out.
    Warn,
    /// Withhold every ICE server outside the device's zone.
    Enforce,
}

/// `app.business_isolation` → the gate's mode, `None` for `off`. Mirrors
/// `meshharbor_mod_network::business_isolation::Mode::parse` (anything but
/// `off` / `warn` is `enforce`: a mistyped security setting must not disable
/// it). A test in the network module locks the two together.
pub fn gate_mode(raw: &str) -> Option<IceGateMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "off" => None,
        "warn" => Some(IceGateMode::Warn),
        _ => Some(IceGateMode::Enforce),
    }
}

/// The host and port an ICE URL names (`turn:h:3478?transport=udp`,
/// `turns:h:5349`, `stun:h`, `turn:[2001:db8::1]:3478`). `None` for a URL with
/// no host. The default port is 3478 (5349 for `turns:`), which matters only
/// for resolution.
pub fn host_of(url: &str) -> Option<(String, u16)> {
    let (scheme, rest) = url.split_once(':')?;
    let rest = rest.trim_start_matches("//");
    let rest = rest.split(['?', '/']).next().unwrap_or("");
    let default_port = if scheme.eq_ignore_ascii_case("turns") {
        5349
    } else {
        3478
    };
    if let Some(v6) = rest.strip_prefix('[') {
        let (host, after) = v6.split_once(']')?;
        let port = after
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return (!host.is_empty()).then(|| (host.to_string(), port));
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (rest, default_port),
    };
    (!host.is_empty()).then(|| (host.to_ascii_lowercase(), port))
}

/// Host → zone, as last resolved. Absent and `None` both mean "no zone".
#[derive(Default)]
pub struct IceServerZones {
    map: DashMap<String, Option<BusinessZone>>,
}

impl IceServerZones {
    /// The zone of the server one ICE URL names. `None` when the host was
    /// never resolved or resolved to no single known zone.
    pub fn zone_of_url(&self, url: &str) -> Option<BusinessZone> {
        let (host, _) = host_of(url)?;
        self.map.get(&host).and_then(|z| *z)
    }

    /// Record `host`'s zone directly. Tests and IP-literal hosts.
    pub fn set(&self, host: &str, zone: Option<BusinessZone>) {
        self.map.insert(host.to_ascii_lowercase(), zone);
    }

    /// Resolve every distinct host named in `urls` and record its zone.
    pub async fn refresh(&self, core: &Core, urls: &[String]) {
        let mut seen = std::collections::HashSet::new();
        for url in urls {
            let Some((host, port)) = host_of(url) else {
                continue;
            };
            if !seen.insert(host.clone()) {
                continue;
            }
            let addrs: Vec<IpAddr> = match host.parse::<IpAddr>() {
                Ok(ip) => vec![ip],
                Err(_) => match tokio::time::timeout(
                    Duration::from_secs(3),
                    tokio::net::lookup_host((host.as_str(), port)),
                )
                .await
                {
                    Ok(Ok(it)) => it.map(|sa| sa.ip()).collect(),
                    _ => Vec::new(),
                },
            };
            let zone = single_zone(addrs.iter().map(|ip| address_zone(core, *ip)));
            tracing::info!(%host, ?zone, addresses = addrs.len(), "ice zones: resolved");
            self.map.insert(host, zone);
        }
    }
}

/// One zone when every element is `Some` of the same zone; `None` otherwise
/// (including for no elements at all).
fn single_zone(zones: impl Iterator<Item = Option<BusinessZone>>) -> Option<BusinessZone> {
    let mut out = None;
    for z in zones {
        match (out, z) {
            (_, None) => return None,
            (None, Some(z)) => out = Some(z),
            (Some(a), Some(b)) if a == b => {}
            _ => return None,
        }
    }
    out
}

/// Every ICE URL a deployment can hand out: the legacy TURN config (and its
/// per-worker variants), every region's config, then the public STUN set. The
/// deployment's own relays come first, so they resolve before the public
/// hostnames' lookups (each bounded at 3 s).
pub fn all_urls(turn: &TurnMap) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let cfgs = turn.default.iter().chain(turn.regions.values());
    for cfg in cfgs {
        out.extend(cfg.urls.iter().cloned());
        out.extend(cfg.workers.iter().flatten().cloned());
    }
    out.extend(turn.specs.iter().map(|s| s.turn_url.clone()));
    out.extend(default_stun_servers().into_iter().flat_map(|s| s.urls));
    out
}

/// Re-resolve the deployment's ICE hosts now and every 10 minutes, so a
/// DNS or GeoIP change is picked up without a restart.
pub fn spawn_refresh(core: Core, zones: Arc<IceServerZones>, urls: Vec<String>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(600));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            zones.refresh(&core, &urls).await;
        }
    });
}

/// Keep only the ICE URLs whose server is in `zone`, dropping an
/// [`IceServer`] whose URL list empties. `zone == None` (the device's own zone
/// is unknown) keeps nothing. Returns what remains and how many URLs were
/// withheld.
pub fn keep_in_zone(
    servers: Vec<IceServer>,
    zone: Option<BusinessZone>,
    zone_of: impl Fn(&str) -> Option<BusinessZone>,
) -> (Vec<IceServer>, usize) {
    let mut dropped = 0;
    let kept = servers
        .into_iter()
        .filter_map(|mut s| {
            let before = s.urls.len();
            s.urls
                .retain(|u| zone.is_some_and(|z| zone_of(u) == Some(z)));
            dropped += before - s.urls.len();
            (!s.urls.is_empty()).then_some(s)
        })
        .collect();
    (kept, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use BusinessZone::{Mainland, NonMainland};

    #[test]
    fn host_of_reads_every_ice_url_shape() {
        assert_eq!(
            host_of("turn:Coturn.Example:3478?transport=udp"),
            Some(("coturn.example".into(), 3478))
        );
        assert_eq!(
            host_of("turns:h.example?transport=tcp"),
            Some(("h.example".into(), 5349))
        );
        assert_eq!(
            host_of("stun:stun.l.google.com:19302"),
            Some(("stun.l.google.com".into(), 19302))
        );
        assert_eq!(
            host_of("stun:203.0.113.5"),
            Some(("203.0.113.5".into(), 3478))
        );
        assert_eq!(
            host_of("turn:[2001:db8::1]:3478?transport=udp"),
            Some(("2001:db8::1".into(), 3478))
        );
        assert_eq!(host_of("turn:"), None);
        assert_eq!(host_of("nonsense"), None);
    }

    #[test]
    fn a_host_has_a_zone_only_when_every_address_agrees() {
        assert_eq!(
            single_zone([Some(Mainland), Some(Mainland)].into_iter()),
            Some(Mainland)
        );
        assert_eq!(
            single_zone([Some(Mainland), Some(NonMainland)].into_iter()),
            None
        );
        assert_eq!(single_zone([Some(Mainland), None].into_iter()), None);
        assert_eq!(
            single_zone(std::iter::empty()),
            None,
            "unresolved is no zone"
        );
    }

    fn server(urls: &[&str]) -> IceServer {
        IceServer {
            urls: urls.iter().map(|u| u.to_string()).collect(),
            username: None,
            credential: None,
        }
    }

    #[test]
    fn only_servers_in_the_devices_zone_are_kept() {
        let zones = IceServerZones::default();
        zones.set("cn-turn.example", Some(Mainland));
        zones.set("us-turn.example", Some(NonMainland));
        // "unknown.example" never resolved.
        let list = vec![
            server(&["stun:us-turn.example:3478", "stun:unknown.example"]),
            server(&[
                "turn:cn-turn.example:3478?transport=udp",
                "turn:us-turn.example:3478",
            ]),
        ];
        let (kept, dropped) = keep_in_zone(list.clone(), Some(Mainland), |u| zones.zone_of_url(u));
        assert_eq!(kept.len(), 1, "the STUN entry empties and is dropped");
        assert_eq!(
            kept[0].urls,
            vec!["turn:cn-turn.example:3478?transport=udp"]
        );
        assert_eq!(dropped, 3);

        let (kept, _) = keep_in_zone(list.clone(), Some(NonMainland), |u| zones.zone_of_url(u));
        let urls: Vec<_> = kept.iter().flat_map(|s| s.urls.clone()).collect();
        assert_eq!(
            urls,
            vec!["stun:us-turn.example:3478", "turn:us-turn.example:3478"]
        );

        let (kept, dropped) = keep_in_zone(list, None, |u| zones.zone_of_url(u));
        assert!(
            kept.is_empty(),
            "a device with no known zone gets no ICE server"
        );
        assert_eq!(dropped, 4, "every URL of both servers");
    }

    #[test]
    fn the_gate_mode_reads_like_the_isolation_setting() {
        assert_eq!(gate_mode("off"), None);
        assert_eq!(gate_mode(" Warn "), Some(IceGateMode::Warn));
        assert_eq!(gate_mode("enforce"), Some(IceGateMode::Enforce));
        assert_eq!(
            gate_mode("enforec"),
            Some(IceGateMode::Enforce),
            "a typo enforces"
        );
    }
}
