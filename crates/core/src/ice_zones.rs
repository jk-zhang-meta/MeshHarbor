// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! MeshHarbor #21 — relay locality for ICE servers.
//!
//! The isolation rule is that a mainland node connects only to mainland nodes
//! (and non-mainland only to non-mainland), through ANY hop. A STUN/TURN server
//! handed to a device is a hop the device itself connects to, so under
//! `app.rc_ice_zone_mode = enforce` a device is handed only the ICE servers
//! that sit in its own business zone.
//!
//! The setting is its OWN, not `app.business_isolation`'s: withholding every
//! server outside a device's zone removes that device's srflx and relay
//! candidates, which breaks cross-network remote desktop to a device whose zone
//! differs from the deployment's relays. Turning that on is a product decision,
//! never a side effect of enforcing isolation. The default is `warn`.
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

/// `app.rc_ice_zone_mode` → the gate's mode, `None` for `off`.
///
/// ⚠️ Unlike `app.business_isolation`, an unknown value reads as `Warn`, not
/// `Enforce`, and is logged loudly. `enforce` here withholds STUN/TURN, which
/// can cut the operator's own remote access, so a typo must never switch it
/// on.
pub fn gate_mode(raw: &str) -> Option<IceGateMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "off" => None,
        "warn" => Some(IceGateMode::Warn),
        "enforce" => Some(IceGateMode::Enforce),
        other => {
            tracing::error!(
                value = %other,
                "app.rc_ice_zone_mode: unknown value, reading it as `warn` (expected off | warn | enforce)"
            );
            Some(IceGateMode::Warn)
        }
    }
}

/// How long an identical `warn` line for one device is suppressed.
pub const WARN_DEDUPE: Duration = Duration::from_secs(600);

/// Per-key suppression of repeated identical log lines (`warn` mode: one line
/// per device per [`WARN_DEDUPE`], not one per issuance).
#[derive(Default)]
pub struct LogDedupe {
    seen: DashMap<String, (String, std::time::Instant)>,
}

impl LogDedupe {
    /// `true` when `line` should be logged for `key`: no identical line was
    /// logged for it within `window`. Records the line when it returns `true`.
    pub fn first_in(&self, key: &str, line: &str, window: Duration) -> bool {
        let now = std::time::Instant::now();
        if let Some(prev) = self.seen.get(key)
            && prev.0 == line
            && now.saturating_duration_since(prev.1) < window
        {
            return false;
        }
        self.seen.insert(key.to_string(), (line.to_string(), now));
        true
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

/// Host → zone (and exact ISO-3166-1 alpha-2 country when uniform), as last
/// resolved. Absent and `None` both mean "no zone".
#[derive(Default)]
pub struct IceServerZones {
    map: DashMap<String, Option<BusinessZone>>,
    countries: DashMap<String, Option<String>>,
}

impl IceServerZones {
    /// The zone of the server one ICE URL names. `None` when the host was
    /// never resolved or resolved to no single known zone.
    pub fn zone_of_url(&self, url: &str) -> Option<BusinessZone> {
        let (host, _) = host_of(url)?;
        self.map.get(&host).and_then(|z| *z)
    }

    /// Exact ISO-3166-1 alpha-2 country code of the server one ICE URL names
    /// when every resolved address shares a single country.
    pub fn country_of_url(&self, url: &str) -> Option<String> {
        let (host, _) = host_of(url)?;
        self.countries.get(&host).and_then(|c| c.clone())
    }

    /// Record `host`'s zone directly. Tests and IP-literal hosts.
    pub fn set(&self, host: &str, zone: Option<BusinessZone>) {
        let key = host.to_ascii_lowercase();
        if zone == Some(BusinessZone::Mainland) {
            self.countries.insert(key.clone(), Some("CN".to_string()));
        } else {
            self.countries.remove(&key);
        }
        self.map.insert(key, zone);
    }

    /// Record `host`'s exact country code directly (also updating its binary
    /// `BusinessZone`).
    pub fn set_country(&self, host: &str, country: Option<&str>) {
        let key = host.to_ascii_lowercase();
        let cc = country
            .map(|c| c.trim().to_ascii_uppercase())
            .filter(|c| crate::business_authority::known_zone(Some(c)).is_some());
        let zone = crate::business_authority::known_zone(cc.as_deref());
        self.countries.insert(key.clone(), cc);
        self.map.insert(key, zone);
    }

    /// Whether `url` belongs to the allowed infrastructure countries of a
    /// `RouterOnly` [`meshharbor_remote_control::models::NetworkZone`].
    pub fn url_matches_countries(
        &self,
        geoip: &crate::user_analytics::GeoIp,
        url: &str,
        allowed_countries: &std::collections::HashSet<String>,
    ) -> bool {
        if allowed_countries.is_empty() {
            return false;
        }
        if let Some((host, _)) = host_of(url)
            && let Ok(ip) = host.parse::<IpAddr>()
        {
            return geoip
                .security_lookup(ip)
                .country_code
                .is_some_and(|cc| allowed_countries.contains(&cc.to_ascii_uppercase()));
        }
        if let Some(cc) = self.country_of_url(url) {
            return allowed_countries.contains(&cc.to_ascii_uppercase());
        }
        false
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
            let country = single_country(addrs.iter().map(|ip| {
                address_zone(core, *ip)?;
                core.geoip.security_lookup(*ip).country_code
            }));
            tracing::info!(%host, ?zone, ?country, addresses = addrs.len(), "ice zones: resolved");
            self.countries.insert(host.clone(), country);
            self.map.insert(host, zone);
        }
    }
}

fn single_country(countries: impl Iterator<Item = Option<String>>) -> Option<String> {
    let mut out: Option<String> = None;
    for c in countries {
        match (&out, c) {
            (_, None) => return None,
            (None, Some(c)) => out = Some(c),
            (Some(a), Some(b)) if a == &b => {}
            _ => return None,
        }
    }
    out
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

/// What [`keep_in_zone`] kept, and why it withheld the rest.
#[derive(Debug)]
pub struct Filtered {
    pub kept: Vec<IceServer>,
    pub kept_urls: usize,
    pub withheld_urls: usize,
    /// `none` (nothing withheld) | `device_zone_unknown` | `outside_device_zone`
    /// | `server_zone_unknown` | `outside_device_zone_or_unknown`.
    pub reason: &'static str,
}

/// Keep only the ICE URLs whose server is in `zone`, dropping an
/// [`IceServer`] whose URL list empties. `zone == None` (the device's own zone
/// is unknown) keeps nothing.
pub fn keep_in_zone(
    servers: Vec<IceServer>,
    zone: Option<BusinessZone>,
    zone_of: impl Fn(&str) -> Option<BusinessZone>,
) -> Filtered {
    let (mut kept_urls, mut other_zone, mut unknown) = (0, 0, 0);
    let kept = servers
        .into_iter()
        .filter_map(|mut s| {
            s.urls.retain(|u| {
                let server = zone_of(u);
                let keep = zone.is_some() && server == zone;
                match (keep, server) {
                    (true, _) => kept_urls += 1,
                    (false, Some(_)) => other_zone += 1,
                    (false, None) => unknown += 1,
                }
                keep
            });
            (!s.urls.is_empty()).then_some(s)
        })
        .collect();
    let withheld_urls = other_zone + unknown;
    let reason = match (zone, other_zone, unknown) {
        _ if withheld_urls == 0 => "none",
        (None, _, _) => "device_zone_unknown",
        (Some(_), _, 0) => "outside_device_zone",
        (Some(_), 0, _) => "server_zone_unknown",
        (Some(_), _, _) => "outside_device_zone_or_unknown",
    };
    Filtered {
        kept,
        kept_urls,
        withheld_urls,
        reason,
    }
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
        let f = keep_in_zone(list.clone(), Some(Mainland), |u| zones.zone_of_url(u));
        assert_eq!(f.kept.len(), 1, "the STUN entry empties and is dropped");
        assert_eq!(
            f.kept[0].urls,
            vec!["turn:cn-turn.example:3478?transport=udp"]
        );
        assert_eq!((f.kept_urls, f.withheld_urls), (1, 3));
        assert_eq!(f.reason, "outside_device_zone_or_unknown");

        let f = keep_in_zone(list.clone(), Some(NonMainland), |u| zones.zone_of_url(u));
        let urls: Vec<_> = f.kept.iter().flat_map(|s| s.urls.clone()).collect();
        assert_eq!(
            urls,
            vec!["stun:us-turn.example:3478", "turn:us-turn.example:3478"]
        );

        let f = keep_in_zone(list.clone(), None, |u| zones.zone_of_url(u));
        assert!(
            f.kept.is_empty(),
            "a device with no known zone gets no ICE server"
        );
        assert_eq!(
            (f.kept_urls, f.withheld_urls),
            (0, 4),
            "every URL of both servers"
        );
        assert_eq!(f.reason, "device_zone_unknown");

        let only_cn = vec![server(&["turn:cn-turn.example:3478"])];
        let f = keep_in_zone(only_cn.clone(), Some(NonMainland), |u| zones.zone_of_url(u));
        assert_eq!(f.reason, "outside_device_zone");
        let f = keep_in_zone(only_cn, Some(Mainland), |u| zones.zone_of_url(u));
        assert_eq!((f.withheld_urls, f.reason), (0, "none"));
        let f = keep_in_zone(
            vec![server(&["stun:unknown.example"])],
            Some(Mainland),
            |u| zones.zone_of_url(u),
        );
        assert_eq!(f.reason, "server_zone_unknown");
    }

    #[test]
    fn the_mode_has_three_values_and_a_typo_only_warns() {
        assert_eq!(gate_mode("off"), None);
        assert_eq!(gate_mode(" Warn "), Some(IceGateMode::Warn));
        assert_eq!(gate_mode("ENFORCE"), Some(IceGateMode::Enforce));
        assert_eq!(
            gate_mode("enforec"),
            Some(IceGateMode::Warn),
            "unlike business_isolation, a typo must never enforce here"
        );
        assert_eq!(gate_mode(""), Some(IceGateMode::Warn));
    }

    #[test]
    fn an_identical_line_per_key_is_logged_once_per_window() {
        let d = LogDedupe::default();
        assert!(d.first_in("dev1", "zone=Mainland withheld=2", WARN_DEDUPE));
        assert!(!d.first_in("dev1", "zone=Mainland withheld=2", WARN_DEDUPE));
        assert!(
            d.first_in("dev2", "zone=Mainland withheld=2", WARN_DEDUPE),
            "per key"
        );
        assert!(
            d.first_in("dev1", "zone=Mainland withheld=3", WARN_DEDUPE),
            "a change logs"
        );
        assert!(
            d.first_in("dev1", "zone=Mainland withheld=3", Duration::ZERO),
            "window over"
        );
    }

    #[test]
    fn mixed_country_dns_fails_closed_for_exact_country_sets_while_uniform_passes() {
        let zones = IceServerZones::default();
        // Mixed US + DE DNS answers produce `NonMainland` binary zone, but NO uniform country (`None`).
        zones
            .map
            .insert("mixed-turn.example".into(), Some(NonMainland));
        zones.countries.insert("mixed-turn.example".into(), None);

        // Uniform JP DNS answers produce both `NonMainland` and exact `Some("JP")`.
        zones
            .map
            .insert("jp-turn.example".into(), Some(NonMainland));
        zones
            .countries
            .insert("jp-turn.example".into(), Some("JP".into()));

        let geoip = crate::user_analytics::GeoIp::open(None);
        let jp_only = std::collections::HashSet::from(["JP".to_string()]);
        let us_only = std::collections::HashSet::from(["US".to_string()]);

        assert!(
            !zones.url_matches_countries(&geoip, "stun:mixed-turn.example:3478", &jp_only),
            "mixed US/DE hostname must fail closed for {{JP}}"
        );
        assert!(
            !zones.url_matches_countries(&geoip, "stun:mixed-turn.example:3478", &us_only),
            "mixed US/DE hostname must fail closed for {{US}}"
        );
        assert!(
            zones.url_matches_countries(&geoip, "stun:jp-turn.example:3478", &jp_only),
            "uniform JP hostname passes {{JP}}"
        );
        assert!(
            !zones.url_matches_countries(&geoip, "stun:jp-turn.example:3478", &us_only),
            "uniform JP hostname rejected for {{US}}"
        );
    }
}
