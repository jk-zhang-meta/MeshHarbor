// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-128 — how this device reaches its centre: directly, or through one of its zone's
//! management entries (a gateway that forwards the TLS connection to the centre unread).
//!
//! The centre says which (`rc:agent.management_path`, persisted here so it holds at boot); the
//! device's owner may add entries of their own (`management_entries`, any address, a LAN peer
//! included). The control socket picks a path with [`plan`], and every HTTP request to the
//! centre follows the path the socket is on ([`route_http`]): the client resolves the centre's
//! host to the entry, so SNI and the certificate check are exactly those of a direct request.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// `MESHHARBORD_MANAGEMENT_ENTRIES=0`: dial the centre directly, whatever it pushed.
pub const KILL_SWITCH_ENV: &str = "MESHHARBORD_MANAGEMENT_ENTRIES";
const FILE: &str = "management-path.json";

/// The kill switch is on (direct only, the pre-FR-128 behaviour).
pub fn disabled() -> bool {
    std::env::var(KILL_SWITCH_ENV).is_ok_and(|v| v.trim() == "0")
}

/// What the centre pushed. The default (nothing pushed yet) is direct with no entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pushed {
    pub direct: bool,
    #[serde(default)]
    pub entries: Vec<String>,
}

impl Default for Pushed {
    fn default() -> Self {
        Self {
            direct: true,
            entries: Vec::new(),
        }
    }
}

/// One way to the centre.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Candidate {
    Direct,
    Entry(SocketAddr),
}

impl std::fmt::Display for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => f.write_str("direct"),
            Self::Entry(a) => write!(f, "entry {a}"),
        }
    }
}

/// The order to try, and whether a trailing `Direct` is only a last resort (the zone may not
/// reach the centre directly, but a device must stay manageable).
///
/// - Entries: the owner's local ones first (any address), then the pushed ones (public
///   literals only: a server-pushed dial target must not reach into a private network); the
///   one that last worked first among them.
/// - Direct allowed (or no entry at all): direct first, then the entries.
/// - Direct not allowed: the entries, then direct as the last resort.
pub fn plan(
    pushed: &Pushed,
    local: &[String],
    last_good: Option<Candidate>,
) -> (Vec<Candidate>, bool) {
    let mut entries: Vec<Candidate> = Vec::new();
    let local = local
        .iter()
        .filter_map(|s| s.trim().parse::<SocketAddr>().ok());
    let pushed_eps = pushed
        .entries
        .iter()
        .filter_map(|s| s.trim().parse::<SocketAddr>().ok())
        .filter(|a| is_public(a.ip()));
    for a in local.chain(pushed_eps) {
        if a.port() != 0 && !entries.contains(&Candidate::Entry(a)) {
            entries.push(Candidate::Entry(a));
        }
    }
    if let Some(good @ Candidate::Entry(_)) = last_good
        && let Some(i) = entries.iter().position(|c| *c == good)
    {
        let c = entries.remove(i);
        entries.insert(0, c);
    }
    if disabled() || pushed.direct || entries.is_empty() {
        let mut out = vec![Candidate::Direct];
        if !disabled() {
            out.extend(entries);
        }
        return (out, false);
    }
    entries.push(Candidate::Direct);
    (entries, true)
}

fn is_public(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => {
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_multicast()
                // 100.64.0.0/10 (CGNAT, and the mesh's own addresses)
                || (v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64))
        }
        std::net::IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return is_public(std::net::IpAddr::V4(v4));
            }
            let s = v.segments()[0];
            !(v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (s & 0xfe00) == 0xfc00
                || (s & 0xffc0) == 0xfe80)
        }
    }
}

/// Where the pushed path is kept: beside the daemon's logs, like the capability cache.
pub fn state_path() -> Option<PathBuf> {
    crate::logging::log_dir()
        .or_else(crate::logging::resolve_log_dir)
        .map(|d| d.join(FILE))
}

/// The kept file: each centre's last pushed path, by the centre's host. A path is the centre's
/// own: one kept for a different server (another enrollment, or an in-process test daemon on
/// this host talking to a loopback server) must never steer this one.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Kept {
    by_centre: std::collections::BTreeMap<String, Pushed>,
}

/// An older build (0.4.209–0.4.211) kept one path with no host: `{direct, entries}`.
enum KeptFile {
    Nothing,
    Legacy(Pushed),
    ByCentre(Kept),
}

fn read_kept(path: &Path) -> KeptFile {
    let Some(v) = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
    else {
        return KeptFile::Nothing;
    };
    if v.get("by_centre").is_some() {
        return serde_json::from_value(v).map_or(KeptFile::Nothing, KeptFile::ByCentre);
    }
    serde_json::from_value(v).map_or(KeptFile::Nothing, KeptFile::Legacy)
}

/// The host a centre is kept under: `server_url`'s, lower-cased (`""` when it does not parse).
pub fn centre_host(server_url: &str) -> String {
    reqwest::Url::parse(server_url)
        .ok()
        .and_then(|u| {
            u.host_str()
                .map(|h| h.trim_matches(['[', ']']).to_ascii_lowercase())
        })
        .unwrap_or_default()
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// The last path pushed by the centre at `centre` (a host), or the default when none was kept
/// (or the file does not parse). An older build's host-less path applies to any centre that is
/// not on loopback: a device updated from it still finds its entries at boot.
pub fn load(path: &Path, centre: &str) -> Pushed {
    match read_kept(path) {
        KeptFile::ByCentre(k) => k
            .by_centre
            .get(&centre.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default(),
        KeptFile::Legacy(p) if !is_loopback_host(centre) => p,
        _ => Pushed::default(),
    }
}

/// Every path kept, whichever centre pushed it.
fn load_all(path: &Path) -> Vec<Pushed> {
    match read_kept(path) {
        KeptFile::ByCentre(k) => k.by_centre.into_values().collect(),
        KeptFile::Legacy(p) => vec![p],
        KeptFile::Nothing => Vec::new(),
    }
}

/// Keep the path the centre at `centre` pushed, beside the others. Written beside (per
/// process), then renamed, so a crash never leaves half a file.
pub fn store(path: &Path, centre: &str, pushed: &Pushed) -> std::io::Result<()> {
    let mut kept = match read_kept(path) {
        KeptFile::ByCentre(k) => k,
        // A loopback centre (an in-process test daemon) is not the one that pushed the
        // host-less path: leave that path for the real centre to replace.
        KeptFile::Legacy(_) if is_loopback_host(centre) => return Ok(()),
        // The host-less path was this centre's (it is the one pushing again now).
        KeptFile::Legacy(_) | KeptFile::Nothing => Kept::default(),
    };
    kept.by_centre
        .insert(centre.to_ascii_lowercase(), pushed.clone());
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    std::fs::write(&tmp, serde_json::to_vec(&kept)?)?;
    std::fs::rename(&tmp, path)
}

/// The addresses of every entry the control socket may ride (the kept pushed path and the
/// owner's own): control plane, like the centre's own addresses, for exit-node routing to exempt.
pub fn entry_ips(local: &[String]) -> Vec<std::net::IpAddr> {
    if disabled() {
        return Vec::new();
    }
    let kept = state_path().map(|p| load_all(&p)).unwrap_or_default();
    let mut out = Vec::new();
    for pushed in kept.iter().chain(std::iter::once(&Pushed::default())) {
        for c in plan(pushed, local, None).0 {
            if let Candidate::Entry(a) = c
                && !out.contains(&a.ip())
            {
                out.push(a.ip());
            }
        }
    }
    out
}

/// The path the control socket is on: `(centre host, entry)`. `None` = direct.
static ROUTE: RwLock<Option<(String, SocketAddr)>> = RwLock::new(None);
/// The way the last control socket connected, and whether that was direct as a last resort.
static LAST: RwLock<Option<(Candidate, bool)>> = RwLock::new(None);

/// How many control sockets in a row fell to the direct path as a last resort.
static LAST_RESORT_RUN: AtomicU32 = AtomicU32::new(0);

/// The control socket to the centre at `host` connected along `c`.
pub fn note_connected(host: &str, c: Candidate, last_resort: bool) {
    set_route(
        host,
        match c {
            Candidate::Entry(a) => Some(a),
            Candidate::Direct => None,
        },
    );
    *LAST.write().unwrap_or_else(|e| e.into_inner()) = Some((c, last_resort));
    if last_resort {
        LAST_RESORT_RUN.fetch_add(1, Ordering::Relaxed);
    } else {
        LAST_RESORT_RUN.store(0, Ordering::Relaxed);
    }
}

/// A socket on the direct path as a last resort looks for a working entry again after this
/// long (never ratchet: an entry that was down for a restart is used again once it is back).
/// `None` when the socket is not on a last resort.
pub fn entry_retry_after() -> Option<Duration> {
    if disabled() || !matches!(last_connected(), Some((Candidate::Direct, true))) {
        return None;
    }
    Some(retry_delay(LAST_RESORT_RUN.load(Ordering::Relaxed)))
}

/// 2 min after the first last resort, doubling with each one in a row, at most 30 min: an entry
/// that answers yet cannot carry the socket costs a reconnect that often, not every 2 min.
fn retry_delay(run: u32) -> Duration {
    let doublings = run.saturating_sub(1).min(4);
    Duration::from_secs((120u64 << doublings).min(1800))
}

/// How the last control socket connected: `(path, direct as a last resort)`.
pub fn last_connected() -> Option<(Candidate, bool)> {
    *LAST.read().unwrap_or_else(|e| e.into_inner())
}

/// A newly pushed path asks the live socket to move: it is on the direct path by choice (not as
/// a last resort), and the zone now forbids direct while it has entries to use.
pub fn should_move(pushed: &Pushed, local: &[String]) -> bool {
    if disabled() {
        return false;
    }
    let on_direct_by_choice = matches!(last_connected(), Some((Candidate::Direct, false)));
    let (order, last_resort) = plan(pushed, local, None);
    on_direct_by_choice && last_resort && order.len() > 1
}

/// The control socket connected to the centre at `host`, through `via` (`None` = directly).
pub fn set_route(host: &str, via: Option<SocketAddr>) {
    let mut r = ROUTE.write().unwrap_or_else(|e| e.into_inner());
    *r = via.map(|a| (host.to_ascii_lowercase(), a));
}

/// The control socket's current route, `(centre host, entry)`; `None` = direct. A client built
/// once compares it to rebuild when the path changes.
pub fn current_route() -> Option<(String, SocketAddr)> {
    ROUTE.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The kept path sends this device to its entries first (its zone may not reach the centre
/// directly): a probe of the centre's address at boot would itself be a direct connection.
pub fn entries_only(local: &[String], centre: &str) -> bool {
    if disabled() {
        return false;
    }
    let pushed = state_path().map(|p| load(&p, centre)).unwrap_or_default();
    plan(&pushed, local, None).1
}

/// The entry requests to `host` go through, if the control socket is on one.
pub fn route_for(host: &str) -> Option<SocketAddr> {
    let r = ROUTE.read().unwrap_or_else(|e| e.into_inner());
    r.as_ref()
        .filter(|(h, _)| h.eq_ignore_ascii_case(host))
        .map(|(_, a)| *a)
}

/// Point a client at the entry the control socket is on, for requests to the centre's host
/// only (`resolve` overrides that one name). The entry's port is used unless a URL names a port
/// of its own (reqwest's rule). A client built while the socket is direct stays direct.
pub fn route_http(builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    let route = ROUTE.read().unwrap_or_else(|e| e.into_inner()).clone();
    match route {
        Some((host, entry)) => builder.resolve(&host, entry),
        None => builder,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_last_resort_looks_for_an_entry_again_backing_off_to_half_an_hour() {
        let secs: Vec<u64> = [0, 1, 2, 3, 4, 5, 9]
            .iter()
            .map(|r| retry_delay(*r).as_secs())
            .collect();
        assert_eq!(secs, vec![120, 120, 240, 480, 960, 1800, 1800]);
    }

    fn p(direct: bool, entries: &[&str]) -> Pushed {
        Pushed {
            direct,
            entries: entries.iter().map(|s| s.to_string()).collect(),
        }
    }
    fn e(s: &str) -> Candidate {
        Candidate::Entry(s.parse().unwrap())
    }

    #[test]
    fn direct_first_when_allowed_then_the_entries() {
        let (order, last_resort) = plan(&p(true, &["198.51.100.1:18443"]), &[], None);
        assert_eq!(order, vec![Candidate::Direct, e("198.51.100.1:18443")]);
        assert!(!last_resort);
    }

    #[test]
    fn a_strict_zone_tries_its_entries_and_direct_only_last() {
        let local = vec!["172.20.35.99:18443".to_string()];
        let (order, last_resort) = plan(
            &p(false, &["198.51.100.1:18443", "198.51.100.2:18443"]),
            &local,
            Some(e("198.51.100.2:18443")),
        );
        assert_eq!(
            order,
            vec![
                e("198.51.100.2:18443"),
                e("172.20.35.99:18443"),
                e("198.51.100.1:18443"),
                Candidate::Direct
            ]
        );
        assert!(last_resort);
    }

    #[test]
    fn pushed_private_addresses_are_dropped_and_no_entry_means_direct() {
        let (order, last_resort) = plan(
            &p(false, &["10.0.0.1:18443", "100.64.0.7:18443", "junk"]),
            &[],
            None,
        );
        assert_eq!(order, vec![Candidate::Direct]);
        assert!(!last_resort);
    }

    #[test]
    fn the_route_applies_only_to_the_centres_host() {
        set_route(
            "Centre.Example",
            Some("198.51.100.1:18443".parse().unwrap()),
        );
        assert_eq!(
            route_for("centre.example"),
            Some("198.51.100.1:18443".parse().unwrap())
        );
        assert_eq!(route_for("other.example"), None);
        set_route("centre.example", None);
        assert_eq!(route_for("centre.example"), None);
    }

    #[test]
    fn a_kept_path_round_trips_and_a_missing_one_is_direct() {
        let dir = std::env::temp_dir().join(format!("mh-fr128-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE);
        assert_eq!(load(&path, "centre.example"), Pushed::default());
        let kept = p(false, &["198.51.100.1:18443"]);
        store(&path, "Centre.Example", &kept).unwrap();
        assert_eq!(load(&path, "centre.example"), kept);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A path is its centre's: a daemon on this host talking to another server (a test
    /// daemon against a loopback server, which is how this was found) neither reads nor
    /// overwrites it, and an older build's host-less file still applies to the real centre.
    #[test]
    fn each_centre_keeps_its_own_path_and_a_legacy_one_serves_only_a_real_centre() {
        let dir = std::env::temp_dir().join(format!("mh-fr128-c-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(FILE);
        let real = p(false, &["198.51.100.1:18443"]);
        std::fs::write(&path, serde_json::to_vec(&real).unwrap()).unwrap();
        assert_eq!(
            load(&path, "centre.example"),
            real,
            "legacy file, real centre"
        );
        assert_eq!(
            load(&path, "127.0.0.1"),
            Pushed::default(),
            "legacy file, loopback"
        );
        assert_eq!(load(&path, "localhost"), Pushed::default());
        store(&path, "127.0.0.1", &Pushed::default()).unwrap();
        assert_eq!(
            load(&path, "centre.example"),
            real,
            "a loopback store leaves the legacy path to the real centre"
        );

        store(&path, "centre.example", &real).unwrap();
        store(&path, "127.0.0.1", &Pushed::default()).unwrap();
        assert_eq!(
            load(&path, "centre.example"),
            real,
            "not overwritten by the other"
        );
        assert_eq!(load(&path, "127.0.0.1"), Pushed::default());
        assert_eq!(load(&path, "other.example"), Pushed::default());
        assert_eq!(
            centre_host("https://Centre.Example/meshharbor"),
            "centre.example"
        );
        assert_eq!(centre_host("wss://[::1]:8443/ws"), "::1");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
