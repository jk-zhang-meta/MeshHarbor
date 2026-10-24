// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Short-lived TURN credentials following the coturn REST API convention
//! ("draft-uberti-behave-turn-rest").
//!
//! Username format:  `<unix_expiry>:<user_id>`
//! Password:         base64( HMAC-SHA1(shared_secret, username) )
//!
//! FR-115 P4b — where the issuer knows the org that pays for the relay, the
//! `user_id` part is [`charged`]: `<principal>:org-<org>`, so the username
//! reads `<unix_expiry>:<principal>:org-<org>` and coturn's own statistics
//! name the org ([`org_of_username`]). coturn reads the expiry before the
//! FIRST `:` and HMACs the whole username, so neither it nor any client sees
//! a difference.
//!
//! The shared secret is the value passed as `--static-auth-secret` to coturn,
//! also set as `RC_TURN_SECRET` in roomler env.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::signaling::IceServer;
use crate::worker_pick::pick_index_fnv1a;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone)]
pub struct TurnConfig {
    /// e.g. ["turn:coturn.roomler.live:3478?transport=udp",
    ///        "turn:coturn.roomler.live:3478?transport=tcp",
    ///        "turns:coturn.roomler.live:5349?transport=tcp"]
    pub urls: Vec<String>,
    /// Same-worker TURN affinity (2026-07-14): per-worker URL variant lists,
    /// one inner `Vec` per coturn worker (each expanded like `urls`). The
    /// generic hostname is 3 DNS A records (one per worker), so each ICE side
    /// resolves independently and relay↔relay sessions routinely straddle two
    /// workers — and cross-worker flows involving the dual-IP worker drop
    /// packets under its SNAT asymmetry (the rc.112 tunnel same-worker-pin
    /// lesson; field 2026-07-14: corp↔corp double-relay stall-bursts). When
    /// ≥2 workers are configured (`ROOMLER__TURN__WORKER_URLS`),
    /// [`Self::issue_for_session`] deterministically picks ONE worker per
    /// session for BOTH sides — worker URLs first, generic-hostname fallback
    /// retained. Empty (default) = exactly the old behaviour.
    pub workers: Vec<Vec<String>>,
    pub shared_secret: String,
    pub ttl_secs: u32,
}

impl TurnConfig {
    pub fn issue(&self, user_id: &str) -> IceServer {
        self.issue_with_ttl(user_id, self.ttl_secs)
    }

    /// C4 stage 1.5 — like [`Self::issue`] but with an explicit credential
    /// TTL. The WARM allocation grant mints long-lived creds (the cred
    /// timestamp bounds the allocation's TOTAL life — refreshes
    /// re-authenticate with the same username, so a 600 s pair-grant TTL
    /// killed every warm allocation at the 10-minute mark; field
    /// 2026-08-15, the first status line: `creds 600s left`). Pair grants
    /// keep the short config TTL.
    pub fn issue_with_ttl(&self, user_id: &str, ttl_secs: u32) -> IceServer {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let expiry = now_secs + ttl_secs as u64;
        let username = format!("{expiry}:{user_id}");

        let mut mac = HmacSha1::new_from_slice(self.shared_secret.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(username.as_bytes());
        let credential = B64.encode(mac.finalize().into_bytes());

        IceServer {
            urls: self.urls.clone(),
            username: Some(username),
            credential: Some(credential),
        }
    }

    /// Same-worker affinity issuance: like [`Self::issue`] but, when ≥2
    /// workers are configured, puts ONE session-selected worker's URLs first
    /// (both ICE stacks weight earlier servers higher in candidate priority,
    /// so both sides converge on the same worker) with the generic-hostname
    /// `urls` kept after as the worker-down fallback. The selection is a
    /// stable hash of `session_key`, so the controller and the agent — issued
    /// creds independently by the Hub — pick the SAME worker. With <2 workers
    /// this is exactly [`Self::issue`].
    pub fn issue_for_session(&self, user_id: &str, session_key: &str) -> IceServer {
        self.issue_for_session_with_ttl(user_id, session_key, self.ttl_secs)
    }

    /// FR-90 P0d-2 — [`Self::issue_for_session`] with an explicit credential
    /// TTL, for a peer that must outlive the config TTL: the credential's
    /// timestamp bounds a TURN allocation's TOTAL life (see
    /// [`Self::issue_with_ttl`]), and a viewer peer stays open as long as its
    /// room is.
    pub fn issue_for_session_with_ttl(
        &self,
        user_id: &str,
        session_key: &str,
        ttl_secs: u32,
    ) -> IceServer {
        let mut server = self.issue_with_ttl(user_id, ttl_secs);
        if self.workers.len() >= 2
            && let Some(idx) = pick_index_fnv1a(session_key, self.workers.len())
        {
            let mut urls = self.workers[idx].clone();
            urls.extend(server.urls);
            server.urls = urls;
        }
        server
    }
}

/// One relay region as configured in `ROOMLER__RELAY__REGIONS` (a JSON array
/// of these). Mirrors the legacy `turn.*` settings shape per region: a generic
/// base URL, optional per-worker URLs for same-worker affinity, and the
/// variant capability set the PoP actually serves.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayRegionSpec {
    /// Region id, e.g. `"us-east"` — the value carried in `relay_home`.
    pub id: String,
    /// Generic base URL, e.g. `"turn:coturn-us-east.roomler.ai:3478"`.
    pub turn_url: String,
    /// Optional per-worker base URLs (multi-worker regions), like
    /// `ROOMLER__TURN__WORKER_URLS`.
    #[serde(default)]
    pub worker_urls: Vec<String>,
    /// The region's DERP relay endpoint, e.g.
    /// `"wss://derp-us-east.roomler.ai/derp"`. Absent = the region has no
    /// regional DERP; pairs fall back to the central `/derp`.
    #[serde(default)]
    pub derp_url: Option<String>,
    /// Explicit `/stats` endpoints for the load poller, overriding the
    /// URL normally derived from `derp_url`. Needed by regions that serve
    /// TURN without a regional DERP — the CENTRAL fleet, whose `/derp` is
    /// JWT-authed (so it carries no `derp_url`) but whose coturn workers
    /// each run a stats producer. Multiple entries = a multi-worker
    /// region: the poller polls all and aggregates (healthy if ANY answers,
    /// worst-case load, summed traffic).
    #[serde(default)]
    pub stats_urls: Vec<String>,
    /// Per-region coturn `static-auth-secret`; falls back to the global
    /// `turn.shared_secret` when absent (one secret fleet-wide, v1).
    #[serde(default)]
    pub shared_secret: Option<String>,
    /// Which transport variants this PoP serves (absent fields = true).
    #[serde(default)]
    pub caps: crate::turn_url::VariantCaps,
    /// Phase E (overlay v3) — the region's coturn relay allocation band
    /// (`min-port`..=`max-port`, a DEPLOYMENT property mirrored from the
    /// PoP's coturn config). Pushed to agents in
    /// [`crate::signaling::RelayRegionInfo`] so the netcheck relay-band
    /// probe (and operators) can name the REAL band a dialer must reach,
    /// instead of inferring it from one allocation's port. Absent = not
    /// declared (agents keep the allocation-derived behavior).
    #[serde(default)]
    pub relay_band: Option<(u16, u16)>,
    /// Parsed-but-disabled regions never issue (procurement staging).
    #[serde(default = "spec_enabled_default")]
    pub enabled: bool,
}

fn spec_enabled_default() -> bool {
    true
}

/// Region-keyed TURN issuance. `default` is the legacy single-region
/// `turn.*` config; `regions` are the PoPs from `ROOMLER__RELAY__REGIONS`.
/// With `enabled == false` (the default) `cfg_for` ALWAYS answers `default`,
/// so every pre-region call path is provably unchanged.
#[derive(Debug, Clone, Default)]
pub struct TurnMap {
    pub default: Option<TurnConfig>,
    pub regions: std::collections::HashMap<String, TurnConfig>,
    /// The parsed specs (DERP endpoints, caps) for the wire push (PR3) and
    /// the regional-DERP side (PR4).
    pub specs: Vec<RelayRegionSpec>,
    /// `relay.regions_enabled` — the master gate.
    pub enabled: bool,
}

impl TurnMap {
    /// Legacy single-region map (tests + the pre-region constructor path).
    pub fn single(default: Option<TurnConfig>) -> Self {
        Self {
            default,
            ..Self::default()
        }
    }

    /// The issuing config for `region`: the region's own config when the map
    /// is enabled and knows it; the legacy default otherwise (unknown region
    /// ids and `None` both degrade safely).
    pub fn cfg_for(&self, region: Option<&str>) -> Option<&TurnConfig> {
        if self.enabled
            && let Some(r) = region
            && let Some(cfg) = self.regions.get(r)
        {
            return Some(cfg);
        }
        self.default.as_ref()
    }
}

/// Build the [`crate::signaling::ServerMsg::RelayRegions`] payload: one probe
/// target per enabled+usable region. `None` when the map is disabled or
/// nothing is probe-able — the capability-flagged agent then simply never
/// probes. `rev` is FNV-1a over the serialized list: deterministic across
/// pods/processes (both build from the same env), so an agent only re-probes
/// when the region set actually changes.
pub fn relay_regions_wire(map: &TurnMap) -> Option<(Vec<crate::signaling::RelayRegionInfo>, u64)> {
    if !map.enabled {
        return None;
    }
    let mut out = Vec::new();
    for spec in &map.specs {
        if !spec.enabled || !map.regions.contains_key(&spec.id) {
            continue;
        }
        let Some((host, port)) = crate::turn_url::host_port(&spec.turn_url) else {
            continue;
        };
        out.push(crate::signaling::RelayRegionInfo {
            id: spec.id.clone(),
            stun: format!("{host}:{port}"),
            derp_url: spec.derp_url.clone(),
            relay_band: spec.relay_band,
        });
    }
    if out.is_empty() {
        return None;
    }
    let json = serde_json::to_string(&out).unwrap_or_default();
    Some((out, fnv1a64(json.as_bytes())))
}

/// FNV-1a 64-bit — stable across processes (unlike `RandomState` hashing),
/// which is all `rev` needs.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// One region's live load snapshot, written by the API's `/stats` poller and
/// consulted at issuance time. Everything here is advisory: a missing or
/// STALE entry means "not busy" (fail-open — a stats blip must never
/// mass-reroute traffic off a healthy PoP).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegionLoad {
    pub busy: bool,
    pub load1: f64,
    pub tx_mbps: f64,
    pub coturn_allocations: f64,
    /// Unix seconds of the sample; entries older than
    /// [`REGION_LOAD_FRESH_SECS`] are ignored.
    pub updated_unix: u64,
}

/// How long a load sample stays authoritative (3 missed 30 s polls).
pub const REGION_LOAD_FRESH_SECS: u64 = 120;

/// Shared region-load table: region id → latest snapshot.
pub type RelayLoadMap = std::sync::Arc<dashmap::DashMap<String, RegionLoad>>;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Is `region` currently marked busy by a FRESH sample?
pub fn region_busy(load: &RelayLoadMap, region: &str) -> bool {
    load.get(region)
        .map(|l| l.busy && now_unix().saturating_sub(l.updated_unix) <= REGION_LOAD_FRESH_SECS)
        .unwrap_or(false)
}

/// Load-aware single-node region pick (RC sessions / tunnel): the agent's
/// nearest region unless it's busy, then the agent's next-nearest non-busy
/// region from `prefs` (its RTT-ordered probe results). Every region busy →
/// the nearest anyway (nearest-busy still beats far-and-idle for latency,
/// and thresholds are advisory). `None` = the default region.
pub fn pick_region_with_load(
    map: &TurnMap,
    load: &RelayLoadMap,
    home: Option<&str>,
    prefs: &[String],
) -> Option<String> {
    if !map.enabled {
        return None;
    }
    let home = home.filter(|r| map.regions.contains_key(*r))?;
    if !region_busy(load, home) {
        return Some(home.to_string());
    }
    prefs
        .iter()
        .find(|r| map.regions.contains_key(*r) && !region_busy(load, r))
        .map(|r| r.to_string())
        .or(Some(home.to_string()))
}

/// Pick the relay region for a PAIR from the two ends' `relay_home`s.
/// Interim policy until RTT tables land: agreement wins; a single known home
/// wins over none; two DIFFERENT homes fall to a deterministic FNV pick over
/// the pair key (either end's PoP beats the default-region hairpin for a
/// same-continent pair, and the broker computes this once so both grants
/// agree). `None` = use the default region.
pub fn select_pair_region(
    map: &TurnMap,
    load: &RelayLoadMap,
    home_a: Option<&str>,
    home_b: Option<&str>,
    pair_key: &str,
    needs_tls: bool,
) -> Option<String> {
    if !map.enabled {
        return None;
    }
    // Phase E — region-level capability filter: when either end of the pair
    // can only reach coturn over TLS (measured `!stun_udp`, or srflx-empty
    // as the legacy proxy — derived by the caller), a candidate region must
    // actually serve a TLS variant, or that end's anchor allocation strands
    // at grant time. Falling out of every home lands on the DEFAULT region
    // (`None`), which serves the full variant set. Per-worker filtering is
    // deliberately absent (no recorded intra-region divergence; hand-written
    // per-worker caps would drift exactly like the tribal knowledge did) —
    // and the pair-sticky cache above this fn keys the OUTPUT, so a mid-TTL
    // capability change can never split the two ends' worker sets.
    let serves = |r: &str| -> bool {
        if !needs_tls {
            return true;
        }
        map.specs
            .iter()
            .find(|s| s.id == r)
            .map(|s| s.caps.tls_5349 || s.caps.tls_443_tcp)
            .unwrap_or(true)
    };
    let known_a = home_a.filter(|r| map.regions.contains_key(*r) && serves(r));
    let known_b = home_b.filter(|r| map.regions.contains_key(*r) && serves(r));
    let chosen = match (known_a, known_b) {
        (Some(a), Some(b)) if a == b => Some(a.to_string()),
        (Some(a), Some(b)) => {
            // Sorted so the pick is symmetric in argument order.
            let mut pair = [a, b];
            pair.sort_unstable();
            pick_index_fnv1a(pair_key, 2).map(|i| pair[i].to_string())
        }
        (Some(one), None) | (None, Some(one)) => Some(one.to_string()),
        (None, None) => None,
    }?;
    // Load-aware fallback for pairs: a busy pick moves to the OTHER end's
    // non-busy home, else to the default region (`None`) — per-node RTT
    // tables aren't available on this path, so "next closest" degrades to
    // "the other end's closest, then central".
    if region_busy(load, &chosen) {
        let other = [known_a, known_b]
            .into_iter()
            .flatten()
            .find(|r| *r != chosen && !region_busy(load, r));
        return other.map(|r| r.to_string());
    }
    Some(chosen)
}

/// FR-115 P4b — the marker before the org in a charged username.
const ORG_MARK: &str = "org-";

/// FR-115 P4b — the `user_id` to issue under when the org that pays for the
/// relay is known: `<principal>:org-<org>`. The username then reads
/// `<expiry>:<principal>:org-<org>`, and coturn's statistics name the org.
///
/// ⚠️ The `org-` marker is what makes the org readable, not its position: an
/// overlay pair's principal is itself `<node>:<node>` (`overlay::pair_key`),
/// so an uncharged pair username ends in an ObjectId too — a node's, which a
/// "last hex part" rule would book as an org.
pub fn charged(principal: &str, org_hex: &str) -> String {
    format!("{principal}:{ORG_MARK}{org_hex}")
}

/// FR-115 P4b — the org a coturn username names, when it was issued
/// [`charged`]: the last `:`-separated part, if it is `org-` and a 24-hex
/// ObjectId. `None` for an uncharged username (`<expiry>:<user>`, the
/// session-less pre-fetch), whose bytes are counted as unattributed and never
/// guessed.
pub fn org_of_username(username: &str) -> Option<&str> {
    let org = username.rsplit(':').next()?.strip_prefix(ORG_MARK)?;
    (org.len() == 24 && org.bytes().all(|b| b.is_ascii_hexdigit())).then_some(org)
}

/// Public STUN redundancy for both REST/browser and per-session/native ICE.
/// These are discovery servers, NOT relays: no credentials, TURN allocations,
/// or forced-relay policy. Keep independent providers so one blocked UDP
/// destination does not leave a WAN session with only private host candidates.
pub fn default_stun_servers() -> Vec<IceServer> {
    vec![IceServer {
        urls: vec![
            "stun:stun.cloudflare.com:3478".into(),
            "stun:stun.l.google.com:19302".into(),
        ],
        username: None,
        credential: None,
    }]
}

/// Convenience: also include public STUN servers so trickle ICE has something
/// to work with even before TURN auth completes.
pub fn ice_servers_for(user_id: &str, turn: Option<&TurnConfig>) -> Vec<IceServer> {
    ice_servers_for_with_ttl(user_id, turn, None)
}

/// C4 stage 1.5 — [`ice_servers_for`] with an optional credential-TTL
/// override (see [`TurnConfig::issue_with_ttl`]). `None` = the config TTL.
pub fn ice_servers_for_with_ttl(
    user_id: &str,
    turn: Option<&TurnConfig>,
    ttl_override: Option<u32>,
) -> Vec<IceServer> {
    let mut out = default_stun_servers();
    if let Some(t) = turn {
        out.push(match ttl_override {
            Some(ttl) => t.issue_with_ttl(user_id, ttl),
            None => t.issue(user_id),
        });
    }
    out
}

/// Session-aware variant of [`ice_servers_for`] — used by the Hub on the two
/// per-session issuance paths (`Ready` → controller, `SdpOffer` → agent) so
/// both sides receive the SAME worker-first TURN ordering for one session.
pub fn ice_servers_for_session(
    user_id: &str,
    session_key: &str,
    turn: Option<&TurnConfig>,
) -> Vec<IceServer> {
    let mut out = default_stun_servers();
    if let Some(t) = turn {
        out.push(t.issue_for_session(user_id, session_key));
    }
    out
}

/// FR-90 P0d-2 — [`ice_servers_for_session`] with an explicit credential
/// TTL ([`TurnConfig::issue_for_session_with_ttl`]): the viewer peer's ICE
/// servers, one set minted per grant for both ends.
pub fn ice_servers_for_session_with_ttl(
    user_id: &str,
    session_key: &str,
    turn: Option<&TurnConfig>,
    ttl_secs: u32,
) -> Vec<IceServer> {
    let mut out = default_stun_servers();
    if let Some(t) = turn {
        out.push(t.issue_for_session_with_ttl(user_id, session_key, ttl_secs));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-115 P4b — a charged username names its org at the end, and an
    /// uncharged one names none. The expiry stays first, so coturn's REST
    /// check reads it as before.
    #[test]
    fn a_charged_username_names_its_org() {
        let org = "6a975e17971e2d55ddcdedb2";
        let cfg = TurnConfig {
            urls: vec!["turn:example.test:3478".into()],
            workers: vec![],
            shared_secret: "s".into(),
            ttl_secs: 600,
        };
        let charged_user = charged("6a975e17971e2d55ddcdedb0", org);
        let server = cfg.issue(&charged_user);
        let username = server.username.unwrap();
        assert!(
            username.split(':').next().unwrap().parse::<u64>().is_ok(),
            "the expiry stays before the first ':' ({username})"
        );
        assert_eq!(org_of_username(&username), Some(org));
        // An overlay pair's principal is `<node>:<node>`, charged the same way.
        let (a, b) = ("6a975e17971e2d55ddcdeda1", "6a975e17971e2d55ddcdeda2");
        let pair = format!("{a}:{b}");
        assert_eq!(
            org_of_username(&format!("1792000000:{}", charged(&pair, org))),
            Some(org)
        );
        // ⚠️ Uncharged, that pair ends in a node's ObjectId: not an org.
        assert_eq!(org_of_username(&format!("1792000000:{pair}")), None);
        // Uncharged (the session-less pre-fetch), or not an org at the end.
        assert_eq!(org_of_username("1792000000:6a975e17971e2d55ddcdedb0"), None);
        assert_eq!(org_of_username("1792000000:u:org-not-an-org"), None);
        assert_eq!(org_of_username(&format!("1792000000:u:org-{org}x")), None);
        assert_eq!(org_of_username("garbage"), None);
    }

    fn affinity_cfg() -> TurnConfig {
        TurnConfig {
            urls: vec!["turn:coturn.example:3478".into()],
            workers: vec![
                vec!["turn:coturn-1.example:3478".into()],
                vec!["turn:coturn-2.example:3478".into()],
                vec!["turn:coturn-3.example:3478".into()],
            ],
            shared_secret: "topsecret".into(),
            ttl_secs: 600,
        }
    }

    #[test]
    fn issue_for_session_is_deterministic_and_worker_first() {
        let cfg = affinity_cfg();
        // Same session key → same worker, on every call (this is what makes
        // BOTH sides of one session land on the same coturn worker).
        let a = cfg.issue_for_session("controller", "6a54bf440b4fd609a7356f97");
        let b = cfg.issue_for_session("agent", "6a54bf440b4fd609a7356f97");
        assert_eq!(a.urls[0], b.urls[0], "both sides must pick the same worker");
        assert!(a.urls[0].contains("coturn-"), "worker URL must come first");
        // Generic hostname retained as the fallback tail.
        assert_eq!(a.urls.last().unwrap(), "turn:coturn.example:3478");
    }

    /// worker-pick golden vector — the exact literals pinned in
    /// `worker_pick::tests::worker_pick_golden_vector` (invariant I6),
    /// re-asserted through this consumer's call path.
    #[test]
    fn session_worker_pick_matches_golden_vector() {
        let cfg = affinity_cfg();
        // FNV-1a("6a54bf440b4fd609a7356f97") % 3 == 0 → worker 1 first.
        let s = cfg.issue_for_session("u", "6a54bf440b4fd609a7356f97");
        assert_eq!(s.urls[0], "turn:coturn-1.example:3478");
    }

    /// FR-90 P0d-2 — a viewer peer's credential carries ITS ttl (the
    /// username's expiry is what bounds a TURN allocation's life), and the
    /// same worker affinity as the config-TTL path.
    #[test]
    fn a_session_credential_with_its_own_ttl_keeps_the_worker() {
        let cfg = affinity_cfg();
        let key = "6a54bf440b4fd609a7356f97";
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let long = cfg.issue_for_session_with_ttl("viewer", key, 12 * 3600);
        let expiry: u64 = long
            .username
            .as_deref()
            .unwrap()
            .split(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(
            expiry >= now + 12 * 3600 - 5 && expiry <= now + 12 * 3600 + 5,
            "{expiry} vs {now}"
        );
        assert_eq!(long.urls, cfg.issue_for_session("viewer", key).urls);
        let servers = ice_servers_for_session_with_ttl("viewer", key, Some(&cfg), 12 * 3600);
        assert_eq!(servers.len(), 2, "STUN, then the TURN credential");
        assert_eq!(servers[1].urls, long.urls);
    }

    #[test]
    fn issue_for_session_spreads_across_workers() {
        let cfg = affinity_cfg();
        // Different sessions should not all land on one worker.
        let mut seen = std::collections::HashSet::new();
        for i in 0..32 {
            let s = cfg.issue_for_session("u", &format!("session-{i}"));
            seen.insert(s.urls[0].clone());
        }
        assert!(seen.len() >= 2, "hash must spread sessions across workers");
    }

    #[test]
    fn issue_for_session_without_workers_matches_issue() {
        let cfg = TurnConfig {
            urls: vec!["turn:coturn.example:3478".into()],
            workers: vec![],
            shared_secret: "topsecret".into(),
            ttl_secs: 600,
        };
        let s = cfg.issue_for_session("u1", "any-session");
        assert_eq!(s.urls, vec!["turn:coturn.example:3478".to_string()]);
    }

    #[test]
    fn issues_well_formed_creds() {
        let cfg = TurnConfig {
            urls: vec!["turn:coturn.example:3478".into()],
            workers: vec![],
            shared_secret: "topsecret".into(),
            ttl_secs: 600,
        };
        let cred = cfg.issue("user_42");
        let username = cred.username.unwrap();
        let mut parts = username.splitn(2, ':');
        let expiry: u64 = parts.next().unwrap().parse().unwrap();
        let uid = parts.next().unwrap();
        assert_eq!(uid, "user_42");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(expiry > now && expiry <= now + 600);
        assert!(cred.credential.unwrap().len() >= 20);
    }

    #[test]
    fn stun_redundancy_is_identical_for_browser_native_and_ttl_paths() {
        let expected = default_stun_servers();
        for actual in [
            ice_servers_for("u", None),
            ice_servers_for_session("u", "session", None),
            ice_servers_for_session_with_ttl("u", "session", None, 60),
        ] {
            assert_eq!(actual.len(), 1);
            assert_eq!(actual[0].urls, expected[0].urls);
            assert_eq!(
                actual[0].urls,
                vec![
                    "stun:stun.cloudflare.com:3478",
                    "stun:stun.l.google.com:19302"
                ]
            );
            assert!(actual[0].username.is_none() && actual[0].credential.is_none());
            assert!(actual[0].urls.iter().all(|u| u.starts_with("stun:")));
        }
        let cfg = region_cfg("turn.example");
        let actual = ice_servers_for_session("u", "session", Some(&cfg));
        assert_eq!(actual.len(), 2, "real TURN remains additive, not replaced");
        assert_eq!(actual[0].urls, expected[0].urls);
        assert!(actual[1].urls.iter().all(|u| u.starts_with("turn:")));
        assert!(actual[1].username.is_some() && actual[1].credential.is_some());
    }

    #[test]
    fn ice_list_includes_stun() {
        let list = ice_servers_for("u1", None);
        assert!(list[0].urls[0].starts_with("stun:"));
    }

    fn region_cfg(host: &str) -> TurnConfig {
        TurnConfig {
            urls: vec![format!("turn:{host}:3478")],
            workers: vec![],
            shared_secret: "topsecret".into(),
            ttl_secs: 600,
        }
    }

    fn no_load() -> RelayLoadMap {
        std::sync::Arc::new(dashmap::DashMap::new())
    }

    fn load_with(region: &str, busy: bool, age_s: u64) -> RelayLoadMap {
        let m = no_load();
        m.insert(
            region.to_string(),
            RegionLoad {
                busy,
                load1: 3.0,
                tx_mbps: 450.0,
                coturn_allocations: 10.0,
                updated_unix: now_unix().saturating_sub(age_s),
            },
        );
        m
    }

    fn two_region_map(enabled: bool) -> TurnMap {
        let mut regions = std::collections::HashMap::new();
        regions.insert("us-east".to_string(), region_cfg("coturn-us-east.example"));
        regions.insert("eu-west".to_string(), region_cfg("coturn-eu-west.example"));
        TurnMap {
            default: Some(region_cfg("coturn.example")),
            regions,
            specs: vec![],
            enabled,
        }
    }

    /// The flag-off no-op guarantee: a DISABLED map answers the legacy
    /// default for every input, including a known region id.
    #[test]
    fn disabled_map_always_answers_default() {
        let map = two_region_map(false);
        for region in [None, Some("us-east"), Some("nope")] {
            let cfg = map.cfg_for(region).expect("default present");
            assert_eq!(cfg.urls[0], "turn:coturn.example:3478");
        }
        assert_eq!(
            select_pair_region(
                &map,
                &no_load(),
                Some("us-east"),
                Some("us-east"),
                "k",
                false
            ),
            None
        );
    }

    #[test]
    fn enabled_map_resolves_regions_and_degrades() {
        let map = two_region_map(true);
        assert_eq!(
            map.cfg_for(Some("us-east")).unwrap().urls[0],
            "turn:coturn-us-east.example:3478"
        );
        // Unknown region + None both degrade to the default.
        assert_eq!(
            map.cfg_for(Some("buildhost")).unwrap().urls[0],
            "turn:coturn.example:3478"
        );
        assert_eq!(
            map.cfg_for(None).unwrap().urls[0],
            "turn:coturn.example:3478"
        );
    }

    #[test]
    fn pair_region_agreement_and_fallbacks() {
        let map = two_region_map(true);
        // Agreement.
        assert_eq!(
            select_pair_region(
                &map,
                &no_load(),
                Some("us-east"),
                Some("us-east"),
                "k",
                false
            )
            .as_deref(),
            Some("us-east")
        );
        // One known home wins over none / over an UNKNOWN home.
        assert_eq!(
            select_pair_region(&map, &no_load(), Some("eu-west"), None, "k", false).as_deref(),
            Some("eu-west")
        );
        assert_eq!(
            select_pair_region(&map, &no_load(), Some("gone"), Some("eu-west"), "k", false)
                .as_deref(),
            Some("eu-west")
        );
        // No homes → default region.
        assert_eq!(
            select_pair_region(&map, &no_load(), None, None, "k", false),
            None
        );
        // Differing homes: deterministic AND symmetric in argument order.
        let ab = select_pair_region(
            &map,
            &no_load(),
            Some("us-east"),
            Some("eu-west"),
            "pair-1",
            false,
        );
        let ba = select_pair_region(
            &map,
            &no_load(),
            Some("eu-west"),
            Some("us-east"),
            "pair-1",
            false,
        );
        assert_eq!(ab, ba);
        assert!(ab.as_deref() == Some("us-east") || ab.as_deref() == Some("eu-west"));
    }

    /// Load-aware picks: fresh-busy home falls to the next non-busy pref;
    /// stale-busy is IGNORED (fail-open); all-busy keeps the nearest.
    #[test]
    fn load_aware_pick_and_freshness() {
        let map = two_region_map(true);
        let prefs = vec!["us-east".to_string(), "eu-west".to_string()];

        // Not busy → home.
        assert_eq!(
            pick_region_with_load(&map, &no_load(), Some("us-east"), &prefs).as_deref(),
            Some("us-east")
        );
        // Fresh busy home → next non-busy pref.
        let busy = load_with("us-east", true, 0);
        assert_eq!(
            pick_region_with_load(&map, &busy, Some("us-east"), &prefs).as_deref(),
            Some("eu-west")
        );
        // STALE busy sample → ignored (fail-open).
        let stale = load_with("us-east", true, REGION_LOAD_FRESH_SECS + 30);
        assert_eq!(
            pick_region_with_load(&map, &stale, Some("us-east"), &prefs).as_deref(),
            Some("us-east")
        );
        // Every candidate busy → nearest anyway.
        let all = load_with("us-east", true, 0);
        all.insert(
            "eu-west".into(),
            RegionLoad {
                busy: true,
                load1: 9.0,
                tx_mbps: 480.0,
                coturn_allocations: 99.0,
                updated_unix: now_unix(),
            },
        );
        assert_eq!(
            pick_region_with_load(&map, &all, Some("us-east"), &prefs).as_deref(),
            Some("us-east")
        );
        // Disabled map / unknown home → default region.
        assert_eq!(
            pick_region_with_load(&two_region_map(false), &no_load(), Some("us-east"), &prefs),
            None
        );
        assert_eq!(
            pick_region_with_load(&map, &no_load(), Some("buildhost"), &prefs),
            None
        );

        // Pair fallback: busy pick moves to the other end's home, else default.
        let busy_us = load_with("us-east", true, 0);
        assert_eq!(
            select_pair_region(&map, &busy_us, Some("us-east"), Some("eu-west"), "k", false)
                .as_deref(),
            Some("eu-west")
        );
        assert_eq!(
            select_pair_region(&map, &busy_us, Some("us-east"), Some("us-east"), "k", false),
            None,
            "both ends on the busy region → default"
        );
    }

    #[test]
    fn relay_regions_wire_builds_probe_targets() {
        let spec = |id: &str, url: &str, enabled: bool| RelayRegionSpec {
            id: id.into(),
            turn_url: url.into(),
            worker_urls: vec![],
            derp_url: Some(format!("wss://derp-{id}.example/derp")),
            stats_urls: vec![],
            shared_secret: None,
            caps: Default::default(),
            relay_band: Some((10000, 13000)),
            enabled,
        };
        let mut map = two_region_map(true);
        map.specs = vec![
            spec("us-east", "turn:coturn-us-east.example:3478", true),
            // Disabled spec: parsed but never pushed.
            spec("eu-west", "turn:coturn-eu-west.example:3478", false),
            // Spec without a compiled region (e.g. no secret): never pushed.
            spec("ghost", "turn:ghost.example:3478", true),
        ];
        let (regions, rev) = relay_regions_wire(&map).expect("one probe target");
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].id, "us-east");
        assert_eq!(regions[0].stun, "coturn-us-east.example:3478");
        // Phase E — the region's declared relay band rides the wire.
        assert_eq!(regions[0].relay_band, Some((10000, 13000)));
        // rev is stable across calls (deterministic hash).
        assert_eq!(relay_regions_wire(&map).unwrap().1, rev);
        // Master flag off ⇒ nothing is ever pushed.
        map.enabled = false;
        assert!(relay_regions_wire(&map).is_none());
    }

    /// Phase E — the region-level capability filter: a TLS-needing pair is
    /// never granted a region without a TLS listener; a spec-less region
    /// fails OPEN (region_cfg-only maps stay unfiltered), and needs_tls =
    /// false leaves every input byte-identical to pre-E behavior.
    #[test]
    fn needs_tls_filters_regions_without_a_tls_listener() {
        let spec = |id: &str, tls: bool| RelayRegionSpec {
            id: id.into(),
            turn_url: format!("turn:coturn-{id}.example:3478"),
            worker_urls: vec![],
            derp_url: None,
            stats_urls: vec![],
            shared_secret: None,
            caps: crate::turn_url::VariantCaps {
                tls_5349: tls,
                tls_443_tcp: tls,
                ..Default::default()
            },
            relay_band: None,
            enabled: true,
        };
        let mut map = two_region_map(true);
        map.specs = vec![spec("us-east", false), spec("eu-west", true)];

        // No TLS need: the home wins exactly as before.
        assert_eq!(
            select_pair_region(
                &map,
                &no_load(),
                Some("us-east"),
                Some("us-east"),
                "k",
                false
            )
            .as_deref(),
            Some("us-east")
        );
        // TLS-needing pair homed on the TLS-less region: falls to the OTHER
        // end's (TLS-capable) home…
        assert_eq!(
            select_pair_region(
                &map,
                &no_load(),
                Some("us-east"),
                Some("eu-west"),
                "k",
                true
            )
            .as_deref(),
            Some("eu-west")
        );
        // …and with no qualifying home at all, to the default region (None),
        // which serves the full variant set.
        assert_eq!(
            select_pair_region(
                &map,
                &no_load(),
                Some("us-east"),
                Some("us-east"),
                "k",
                true
            ),
            None
        );
        // A region WITHOUT a spec fails open (filter can't judge it).
        map.specs = vec![];
        assert_eq!(
            select_pair_region(
                &map,
                &no_load(),
                Some("us-east"),
                Some("us-east"),
                "k",
                true
            )
            .as_deref(),
            Some("us-east")
        );
    }

    #[test]
    fn region_spec_parses_with_defaults() {
        let spec: RelayRegionSpec = serde_json::from_str(
            r#"{"id":"us-east","turn_url":"turn:coturn-us-east.roomler.ai:3478",
                "derp_url":"wss://derp-us-east.roomler.ai/derp",
                "caps":{"tls_443_tcp":false}}"#,
        )
        .unwrap();
        assert_eq!(spec.id, "us-east");
        assert!(spec.enabled);
        assert!(spec.worker_urls.is_empty());
        assert!(spec.shared_secret.is_none());
        assert!(!spec.caps.tls_443_tcp);
        assert!(spec.caps.udp_443);
    }
}
