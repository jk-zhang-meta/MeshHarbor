// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-84 D5b — the daemon's side of the companion's Devices page.
//!
//! The desktop companion reaches only this daemon, over the LocalAPI pipe. The
//! daemon holds each enrollment's AGENT token, and the server answers two
//! questions for an agent token (FR-84 D5a): `GET /api/agent/self/devices` —
//! the devices THIS device's overlay netmap already carries, plus itself,
//! searched / sorted / paged on the server — and `GET /api/agent/self/mesh`,
//! the org mesh graph restricted to the same set. This module asks them, with
//! the right org's token, and hands the answer over the pipe as the LocalAPI's
//! leaf types ([`DevicesPage`], [`MeshView`]).
//!
//! What it deliberately is NOT: a second visibility rule. The server decides
//! what a device may see (the join-time netmap shaping); the daemon relays
//! that verbatim and adds nothing but the org label it asked for.
//!
//! ```text
//!  companion ──pipe──▶ LocalAPI Devices{org,q,…} ──▶ SelfView
//!                                                  │ resolve org → (server, agent token)
//!                                                  │ cache hit (10 s / 20 s)? ──▶ answer
//!                                                  ▼ single flight per (org, query)
//!                           GET {server}/api/agent/self/devices?…  (bearer = agent token)
//!                                                  ▼
//!                  2xx → VisibleDevicesPage → DevicesPage (field by field)
//!                  else → Upstream{code}: server_unreachable · unauthorized ·
//!                         unsupported_server · module_unmounted · rate_limited ·
//!                         server_error · bad_request · bad_response
//! ```
//!
//! ⚠️ The token never leaves this process on any path but the `Authorization`
//! header to the org's own server: it is not in a log line, a `Debug` render
//! ([`OrgHttp`] redacts it), an error message or a LocalAPI answer.
//!
//! ⚠️ A failure is a NAMED STATE, never an empty list. An empty page and a
//! server that could not be reached are different facts, and a client that
//! could not tell them apart would paint "no devices" every time the network
//! blinked — the exact failure FR-84 D1 removed from the Routes page.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use meshharbor_node_core::management_path::Candidate;
use meshharbor_remote_control::models::{OsKind, VisibleDeviceRow, VisibleDevicesPage};
use tunnel_core::localapi::{
    DeviceRowLite, DevicesPage, DevicesQuery, GpuFleetPage, GpuUsersPage, MeshView, Response,
};

use crate::config::{AgentConfig, OrgEntry, PRIMARY_ORG_LABEL};

/// Connect budget for one request — a dead route or a black-holed port must
/// fail inside the window a person is looking at the page for.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-candidate connect budget (TCP + TLS handshake) when at least one backup
/// management-path candidate remains, leaving room inside [`REQUEST_TIMEOUT`]
/// to fail over cleanly without surfacing an error.
pub const FAILOVER_CONNECT_TIMEOUT: Duration = Duration::from_millis(3500);
/// Base per-candidate request-header timeout when backup candidates remain
/// (catches both cold TLS stalls and silently black-holed warm keep-alive
/// sockets); extended by any explicit `wait_ms` up to [`FAILOVER_REQUEST_MAX`].
const FAILOVER_REQUEST_BASE: Duration = Duration::from_millis(4500);
/// Upper bound on an individual candidate attempt while another backup
/// candidate still waits, reserving at least 4 s inside [`REQUEST_TIMEOUT`].
const FAILOVER_REQUEST_MAX: Duration = Duration::from_secs(6);
/// Whole-request budget (connect + TLS + answer, across all failover tries).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a failover override candidate stays sticky before re-checking the
/// control socket's primary route (or immediately on `route_generation` bump).
const FALLBACK_STICKY_TTL: Duration = Duration::from_secs(60);
/// Minimum remaining budget needed before attempting an additional candidate.
const MIN_RETRY_REMAINING: Duration = Duration::from_millis(500);
/// Fast transport error window on a reused keep-alive client (e.g. half-open
/// socket after sleep/wake or idle NAT eviction) that earns one fresh retry.
const STALE_POOL_FAST_FAIL: Duration = Duration::from_secs(1);
/// How long a device page stays fresh. The companion re-asks every 30 s while
/// the page is on screen; this only coalesces a burst (a search being typed,
/// two windows, the CLI next to the companion).
pub const DEVICES_FRESH: Duration = Duration::from_secs(10);
/// How long a mesh graph stays fresh — it moves slower, and costs the server
/// more to build.
pub const MESH_FRESH: Duration = Duration::from_secs(20);
/// A failure is held just long enough for callers WAITING on the same key to
/// share it, instead of each re-trying a server that just failed.
const ERROR_HOLD: Duration = Duration::from_secs(2);
/// Distinct (org, query) answers kept. A person types a search one key at a
/// time; the bound keeps that from growing without end.
const CACHE_CAP: usize = 32;
/// The largest answer read. A page is at most 100 rows and a mesh at most 500
/// nodes; anything this big is not one of ours.
const MAX_BODY: usize = 4 * 1024 * 1024;
/// Longest search text forwarded. The pipe admits interactive users, and a
/// megabyte of `q` has no business becoming a URL.
const MAX_QUERY_LEN: usize = 256;
/// Longest `sort` / `dir` value forwarded (the real ones are a dozen bytes).
const MAX_KEY_LEN: usize = 32;

/// One enrollment's HTTP identity: which server to ask and with which agent
/// token. Seeded where the `OrgRuntime` status rows are (boot, and a live
/// `rc:agent.join_org`), from the same config the org's WS loop uses.
#[derive(Clone)]
pub struct OrgHttp {
    /// `primary`, or the `[[orgs]]` label.
    pub label: String,
    pub server_url: String,
    /// ⚠️ Secret. Redacted from `Debug`, never logged. FR-103: the
    /// enrollment's LIVE slot, shared with its signalling loop and read per
    /// request, so a renewed token is the one the next request carries.
    pub token: crate::token_slot::TokenSlot,
    pub primary: bool,
    /// A disabled (or invalid) `[[orgs]]` entry has no loop; the device list
    /// for it is refused as `org_disabled` rather than asked with a token
    /// its operator switched off.
    pub enabled: bool,
}

impl OrgHttp {
    /// The primary enrollment — the config's scalar identity — with its
    /// loop's token slot.
    pub fn primary(cfg: &AgentConfig, token: crate::token_slot::TokenSlot) -> Self {
        Self {
            label: PRIMARY_ORG_LABEL.to_string(),
            server_url: cfg.server_url.clone(),
            token,
            primary: true,
            enabled: true,
        }
    }

    /// A secondary `[[orgs]]` enrollment, with its loop's token slot.
    /// `runnable` is false for an entry the daemon refused to start (a
    /// duplicate or malformed label), which is treated like a disabled one.
    pub fn secondary(org: &OrgEntry, runnable: bool, token: crate::token_slot::TokenSlot) -> Self {
        Self {
            label: org.label.clone(),
            server_url: org.server_url.clone(),
            token,
            primary: false,
            enabled: org.enabled && runnable,
        }
    }
}

impl std::fmt::Debug for OrgHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrgHttp")
            .field("label", &self.label)
            .field("server_url", &self.server_url)
            .field("token", &"<redacted>")
            .field("primary", &self.primary)
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// Shared registry of [`OrgHttp`] rows (primary first).
pub type OrgHttpRegistry = Arc<Mutex<Vec<OrgHttp>>>;

/// Replace the row for `row.label` (or add it) — the live join path, where
/// a re-spawned org must not leave its old token behind.
pub fn upsert(registry: &OrgHttpRegistry, row: OrgHttp) {
    let mut rows = registry.lock().unwrap_or_else(|p| p.into_inner());
    rows.retain(|r| r.label != row.label);
    rows.push(row);
}

/// How long answers stay fresh — a struct so tests can shrink it.
#[derive(Debug, Clone, Copy)]
pub struct Freshness {
    pub devices: Duration,
    pub mesh: Duration,
    pub error: Duration,
}

impl Default for Freshness {
    fn default() -> Self {
        Self {
            devices: DEVICES_FRESH,
            mesh: MESH_FRESH,
            error: ERROR_HOLD,
        }
    }
}

/// A failure, before it becomes a [`Response::Upstream`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Upstream {
    pub code: &'static str,
    pub message: String,
    pub status: Option<u16>,
}

impl Upstream {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            status: None,
        }
    }

    fn into_response(self) -> Response {
        Response::Upstream {
            code: self.code.to_string(),
            message: self.message,
            status: self.status,
        }
    }
}

type Slot = Arc<tokio::sync::Mutex<Option<(Instant, Response)>>>;

struct CacheEntry {
    slot: Slot,
    last_used: Instant,
}

/// `(verb, org label, canonical query)`.
type CacheKey = (&'static str, String, String);

/// Cached production HTTP client for one centre host, bound to a specific
/// management-path candidate so HTTP keep-alive connections are reused across
/// sub-second/1 s GPU polls while still invalidating immediately on route
/// transitions or failing over cleanly when an entry stalls.
#[derive(Clone)]
struct PooledClient {
    client: reqwest::Client,
    candidate: Candidate,
    connect_timeout: Duration,
    route_gen: u64,
    override_until: Option<Instant>,
}

enum HttpClients {
    /// Tests (`SelfView::with_client`): explicit injected client used verbatim.
    Fixed(Result<reqwest::Client, String>),
    /// Production daemon: lazy-built on first real ask and pooled per centre
    /// host so most headless daemons never load TLS roots while active views
    /// reuse warm keep-alive TLS connections across polls.
    Pooled(Mutex<HashMap<String, PooledClient>>),
}

/// The daemon's proxy for the self-view routes. One per daemon; cheap to
/// share (`Arc` it).
pub struct SelfView {
    registry: OrgHttpRegistry,
    http: HttpClients,
    fresh: Freshness,
    cache: Mutex<HashMap<CacheKey, CacheEntry>>,
    /// The last outcome per (verb, org): `None` = answered, `Some(code)` =
    /// failed with that code. Only a CHANGE is logged at info, so a server
    /// down for a day is one line, not 2 880.
    outcomes: Mutex<HashMap<(&'static str, String), Option<&'static str>>>,
}

/// Build a pooled client pinned to one explicit FR-128/FR-134 candidate for `host`.
fn build_candidate_client(
    host: &str,
    candidate: Candidate,
    connect_timeout: Duration,
) -> Result<reqwest::Client, String> {
    build_client_from(
        meshharbor_node_core::management_path::route_http_candidate(
            meshharbor_node_core::http_client::builder(),
            host,
            candidate,
        ),
        connect_timeout,
    )
}

fn build_client_from(
    builder: reqwest::ClientBuilder,
    connect_timeout: Duration,
) -> Result<reqwest::Client, String> {
    builder
        .user_agent(concat!("meshharbord-localapi/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(connect_timeout)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| format!("building the HTTP client: {e}"))
}

impl SelfView {
    /// The daemon's instance: production clients, built lazily on first use.
    pub fn new(registry: OrgHttpRegistry) -> Self {
        Self::assemble(
            registry,
            HttpClients::Pooled(Mutex::new(HashMap::new())),
            Freshness::default(),
        )
    }

    /// Tests: a client of their own (no proxy, short budgets) and short
    /// freshness windows.
    pub fn with_client(
        registry: OrgHttpRegistry,
        http: Result<reqwest::Client, String>,
        fresh: Freshness,
    ) -> Self {
        Self::assemble(registry, HttpClients::Fixed(http), fresh)
    }

    fn assemble(registry: OrgHttpRegistry, http: HttpClients, fresh: Freshness) -> Self {
        Self {
            registry,
            http,
            fresh,
            cache: Mutex::new(HashMap::new()),
            outcomes: Mutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    fn pooled_client_count(&self) -> usize {
        match &self.http {
            HttpClients::Fixed(_) => 1,
            HttpClients::Pooled(pool) => pool.lock().unwrap_or_else(|p| p.into_inner()).len(),
        }
    }

    /// `GET /api/agent/self/devices` for `org` (empty / `primary` = the
    /// primary enrollment) → [`Response::Devices`] or [`Response::Upstream`].
    pub async fn devices(&self, org: &str, query: &DevicesQuery) -> Response {
        const VERB: &str = "devices";
        let started = Instant::now();
        let params = match query_params(query) {
            Ok(p) => p,
            Err(e) => return e.into_response(),
        };
        let target = match self.resolve(org) {
            Ok(t) => t,
            Err(e) => return e.into_response(),
        };
        let key = (VERB, target.label.clone(), canonical(&params));
        let label = target.label.clone();
        let resp = self
            .cached(key, self.fresh.devices, || async move {
                match self.get(&target, "/api/agent/self/devices", &params).await {
                    Ok(body) => match parse_devices_page(&body, &target.label) {
                        Ok(page) => Response::Devices(Box::new(page)),
                        Err(e) => e.into_response(),
                    },
                    Err(e) => e.into_response(),
                }
            })
            .await;
        self.note_outcome(VERB, &label, &resp, started);
        resp
    }

    /// `GET /api/agent/self/mesh` for `org` → [`Response::Mesh`] (whose
    /// `enabled: false` is the server's statistics being off — data) or
    /// [`Response::Upstream`].
    pub async fn mesh(&self, org: &str) -> Response {
        const VERB: &str = "mesh";
        let started = Instant::now();
        let target = match self.resolve(org) {
            Ok(t) => t,
            Err(e) => return e.into_response(),
        };
        let key = (VERB, target.label.clone(), String::new());
        let label = target.label.clone();
        let resp = self
            .cached(key, self.fresh.mesh, || async move {
                match self.get(&target, "/api/agent/self/mesh", &[]).await {
                    Ok(body) => match parse_mesh(&body, &target.label) {
                        Ok(view) => Response::Mesh(Box::new(view)),
                        Err(e) => e.into_response(),
                    },
                    Err(e) => e.into_response(),
                }
            })
            .await;
        self.note_outcome(VERB, &label, &resp, started);
        resp
    }

    /// FR-139 — `GET /api/agent/self/gpu/fleet` for `org`.
    /// When `live` is true, bypasses the short cache so the server immediately
    /// grants/renews a 2 s live sampling lease and optionally waits up to `wait_ms`.
    pub async fn gpu_fleet(
        &self,
        org: &str,
        live: bool,
        wait_ms: u32,
        hosts: &[String],
        interval_ms: Option<u32>,
    ) -> Response {
        const VERB: &str = "gpu_fleet";
        let started = Instant::now();
        let target = match self.resolve(org) {
            Ok(t) => t,
            Err(e) => return e.into_response(),
        };
        let mut params: Vec<(&'static str, String)> = Vec::new();
        if live {
            params.push(("live", "1".to_string()));
            if let Some(iv) = interval_ms {
                params.push(("interval_ms", iv.clamp(500, 10_000).to_string()));
            }
        }
        if wait_ms > 0 {
            params.push(("wait_ms", wait_ms.min(3000).to_string()));
        }
        if !hosts.is_empty() {
            let joined = hosts
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(",");
            if !joined.is_empty() {
                params.push(("hosts", joined));
            }
        }
        let label = target.label.clone();
        let resp = if live {
            match self
                .get(&target, "/api/agent/self/gpu/fleet", &params)
                .await
            {
                Ok(body) => match parse_gpu_fleet(&body, &target.label) {
                    Ok(page) => Response::GpuFleet(Box::new(page)),
                    Err(e) => e.into_response(),
                },
                Err(e) => e.into_response(),
            }
        } else {
            let key = (VERB, target.label.clone(), canonical(&params));
            self.cached(key, self.fresh.devices, || async move {
                match self
                    .get(&target, "/api/agent/self/gpu/fleet", &params)
                    .await
                {
                    Ok(body) => match parse_gpu_fleet(&body, &target.label) {
                        Ok(page) => Response::GpuFleet(Box::new(page)),
                        Err(e) => e.into_response(),
                    },
                    Err(e) => e.into_response(),
                }
            })
            .await
        };
        self.note_outcome(VERB, &label, &resp, started);
        resp
    }

    /// FR-139 — `GET /api/agent/self/gpu/users` for `org`.
    pub async fn gpu_users(&self, org: &str, range: &str) -> Response {
        const VERB: &str = "gpu_users";
        let started = Instant::now();
        let target = match self.resolve(org) {
            Ok(t) => t,
            Err(e) => return e.into_response(),
        };
        let norm_range = match range.trim() {
            "7d" => "7d",
            "30d" => "30d",
            _ => "24h",
        };
        let params = vec![("range", norm_range.to_string())];
        let key = (VERB, target.label.clone(), canonical(&params));
        let label = target.label.clone();
        let resp = self
            .cached(key, self.fresh.mesh, || async move {
                match self
                    .get(&target, "/api/agent/self/gpu/users", &params)
                    .await
                {
                    Ok(body) => match parse_gpu_users(&body, &target.label) {
                        Ok(page) => Response::GpuUsers(page),
                        Err(e) => e.into_response(),
                    },
                    Err(e) => e.into_response(),
                }
            })
            .await;
        self.note_outcome(VERB, &label, &resp, started);
        resp
    }
    /// primary enrollment, whatever its row is labelled.
    fn resolve(&self, org: &str) -> Result<OrgHttp, Upstream> {
        let want = org.trim();
        let rows = self.registry.lock().unwrap_or_else(|p| p.into_inner());
        let row = if want.is_empty() || want == PRIMARY_ORG_LABEL {
            rows.iter().find(|r| r.primary)
        } else {
            rows.iter().find(|r| r.label == want)
        };
        let Some(row) = row else {
            return Err(Upstream::new(
                "unknown_org",
                format!(
                    "this device has no enrollment labelled {want:?} (see `meshharbord org ls`)"
                ),
            ));
        };
        if !row.enabled {
            return Err(Upstream::new(
                "org_disabled",
                format!(
                    "the enrollment {:?} is disabled on this device, so the daemon does not \
                     speak for it",
                    row.label
                ),
            ));
        }
        Ok(row.clone())
    }

    /// Serve `key` from the cache while fresh; otherwise run `fetch` — ONCE,
    /// however many callers ask for the same key at the same moment (they
    /// wait on the key's lock and read what the first one stored).
    async fn cached<F, Fut>(&self, key: CacheKey, fresh_for: Duration, fetch: F) -> Response
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Response>,
    {
        let slot = self.slot(&key);
        let mut held = slot.lock().await;
        if let Some((at, resp)) = held.as_ref() {
            let ttl = if is_answer(resp) {
                fresh_for
            } else {
                self.fresh.error
            };
            if at.elapsed() < ttl {
                return resp.clone();
            }
        }
        let resp = fetch().await;
        *held = Some((Instant::now(), resp.clone()));
        resp
    }

    /// The key's slot, created on first use. Over the cap, idle slots (no
    /// caller holding them) go first, least recently used first; a slot in
    /// use is never evicted, so the map can exceed the cap only by the number
    /// of asks in flight.
    fn slot(&self, key: &CacheKey) -> Slot {
        let mut map = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        if let Some(e) = map.get_mut(key) {
            e.last_used = now;
            return e.slot.clone();
        }
        if map.len() >= CACHE_CAP {
            let mut idle: Vec<(CacheKey, Instant)> = map
                .iter()
                .filter(|(_, e)| Arc::strong_count(&e.slot) == 1)
                .map(|(k, e)| (k.clone(), e.last_used))
                .collect();
            idle.sort_by_key(|(_, at)| *at);
            let excess = map.len() + 1 - CACHE_CAP;
            for (k, _) in idle.into_iter().take(excess) {
                map.remove(&k);
            }
        }
        let slot: Slot = Arc::new(tokio::sync::Mutex::new(None));
        map.insert(
            key.clone(),
            CacheEntry {
                slot: slot.clone(),
                last_used: now,
            },
        );
        slot
    }

    #[cfg(test)]
    fn cache_len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    /// Look up a warm cached client for `(host, candidate, connect_timeout, route_gen)`, or build
    /// a fresh one without caching it yet (callers store only on a successful connect/response).
    fn get_or_build_pooled(
        pool: &Mutex<HashMap<String, PooledClient>>,
        host: &str,
        candidate: Candidate,
        connect_timeout: Duration,
        route_gen: u64,
    ) -> Result<(reqwest::Client, bool), String> {
        {
            let guard = pool.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(entry) = guard.get(host)
                && entry.candidate == candidate
                && entry.connect_timeout == connect_timeout
                && entry.route_gen == route_gen
            {
                return Ok((entry.client.clone(), true));
            }
        }
        let client = build_candidate_client(host, candidate, connect_timeout)?;
        Ok((client, false))
    }

    fn store_pooled(pool: &Mutex<HashMap<String, PooledClient>>, host: &str, entry: PooledClient) {
        let mut guard = pool.lock().unwrap_or_else(|p| p.into_inner());
        guard.insert(host.to_string(), entry);
    }

    fn evict_pooled(pool: &Mutex<HashMap<String, PooledClient>>, host: &str, candidate: Candidate) {
        let mut guard = pool.lock().unwrap_or_else(|p| p.into_inner());
        if guard.get(host).is_some_and(|e| e.candidate == candidate) {
            guard.remove(host);
        }
    }

    /// Reconcile any cached client for `host` with the current `route_gen` and candidate ladder:
    /// - When `route_gen` changed to the exact candidate we already hold, keep the warm pool.
    /// - When `route_gen` changed to a different primary candidate, drop the old pool.
    /// - When `route_gen` is unchanged and a non-expired sticky failover candidate is still in
    ///   `candidates`, promote it to index 0 so live sub-second/1 s polls do not re-hit a stalled
    ///   entry on every tick.
    fn apply_sticky_candidate(
        pool: &Mutex<HashMap<String, PooledClient>>,
        host: &str,
        route_gen: u64,
        candidates: &mut Vec<Candidate>,
    ) -> Option<Instant> {
        let primary = candidates[0];
        let mut guard = pool.lock().unwrap_or_else(|p| p.into_inner());
        let entry = guard.get_mut(host)?;
        if entry.route_gen != route_gen {
            if entry.candidate == primary {
                entry.route_gen = route_gen;
                entry.override_until = None;
            } else {
                guard.remove(host);
            }
            return None;
        }
        if entry.candidate == primary {
            return None;
        }
        let until = entry.override_until.filter(|u| Instant::now() < *u);
        if let Some(until) = until
            && candidates.contains(&entry.candidate)
        {
            let sticky = entry.candidate;
            candidates.retain(|c| *c != sticky);
            candidates.insert(0, sticky);
            return Some(until);
        }
        guard.remove(host);
        None
    }

    /// One authenticated GET against the org's server. `Ok` is a 2xx body;
    /// every other outcome is a named [`Upstream`].
    async fn get(
        &self,
        org: &OrgHttp,
        path: &str,
        params: &[(&'static str, String)],
    ) -> Result<Vec<u8>, Upstream> {
        let base = org.server_url.trim().trim_end_matches('/');
        if !(base.starts_with("https://") || base.starts_with("http://")) {
            return Err(Upstream::new(
                "server_unreachable",
                format!(
                    "the {} enrollment's server URL is not http(s): {base:?}",
                    org.label
                ),
            ));
        }
        let url = format!("{base}{path}");
        match &self.http {
            HttpClients::Fixed(fixed) => {
                let http = fixed
                    .as_ref()
                    .map_err(|e| Upstream::new("server_unreachable", e.clone()))?;
                let resp = http
                    .get(&url)
                    .bearer_auth(org.token.get())
                    .query(params)
                    .send()
                    .await
                    .map_err(|e| transport_error(base, e, CONNECT_TIMEOUT, REQUEST_TIMEOUT))?;
                finish_response(base, resp, CONNECT_TIMEOUT, REQUEST_TIMEOUT).await
            }
            HttpClients::Pooled(pool) => {
                let host = meshharbor_node_core::management_path::centre_host(base);
                let route_gen = meshharbor_node_core::management_path::route_generation();
                let (mut candidates, _last_resort) =
                    meshharbor_node_core::management_path::http_candidates_for_url(base);
                if candidates.is_empty() {
                    candidates.push(Candidate::Direct);
                }
                let primary_candidate = candidates[0];
                let sticky_until =
                    Self::apply_sticky_candidate(pool, &host, route_gen, &mut candidates);

                let wait_budget = params
                    .iter()
                    .find(|(k, _)| *k == "wait_ms")
                    .and_then(|(_, v)| v.parse::<u64>().ok())
                    .map(|ms| Duration::from_millis(ms.min(3000)))
                    .unwrap_or(Duration::ZERO);
                let total_candidates = candidates.len();
                let pool_connect_timeout = if total_candidates > 1 {
                    FAILOVER_CONNECT_TIMEOUT
                } else {
                    CONNECT_TIMEOUT
                };
                let overall_deadline = Instant::now() + REQUEST_TIMEOUT;
                let mut last_err: Option<Upstream> = None;

                for (idx, candidate) in candidates.iter().copied().enumerate() {
                    let remaining = overall_deadline.saturating_duration_since(Instant::now());
                    if idx > 0 && remaining < MIN_RETRY_REMAINING {
                        break;
                    }
                    let has_more = idx + 1 < total_candidates;
                    let request_budget = if has_more {
                        (FAILOVER_REQUEST_BASE + wait_budget)
                            .min(FAILOVER_REQUEST_MAX)
                            .min(remaining)
                    } else {
                        remaining
                    };

                    let (client, was_reused) = match Self::get_or_build_pooled(
                        pool,
                        &host,
                        candidate,
                        pool_connect_timeout,
                        route_gen,
                    ) {
                        Ok(pair) => pair,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "localapi self-view: no HTTP client — the view will report server_unreachable"
                            );
                            last_err = Some(Upstream::new("server_unreachable", e));
                            continue;
                        }
                    };

                    let attempt_started = Instant::now();
                    match client
                        .get(&url)
                        .bearer_auth(org.token.get())
                        .query(params)
                        .timeout(request_budget)
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            if !was_reused {
                                let override_until = if candidate == primary_candidate {
                                    None
                                } else if idx == 0 && sticky_until.is_some() {
                                    sticky_until
                                } else {
                                    Some(Instant::now() + FALLBACK_STICKY_TTL)
                                };
                                Self::store_pooled(
                                    pool,
                                    &host,
                                    PooledClient {
                                        client,
                                        candidate,
                                        connect_timeout: pool_connect_timeout,
                                        route_gen,
                                        override_until,
                                    },
                                );
                            }
                            if idx > 0 {
                                tracing::info!(
                                    org = %org.label,
                                    from = %candidates[0],
                                    to = %candidate,
                                    elapsed_ms = attempt_started.elapsed().as_millis() as u64,
                                    "localapi self-view: failed over to alternate management path"
                                );
                            }
                            return finish_response(
                                base,
                                resp,
                                pool_connect_timeout,
                                request_budget,
                            )
                            .await;
                        }
                        Err(e) => {
                            let attempt_elapsed = attempt_started.elapsed();
                            Self::evict_pooled(pool, &host, candidate);

                            // Single-candidate stale keep-alive protection: if a reused pooled
                            // socket failed fast (e.g. half-open TCP after sleep/wake or NAT
                            // idle timeout), retry once on a fresh connection.
                            if !has_more
                                && idx == 0
                                && was_reused
                                && !e.is_timeout()
                                && attempt_elapsed < STALE_POOL_FAST_FAIL
                            {
                                let retry_remaining =
                                    overall_deadline.saturating_duration_since(Instant::now());
                                if retry_remaining >= MIN_RETRY_REMAINING
                                    && let Ok(fresh) = build_candidate_client(
                                        &host,
                                        candidate,
                                        pool_connect_timeout,
                                    )
                                {
                                    match fresh
                                        .get(&url)
                                        .bearer_auth(org.token.get())
                                        .query(params)
                                        .timeout(retry_remaining)
                                        .send()
                                        .await
                                    {
                                        Ok(resp) => {
                                            Self::store_pooled(
                                                pool,
                                                &host,
                                                PooledClient {
                                                    client: fresh,
                                                    candidate,
                                                    connect_timeout: pool_connect_timeout,
                                                    route_gen,
                                                    override_until: None,
                                                },
                                            );
                                            return finish_response(
                                                base,
                                                resp,
                                                pool_connect_timeout,
                                                retry_remaining,
                                            )
                                            .await;
                                        }
                                        Err(e2) => {
                                            last_err = Some(transport_error(
                                                base,
                                                e2,
                                                pool_connect_timeout,
                                                retry_remaining,
                                            ));
                                            break;
                                        }
                                    }
                                }
                            }

                            last_err = Some(transport_error(
                                base,
                                e,
                                pool_connect_timeout,
                                request_budget,
                            ));
                        }
                    }
                }

                Err(last_err.unwrap_or_else(|| {
                    Upstream::new(
                        "server_unreachable",
                        format!(
                            "no answer from {base} within {}",
                            fmt_budget(REQUEST_TIMEOUT)
                        ),
                    )
                }))
            }
        }
    }

    /// Log a CHANGE of outcome per (verb, org) at info, everything at debug.
    fn note_outcome(&self, verb: &'static str, org: &str, resp: &Response, started: Instant) {
        let code: Option<&'static str> = match resp {
            r if is_answer(r) => None,
            Response::Upstream { code, .. } => Some(static_code(code)),
            _ => Some("error"),
        };
        let elapsed_ms = started.elapsed().as_millis() as u64;
        let previous = self
            .outcomes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((verb, org.to_string()), code);
        let changed = previous != Some(code);
        match (resp, changed) {
            (
                Response::Upstream {
                    code,
                    message,
                    status,
                },
                true,
            ) => tracing::info!(
                verb, org, code = %code, status = ?status, %message, elapsed_ms,
                "localapi self-view: the server did not give the list"
            ),
            (_, true) if matches!(previous, Some(Some(_))) => tracing::info!(
                verb,
                org,
                elapsed_ms,
                "localapi self-view: the server answers again"
            ),
            _ => tracing::debug!(verb, org, code = ?code, elapsed_ms, "localapi self-view"),
        }
    }
}

/// A successful answer (as opposed to a failure held for [`ERROR_HOLD`]).
fn is_answer(resp: &Response) -> bool {
    matches!(
        resp,
        Response::Devices(_) | Response::Mesh(_) | Response::GpuFleet(_) | Response::GpuUsers(_)
    )
}

fn parse_gpu_fleet(body: &[u8], org: &str) -> Result<GpuFleetPage, Upstream> {
    let mut page: GpuFleetPage = serde_json::from_slice(body).map_err(|e| {
        Upstream::new(
            "bad_response",
            format!("could not decode GPU fleet JSON from server: {e}"),
        )
    })?;
    page.org = org.to_string();
    Ok(page)
}

fn parse_gpu_users(body: &[u8], org: &str) -> Result<GpuUsersPage, Upstream> {
    let mut page: GpuUsersPage = serde_json::from_slice(body).map_err(|e| {
        Upstream::new(
            "bad_response",
            format!("could not decode GPU users JSON from server: {e}"),
        )
    })?;
    page.org = org.to_string();
    Ok(page)
}

/// The outcome map stores `&'static str`s; map a code back to its constant.
fn static_code(code: &str) -> &'static str {
    const CODES: [&str; 12] = [
        "server_unreachable",
        "unauthorized",
        "unsupported_server",
        "module_unmounted",
        "rate_limited",
        "server_error",
        "bad_request",
        "bad_response",
        "unknown_org",
        "org_disabled",
        "unsupported",
        "error",
    ];
    CODES
        .iter()
        .copied()
        .find(|c| *c == code)
        .unwrap_or("error")
}

/// The query as the server's grid wants it: only what was asked, validated
/// for size (never for meaning — the server owns the sort keys and says 400
/// for one it does not know).
fn query_params(q: &DevicesQuery) -> Result<Vec<(&'static str, String)>, Upstream> {
    let mut out = Vec::new();
    if q.page > 0 {
        out.push(("page", q.page.to_string()));
    }
    if q.per_page > 0 {
        out.push(("per_page", q.per_page.to_string()));
    }
    if let Some(text) = q.q.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        if text.chars().count() > MAX_QUERY_LEN {
            return Err(Upstream::new(
                "bad_request",
                format!("the search text is longer than {MAX_QUERY_LEN} characters"),
            ));
        }
        out.push(("q", text.to_string()));
    }
    for (name, value) in [("sort", &q.sort), ("dir", &q.dir)] {
        if let Some(v) = value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
            if v.len() > MAX_KEY_LEN {
                return Err(Upstream::new(
                    "bad_request",
                    format!("`{name}` is longer than {MAX_KEY_LEN} characters"),
                ));
            }
            out.push((name, v.to_string()));
        }
    }
    Ok(out)
}

fn canonical(params: &[(&'static str, String)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

enum BodyError {
    TooLarge,
    Transport(reqwest::Error),
}

/// Read the body, refusing anything over `cap` — declared or actual.
async fn read_capped(mut resp: reqwest::Response, cap: usize) -> Result<Vec<u8>, BodyError> {
    if resp.content_length().is_some_and(|len| len > cap as u64) {
        return Err(BodyError::TooLarge);
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(BodyError::Transport)? {
        if out.len() + chunk.len() > cap {
            return Err(BodyError::TooLarge);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

async fn finish_response(
    base: &str,
    resp: reqwest::Response,
    connect_timeout: Duration,
    request_timeout: Duration,
) -> Result<Vec<u8>, Upstream> {
    let status = resp.status().as_u16();
    let body = read_capped(resp, MAX_BODY).await.map_err(|e| match e {
        BodyError::TooLarge => Upstream {
            code: "bad_response",
            message: format!("the server's answer is larger than {MAX_BODY} bytes"),
            status: Some(status),
        },
        BodyError::Transport(e) => transport_error(base, e, connect_timeout, request_timeout),
    })?;
    if (200..300).contains(&status) {
        Ok(body)
    } else {
        Err(classify_status(status, &body))
    }
}

fn fmt_budget(d: Duration) -> String {
    if d.subsec_millis() == 0 {
        format!("{}s", d.as_secs().max(1))
    } else {
        format!("{:.1}s", d.as_secs_f64())
    }
}

/// A request that never got an HTTP status: connect / DNS / TLS failures and
/// timeouts. All `server_unreachable`; the message says which, with the
/// underlying cause (reqwest's own Display is only "error sending request").
fn transport_error(
    server: &str,
    e: reqwest::Error,
    connect_timeout: Duration,
    request_timeout: Duration,
) -> Upstream {
    let what = if e.is_connect() && e.is_timeout() {
        format!(
            "could not connect to {server} within {}",
            fmt_budget(connect_timeout)
        )
    } else if e.is_timeout() {
        format!(
            "no answer from {server} within {}",
            fmt_budget(request_timeout)
        )
    } else if e.is_connect() {
        format!("could not connect to {server}")
    } else {
        format!("the request to {server} failed")
    };
    // The URL carries only the path and the search text, but the chain below
    // is the useful part; strip the URL so the line stays short.
    let e = e.without_url();
    let mut chain = e.to_string();
    let mut source = std::error::Error::source(&e);
    while let Some(s) = source {
        let text = s.to_string();
        if !chain.contains(&text) {
            chain.push_str(": ");
            chain.push_str(&text);
        }
        source = s.source();
    }
    Upstream::new("server_unreachable", format!("{what} ({chain})"))
}

/// A non-2xx answer → its named cause. Pure, so the table is a unit test.
///
/// ⚠️ A 503 is `module_unmounted` only when it is the SERVER's own 503 (its
/// JSON error body, `"error": "service_unavailable"`) — a load balancer's
/// 503 during a pod roll is a transient server error, and naming it "the
/// module is not mounted" would send an operator to the wrong fix.
pub(crate) fn classify_status(status: u16, body: &[u8]) -> Upstream {
    #[derive(serde::Deserialize)]
    struct ApiErrorBody {
        #[serde(default)]
        error: String,
        #[serde(default)]
        message: String,
    }
    let api: Option<ApiErrorBody> = serde_json::from_slice(body).ok();
    let said = api
        .as_ref()
        .map(|a| a.message.trim())
        .filter(|m| !m.is_empty())
        .map(str::to_string);
    let (code, message) = match status {
        400 => (
            "bad_request",
            said.unwrap_or_else(|| "the server refused the query".to_string()),
        ),
        401 => (
            "unauthorized",
            "the server refused this device's credentials — it may have been removed from \
             its organization or quarantined (re-enroll it)"
                .to_string(),
        ),
        404 => (
            "unsupported_server",
            "the server does not offer the device list yet — it predates FR-84; update the \
             server"
                .to_string(),
        ),
        429 => (
            "rate_limited",
            "the server is rate-limiting this address — the list will be asked for again \
             shortly"
                .to_string(),
        ),
        503 if api
            .as_ref()
            .is_some_and(|a| a.error == "service_unavailable") =>
        {
            (
                "module_unmounted",
                said.unwrap_or_else(|| "a module this needs is not mounted on the server".into()),
            )
        }
        _ => (
            "server_error",
            match said {
                Some(m) => format!("the server answered HTTP {status}: {m}"),
                None => format!("the server answered HTTP {status}"),
            },
        ),
    };
    Upstream {
        code,
        message,
        status: Some(status),
    }
}

/// The server's page → the LocalAPI's. Typed first, through the server's own
/// struct and the exhaustive conversion below; if that parse fails — a newer
/// server listing an OS this build's enum does not know — the tolerant leaf
/// parse takes over, so a newer server can never blank an older daemon's
/// list. Both failing is `bad_response`.
pub(crate) fn parse_devices_page(body: &[u8], org: &str) -> Result<DevicesPage, Upstream> {
    match serde_json::from_slice::<VisibleDevicesPage>(body) {
        Ok(page) => Ok(devices_page_from_server(page, org)),
        Err(typed) => match serde_json::from_slice::<DevicesPage>(body) {
            Ok(mut page) => {
                tracing::debug!(error = %typed, "localapi self-view: typed parse failed, the tolerant one answered");
                page.org = org.to_string();
                Ok(page)
            }
            Err(_) => Err(Upstream::new(
                "bad_response",
                format!("the server's device list could not be read: {typed}"),
            )),
        },
    }
}

/// The server's mesh payload is JSON it builds by hand (`stats::to_payload`),
/// so the leaf type IS the only typed shape; it tolerates the rest.
pub(crate) fn parse_mesh(body: &[u8], org: &str) -> Result<MeshView, Upstream> {
    let mut view: MeshView = serde_json::from_slice(body).map_err(|e| {
        Upstream::new(
            "bad_response",
            format!("the server's mesh graph could not be read: {e}"),
        )
    })?;
    view.org = org.to_string();
    Ok(view)
}

/// `VisibleDevicesPage` → [`DevicesPage`], field by field.
pub(crate) fn devices_page_from_server(page: VisibleDevicesPage, org: &str) -> DevicesPage {
    // Exhaustive on purpose (no `..`): a field added to the server's page must
    // fail to compile HERE until someone decides whether the companion gets it.
    let VisibleDevicesPage {
        items,
        total,
        page,
        per_page,
        total_pages,
        overlay,
        acl_mode,
        self_node_id,
        org_name,
    } = page;
    DevicesPage {
        org: org.to_string(),
        items: items.into_iter().map(device_row_from_server).collect(),
        total,
        page,
        per_page,
        total_pages,
        overlay,
        acl_mode,
        self_node_id,
        org_name,
    }
}

/// `VisibleDeviceRow` → [`DeviceRowLite`], field by field — the NetmapPeer →
/// PeerInfo discipline. Exhaustive on purpose (no `..`): a field the server
/// adds must fail to compile here, because what a DEVICE may see about its
/// peers is a security decision (the server row deliberately has no slot for
/// `machine_id`, owner ids or keys), not a serde default.
pub(crate) fn device_row_from_server(row: VisibleDeviceRow) -> DeviceRowLite {
    let VisibleDeviceRow {
        kind,
        id,
        name,
        display_name,
        os,
        version,
        presence,
        is_online,
        last_seen_at,
        overlay_ip,
        overlay_node_id,
        magic_dns_name,
        magic_dns_fqdn,
        tags,
        reachable,
        ephemeral,
        is_self,
        rdp_available,
        rdp_port,
        rdp_cert_sha256,
        rdp_mesh_reachable,
        public_ip,
        physical_public_ip,
        physical_seen_at,
        country_code,
        country,
        region,
        city,
        lat,
        lon,
        accuracy_radius_km,
        geo_level,
        pinned_zone_id,
        effective_zone_id,
        effective_zone_name,
        zone_source,
        default_route_vpn,
    } = row;
    DeviceRowLite {
        kind,
        id,
        name,
        display_name,
        os: os_wire(os).to_string(),
        version,
        presence,
        is_online,
        last_seen_at,
        overlay_ip,
        overlay_node_id,
        magic_dns_name,
        magic_dns_fqdn,
        tags,
        reachable,
        ephemeral,
        is_self,
        rdp_available,
        rdp_port,
        rdp_cert_sha256,
        rdp_mesh_reachable,
        public_ip,
        physical_public_ip,
        physical_seen_at,
        country_code,
        country,
        region,
        city,
        lat,
        lon,
        accuracy_radius_km,
        geo_level: geo_level.map(|g| g.as_str().to_string()),
        pinned_zone_id,
        effective_zone_id,
        effective_zone_name,
        zone_source: zone_source.map(|s| s.as_str().to_string()),
        default_route_vpn,
    }
}

/// The server's `OsKind` spelling (its serde `snake_case`). Exhaustive, so a
/// new OS is a compile error here rather than a silent fallback.
fn os_wire(os: OsKind) -> &'static str {
    match os {
        OsKind::Linux => "linux",
        OsKind::Macos => "macos",
        OsKind::Windows => "windows",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn server_row() -> VisibleDeviceRow {
        VisibleDeviceRow {
            kind: "tunnel_client".into(),
            id: "0123456789abcdef01234567".into(),
            name: "bravo-box".into(),
            display_name: Some("Kilo".into()),
            os: OsKind::Macos,
            version: "0.4.103".into(),
            presence: "stale".into(),
            is_online: true,
            last_seen_at: "2026-09-25T09:00:00Z".into(),
            overlay_ip: Some("100.64.0.3".into()),
            overlay_node_id: Some("76543210fedcba9876543210".into()),
            magic_dns_name: Some("bravo-box".into()),
            magic_dns_fqdn: Some("bravo-box.acme.meshharbor.net".into()),
            tags: vec!["lab".into(), "prod".into()],
            reachable: true,
            ephemeral: true,
            is_self: true,
            rdp_available: Some(true),
            rdp_port: Some(13389),
            rdp_mesh_reachable: Some(true),
            rdp_cert_sha256: Some(
                "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"
                    .into(),
            ),
            public_ip: Some("14.20.0.1".into()),
            physical_public_ip: Some("198.51.100.10".into()),
            physical_seen_at: Some("2026-09-25T08:55:00Z".into()),
            country_code: Some("CN".into()),
            country: Some("中国".into()),
            region: Some("广东省".into()),
            city: Some("深圳市".into()),
            lat: Some(22.5431),
            lon: Some(114.0579),
            accuracy_radius_km: Some(50),
            geo_level: Some(meshharbor_remote_control::models::GeoLevel::Coords),
            pinned_zone_id: Some("siat".into()),
            effective_zone_id: Some("siat".into()),
            effective_zone_name: Some("SIAT Campus".into()),
            zone_source: Some(meshharbor_remote_control::models::ZoneSource::AutoPhysical),
            default_route_vpn: true,
        }
    }

    /// The two mirrors cannot drift silently: a FULLY populated server row
    /// (every field non-default, so no omission rule can hide one) converts
    /// field for field, and the JSON the companion receives is the JSON the
    /// server sent — same keys, same values.
    #[test]
    fn a_fully_populated_server_row_converts_field_for_field() {
        let row = server_row();
        let lite = device_row_from_server(row.clone());
        assert_eq!(
            lite,
            DeviceRowLite {
                kind: "tunnel_client".into(),
                id: "0123456789abcdef01234567".into(),
                name: "bravo-box".into(),
                display_name: Some("Kilo".into()),
                os: "macos".into(),
                version: "0.4.103".into(),
                presence: "stale".into(),
                is_online: true,
                last_seen_at: "2026-09-25T09:00:00Z".into(),
                overlay_ip: Some("100.64.0.3".into()),
                overlay_node_id: Some("76543210fedcba9876543210".into()),
                magic_dns_name: Some("bravo-box".into()),
                magic_dns_fqdn: Some("bravo-box.acme.meshharbor.net".into()),
                tags: vec!["lab".into(), "prod".into()],
                reachable: true,
                ephemeral: true,
                is_self: true,
                rdp_available: Some(true),
                rdp_port: Some(13389),
                rdp_mesh_reachable: Some(true),
                rdp_cert_sha256: Some(
                    "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"
                        .into(),
                ),
                public_ip: Some("14.20.0.1".into()),
                physical_public_ip: Some("198.51.100.10".into()),
                physical_seen_at: Some("2026-09-25T08:55:00Z".into()),
                country_code: Some("CN".into()),
                country: Some("中国".into()),
                region: Some("广东省".into()),
                city: Some("深圳市".into()),
                lat: Some(22.5431),
                lon: Some(114.0579),
                accuracy_radius_km: Some(50),
                geo_level: Some("coords".into()),
                pinned_zone_id: Some("siat".into()),
                effective_zone_id: Some("siat".into()),
                effective_zone_name: Some("SIAT Campus".into()),
                zone_source: Some("auto_physical".into()),
                default_route_vpn: true,
            }
        );
        assert_eq!(
            serde_json::to_value(&row).unwrap(),
            serde_json::to_value(&lite).unwrap(),
            "the leaf row must serialise exactly like the server's"
        );

        let page = VisibleDevicesPage {
            items: vec![row],
            total: 17,
            page: 2,
            per_page: 10,
            total_pages: 2,
            overlay: "ok".into(),
            acl_mode: "enforce".into(),
            self_node_id: Some("aaaaaaaaaaaaaaaaaaaaaaaa".into()),
            org_name: Some("Example Org".into()),
        };
        let lite = devices_page_from_server(page.clone(), "acme");
        assert_eq!(lite.org_name.as_deref(), Some("Example Org"));
        assert_eq!(lite.org, "acme");
        let mut server = serde_json::to_value(&page).unwrap();
        server["org"] = serde_json::json!("acme");
        assert_eq!(server, serde_json::to_value(&lite).unwrap());

        // Every OS the server can name maps to its own serde spelling.
        for os in [OsKind::Linux, OsKind::Macos, OsKind::Windows] {
            assert_eq!(
                serde_json::to_value(os).unwrap(),
                serde_json::json!(os_wire(os))
            );
        }
    }

    /// A newer server may list a device whose OS this build's enum does not
    /// know. The typed parse fails on the whole page; the tolerant one must
    /// still produce it, row for row.
    #[test]
    fn a_newer_server_page_falls_back_to_the_tolerant_parse() {
        let body = br#"{"items":[
            {"kind":"agent","id":"a","name":"phone","os":"android","presence":"online","is_self":false},
            {"kind":"agent","id":"b","name":"box","os":"linux","presence":"offline","is_self":true}
          ],"total":2,"page":1,"per_page":25,"total_pages":1,"overlay":"ok","acl_mode":"off",
          "some_future_field":true}"#;
        assert!(serde_json::from_slice::<VisibleDevicesPage>(body).is_err());
        let page = parse_devices_page(body, "primary").unwrap();
        assert_eq!(page.org, "primary");
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].os, "android");
        assert!(page.items[1].is_self);

        let err = parse_devices_page(b"<html>gateway</html>", "primary").unwrap_err();
        assert_eq!(err.code, "bad_response");
    }

    /// Every failure status names its cause, and a 503 is `module_unmounted`
    /// only when the server itself said so.
    #[test]
    fn status_codes_name_their_cause() {
        let json = |error: &str, message: &str| {
            serde_json::to_vec(&serde_json::json!({ "error": error, "message": message })).unwrap()
        };
        let cases: [(u16, Vec<u8>, &str); 9] = [
            (
                400,
                json("bad_request", "Unknown sort key: bogus"),
                "bad_request",
            ),
            (
                401,
                json("unauthorized", "Invalid agent token"),
                "unauthorized",
            ),
            (404, Vec::new(), "unsupported_server"),
            (429, b"Too Many Requests".to_vec(), "rate_limited"),
            (
                503,
                json(
                    "service_unavailable",
                    "the fleet module is not mounted on this server",
                ),
                "module_unmounted",
            ),
            (
                503,
                b"<html>upstream unavailable</html>".to_vec(),
                "server_error",
            ),
            (500, json("internal", "boom"), "server_error"),
            (502, Vec::new(), "server_error"),
            (403, b"blocked by policy".to_vec(), "server_error"),
        ];
        for (status, body, want) in cases {
            let got = classify_status(status, &body);
            assert_eq!(got.code, want, "HTTP {status}");
            assert_eq!(got.status, Some(status));
        }
        // The server's own words reach the caller where they help.
        assert_eq!(
            classify_status(400, &json("bad_request", "Unknown sort key: bogus")).message,
            "Unknown sort key: bogus"
        );
        assert!(
            classify_status(500, &json("internal", "boom"))
                .message
                .contains("boom")
        );
    }

    /// The production client builds with the real budgets (a TLS backend that
    /// cannot initialise would surface here, not on an operator's page).
    #[test]
    fn the_production_client_builds() {
        assert!(build_candidate_client("", Candidate::Direct, CONNECT_TIMEOUT).is_ok());
        assert_eq!(fmt_budget(CONNECT_TIMEOUT), "5s");
        assert_eq!(fmt_budget(FAILOVER_CONNECT_TIMEOUT), "3.5s");
        assert_eq!(fmt_budget(REQUEST_TIMEOUT), "10s");
    }

    /// A daemon that never serves a Devices page never builds the client
    /// (TLS roots and all): nothing at start, nothing for a request the
    /// registry refuses, and cached on the first real successful ask.
    #[tokio::test]
    async fn the_client_is_built_on_the_first_real_ask() {
        let srv = fake_server(|_| (200, page_json(&["me"])), Duration::ZERO).await;
        let view = SelfView::new(registry(&srv.url));
        assert_eq!(view.pooled_client_count(), 0, "built at start");
        let _ = view.devices("ghost", &DevicesQuery::default()).await;
        assert_eq!(view.pooled_client_count(), 0, "built for a refused org");
        assert!(matches!(
            view.devices("", &DevicesQuery::default()).await,
            Response::Devices(_)
        ));
        assert_eq!(view.pooled_client_count(), 1);
    }

    #[test]
    fn the_token_never_appears_in_debug_output() {
        let row = OrgHttp {
            label: "acme".into(),
            server_url: "https://acme.invalid".into(),
            token: crate::token_slot::TokenSlot::new("eyJ-super-secret"),
            primary: false,
            enabled: true,
        };
        let rendered = format!("{row:?}");
        assert!(!rendered.contains("super-secret"), "{rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    /// Search text and keys are bounded before they become a URL.
    #[test]
    fn oversized_query_parts_are_refused_locally() {
        let long = DevicesQuery {
            q: Some("x".repeat(MAX_QUERY_LEN + 1)),
            ..Default::default()
        };
        assert_eq!(query_params(&long).unwrap_err().code, "bad_request");
        let long_sort = DevicesQuery {
            sort: Some("s".repeat(MAX_KEY_LEN + 1)),
            ..Default::default()
        };
        assert_eq!(query_params(&long_sort).unwrap_err().code, "bad_request");
        // Blank parts are simply not sent.
        let blank = DevicesQuery {
            q: Some("   ".into()),
            sort: Some(String::new()),
            ..Default::default()
        };
        assert!(query_params(&blank).unwrap().is_empty());
    }

    // ── against a real socket ──────────────────────────────────────────

    struct FakeServer {
        url: String,
        hits: Arc<AtomicUsize>,
        heads: Arc<Mutex<Vec<String>>>,
    }

    /// A minimal HTTP/1.1 server: records each request head, answers with
    /// `respond(head)` after `delay`, closes the connection.
    async fn fake_server(
        respond: impl Fn(&str) -> (u16, String) + Send + Sync + 'static,
        delay: Duration,
    ) -> FakeServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let heads = Arc::new(Mutex::new(Vec::new()));
        let respond = Arc::new(respond);
        {
            let hits = hits.clone();
            let heads = heads.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let hits = hits.clone();
                    let heads = heads.clone();
                    let respond = respond.clone();
                    tokio::spawn(async move {
                        let mut buf = Vec::new();
                        let mut chunk = [0u8; 4096];
                        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            match sock.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                            }
                        }
                        let head = String::from_utf8_lossy(&buf).to_string();
                        hits.fetch_add(1, Ordering::SeqCst);
                        heads.lock().unwrap().push(head.clone());
                        tokio::time::sleep(delay).await;
                        let (status, body) = respond(&head);
                        let reply = format!(
                            "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                             content-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = sock.write_all(reply.as_bytes()).await;
                        let _ = sock.shutdown().await;
                    });
                }
            });
        }
        FakeServer { url, hits, heads }
    }

    fn test_client() -> Result<reqwest::Client, String> {
        meshharbor_node_core::http_client::builder_with(false)
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| e.to_string())
    }

    fn registry(url: &str) -> OrgHttpRegistry {
        Arc::new(Mutex::new(vec![
            OrgHttp {
                label: PRIMARY_ORG_LABEL.into(),
                server_url: format!("{url}/"),
                token: crate::token_slot::TokenSlot::new("tok-primary"),
                primary: true,
                enabled: true,
            },
            OrgHttp {
                label: "acme".into(),
                server_url: url.to_string(),
                token: crate::token_slot::TokenSlot::new("tok-acme"),
                primary: false,
                enabled: true,
            },
            OrgHttp {
                label: "parked".into(),
                server_url: url.to_string(),
                token: crate::token_slot::TokenSlot::new("tok-parked"),
                primary: false,
                enabled: false,
            },
        ]))
    }

    fn page_json(names: &[&str]) -> String {
        let items: Vec<VisibleDeviceRow> = names
            .iter()
            .map(|n| VisibleDeviceRow {
                name: n.to_string(),
                is_self: *n == "me",
                ..server_row()
            })
            .collect();
        serde_json::to_string(&VisibleDevicesPage {
            total: items.len() as u64,
            items,
            page: 1,
            per_page: 25,
            total_pages: 1,
            overlay: "ok".into(),
            acl_mode: "off".into(),
            self_node_id: Some("aaaaaaaaaaaaaaaaaaaaaaaa".into()),
            org_name: None,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn devices_asks_with_the_orgs_token_and_query_and_maps_the_page() {
        let srv = fake_server(
            |head| {
                if head.contains("/mesh") {
                    (
                        200,
                        r#"{"enabled":true,"nodes":[{"id":"n1","label":"Kilo"}],"edges":[],"agents":[]}"#
                            .into(),
                    )
                } else {
                    (200, page_json(&["me", "peer"]))
                }
            },
            Duration::ZERO,
        )
        .await;
        let view = SelfView::with_client(registry(&srv.url), test_client(), Freshness::default());

        let q = DevicesQuery {
            page: 2,
            per_page: 10,
            q: Some("Kilo box".into()),
            sort: Some("name".into()),
            dir: Some("desc".into()),
        };
        // The primary, asked for by its empty label.
        match view.devices("", &q).await {
            Response::Devices(p) => {
                assert_eq!(p.org, "primary");
                assert_eq!(p.items.len(), 2);
                assert!(p.items[0].is_self);
            }
            other => panic!("expected a page, got {other:?}"),
        }
        let head = srv.heads.lock().unwrap()[0].clone();
        let first = head.lines().next().unwrap();
        assert_eq!(
            first,
            "GET /api/agent/self/devices?page=2&per_page=10&q=Kilo+box&sort=name&dir=desc HTTP/1.1"
        );
        let lower = head.to_ascii_lowercase();
        assert!(
            lower.contains("authorization: bearer tok-primary"),
            "{head}"
        );

        // A secondary org is asked with ITS token, and the answer is stamped
        // with ITS label.
        match view.mesh("acme").await {
            Response::Mesh(v) => {
                assert_eq!(v.org, "acme");
                assert_eq!(v.nodes[0].label, "Kilo");
            }
            other => panic!("expected a mesh, got {other:?}"),
        }
        let head = srv.heads.lock().unwrap()[1].to_ascii_lowercase();
        assert!(
            head.starts_with("get /api/agent/self/mesh http/1.1"),
            "{head}"
        );
        assert!(head.contains("authorization: bearer tok-acme"), "{head}");
    }

    #[tokio::test]
    async fn unknown_and_disabled_orgs_are_refused_before_any_request() {
        let srv = fake_server(|_| (200, page_json(&["me"])), Duration::ZERO).await;
        let view = SelfView::with_client(registry(&srv.url), test_client(), Freshness::default());
        match view.devices("ghost", &DevicesQuery::default()).await {
            Response::Upstream { code, .. } => assert_eq!(code, "unknown_org"),
            other => panic!("{other:?}"),
        }
        match view.mesh("parked").await {
            Response::Upstream { code, .. } => assert_eq!(code, "org_disabled"),
            other => panic!("{other:?}"),
        }
        assert_eq!(srv.hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_refused_connection_is_server_unreachable() {
        // Bind, learn the port, close it: nothing listens there.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let view = SelfView::with_client(
            registry(&format!("http://127.0.0.1:{port}")),
            test_client(),
            Freshness::default(),
        );
        match view.devices("", &DevicesQuery::default()).await {
            Response::Upstream {
                code,
                status,
                message,
            } => {
                assert_eq!(code, "server_unreachable");
                assert_eq!(status, None);
                assert!(!message.contains("tok-primary"), "{message}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn failure_statuses_become_named_upstreams_with_the_status() {
        let srv = fake_server(
            |head| {
                if head.contains("/mesh") {
                    (404, String::new())
                } else {
                    (401, r#"{"error":"unauthorized","message":"nope"}"#.into())
                }
            },
            Duration::ZERO,
        )
        .await;
        let view = SelfView::with_client(registry(&srv.url), test_client(), Freshness::default());
        match view.devices("", &DevicesQuery::default()).await {
            Response::Upstream { code, status, .. } => {
                assert_eq!((code.as_str(), status), ("unauthorized", Some(401)));
            }
            other => panic!("{other:?}"),
        }
        match view.mesh("").await {
            Response::Upstream { code, status, .. } => {
                assert_eq!((code.as_str(), status), ("unsupported_server", Some(404)));
            }
            other => panic!("{other:?}"),
        }
    }

    /// Statistics off is an answer, not a failure.
    #[tokio::test]
    async fn mesh_with_statistics_off_is_data() {
        let srv = fake_server(|_| (200, r#"{"enabled":false}"#.into()), Duration::ZERO).await;
        let view = SelfView::with_client(registry(&srv.url), test_client(), Freshness::default());
        match view.mesh("acme").await {
            Response::Mesh(v) => {
                assert!(!v.enabled);
                assert_eq!(v.org, "acme");
            }
            other => panic!("{other:?}"),
        }
    }

    /// Fresh answers come from the cache; five callers asking the same thing
    /// at the same moment share ONE request; a different query is its own
    /// key; an answer past its window is asked again.
    #[tokio::test]
    async fn the_cache_serves_fresh_answers_and_single_flights_concurrent_asks() {
        let srv = fake_server(
            |_| (200, page_json(&["me", "peer"])),
            Duration::from_millis(150),
        )
        .await;
        let fresh = Freshness {
            devices: Duration::from_millis(600),
            mesh: Duration::from_millis(600),
            error: Duration::from_millis(50),
        };
        let view = Arc::new(SelfView::with_client(
            registry(&srv.url),
            test_client(),
            fresh,
        ));
        let q = DevicesQuery {
            q: Some("peer".into()),
            ..Default::default()
        };
        let mut tasks = Vec::new();
        for _ in 0..5 {
            let view = view.clone();
            let q = q.clone();
            tasks.push(tokio::spawn(async move { view.devices("", &q).await }));
        }
        for t in tasks {
            assert!(matches!(t.await.unwrap(), Response::Devices(_)));
        }
        assert_eq!(
            srv.hits.load(Ordering::SeqCst),
            1,
            "one flight for five asks"
        );

        // Still fresh: served from the cache.
        assert!(matches!(view.devices("", &q).await, Response::Devices(_)));
        assert_eq!(srv.hits.load(Ordering::SeqCst), 1);

        // `primary` and the empty label are the same key.
        assert!(matches!(
            view.devices("primary", &q).await,
            Response::Devices(_)
        ));
        assert_eq!(srv.hits.load(Ordering::SeqCst), 1);

        // A different query is a different answer.
        assert!(matches!(
            view.devices("", &DevicesQuery::default()).await,
            Response::Devices(_)
        ));
        assert_eq!(srv.hits.load(Ordering::SeqCst), 2);

        // Past the window, asked again.
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(matches!(view.devices("", &q).await, Response::Devices(_)));
        assert_eq!(srv.hits.load(Ordering::SeqCst), 3);
    }

    /// Typing a search one key at a time must not grow the cache without end.
    #[tokio::test]
    async fn the_cache_is_bounded() {
        let srv = fake_server(|_| (200, page_json(&["me"])), Duration::ZERO).await;
        let view = SelfView::with_client(registry(&srv.url), test_client(), Freshness::default());
        for i in 0..(CACHE_CAP + 8) {
            let q = DevicesQuery {
                q: Some(format!("needle-{i}")),
                ..Default::default()
            };
            assert!(matches!(view.devices("", &q).await, Response::Devices(_)));
        }
        assert!(
            view.cache_len() <= CACHE_CAP,
            "cache grew to {}",
            view.cache_len()
        );
    }

    static MGMT_PATH_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct KeepAliveServer {
        addr: std::net::SocketAddr,
        accepts: Arc<AtomicUsize>,
        requests: Arc<AtomicUsize>,
    }

    /// Minimal HTTP/1.1 keep-alive server that serves multiple sequential GETs
    /// on a single TCP connection so tests can assert real connection reuse.
    async fn keep_alive_gpu_server(body: String) -> KeepAliveServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let body = Arc::new(body);
        {
            let accepts = accepts.clone();
            let requests = requests.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    accepts.fetch_add(1, Ordering::SeqCst);
                    let requests = requests.clone();
                    let body = body.clone();
                    tokio::spawn(async move {
                        let mut buf = Vec::new();
                        let mut chunk = [0u8; 4096];
                        loop {
                            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                match sock.read(&mut chunk).await {
                                    Ok(0) | Err(_) => return,
                                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                                }
                            }
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                buf.drain(..pos + 4);
                            }
                            requests.fetch_add(1, Ordering::SeqCst);
                            let reply = format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                                 content-length: {}\r\nconnection: keep-alive\r\n\r\n{}",
                                body.len(),
                                body.as_str()
                            );
                            if sock.write_all(reply.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                    });
                }
            });
        }
        KeepAliveServer {
            addr,
            accepts,
            requests,
        }
    }

    fn empty_gpu_fleet_json() -> String {
        serde_json::to_string(&GpuFleetPage::default()).unwrap()
    }

    #[tokio::test]
    async fn routed_gpu_fleet_reuses_keep_alive_connection_and_switches_on_route_change() {
        let _guard = MGMT_PATH_TEST_LOCK.lock().await;
        use meshharbor_node_core::management_path as mp;

        let entry_a = keep_alive_gpu_server(empty_gpu_fleet_json()).await;
        let entry_b = keep_alive_gpu_server(empty_gpu_fleet_json()).await;
        let centre = "selfview-reuse.fr134.invalid";
        let url = format!("http://{centre}");

        mp::note_config(&url, &[entry_a.addr.to_string(), entry_b.addr.to_string()]);
        mp::note_pushed(
            centre,
            &mp::Pushed {
                direct: false,
                entries: Vec::new(),
            },
        );
        mp::note_connected(centre, mp::Candidate::Entry(entry_a.addr), false);

        let view = SelfView::new(registry(&url));
        for _ in 0..3 {
            match view.gpu_fleet("", true, 0, &[], Some(500)).await {
                Response::GpuFleet(_) => {}
                other => panic!("expected GpuFleet via entry A, got {other:?}"),
            }
        }
        assert_eq!(entry_a.requests.load(Ordering::SeqCst), 3);
        assert_eq!(
            entry_a.accepts.load(Ordering::SeqCst),
            1,
            "consecutive live gpu_fleet polls on the same entry must reuse keep-alive TCP/TLS"
        );

        // Route switches to entry B -> pooled client must follow immediately without sticking to A.
        mp::note_connected(centre, mp::Candidate::Entry(entry_b.addr), false);
        for _ in 0..2 {
            match view.gpu_fleet("", true, 0, &[], Some(500)).await {
                Response::GpuFleet(_) => {}
                other => panic!("expected GpuFleet via entry B, got {other:?}"),
            }
        }
        assert_eq!(entry_a.requests.load(Ordering::SeqCst), 3);
        assert_eq!(entry_b.requests.load(Ordering::SeqCst), 2);
        assert_eq!(
            entry_b.accepts.load(Ordering::SeqCst),
            1,
            "requests after route change must reuse keep-alive on the new entry"
        );

        mp::set_route(centre, None);
        mp::note_config("", &[]);
    }

    #[tokio::test]
    async fn dead_or_stalled_active_entry_fails_over_to_healthy_backup_entry_and_sticks() {
        let _guard = MGMT_PATH_TEST_LOCK.lock().await;
        use meshharbor_node_core::management_path as mp;

        // 1. Active entry accepts TCP and stalls silently (exact model of a gateway whose
        //    upstream leg to the centre is hanging while TCP accept on :18443 still succeeds).
        let stalled = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stalled_addr = stalled.local_addr().unwrap();
        let stalled_accepts = Arc::new(AtomicUsize::new(0));
        {
            let stalled_accepts = stalled_accepts.clone();
            tokio::spawn(async move {
                let mut held = Vec::new();
                while let Ok((sock, _)) = stalled.accept().await {
                    stalled_accepts.fetch_add(1, Ordering::SeqCst);
                    held.push(sock);
                }
            });
        }
        let healthy = keep_alive_gpu_server(empty_gpu_fleet_json()).await;
        let centre = "selfview-failover.fr134.invalid";
        let url = format!("http://{centre}");

        mp::note_config(&url, &[stalled_addr.to_string(), healthy.addr.to_string()]);
        mp::note_pushed(
            centre,
            &mp::Pushed {
                direct: false,
                entries: Vec::new(),
            },
        );
        mp::note_connected(centre, mp::Candidate::Entry(stalled_addr), false);

        let view = SelfView::new(registry(&url));
        match view.gpu_fleet("", true, 0, &[], Some(500)).await {
            Response::GpuFleet(_) => {}
            other => panic!("expected automatic failover to healthy backup entry, got {other:?}"),
        }
        assert_eq!(healthy.requests.load(Ordering::SeqCst), 1);
        let stalled_after_first = stalled_accepts.load(Ordering::SeqCst);

        // Subsequent polls must stick to the healthy fallback with keep-alive (no repeated stalls).
        let t0 = Instant::now();
        for _ in 0..2 {
            match view.gpu_fleet("", true, 0, &[], Some(500)).await {
                Response::GpuFleet(_) => {}
                other => panic!("expected sticky healthy fallback, got {other:?}"),
            }
        }
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "sticky fallback took too long: {:?}",
            t0.elapsed()
        );
        assert_eq!(
            stalled_accepts.load(Ordering::SeqCst),
            stalled_after_first,
            "sticky fallback must not re-hit the stalled entry on every poll"
        );
        assert_eq!(healthy.requests.load(Ordering::SeqCst), 3);
        assert_eq!(healthy.accepts.load(Ordering::SeqCst), 1);

        mp::set_route(centre, None);
        mp::note_config("", &[]);
    }

    #[tokio::test]
    async fn note_outcome_treats_gpu_responses_as_success() {
        let srv = fake_server(|_| (200, empty_gpu_fleet_json()), Duration::ZERO).await;
        let view = SelfView::with_client(registry(&srv.url), test_client(), Freshness::default());
        assert!(matches!(
            view.gpu_fleet("", true, 0, &[], Some(1000)).await,
            Response::GpuFleet(_)
        ));
        let recorded = view
            .outcomes
            .lock()
            .unwrap()
            .get(&("gpu_fleet", "primary".to_string()))
            .copied();
        assert_eq!(
            recorded,
            Some(None),
            "GpuFleet must record as success (None), not Some(\"error\")"
        );
    }
}
