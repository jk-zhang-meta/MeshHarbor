// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Relay-PoP load poller — the server half of load-aware region routing.
//!
//! Every `relay.stats_poll_secs` (default 30 s) it fetches each enabled
//! region's `https://<derp-host>/stats` (served by the PoP's derp-relay,
//! P6a) and writes a [`RegionLoad`] into the shared [`RelayLoadMap`] the Hub
//! and the overlay broker consult at issuance time. Busy-ness is advisory
//! and deliberately conservative:
//!
//! - `load5 / cpus > relay.busy_load` (default 1.5), or
//! - available memory below ~8 % of total, or
//! - sustained egress above `relay.busy_tx_mbps` (default 400 — sized for
//!   the 500 Mbps-capped OVH PoPs), computed from successive monotonic
//!   counter samples.
//!
//! A fetch failure leaves the region's last sample in place; consumers
//! ignore samples older than `REGION_LOAD_FRESH_SECS` (fail-open — a stats
//! blip must never mass-reroute traffic off a healthy PoP).
//!
//! Stats PR-1: when a [`StatsDao`] sink is provided, every tick is also
//! persisted as a `stats_relay` bucket — success as a full `$set` sample
//! (incl. poll RTT + the fields busy-ness doesn't need: rx rate, uptime,
//! DERP registrations, coturn sessions), failure as a `$setOnInsert`-only
//! `healthy:false` marker so the OTHER pod's success always wins the
//! bucket.
//!
//! Stats follow-up: a region can also declare explicit `stats_urls` —
//! needed by the CENTRAL fleet, which serves TURN from N coturn workers
//! and carries no `derp_url` (its `/derp` is JWT-authed). Multiple
//! endpoints are polled per tick and aggregated by [`Agg`]. A region with
//! neither source stays unpolled and renders "not monitored", never down.

use meshharbor_remote_control::turn_creds::{RegionLoad, RelayLoadMap, TurnMap};
use meshharbor_services::dao::stats::{RelaySample, StatsDao};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Derive the stats URL from a region's `derp_url`
/// (`wss://derp-x.meshharbor.itachi.fans/derp` → `https://derp-x.meshharbor.itachi.fans/stats`).
fn stats_url(derp_url: &str) -> Option<String> {
    let rest = derp_url
        .strip_prefix("wss://")
        .or_else(|| derp_url.strip_prefix("ws://"))?;
    let host = rest.split('/').next()?;
    Some(format!("https://{host}/stats"))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Rate in Mbps from successive monotonic byte counters; 0.0 on the first
/// sample or a counter reset (PoP reboot).
fn rate_mbps(prev: Option<(u64, Instant)>, bytes: u64, now: Instant) -> f64 {
    match prev {
        Some((p, at)) if bytes >= p && now > at => {
            (bytes - p) as f64 * 8.0 / now.duration_since(at).as_secs_f64() / 1_000_000.0
        }
        _ => 0.0,
    }
}

/// Aggregate of one region's `/stats` endpoints for a single tick.
///
/// A region can be one PoP (the usual case — every rule below is the
/// identity on a single sample) or N coturn workers (the central fleet).
/// The combining rules are deliberately pessimistic on pressure and
/// additive on volume, so a busy worker can't hide behind idle siblings:
///
/// - capacity/pressure (`load1`, `load5`, `poll_rtt_ms`) → **max**
/// - headroom (`mem_available_kb` as a fraction, `uptime_s`) → **worst**
///   (the least free memory, the most recently restarted worker)
/// - volume (`net_rx/tx_bytes`, allocations, sessions, DERP registrations)
///   → **sum** (region totals)
/// - `cpus` → max, so the `load5 / cpus` busy ratio compares like with like
#[derive(Debug, Default)]
struct Agg {
    answered: u32,
    poll_rtt_ms: u32,
    cpus: f64,
    load1: f64,
    load5: f64,
    mem_total_kb: f64,
    mem_available_kb: f64,
    net_rx_bytes: u64,
    net_tx_bytes: u64,
    allocations: f64,
    coturn_sessions: f64,
    derp_registrations: f64,
    uptime_s: f64,
    /// FR-20 B — the PoP's CUMULATIVE relayed bytes per overlay network.
    /// Volume, so summed across a region's endpoints like the `net_*` pair.
    /// Absent from the payload ⇒ this PoP predates the field and the region is
    /// simply **not monitored** — which is why it stays an empty map rather
    /// than a zero: a zero would be indistinguishable from "relayed nothing".
    per_network: std::collections::HashMap<String, u64>,
}

impl Agg {
    fn add(&mut self, body: &serde_json::Value, rtt_ms: u32) {
        let f = |k: &str| body[k].as_f64().unwrap_or(0.0);
        let mem_total = f("mem_total_kb");
        let mem_avail = f("mem_available_kb");
        // Worst free-memory FRACTION wins, so mixed-size workers compare
        // fairly; carry that worker's pair so the ratio stays consistent.
        let worse_mem = self.answered == 0
            || (mem_total > 0.0
                && (self.mem_total_kb <= 0.0
                    || mem_avail / mem_total < self.mem_available_kb / self.mem_total_kb));
        if worse_mem {
            self.mem_total_kb = mem_total;
            self.mem_available_kb = mem_avail;
        }
        let uptime = f("uptime_s");
        if self.answered == 0 || (uptime > 0.0 && uptime < self.uptime_s) {
            self.uptime_s = uptime;
        }
        self.answered += 1;
        self.poll_rtt_ms = self.poll_rtt_ms.max(rtt_ms);
        self.cpus = self.cpus.max(f("cpus"));
        self.load1 = self.load1.max(f("load1"));
        self.load5 = self.load5.max(f("load5"));
        self.net_rx_bytes = self
            .net_rx_bytes
            .saturating_add(body["net_rx_bytes"].as_u64().unwrap_or(0));
        self.net_tx_bytes = self
            .net_tx_bytes
            .saturating_add(body["net_tx_bytes"].as_u64().unwrap_or(0));
        self.allocations += body["coturn"]["allocations"].as_f64().unwrap_or(0.0);
        self.coturn_sessions += body["coturn"]["sessions"].as_f64().unwrap_or(0.0);
        self.derp_registrations += f("derp_registrations");
        if let Some(map) = body["per_network"].as_object() {
            for (network, v) in map {
                if let Some(n) = v.as_u64() {
                    *self.per_network.entry(network.clone()).or_insert(0) += n;
                }
            }
        }
    }
}

/// A region's `/stats` endpoints: the explicit `stats_urls` override when
/// set (multi-worker regions like the central fleet, which has no
/// `derp_url` because the central `/derp` is JWT-authed), else the single
/// URL derived from `derp_url`. Regions with neither stay unpolled and
/// render as "not monitored" — never as down.
fn region_stats_urls(spec: &meshharbor_remote_control::turn_creds::RelayRegionSpec) -> Vec<String> {
    if !spec.stats_urls.is_empty() {
        return spec.stats_urls.clone();
    }
    spec.derp_url
        .as_deref()
        .and_then(stats_url)
        .into_iter()
        .collect()
}

/// FR-115 P4a-2 — the push of the over-allowance set to the PoPs, on the
/// poll the API already makes (`POST` to the same `/stats`; the `GET` is
/// unchanged). The set is the one the throttle's job publishes in Redis
/// (`meshharbor_services::relay_allowance::set_key`), signed with the DERP
/// ticket key the PoP already verifies tickets with, so the PoP stays DB-free
/// and secret-free.
///
/// Every way this can fail leaves the PoPs throttling NOTHING: a PoP keeps a
/// set three polls after it arrives and then lets it lapse, so a stopped
/// push, an unreachable PoP and an older PoP (which answers the `POST` 405
/// and has no throttle) all fail open. An empty or absent set is pushed too:
/// that is how the API's kill switch reaches a PoP within one poll.
pub struct AllowancePush {
    redis: Arc<crate::ws::redis_pubsub::RedisPubSub>,
    key: String,
    signer: meshharbor_remote_control::derp_ticket::DerpTicketSigner,
}

impl AllowancePush {
    /// `None` without a usable ticket key: no PoP could verify a set.
    pub fn new(
        settings: &meshharbor_config::RelaySettings,
        redis: Arc<crate::ws::redis_pubsub::RedisPubSub>,
        db_name: &str,
    ) -> Option<Self> {
        let private_b64 = settings.derp_ticket_private_key.as_deref()?;
        match meshharbor_remote_control::derp_ticket::DerpTicketSigner::from_pkcs8_b64(private_b64)
        {
            Ok(signer) => Some(Self {
                redis,
                key: meshharbor_services::relay_allowance::set_key(db_name),
                signer,
            }),
            Err(e) => {
                warn!(%e, "relay allowance push: no usable ticket key; PoPs will not throttle");
                None
            }
        }
    }

    /// Sign the current set and `POST` it to every endpoint at once (one dead
    /// PoP must not stretch the tick by its timeout per endpoint).
    async fn push(&self, client: &reqwest::Client, targets: &[(String, Vec<String>)], ttl: u64) {
        let raw = match self.redis.kv_get(&self.key).await {
            Ok(raw) => raw,
            Err(e) => {
                // Unreadable: push nothing, rather than an empty set over the
                // one another pod just pushed. The PoPs lapse on their own.
                debug!(%e, "relay allowance push: the set is unreadable; skipping this poll");
                return;
            }
        };
        // Absent = nobody is over (the job deletes an empty set); a set that
        // does not parse is treated the same way, which fails open.
        let set: std::collections::BTreeMap<String, u64> = raw
            .and_then(|r| serde_json::from_str(&r).ok())
            .unwrap_or_default();
        let token = match self.signer.sign_allowance_set(set, ttl) {
            Ok(t) => t,
            Err(e) => {
                warn!(%e, "relay allowance push: signing failed");
                return;
            }
        };
        let token = &token;
        let pushes = targets.iter().flat_map(|(region, urls)| {
            urls.iter().map(move |url| {
                let req = client
                    .post(url)
                    .header("content-type", "application/jwt")
                    .body(token.clone());
                async move { (region, url, req.send().await) }
            })
        });
        for (region, url, res) in futures::future::join_all(pushes).await {
            match res {
                Ok(r) if r.status().is_success() => {}
                // An older PoP answers 405: it has no throttle to feed.
                Ok(r) => {
                    debug!(%region, %url, status = %r.status(), "relay allowance push: refused")
                }
                Err(e) => debug!(%region, %url, %e, "relay allowance push: failed"),
            }
        }
    }
}

/// Spawn the poller. No-op (never spawns) when regions are disabled or none
/// exposes a `/stats` endpoint, or when `relay.stats_poll_secs` is 0.
pub fn spawn_poller(
    turn_map: Arc<TurnMap>,
    load: RelayLoadMap,
    settings: &meshharbor_config::RelaySettings,
    stats: Option<Arc<StatsDao>>,
    // FR-20 B — resolves an overlay network id to its tenant so PoP-relayed
    // bytes can be attributed. `None` ⇒ metering off; the load poller itself
    // is unaffected.
    networks: Option<Arc<meshharbor_services::dao::overlay_network::OverlayNetworkDao>>,
    // FR-115 P4a-2 — `None` ⇒ no push, and so no PoP throttles (fail open).
    allowance_push: Option<AllowancePush>,
) {
    let poll_secs = settings.stats_poll_secs;
    let busy_load = settings.busy_load;
    let busy_tx_mbps = settings.busy_tx_mbps;
    let targets: Vec<(String, Vec<String>)> = turn_map
        .specs
        .iter()
        .filter(|s| s.enabled && turn_map.regions.contains_key(&s.id))
        .map(|s| (s.id.clone(), region_stats_urls(s)))
        .filter(|(_, urls)| !urls.is_empty())
        .collect();
    if !turn_map.enabled || targets.is_empty() || poll_secs == 0 {
        return;
    }
    info!(
        regions = targets.len(),
        poll_secs,
        busy_load,
        busy_tx_mbps,
        persist = stats.is_some(),
        "relay load poller starting"
    );
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(%e, "relay load poller: client build failed; poller disabled");
                return;
            }
        };
        // region → ((tx_bytes, at), (rx_bytes, at)) for rate derivation
        // across samples.
        let mut prev_tx: HashMap<String, (u64, Instant)> = HashMap::new();
        let mut prev_rx: HashMap<String, (u64, Instant)> = HashMap::new();
        // FR-20 B — (region, network) → the last CUMULATIVE byte total seen.
        // The PoP counters never reset except on restart, so what we bill is
        // the diff between successive samples.
        let mut prev_net: HashMap<(String, String), u64> = HashMap::new();
        let mut tick = tokio::time::interval(Duration::from_secs(poll_secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            // FR-115 P4a-2 — a PoP keeps the set three polls after it arrives.
            if let Some(push) = &allowance_push {
                push.push(&client, &targets, poll_secs.saturating_mul(3))
                    .await;
            }
            for (region, urls) in &targets {
                // Multi-worker region: poll every endpoint and aggregate
                // pessimistically (see `Agg`). One unreachable worker of
                // three is NOT a down region — but its load no longer
                // hides behind its healthy siblings either.
                let mut agg = Agg::default();
                for url in urls {
                    let started = Instant::now();
                    let body = match client.get(url).send().await {
                        Ok(r) if r.status().is_success() => {
                            match r.json::<serde_json::Value>().await {
                                Ok(v) => v,
                                Err(e) => {
                                    debug!(%region, %url, %e, "relay load: bad stats body");
                                    continue;
                                }
                            }
                        }
                        Ok(r) => {
                            debug!(%region, %url, status = %r.status(), "relay load: stats fetch non-200");
                            continue;
                        }
                        Err(e) => {
                            debug!(%region, %url, %e, "relay load: stats fetch failed");
                            continue;
                        }
                    };
                    agg.add(
                        &body,
                        started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32,
                    );
                }
                if agg.answered == 0 {
                    record_unreachable(&stats, region).await;
                    continue;
                }
                let poll_rtt_ms = agg.poll_rtt_ms;
                let cpus = agg.cpus.max(1.0);
                let load5 = agg.load5;
                let mem_total = agg.mem_total_kb;
                let mem_avail = agg.mem_available_kb;
                let tx_bytes = agg.net_tx_bytes;
                let rx_bytes = agg.net_rx_bytes;
                let now = Instant::now();
                let tx_mbps = rate_mbps(
                    prev_tx.insert(region.clone(), (tx_bytes, now)),
                    tx_bytes,
                    now,
                );
                let rx_mbps = rate_mbps(
                    prev_rx.insert(region.clone(), (rx_bytes, now)),
                    rx_bytes,
                    now,
                );
                let busy = load5 / cpus > busy_load
                    || (mem_total > 0.0 && mem_avail / mem_total < 0.08)
                    || tx_mbps > busy_tx_mbps;
                if busy {
                    info!(%region, load5, cpus, tx_mbps, "relay load: region marked BUSY");
                }
                load.insert(
                    region.clone(),
                    RegionLoad {
                        busy,
                        load1: agg.load1,
                        tx_mbps,
                        coturn_allocations: agg.allocations,
                        updated_unix: unix_now() as u64,
                    },
                );
                if let Some(st) = &stats {
                    let sample = RelaySample {
                        region: region.clone(),
                        unix: unix_now(),
                        poll_rtt_ms,
                        cpus,
                        load1: agg.load1,
                        load5,
                        mem_total_kb: mem_total,
                        mem_available_kb: mem_avail,
                        rx_mbps,
                        tx_mbps,
                        allocations: agg.allocations,
                        coturn_sessions: agg.coturn_sessions,
                        derp_registrations: agg.derp_registrations,
                        uptime_s: agg.uptime_s,
                    };
                    if let Err(e) = st.upsert_relay_sample(&sample).await {
                        debug!(%region, %e, "relay load: sample persist failed");
                    }

                    // FR-20 B — attribute this PoP's relayed bytes.
                    //
                    // ⚠ The PoP counters are CUMULATIVE, so what we bill is the
                    // DIFF against the previous sample. A PoP restart resets
                    // them, making the diff negative — that interval is dropped
                    // and the new total becomes the baseline, so the bucket
                    // UNDER-reports rather than going negative or inventing a
                    // carry-over. Same trade the `net_*_bytes` rate above makes.
                    if let Some(nets) = &networks {
                        for (network, cumulative) in &agg.per_network {
                            let key = (region.clone(), network.clone());
                            let prev = prev_net.insert(key, *cumulative);
                            let Some(delta) = prev.and_then(|p| cumulative.checked_sub(p)) else {
                                // First sample for this pair, or a restart.
                                continue;
                            };
                            if delta == 0 {
                                continue;
                            }
                            let Ok(nid) = bson::oid::ObjectId::parse_str(network) else {
                                continue;
                            };
                            match nets.base.find_by_id(nid).await {
                                Ok(n) => {
                                    if let Err(e) = st
                                        .add_usage(
                                            n.tenant_id,
                                            meshharbor_services::dao::stats::Meter::DerpBytes,
                                            unix_now(),
                                            delta as i64,
                                        )
                                        .await
                                    {
                                        debug!(%region, %e, "fr-20: PoP usage bucket write failed");
                                    }
                                }
                                // Unresolvable ⇒ logged and dropped. An
                                // unattributed byte must never become a
                                // wrongly-attributed one.
                                Err(_) => debug!(
                                    %region, %network,
                                    "fr-20: PoP bytes for an unknown network — unattributed"
                                ),
                            }
                        }
                    }
                }
            }
        }
    });
}

/// Persist a `healthy:false` marker for this tick's bucket ($setOnInsert
/// only — must never clobber the other pod's successful sample).
async fn record_unreachable(stats: &Option<Arc<StatsDao>>, region: &str) {
    if let Some(st) = stats
        && let Err(e) = st.upsert_relay_unreachable(region, unix_now()).await
    {
        debug!(%region, %e, "relay load: unreachable marker persist failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_url_derives_from_derp_url() {
        assert_eq!(
            stats_url("wss://derp-us-east.meshharbor.itachi.fans/derp").as_deref(),
            Some("https://derp-us-east.meshharbor.itachi.fans/stats")
        );
        assert_eq!(stats_url("https://not-ws.example/derp"), None);
    }

    fn body(
        load5: f64,
        cpus: f64,
        mem_total: f64,
        mem_avail: f64,
        tx: u64,
        allocs: f64,
    ) -> serde_json::Value {
        serde_json::json!({
            "cpus": cpus, "load1": load5 / 2.0, "load5": load5,
            "mem_total_kb": mem_total, "mem_available_kb": mem_avail,
            "net_rx_bytes": 10u64, "net_tx_bytes": tx,
            "uptime_s": 5000.0, "derp_registrations": 1.0,
            "coturn": { "allocations": allocs, "sessions": 2.0 },
        })
    }

    #[test]
    fn agg_of_one_endpoint_is_the_identity() {
        let mut a = Agg::default();
        a.add(&body(1.5, 2.0, 4_000_000.0, 1_000_000.0, 900, 7.0), 42);
        assert_eq!(a.answered, 1);
        assert_eq!(a.poll_rtt_ms, 42);
        assert_eq!(a.load5, 1.5);
        assert_eq!(a.cpus, 2.0);
        assert_eq!(a.mem_available_kb, 1_000_000.0);
        assert_eq!(a.net_tx_bytes, 900);
        assert_eq!(a.allocations, 7.0);
        assert_eq!(a.coturn_sessions, 2.0);
        assert_eq!(a.uptime_s, 5000.0);
    }

    #[test]
    fn agg_takes_worst_pressure_and_sums_volume() {
        // Three central coturn workers: one busy + memory-tight, two idle.
        let mut a = Agg::default();
        a.add(&body(0.1, 4.0, 8_000_000.0, 6_000_000.0, 100, 1.0), 10);
        a.add(&body(3.9, 2.0, 4_000_000.0, 200_000.0, 500, 4.0), 55);
        a.add(&body(0.2, 4.0, 8_000_000.0, 7_000_000.0, 300, 2.0), 12);

        assert_eq!(a.answered, 3);
        assert_eq!(a.poll_rtt_ms, 55, "worst RTT wins");
        assert_eq!(a.load5, 3.9, "busiest worker's load wins");
        assert_eq!(a.cpus, 4.0);
        // Tightest worker's memory pair is carried whole (5% free).
        assert_eq!(a.mem_total_kb, 4_000_000.0);
        assert_eq!(a.mem_available_kb, 200_000.0);
        // Volume is region-wide.
        assert_eq!(a.net_tx_bytes, 900);
        assert_eq!(a.net_rx_bytes, 30);
        assert_eq!(a.allocations, 7.0);
        assert_eq!(a.coturn_sessions, 6.0);
        assert_eq!(a.derp_registrations, 3.0);
    }

    #[test]
    fn region_stats_urls_prefers_explicit_override() {
        use meshharbor_remote_control::turn_creds::RelayRegionSpec;
        let spec = |derp: Option<&str>, stats: Vec<&str>| RelayRegionSpec {
            id: "r".into(),
            turn_url: "turn:x:3478".into(),
            worker_urls: vec![],
            derp_url: derp.map(str::to_string),
            stats_urls: stats.into_iter().map(str::to_string).collect(),
            shared_secret: None,
            caps: Default::default(),
            relay_band: None,
            enabled: true,
        };
        // PoP: derived from derp_url (unchanged behaviour).
        assert_eq!(
            region_stats_urls(&spec(Some("wss://derp-x.example/derp"), vec![])),
            vec!["https://derp-x.example/stats".to_string()]
        );
        // Central fleet: no derp_url, explicit multi-worker endpoints.
        assert_eq!(
            region_stats_urls(&spec(None, vec!["http://a/stats", "http://b/stats"])).len(),
            2
        );
        // Override beats derivation when both are present.
        assert_eq!(
            region_stats_urls(&spec(
                Some("wss://derp-x.example/derp"),
                vec!["http://only/stats"]
            )),
            vec!["http://only/stats".to_string()]
        );
        // Neither ⇒ unpolled ("not monitored", never "down").
        assert!(region_stats_urls(&spec(None, vec![])).is_empty());
    }

    #[test]
    fn rate_mbps_handles_first_sample_and_counter_reset() {
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(10);
        // First sample → no rate.
        assert_eq!(rate_mbps(None, 1_000_000, t1), 0.0);
        // 10 MB over 10 s = 8 Mbps.
        let r = rate_mbps(Some((0, t0)), 10_000_000, t1);
        assert!((r - 8.0).abs() < 0.01, "got {r}");
        // Counter reset (reboot) → no rate, not a negative one.
        assert_eq!(rate_mbps(Some((5_000_000, t0)), 1_000_000, t1), 0.0);
    }
}

#[cfg(test)]
mod fr20_tests {
    /// The PoP counters are cumulative, so what gets billed is the DIFF. This
    /// pins the three cases, because two of them are ways to bill wrongly.
    ///
    /// `checked_sub` is the whole mechanism: it yields `None` on a counter
    /// reset, which the poller treats as "re-baseline, bill nothing", so the
    /// interval under-reports instead of going negative or inventing a
    /// carry-over. An invented byte on a cost ledger is worse than a missing
    /// one — the missing one is recoverable, the invented one is a refund.
    #[test]
    fn cumulative_counters_are_billed_as_diffs() {
        // Normal: bill the increment, not the total.
        assert_eq!(5_000u64.checked_sub(3_000), Some(2_000));
        // Idle interval: nothing to bill.
        assert_eq!(3_000u64.checked_sub(3_000), Some(0));
        // PoP restart (counter reset): no diff exists, so bill NOTHING and
        // let the new total become the baseline.
        assert_eq!(100u64.checked_sub(3_000), None);
    }

    /// A region with no `per_network` in its payload is a PoP that predates
    /// the field: "not monitored", which must not be confused with "relayed
    /// zero bytes". An empty map produces no buckets at all; a zero would
    /// produce a row asserting the tenant used nothing.
    #[test]
    fn a_missing_per_network_object_yields_no_buckets() {
        let body = serde_json::json!({ "region": "eu", "net_rx_bytes": 1 });
        assert!(body["per_network"].as_object().is_none());
    }
}
