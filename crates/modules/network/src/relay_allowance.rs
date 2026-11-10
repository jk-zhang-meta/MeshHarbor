// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-115 P4a — the relay allowance on DERP (`docs/fr/FR-115-pricing-reshape.md`,
//! *P4a — the DERP throttle*).
//!
//! An org past its plan's monthly relay allowance keeps its DERP floor, the
//! path that always connects, at a throttled rate, and for **bulk** frames
//! only. A WireGuard handshake (types 1–3) and disco are never held back: a
//! throttle that delayed the handshake past its retry window would turn
//! "slow" into "down" for exactly the hosts that have no other path.
//!
//! Three pieces:
//!
//! * **The job.** Every [`JOB_EVERY`], one pod (a Redis claim), and only where
//!   plans are sold, reads month-to-date `derp_bytes` per org from FR-20's
//!   ledger, compares it with `relay_bytes_per_month` for the org's plan and
//!   seats, and publishes the networks of every org over it, each with its
//!   rate, for [`SET_TTL`].
//! * **The refresh.** Every pod reads the set every [`REFRESH_EVERY`] into a
//!   local map. An absent or unreadable set is an EMPTY one, so a stopped job,
//!   a Redis outage and the kill switch all fail OPEN, within [`SET_TTL`] at
//!   the latest.
//! * **The bucket.** `forward_frame` asks [`rate_of`] for every frame, which
//!   is one relaxed atomic load while no network is over, and [`permits`] for
//!   a bulk frame of a network that is.
//!
//! What it never touches: a direct path and an org relay carry no DERP bytes,
//! so they neither count toward the allowance nor meet the throttle.

use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bson::{DateTime, doc, oid::ObjectId};
use dashmap::DashMap;
use tracing::{debug, info, warn};

use crate::NetworkState;

/// How often one pod recomputes the set.
pub const JOB_EVERY: Duration = Duration::from_secs(300);
/// How long a published set lives: three job periods, so one missed run
/// never lifts a throttle, and a job that stops lifts them all.
pub const SET_TTL: Duration = Duration::from_secs(900);
/// How often every pod re-reads the set.
pub const REFRESH_EVERY: Duration = Duration::from_secs(60);
/// The smallest bucket: one second at the rate, but never under this, so a
/// burst of full-size frames can always start.
const MIN_BURST_BYTES: f64 = 64.0 * 1024.0;

/// network → throttled rate (bytes/s), as this pod last read it.
static OVER: LazyLock<DashMap<ObjectId, u64>> = LazyLock::new(DashMap::new);
/// `OVER.len()`, kept beside it so the hot path costs one relaxed load (a
/// `DashMap::is_empty` would read-lock every shard).
static OVER_LEN: AtomicUsize = AtomicUsize::new(0);
/// network → (tokens, last refill).
static BUCKETS: LazyLock<DashMap<ObjectId, std::sync::Mutex<(f64, Instant)>>> =
    LazyLock::new(DashMap::new);

/// The Redis key of the published set, scoped to the database (in
/// `meshharbor-services`: the push to the PoPs reads it too, FR-115 P4a-2).
pub use meshharbor_services::relay_allowance::set_key;

/// The throttled rate for `network_id` (bytes/s), while its org is over.
pub fn rate_of(network_id: &ObjectId) -> Option<u64> {
    if OVER_LEN.load(Ordering::Relaxed) == 0 {
        return None;
    }
    OVER.get(network_id).map(|r| *r)
}

/// A bulk frame: WireGuard transport data (type 4), or anything that is
/// neither WireGuard nor disco (the tunnel-class payloads). A handshake
/// (types 1–3) and disco are control, and pass whatever the allowance. The
/// PoPs read frames by the same definition (`remote_control::derp_frame`).
pub use meshharbor_remote_control::derp_frame::frame_is_bulk;

/// Debit `len` bytes from the network's bucket at `rate` bytes/s; `false`
/// means over the rate, and the frame is dropped, as R4 drops a tunnel frame.
/// WireGuard rides UDP semantics, and TCP inside it backs off to the rate.
pub fn permits(network_id: ObjectId, len: usize, rate: u64) -> bool {
    let rate = rate as f64;
    let burst = rate.max(MIN_BURST_BYTES);
    let entry = BUCKETS
        .entry(network_id)
        .or_insert_with(|| std::sync::Mutex::new((burst, Instant::now())));
    let mut bucket = entry.lock().unwrap_or_else(|p| p.into_inner());
    let now = Instant::now();
    bucket.0 = (bucket.0 + now.duration_since(bucket.1).as_secs_f64() * rate).min(burst);
    bucket.1 = now;
    if bucket.0 >= len as f64 {
        bucket.0 -= len as f64;
        true
    } else {
        false
    }
}

/// The allowance's arithmetic lives in `meshharbor-services`, shared with the
/// org's analytics page, so what an org is shown is what it is throttled by.
pub use meshharbor_services::relay_allowance::{month_start, rate_for};

/// Month-to-date relayed bytes per org (`StatsDao::relay_month_to_date`).
pub async fn month_to_date(
    state: &NetworkState,
    now: DateTime,
) -> anyhow::Result<HashMap<ObjectId, u64>> {
    Ok(state.stats.relay_month_to_date(None, now).await?)
}

/// The over-allowance set at `now`: network → rate, for every network of
/// every org past its allowance.
pub async fn compute(
    state: &NetworkState,
    now: DateTime,
) -> anyhow::Result<HashMap<ObjectId, u64>> {
    let s = &state.settings.relay_allowance;
    let used = month_to_date(state, now).await?;
    if used.is_empty() {
        return Ok(HashMap::new());
    }
    let ids: Vec<ObjectId> = used.keys().copied().collect();
    let tenants = state
        .tenants
        .base
        .find_many(doc! { "_id": { "$in": &ids } }, None)
        .await?;
    let mut rate_of_org: HashMap<ObjectId, u64> = HashMap::new();
    for t in tenants {
        let Some(id) = t.id else { continue };
        let Some(&bytes) = used.get(&id) else {
            continue;
        };
        if let Some(rate) = rate_for(&t.plan, t.billed_seats(), bytes, s) {
            rate_of_org.insert(id, rate);
        }
    }
    if rate_of_org.is_empty() {
        return Ok(HashMap::new());
    }
    let orgs: Vec<ObjectId> = rate_of_org.keys().copied().collect();
    let networks = state
        .overlay_networks
        .base
        .find_many(doc! { "tenant_id": { "$in": &orgs } }, None)
        .await?;
    Ok(networks
        .into_iter()
        .filter_map(|n| Some((n.id?, *rate_of_org.get(&n.tenant_id)?)))
        .collect())
}

/// Replace this pod's set: networks that left it lose their bucket, and the
/// changes are logged (an org entering or leaving the throttle is rare).
pub fn apply(next: HashMap<ObjectId, u64>) {
    let entered: Vec<String> = next
        .keys()
        .filter(|k| !OVER.contains_key(*k))
        .map(|k| k.to_hex())
        .collect();
    let mut left_ids: Vec<ObjectId> = Vec::new();
    OVER.retain(|k, _| {
        let keep = next.contains_key(k);
        if !keep {
            left_ids.push(*k);
        }
        keep
    });
    for (k, v) in &next {
        OVER.insert(*k, *v);
    }
    OVER_LEN.store(next.len(), Ordering::Relaxed);
    // A network that left the set drops its bucket; one that re-enters
    // later starts with a full burst.
    for k in &left_ids {
        BUCKETS.remove(k);
    }
    let left: Vec<String> = left_ids.iter().map(|k| k.to_hex()).collect();
    if !entered.is_empty() || !left.is_empty() {
        info!(
            over = next.len(),
            ?entered,
            ?left,
            "relay allowance: the throttled networks changed"
        );
    }
}

/// One run of the job, if this pod wins the tick (a Redis claim; without
/// Redis this pod is the only one and always runs it).
pub async fn run_job_once(state: &NetworkState, now: DateTime) -> Option<usize> {
    if let Some(redis) = &state.redis_pubsub {
        let claim = format!("meshharbor:relay_allowance_job:{}", state.db.name());
        match redis
            .try_claim(&claim, JOB_EVERY.as_secs().saturating_sub(30).max(1))
            .await
        {
            Ok(true) => {}
            Ok(false) => return None,
            Err(e) => {
                debug!(%e, "relay allowance: the job's claim failed; skipping this tick");
                return None;
            }
        }
    }
    publish(state, now).await
}

/// The job's body, without the tick's claim: compute the set and publish it
/// (an empty one deletes the key, so every pod lifts its throttles).
/// Without Redis it applies the set here, since this pod is the only one.
/// `None` when the month-to-date read failed and the published set stands.
pub async fn publish(state: &NetworkState, now: DateTime) -> Option<usize> {
    let s = &state.settings.relay_allowance;
    // The kill switch, and a server that sells no plans (self-hosting is
    // unlimited): an empty set.
    let set = if !s.enabled || !state.plans_sold {
        HashMap::new()
    } else {
        match compute(state, now).await {
            Ok(set) => set,
            Err(e) => {
                // Keep what is published: it lapses on its own TTL.
                warn!(%e, "relay allowance: the month-to-date read failed; the published set stands");
                return None;
            }
        }
    };
    let n = set.len();
    match &state.redis_pubsub {
        Some(redis) => {
            let key = set_key(state.db.name());
            let written = if set.is_empty() {
                redis.kv_del(&key).await
            } else {
                let body: HashMap<String, u64> =
                    set.iter().map(|(k, v)| (k.to_hex(), *v)).collect();
                let body = serde_json::to_string(&body).unwrap_or_default();
                redis.kv_set_ex(&key, &body, SET_TTL.as_secs()).await
            };
            if let Err(e) = written {
                warn!(%e, "relay allowance: the set could not be published");
            }
        }
        None => apply(set),
    }
    Some(n)
}

/// Read the published set into this pod's map. Absent, unreadable or
/// unparsable all read as EMPTY: the allowance fails open.
pub async fn refresh(state: &NetworkState) {
    let Some(redis) = &state.redis_pubsub else {
        return; // no Redis: the job applies the set on this, the only, pod
    };
    let raw = match redis.kv_get(&set_key(state.db.name())).await {
        Ok(raw) => raw,
        Err(e) => {
            debug!(%e, "relay allowance: the set could not be read; failing open");
            None
        }
    };
    let next: HashMap<ObjectId, u64> = raw
        .and_then(|r| serde_json::from_str::<HashMap<String, u64>>(&r).ok())
        .map(|m| {
            m.into_iter()
                .filter_map(|(k, v)| Some((ObjectId::parse_str(&k).ok()?, v)))
                .collect()
        })
        .unwrap_or_default();
    apply(next);
}

/// Start the job (it competes for the tick on every pod) and the refresh.
pub fn spawn(state: NetworkState) {
    let job = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(JOB_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            run_job_once(&job, DateTime::now()).await;
        }
    });
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(REFRESH_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            refresh(&state).await;
        }
    });
}

/// The map is process-wide, and two tests in this crate replace it whole
/// (this module's and `derp`'s): each holds this while it does.
#[cfg(test)]
pub(crate) static TEST_MAP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use meshharbor_config::RelayAllowanceSettings;
    use meshharbor_db::models::Plan;

    const GB: u64 = 1_000_000_000;

    fn s() -> RelayAllowanceSettings {
        RelayAllowanceSettings {
            enabled: true,
            free_rate_kbps: 1_000,
            paid_rate_kbps: 4_000,
            turn_attribution: false,
        }
    }

    /// Only bulk is throttled: a WireGuard handshake, its response, a cookie
    /// reply and disco always pass; transport data and tunnel-class payloads
    /// do not.
    #[test]
    fn only_bulk_frames_meet_the_throttle() {
        for t in 1u8..=3 {
            assert!(
                !frame_is_bulk(&[t, 0, 0, 0, 9, 9, 9, 9]),
                "WireGuard type {t} is control"
            );
        }
        assert!(
            frame_is_bulk(&[4, 0, 0, 0, 9, 9, 9, 9]),
            "WireGuard transport data is bulk"
        );
        let mut disco = b"RMDISCO1".to_vec();
        disco.extend_from_slice(&[1, 2, 3]);
        assert!(!frame_is_bulk(&disco), "disco is control");
        assert!(
            frame_is_bulk(&[0x41, 7, 7, 7, 7]),
            "a QUIC short header (tunnel class) is bulk"
        );
        assert!(
            frame_is_bulk(&[1, 0, 0, 1]),
            "one byte off WireGuard's header is not WireGuard"
        );
    }

    /// Inside the allowance nothing is throttled; past it, Free gets its
    /// rate and a paid plan its own; a per-seat plan's allowance grows with
    /// its seats.
    #[test]
    fn the_rate_starts_only_past_the_allowance() {
        assert_eq!(
            rate_for(&Plan::Free, 1, 10 * GB, &s()),
            None,
            "exactly at it is inside"
        );
        assert_eq!(rate_for(&Plan::Free, 1, 10 * GB + 1, &s()), Some(125_000));
        // Pro is 25 GB per seat: 3 seats = 75 GB.
        assert_eq!(rate_for(&Plan::Pro, 3, 74 * GB, &s()), None);
        assert_eq!(rate_for(&Plan::Pro, 3, 76 * GB, &s()), Some(500_000));
        // Business is 100 GB per seat.
        assert_eq!(rate_for(&Plan::Business, 2, 199 * GB, &s()), None);
        assert_eq!(rate_for(&Plan::Business, 2, 201 * GB, &s()), Some(500_000));
    }

    #[test]
    fn the_month_starts_on_the_first_utc() {
        let at = |y, mo, d, h, mi| {
            DateTime::from_millis(
                Utc.with_ymd_and_hms(y, mo, d, h, mi, 0)
                    .single()
                    .unwrap()
                    .timestamp_millis(),
            )
        };
        assert_eq!(month_start(at(2026, 10, 20, 14, 0)), at(2026, 10, 1, 0, 0));
        assert_eq!(month_start(at(2026, 12, 31, 23, 59)), at(2026, 12, 1, 0, 0));
        assert_eq!(month_start(at(2028, 2, 29, 12, 0)), at(2028, 2, 1, 0, 0));
        assert_eq!(month_start(at(2026, 11, 1, 0, 0)), at(2026, 11, 1, 0, 0));
    }

    /// The bucket lets a burst through, refuses past it, and refills at the
    /// rate.
    #[test]
    fn the_bucket_refills_at_the_rate() {
        let net = ObjectId::new();
        let rate = 10_000_000; // 10 MB/s, so a short sleep refills measurably
        assert!(
            permits(net, 10_000_000, rate),
            "a full second's burst passes"
        );
        assert!(!permits(net, 1_000_000, rate), "nothing is left");
        std::thread::sleep(Duration::from_millis(150));
        assert!(permits(net, 1_000_000, rate), "150 ms refills 1.5 MB");
    }

    /// The pod's map: a network in the set has its rate, any other none,
    /// and an empty set lifts every throttle. One test, because the map is
    /// process-wide.
    #[test]
    fn the_map_follows_the_set() {
        let _map = TEST_MAP_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (a, b) = (ObjectId::new(), ObjectId::new());
        apply(HashMap::from([(a, 125_000)]));
        assert_eq!(rate_of(&a), Some(125_000));
        assert_eq!(rate_of(&b), None);
        apply(HashMap::from([(b, 500_000)]));
        assert_eq!(
            rate_of(&a),
            None,
            "a network that left the set is free again"
        );
        assert_eq!(rate_of(&b), Some(500_000));
        apply(HashMap::new());
        assert_eq!(rate_of(&b), None);
    }
}
