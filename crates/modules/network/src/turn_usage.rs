// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-115 P4b — per-org TURN bytes from coturn's statistics DB
//! (`docs/fr/FR-115-pricing-reshape.md`, *P4b, as proposed*). This is the
//! per-tenant TURN attribution FR-20's P3 deferred, by the route FR-20
//! recommended.
//!
//! coturn started with `--redis-statsdb` publishes, when an allocation is
//! deleted, its totals on
//! `turn/realm/<realm>/user/<username>/allocation/<id>/total_traffic` (the
//! client leg) and `…/total_traffic/peer` (the relay ↔ peer leg), as
//! `rcvp=…, rcvb=…, sentp=…, sentb=…` (coturn's
//! `src/apps/relay/ns_ioalib_engine_impl.c`). A username issued with
//! `turn_creds::charged` (`<expiry>:<principal>:org-<org>`) names the org
//! that pays. This subscribes to both
//! channels and adds what coturn SENT on each leg (`sentb`, the egress it
//! carried) to that org's `turn_bytes`, the way DERP counts what it forwards.
//!
//! * **Once per allocation and leg**, though every API pod subscribes: a
//!   `SET NX` decides which pod records it. The key carries the username as
//!   well as the allocation id, because coturn numbers allocations per
//!   process, and two workers can reuse the same id.
//! * **Never guessed.** A username that names no org (the session-less
//!   pre-fetch) adds to [`TURN_UNATTRIBUTED_BYTES`] and is skipped.
//! * Kill switch: `relay_allowance.turn_attribution`, off by default,
//!   because coturn must publish here first.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bson::{DateTime, oid::ObjectId};
use futures::StreamExt;
use meshharbor_remote_control::turn_creds::org_of_username;
use meshharbor_services::dao::stats::Meter;
use tracing::{debug, info, warn};

use crate::NetworkState;

/// coturn's per-allocation totals: the client leg, and the peer leg.
pub const CHANNELS: [&str; 2] = [
    "turn/realm/*/user/*/allocation/*/total_traffic",
    "turn/realm/*/user/*/allocation/*/total_traffic/peer",
];
/// How long an allocation leg's "counted" mark lives: far past any
/// allocation's life, so a late duplicate is still recognised.
const COUNTED_TTL_SECS: u64 = 7 * 86_400;

/// Bytes coturn reported under a username that names no org. A diagnostic,
/// not a ledger: every pod hears every message, and nothing is claimed for
/// these, so each pod counts all of them.
pub static TURN_UNATTRIBUTED_BYTES: AtomicU64 = AtomicU64::new(0);

/// One allocation leg's totals, as coturn published them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reported {
    pub username: String,
    pub allocation: String,
    pub peer_leg: bool,
    /// What coturn sent on this leg: toward the client, or toward the peer.
    pub sentb: u64,
}

/// Parse one coturn message. `channel` is
/// `turn/realm/<realm>/user/<username>/allocation/<id>/total_traffic[/peer]`
/// and `payload` is `rcvp=…, rcvb=…, sentp=…, sentb=…`. Anything else,
/// including the periodic `traffic` deltas, is `None`.
pub fn parse(channel: &str, payload: &str) -> Option<Reported> {
    let parts: Vec<&str> = channel.split('/').collect();
    let (peer_leg, len) = match parts.as_slice() {
        [.., "total_traffic", "peer"] => (true, 9),
        [.., "total_traffic"] => (false, 8),
        _ => return None,
    };
    if parts.len() != len
        || parts[0] != "turn"
        || parts[1] != "realm"
        || parts[3] != "user"
        || parts[5] != "allocation"
        || parts[4].is_empty()
        || parts[6].is_empty()
    {
        return None;
    }
    let sentb = payload.split(',').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        if k.trim() == "sentb" {
            v.trim().parse::<u64>().ok()
        } else {
            None
        }
    })?;
    Some(Reported {
        username: parts[4].to_string(),
        allocation: parts[6].to_string(),
        peer_leg,
        sentb,
    })
}

/// Record one leg against the org its username names, once across pods.
async fn record(state: &NetworkState, r: Reported) {
    let Some(org) = org_of_username(&r.username).and_then(|h| ObjectId::parse_str(h).ok()) else {
        let total = TURN_UNATTRIBUTED_BYTES.fetch_add(r.sentb, Ordering::Relaxed) + r.sentb;
        info!(
            username = %r.username,
            bytes = r.sentb,
            unattributed_total = total,
            "turn usage: a username naming no org (unattributed, never guessed)"
        );
        return;
    };
    if r.sentb == 0 {
        return;
    }
    // Without the claim every pod would record it ([`spawn`] does not
    // subscribe then; this is the belt to that).
    let Some(redis) = &state.redis_pubsub else {
        return;
    };
    let leg = if r.peer_leg { "peer" } else { "client" };
    let key = format!(
        "meshharbor:turn_counted:{}:{}:{}:{}",
        state.db.name(),
        r.username,
        r.allocation,
        leg
    );
    match redis.try_claim(&key, COUNTED_TTL_SECS).await {
        Ok(true) => {}
        Ok(false) => return, // another pod recorded it
        Err(e) => {
            // Not recording is the cheaper error: a retry that half
            // succeeded would count twice.
            warn!(%e, "turn usage: the once-only claim failed; not recording (under-reports)");
            return;
        }
    }
    let now = DateTime::now().timestamp_millis() / 1000;
    if let Err(e) = state
        .stats
        .add_usage(org, Meter::TurnBytes, now, r.sentb as i64)
        .await
    {
        warn!(%org, %e, "turn usage: the usage bucket write failed (under-reports)");
    }
}

/// One subscription's life: connect, subscribe, record until the stream ends.
async fn run(state: &NetworkState, url: &str) -> Result<(), redis::RedisError> {
    let client = redis::Client::open(url)?;
    let mut pubsub = client.get_async_pubsub().await?;
    for channel in CHANNELS {
        pubsub.psubscribe(channel).await?;
    }
    info!("turn usage: subscribed to coturn's statistics");
    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        if !state.settings.stats.enabled {
            continue;
        }
        let channel = msg.get_channel_name().to_string();
        let Ok(payload) = msg.get_payload::<String>() else {
            continue;
        };
        match parse(&channel, &payload) {
            Some(r) => record(state, r).await,
            None => debug!(%channel, "turn usage: not a coturn total"),
        }
    }
    Ok(())
}

/// Subscribe on every pod, reconnecting with a backoff; nothing at all with
/// the kill switch off.
pub fn spawn(state: NetworkState) {
    if !state.settings.relay_allowance.turn_attribution {
        info!("turn usage: attribution off (relay_allowance.turn_attribution)");
        return;
    }
    let url = state.settings.redis.url.clone();
    if url.trim().is_empty() || state.redis_pubsub.is_none() {
        // No once-only claim without the cluster's Redis: every pod would
        // record every allocation. Under-reporting is the cheaper error.
        warn!("turn usage: no Redis pub/sub on this pod; TURN bytes are not attributed");
        return;
    }
    tokio::spawn(async move {
        let mut backoff = 1u64;
        loop {
            match run(&state, &url).await {
                Ok(()) => {
                    backoff = 1;
                    warn!("turn usage: the subscription ended; reconnecting");
                }
                Err(e) => warn!(%e, "turn usage: subscribe failed; retrying in {backoff}s"),
            }
            tokio::time::sleep(Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(30);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORG: &str = "6a975e17971e2d55ddcdedb2";

    fn user() -> String {
        let principal =
            meshharbor_remote_control::turn_creds::charged("6a975e17971e2d55ddcdedb0", ORG);
        format!("1792000000:{principal}")
    }

    /// The two channels coturn publishes an allocation's totals on, in its
    /// own format.
    #[test]
    fn both_legs_of_a_total_parse() {
        let u = user();
        let client = parse(
            &format!("turn/realm/roomler.ai/user/{u}/allocation/001000000000000042/total_traffic"),
            "rcvp=10, rcvb=1200, sentp=12, sentb=34567",
        )
        .unwrap();
        assert_eq!(
            client,
            Reported {
                username: u.clone(),
                allocation: "001000000000000042".into(),
                peer_leg: false,
                sentb: 34_567,
            }
        );
        let peer = parse(
            &format!(
                "turn/realm/roomler.ai/user/{u}/allocation/001000000000000042/total_traffic/peer"
            ),
            "rcvp=12, rcvb=34567, sentp=10, sentb=1200",
        )
        .unwrap();
        assert!(peer.peer_leg);
        assert_eq!(peer.sentb, 1_200);
        assert_eq!(org_of_username(&peer.username), Some(ORG));
    }

    /// The periodic deltas, other shapes and a payload without `sentb` are
    /// not totals.
    #[test]
    fn only_totals_parse() {
        let u = user();
        assert_eq!(
            parse(
                &format!("turn/realm/r/user/{u}/allocation/1/traffic"),
                "rcvp=1, rcvb=1, sentp=1, sentb=1"
            ),
            None
        );
        assert_eq!(
            parse(
                &format!("turn/user/{u}/allocation/1/total_traffic"),
                "rcvp=1, rcvb=1, sentp=1, sentb=1"
            ),
            None,
            "realm-less channels are not subscribed to"
        );
        assert_eq!(
            parse(
                &format!("turn/realm/r/user/{u}/allocation/1/total_traffic"),
                "rcvp=1, rcvb=1"
            ),
            None
        );
        assert_eq!(parse("meshharbor:ws", "{}"), None);
    }
}
