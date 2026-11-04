// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Stats PR-2 — the mediasoup conference sampler.
//!
//! Every 30 s, each pod samples the conferences IT owns (multi-pod media
//! is single-owner per room, so iterating this pod's own `RoomManager` is
//! the single-writer guarantee — no claim needed) and upserts one
//! `stats_call` bucket per live room: participant count, relayed-vs-direct
//! split, aggregate bitrates and loss.
//!
//! Relay classification: mediasoup only sees the packet SOURCE, so a
//! TURN-relayed participant's `ice_selected_tuple.remote_ip` is the coturn
//! server's address — "relayed" = remote ip ∈ the resolved TURN pool
//! (re-resolved every 30 min). With `turn.force_relay` set, every
//! participant classifies as relayed — that's policy, not a bug.
//!
//! Deadlock note: `sample_transports()` clones transport handles under the
//! DashMap guards and drops them; the `get_stats()` awaits run OUT of the
//! guards, bounded by `buffer_unordered(16)`.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use bson::{Document, doc, oid::ObjectId};
use futures::{StreamExt, TryStreamExt};
// `mediasoup::data_structures` is private — the public path to the shared
// types is the `types` re-export of the mediasoup-types crate.
use mediasoup::prelude::*;
use mediasoup::types::data_structures::TransportTuple;
use mediasoup::webrtc_transport::WebRtcTransportStat;
use tracing::{debug, info};

use crate::ConferenceState;

const SAMPLE_INTERVAL_SECS: u64 = 30;
const TURN_RESOLVE_INTERVAL_SECS: u64 = 1800;

fn tuple_remote_ip(t: &TransportTuple) -> Option<IpAddr> {
    match t {
        TransportTuple::WithRemote { remote_ip, .. } => Some(*remote_ip),
        TransportTuple::LocalOnly { .. } => None,
    }
}

/// Every configured TURN hostname (default region + workers + regional
/// PoPs) — the classification set is the UNION across regions, since a
/// conference client can be granted any of them.
fn turn_hosts(map: &meshharbor_remote_control::turn_creds::TurnMap) -> Vec<(String, u16)> {
    let mut out = Vec::new();
    let mut push_cfg = |cfg: &meshharbor_remote_control::turn_creds::TurnConfig| {
        for url in cfg
            .urls
            .iter()
            .chain(cfg.workers.iter().flat_map(|w| w.iter()))
        {
            if let Some(hp) = meshharbor_remote_control::turn_url::host_port(url) {
                out.push(hp);
            }
        }
    };
    if let Some(d) = &map.default {
        push_cfg(d);
    }
    for cfg in map.regions.values() {
        push_cfg(cfg);
    }
    out.sort();
    out.dedup();
    out
}

async fn resolve_turn_ips(hosts: &[(String, u16)]) -> HashSet<IpAddr> {
    let mut out = HashSet::new();
    for (host, port) in hosts {
        match tokio::net::lookup_host((host.as_str(), *port)).await {
            Ok(addrs) => out.extend(addrs.map(|a| a.ip())),
            Err(e) => debug!(%host, %e, "media sampler: TURN host resolve failed"),
        }
    }
    out
}

fn stat_of(stats: &Option<Vec<WebRtcTransportStat>>) -> Option<&WebRtcTransportStat> {
    stats.as_ref().and_then(|v| v.first())
}

/// Sample every locally-owned conference once. Public so tests can drive
/// it without the timer. Returns the number of rooms sampled.
pub async fn run_media_sample_once(state: &ConferenceState, turn_ips: &HashSet<IpAddr>) -> usize {
    let snapshot = state.room_manager.sample_transports();
    if snapshot.is_empty() {
        return 0;
    }
    // One query resolves tenancy + call attribution for every live room.
    let room_ids: Vec<ObjectId> = snapshot.iter().map(|(r, _)| *r).collect();
    let mut meta: HashMap<ObjectId, (ObjectId, Option<ObjectId>)> = HashMap::new();
    let mut cursor = match state
        .db
        .collection::<Document>("rooms")
        .find(doc! { "_id": { "$in": &room_ids } })
        .projection(doc! { "tenant_id": 1, "current_call_id": 1 })
        .await
    {
        Ok(c) => c,
        Err(e) => {
            debug!(%e, "media sampler: rooms lookup failed");
            return 0;
        }
    };
    while let Ok(Some(d)) = cursor.try_next().await {
        let (Ok(id), Ok(tid)) = (d.get_object_id("_id"), d.get_object_id("tenant_id")) else {
            continue;
        };
        meta.insert(id, (tid, d.get_object_id("current_call_id").ok()));
    }

    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let mut sampled = 0usize;
    for (room_id, parts) in snapshot {
        let Some((tenant_id, call_id)) = meta.get(&room_id).copied() else {
            continue;
        };
        let stats_futs = parts.into_iter().map(|(user, send, recv)| async move {
            let s = send.get_stats().await.ok();
            let r = recv.get_stats().await.ok();
            (user, s, r)
        });
        let results: Vec<_> = futures::stream::iter(stats_futs)
            .buffer_unordered(16)
            .collect()
            .await;

        let mut participants = 0i32;
        let mut relayed = 0i32;
        let mut send_bps = 0f64; // SFU → clients (their download)
        let mut recv_bps = 0f64; // clients → SFU (their upload)
        let mut loss_sum = 0f64;
        let mut loss_n = 0u32;
        // Per-participant rows for the usage ledger (wave 3). The room
        // totals below are sums of exactly these, so the two can never
        // disagree — and unlike the room bucket, this one can answer
        // "how much did THIS user move", which usage accounting needs.
        let mut per_user: Vec<(ObjectId, f64, f64)> = Vec::with_capacity(results.len());
        for (user, s, r) in &results {
            participants += 1;
            let s_ip = stat_of(s)
                .and_then(|st| st.ice_selected_tuple.as_ref())
                .and_then(tuple_remote_ip);
            let r_ip = stat_of(r)
                .and_then(|st| st.ice_selected_tuple.as_ref())
                .and_then(tuple_remote_ip);
            if s_ip.map(|ip| turn_ips.contains(&ip)).unwrap_or(false)
                || r_ip.map(|ip| turn_ips.contains(&ip)).unwrap_or(false)
            {
                relayed += 1;
            }
            // Named from the USER's side: their upload is what the SFU
            // receives on their send transport, their download is what it
            // sends on their recv transport.
            let mut up_bps = 0f64;
            let mut down_bps = 0f64;
            if let Some(st) = stat_of(s) {
                up_bps = f64::from(st.recv_bitrate);
                recv_bps += up_bps;
                if let Some(l) = st.rtp_packet_loss_received {
                    loss_sum += l;
                    loss_n += 1;
                }
            }
            if let Some(st) = stat_of(r) {
                down_bps = f64::from(st.send_bitrate);
                send_bps += down_bps;
            }
            per_user.push((*user, up_bps, down_bps));
        }
        let loss_pct = if loss_n > 0 {
            loss_sum / f64::from(loss_n) * 100.0
        } else {
            0.0
        };

        let bucket = meshharbor_services::dao::stats::bucket_start(
            unix,
            meshharbor_services::dao::stats::CALL_BUCKET_SECS,
        );
        let mut set = doc! {
            "tenant_id": tenant_id,
            "room_id": room_id,
            "ts": bson::DateTime::from_millis(bucket * 1000),
            "participants": participants,
            "relayed": relayed,
            "direct": participants - relayed,
            "send_bps": send_bps,
            "recv_bps": recv_bps,
            "loss_pct": loss_pct,
        };
        if let Some(cid) = call_id {
            set.insert("call_id", cid);
        }
        let id = format!("{}:{}", room_id.to_hex(), bucket);
        if let Err(e) = state
            .db
            .collection::<Document>(meshharbor_services::dao::stats::STATS_CALL)
            .update_one(doc! { "_id": &id }, doc! { "$set": set })
            .upsert(true)
            .await
        {
            debug!(room = %room_id, %e, "media sampler: bucket upsert failed");
            continue;
        }
        if let Some(cid) = call_id
            && let Err(e) = state.stats.max_call_peak(cid, participants).await
        {
            debug!(room = %room_id, %e, "media sampler: peak update failed");
        }
        // Per-participant rows. A failure here is logged and skipped, never
        // fatal to the tick — the room bucket is already durable, and one
        // missing usage sample must not cost the whole room's series.
        for (user, up_bps, down_bps) in per_user {
            if let Err(e) = state
                .stats
                .upsert_call_user_sample(tenant_id, room_id, call_id, user, unix, up_bps, down_bps)
                .await
            {
                debug!(room = %room_id, user = %user, %e, "media sampler: per-user upsert failed");
            }
        }
        sampled += 1;
    }
    sampled
}

/// Spawn the per-pod sampler. No claim: each pod samples only rooms in
/// its OWN RoomManager (media ownership is single-pod per room).
pub fn spawn_media_sampler(state: ConferenceState) {
    if !state.settings.stats.enabled {
        return;
    }
    tokio::spawn(async move {
        let hosts = turn_hosts(&state.turn_map);
        if hosts.is_empty() {
            info!("media sampler: no TURN hosts configured — relay classification will be 0");
        }
        let mut turn_ips = resolve_turn_ips(&hosts).await;
        let mut last_resolve = std::time::Instant::now();
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(SAMPLE_INTERVAL_SECS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Swallow the immediate first tick so short-lived TestApps never
        // race a test driving run_media_sample_once directly.
        tick.tick().await;
        loop {
            tick.tick().await;
            if last_resolve.elapsed().as_secs() >= TURN_RESOLVE_INTERVAL_SECS {
                turn_ips = resolve_turn_ips(&hosts).await;
                last_resolve = std::time::Instant::now();
            }
            run_media_sample_once(&state, &turn_ips).await;
        }
    });
}
