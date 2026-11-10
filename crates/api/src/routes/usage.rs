// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Wave 3 — per-USER usage accounting (minutes + bytes).
//!
//! Every other stats surface is keyed by device, region or org. This one is
//! keyed by *who*, across three activity classes:
//!
//! - **remote desktop** — `remote_sessions` for the controller (exact
//!   `started_at`→`ended_at`), plus watcher windows rebuilt from the
//!   `remote_audit` `WatcherJoined`/`WatcherLeft` pair. A watcher is
//!   *viewing the screen*, so leaving them out would undercount the thing
//!   this feature exists to show.
//! - **calls** — minutes from `room_members.sessions[]` (the existing source
//!   of truth for participation), bytes from the wave-3 `stats_call_user`
//!   buckets.
//! - **tunnel** — session windows from `tunnel_audit`, plus the per-flow
//!   byte totals the ORIGINATING endpoint reports on close. The server
//!   cannot measure those itself (payload is P2P over the data channel),
//!   which is why those columns held a literal 0 on every row written
//!   before wave 3. A window whose flows all predate that reports
//!   `bytes_known: false` rather than a zero.
//!
//! **Windows are clamped to the query range.** A session that began before
//! the window contributes only its overlap, so the numbers sum to something
//! meaningful ("hours viewed in the last 7 days") instead of over-counting
//! long-running sessions at every range.
//!
//! Authz: at org level a member may ALWAYS read their OWN usage — being able
//! to see what was recorded about you shouldn't require the admin bit —
//! while anyone else's needs `MANAGE_AGENTS`. Platform level is the ObjectId
//! allowlist. All failures are **404, never 403** (the web client wipes
//! tokens on 403; see the `stats` module docs).

use axum::{
    Json,
    extract::{Path, Query, State},
};
use bson::{DateTime, Document, doc, oid::ObjectId};
use futures::TryStreamExt;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

use super::stats::{
    Tier, disabled_payload, floor_dt, parse_tid, range_spec, require_platform_admin,
    require_tenant_stats,
};
use crate::{core_state::Core, error::ApiError, extractors::auth::AuthUser};
use meshharbor_services::dao::stats::{STATS_CALL_USER, STATS_CALL_USER_1D, STATS_CALL_USER_1H};

/// `remote_audit` is TTL'd at 90 days, so watcher windows simply do not
/// exist beyond that. Controller sessions do (`remote_sessions` has no TTL),
/// which would silently make old ranges look watcher-free — the payload
/// carries `watchers_complete` so the UI can say so instead of implying it.
const AUDIT_RETENTION_SECS: i64 = 90 * 86_400;

/// Cap on rows returned by the table endpoints.
const MAX_ROWS: i64 = 500;

/// Cap on individual timeline entries in a detail response. A user with more
/// sessions than this in one window is an outlier; the payload says so via
/// `truncated` rather than silently showing a partial picture.
const MAX_TIMELINE: usize = 2_000;

#[derive(Debug, Deserialize)]
pub struct UsageQuery {
    #[serde(default)]
    pub range: Option<String>,
    /// Platform scope only — narrow to one org.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

fn now_dt() -> DateTime {
    DateTime::now()
}

/// Milliseconds between two BSON dates as whole seconds, floored at 0.
fn secs_between(a: DateTime, b: DateTime) -> f64 {
    ((b.timestamp_millis() - a.timestamp_millis()) as f64 / 1000.0).max(0.0)
}

fn unix_secs(d: DateTime) -> i64 {
    d.timestamp_millis() / 1000
}

/// Overlap of `[start, end]` with the query window, in seconds. `end: None`
/// means "still running" and is clamped to now.
fn clamped_secs(start: DateTime, end: Option<DateTime>, floor: DateTime, now: DateTime) -> f64 {
    let s = if start < floor { floor } else { start };
    let e = match end {
        Some(e) if e < now => e,
        _ => now,
    };
    secs_between(s, e)
}

// ── Per-class accumulators ──────────────────────────────────────────────

/// Total wall-clock covered by `spans`, merging overlaps.
///
/// Summing raw durations would double-count concurrency, and for these
/// classes concurrency is the norm, not the exception: a person with five
/// declared tunnel routes open all day has spent 24 h tunnelling, not 120 h.
/// The first prod render of this table reported **1103 h of tunnel use in a
/// 24 h window** for exactly that reason. "Minutes" has to mean time spent,
/// so overlapping windows merge; `sessions` still counts them individually.
fn merged_secs(mut spans: Vec<(i64, i64)>) -> f64 {
    if spans.is_empty() {
        return 0.0;
    }
    spans.sort_unstable();
    let mut total = 0i64;
    let (mut cur_s, mut cur_e) = spans[0];
    for (s, e) in spans.into_iter().skip(1) {
        if s > cur_e {
            total += cur_e - cur_s;
            cur_s = s;
            cur_e = e;
        } else if e > cur_e {
            cur_e = e;
        }
    }
    total += cur_e - cur_s;
    total.max(0) as f64
}

#[derive(Default, Clone)]
struct ClassTotals {
    /// Half-open `[start, end)` unix-second windows, already clamped to the
    /// query range. Merged (not summed) into minutes — see [`merged_secs`].
    spans: Vec<(i64, i64)>,
    bytes: f64,
    sessions: u32,
    /// How many of those sessions actually reported bytes. Zero with
    /// `sessions > 0` is what drives `bytes_known: false` — the difference
    /// between "moved no data" and "we never measured".
    with_bytes: u32,
    devices: HashSet<ObjectId>,
}

impl ClassTotals {
    fn add(&mut self, start: DateTime, end: Option<DateTime>, floor: DateTime, now: DateTime) {
        let s = if start < floor { floor } else { start };
        let e = match end {
            Some(e) if e < now => e,
            _ => now,
        };
        if e > s {
            self.spans.push((unix_secs(s), unix_secs(e)));
        }
        self.sessions += 1;
    }

    fn seconds(&self) -> f64 {
        merged_secs(self.spans.clone())
    }

    fn json(&self, bytes_measurable: bool) -> serde_json::Value {
        serde_json::json!({
            "minutes": (self.seconds() / 60.0 * 10.0).round() / 10.0,
            "bytes": self.bytes.round(),
            "sessions": self.sessions,
            "devices": self.devices.len(),
            // False when nothing in this window carried a byte count, so the
            // UI renders "—" instead of a confident 0.
            "bytes_known": bytes_measurable && self.with_bytes > 0,
        })
    }
}

#[derive(Default, Clone)]
struct UserTotals {
    rc: ClassTotals,
    call: ClassTotals,
    tunnel: ClassTotals,
    /// Orgs this user was active in during the window (platform scope).
    tenants: HashSet<ObjectId>,
}

// ── Remote desktop ──────────────────────────────────────────────────────

/// Controller-side sessions, clamped to the window. `started_at: null` means
/// the session never got past consent — no screen was viewed, so it is
/// excluded rather than counted as a zero-length view.
async fn rc_sessions(
    state: &Core,
    tenant: Option<ObjectId>,
    user: Option<ObjectId>,
    floor: DateTime,
    now: DateTime,
) -> Result<Vec<Document>, ApiError> {
    let mut filter = doc! {
        "started_at": { "$ne": null },
        // Overlaps the window: ended inside it, or still open.
        "$or": [ { "ended_at": null }, { "ended_at": { "$gte": floor } } ],
    };
    if let Some(t) = tenant {
        filter.insert("tenant_id", t);
    }
    if let Some(u) = user {
        filter.insert("controller_user_id", u);
    }
    let cursor = state
        .db
        .collection::<Document>("remote_sessions")
        .find(filter)
        .sort(doc! { "started_at": -1 })
        .limit(MAX_TIMELINE as i64)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let docs: Vec<Document> = cursor
        .try_collect()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    // A session that ended before the floor can still match when `ended_at`
    // is null-but-stale; drop anything with no real overlap.
    Ok(docs
        .into_iter()
        .filter(|d| {
            d.get_datetime("started_at")
                .map(|s| {
                    clamped_secs(*s, d.get_datetime("ended_at").ok().copied(), floor, now) > 0.0
                })
                .unwrap_or(false)
        })
        .collect())
}

/// One reconstructed viewing window.
struct ViewWindow {
    user_id: ObjectId,
    tenant_id: ObjectId,
    agent_id: ObjectId,
    session_id: ObjectId,
    start: DateTime,
    end: Option<DateTime>,
    /// Bytes are only ever attributed to the CONTROLLER — the session's
    /// `stats` block counts the peer connection once, and splitting it
    /// across watchers would invent numbers.
    controller: bool,
    bytes: f64,
}

/// Rebuild watcher windows for the given sessions by pairing
/// `WatcherJoined`/`WatcherLeft` in timestamp order.
///
/// Bounded by the sessions themselves (a watcher window cannot exist outside
/// its session), which is also why no time filter is applied to the audit
/// query — the `{session_id, at}` index makes it a direct lookup, and a join
/// that happened before the query window still needs to be seen so its
/// window can be clamped rather than lost.
async fn watcher_windows(
    state: &Core,
    sessions: &[Document],
    only_user: Option<ObjectId>,
) -> Result<Vec<ViewWindow>, ApiError> {
    if sessions.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<ObjectId> = sessions
        .iter()
        .filter_map(|d| d.get_object_id("_id").ok())
        .collect();
    let by_id: HashMap<ObjectId, &Document> = sessions
        .iter()
        .filter_map(|d| d.get_object_id("_id").ok().map(|i| (i, d)))
        .collect();

    let mut filter = doc! {
        "session_id": { "$in": &ids },
        "event.kind": { "$in": [ "watcher_joined", "watcher_left" ] },
    };
    if let Some(u) = only_user {
        filter.insert("event.user_id", u);
    }
    let cursor = state
        .db
        .collection::<Document>("remote_audit")
        .find(filter)
        .sort(doc! { "session_id": 1, "at": 1 })
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let events: Vec<Document> = cursor
        .try_collect()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // (session, user) → the currently open join, if any.
    let mut open: HashMap<(ObjectId, ObjectId), DateTime> = HashMap::new();
    let mut out: Vec<ViewWindow> = Vec::new();
    for ev in &events {
        let (Ok(sid), Ok(at)) = (ev.get_object_id("session_id"), ev.get_datetime("at")) else {
            continue;
        };
        let Ok(kind_doc) = ev.get_document("event") else {
            continue;
        };
        let (Ok(kind), Ok(uid)) = (kind_doc.get_str("kind"), kind_doc.get_object_id("user_id"))
        else {
            continue;
        };
        let Some(session) = by_id.get(&sid) else {
            continue;
        };
        match kind {
            "watcher_joined" => {
                // A duplicate join without a leave keeps the EARLIER start:
                // the viewer never stopped watching in between.
                open.entry((sid, uid)).or_insert(*at);
            }
            "watcher_left" => {
                if let Some(start) = open.remove(&(sid, uid)) {
                    out.push(ViewWindow {
                        user_id: uid,
                        tenant_id: session.get_object_id("tenant_id").unwrap_or_default(),
                        agent_id: session.get_object_id("agent_id").unwrap_or_default(),
                        session_id: sid,
                        start,
                        end: Some(*at),
                        controller: false,
                        bytes: 0.0,
                    });
                }
            }
            _ => {}
        }
    }
    // Still-open joins close when their SESSION did (or stay open if it is
    // still live) — a watcher cannot outlive the session they are watching.
    for ((sid, uid), start) in open {
        let Some(session) = by_id.get(&sid) else {
            continue;
        };
        out.push(ViewWindow {
            user_id: uid,
            tenant_id: session.get_object_id("tenant_id").unwrap_or_default(),
            agent_id: session.get_object_id("agent_id").unwrap_or_default(),
            session_id: sid,
            start,
            end: session.get_datetime("ended_at").ok().copied(),
            controller: false,
            bytes: 0.0,
        });
    }
    Ok(out)
}

/// Controller windows + watcher windows, as one list.
async fn view_windows(
    state: &Core,
    tenant: Option<ObjectId>,
    user: Option<ObjectId>,
    floor: DateTime,
    now: DateTime,
) -> Result<Vec<ViewWindow>, ApiError> {
    // Controller rows are filtered by user; watcher rows are not (the user
    // may have watched a session someone else controlled), so the session
    // sweep for watchers must be unfiltered by controller.
    let controller_docs = rc_sessions(state, tenant, user, floor, now).await?;
    let all_docs = if user.is_some() {
        rc_sessions(state, tenant, None, floor, now).await?
    } else {
        controller_docs.clone()
    };

    let mut out: Vec<ViewWindow> = controller_docs
        .iter()
        .filter_map(|d| {
            let stats = d.get_document("stats").ok();
            let b = |k: &str| {
                stats
                    .and_then(|s| s.get(k))
                    .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
                    .unwrap_or(0) as f64
            };
            Some(ViewWindow {
                user_id: d.get_object_id("controller_user_id").ok()?,
                tenant_id: d.get_object_id("tenant_id").ok()?,
                agent_id: d.get_object_id("agent_id").ok()?,
                session_id: d.get_object_id("_id").ok()?,
                start: *d.get_datetime("started_at").ok()?,
                end: d.get_datetime("ended_at").ok().copied(),
                controller: true,
                bytes: b("bytes_sent") + b("bytes_recv"),
            })
        })
        .collect();
    out.extend(watcher_windows(state, &all_docs, user).await?);
    Ok(out)
}

// ── Calls ───────────────────────────────────────────────────────────────

/// Per-user in-call seconds from the participation ledger. `left_at: null`
/// is an open session, clamped to now.
async fn call_minutes(
    state: &Core,
    tenant: Option<ObjectId>,
    user: Option<ObjectId>,
    floor: DateTime,
    now: DateTime,
) -> Result<Vec<(ObjectId, ObjectId, ObjectId, DateTime, Option<DateTime>)>, ApiError> {
    let mut filter = doc! { "sessions": { "$exists": true, "$ne": [] } };
    if let Some(t) = tenant {
        filter.insert("tenant_id", t);
    }
    if let Some(u) = user {
        filter.insert("user_id", u);
    }
    let cursor = state
        .db
        .collection::<Document>("room_members")
        .find(filter)
        .projection(doc! { "tenant_id": 1, "room_id": 1, "user_id": 1, "sessions": 1 })
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let docs: Vec<Document> = cursor
        .try_collect()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let mut out = Vec::new();
    for d in docs {
        let (Ok(tid), Ok(rid)) = (d.get_object_id("tenant_id"), d.get_object_id("room_id")) else {
            continue;
        };
        let Ok(uid) = d.get_object_id("user_id") else {
            continue; // external participant with no account
        };
        let Ok(sessions) = d.get_array("sessions") else {
            continue;
        };
        for s in sessions {
            let Some(s) = s.as_document() else { continue };
            let Ok(joined) = s.get_datetime("joined_at") else {
                continue;
            };
            let left = s.get_datetime("left_at").ok().copied();
            if clamped_secs(*joined, left, floor, now) > 0.0 {
                out.push((uid, tid, rid, *joined, left));
            }
        }
    }
    Ok(out)
}

/// Per-user call BYTES from the wave-3 sampler buckets, integrated from the
/// stored rates. Tier follows the same raw/1h/1d selection as every other
/// series so a 1-year query doesn't fall off the 7-day raw TTL.
async fn call_bytes(
    state: &Core,
    tenant: Option<ObjectId>,
    user: Option<ObjectId>,
    floor: DateTime,
    tier: Tier,
) -> Result<HashMap<ObjectId, f64>, ApiError> {
    let (coll, rolled) = match tier {
        Tier::Raw => (STATS_CALL_USER, false),
        Tier::Hour => (STATS_CALL_USER_1H, true),
        Tier::Day => (STATS_CALL_USER_1D, true),
    };
    let mut m = doc! { "ts": { "$gte": floor } };
    if let Some(t) = tenant {
        m.insert("tenant_id", t);
    }
    if let Some(u) = user {
        m.insert("user_id", u);
    }
    // Raw rows hold 30 s rate gauges; rolled rows already hold byte sums.
    let sum = if rolled {
        doc! { "$add": [ { "$ifNull": [ "$up_bytes", 0 ] }, { "$ifNull": [ "$down_bytes", 0 ] } ] }
    } else {
        doc! { "$divide": [
            { "$multiply": [
                { "$add": [ { "$ifNull": [ "$up_bps", 0 ] }, { "$ifNull": [ "$down_bps", 0 ] } ] },
                30,
            ]},
            8,
        ]}
    };
    let cursor = state
        .db
        .collection::<Document>(coll)
        .aggregate(vec![
            doc! { "$match": m },
            doc! { "$group": { "_id": "$user_id", "bytes": { "$sum": sum } } },
        ])
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let docs: Vec<Document> = cursor
        .try_collect()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(docs
        .into_iter()
        .filter_map(|d| {
            let u = d.get_object_id("_id").ok()?;
            let b = d
                .get_f64("bytes")
                .ok()
                .or_else(|| d.get_i64("bytes").ok().map(|v| v as f64))?;
            Some((u, b))
        })
        .collect())
}

// ── Tunnel ──────────────────────────────────────────────────────────────

/// One tunnel session's window, from its first to its last audit event.
///
/// Bytes are deliberately absent: `tunnel_audit.bytes_in/out` exist but every
/// writer passes 0 (the payload is P2P over the data channel — the server
/// never sees it). PR-3 has the originator report them.
async fn tunnel_windows(
    state: &Core,
    tenant: Option<ObjectId>,
    user: Option<ObjectId>,
    floor: DateTime,
) -> Result<Vec<Document>, ApiError> {
    let mut m = doc! { "at": { "$gte": floor } };
    if let Some(t) = tenant {
        m.insert("tenant_id", t);
    }
    if let Some(u) = user {
        m.insert("user_id", u);
    }
    let cursor = state
        .db
        .collection::<Document>("tunnel_audit")
        .aggregate(vec![
            doc! { "$match": m },
            doc! { "$group": {
                "_id": "$tunnel_session_id",
                "user_id": { "$first": "$user_id" },
                "tenant_id": { "$first": "$tenant_id" },
                "agent_id": { "$first": "$agent_id" },
                "first": { "$min": "$at" },
                "last": { "$max": "$at" },
                "events": { "$sum": 1 },
                // Per-flow totals, summed over the session's close rows.
                // Only the endpoint can count these, so a session whose
                // flows all predate wave 3 sums to 0 — `measured` is what
                // separates that from "moved nothing".
                "bytes": { "$sum": { "$add": [
                    { "$ifNull": [ "$bytes_in", 0 ] },
                    { "$ifNull": [ "$bytes_out", 0 ] },
                ]}},
                "measured": { "$sum": { "$cond": [
                    { "$gt": [ { "$add": [
                        { "$ifNull": [ "$bytes_in", 0 ] },
                        { "$ifNull": [ "$bytes_out", 0 ] },
                    ]}, 0 ] },
                    1, 0,
                ]}},
            }},
            doc! { "$sort": { "last": -1 } },
            doc! { "$limit": MAX_TIMELINE as i64 },
        ])
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    cursor
        .try_collect()
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))
}

// ── Name resolution ─────────────────────────────────────────────────────

async fn names(
    state: &Core,
    coll: &str,
    ids: &HashSet<ObjectId>,
    fields: &[&str],
) -> HashMap<ObjectId, String> {
    if ids.is_empty() {
        return HashMap::new();
    }
    let ids: Vec<ObjectId> = ids.iter().copied().collect();
    let mut proj = doc! {};
    for f in fields {
        proj.insert(*f, 1);
    }
    let Ok(cursor) = state
        .db
        .collection::<Document>(coll)
        .find(doc! { "_id": { "$in": ids } })
        .projection(proj)
        .await
    else {
        return HashMap::new();
    };
    let docs: Vec<Document> = cursor.try_collect().await.unwrap_or_default();
    docs.into_iter()
        .filter_map(|d| {
            let id = d.get_object_id("_id").ok()?;
            let name = fields
                .iter()
                .find_map(|f| d.get_str(*f).ok().filter(|s| !s.is_empty()))
                .unwrap_or("")
                .to_string();
            Some((id, name))
        })
        .collect()
}

async fn user_names(state: &Core, ids: &HashSet<ObjectId>) -> HashMap<ObjectId, String> {
    names(state, "users", ids, &["display_name", "username", "email"]).await
}

async fn agent_names(state: &Core, ids: &HashSet<ObjectId>) -> HashMap<ObjectId, String> {
    // "hostname" was projected here for as long as this helper existed, but
    // no such field has ever been on the Agent model — harmless, misleading.
    names(state, "agents", ids, &["name", "machine_id"]).await
}

/// FR-116 D4 — each device's friendly name, beside the machine name
/// [`agent_names`] resolves. Additive: `agent_name` keeps meaning the
/// machine's name for every reader that already parses it, and the web shows
/// `agent_display_name` first (the `HeartbeatBefore::label` rule), as the
/// device list does. A device without one is absent from the map.
async fn agent_display_names(state: &Core, ids: &HashSet<ObjectId>) -> HashMap<ObjectId, String> {
    let mut m = names(state, "agents", ids, &["display_name"]).await;
    m.retain(|_, v| !v.is_empty());
    m
}

async fn tenant_names(state: &Core, ids: &HashSet<ObjectId>) -> HashMap<ObjectId, String> {
    names(state, "tenants", ids, &["name", "slug"]).await
}

async fn room_names(state: &Core, ids: &HashSet<ObjectId>) -> HashMap<ObjectId, String> {
    names(state, "rooms", ids, &["name", "slug"]).await
}

// ── Table ───────────────────────────────────────────────────────────────

async fn usage_table(
    state: &Core,
    tenant: Option<ObjectId>,
    range: Option<&str>,
) -> Result<serde_json::Value, ApiError> {
    let (window, tier) = range_spec(range)?;
    let floor = floor_dt(window);
    let now = now_dt();

    let mut totals: HashMap<ObjectId, UserTotals> = HashMap::new();

    for w in view_windows(state, tenant, None, floor, now).await? {
        let e = totals.entry(w.user_id).or_default();
        e.rc.add(w.start, w.end, floor, now);
        e.rc.devices.insert(w.agent_id);
        e.tenants.insert(w.tenant_id);
        if w.bytes > 0.0 {
            e.rc.bytes += w.bytes;
            e.rc.with_bytes += 1;
        }
    }

    for (uid, tid, rid, joined, left) in call_minutes(state, tenant, None, floor, now).await? {
        let e = totals.entry(uid).or_default();
        e.call.add(joined, left, floor, now);
        e.call.devices.insert(rid);
        e.tenants.insert(tid);
    }
    for (uid, bytes) in call_bytes(state, tenant, None, floor, tier).await? {
        let e = totals.entry(uid).or_default();
        e.call.bytes += bytes;
        if bytes > 0.0 {
            e.call.with_bytes += 1;
        }
    }

    for d in tunnel_windows(state, tenant, None, floor).await? {
        let (Ok(uid), Ok(first), Ok(last)) = (
            d.get_object_id("user_id"),
            d.get_datetime("first"),
            d.get_datetime("last"),
        ) else {
            continue;
        };
        let e = totals.entry(uid).or_default();
        e.tunnel.add(*first, Some(*last), floor, now);
        // Wave 3: tunnel bytes are real once the endpoint reports them.
        let b = d
            .get_f64("bytes")
            .ok()
            .or_else(|| d.get_i64("bytes").ok().map(|v| v as f64))
            .unwrap_or(0.0);
        if b > 0.0 {
            e.tunnel.bytes += b;
            e.tunnel.with_bytes += 1;
        }
        if let Ok(a) = d.get_object_id("agent_id") {
            e.tunnel.devices.insert(a);
        }
        if let Ok(t) = d.get_object_id("tenant_id") {
            e.tenants.insert(t);
        }
    }

    let uids: HashSet<ObjectId> = totals.keys().copied().collect();
    let unames = user_names(state, &uids).await;
    let all_tenants: HashSet<ObjectId> = totals
        .values()
        .flat_map(|t| t.tenants.iter().copied())
        .collect();
    let tnames = if tenant.is_none() {
        tenant_names(state, &all_tenants).await
    } else {
        HashMap::new()
    };

    let mut rows: Vec<serde_json::Value> = totals
        .iter()
        .map(|(uid, t)| {
            let orgs: Vec<serde_json::Value> = if tenant.is_none() {
                t.tenants
                    .iter()
                    .map(|tid| {
                        serde_json::json!({
                            "tenant_id": tid.to_hex(),
                            "name": tnames.get(tid).cloned().unwrap_or_default(),
                        })
                    })
                    .collect()
            } else {
                Vec::new()
            };
            serde_json::json!({
                "user_id": uid.to_hex(),
                "name": unames.get(uid).cloned().unwrap_or_default(),
                "rc": t.rc.json(true),
                "call": t.call.json(true),
                // Tunnel bytes are not measurable server-side today.
                // Measurable since wave 3 (the endpoint reports its flow
                // totals on close); `bytes_known` still falls back to false
                // for a window whose flows all predate that.
                "tunnel": t.tunnel.json(true),
                // Merged across classes too: someone on a call while a
                // tunnel is up spent that hour once, not twice. This is
                // "time active on the platform", which is what a reader
                // sorting by Total is actually after.
                "total_minutes": (merged_secs(
                    t.rc.spans.iter()
                        .chain(t.call.spans.iter())
                        .chain(t.tunnel.spans.iter())
                        .copied()
                        .collect(),
                ) / 60.0 * 10.0).round() / 10.0,
                "orgs": orgs,
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        let f = |v: &serde_json::Value| v["total_minutes"].as_f64().unwrap_or(0.0);
        f(b).partial_cmp(&f(a)).unwrap_or(std::cmp::Ordering::Equal)
    });
    rows.truncate(MAX_ROWS as usize);

    Ok(serde_json::json!({
        "enabled": true,
        "range": range.unwrap_or("24h"),
        "watchers_complete": window <= AUDIT_RETENTION_SECS,
        "users": rows,
    }))
}

// ── Detail ──────────────────────────────────────────────────────────────

async fn usage_detail(
    state: &Core,
    tenant: Option<ObjectId>,
    user: ObjectId,
    range: Option<&str>,
) -> Result<serde_json::Value, ApiError> {
    let (window, tier) = range_spec(range)?;
    let floor = floor_dt(window);
    let now = now_dt();

    let windows = view_windows(state, tenant, Some(user), floor, now).await?;
    let mine: Vec<&ViewWindow> = windows.iter().filter(|w| w.user_id == user).collect();

    let agent_ids: HashSet<ObjectId> = mine.iter().map(|w| w.agent_id).collect();
    let mut tenant_ids: HashSet<ObjectId> = mine.iter().map(|w| w.tenant_id).collect();

    let calls = call_minutes(state, tenant, Some(user), floor, now).await?;
    let room_ids: HashSet<ObjectId> = calls.iter().map(|(_, _, r, _, _)| *r).collect();
    tenant_ids.extend(calls.iter().map(|(_, t, _, _, _)| *t));

    let tunnels = tunnel_windows(state, tenant, Some(user), floor).await?;
    let tunnel_agents: HashSet<ObjectId> = tunnels
        .iter()
        .filter_map(|d| d.get_object_id("agent_id").ok())
        .collect();
    tenant_ids.extend(
        tunnels
            .iter()
            .filter_map(|d| d.get_object_id("tenant_id").ok()),
    );

    let all_agents: HashSet<ObjectId> = agent_ids.union(&tunnel_agents).copied().collect();
    let anames = agent_names(state, &all_agents).await;
    let adnames = agent_display_names(state, &all_agents).await;
    let tnames = tenant_names(state, &tenant_ids).await;
    let rnames = room_names(state, &room_ids).await;
    let unames = user_names(state, &HashSet::from([user])).await;

    // The headline: every window this user spent looking at a screen.
    let mut viewing: Vec<serde_json::Value> = mine
        .iter()
        .map(|w| {
            serde_json::json!({
                "session_id": w.session_id.to_hex(),
                "agent_id": w.agent_id.to_hex(),
                "agent_name": anames.get(&w.agent_id).cloned().unwrap_or_default(),
                "agent_display_name": adnames.get(&w.agent_id),
                "tenant_id": w.tenant_id.to_hex(),
                "tenant_name": tnames.get(&w.tenant_id).cloned().unwrap_or_default(),
                "started_at": unix_secs(w.start),
                "ended_at": w.end.map(unix_secs),
                "seconds": clamped_secs(w.start, w.end, floor, now).round(),
                "role": if w.controller { "controller" } else { "watcher" },
                "bytes": w.bytes,
                "bytes_known": w.bytes > 0.0,
            })
        })
        .collect();
    viewing.sort_by_key(|v| -(v["started_at"].as_i64().unwrap_or(0)));
    let truncated = viewing.len() >= MAX_TIMELINE;
    viewing.truncate(MAX_TIMELINE);

    let call_rows: Vec<serde_json::Value> = calls
        .iter()
        .map(|(_, tid, rid, joined, left)| {
            serde_json::json!({
                "room_id": rid.to_hex(),
                "room_name": rnames.get(rid).cloned().unwrap_or_default(),
                "tenant_id": tid.to_hex(),
                "tenant_name": tnames.get(tid).cloned().unwrap_or_default(),
                "started_at": unix_secs(*joined),
                "ended_at": left.map(unix_secs),
                "seconds": clamped_secs(*joined, *left, floor, now).round(),
            })
        })
        .collect();

    let tunnel_rows: Vec<serde_json::Value> = tunnels
        .iter()
        .filter_map(|d| {
            let first = d.get_datetime("first").ok()?;
            let last = d.get_datetime("last").ok()?;
            let aid = d.get_object_id("agent_id").ok();
            let tid = d.get_object_id("tenant_id").ok();
            let bytes = d
                .get_f64("bytes")
                .ok()
                .or_else(|| d.get_i64("bytes").ok().map(|v| v as f64))
                .unwrap_or(0.0);
            Some(serde_json::json!({
                "session_id": d.get_object_id("_id").ok().map(|i| i.to_hex()),
                "agent_id": aid.map(|a| a.to_hex()),
                "agent_name": aid.and_then(|a| anames.get(&a).cloned()).unwrap_or_default(),
                "agent_display_name": aid.and_then(|a| adnames.get(&a)),
                "tenant_id": tid.map(|t| t.to_hex()),
                "tenant_name": tid.and_then(|t| tnames.get(&t).cloned()).unwrap_or_default(),
                "started_at": unix_secs(*first),
                "ended_at": unix_secs(*last),
                "seconds": clamped_secs(*first, Some(*last), floor, now).round(),
                "events": d.get_i32("events").unwrap_or(0),
                "bytes": bytes,
                // Per SESSION, not global: a long-lived route whose flows
                // closed before wave 3 genuinely has no count, even while
                // a newer session next to it does.
                "bytes_known": bytes > 0.0,
            }))
        })
        .collect();

    let call_byte_total: f64 = call_bytes(state, tenant, Some(user), floor, tier)
        .await?
        .values()
        .sum();
    let rc_bytes: f64 = mine.iter().map(|w| w.bytes).sum();

    // Clamp each window to the range, then MERGE — a person controlling two
    // machines at once spent that hour once.
    let span_of = |s: DateTime, e: Option<DateTime>| -> Option<(i64, i64)> {
        let s = if s < floor { floor } else { s };
        let e = match e {
            Some(e) if e < now => e,
            _ => now,
        };
        (e > s).then(|| (unix_secs(s), unix_secs(e)))
    };
    let rc_total_secs = merged_secs(
        mine.iter()
            .filter_map(|w| span_of(w.start, w.end))
            .collect(),
    );
    let call_total_secs = merged_secs(
        calls
            .iter()
            .filter_map(|(_, _, _, j, l)| span_of(*j, *l))
            .collect(),
    );
    let tunnel_total_secs = merged_secs(
        tunnels
            .iter()
            .filter_map(|d| {
                let f = d.get_datetime("first").ok()?;
                let l = d.get_datetime("last").ok()?;
                span_of(*f, Some(*l))
            })
            .collect(),
    );

    Ok(serde_json::json!({
        "enabled": true,
        "range": range.unwrap_or("24h"),
        "watchers_complete": window <= AUDIT_RETENTION_SECS,
        "user": {
            "user_id": user.to_hex(),
            "name": unames.get(&user).cloned().unwrap_or_default(),
        },
        "totals": {
            // Merged, not summed — concurrent windows are one stretch of
            // time, and these headline numbers have to agree with the
            // table's (see `merged_secs`).
            "rc_minutes": (rc_total_secs / 60.0 * 10.0).round() / 10.0,
            "rc_bytes": rc_bytes,
            "call_minutes": (call_total_secs / 60.0 * 10.0).round() / 10.0,
            "call_bytes": call_byte_total,
            "tunnel_minutes": (tunnel_total_secs / 60.0 * 10.0).round() / 10.0,
            "tunnel_bytes": tunnel_rows.iter()
                .map(|r| r["bytes"].as_f64().unwrap_or(0.0)).sum::<f64>(),
        },
        "viewing": viewing,
        "calls": call_rows,
        "tunnels": tunnel_rows,
        "truncated": truncated,
    }))
}

// ── Handlers: org scope ─────────────────────────────────────────────────

/// `GET /api/tenant/{tid}/stats/usage` — per-user usage for one org.
/// Requires `MANAGE_AGENTS` (it shows everyone's activity).
pub async fn tenant_usage(
    State(state): State<Core>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Query(q): Query<UsageQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = parse_tid(&tenant_id)?;
    require_tenant_stats(&state, tid, auth.user_id, true).await?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }
    Ok(Json(
        usage_table(&state, Some(tid), q.range.as_deref()).await?,
    ))
}

/// `GET /api/tenant/{tid}/stats/usage/{uid}` — one user's timeline.
///
/// A member may always read their OWN row; anyone else's needs
/// `MANAGE_AGENTS`. Seeing what the platform recorded about yourself should
/// not require the admin bit.
pub async fn tenant_usage_detail(
    State(state): State<Core>,
    auth: AuthUser,
    Path((tenant_id, user_id)): Path<(String, String)>,
    Query(q): Query<UsageQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tid = parse_tid(&tenant_id)?;
    let uid = ObjectId::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest("Invalid user_id".into()))?;
    let self_query = uid == auth.user_id;
    require_tenant_stats(&state, tid, auth.user_id, !self_query).await?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }
    Ok(Json(
        usage_detail(&state, Some(tid), uid, q.range.as_deref()).await?,
    ))
}

// ── Handlers: platform scope ────────────────────────────────────────────

/// `GET /api/admin/stats/usage` — per-user usage across every org.
pub async fn admin_usage(
    State(state): State<Core>,
    auth: AuthUser,
    Query(q): Query<UsageQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_platform_admin(&state, &auth)?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }
    let tenant = match q.tenant_id.as_deref() {
        Some(t) if !t.is_empty() => Some(parse_tid(t)?),
        _ => None,
    };
    Ok(Json(usage_table(&state, tenant, q.range.as_deref()).await?))
}

/// `GET /api/admin/stats/usage/{uid}` — one user's timeline across orgs.
pub async fn admin_usage_detail(
    State(state): State<Core>,
    auth: AuthUser,
    Path(user_id): Path<String>,
    Query(q): Query<UsageQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_platform_admin(&state, &auth)?;
    if !state.settings.stats.enabled {
        return Ok(disabled_payload());
    }
    let uid = ObjectId::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest("Invalid user_id".into()))?;
    let tenant = match q.tenant_id.as_deref() {
        Some(t) if !t.is_empty() => Some(parse_tid(t)?),
        _ => None,
    };
    Ok(Json(
        usage_detail(&state, tenant, uid, q.range.as_deref()).await?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dt(secs: i64) -> DateTime {
        DateTime::from_millis(secs * 1000)
    }

    #[test]
    fn window_clamped_to_range_floor() {
        // Started an hour before the window, ended 10 min inside it.
        let floor = dt(1_000);
        let now = dt(2_000);
        assert_eq!(clamped_secs(dt(0), Some(dt(1_600)), floor, now), 600.0);
    }

    #[test]
    fn open_window_clamps_to_now_not_beyond() {
        let floor = dt(1_000);
        let now = dt(2_000);
        assert_eq!(clamped_secs(dt(1_500), None, floor, now), 500.0);
    }

    #[test]
    fn window_entirely_before_range_is_zero() {
        let floor = dt(1_000);
        let now = dt(2_000);
        assert_eq!(clamped_secs(dt(0), Some(dt(500)), floor, now), 0.0);
    }

    /// The bug the first prod render exposed: five tunnels open all day
    /// summed to 120 h of "usage" in a 24 h window. Concurrent windows are
    /// ONE stretch of wall-clock.
    #[test]
    fn concurrent_windows_merge_instead_of_summing() {
        let day = 86_400;
        let five_all_day: Vec<(i64, i64)> = (0..5).map(|_| (0, day)).collect();
        assert_eq!(merged_secs(five_all_day), day as f64);
    }

    #[test]
    fn disjoint_windows_still_add_up() {
        assert_eq!(merged_secs(vec![(0, 100), (200, 350)]), 250.0);
        // Touching at a boundary is one continuous stretch, not two.
        assert_eq!(merged_secs(vec![(0, 100), (100, 250)]), 250.0);
        // Order must not matter, and a window fully inside another adds none.
        assert_eq!(merged_secs(vec![(200, 350), (0, 400), (10, 20)]), 400.0);
        assert_eq!(merged_secs(vec![]), 0.0);
    }

    #[test]
    fn class_totals_merge_across_added_windows() {
        let floor = dt(1_000);
        let now = dt(2_000);
        let mut c = ClassTotals::default();
        // Two overlapping sessions: 1000..1600 and 1400..1800 = 800 s.
        c.add(dt(1_000), Some(dt(1_600)), floor, now);
        c.add(dt(1_400), Some(dt(1_800)), floor, now);
        assert_eq!(c.seconds(), 800.0);
        // Both still count as sessions — merging is about TIME, not tally.
        assert_eq!(c.sessions, 2);
    }

    #[test]
    fn bytes_known_false_when_nothing_measured() {
        // Sessions happened but none reported bytes — must not read as 0 B.
        let t = ClassTotals {
            spans: vec![(0, 600)],
            sessions: 3,
            ..Default::default()
        };
        assert_eq!(t.json(true)["bytes_known"], serde_json::json!(false));
        let t2 = ClassTotals {
            spans: vec![(0, 600)],
            sessions: 3,
            bytes: 1024.0,
            with_bytes: 1,
            ..Default::default()
        };
        assert_eq!(t2.json(true)["bytes_known"], serde_json::json!(true));
        // …and a class whose bytes are structurally unmeasurable stays false
        // even when a row somehow carried one.
        assert_eq!(t2.json(false)["bytes_known"], serde_json::json!(false));
    }
}
