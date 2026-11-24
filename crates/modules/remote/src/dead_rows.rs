// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-130 P1b-2 — `POST /api/admin/rc-sessions/close-dead`: the one-time
//! close of the session rows a pod that died before FR-130 left open
//! (`docs/fr/FR-130-the-session-outlives-its-control-socket.md` §2.3, §10).
//! P0 counted 11 such rows on production, started 2026-08-12 to 10-31, each
//! on a device that has had a session since: 17,757.7 hours the growth
//! digest read as live. FR-130's registration read and sweep close the rows
//! a dying pod leaves from now on. This closes the ones from before.
//!
//! Platform operators only: anyone else gets the 404 every `/api/admin/*`
//! route gives, before the body is read. A dry run by default, which lists
//! what a real run would close and writes nothing. Paged by `limit` and
//! `after` (the answer's `next`), and idempotent: a second run finds nothing
//! left.
//!
//! **The proof of death** (review 2, N1). A live session is held in the hub
//! of the pod that holds its device's control socket, and nowhere else. So
//! a row is dead when all of these hold:
//!
//! | Check | Why |
//! |---|---|
//! | live (Active, no `ended_at`) and created more than `min_age_hours` ago (24 by default, 1 at least) | a live session younger than that is someone's |
//! | its own clock has not moved since: no `stats_at`, or one that old | a live session's stats land about every 15 s while `stats.enabled` is on, which a real run requires |
//! | no hub on this pod holds it | a session this pod runs is not dead |
//! | its device has a session row created after it, in its org | the device came back and was used since |
//! | its device is offline everywhere; or its socket is on this pod, whose hub does not hold the session; or it is on another pod, which answers that its hub does not hold the session (`rc.session_held`) | the only place a live session can be is the hub of its device's pod |
//!
//! Anything this pod cannot read (the device's presence, another pod's
//! answer) keeps the row, and says so. Every row read is answered with its
//! evidence: dead rows in `rows`, the others in `kept` with the reason.
//!
//! A real run is refused while `stats.enabled` is off: no row's own clock
//! moves then, so a live session looks as quiet as a dead one. It ends each
//! dead row as `agent_disconnect`, dated by the row's own last clock
//! (`crate::resume::inferred_end`: `detached_at`, else `stats_at`, else
//! `started_at`, else `created_at`; never the operator's clock, so it adds no
//! hours) and marked `end_source: backfill`. Each write is conditional on the
//! row as it was read (still live, at the fencing number, the `resume_by`
//! and the `stats_at` read) and on its creation before the cut-off.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use axum::{
    Json,
    extract::{State, rejection::JsonRejection},
};
use bson::DateTime;
use bson::oid::ObjectId;
use meshharbor_core::cluster::directory::OwnerRecord;
use meshharbor_core::{ApiError, extractors::auth::AuthUser, guards::require_platform_admin};
use meshharbor_mod_fleet::agent::fmt_dt;
use meshharbor_mod_fleet::hub::RowEnd;
use meshharbor_remote_control::models::{EndReason, EndSource, RemoteSession};
use meshharbor_services::dao::remote_session::RowCursor;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::RemoteState;
use crate::resume::inferred_end;

/// How many rows one call reads at most, by default and at most.
const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 500;
/// How old a live row must be before it may be dead, in hours, by default.
const DEFAULT_MIN_AGE_HOURS: u32 = 24;
/// It may never be younger than this, whatever the call asks.
const MIN_AGE_HOURS_FLOOR: u32 = 1;
/// The bus class another pod answers "does your hub hold this session?" on.
pub const SESSION_HELD: &str = "rc.session_held";
/// How long the devices' presence may take to read.
const PRESENCE_BUDGET: Duration = Duration::from_secs(2);

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseDeadRequest {
    /// List only, write nothing. On unless the body says otherwise.
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// How many rows one call reads: [`DEFAULT_LIMIT`] by default,
    /// [`MAX_LIMIT`] at most.
    pub limit: Option<u32>,
    /// How old a live row must be, in hours: [`DEFAULT_MIN_AGE_HOURS`] by
    /// default, never under [`MIN_AGE_HOURS_FLOOR`].
    pub min_age_hours: Option<u32>,
    /// Read on after this row: the `next` of the previous answer.
    pub after: Option<String>,
}

/// What a row's verdict rests on.
#[derive(Debug, Serialize)]
pub struct Evidence {
    /// The row's own clock: its last stats merge, `null` when it never had
    /// one.
    pub stats_at: Option<String>,
    /// How old that clock is, in hours.
    pub stats_age_hours: Option<f64>,
    /// This pod's hub holds the session.
    pub held_here: bool,
    /// Where the row's device is now: `here` (its socket is on this pod),
    /// `elsewhere` (on another pod), `offline`, or `unknown` (unreadable).
    pub device: &'static str,
    /// The pod that holds the device's socket, when it is another one.
    pub owner_pod: Option<String>,
    /// That pod's answer, when it was asked: its hub holds the session.
    pub held_by_owner: Option<bool>,
    /// The device has had a session since, in its org.
    pub later_row: bool,
}

/// One dead row, as it was read and as a real run ends it.
#[derive(Debug, Serialize)]
pub struct DeadRow {
    pub session_id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub created_at: String,
    pub started_at: Option<String>,
    /// The `ended_at` a real run writes: the row's own last clock.
    pub ends_at: String,
    /// Hours the row has been open, which the growth digest read as live.
    pub open_hours: f64,
    pub evidence: Evidence,
}

/// A row read and kept: not proven dead.
#[derive(Debug, Serialize)]
pub struct KeptRow {
    pub session_id: String,
    pub tenant_id: String,
    pub agent_id: String,
    pub created_at: String,
    /// `held_here`, `no_later_row`, `held_by_owner`, `owner_no_answer` or
    /// `device_unknown`.
    pub why: &'static str,
    pub evidence: Evidence,
}

#[derive(Debug, Serialize)]
pub struct CloseDeadResponse {
    pub dry_run: bool,
    /// `stats.enabled`: with it off a real run is refused.
    pub stats_enabled: bool,
    /// The dead rows of this page.
    pub rows: Vec<DeadRow>,
    /// The rows of this page that are not proven dead, with why.
    pub kept: Vec<KeptRow>,
    /// Rows this call ended (always 0 in a dry run).
    pub closed: u64,
    /// Dead rows a real run could not end: it ended, was resumed or
    /// detached, or its own clock moved, meanwhile, or the write failed (in
    /// the log). A later call reads again.
    pub skipped: u64,
    /// The read stopped at the limit: call again with `after: next`.
    pub more: bool,
    pub next: Option<String>,
}

/// Where a row's device is now.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Device {
    Here,
    Elsewhere(String),
    Offline,
    Unknown,
}

/// `POST /api/admin/rc-sessions/close-dead` (the module doc).
pub async fn close_dead(
    State(state): State<RemoteState>,
    auth: AuthUser,
    body: Result<Json<CloseDeadRequest>, JsonRejection>,
) -> Result<Json<CloseDeadResponse>, ApiError> {
    require_platform_admin(&state, &auth)?;
    let Json(body) = body.map_err(|e| ApiError::BadRequest(e.body_text()))?;
    let stats_enabled = state.settings.stats.enabled;
    if !body.dry_run && !stats_enabled {
        return Err(ApiError::Conflict(
            "stats.enabled is off: no row's own clock moves, so a live session cannot be told \
             from a dead one, and nothing is closed"
                .into(),
        ));
    }
    let limit = body.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let min_age_hours = body
        .min_age_hours
        .unwrap_or(DEFAULT_MIN_AGE_HOURS)
        .max(MIN_AGE_HOURS_FLOOR);
    let after = body.after.as_deref().map(parse_cursor).transpose()?;
    let now = DateTime::now();
    let older_than = DateTime::from_millis(
        now.timestamp_millis()
            .saturating_sub(i64::from(min_age_hours) * 3_600_000),
    );

    let mut page = state
        .remote_sessions
        .dead_candidates(older_than, after, i64::from(limit) + 1)
        .await?;
    let more = page.len() > limit as usize;
    page.truncate(limit as usize);
    let next = more
        .then(|| {
            page.last()
                .and_then(|r| Some(cursor_of((r.created_at, r.id?))))
        })
        .flatten();
    let presence = device_presence(&state, &page).await;

    let (mut dead, mut kept) = (Vec::new(), Vec::new());
    let mut silent_pods: HashSet<String> = HashSet::new();
    for row in &page {
        let Some(session_id) = row.id else { continue };
        let held_here = state.fleet.rc_hub.session_snapshot(session_id).is_some();
        let later_row = !held_here
            && state
                .remote_sessions
                .has_later_row(row.tenant_id, row.agent_id, row.created_at)
                .await?;
        let device = presence
            .get(&row.agent_id)
            .cloned()
            .unwrap_or(Device::Unknown);
        let mut evidence = Evidence {
            stats_at: row.stats_at.map(fmt_dt),
            stats_age_hours: row.stats_at.map(|t| hours_between(t, now)),
            held_here,
            device: match device {
                Device::Here => "here",
                Device::Elsewhere(_) => "elsewhere",
                Device::Offline => "offline",
                Device::Unknown => "unknown",
            },
            owner_pod: match &device {
                Device::Elsewhere(pod) => Some(pod.clone()),
                _ => None,
            },
            held_by_owner: None,
            later_row,
        };
        let why = if held_here {
            Some("held_here")
        } else if !later_row {
            Some("no_later_row")
        } else {
            match &device {
                Device::Here | Device::Offline => None,
                Device::Unknown => Some("device_unknown"),
                Device::Elsewhere(pod) if silent_pods.contains(pod) => Some("owner_no_answer"),
                Device::Elsewhere(pod) => match held_by(&state, pod, session_id).await {
                    Some(held) => {
                        evidence.held_by_owner = Some(held);
                        held.then_some("held_by_owner")
                    }
                    None => {
                        silent_pods.insert(pod.clone());
                        Some("owner_no_answer")
                    }
                },
            }
        };
        match why {
            Some(why) => kept.push(KeptRow {
                session_id: session_id.to_hex(),
                tenant_id: row.tenant_id.to_hex(),
                agent_id: row.agent_id.to_hex(),
                created_at: fmt_dt(row.created_at),
                why,
                evidence,
            }),
            None => dead.push((row, evidence)),
        }
    }

    let (mut closed, mut skipped) = (0u64, 0u64);
    if !body.dry_run {
        for (row, _) in &dead {
            let Some(session_id) = row.id else { continue };
            let at = inferred_end(row);
            match state.remote_sessions.close_dead(row, at, older_than).await {
                Ok(true) => {
                    closed += 1;
                    state.fleet.rc_hub.record_end(
                        session_id,
                        row.agent_id,
                        row.tenant_id,
                        EndReason::AgentDisconnect,
                        None,
                        RowEnd::inferred(row.attach_seq, at, EndSource::Backfill).already_written(),
                    );
                }
                Ok(false) => skipped += 1,
                Err(e) => {
                    skipped += 1;
                    warn!(session = %session_id, %e, "rc dead-row close: the row could not be written");
                }
            }
        }
    }
    let rows: Vec<DeadRow> = dead
        .into_iter()
        .filter_map(|(row, evidence)| {
            let session_id = row.id?;
            Some(DeadRow {
                session_id: session_id.to_hex(),
                tenant_id: row.tenant_id.to_hex(),
                agent_id: row.agent_id.to_hex(),
                created_at: fmt_dt(row.created_at),
                started_at: row.started_at.map(fmt_dt),
                ends_at: fmt_dt(inferred_end(row)),
                open_hours: open_hours(row, now),
                evidence,
            })
        })
        .collect();
    info!(
        operator = %auth.user_id,
        dry_run = body.dry_run,
        rows = rows.len(),
        kept = kept.len(),
        closed,
        skipped,
        more,
        "rc dead-row close"
    );
    Ok(Json(CloseDeadResponse {
        dry_run: body.dry_run,
        stats_enabled,
        rows,
        kept,
        closed,
        skipped,
        more,
        next,
    }))
}

/// Where each device of `page` is now: its socket on this pod (the hub), on
/// another pod (a fresh presence record names it), or nowhere. With no Redis
/// the hub is the whole truth. A record that names this very process while
/// the hub does not hold the device, or a read that fails, is `Unknown`.
async fn device_presence(state: &RemoteState, page: &[RemoteSession]) -> HashMap<ObjectId, Device> {
    let mut out = HashMap::new();
    let mut ask: Vec<ObjectId> = Vec::new();
    for row in page {
        if out.contains_key(&row.agent_id) || ask.contains(&row.agent_id) {
            continue;
        }
        if state.fleet.rc_hub.is_agent_online(row.agent_id) {
            out.insert(row.agent_id, Device::Here);
        } else {
            ask.push(row.agent_id);
        }
    }
    let Some(redis) = &state.redis_pubsub else {
        out.extend(ask.into_iter().map(|a| (a, Device::Offline)));
        return out;
    };
    let hexes: Vec<String> = ask.iter().map(|a| a.to_hex()).collect();
    let records = tokio::time::timeout(PRESENCE_BUDGET, redis.agent_presence_get_many(&hexes))
        .await
        .ok()
        .and_then(Result::ok);
    let Some(records) = records else {
        warn!("rc dead-row close: the devices' presence could not be read; their rows are kept");
        out.extend(ask.into_iter().map(|a| (a, Device::Unknown)));
        return out;
    };
    let me = redis.instance_id().to_string();
    for (agent_id, record) in ask.into_iter().zip(records) {
        let device = match record {
            None => Device::Offline,
            Some(token) if token.starts_with(&me) => Device::Unknown,
            Some(token) => match OwnerRecord::parse(&token) {
                Some(r) if !r.pod_id.is_empty() => Device::Elsewhere(r.pod_id),
                _ => Device::Unknown,
            },
        };
        out.insert(agent_id, device);
    }
    out
}

/// Ask `pod`, which holds the device's socket, whether its hub holds
/// `session_id`. `None` when it does not answer (the bus is down, the pod is
/// gone or too old to know the question).
async fn held_by(state: &RemoteState, pod: &str, session_id: ObjectId) -> Option<bool> {
    let bus = state.cluster_bus.as_ref()?;
    let answer = bus
        .request(
            pod,
            SESSION_HELD,
            serde_json::json!({ "session_id": session_id.to_hex() }),
        )
        .await;
    match answer {
        Ok(v) => v.get("held").and_then(serde_json::Value::as_bool),
        Err(e) => {
            warn!(%pod, session = %session_id, %e, "rc dead-row close: the device's pod did not answer; the row is kept");
            None
        }
    }
}

/// Answer [`SESSION_HELD`] on this pod's bus: whether this pod's hub holds
/// the session. Called once, at the module's init.
pub fn wire_session_held(state: &RemoteState) {
    let Some(bus) = state.cluster_bus.clone() else {
        return;
    };
    let state = state.clone();
    bus.register(SESSION_HELD, move |body| {
        let state = state.clone();
        Box::pin(async move {
            let session_id = body
                .get("session_id")
                .and_then(|v| v.as_str())
                .and_then(|s| ObjectId::parse_str(s).ok())
                .ok_or_else(|| "bad session_id".to_string())?;
            let held = state.fleet.rc_hub.session_snapshot(session_id).is_some();
            Ok(serde_json::json!({ "held": held }))
        })
    });
}

/// `next`: the last row of a page, as `<created_at ms>-<session id>`.
fn cursor_of((created_at, id): RowCursor) -> String {
    format!("{}-{}", created_at.timestamp_millis(), id.to_hex())
}

/// `after`, as [`cursor_of`] wrote it.
fn parse_cursor(s: &str) -> Result<RowCursor, ApiError> {
    let bad = || ApiError::BadRequest(format!("after must be a `next` this route gave, got {s:?}"));
    let (ms, id) = s.split_once('-').ok_or_else(bad)?;
    let ms: i64 = ms.parse().map_err(|_| bad())?;
    let id = ObjectId::parse_str(id).map_err(|_| bad())?;
    Ok((DateTime::from_millis(ms), id))
}

fn hours_between(from: DateTime, to: DateTime) -> f64 {
    let ms = to
        .timestamp_millis()
        .saturating_sub(from.timestamp_millis());
    (ms as f64 / 3_600_000.0 * 10.0).round() / 10.0
}

/// Hours from when the row went live (else was created) to `now`: what an
/// open row has added to the digest's session hours so far.
fn open_hours(row: &RemoteSession, now: DateTime) -> f64 {
    hours_between(row.started_at.unwrap_or(row.created_at), now)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `next` reads back as the cursor it was written from, and anything
    /// else is a 400.
    #[test]
    fn a_cursor_reads_back_and_a_bad_one_is_refused() {
        let c = (DateTime::from_millis(1_762_000_000_123), ObjectId::new());
        assert_eq!(parse_cursor(&cursor_of(c)).unwrap(), c);
        for bad in ["", "123", "x-6a975e17971e2d55ddcdedb2", "123-nothex"] {
            assert!(
                matches!(parse_cursor(bad), Err(ApiError::BadRequest(_))),
                "{bad}"
            );
        }
    }
}
