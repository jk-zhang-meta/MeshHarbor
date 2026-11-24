// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-130 P1b-2 — the sweep (`docs/fr/FR-130-the-session-outlives-its-control-socket.md`
//! §4.4, "The sweep"): what ends a session row whose end nobody saw, once no
//! device will ever claim it. One pod at a time, as the presence sweep runs
//! and on its cadence (`rc.presence_sweep_secs`): a per-cycle Redis claim
//! keyed by the database's name, its own key.
//!
//! | Rows it ends | When | Dated by |
//! |---|---|---|
//! | detached (`resume_by` set) and live past `resume_by` | at every window, 0 included: only a detach writes `resume_by`, so with the window at 0 from the start there are none, and a window turned back to 0 still ends what was detached before | `detached_at` |
//! | live with no `resume_by`, quiet for longer than the window, on a device in the resume scope that the presence sweep found offline for longer than the window: the pod that held it died without a word, and the device has not come back | only with the window on | `stats_at`, else `started_at` |
//!
//! Each end is `agent_disconnect` with `end_source: sweep`, written straight
//! to the row conditional on the row as the sweep read it: still live, at the
//! `attach_seq`, the `resume_by` and the `stats_at` read (a claim that resumed
//! it meanwhile bumps the one and clears the other; a session whose own clock
//! moved is alive), and recorded in the audit as its trail. The session's
//! FR-115 slot, which nobody renews once its session was detached, is given
//! back. A row outside the scope with no `resume_by` stays as it is, until
//! the scope reaches its device.
//!
//! The second kind is read a page a cycle (review 2, N7): the scope is read
//! once and asked of the query, so rows outside it never come back, and the
//! next cycle reads on after the page's last row ([`Cursor`]), so the rows it
//! keeps (a device online, a session this pod holds) never starve a newer
//! one. A device that was removed is gone for good (N6): its rows are
//! abandoned like those of a device offline.

use std::time::Duration;

use bson::{DateTime, doc};
use meshharbor_core::cluster::session_slots::SlotScope;
use meshharbor_mod_fleet::hub::RowEnd;
use meshharbor_mod_fleet::resume_scope::{ScopeTarget, covered_by};
use meshharbor_remote_control::models::{EndReason, EndSource, RemoteSession};
use meshharbor_services::dao::base::DaoError;
use meshharbor_services::dao::rc_resume_scope::ResumeScopeKind;
use meshharbor_services::dao::remote_session::RowCursor;
use tracing::{debug, info, warn};

use crate::RemoteState;

/// The most rows one cycle reads of each kind; the next cycle reads on.
const SWEEP_LIMIT: i64 = 200;

/// Where this pod's next cycle reads the quiet rows on from: after the last
/// row of a full page, or from the start (review 2, N7). Per pod, like the
/// cycle it serves; any pod's cycles cover every row in turn.
pub type Cursor = std::sync::Mutex<Option<RowCursor>>;

/// What one cycle ended.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Swept {
    /// Detached rows past their `resume_by`.
    pub detached: usize,
    /// Rows a pod that died without a word left open, on a device gone
    /// offline for longer than the window.
    pub abandoned: usize,
}

/// Spawn the sweep loop, on the presence sweep's cadence. The first cycle is
/// a full interval out, so a short-lived test server never races a test.
pub fn spawn(state: RemoteState) {
    let every = state.settings.rc.presence_sweep_secs.max(5);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(every)).await;
            if let Some(redis) = &state.redis_pubsub {
                let key = format!("meshharbor:rc-resume-sweep:{}", state.db.name());
                let ttl = every.saturating_sub(5).max(5);
                match redis.try_claim(&key, ttl).await {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(e) => {
                        debug!(%e, "rc resume sweep: the cycle's claim failed; skipping it");
                        continue;
                    }
                }
            }
            let swept = run_sweep(&state).await;
            if swept != Swept::default() {
                info!(
                    detached = swept.detached,
                    abandoned = swept.abandoned,
                    "rc resume sweep ended rows nobody will claim"
                );
            }
        }
    });
}

/// One cycle (the table above). Public so a test drives it directly.
pub async fn run_sweep(state: &RemoteState) -> Swept {
    let now = DateTime::now();
    let mut swept = Swept::default();

    match state.remote_sessions.detached_past(now, SWEEP_LIMIT).await {
        Ok(rows) => {
            for row in rows {
                let at = row
                    .detached_at
                    .unwrap_or_else(|| crate::resume::inferred_end(&row));
                if end_row(state, &row, at).await {
                    swept.detached += 1;
                }
            }
        }
        Err(e) => warn!(%e, "rc resume sweep: the detached rows could not be read"),
    }

    let window =
        meshharbor_mod_fleet::resume_scope::capped_window(state.settings.rc.session_resume_secs);
    if window == 0 {
        return swept;
    }
    // The scope, once a cycle: only a device it covers can have a row ended
    // this way, so the read asks for those rows alone.
    let targets: Vec<ScopeTarget> = match state.fleet.rc_resume_scope.list().await {
        Ok(entries) => entries.iter().map(|e| (e.kind, e.id)).collect(),
        Err(e) => {
            warn!(%e, "rc resume sweep: the scope could not be read; the quiet rows wait");
            return swept;
        }
    };
    let Some(within) = scope_filter(&targets) else {
        return swept;
    };
    let window_ms = i64::from(window) * 1000;
    let quiet_since = DateTime::from_millis(now.timestamp_millis().saturating_sub(window_ms));
    let after = *state
        .sweep_cursor
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let rows = match state
        .remote_sessions
        .unclaimed_quiet(quiet_since, within, after, SWEEP_LIMIT)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            warn!(%e, "rc resume sweep: the quiet rows could not be read");
            return swept;
        }
    };
    // A full page: the next cycle reads on after its last row. Else from the
    // start again.
    let next = (rows.len() as i64 >= SWEEP_LIMIT)
        .then(|| rows.last().and_then(|r| Some((r.created_at, r.id?))))
        .flatten();
    *state
        .sweep_cursor
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = next;
    for row in rows {
        if abandoned(state, &row, quiet_since, &targets).await
            && end_row(state, &row, crate::resume::inferred_end(&row)).await
        {
            swept.abandoned += 1;
        }
    }
    swept
}

/// The resume scope as a filter on the rows' org and device: `None` when it
/// covers nothing (the read is skipped), `Some(None)` when it covers every
/// org (`all`).
fn scope_filter(targets: &[ScopeTarget]) -> Option<Option<bson::Document>> {
    if targets.is_empty() {
        return None;
    }
    if targets
        .iter()
        .any(|(kind, _)| *kind == ResumeScopeKind::All)
    {
        return Some(None);
    }
    let ids = |want: ResumeScopeKind| -> Vec<bson::oid::ObjectId> {
        targets
            .iter()
            .filter(|(kind, _)| *kind == want)
            .filter_map(|(_, id)| *id)
            .collect()
    };
    let mut any = Vec::new();
    let orgs = ids(ResumeScopeKind::Org);
    if !orgs.is_empty() {
        any.push(doc! { "tenant_id": { "$in": orgs } });
    }
    let devices = ids(ResumeScopeKind::Device);
    if !devices.is_empty() {
        any.push(doc! { "agent_id": { "$in": devices } });
    }
    if any.is_empty() {
        return None;
    }
    Some(Some(doc! { "$or": any }))
}

/// A live row with no `resume_by` whose pod died without a word: its device
/// is in the scope (`targets`), no pod here holds it, and the presence sweep
/// found the device offline before `quiet_since` (the window ago), or the
/// device was removed (review 2, N6: it never comes back for the session).
/// Anything unread is not abandoned: the row waits for the next cycle.
async fn abandoned(
    state: &RemoteState,
    row: &RemoteSession,
    quiet_since: DateTime,
    targets: &[ScopeTarget],
) -> bool {
    let Some(session_id) = row.id else {
        return false;
    };
    let hub = &state.fleet.rc_hub;
    if hub.session_snapshot(session_id).is_some()
        || hub.is_agent_online(row.agent_id)
        || !covered_by(targets, row.tenant_id, row.agent_id)
    {
        return false;
    }
    match state
        .fleet
        .agents
        .find_live_in_tenant(row.tenant_id, row.agent_id)
        .await
    {
        Ok(agent) => {
            agent.last_presence.as_deref() == Some(meshharbor_mod_fleet::presence::OFFLINE)
                && agent.last_seen_at < quiet_since
        }
        // A tombstone reads as no live device: removed, it is gone for good.
        Err(DaoError::NotFound) => true,
        Err(e) => {
            debug!(session = %session_id, %e, "rc resume sweep: the device could not be read; left for later");
            false
        }
    }
}

/// End one row the sweep found, as it read it, dated `at`; its trail in the
/// audit and its slot given back. `true` when it ended it.
async fn end_row(state: &RemoteState, row: &RemoteSession, at: DateTime) -> bool {
    let Some(session_id) = row.id else {
        return false;
    };
    match state.remote_sessions.end_swept(row, at).await {
        Ok(true) => {}
        Ok(false) => return false,
        Err(e) => {
            warn!(session = %session_id, %e, "rc resume sweep: the row could not be written");
            return false;
        }
    }
    info!(
        session = %session_id,
        agent = %row.agent_id,
        ended_at_ms = at.timestamp_millis(),
        "rc session nobody will claim — swept at its own last clock"
    );
    state.fleet.rc_hub.record_end(
        session_id,
        row.agent_id,
        row.tenant_id,
        EndReason::AgentDisconnect,
        None,
        RowEnd::inferred(row.attach_seq, at, EndSource::Sweep).already_written(),
    );
    if crate::slots::enabled(state)
        && let Some(slots) = &state.session_slots
        && let Err(e) = slots
            .release(SlotScope::Org(row.tenant_id), session_id)
            .await
    {
        debug!(session = %session_id, %e, "rc resume sweep: the slot was not given back; it expires on its own");
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::oid::ObjectId;

    /// The scope becomes the rows' filter: nothing for an empty scope (the
    /// read is skipped), no filter for `all`, else the orgs and devices it
    /// names.
    #[test]
    fn the_scope_filters_the_rows_the_sweep_reads() {
        assert_eq!(scope_filter(&[]), None, "an empty scope covers nothing");
        let (org, dev) = (ObjectId::new(), ObjectId::new());
        assert_eq!(
            scope_filter(&[
                (ResumeScopeKind::Device, Some(dev)),
                (ResumeScopeKind::All, None)
            ]),
            Some(None),
            "all covers every org"
        );
        assert_eq!(
            scope_filter(&[(ResumeScopeKind::Org, Some(org))]),
            Some(Some(doc! { "$or": [ { "tenant_id": { "$in": [org] } } ] }))
        );
        assert_eq!(
            scope_filter(&[
                (ResumeScopeKind::Org, Some(org)),
                (ResumeScopeKind::Device, Some(dev)),
            ]),
            Some(Some(doc! { "$or": [
                { "tenant_id": { "$in": [org] } },
                { "agent_id": { "$in": [dev] } },
            ] }))
        );
        assert_eq!(
            scope_filter(&[(ResumeScopeKind::Device, None)]),
            None,
            "an entry that names nothing covers nothing"
        );
    }
}
