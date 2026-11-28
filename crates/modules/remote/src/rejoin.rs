// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-130 P1b-2 — `rc:session.rejoin`, the viewer's claim on a session held
//! for it (`docs/fr/FR-130-the-session-outlives-its-control-socket.md` §4.4,
//! §4.5), answered on the pod the viewer's new socket reached.
//!
//! Each rejoin gets exactly one answer, and it names the session:
//! `rc:session.resumed`, `rc:session.detached {resume_by}` (ask again, in a
//! second, until `resume_by`), or `rc:terminate`. Never an `rc:error`: the
//! page asks again only after a `detached`, so a rejoin left unanswered
//! would hold it until its own deadline.
//!
//! | Where the session is | Answer |
//! |---|---|
//! | held by this pod's hub, for this person | the gate a request runs, again; then bound here and `rc:session.resumed`, or ended `admin_terminated` |
//! | the row names someone else, or nothing | `rc:terminate agent_disconnect`, the same as for no session: nothing leaks |
//! | the row is ended | `rc:terminate` with the row's own reason, except `controller_hangup`, answered `agent_disconnect` (`rejoin_end_reason`) |
//! | the row is live, and the gate refuses | written to the row as `admin_terminated`, and published, as an admin's end; `rc:terminate admin_terminated` |
//! | the gate cannot be run (a read failed) | nothing bound, nothing written: `rc:session.detached` with when the session ends if nobody claims it, so the viewer asks again |
//! | the row cannot be read | `rc:session.detached` with the window from now: the viewer asks again, and the first answer that reads the row brings its deadline in |
//! | detached by the device's side, inside `resume_by` | `rc:session.detached` with the row's `resume_by`: ask again |
//! | detached, past `resume_by` | `rc:terminate agent_disconnect` |
//! | live in the hub of the pod that holds the device's socket | relayed there (`rc.cmd`), bound there, answered through the relay |
//! | live, but in no hub yet (the claim is not answered, or a pod died without a word) | `rc:session.detached` with when it would end, or `rc:terminate agent_disconnect` once that has passed |
//!
//! Review 2, N14 — the gate costs about five reads, and a page asks every
//! second while its session waits for the device's claim. Where nothing is
//! bound or relayed (a detached row, a live row in no hub yet) the gate runs
//! at most once per 5 s per session and viewer ([`GateRuns`]), and a refusal
//! answers as the table says: a viewer removed from the org is refused
//! within about 5 s. Before a bind (held here) or a relay it always runs. A
//! pair's timing goes at its bind, its relay or its refusal, and the rest
//! are pruned at most once a second (PR D's review, LOW 8).
//!
//! With the window at 0 the rejoin is dropped unanswered, as a server before
//! FR-130 drops it. No page sends one then: none was told `resume_secs`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bson::{DateTime, oid::ObjectId};
use dashmap::DashMap;
use meshharbor_mod_fleet::hub::OrgPolicy;
use meshharbor_remote_control::models::{ConsentMode, EndReason, RemoteSession, SessionPhase};
use meshharbor_remote_control::session::ClientTx;
use meshharbor_remote_control::signaling::{ClientMsg, ServerMsg};
use meshharbor_services::dao::base::DaoError;
use tracing::{debug, info, warn};

use crate::RemoteState;
use crate::controller::{ResumeGate, resume_gate};

/// At most one gate per session and viewer this often, while nothing is
/// bound or relayed.
const GATE_EVERY: Duration = Duration::from_secs(5);

/// PR D's review, LOW 8 — how often [`GateRuns`] drops its old entries: at
/// most once in this long, whatever the number of asks.
const PRUNE_EVERY: Duration = Duration::from_secs(1);

/// Review 2, N14 — when each (session, viewer) last ran the gate on a rejoin
/// that binds nothing (`RemoteState::rejoin_gates`), on this pod.
///
/// PR D's review, LOW 8 — bounded without walking the map on every ask: an
/// entry goes when its session binds or is relayed, and when the gate
/// refuses its viewer ([`Self::forget`]); the rest go once they are older
/// than [`GATE_EVERY`], at a prune that runs at most once per
/// [`PRUNE_EVERY`] across all asks. Every call is synchronous: no guard of
/// the map outlives it.
pub struct GateRuns {
    runs: DashMap<(ObjectId, ObjectId), Instant>,
    /// What `pruned_ms` counts from.
    base: Instant,
    /// When the last prune ran, in ms after `base`.
    pruned_ms: AtomicU64,
}

impl Default for GateRuns {
    fn default() -> Self {
        Self::new()
    }
}

impl GateRuns {
    pub fn new() -> Self {
        Self {
            runs: DashMap::new(),
            base: Instant::now(),
            pruned_ms: AtomicU64::new(0),
        }
    }

    /// The (session, viewer) pairs timed now.
    pub fn len(&self) -> usize {
        self.runs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }

    /// `user_id`'s rejoins of `session_id` are timed no more: its session is
    /// bound or relayed, or the gate refused the viewer.
    pub fn forget(&self, session_id: ObjectId, user_id: ObjectId) {
        self.runs.remove(&(session_id, user_id));
    }

    /// Whether the ask of `key` at `now` runs the gate: the first ask does,
    /// and then one every [`GATE_EVERY`].
    fn due(&self, key: (ObjectId, ObjectId), now: Instant) -> bool {
        self.prune(now);
        let mut due = true;
        self.runs
            .entry(key)
            .and_modify(|at| {
                if now.saturating_duration_since(*at) < GATE_EVERY {
                    due = false;
                } else {
                    *at = now;
                }
            })
            .or_insert(now);
        due
    }

    /// Drop the entries older than [`GATE_EVERY`], at most once per
    /// [`PRUNE_EVERY`]: of two asks in the same instant, one prunes.
    fn prune(&self, now: Instant) {
        let now_ms =
            u64::try_from(now.saturating_duration_since(self.base).as_millis()).unwrap_or(u64::MAX);
        let last = self.pruned_ms.load(Ordering::Relaxed);
        if u128::from(now_ms.saturating_sub(last)) < PRUNE_EVERY.as_millis() {
            return;
        }
        if self
            .pruned_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        self.runs
            .retain(|_, at| now.saturating_duration_since(*at) < GATE_EVERY);
    }
}

/// Whether `user_id`'s rejoin of `session_id` runs the gate now
/// ([`GateRuns`]).
fn gate_due(state: &RemoteState, session_id: ObjectId, user_id: ObjectId) -> bool {
    state
        .rejoin_gates
        .due((session_id, user_id), Instant::now())
}

/// The viewer's socket the rejoin came in on.
pub struct Viewer<'a> {
    pub user_id: ObjectId,
    pub name: &'a str,
    pub tx: &'a ClientTx,
    /// The address the relay routes the answer back to, when the session is
    /// held on another pod.
    pub connection_id: &'a str,
}

fn end(session_id: ObjectId, reason: EndReason) -> ServerMsg {
    ServerMsg::Terminate {
        session_id,
        reason,
        limit: None,
    }
}

fn detached(session_id: ObjectId, resume_by: DateTime) -> ServerMsg {
    ServerMsg::SessionDetached {
        session_id,
        resume_by: u64::try_from(resume_by.timestamp_millis()).unwrap_or(0),
    }
}

/// `window_secs` after `from`.
fn after(from: DateTime, window_secs: u32) -> DateTime {
    DateTime::from_millis(
        from.timestamp_millis()
            .saturating_add(i64::from(window_secs).saturating_mul(1000)),
    )
}

/// Review 2, N9 — the reason a rejoin is told when it finds the row ended.
/// The page that rejoins never hung up: its socket went. So a row ended
/// `controller_hangup` was ended by the hold's window running out (a rejoin
/// that lands just after it, before the device's close reaches the page) or
/// by the same person's other request reaping it, and the page reads
/// `controller_hangup` as its own hangup and stops. It is told
/// `agent_disconnect` instead, which it redials on, as a page before FR-130
/// redialed after every drop. Every other reason is the row's own.
fn rejoin_end_reason(row_reason: Option<EndReason>) -> EndReason {
    match row_reason {
        None | Some(EndReason::ControllerHangup) => EndReason::AgentDisconnect,
        Some(reason) => reason,
    }
}

/// The answer while the session waits for its claim: ask again until `by`,
/// and once `by` has passed, it is over.
fn until(session_id: ObjectId, by: DateTime, now: DateTime) -> ServerMsg {
    if by > now {
        detached(session_id, by)
    } else {
        end(session_id, EndReason::AgentDisconnect)
    }
}

/// Answer one `rc:session.rejoin` (the table above).
pub async fn rejoin(state: &RemoteState, v: Viewer<'_>, session_id: ObjectId) {
    let window =
        meshharbor_mod_fleet::resume_scope::capped_window(state.settings.rc.session_resume_secs);
    if window == 0 {
        debug!(session = %session_id.to_hex(), "rc:session.rejoin dropped: the window is off");
        return;
    }
    let hub = &state.fleet.rc_hub;
    let answer = |msg: ServerMsg| {
        let _ = v.tx.try_send(msg);
    };

    // Held on this pod, for this person.
    if let Some(p) = hub
        .held_parties(session_id)
        .filter(|p| p.controller_user_id == v.user_id)
    {
        match resume_gate(state, v.user_id, p.tenant_id, p.agent_id, p.permissions).await {
            ResumeGate::Allow { .. } => match hub.rejoin(session_id, v.user_id, v.tx) {
                Ok(()) => {
                    state.rejoin_gates.forget(session_id, v.user_id);
                    return;
                }
                // It ended, or may not be held: the row says how.
                Err(e) => {
                    debug!(session = %session_id.to_hex(), %e, "rc:session.rejoin: not held here any more; reading the row");
                }
            },
            ResumeGate::Deny(why) => {
                info!(session = %session_id.to_hex(), user = %v.user_id, %why, "rc:session.rejoin: the viewer may no longer control the device");
                hub.refuse_rejoin(session_id, v.user_id, v.tx, EndReason::AdminTerminated);
                state.rejoin_gates.forget(session_id, v.user_id);
                return;
            }
            // Decided nothing: when the hold ends, and the viewer asks again.
            ResumeGate::Unknown(why) => {
                warn!(session = %session_id.to_hex(), %why, "rc:session.rejoin: the gate could not be run; ask again");
                let by = p
                    .held_until
                    .unwrap_or_else(|| after(DateTime::now(), window));
                answer(detached(session_id, by));
                return;
            }
        }
    }

    // Not held here: the row, which must name this person.
    let row = match state
        .remote_sessions
        .find_for_controller(session_id, v.user_id)
        .await
    {
        Ok(row) => row,
        Err(DaoError::NotFound) => {
            answer(end(session_id, EndReason::AgentDisconnect));
            return;
        }
        Err(e) => {
            warn!(session = %session_id.to_hex(), %e, "rc:session.rejoin: the row could not be read; ask again");
            answer(detached(session_id, after(DateTime::now(), window)));
            return;
        }
    };
    if row.ended_at.is_some() || row.phase == SessionPhase::Closed {
        answer(end(session_id, rejoin_end_reason(row.end_reason)));
        return;
    }
    if row.phase != SessionPhase::Active {
        answer(end(session_id, EndReason::AgentDisconnect));
        return;
    }
    // Detached when the device's socket went, and not claimed yet: nothing is
    // bound, so the gate runs once per `GATE_EVERY` for this viewer (N14).
    if let Some(by) = row.resume_by {
        if gate_due(state, session_id, v.user_id)
            && run_gate(state, &v, &row, session_id).await.is_none()
        {
            return;
        }
        answer(until(session_id, by, DateTime::now()));
        return;
    }
    // Live in the hub of the pod that holds the device's socket: bound there,
    // so the gate always runs first.
    let owner = if hub.is_agent_online(row.agent_id) {
        None
    } else {
        foreign_owner(state, row.agent_id).await
    };
    if let Some(owner) = owner {
        match run_gate(state, &v, &row, session_id).await {
            None => return,
            Some(true) => {
                if relay(state, &v, &owner, session_id).await {
                    state.rejoin_gates.forget(session_id, v.user_id);
                    return;
                }
            }
            Some(false) => {}
        }
    } else if gate_due(state, session_id, v.user_id)
        && run_gate(state, &v, &row, session_id).await.is_none()
    {
        return;
    }
    // In no hub yet: the device's claim is not answered, or the pod that held
    // it died without a word. The viewer may ask again until it would end.
    let by = wait_until(state, &row, window).await;
    answer(until(session_id, by, DateTime::now()));
}

/// The gate a request runs, for the viewer of a session no hub on this pod
/// holds. `None` when it refused: the row is ended as an admin's end is, the
/// viewer is told `admin_terminated`, and its rejoins are timed no more.
/// `Some(true)` when allowed; `Some(false)` when a read failed and nothing
/// was decided, so nothing is bound, the deadline is answered, and the viewer
/// asks again.
async fn run_gate(
    state: &RemoteState,
    v: &Viewer<'_>,
    row: &RemoteSession,
    session_id: ObjectId,
) -> Option<bool> {
    match resume_gate(
        state,
        v.user_id,
        row.tenant_id,
        row.agent_id,
        row.permissions,
    )
    .await
    {
        ResumeGate::Allow { .. } => Some(true),
        ResumeGate::Deny(why) => {
            info!(session = %session_id.to_hex(), user = %v.user_id, %why, "rc:session.rejoin: the viewer may no longer control the device");
            crate::row_end::revoked(state, row).await;
            let _ = v.tx.try_send(end(session_id, EndReason::AdminTerminated));
            state.rejoin_gates.forget(session_id, v.user_id);
            None
        }
        ResumeGate::Unknown(why) => {
            warn!(session = %session_id.to_hex(), %why, "rc:session.rejoin: the gate could not be run; ask again");
            Some(false)
        }
    }
}

/// The pod that holds the device's socket, when it is another one.
async fn foreign_owner(state: &RemoteState, agent_id: ObjectId) -> Option<String> {
    let redis = state.redis_pubsub.as_ref()?;
    let owner = tokio::time::timeout(
        Duration::from_millis(250),
        redis.agent_presence_foreign(&agent_id.to_hex()),
    )
    .await
    .ok()?
    .ok()??;
    meshharbor_core::cluster::directory::OwnerRecord::parse(&owner)
        .map(|r| r.pod_id)
        .filter(|pod| !pod.is_empty())
}

/// Relay the rejoin to `owner`, whose hub binds it to a proxy for this
/// socket and answers through it. `true` when it was bound there. The gate
/// already ran here, as it does for a relayed request. Anything else (the
/// owner's hub does not hold it, or the bus failed) is answered here.
async fn relay(state: &RemoteState, v: &Viewer<'_>, owner: &str, session_id: ObjectId) -> bool {
    let Ok(frame) = serde_json::to_value(ClientMsg::SessionRejoin { session_id }) else {
        return false;
    };
    let relayed = crate::relay::relay_rc_frame(
        state,
        owner,
        v.connection_id,
        v.user_id,
        v.name,
        ConsentMode::Prompt,
        &None,
        None,
        &None,
        false,
        false,
        OrgPolicy::Unavailable,
        None,
        None,
        None,
        None,
        false,
        &frame,
    )
    .await;
    matches!(relayed, Ok(None))
}

/// When a live session no hub holds would end if nobody claims it: the
/// device's last word to any pod (`last_seen_at`) or the row's own last
/// clock, whichever is later, plus the window. The pod that held it wrote no
/// `resume_by`, so this is the server's best reading of the device's own
/// deadline, at most a heartbeat early.
async fn wait_until(state: &RemoteState, row: &RemoteSession, window: u32) -> DateTime {
    let row_clock = crate::resume::inferred_end(row);
    let from = match state
        .fleet
        .agents
        .find_live_in_tenant(row.tenant_id, row.agent_id)
        .await
    {
        Ok(agent) => agent.last_seen_at.max(row_clock),
        Err(_) => row_clock,
    };
    after(from, window)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(ms: i64) -> DateTime {
        DateTime::from_millis(ms)
    }

    /// While the deadline is ahead the viewer is told it and asks again; at
    /// it or past it the session is over, `agent_disconnect`.
    #[test]
    fn a_waiting_session_is_detached_until_its_deadline_then_ended() {
        let sid = ObjectId::new();
        match until(sid, at(10_000), at(9_999)) {
            ServerMsg::SessionDetached {
                session_id,
                resume_by,
            } => {
                assert_eq!(session_id, sid);
                assert_eq!(resume_by, 10_000);
            }
            other => panic!("{other:?}"),
        }
        for now in [10_000, 10_001] {
            assert!(matches!(
                until(sid, at(10_000), at(now)),
                ServerMsg::Terminate {
                    reason: EndReason::AgentDisconnect,
                    limit: None,
                    ..
                }
            ));
        }
        assert_eq!(after(at(1_000), 60), at(61_000));
        assert_eq!(after(at(i64::MAX - 1), 60), at(i64::MAX), "saturates");
    }

    /// Review 2, N14 — one gate per pair every 5 s: the first ask runs it,
    /// the asks inside the 5 s do not, and the first after them does.
    #[test]
    fn a_pairs_gate_runs_once_per_five_seconds() {
        let runs = GateRuns::new();
        let t0 = runs.base + Duration::from_secs(10);
        let pair = (ObjectId::new(), ObjectId::new());
        assert!(runs.due(pair, t0), "the first ask runs it");
        for ms in [1, 1_000, 4_999] {
            assert!(
                !runs.due(pair, t0 + Duration::from_millis(ms)),
                "{ms} ms after it"
            );
        }
        assert!(runs.due(pair, t0 + Duration::from_secs(5)), "5 s after it");
        let other = (pair.0, ObjectId::new());
        assert!(runs.due(other, t0 + Duration::from_secs(5)), "per viewer");
        runs.forget(pair.0, pair.1);
        assert!(runs.due(pair, t0 + Duration::from_secs(6)), "forgotten");
    }

    /// PR D's review, LOW 8 — the old entries go at a prune, and a prune runs
    /// at most once a second, however many asks come: an entry past 5 s
    /// stays until the next prune is due.
    #[test]
    fn the_rate_map_drops_old_entries_at_most_once_a_second() {
        let runs = GateRuns::new();
        let t0 = runs.base + Duration::from_secs(10);
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let pair = || (ObjectId::new(), ObjectId::new());
        let (x, y, z, w, v) = (pair(), pair(), pair(), pair(), pair());
        runs.due(x, at(0)); // prunes, at 0
        runs.due(y, at(500)); // too soon to prune
        assert_eq!(runs.len(), 2);
        runs.due(z, at(5_200)); // prunes: x is 5.2 s old, y 4.7 s
        assert!(!runs.runs.contains_key(&x), "x went");
        assert_eq!(runs.len(), 2, "y and z");
        runs.due(w, at(5_700)); // 0.5 s after the last prune: none
        assert!(runs.runs.contains_key(&y), "y, now 5.2 s old, waits");
        assert_eq!(runs.len(), 3);
        runs.due(v, at(6_300)); // prunes: y is 5.8 s old
        assert!(!runs.runs.contains_key(&y), "y went");
        assert_eq!(runs.len(), 3, "z, w and v");
        runs.forget(v.0, v.1);
        assert_eq!(runs.len(), 2);
    }

    /// Review 2, N9 — a page that rejoins never hung up, so a row ended
    /// `controller_hangup` (its hold ran out) answers a reason the page
    /// redials on; a row with no reason does too, and every other reason is
    /// the row's own.
    #[test]
    fn a_rejoin_that_finds_its_hold_ended_is_told_a_reason_it_redials_on() {
        assert_eq!(
            rejoin_end_reason(Some(EndReason::ControllerHangup)),
            EndReason::AgentDisconnect
        );
        assert_eq!(rejoin_end_reason(None), EndReason::AgentDisconnect);
        for reason in [
            EndReason::AgentDisconnect,
            EndReason::AdminTerminated,
            EndReason::HostDisconnect,
            EndReason::IdleTimeout,
            EndReason::Error,
        ] {
            assert_eq!(rejoin_end_reason(Some(reason)), reason, "{reason:?}");
        }
    }
}
