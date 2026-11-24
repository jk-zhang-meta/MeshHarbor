// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-130 — the server's answer to a device that comes back for the sessions
//! it kept (`docs/fr/FR-130-the-session-outlives-its-control-socket.md`
//! §4.4), run in this module's agent-socket `hello`, before the socket's read
//! loop starts. Only for a connection announced a window: with the window at
//! 0, or a device outside the scope or without `rc-resume`, nothing here runs
//! and nothing is read.
//!
//! **The claim.** For each session the hello names, the pod the device
//! reached decides from the session's ROW, never from any pod's memory:
//!
//! | Check | Fails as |
//! |---|---|
//! | the row exists in the device's tenant and names this device | `agent_disconnect`, nothing written |
//! | the row is live and not ended | the row's own end reason (an admin's end written during the gap reads `admin_terminated`), nothing written |
//! | `resume_by` has not passed, when the row has one | `agent_disconnect`, the row ended as inferred |
//! | the row is not marked `external` (review 1, L6: a device never keeps an external session, D3) | `agent_disconnect`, the row ended at the number read |
//! | the gate a request runs, run again (`controller::resume_gate`) | `admin_terminated`; a read that failed decides nothing: `agent_disconnect`, and the session is over, so the device's newest connection ends the row as inferred |
//! | the org's maximum length, counted from `started_at` | `idle_timeout`, limit `max_duration` |
//!
//! A claim that passes commits with one conditional update that bumps the
//! fencing number ([`RemoteSessionDao::commit_resume`]). Only then is the
//! FR-115 slot taken again under the session's own id (PR C's deferred race:
//! a claim that loses never renews or retags the winner's lease), and before
//! the hub rebuilds anything (PR D's review, MEDIUM 2): a session whose slot
//! another took during the gap is refused there, fenced at the number
//! committed, and otherwise its lease enters the hub with the session the
//! hub rebuilds and counts. The row is read once more, so an end that landed
//! meanwhile wins, and only then does the device hear `rc:session.resumed`.
//! A claim whose connection was gone once it had committed, or whose refusal
//! nobody hears, writes the detach back (review 1, L2; `write_back`).
//! Consent is the one check not re-run. A commit that matched nothing is
//! decided from the row read again (`commit`): the device's NEWEST
//! connection tries once more at the row's number while the row is still
//! live and inside its window (an older connection's claim of the same
//! device committed first), or ends the row it refuses; an older
//! connection's claim does neither, and leaves the slot alone.
//!
//! **The registration read.** Then every live row of the device created
//! before this registration that the hello does not claim (and the hub did
//! not just reap) is ended as `agent_disconnect`, dated by the row's own last
//! clock ([`inferred_end`]) and marked `end_source: registration`, fenced at
//! the number read. That is what closes a row a pod that died left open.
//!
//! [`RemoteSessionDao::commit_resume`]: meshharbor_services::dao::remote_session::RemoteSessionDao::commit_resume

use std::collections::HashMap;
use std::time::Duration;

use bson::DateTime;
use bson::oid::ObjectId;
use dashmap::DashMap;
use meshharbor_core::AgentCtx;
use meshharbor_core::cluster::session_slots::{Lease, SlotScope};
use meshharbor_mod_fleet::hub::{Resumed, ResumedSession, RowEnd};
use meshharbor_remote_control::models::{EndReason, EndSource, RemoteSession, SessionPhase};
use meshharbor_remote_control::signaling::Role;
use meshharbor_services::dao::base::DaoError;
use tracing::{debug, info, warn};

use crate::RemoteState;
use crate::controller::ResumeGate;
use crate::slots::SlotDecision;

/// P1b-2 — the sessions each connection's registration ended because the
/// hello did not claim them, keyed by the connection (`AgentCtx::conn_id`):
/// the registration read's inferred ends, with the row's own clock they were
/// dated by, and the hub's in-memory reap (`None`). The device's own end of
/// one, reported after its hello, replaces the reason ([`device_end`]).
/// Filled only under a window; released when the connection closes.
pub type RegistrationEnds = DashMap<String, HashMap<ObjectId, Option<DateTime>>>;

/// Remember that this connection's registration ended `session_id` without
/// seeing its end.
fn note_registration_end(
    state: &RemoteState,
    ctx: &AgentCtx,
    session_id: ObjectId,
    inferred_at: Option<DateTime>,
) {
    state
        .registration_ends
        .entry(ctx.conn_id.clone())
        .or_default()
        .insert(session_id, inferred_at);
}

/// The most rows an earlier connection left open that one registration ends.
/// A device holds at most its capacity of live sessions, so past this the
/// next registration reads on.
const REGISTRATION_READ_LIMIT: i64 = 64;

/// The device's hello landed under a window: answer each claim, then end
/// what earlier connections left open.
pub async fn on_hello(state: &RemoteState, ctx: &AgentCtx) {
    if ctx.resume.window_secs == 0 {
        return;
    }
    // The hub's in-memory reap ended these at the registration: the device
    // may still report how they really ended (`device_end`).
    for &session_id in &ctx.resume.reaped {
        note_registration_end(state, ctx, session_id, None);
    }
    for &session_id in &ctx.resume.claims {
        claim(state, ctx, session_id).await;
    }
    registration_read(state, ctx).await;
}

/// The best-known real end of a session whose end nobody saw (spec §4.4):
/// when it was detached, else its last stats merge, else when it went live
/// (else when it was asked for). Never the reader's clock, so a row left
/// open for weeks adds no hours.
pub fn inferred_end(row: &RemoteSession) -> DateTime {
    row.detached_at
        .or(row.stats_at)
        .or(row.started_at)
        .unwrap_or(row.created_at)
}

fn refuse(
    state: &RemoteState,
    ctx: &AgentCtx,
    session_id: ObjectId,
    reason: EndReason,
    limit: Option<&'static str>,
    row: Option<RowEnd>,
) {
    state
        .fleet
        .rc_hub
        .refuse_claim(ctx.agent_id, &ctx.tx, session_id, reason, limit, row);
}

/// Decide one claim, and answer it.
async fn claim(state: &RemoteState, ctx: &AgentCtx, session_id: ObjectId) {
    let agent = ctx.agent_id;
    // The row, resolved in the device's tenant and naming the device: a claim
    // never reaches a row of another tenant or device, and writes none.
    let row = match state
        .remote_sessions
        .find_in_tenant(ctx.tenant_id, session_id)
        .await
    {
        Ok(row) if row.agent_id == agent => row,
        Ok(_) => {
            warn!(%agent, session = %session_id, "rc session claim names another device's session — refused");
            return refuse(
                state,
                ctx,
                session_id,
                EndReason::AgentDisconnect,
                None,
                None,
            );
        }
        Err(DaoError::NotFound) => {
            info!(%agent, session = %session_id, "rc session claim names no session of the device's org — refused");
            return refuse(
                state,
                ctx,
                session_id,
                EndReason::AgentDisconnect,
                None,
                None,
            );
        }
        Err(e) => {
            warn!(%agent, session = %session_id, %e, "rc session claim: the row could not be read — refused");
            return refuse(
                state,
                ctx,
                session_id,
                EndReason::AgentDisconnect,
                None,
                None,
            );
        }
    };
    claim_as_read(state, ctx, session_id, row).await;
}

/// Decide one claim on its row as the claim read it: everything after the
/// read. Public for the integration tests, which hand it a row read before
/// another claim of the same device committed: two claims racing is a case
/// they cover, and no socket orders one on demand. A row that is not this
/// device's, in its org, is refused as the read refuses it.
#[doc(hidden)]
pub async fn claim_as_read(
    state: &RemoteState,
    ctx: &AgentCtx,
    session_id: ObjectId,
    row: RemoteSession,
) {
    let agent = ctx.agent_id;
    if row.agent_id != agent || row.tenant_id != ctx.tenant_id || row.id != Some(session_id) {
        return refuse(
            state,
            ctx,
            session_id,
            EndReason::AgentDisconnect,
            None,
            None,
        );
    }
    // Ended while no pod held it (an admin's end, the controller's): its own
    // reason, and the row is left as it is.
    if row.ended_at.is_some() || row.phase == SessionPhase::Closed {
        let reason = row.end_reason.unwrap_or(EndReason::AgentDisconnect);
        return refuse(state, ctx, session_id, reason, None, None);
    }
    if row.phase != SessionPhase::Active {
        return refuse(
            state,
            ctx,
            session_id,
            EndReason::AgentDisconnect,
            None,
            None,
        );
    }
    let seq = row.attach_seq;
    let now = DateTime::now();
    if row.resume_by.is_some_and(|by| by <= now) {
        let at = inferred_end(&row);
        note_registration_end(state, ctx, session_id, Some(at));
        let end = RowEnd::inferred(seq, at, EndSource::Registration);
        return refuse(
            state,
            ctx,
            session_id,
            EndReason::AgentDisconnect,
            None,
            Some(end),
        );
    }
    // Review 1, L6 (D3) — a device never keeps an external session: a row
    // marked external (requested while the device held a window) is refused
    // whatever the gate says, and ended at the number read.
    if row.external {
        info!(%agent, session = %session_id, "rc session claim names an external session, which a device never keeps — refused");
        return refuse(
            state,
            ctx,
            session_id,
            EndReason::AgentDisconnect,
            None,
            Some(RowEnd::fenced(seq)),
        );
    }
    let (max_limit, org_session_cap) = match crate::controller::resume_gate(
        state,
        row.controller_user_id,
        ctx.tenant_id,
        agent,
        row.permissions,
    )
    .await
    {
        ResumeGate::Allow {
            max_duration,
            org_session_cap,
        } => (max_duration, org_session_cap),
        ResumeGate::Deny(why) => {
            info!(%agent, session = %session_id, %why, "rc session claim: the controller may no longer control the device — refused");
            let end = RowEnd::fenced(seq);
            return refuse(
                state,
                ctx,
                session_id,
                EndReason::AdminTerminated,
                None,
                Some(end),
            );
        }
        // P1b-2 (P1b-1's review, H1) — a read failed, so nothing was
        // decided: not resumed, and no verdict written. The viewer's redial
        // runs the whole gate again, consent included.
        //
        // Review 2, N4 — but the device is told to close the session, so it
        // is over, and its row ends with it rather than reading live while
        // the device stays connected: `agent_disconnect` at the row's own
        // last clock, marked inferred (no one decided it), fenced at the
        // number read. Only the device's newest connection writes it: an
        // older connection's claim must not end the session the newest one
        // may be resuming.
        ResumeGate::Unknown(why) => {
            let end = if newest_connection(state, ctx, session_id).await {
                warn!(%agent, session = %session_id, %why, "rc session claim: the gate could not be run — refused, and the row ended as inferred");
                let at = inferred_end(&row);
                note_registration_end(state, ctx, session_id, Some(at));
                Some(RowEnd::inferred(seq, at, EndSource::Registration))
            } else {
                warn!(%agent, session = %session_id, %why, "rc session claim: the gate could not be run on an older connection's claim — refused, the row left to the newest");
                None
            };
            return refuse(
                state,
                ctx,
                session_id,
                EndReason::AgentDisconnect,
                None,
                end,
            );
        }
    };
    // FR-101 — the org's maximum length runs from when the session went
    // live, never from the resume.
    let started_at = row.started_at.unwrap_or(row.created_at);
    let max_duration = match max_limit {
        None => None,
        Some(limit) => {
            let lived_ms = now
                .timestamp_millis()
                .saturating_sub(started_at.timestamp_millis());
            let lived = Duration::from_millis(u64::try_from(lived_ms).unwrap_or(0));
            match limit.checked_sub(lived) {
                Some(left) if !left.is_zero() => Some((left, limit)),
                _ => {
                    let end = RowEnd::fenced(seq);
                    return refuse(
                        state,
                        ctx,
                        session_id,
                        EndReason::IdleTimeout,
                        Some("max_duration"),
                        Some(end),
                    );
                }
            }
        }
    };

    // The commit: at the number read, still live, its window still open; one
    // that matched nothing is decided from the row read again. Nothing before
    // it touches the org's slot (PR C's deferred race): a claim takes the slot
    // only once its commit has won, so one that loses never renews the
    // winner's lease or writes its own pod into it.
    let Some(committed) = commit(state, ctx, session_id, seq, now).await else {
        return;
    };
    let next = committed + 1;

    // FR-115 — the org's slot, taken again under the session's own id now
    // that the commit has won: its own lease when it outlived the gap (the
    // detach kept it), a new one when the org has room. Taken BEFORE the hub
    // rebuilds anything (PR D's review, MEDIUM 2), so the lease enters the
    // hub with the session, and a drop of the device's connection from then
    // on keeps it with the session rather than finding none. When another
    // session took the slot during the gap, the claim is refused here,
    // fenced at the number committed, before any copy is rebuilt.
    let slot = match reclaim_slot(state, &row, session_id, org_session_cap).await {
        Ok(slot) => slot,
        Err(()) => {
            info!(%agent, session = %session_id, attach_seq = next, "rc session claim: the org's slots are taken — the resumed session ends");
            if !state.fleet.rc_hub.refuse_resumed(
                agent,
                &ctx.tx,
                session_id,
                next,
                EndReason::AgentDisconnect,
            ) {
                // The connection is gone, so nobody hears the refusal and
                // nothing ends: the detach is written back, as below, and the
                // server decides again at the device's next claim, whose own
                // deadline for the peer it kept bounds any repeat.
                write_back(state, ctx, session_id, next).await;
            }
            return;
        }
    };

    let built = state.fleet.rc_hub.resume_claimed(
        agent,
        &ctx.tx,
        ResumedSession {
            session_id,
            tenant_id: ctx.tenant_id,
            controller_user_id: row.controller_user_id,
            permissions: row.permissions,
            created_at: row.created_at,
            started_at,
            attach_seq: next,
            max_duration,
            external: row.external,
            slot: slot.clone(),
            // P1b-2 — how long the rebuilt session waits for its viewer.
            resume_secs: ctx.resume.window_secs,
        },
    );
    // No longer pending: the hub holds the lease with the session, or the
    // detach written back below keeps it.
    if let Some(lease) = &slot {
        crate::slots::settle(lease);
    }
    if built == Resumed::NotPending {
        write_back(state, ctx, session_id, next).await;
        return;
    }

    // An end wins over a resume: one that landed after the commit is in the
    // row now, and one after this read reaches the hub by its control event.
    match state
        .remote_sessions
        .find_in_tenant(ctx.tenant_id, session_id)
        .await
    {
        Ok(r) if r.ended_at.is_some() => {
            let reason = r.end_reason.unwrap_or(EndReason::AgentDisconnect);
            info!(%agent, session = %session_id, ?reason, "rc session claim: an end landed before the resume — ended");
            // The rebuilt copy's lease goes with it. PR D's review, LOW 6 —
            // and the lease goes back by the session's id too, for one the
            // hub never held (a claim that fell back on a Redis error while
            // the detach's kept lease lived on): the row is ended, so nobody
            // holds it.
            state.fleet.rc_hub.drop_resumed(session_id, reason);
            crate::slots::release_ended(state, ctx.tenant_id, session_id).await;
            return;
        }
        Ok(_) => {}
        Err(e) => {
            debug!(%agent, session = %session_id, %e, "rc session claim: the second read failed; the resume stands");
        }
    }
    state
        .fleet
        .rc_hub
        .confirm_resumed(agent, &ctx.tx, session_id, next);
}

/// Review 1, L2 — a claim committed, and its connection was gone before the
/// hub rebuilt the session or heard its refusal: the commit cleared the row's
/// deadline and no pod holds the session, so the detach is written back,
/// fenced at the number committed (`attach_seq`), and its slot kept to match.
/// The deadline is a fresh window from now. The device never heard the
/// resume, so it still holds the session as kept, to the deadline it set at
/// its first drop: that deadline, which may come first, bounds when it claims
/// again, and a server that waits longer only tells the viewer `detached`
/// and keeps the slot that much longer. Whichever connection of the device
/// claims it next resumes it at that number, and the sweep ends it if none
/// does. A write a newer claim's commit overtook lands nowhere.
async fn write_back(state: &RemoteState, ctx: &AgentCtx, session_id: ObjectId, attach_seq: u32) {
    let resume_by = DateTime::from_millis(
        DateTime::now()
            .timestamp_millis()
            .saturating_add(i64::from(ctx.resume.window_secs).saturating_mul(1000)),
    );
    info!(agent = %ctx.agent_id, session = %session_id, attach_seq, "rc session claim: the connection that made it is gone after its commit — the detach written back");
    state.fleet.rc_hub.record_detach(
        session_id,
        ctx.agent_id,
        ctx.tenant_id,
        attach_seq,
        resume_by,
    );
    crate::slots::keep(state, ctx.tenant_id, session_id, resume_by).await;
}

/// How long the claim waits on the device's presence: as the rejoin's relay
/// waits on it. Past this, the presence counts as unreadable.
const PRESENCE_READ_BUDGET: Duration = Duration::from_millis(250);

/// The claim's commit (spec §4.4, "Fencing"), at the number read (`seq`,
/// `now`). `Some(n)`: committed at `n`, and the session resumes at `n + 1`.
/// `None`: refused, and answered.
///
/// A commit that matched nothing (or failed) is decided from the row read
/// again. Before P1b-1's review it was always refused with no write, and its
/// slot given back by the session's id (M4, L1; review 2, N4). The claim
/// holds no slot of its own here: it takes the slot only once its commit has
/// won (PR C's deferred race), so a claim that loses leaves the lease alone,
/// whoever holds it:
///
/// | The row read again | Answer | Slot |
/// |---|---|---|
/// | cannot be read | `agent_disconnect`, nothing written | left alone |
/// | ended | its own reason, nothing written | given back by the session's id: nobody holds it |
/// | this is not the device's newest connection | `agent_disconnect`, nothing written | left alone: the newest may hold it |
/// | live, names the device, inside any `resume_by`, not yet tried again | committed once more, at the row's number | taken after the commit |
/// | anything else | `agent_disconnect`, the row ended as inferred, fenced at the number last tried | given back by the session's id when that end lands |
///
/// The second try is the case M4 found: an older connection's claim of the
/// same device read the row first and committed first, then found its
/// connection gone, and the row waits at its number for whichever connection
/// claims it next. Refused, the live connection closed a session nobody
/// ended. Only the newest connection tries again ([`newest_connection`]),
/// and only once: an older one could take the fencing number from the live
/// one. The end in the last row is fenced at the number last TRIED, never
/// the number read again, so it lands nowhere if another claim resumed the
/// session since.
async fn commit(
    state: &RemoteState,
    ctx: &AgentCtx,
    session_id: ObjectId,
    mut seq: u32,
    mut now: DateTime,
) -> Option<u32> {
    let agent = ctx.agent_id;
    let mut retried = false;
    loop {
        match state
            .remote_sessions
            .commit_resume(ctx.tenant_id, agent, session_id, seq, now)
            .await
        {
            Ok(true) => return Some(seq),
            Ok(false) => {}
            Err(e) => {
                warn!(%agent, session = %session_id, %e, "rc session claim: the commit failed; reading the row again");
            }
        }
        let row = match state
            .remote_sessions
            .find_in_tenant(ctx.tenant_id, session_id)
            .await
        {
            Ok(row) => row,
            Err(e) => {
                warn!(%agent, session = %session_id, %e, "rc session claim: the commit missed and the row could not be read again — refused, nothing written");
                refuse(
                    state,
                    ctx,
                    session_id,
                    EndReason::AgentDisconnect,
                    None,
                    None,
                );
                return None;
            }
        };
        if row.ended_at.is_some() || row.phase == SessionPhase::Closed {
            let reason = row.end_reason.unwrap_or(EndReason::AgentDisconnect);
            info!(%agent, session = %session_id, ?reason, "rc session claim: it ended before the commit — refused");
            crate::slots::release_ended(state, ctx.tenant_id, session_id).await;
            refuse(state, ctx, session_id, reason, None, None);
            return None;
        }
        if !newest_connection(state, ctx, session_id).await {
            info!(%agent, session = %session_id, "rc session claim: an older connection of the device lost its commit — refused; the row and its slot are the newest connection's");
            refuse(
                state,
                ctx,
                session_id,
                EndReason::AgentDisconnect,
                None,
                None,
            );
            return None;
        }
        now = DateTime::now();
        let claimable = row.phase == SessionPhase::Active
            && row.agent_id == agent
            && row.resume_by.is_none_or(|by| by > now);
        if claimable && !retried {
            info!(%agent, session = %session_id, lost_at = seq, at = row.attach_seq, "rc session claim: the commit lost to another claim of the device — tried once more");
            seq = row.attach_seq;
            retried = true;
            continue;
        }
        // Nobody resumes it through this claim, and the device is told to
        // close it: its row ends with it, at its own last clock. Written only
        // when it lands (the row is still at the number tried): an end of a
        // session another claim resumed since would be a false entry in the
        // audit, and writes nothing to the row anyway.
        let lands = row.attach_seq == seq;
        if lands {
            crate::slots::release_ended(state, ctx.tenant_id, session_id).await;
        }
        let end = lands.then(|| {
            let at = inferred_end(&row);
            note_registration_end(state, ctx, session_id, Some(at));
            RowEnd::inferred(seq, at, EndSource::Registration)
        });
        info!(%agent, session = %session_id, at = seq, ended = lands, "rc session claim: it can no longer be resumed — refused");
        refuse(
            state,
            ctx,
            session_id,
            EndReason::AgentDisconnect,
            None,
            end,
        );
        return None;
    }
}

/// P1b-1's review, M4 — whether `ctx` is the device's NEWEST connection: its
/// claim of `session_id` is still pending in this pod's hub (no later
/// connection displaced it here, and nothing answered it), and the device's
/// presence names no other pod (a later connection to another pod sets the
/// presence before its hello's claims run, `meshharbor-mod-fleet`'s socket).
/// Only the newest connection may try a lost commit again or end the row it
/// refuses. A presence that cannot be read counts as another pod's: the
/// claim is then refused writing nothing, as before the review.
async fn newest_connection(state: &RemoteState, ctx: &AgentCtx, session_id: ObjectId) -> bool {
    if !state
        .fleet
        .rc_hub
        .claim_pending(ctx.agent_id, &ctx.tx, session_id)
    {
        return false;
    }
    // One pod: no other can hold a connection of the device.
    let Some(redis) = state.redis_pubsub.as_ref() else {
        return true;
    };
    matches!(
        tokio::time::timeout(
            PRESENCE_READ_BUDGET,
            redis.agent_presence_foreign(&ctx.agent_id.to_hex()),
        )
        .await,
        Ok(Ok(None))
    )
}

/// FR-115 — the session's slot taken again under its own id: its own lease,
/// renewed, when it outlived the gap; a new one when the org has room. `Err`
/// when the org is full (another session took the slot during the gap).
/// `None` when slots are off or the org has no cap.
async fn reclaim_slot(
    state: &RemoteState,
    row: &RemoteSession,
    session_id: ObjectId,
    cap: Option<u32>,
) -> Result<Option<Lease>, ()> {
    let Some(cap) = cap else {
        return Ok(None);
    };
    if !crate::slots::enabled(state) {
        return Ok(None);
    }
    match crate::slots::claim_for(
        state,
        SlotScope::Org(row.tenant_id),
        session_id,
        row.controller_user_id,
        row.agent_id,
        cap,
    )
    .await
    {
        SlotDecision::Claimed(lease) => Ok(Some(lease)),
        SlotDecision::Fallback => Ok(None),
        SlotDecision::Full { .. } => Err(()),
    }
}

/// End every live row of the device that an earlier connection left open:
/// created before this registration, not claimed by this hello, not reaped
/// by the hub just now (whose end is real). Each is fenced at the number read
/// and dated by its own last clock.
async fn registration_read(state: &RemoteState, ctx: &AgentCtx) {
    let Some(before) = ctx.resume.registered_at else {
        return;
    };
    let rows = match state
        .remote_sessions
        .open_rows_before(ctx.tenant_id, ctx.agent_id, before, REGISTRATION_READ_LIMIT)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            warn!(agent = %ctx.agent_id, %e, "rc registration read failed; the next registration reads again");
            return;
        }
    };
    for row in rows {
        let Some(session_id) = row.id else {
            continue;
        };
        if ctx.resume.claims.contains(&session_id)
            || ctx.resume.reaped.contains(&session_id)
            || state.fleet.rc_hub.session_snapshot(session_id).is_some()
        {
            continue;
        }
        let at = inferred_end(&row);
        info!(
            agent = %ctx.agent_id,
            session = %session_id,
            ended_at_ms = at.timestamp_millis(),
            "rc session an earlier connection left open — ended at its own last clock"
        );
        note_registration_end(state, ctx, session_id, Some(at));
        state.fleet.rc_hub.record_end(
            session_id,
            ctx.agent_id,
            ctx.tenant_id,
            EndReason::AgentDisconnect,
            None,
            RowEnd::inferred(row.attach_seq, at, EndSource::Registration),
        );
    }
}

/// P1b-2 (AC4, P1b-1's review H2) — the device's own `rc:terminate` for a
/// session no hub here holds, which THIS connection's registration ended
/// without seeing its end: the person at the device pressed Disconnect
/// during the gap, or the session reached its idle limit there, and the
/// device reports it after its hello (it cannot sooner). The device's reason
/// (`host_disconnect`, `idle_timeout` with `limit: idle`, `error`) replaces
/// the inferred `agent_disconnect` on the row, which then reads as an end
/// that was seen: `end_source` cleared, `ended_at` still the row's own last
/// clock, since the frame carries no time (`replace_inferred_end`).
///
/// Review 2, N5 — so does an end inferred BEFORE this connection, which left
/// it no note: the sweep's, once the device had been away past the window,
/// or an earlier connection's registration read's, when the device came back
/// more than once before it could report (`earlier_inferred_end`).
///
/// `false` when it is not such a session, and the hub's dispatch takes the
/// frame as before.
pub async fn device_end(
    state: &RemoteState,
    ctx: &AgentCtx,
    session_id: ObjectId,
    reason: EndReason,
    limit: Option<&str>,
) -> bool {
    let noted = state
        .registration_ends
        .get(&ctx.conn_id)
        .and_then(|ended| ended.get(&session_id).copied());
    // As the hub takes an agent's end: the reason as sent, and a limit only
    // where the device may name one.
    let limit = meshharbor_mod_fleet::hub::device_end_limit(Role::Agent, reason, limit);
    let Some(inferred_at) = noted else {
        return earlier_inferred_end(state, ctx, session_id, reason, limit).await;
    };
    match state
        .remote_sessions
        .replace_inferred_end(
            ctx.tenant_id,
            ctx.agent_id,
            session_id,
            reason,
            inferred_at,
            DateTime::now(),
        )
        .await
    {
        Ok(true) => {
            info!(
                agent = %ctx.agent_id,
                session = %session_id,
                ?reason,
                "rc session ended at the device during the gap: its own reason replaces the inferred one"
            );
            state.fleet.rc_hub.record_end(
                session_id,
                ctx.agent_id,
                ctx.tenant_id,
                reason,
                limit,
                RowEnd::written(inferred_at),
            );
        }
        Ok(false) => {
            debug!(agent = %ctx.agent_id, session = %session_id, "rc session the device ended: its row was ended otherwise meanwhile — left as it is");
        }
        Err(e) => {
            warn!(agent = %ctx.agent_id, session = %session_id, %e, "rc session the device ended: its row could not be written");
        }
    }
    true
}

/// Review 2, N5 — the device's own end of a session of its own whose end was
/// inferred before this connection (`RemoteSessionDao::replace_earlier_inferred_end`):
/// its reason replaces the inferred `agent_disconnect`, `end_source` is
/// cleared, and `ended_at` stays the row's own last clock, which dates the
/// audit's trail. `false` when no such row matched (a seen end, another
/// device's row, the one-time close's): the hub's dispatch takes the frame.
async fn earlier_inferred_end(
    state: &RemoteState,
    ctx: &AgentCtx,
    session_id: ObjectId,
    reason: EndReason,
    limit: Option<&'static str>,
) -> bool {
    match state
        .remote_sessions
        .replace_earlier_inferred_end(ctx.tenant_id, ctx.agent_id, session_id, reason)
        .await
    {
        Ok(Some(ended_at)) => {
            info!(
                agent = %ctx.agent_id,
                session = %session_id,
                ?reason,
                "rc session ended at the device during an earlier gap: its own reason replaces the inferred one"
            );
            state.fleet.rc_hub.record_end(
                session_id,
                ctx.agent_id,
                ctx.tenant_id,
                reason,
                limit,
                RowEnd::written(Some(ended_at)),
            );
            true
        }
        Ok(None) => false,
        Err(e) => {
            warn!(agent = %ctx.agent_id, session = %session_id, %e, "rc session the device ended: an earlier inferred end could not be replaced");
            false
        }
    }
}

/// P1b-2 — the connection closed: what its registration ended is no longer
/// its to replace.
pub fn forget_connection(state: &RemoteState, ctx: &AgentCtx) {
    state.registration_ends.remove(&ctx.conn_id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_remote_control::models::SessionStats;
    use meshharbor_remote_control::permissions::Permissions;

    fn row(
        created: i64,
        started: Option<i64>,
        stats: Option<i64>,
        detached: Option<i64>,
    ) -> RemoteSession {
        let at = DateTime::from_millis;
        RemoteSession {
            id: Some(ObjectId::new()),
            agent_id: ObjectId::new(),
            tenant_id: ObjectId::new(),
            controller_user_id: ObjectId::new(),
            watchers: Vec::new(),
            permissions: Permissions::VIEW,
            phase: SessionPhase::Active,
            created_at: at(created),
            started_at: started.map(at),
            ended_at: None,
            end_reason: None,
            recording_url: None,
            stats: SessionStats::default(),
            carrier: None,
            attach_seq: 0,
            detached_at: detached.map(at),
            resume_by: None,
            stats_at: stats.map(at),
            end_source: None,
            external: false,
        }
    }

    /// The spec's order: `detached_at`, else `stats_at`, else `started_at`,
    /// and `created_at` for a row that never went live. Never later than the
    /// row's own last clock.
    #[test]
    fn an_inferred_end_is_the_rows_own_last_clock() {
        let at = DateTime::from_millis;
        assert_eq!(inferred_end(&row(1, Some(2), Some(3), Some(4))), at(4));
        assert_eq!(inferred_end(&row(1, Some(2), Some(3), None)), at(3));
        assert_eq!(inferred_end(&row(1, Some(2), None, None)), at(2));
        assert_eq!(inferred_end(&row(1, None, None, None)), at(1));
    }
}
