// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-130 — the hub's half of a remote session that outlives its device's
//! control socket (`docs/fr/FR-130-the-session-outlives-its-control-socket.md`
//! §4.4). The hub keeps nothing across a gap: the session's row is its state
//! between pods, and what is here is the in-memory side of each step.
//!
//! * **The detach** ([`Hub::detach_agent_sessions`]): a connection that was
//!   announced a window loses its socket. Each live session its viewer may
//!   hold (told `resume_secs`, not external) leaves this hub without ending:
//!   its row is marked `detached_at` and `resume_by`, fenced at the number
//!   the hub held; its FR-115 slot is kept; its viewer is told
//!   `rc:session.detached`. A session not yet live, an external one (D3), and
//!   one that began before its device was announced a window (its viewer
//!   was never told it may hold it, so it would never rejoin) end as they
//!   always have.
//! * **The claim's bookkeeping**: registration holds a place in the device's
//!   capacity for each session the hello claims back ([`Registration`]). The
//!   module that owns remote sessions decides each claim from the row and the
//!   gate, and answers it here: it rebuilds the session
//!   ([`Hub::resume_claimed`]) and then confirms it ([`Hub::confirm_resumed`])
//!   or, when an end won the race, drops it ([`Hub::drop_resumed`]); or it
//!   refuses it ([`Hub::refuse_claim`]), after its commit too when another
//!   session took the org's slot during the gap ([`Hub::refuse_resumed`]).
//!   Whatever is still unanswered once the hello's lifecycles have run is
//!   refused by the socket ([`Hub::refuse_unanswered_claims`]).
//! * **An end for a session no hub holds** ([`Hub::record_end`]): the claim's
//!   refusals and the registration read write the row through it.
//!
//! The hub stays DB-agnostic: every write here goes through the audit sink,
//! whose projection applies the fencing (`meshharbor_remote_control::audit`).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use bson::DateTime;
use bson::oid::ObjectId;
use meshharbor_core::cluster::session_slots::{Lease, SLOT_KEEP_PAST_RESUME_MS};
use meshharbor_remote_control::models::{AuditKind, EndReason, EndSource};
use meshharbor_remote_control::permissions::Permissions;
use meshharbor_remote_control::session::{ClientTx, LiveSession};
use meshharbor_remote_control::signaling::ServerMsg;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::{Hub, ptr_eq};

/// The most sessions one hello may claim, whatever capacity the device
/// advertises: each claim costs a few reads of its row and the gate.
pub(super) const MAX_CLAIMS: usize = 16;

/// How many ids of a hello's `kept_sessions` are looked at at all, each
/// answered: a device never keeps more than its capacity, so past this a
/// hello is not a device's. Under half the connection's channel, so the
/// answers never crowd out what follows them.
const MAX_KEPT_READ: usize = 32;

/// What a hello said about resuming, as the agent socket read it.
#[derive(Debug, Clone, Default)]
pub struct ResumeHello {
    /// The device advertises `rc-resume` (equality-matched).
    pub advertised: bool,
    /// The window this connection is announced, in seconds: `Some` only for a
    /// device that advertises the verb and is in the resume scope while
    /// `rc.session_resume_secs` is above 0.
    pub window: Option<u32>,
    /// The sessions the hello claims back (`kept_sessions`).
    pub kept: Vec<ObjectId>,
}

/// What [`Hub::register_agent_resuming`] registered.
pub struct Registration {
    /// As [`Hub::register_agent`] answers them.
    pub tx: ClientTx,
    pub cancel: Arc<tokio::sync::Notify>,
    pub rx: mpsc::Receiver<ServerMsg>,
    /// The claims the hub holds a place for, in the hello's order, each once.
    pub claims: Vec<ObjectId>,
    /// The claims refused at once, each owed `rc:terminate`: no window was
    /// announced, or the hello claimed more than the device's capacity.
    pub refused: Vec<ObjectId>,
    /// The sessions the hub held for an earlier connection of the device and
    /// ended at this registration (its in-memory reap).
    pub reaped: Vec<ObjectId>,
    /// The hub's clock at the registration.
    pub registered_at: DateTime,
}

/// A session a claim committed, as the hub rebuilds it: from its row and the
/// gate the claim ran again.
#[derive(Debug, Clone)]
pub struct ResumedSession {
    pub session_id: ObjectId,
    pub tenant_id: ObjectId,
    pub controller_user_id: ObjectId,
    pub permissions: Permissions,
    pub created_at: DateTime,
    pub started_at: DateTime,
    /// The fencing number the claim committed.
    pub attach_seq: u32,
    /// What is left of the org's maximum length, counted from `started_at`,
    /// and the limit itself; `None` = no limit.
    pub max_duration: Option<(Duration, Duration)>,
    /// Review 1, L6 — the row's `external` marker, kept on the rebuilt
    /// session so an FR-52 revocation still finds it. Never true behind D3
    /// today: the claim refuses a row marked external.
    pub external: bool,
    /// The FR-115 lease the claim took again under the session's own id,
    /// once its commit had won. It enters this hub with the session (PR D's
    /// review, MEDIUM 2), so whatever takes the session out of the hub finds
    /// it there: a detach keeps it, an end gives it back.
    pub slot: Option<Lease>,
    /// The window announced to the connection that claimed it, in seconds:
    /// how long the rebuilt session waits for its viewer to rejoin (P1b-2).
    pub resume_secs: u32,
}

/// What [`Hub::resume_claimed`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resumed {
    /// Built from the row: no pod held it.
    Rebuilt,
    /// This hub still held it for the device's earlier connection (a socket a
    /// middlebox kept half-open): it keeps its controller, at the new number.
    Reattached,
    /// The claim is no longer this connection's to answer: the connection
    /// was displaced or closed while the claim was decided.
    NotPending,
}

/// How an end is written to the session's row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EndWrite {
    /// An end someone asked for: the write every end made before FR-130, at
    /// any fencing number.
    Asked,
    /// An end the hub decided on its own: fenced at the number it holds.
    Own,
    /// No write: the row already holds the end this one follows.
    Nothing,
}

/// How the row of a session no hub holds is ended ([`Hub::record_end`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowEnd {
    /// `Some(n)`: an end the hub decided on its own, landing only while the
    /// row is open and still at `n`. `None`: an end someone asked for, at any
    /// number.
    pub attach_seq: Option<u32>,
    /// An end nobody saw: the row's own last clock, and who inferred it.
    pub inferred: Option<(DateTime, EndSource)>,
    /// P1b-2 — the caller already wrote the row itself, with a condition the
    /// audit's projection does not know (an end someone asked for, of a
    /// session no hub held: Active and naming the right person), and awaited
    /// it before its control event. The event is kept as the audit's trail
    /// and projects nothing.
    pub written: bool,
    /// P1b-2 — for a written end, when the session ended, when that is not
    /// when the event is recorded (a device's own end reported after its
    /// hello keeps the time the row was dated by).
    pub ended_at: Option<DateTime>,
}

impl RowEnd {
    /// An end someone asked for, at any number, projected onto the row as
    /// every end was before FR-130.
    pub fn asked() -> Self {
        Self {
            attach_seq: None,
            inferred: None,
            written: false,
            ended_at: None,
        }
    }

    /// P1b-2 — an end someone asked for whose row the caller has written
    /// itself (`RemoteSessionDao::end_unheld`, `replace_inferred_end`): the
    /// audit's trail only, dated `ended_at` when that is not now.
    pub fn written(ended_at: Option<DateTime>) -> Self {
        Self {
            attach_seq: None,
            inferred: None,
            written: true,
            ended_at,
        }
    }

    /// An end decided now, at the number `seq` the decider read.
    pub fn fenced(seq: u32) -> Self {
        Self {
            attach_seq: Some(seq),
            inferred: None,
            written: false,
            ended_at: None,
        }
    }

    /// An end nobody saw, at the number read, dated `at` (the row's own last
    /// clock) and marked as `source`'s inference.
    pub fn inferred(seq: u32, at: DateTime, source: EndSource) -> Self {
        Self {
            attach_seq: Some(seq),
            inferred: Some((at, source)),
            written: false,
            ended_at: None,
        }
    }

    /// P1b-2 — the same end, whose row the caller has already written itself
    /// with a condition the projection does not know (the sweep's `resume_by`,
    /// the dead-row close's own checks): the audit keeps it as the trail.
    pub fn already_written(self) -> Self {
        Self {
            written: true,
            ..self
        }
    }
}

/// Split a hello's claims into the ones the hub holds a place for and the
/// ones it refuses at once. With no window every claim is refused: the server
/// keeps nothing it did not announce. Otherwise each id once, in the hello's
/// order, up to the device's capacity (and [`MAX_CLAIMS`]); the rest are
/// refused.
pub(super) fn sort_claims(
    window: Option<u32>,
    kept: Vec<ObjectId>,
    max_sessions: u8,
) -> (Vec<ObjectId>, Vec<ObjectId>) {
    let mut seen = HashSet::new();
    let mut unique: Vec<ObjectId> = kept
        .into_iter()
        .take(MAX_KEPT_READ)
        .filter(|sid| seen.insert(*sid))
        .collect();
    if window.is_none() {
        return (Vec::new(), unique);
    }
    let room = usize::from(max_sessions.max(1)).min(MAX_CLAIMS);
    let refused = if unique.len() > room {
        unique.split_off(room)
    } else {
        Vec::new()
    };
    (unique, refused)
}

/// The reason `rc:file.child.revoke` carries for a session a device's claim
/// rebuilt: its file child transports did not come back with it.
pub(super) const FILE_CHILDREN_REVOKED_AT_RESUME: &str = "session_resumed";

impl Hub {
    /// FR-130 — the drop of a connection that was announced a window. Each
    /// live session of the device its viewer may hold leaves this hub without
    /// ending (the device keeps its peer), until `resume_by` = now plus the
    /// window; a session not yet live, and an external one (D3), end as they
    /// always have.
    ///
    /// Review 2, N3 — so does a session whose viewer was never told
    /// `resume_secs`: it began before its device was announced a window (the
    /// device entered the scope mid-session). Its page ignores
    /// `rc:session.detached` and never rejoins, so a session kept for it
    /// would wait a whole window for nobody and then end anyway; ended now,
    /// the page hears `agent_disconnect` and redials at once, as before
    /// FR-130. The predicate is the hold's own ([`super::hold::held_for_viewer`]).
    pub(super) fn detach_agent_sessions(&self, agent_id: ObjectId, window_secs: u32) {
        // Collected first: the map is written below.
        let mine: Vec<(ObjectId, bool)> = self
            .inner
            .sessions
            .iter()
            .filter_map(|e| {
                let s = e.value().lock();
                if s.agent_id == agent_id {
                    Some((*e.key(), super::hold::held_for_viewer(&s)))
                } else {
                    None
                }
            })
            .collect();
        if mine.is_empty() {
            return;
        }
        let resume_by = DateTime::from_millis(
            DateTime::now()
                .timestamp_millis()
                .saturating_add(i64::from(window_secs) * 1000),
        );
        for (session_id, live) in mine {
            if live {
                self.detach(session_id, resume_by);
            } else {
                let _ = self.end_own(session_id, EndReason::AgentDisconnect, None);
            }
        }
    }

    /// One live session out of this hub, kept: its row is marked detached
    /// (fenced at the number held), its viewer told, and its slot left held.
    fn detach(&self, session_id: ObjectId, resume_by: DateTime) {
        let Some((_, arc)) = self.inner.sessions.remove(&session_id) else {
            return;
        };
        // FR-115 — the slot stays the session's: only an end gives one back.
        // Nobody renews it from here. Review 1, L5 — it is kept once, in
        // Redis, until `resume_by` plus 10 s, so a window longer than what
        // the lease had left (up to 120 s against 60-90 s) keeps it, and so
        // does the death of this pod. A claim takes it again under the
        // session's own id once its commit has won; a session nobody claims
        // gives it back 10 s after its deadline.
        if let Some((_, lease)) = self.inner.slotted.remove(&session_id) {
            self.keep_slot(lease, resume_by);
        }
        let (agent_id, tenant_id, attach_seq, controller_tx) = {
            let s = arc.lock();
            (
                s.agent_id,
                s.tenant_id,
                s.attach_seq,
                s.controller_tx.clone(),
            )
        };
        let resume_by_ms = resume_by.timestamp_millis();
        if let Some(tx) = controller_tx {
            let _ = tx.try_send(ServerMsg::SessionDetached {
                session_id,
                resume_by: u64::try_from(resume_by_ms).unwrap_or(0),
            });
        }
        self.audit(
            session_id,
            agent_id,
            tenant_id,
            AuditKind::SessionDetached {
                attach_seq,
                resume_by,
            },
        );
        info!(
            session = %session_id.to_hex(),
            %agent_id,
            attach_seq,
            resume_by_ms,
            "rc session detached: the device's control socket dropped, and it may claim the session back until resume_by"
        );
    }

    /// FR-130 — announce `secs` to the device's connection on this pod, and
    /// remember it on the entry; 0 withdraws it, so the connection's loss
    /// ends its sessions again. `false` when this pod does not hold the
    /// device's socket, or the connection does not advertise `rc-resume`
    /// (it could not read the frame). The socket announces at registration;
    /// P1b-2's re-announce on a scope change calls this on every pod.
    pub fn announce_resume_window(&self, agent_id: ObjectId, secs: u32) -> bool {
        let Some(mut a) = self.inner.agents.get_mut(&agent_id) else {
            return false;
        };
        if !a.advertises_resume {
            return false;
        }
        a.resume_window = (secs > 0).then_some(secs);
        let _ = a.tx.try_send(ServerMsg::AgentResumeWindow { secs });
        true
    }

    /// FR-130 P1b-2 — every device connection on this pod that advertises
    /// `rc-resume`: the device, its org and the window it holds. What the
    /// re-announce on a scope change walks.
    pub fn resume_connections(&self) -> Vec<(ObjectId, ObjectId, Option<u32>)> {
        self.inner
            .agents
            .iter()
            .filter(|a| a.advertises_resume)
            .map(|a| (a.agent_id, a.tenant_id, a.resume_window))
            .collect()
    }

    /// FR-130 — the window announced to the device's connection on this pod.
    pub fn agent_resume_window(&self, agent_id: ObjectId) -> Option<u32> {
        self.inner
            .agents
            .get(&agent_id)
            .and_then(|a| a.resume_window)
    }

    /// The session, when this hub holds it for `agent_id`.
    fn held_for(
        &self,
        session_id: ObjectId,
        agent_id: ObjectId,
    ) -> Option<Arc<Mutex<LiveSession>>> {
        let arc = self
            .inner
            .sessions
            .get(&session_id)
            .map(|e| e.value().clone())?;
        let mine = arc.lock().agent_id == agent_id;
        mine.then_some(arc)
    }

    /// Take `session_id` out of `conn`'s unanswered claims; `None` when it is
    /// not one (the connection was displaced or closed, or it was answered).
    /// `count` moves its place into the device's count of live sessions.
    fn take_claim(
        &self,
        agent_id: ObjectId,
        conn: &ClientTx,
        session_id: ObjectId,
        count: bool,
    ) -> Option<ObjectId> {
        let mut a = self.inner.agents.get_mut(&agent_id)?;
        if !ptr_eq(&a.tx, conn) {
            return None;
        }
        let pos = a.pending_claims.iter().position(|s| *s == session_id)?;
        a.pending_claims.remove(pos);
        if count {
            a.active_sessions = a.active_sessions.saturating_add(1);
        }
        Some(a.tenant_id)
    }

    /// FR-130 (P1b-1's review, M4) — `session_id` is still one of `conn`'s
    /// unanswered claims: this hub holds `conn` as the device's connection
    /// (no later one displaced it) and nothing has answered the claim. Half
    /// of "this is the device's newest connection"; the module that answers
    /// claims adds the device's presence, which names the pod of its newest
    /// connection.
    pub fn claim_pending(&self, agent_id: ObjectId, conn: &ClientTx, session_id: ObjectId) -> bool {
        self.inner
            .agents
            .get(&agent_id)
            .is_some_and(|a| ptr_eq(&a.tx, conn) && a.pending_claims.contains(&session_id))
    }

    /// FR-115 — hold `lease` for a copy already in the map (a re-attach),
    /// unless the copy left the map meanwhile (P1b-1's review, L13). Whatever
    /// takes a session out of the map (an end, a detach) takes it out BEFORE
    /// its lease, so a lease put in after that would never leave, and this
    /// pod's renewal round would keep the org's slot taken for good. Checked
    /// after the insert: a lease the remover did not find is taken back out
    /// here, and left in Redis as the remover left the session's lease (PR
    /// D's review, MEDIUM 2: a detach keeps it, and a release here would give
    /// away the slot of the session it just kept; an end gave it back).
    fn hold_slot(&self, session_id: ObjectId, lease: Lease) {
        self.inner.slotted.insert(session_id, lease);
        if !self.inner.sessions.contains_key(&session_id) {
            self.inner.slotted.remove(&session_id);
        }
    }

    /// Review 1, L5 — keep a detached session's lease, off the caller's
    /// thread, until `resume_by` plus 10 s: written once, in Redis, so no
    /// pod renews it through the gap. A failed keep leaves the lease to
    /// lapse at its own expiry, as before.
    fn keep_slot(&self, lease: Lease, resume_by: DateTime) {
        let Some(slots) = self.inner.session_slots.get().cloned() else {
            return;
        };
        let until = resume_by
            .timestamp_millis()
            .saturating_add(SLOT_KEEP_PAST_RESUME_MS);
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                if let Err(e) = slots.keep(lease.scope, lease.session, until).await {
                    warn!(
                        session = %lease.session,
                        %e,
                        "session slot: a detached session's lease was not kept; it lapses at its own expiry"
                    );
                }
            });
        }
    }

    /// Review 1, L2 — a claim committed and its connection was gone before
    /// the hub rebuilt the session: the detach is written back, fenced at the
    /// number committed, so the row is not left open with no pod and no
    /// deadline. The claim keeps the slot (`slots::keep`) and answers nothing.
    pub fn record_detach(
        &self,
        session_id: ObjectId,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        attach_seq: u32,
        resume_by: DateTime,
    ) {
        self.audit(
            session_id,
            agent_id,
            tenant_id,
            AuditKind::SessionDetached {
                attach_seq,
                resume_by,
            },
        );
        info!(
            session = %session_id.to_hex(),
            %agent_id,
            attach_seq,
            resume_by_ms = resume_by.timestamp_millis(),
            "rc session detached again: the claim that committed it lost its connection"
        );
    }

    /// `refuse_claim`'s race — a claim whose commit won, refused before this
    /// hub rebuilt anything because another session took the org's slot
    /// during the gap (PR D's review, MEDIUM 2). As [`Self::refuse_claim`],
    /// with every end fenced at `attach_seq`, the number the commit wrote:
    /// the device is told `reason` and the row ends at that number. A copy
    /// this hub still held for the device's earlier connection is below it
    /// (the commit superseded it), so it is moved to `attach_seq`, as a
    /// re-attach would have moved it, and ends there. A copy at that number
    /// or later is another claim's, and is left alone (PR D's review, LOW 3:
    /// an end a hub decides is fenced at the number it holds). `false` when
    /// the claim is no longer this connection's to answer: nothing is ended.
    pub fn refuse_resumed(
        &self,
        agent_id: ObjectId,
        conn: &ClientTx,
        session_id: ObjectId,
        attach_seq: u32,
        reason: EndReason,
    ) -> bool {
        let Some(tenant_id) = self.take_claim(agent_id, conn, session_id, false) else {
            return false;
        };
        info!(session = %session_id.to_hex(), %agent_id, attach_seq, ?reason, "rc session claim refused after its commit");
        if let Some(arc) = self.held_for(session_id, agent_id) {
            let held_seq = arc.lock().attach_seq;
            if held_seq >= attach_seq {
                // Only a newer claim can have made it, and it holds the
                // session now: nothing is sent or written for this one.
                warn!(session = %session_id.to_hex(), %agent_id, held_seq, attach_seq, "rc session claim refused after its commit: a copy at its number or later is held here, and left alone");
                return true;
            }
            // Taken out of the map exactly as read: a copy an end removed
            // meanwhile is that end's.
            if let Some((_, arc)) = self
                .inner
                .sessions
                .remove_if(&session_id, |_, v| Arc::ptr_eq(v, &arc))
            {
                arc.lock().attach_seq = attach_seq;
                // Never counted on this connection: counted now, so that its
                // end gives back what it takes.
                if let Some(mut a) = self.inner.agents.get_mut(&agent_id) {
                    a.active_sessions = a.active_sessions.saturating_add(1);
                }
                self.end_removed(session_id, &arc, reason, None, EndWrite::Own);
                return true;
            }
        }
        let _ = conn.try_send(ServerMsg::Terminate {
            session_id,
            reason,
            limit: None,
        });
        self.record_end(
            session_id,
            agent_id,
            tenant_id,
            reason,
            None,
            RowEnd::fenced(attach_seq),
        );
        true
    }

    /// FR-130 — a claim committed: rebuild the session on this hub, counted
    /// in the device's capacity from here (its place moves from the claims),
    /// and its maximum length armed again from `started_at`. The org's slot,
    /// which the caller took again once the commit had won, enters the hub
    /// with the session (`r.slot`; PR D's review, MEDIUM 2): a rebuilt
    /// session's lease is in place before the session is, and a re-attached
    /// copy holds it from here ([`Self::hold_slot`]), so whatever takes the
    /// session out of the hub next finds its lease. Nothing is sent yet: the
    /// caller reads the row once more, and then confirms or drops it, so an
    /// end that landed meanwhile wins.
    pub fn resume_claimed(
        &self,
        agent_id: ObjectId,
        conn: &ClientTx,
        r: ResumedSession,
    ) -> Resumed {
        match self.take_claim(agent_id, conn, r.session_id, true) {
            Some(tenant_id) if tenant_id == r.tenant_id => {}
            Some(_) => {
                // Never: the claim read the row in the device's tenant. Give
                // the place back and answer nothing; the socket refuses it.
                if let Some(mut a) = self.inner.agents.get_mut(&agent_id) {
                    a.active_sessions = a.active_sessions.saturating_sub(1);
                }
                return Resumed::NotPending;
            }
            None => return Resumed::NotPending,
        }
        // P1b-1's review, L13 — the held copy is read only once the claim is
        // taken (and the entry's guard, taken in `take_claim`, dropped: it is
        // never held while a session's lock is). Read first, a copy that ended
        // in between was re-attached outside the map and never rebuilt.
        let held = self.held_for(r.session_id, agent_id);
        let outcome = match held {
            Some(arc) => {
                // Review 2, N8 — a copy held for its viewer (no controller)
                // keeps waiting for it, from here: the wait its viewer's
                // departure armed is void once the number moves, so without a
                // new one a page that never rejoins kept the session, its
                // place and its slot for good.
                let rearm = {
                    let mut s = arc.lock();
                    s.attach_seq = r.attach_seq;
                    if s.controller_tx.is_none() {
                        s.held_until = Some(super::hold::due_in(r.resume_secs));
                        Some(s.controller_gen)
                    } else {
                        None
                    }
                };
                if let Some(turn) = rearm {
                    self.arm_viewer_wait(r.session_id, turn, r.attach_seq, r.resume_secs);
                }
                if let Some(lease) = r.slot {
                    self.hold_slot(r.session_id, lease);
                }
                Resumed::Reattached
            }
            None => {
                let mut live = LiveSession::resumed(
                    r.session_id,
                    agent_id,
                    r.tenant_id,
                    r.controller_user_id,
                    r.permissions,
                    r.created_at,
                    r.started_at,
                    r.attach_seq,
                    // FR-121 — the zones as they stand now, with the viewer
                    // on no mesh node: each public address it may still
                    // trickle is placed on its own, and nothing the zones
                    // forbid passes. The rebuilt session never sends the
                    // route's advice (`LiveSession::resumed`).
                    self.zone_route_for(agent_id, None),
                );
                // P1b-2 — no controller until its viewer rejoins, which it
                // may for the window announced to the connection that
                // claimed it; past that, it ends.
                live.resume_secs = Some(r.resume_secs);
                live.held_until = Some(super::hold::due_in(r.resume_secs));
                live.external = r.external;
                // The session's file child transports: what this hub knew of
                // them (the slots, the policy snapshot, the watch that revokes
                // them) went with the copy the detach let go, while the device
                // kept the transports with the peer. A rebuilt session is born
                // with them revoked and the device's acknowledgement owed:
                // `confirm_resumed` tells the device, which closes them, and
                // the fail-closed deadline every revocation has holds here
                // too. The session's own file channel is untouched.
                live.revoke_file_children_irreversibly();
                // FR-115 — the lease first: from the session's insert on, a
                // detach or an end may take it out of the map, and each takes
                // the lease with it (PR D's review, MEDIUM 2).
                if let Some(lease) = r.slot {
                    self.inner.slotted.insert(r.session_id, lease);
                }
                self.inner
                    .sessions
                    .insert(r.session_id, Arc::new(Mutex::new(live)));
                self.arm_viewer_wait(r.session_id, 0, r.attach_seq, r.resume_secs);
                Resumed::Rebuilt
            }
        };
        if let Some((left, limit)) = r.max_duration {
            self.arm_max_duration(r.session_id, r.attach_seq, left, limit);
        }
        outcome
    }

    /// FR-130 — the resume stands (the row was still open once the session
    /// was rebuilt): tell the device, and the viewer when this hub still had
    /// one, `rc:session.resumed`, and audit it. `false` when the session ended
    /// meanwhile (a kick reached it), whose `rc:terminate` is already sent.
    pub fn confirm_resumed(
        &self,
        agent_id: ObjectId,
        conn: &ClientTx,
        session_id: ObjectId,
        attach_seq: u32,
    ) -> bool {
        let Some(arc) = self.held_for(session_id, agent_id) else {
            return false;
        };
        let (tenant_id, held_seq, controller_tx, children_owed) = {
            let s = arc.lock();
            (
                s.tenant_id,
                s.attach_seq,
                s.controller_tx.clone(),
                s.is_file_child_revoke_pending_ack(),
            )
        };
        if held_seq != attach_seq {
            return false;
        }
        let msg = ServerMsg::SessionResumed { session_id };
        let _ = conn.try_send(msg.clone());
        if let Some(tx) = controller_tx.clone() {
            let _ = tx.try_send(msg);
        }
        // A rebuilt session's file child transports are revoked
        // (`resume_claimed`): the device is told AFTER `rc:session.resumed`,
        // on the same socket, so it has the session attached when it closes
        // them, and a viewer still bound here is told with it. No
        // acknowledgement in time ends the session, as for any revocation.
        if children_owed {
            self.notify_and_arm_file_child_revoke(
                session_id,
                agent_id,
                controller_tx,
                FILE_CHILDREN_REVOKED_AT_RESUME,
            );
        }
        self.audit(
            session_id,
            agent_id,
            tenant_id,
            AuditKind::SessionResumed { attach_seq },
        );
        info!(session = %session_id.to_hex(), %agent_id, attach_seq, "rc session resumed: the device claimed it back");
        true
    }

    /// FR-130 — an end won the race: the row ended after the claim committed
    /// (an end written while no hub held the session). The rebuilt session
    /// leaves this hub, both ends are told `reason`, and nothing more is
    /// written: the row holds that end.
    pub fn drop_resumed(&self, session_id: ObjectId, reason: EndReason) {
        let _ = self.end_session(session_id, reason, None, EndWrite::Nothing);
    }

    /// FR-130 — refuse a claim: its place in the capacity is given back and
    /// the device is told `rc:terminate` with `reason` (and `limit`). When
    /// this hub still held the session for the device's earlier connection,
    /// that copy ends, fenced at the number it holds; otherwise `row`, when
    /// the caller found the row still open, is written as its end. `false`
    /// when the claim is no longer this connection's to answer.
    pub fn refuse_claim(
        &self,
        agent_id: ObjectId,
        conn: &ClientTx,
        session_id: ObjectId,
        reason: EndReason,
        limit: Option<&'static str>,
        row: Option<RowEnd>,
    ) -> bool {
        // PR C's deferred race, L13's twin — the claim is taken first, and
        // the held copy read only then, as `resume_claimed` does. Read
        // before, a copy that ended in between was counted on this
        // connection and never given back.
        let Some(tenant_id) = self.take_claim(agent_id, conn, session_id, false) else {
            return false;
        };
        info!(session = %session_id.to_hex(), %agent_id, ?reason, "rc session claim refused");
        // The copy this hub still holds for the device's earlier connection,
        // taken out of the map exactly as read: one that an end removed
        // meanwhile is that end's, and is neither counted nor ended here.
        let held = self.held_for(session_id, agent_id).and_then(|arc| {
            self.inner
                .sessions
                .remove_if(&session_id, |_, v| Arc::ptr_eq(v, &arc))
                .map(|(_, held)| held)
        });
        if let Some(arc) = held {
            // Never counted on this connection: counted now, so that its end
            // gives back what it takes.
            if let Some(mut a) = self.inner.agents.get_mut(&agent_id) {
                a.active_sessions = a.active_sessions.saturating_add(1);
            }
            self.end_removed(session_id, &arc, reason, limit, EndWrite::Own);
            return true;
        }
        let _ = conn.try_send(ServerMsg::Terminate {
            session_id,
            reason,
            limit: limit.map(str::to_string),
        });
        if let Some(end) = row {
            self.record_end(session_id, agent_id, tenant_id, reason, limit, end);
        }
        true
    }

    /// FR-130 — every claim of `conn` still unanswered once the hello's
    /// lifecycles have run: refused with `agent_disconnect`, and nothing
    /// written (nothing read the row). The module that answers claims may not
    /// be mounted, or may have failed part way. The ids refused.
    pub fn refuse_unanswered_claims(&self, agent_id: ObjectId, conn: &ClientTx) -> Vec<ObjectId> {
        let pending: Vec<ObjectId> = match self.inner.agents.get(&agent_id) {
            Some(a) if ptr_eq(&a.tx, conn) => a.pending_claims.clone(),
            _ => return Vec::new(),
        };
        pending
            .into_iter()
            .filter(|sid| {
                self.refuse_claim(agent_id, conn, *sid, EndReason::AgentDisconnect, None, None)
            })
            .collect()
    }

    /// FR-130 — write an end to the row of a session this hub does not hold,
    /// through the audit sink like every end, so the projection applies the
    /// fencing (`end`). The claim's refusals and the registration read use
    /// it. P1b-2's ends for a session no hub holds (an admin's, the
    /// controller's own, a redial's `replaces` of a session not detached, the
    /// device's own after its hello) write the row themselves and record it
    /// here as [`RowEnd::written`]: the audit's trail, with no projection. So
    /// do the inferred ends that write their row as read (the sweep's, the
    /// dead-row close's and, D5 = A, a redial's `replaces` of a detached
    /// session), as [`RowEnd::already_written`].
    pub fn record_end(
        &self,
        session_id: ObjectId,
        agent_id: ObjectId,
        tenant_id: ObjectId,
        reason: EndReason,
        limit: Option<&'static str>,
        end: RowEnd,
    ) {
        let (ended_at, end_source) = match end.inferred {
            Some((at, source)) => (Some(at), Some(source)),
            None => (end.ended_at, None),
        };
        let event = AuditKind::SessionEnded {
            reason,
            limit: limit.map(str::to_string),
            attach_seq: end.attach_seq,
            ended_at,
            end_source,
        };
        if end.written {
            self.inner
                .audit
                .record_trail(session_id, agent_id, tenant_id, event);
        } else {
            self.audit(session_id, agent_id, tenant_id, event);
        }
    }

    /// FR-101 P4b — end the session at the org's maximum length (`limit`),
    /// `after` from now: armed when the session goes live, and again by a
    /// claim that resumes it, from `started_at`. FR-130 — it fires only while
    /// this hub holds the session at the number it was armed at: a session id
    /// survives a resume, and the resume arms its own.
    pub(super) fn arm_max_duration(
        &self,
        session_id: ObjectId,
        attach_seq: u32,
        after: Duration,
        limit: Duration,
    ) {
        let hub = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(after).await;
            let held_at = hub
                .inner
                .sessions
                .get(&session_id)
                .map(|e| e.value().lock().attach_seq);
            if held_at == Some(attach_seq) {
                info!(
                    session = %session_id.to_hex(),
                    limit_secs = limit.as_secs(),
                    "rc session reached the org's maximum length — ending it"
                );
                let _ = hub.end_own(session_id, EndReason::IdleTimeout, Some("max_duration"));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_remote_control::audit::AuditSink;
    use meshharbor_remote_control::models::{ConsentMode, OsKind, SessionPhase};
    use mongodb::Client;

    async fn hub() -> Hub {
        // As the hub's own tests: Mongo is never contacted unless the sink
        // flushes, and a failed write there is only logged.
        let client = Client::with_uri_str("mongodb://localhost:27017")
            .await
            .expect("mongo for tests");
        let (audit, _h) = AuditSink::spawn(client.database("rc_test"));
        Hub::new(audit, None)
    }

    fn hello(window: Option<u32>, kept: Vec<ObjectId>) -> ResumeHello {
        ResumeHello {
            advertised: true,
            window,
            kept,
        }
    }

    fn register(
        hub: &Hub,
        agent: ObjectId,
        tenant: ObjectId,
        max: u8,
        h: ResumeHello,
    ) -> Registration {
        hub.register_agent_resuming(
            agent,
            tenant,
            ObjectId::new(),
            OsKind::Linux,
            max,
            true,
            false,
            h,
        )
    }

    /// A session requested by `user` and its controller's receiver.
    fn open(hub: &Hub, agent: ObjectId, user: ObjectId) -> (ObjectId, mpsc::Receiver<ServerMsg>) {
        let (tx, rx) = mpsc::channel(32);
        let sid = hub
            .create_session(
                agent,
                user,
                "Viewer".into(),
                tx,
                Permissions::default(),
                Vec::new(),
                None,
                None,
                None,
                false,
                ConsentMode::Prompt,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        (sid, rx)
    }

    async fn live(hub: &Hub, sid: ObjectId) {
        hub.deliver_consent(sid, true, None).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        hub.with_session(sid, |s| s.transition(SessionPhase::Active))
            .unwrap();
    }

    fn drain(rx: &mut mpsc::Receiver<ServerMsg>) -> Vec<ServerMsg> {
        let mut out = Vec::new();
        while let Ok(m) = rx.try_recv() {
            out.push(m);
        }
        out
    }

    fn terminated(msgs: &[ServerMsg], sid: ObjectId) -> Option<EndReason> {
        msgs.iter().find_map(|m| match m {
            ServerMsg::Terminate {
                session_id, reason, ..
            } if *session_id == sid => Some(*reason),
            _ => None,
        })
    }

    /// The org slot lease a claim of `session` took.
    fn lease_of(tenant: ObjectId, session: ObjectId, user: ObjectId, device: ObjectId) -> Lease {
        Lease {
            scope: meshharbor_core::cluster::session_slots::SlotScope::Org(tenant),
            session,
            user,
            device,
        }
    }

    #[test]
    fn claims_are_held_only_under_a_window_once_each_and_up_to_the_capacity() {
        let ids: Vec<ObjectId> = (0..4).map(|_| ObjectId::new()).collect();
        let (held, refused) = sort_claims(None, ids.clone(), 2);
        assert!(held.is_empty(), "no window holds nothing");
        assert_eq!(refused, ids, "and refuses every claim");

        let twice = vec![ids[0], ids[1], ids[0]];
        let (held, refused) = sort_claims(Some(60), twice, 2);
        assert_eq!(held, vec![ids[0], ids[1]], "each once, in order");
        assert!(refused.is_empty(), "a repeat is no claim of its own");

        let (held, refused) = sort_claims(Some(60), ids.clone(), 2);
        assert_eq!(held, ids[..2].to_vec());
        assert_eq!(refused, ids[2..].to_vec(), "past the capacity");

        let many: Vec<ObjectId> = (0..40).map(|_| ObjectId::new()).collect();
        let (held, _) = sort_claims(Some(60), many, u8::MAX);
        assert_eq!(held.len(), MAX_CLAIMS);
    }

    /// The drop of an announced connection keeps its live session (out of
    /// the hub, the viewer told `rc:session.detached`, never `rc:terminate`)
    /// and ends the rest as today: one not yet live, and an external one.
    #[tokio::test]
    async fn an_announced_drop_detaches_the_live_session_and_ends_the_rest() {
        let hub = hub().await;
        let (agent, tenant, user) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let reg = register(&hub, agent, tenant, 4, hello(Some(60), Vec::new()));
        let (live_sid, mut live_rx) = open(&hub, agent, user);
        live(&hub, live_sid).await;
        let (ext_sid, mut ext_rx) = open(&hub, agent, user);
        live(&hub, ext_sid).await;
        hub.with_session(ext_sid, |s| {
            s.external = true;
            Ok(())
        })
        .unwrap();
        let (pending_sid, mut pending_rx) = open(&hub, agent, user);

        assert!(hub.unregister_agent(agent, Some(&reg.tx)));

        assert!(hub.session_snapshot(live_sid).is_none(), "no pod holds it");
        let msgs = drain(&mut live_rx);
        assert_eq!(terminated(&msgs, live_sid), None, "{msgs:?}");
        let told = msgs.iter().find_map(|m| match m {
            ServerMsg::SessionDetached {
                session_id,
                resume_by,
            } if *session_id == live_sid => Some(*resume_by),
            _ => None,
        });
        let now = u64::try_from(DateTime::now().timestamp_millis()).unwrap();
        let by = told.expect("the viewer is told it is kept");
        assert!((now + 59_000..=now + 60_500).contains(&by), "{by} vs {now}");

        assert_eq!(
            terminated(&drain(&mut ext_rx), ext_sid),
            Some(EndReason::AgentDisconnect),
            "D3: an external session ends as today"
        );
        assert_eq!(
            terminated(&drain(&mut pending_rx), pending_sid),
            Some(EndReason::AgentDisconnect),
            "a session not yet live ends as today"
        );
        assert_eq!(hub.live_sessions(), 0);
    }

    /// With no window announced the drop ends every session as it always
    /// has, the live one included.
    #[tokio::test]
    async fn a_drop_with_no_window_ends_the_live_session_as_today() {
        let hub = hub().await;
        let (agent, tenant, user) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let reg = register(&hub, agent, tenant, 2, hello(None, Vec::new()));
        let (sid, mut rx) = open(&hub, agent, user);
        live(&hub, sid).await;
        assert!(hub.unregister_agent(agent, Some(&reg.tx)));
        assert_eq!(
            terminated(&drain(&mut rx), sid),
            Some(EndReason::AgentDisconnect)
        );
    }

    /// A claim holds its place from the registration: a request that would
    /// take it is refused busy until the claim is answered, and a refusal
    /// gives the place back. Unanswered claims are refused at the end.
    #[tokio::test]
    async fn a_claim_holds_its_place_until_it_is_answered() {
        let hub = hub().await;
        let (agent, tenant, user) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let (kept_a, kept_b) = (ObjectId::new(), ObjectId::new());
        let mut reg = register(
            &hub,
            agent,
            tenant,
            2,
            hello(Some(60), vec![kept_a, kept_b]),
        );
        assert_eq!(reg.claims, vec![kept_a, kept_b]);

        let (tx, _rx) = mpsc::channel(8);
        let busy = hub.create_session(
            agent,
            user,
            "Viewer".into(),
            tx,
            Permissions::default(),
            Vec::new(),
            None,
            None,
            None,
            false,
            ConsentMode::Prompt,
            None,
            None,
            None,
            None,
        );
        assert!(
            matches!(
                busy,
                Err(meshharbor_remote_control::error::Error::AgentBusy)
            ),
            "{busy:?}"
        );

        assert!(hub.refuse_claim(
            agent,
            &reg.tx,
            kept_a,
            EndReason::AgentDisconnect,
            None,
            None
        ));
        assert!(
            !hub.refuse_claim(
                agent,
                &reg.tx,
                kept_a,
                EndReason::AgentDisconnect,
                None,
                None
            ),
            "a claim is answered once"
        );
        let (sid, _ctl) = open(&hub, agent, user);
        assert!(hub.session_snapshot(sid).is_some(), "the place came back");

        assert_eq!(hub.refuse_unanswered_claims(agent, &reg.tx), vec![kept_b]);
        let to_agent = drain(&mut reg.rx);
        assert_eq!(
            terminated(&to_agent, kept_a),
            Some(EndReason::AgentDisconnect)
        );
        assert_eq!(
            terminated(&to_agent, kept_b),
            Some(EndReason::AgentDisconnect)
        );
    }

    /// A claim rebuilds the session the hub no longer holds; the resume is
    /// told only once confirmed, and an end that won the race drops it with
    /// the row's reason and gives its place back.
    #[tokio::test]
    async fn a_claim_rebuilds_the_session_and_an_end_that_won_drops_it() {
        let hub = hub().await;
        let (agent, tenant, user) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let (sid, gone) = (ObjectId::new(), ObjectId::new());
        let mut reg = register(&hub, agent, tenant, 2, hello(Some(60), vec![sid, gone]));
        let resumed = |session_id| ResumedSession {
            session_id,
            tenant_id: tenant,
            controller_user_id: user,
            permissions: Permissions::VIEW,
            created_at: DateTime::now(),
            started_at: DateTime::now(),
            attach_seq: 1,
            max_duration: None,
            external: false,
            slot: None,
            resume_secs: 60,
        };
        assert_eq!(
            hub.resume_claimed(agent, &reg.tx, resumed(sid)),
            Resumed::Rebuilt
        );
        assert_eq!(hub.session_snapshot(sid), Some((tenant, user)));
        assert!(
            !drain(&mut reg.rx)
                .iter()
                .any(|m| matches!(m, ServerMsg::SessionResumed { .. })),
            "nothing is told before the row is read again"
        );
        assert!(hub.confirm_resumed(agent, &reg.tx, sid, 1));
        assert!(
            drain(&mut reg.rx).iter().any(
                |m| matches!(m, ServerMsg::SessionResumed { session_id } if *session_id == sid)
            )
        );
        assert_eq!(
            hub.resume_claimed(agent, &reg.tx, resumed(sid)),
            Resumed::NotPending,
            "a claim is answered once"
        );

        assert_eq!(
            hub.resume_claimed(agent, &reg.tx, resumed(gone)),
            Resumed::Rebuilt
        );
        hub.drop_resumed(gone, EndReason::AdminTerminated);
        assert!(hub.session_snapshot(gone).is_none());
        assert_eq!(
            terminated(&drain(&mut reg.rx), gone),
            Some(EndReason::AdminTerminated)
        );
        assert!(!hub.confirm_resumed(agent, &reg.tx, gone, 1));
        // One live session counted (sid), so one place is left.
        let (other, _ctl) = open(&hub, agent, user);
        assert!(hub.session_snapshot(other).is_some());
    }

    /// A rebuilt session has no file child transports. What the hub knew of
    /// them went with the copy the detach let go, and the device kept the
    /// transports with the peer, so the rebuilt session is born with them
    /// revoked: the device is told `rc:file.child.revoke` right AFTER
    /// `rc:session.resumed` (it has the session attached by then), its
    /// acknowledgement settles it, and its viewer hears it at the rejoin.
    /// Under a configured zone policy the rebuilt session keeps the strict
    /// zone route (`ZoneRoute::Direct { mesh_fallback: false }`, never falling
    /// open to `ZoneRoute::Open`) and never sends the route's advice.
    #[tokio::test]
    async fn a_rebuilt_session_has_its_file_children_revoked_and_no_open_route() {
        use super::super::{AgentZoneIcePolicy, ZoneRoute, ZoneRouteInfo};
        let hub = hub().await;
        let (agent, tenant, user) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let sid = ObjectId::new();
        let mut reg = register(&hub, agent, tenant, 2, hello(Some(60), vec![sid]));
        hub.set_agent_zone_ice_policy(
            agent,
            AgentZoneIcePolicy {
                policy_revision: 1,
                strict: true,
                allowed_countries: std::collections::HashSet::from(["DE".to_string()]),
                zone: Some("zone-a".to_string()),
                zones: Arc::new(vec![ZoneRouteInfo {
                    id: "zone-a".to_string(),
                    auto_countries: vec!["DE".to_string()],
                    is_default: false,
                    router_only: true,
                }]),
            },
        );
        let r = ResumedSession {
            session_id: sid,
            tenant_id: tenant,
            controller_user_id: user,
            permissions: Permissions::VIEW | Permissions::FILES,
            created_at: DateTime::now(),
            started_at: DateTime::now(),
            attach_seq: 1,
            max_duration: None,
            external: false,
            slot: None,
            resume_secs: 60,
        };
        assert_eq!(hub.resume_claimed(agent, &reg.tx, r), Resumed::Rebuilt);
        let (revoked, owed, advised, route) = hub
            .with_session(sid, |s| {
                Ok((
                    s.is_file_children_revoked(),
                    s.is_file_child_revoke_pending_ack(),
                    s.zone_advised,
                    s.zone_route,
                ))
            })
            .unwrap();
        assert!(revoked && owed, "born revoked, the device's word owed");
        assert!(advised, "a live session is never sent the route's advice");
        assert_eq!(
            route,
            ZoneRoute::Direct {
                mesh_fallback: false
            },
            "under a strict zone policy a rebuilt session enforces the zone route and never falls open"
        );
        assert_eq!(
            route,
            hub.zone_route_for(agent, None),
            "matches the zones as they stand, the viewer on no mesh node"
        );
        assert!(
            hub.with_session(sid, |s| s.reserve_file_child("t1"))
                .is_err(),
            "no child can be reserved on it"
        );

        assert!(hub.confirm_resumed(agent, &reg.tx, sid, 1));
        let told = drain(&mut reg.rx);
        let resumed_at = told.iter().position(
            |m| matches!(m, ServerMsg::SessionResumed { session_id } if *session_id == sid),
        );
        let revoke_at = told.iter().position(|m| {
            matches!(m, ServerMsg::FileChildRevoke { session_id, reason }
                if *session_id == sid && reason == FILE_CHILDREN_REVOKED_AT_RESUME)
        });
        assert!(
            matches!((resumed_at, revoke_at), (Some(a), Some(b)) if a < b),
            "resumed, then the revocation: {told:?}"
        );

        // The device's acknowledgement settles it, as for any revocation.
        hub.with_session(sid, |s| {
            assert!(s.ack_file_child_revocation());
            Ok(())
        })
        .unwrap();
        assert!(
            !hub.with_session(sid, |s| Ok(s.is_file_child_revoke_pending_ack()))
                .unwrap()
        );

        // Its viewer was on no socket when the device was told: the rejoin says it.
        let (ctl, mut ctl_rx) = hub.register_controller(user);
        hub.rejoin(sid, user, &ctl).unwrap();
        let heard = drain(&mut ctl_rx);
        assert!(
            heard.iter().any(
                |m| matches!(m, ServerMsg::SessionResumed { session_id } if *session_id == sid)
            ),
            "{heard:?}"
        );
        assert!(
            heard.iter().any(
                |m| matches!(m, ServerMsg::FileChildRevoke { session_id, .. } if *session_id == sid)
            ),
            "{heard:?}"
        );
    }

    /// A session the hub still held (the claim re-attached it) keeps both its
    /// file child bookkeeping and its zone route: an active file child stays
    /// admitted, nothing is revoked, and its device is told nothing but the
    /// resume.
    #[tokio::test]
    async fn a_reattached_session_keeps_its_file_children() {
        use super::super::{
            AgentZoneIcePolicy, DispatchCtx, OrgPolicy, Role, ZoneRoute, ZoneRouteInfo,
        };
        use meshharbor_remote_control::models::SessionPolicy;
        use meshharbor_remote_control::signaling::{ClientMsg, FileChildDirection};
        let hub = hub().await;
        let (agent, tenant, user) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let _first = register(&hub, agent, tenant, 2, hello(Some(60), Vec::new()));
        hub.set_agent_zone_ice_policy(
            agent,
            AgentZoneIcePolicy {
                policy_revision: 1,
                strict: true,
                allowed_countries: std::collections::HashSet::from(["DE".to_string()]),
                zone: Some("zone-a".to_string()),
                zones: Arc::new(vec![ZoneRouteInfo {
                    id: "zone-a".to_string(),
                    auto_countries: vec!["DE".to_string()],
                    is_default: false,
                    router_only: true,
                }]),
            },
        );
        let (tx, mut ctl_rx) = hub.register_controller(user);
        let ctx = DispatchCtx {
            role: Role::Controller,
            user_id: Some(user),
            agent_id: None,
            controller_name: Some("Viewer".into()),
            controller_tx: Some(tx),
            consent_mode: ConsentMode::Prompt,
            override_reason: None,
            input_mode: None,
            tenant_name: None,
            may_record: false,
            rc_overlay: false,
            session_policy: OrgPolicy::Read(SessionPolicy::default()),
            max_duration: None,
            idle_secs: None,
            lock_on_end: None,
            org_session_cap: None,
            slot: None,
            share_files_account: None,
            continues: None,
            silent_monitor: false,
        };
        hub.dispatch_local_pdp_session_request(
            &ctx,
            ClientMsg::SessionRequest {
                two_factor_code: None,
                agent_id: agent,
                share_grant_id: None,
                permissions: Permissions::VIEW | Permissions::FILES,
                browser_caps: Vec::new(),
                preferred_transport: None,
                chroma_pref: None,
                chunk_framing: None,
                audio_enabled: false,
                override_reason: None,
                local_relay: None,
                initial_resolution: None,
                replaces: None,
                continues_from: None,
                silent_monitor: false,
                monitor_target_session_id: None,
            },
            meshharbor_remote_control::session::FileChildPolicySnapshot::new(Some(2), Some(4)),
        )
        .unwrap();
        let sid = drain(&mut ctl_rx)
            .into_iter()
            .find_map(|m| match m {
                ServerMsg::SessionCreated { session_id, .. } => Some(session_id),
                _ => None,
            })
            .expect("session created");
        live(&hub, sid).await;
        // Reserve and admit a file child before reconnect to prove bookkeeping survives re-attach.
        let child_id = hub
            .with_session(sid, |s| {
                s.set_file_children_enabled_for(FileChildDirection::Download, true);
                let cid = s.reserve_file_child("transfer-1")?;
                s.admit_file_child(cid, "transfer-1")?;
                Ok(cid)
            })
            .expect("file child admitted on live session");
        let route_before = hub.with_session(sid, |s| Ok(s.zone_route)).unwrap();
        assert_eq!(
            route_before,
            ZoneRoute::Direct {
                mesh_fallback: false
            }
        );

        let mut second = register(&hub, agent, tenant, 2, hello(Some(60), vec![sid]));
        let r = ResumedSession {
            session_id: sid,
            tenant_id: tenant,
            controller_user_id: user,
            permissions: Permissions::VIEW | Permissions::FILES,
            created_at: DateTime::now(),
            started_at: DateTime::now(),
            attach_seq: 1,
            max_duration: None,
            external: false,
            slot: None,
            resume_secs: 60,
        };
        assert_eq!(
            hub.resume_claimed(agent, &second.tx, r),
            Resumed::Reattached
        );
        assert!(hub.confirm_resumed(agent, &second.tx, sid, 1));
        let (revoked, route_after, has_child) = hub
            .with_session(sid, |s| {
                Ok((
                    s.is_file_children_revoked(),
                    s.zone_route,
                    s.has_active_file_child(child_id, "transfer-1"),
                ))
            })
            .unwrap();
        assert!(
            !revoked,
            "re-attached session keeps file children unrevoked"
        );
        assert!(has_child, "active file child survives re-attach");
        assert_eq!(route_after, route_before, "zone route survives re-attach");
        assert!(
            !drain(&mut second.rx)
                .iter()
                .any(|m| matches!(m, ServerMsg::FileChildRevoke { .. })),
            "nothing to revoke"
        );
    }

    /// The device's earlier connection on this pod is half-open and still
    /// holds the session: the reap spares the claimed session, the claim
    /// re-attaches it at the new number with its controller, and the
    /// controller is told the resume too.
    #[tokio::test]
    async fn a_session_still_held_for_the_earlier_connection_is_reattached() {
        let hub = hub().await;
        let (agent, tenant, user) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let _first = register(&hub, agent, tenant, 2, hello(Some(60), Vec::new()));
        let (sid, mut ctl) = open(&hub, agent, user);
        live(&hub, sid).await;
        let (other, mut other_ctl) = open(&hub, agent, user);
        live(&hub, other).await;
        drain(&mut ctl);

        let second = register(&hub, agent, tenant, 2, hello(Some(60), vec![sid]));
        assert_eq!(
            second.reaped,
            vec![other],
            "only the unclaimed one is reaped"
        );
        assert_eq!(
            terminated(&drain(&mut other_ctl), other),
            Some(EndReason::AgentDisconnect)
        );
        assert!(drain(&mut ctl).is_empty(), "the claimed one is spared");

        let lease = lease_of(tenant, sid, user, agent);
        let r = ResumedSession {
            session_id: sid,
            tenant_id: tenant,
            controller_user_id: user,
            permissions: Permissions::VIEW,
            created_at: DateTime::now(),
            started_at: DateTime::now(),
            attach_seq: 1,
            max_duration: None,
            external: false,
            slot: Some(lease.clone()),
            resume_secs: 60,
        };
        assert_eq!(
            hub.resume_claimed(agent, &second.tx, r),
            Resumed::Reattached
        );
        assert_eq!(
            hub.inner.slotted.get(&sid).map(|l| l.value().clone()),
            Some(lease),
            "the re-attached copy holds the lease the claim took"
        );
        assert!(hub.confirm_resumed(agent, &second.tx, sid, 1));
        assert!(
            drain(&mut ctl).iter().any(
                |m| matches!(m, ServerMsg::SessionResumed { session_id } if *session_id == sid)
            ),
            "the viewer this pod still had hears the resume"
        );
        assert_eq!(hub.with_session(sid, |s| Ok(s.attach_seq)).unwrap(), 1);
    }

    /// A refusal of a session still held for the earlier connection ends that
    /// copy, telling both ends, and leaves the device's count right.
    #[tokio::test]
    async fn refusing_a_session_still_held_ends_it_and_keeps_the_count() {
        let hub = hub().await;
        let (agent, tenant, user) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let _first = register(&hub, agent, tenant, 1, hello(Some(60), Vec::new()));
        let (sid, mut ctl) = open(&hub, agent, user);
        live(&hub, sid).await;
        drain(&mut ctl);

        let mut second = register(&hub, agent, tenant, 1, hello(Some(60), vec![sid]));
        assert!(hub.refuse_claim(
            agent,
            &second.tx,
            sid,
            EndReason::AdminTerminated,
            None,
            Some(RowEnd::fenced(0)),
        ));
        assert!(hub.session_snapshot(sid).is_none());
        assert_eq!(
            terminated(&drain(&mut ctl), sid),
            Some(EndReason::AdminTerminated)
        );
        assert_eq!(
            terminated(&drain(&mut second.rx), sid),
            Some(EndReason::AdminTerminated)
        );
        let (next, _c) = open(&hub, agent, user);
        assert!(
            hub.session_snapshot(next).is_some(),
            "the device's one place is free again"
        );
    }

    /// PR C's deferred race, L13's twin (a guard: the race is a few
    /// instructions wide) — the refusal takes the claim first and reads the
    /// held copy only then, removing exactly the copy it read. A copy an end
    /// took out first is that end's: the refusal counts nothing for it,
    /// answers the device with its own reason, and the device's one place is
    /// free.
    #[tokio::test]
    async fn a_refused_claim_whose_held_copy_already_ended_counts_nothing() {
        let hub = hub().await;
        let (agent, tenant, user) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let _first = register(&hub, agent, tenant, 1, hello(Some(60), Vec::new()));
        let (sid, _ctl) = open(&hub, agent, user);
        live(&hub, sid).await;
        let mut second = register(&hub, agent, tenant, 1, hello(Some(60), vec![sid]));
        hub.terminate(sid, EndReason::AdminTerminated).unwrap();
        drain(&mut second.rx);

        assert!(hub.refuse_claim(
            agent,
            &second.tx,
            sid,
            EndReason::AgentDisconnect,
            None,
            None,
        ));
        assert_eq!(
            terminated(&drain(&mut second.rx), sid),
            Some(EndReason::AgentDisconnect)
        );
        let count = |hub: &Hub| hub.inner.agents.get(&agent).map(|a| a.active_sessions);
        assert_eq!(
            count(&hub),
            Some(0),
            "nothing counted for a copy that ended"
        );
        let (next, _c) = open(&hub, agent, user);
        assert!(
            hub.session_snapshot(next).is_some(),
            "the device's one place is free"
        );
    }

    /// PR D's review, LOW 3 — a claim refused after its commit ends only what
    /// it may. A displaced connection's refusal ends nothing. A copy still
    /// held for the device's earlier connection, below the number committed,
    /// moves up to it and ends there, and the device's count stays right. A
    /// copy at that number or later is another claim's, and is left alone.
    #[tokio::test]
    async fn a_claim_refused_after_its_commit_ends_only_a_copy_below_its_number() {
        let hub = hub().await;
        let (agent, tenant, user) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let first = register(&hub, agent, tenant, 1, hello(Some(60), Vec::new()));
        let (sid, mut ctl) = open(&hub, agent, user);
        live(&hub, sid).await;
        drain(&mut ctl);
        let mut second = register(&hub, agent, tenant, 1, hello(Some(60), vec![sid]));
        let held_at = hub.with_session(sid, |s| Ok(s.attach_seq)).unwrap();

        assert!(
            !hub.refuse_resumed(
                agent,
                &first.tx,
                sid,
                held_at + 1,
                EndReason::AgentDisconnect
            ),
            "not the displaced connection's to answer"
        );
        assert!(hub.session_snapshot(sid).is_some(), "nothing ended");
        assert!(drain(&mut ctl).is_empty());

        assert!(hub.refuse_resumed(
            agent,
            &second.tx,
            sid,
            held_at + 1,
            EndReason::AgentDisconnect
        ));
        assert!(hub.session_snapshot(sid).is_none(), "the copy below ended");
        assert_eq!(
            terminated(&drain(&mut ctl), sid),
            Some(EndReason::AgentDisconnect)
        );
        assert_eq!(
            terminated(&drain(&mut second.rx), sid),
            Some(EndReason::AgentDisconnect)
        );
        let count = |hub: &Hub| hub.inner.agents.get(&agent).map(|a| a.active_sessions);
        assert_eq!(count(&hub), Some(0), "the count stays right");
        assert!(
            !hub.refuse_resumed(
                agent,
                &second.tx,
                sid,
                held_at + 1,
                EndReason::AgentDisconnect
            ),
            "answered once"
        );

        // A copy at the number committed: another claim's, left alone.
        let (other, mut other_ctl) = open(&hub, agent, user);
        live(&hub, other).await;
        drain(&mut other_ctl);
        let mut third = register(&hub, agent, tenant, 1, hello(Some(60), vec![other]));
        hub.with_session(other, |s| {
            s.attach_seq = 5;
            Ok(())
        })
        .unwrap();
        assert!(hub.refuse_resumed(agent, &third.tx, other, 5, EndReason::AgentDisconnect));
        assert!(hub.session_snapshot(other).is_some(), "left alone");
        assert_eq!(hub.with_session(other, |s| Ok(s.attach_seq)).unwrap(), 5);
        assert!(drain(&mut other_ctl).is_empty(), "nobody told");
        assert_eq!(terminated(&drain(&mut third.rx), other), None);
    }

    /// PR D's review, MEDIUM 2 — the lease a claim took enters the hub with
    /// the session it rebuilds, before the session does. So a drop of the
    /// device's connection right after the rebuild (during the claim's second
    /// read) finds the lease with the session and takes it out with it, kept
    /// with the detach, never left behind for a later hold to release.
    #[tokio::test]
    async fn a_rebuilt_sessions_lease_enters_the_hub_with_it_and_leaves_with_its_detach() {
        let hub = hub().await;
        let (agent, tenant, user) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let sid = ObjectId::new();
        let reg = register(&hub, agent, tenant, 2, hello(Some(60), vec![sid]));
        let lease = lease_of(tenant, sid, user, agent);
        let r = ResumedSession {
            session_id: sid,
            tenant_id: tenant,
            controller_user_id: user,
            permissions: Permissions::VIEW,
            created_at: DateTime::now(),
            started_at: DateTime::now(),
            attach_seq: 1,
            max_duration: None,
            external: false,
            slot: Some(lease.clone()),
            resume_secs: 60,
        };
        assert_eq!(hub.resume_claimed(agent, &reg.tx, r), Resumed::Rebuilt);
        assert_eq!(
            hub.inner.slotted.get(&sid).map(|l| l.value().clone()),
            Some(lease),
            "held with the session"
        );

        assert!(hub.unregister_agent(agent, Some(&reg.tx)));
        assert!(hub.session_snapshot(sid).is_none(), "detached");
        assert!(
            !hub.inner.slotted.contains_key(&sid),
            "its lease left with it"
        );
        assert!(hub.slot_leases().is_empty(), "nothing left to renew");
    }

    /// P1b-1's review, L13 — the copy this hub held for the device's earlier
    /// connection ended before the claim was answered. The claim reads the
    /// hub only once it has taken the claim, so it rebuilds the session rather
    /// than re-attaching a copy no longer in the map: the session is held,
    /// counted once, and its lease renewed from here only while it is held.
    #[tokio::test]
    async fn a_held_copy_that_ended_before_the_claim_is_rebuilt_and_counted_once() {
        let hub = hub().await;
        let (agent, tenant, user) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let _first = register(&hub, agent, tenant, 2, hello(Some(60), Vec::new()));
        let (sid, _ctl) = open(&hub, agent, user);
        live(&hub, sid).await;
        let second = register(&hub, agent, tenant, 2, hello(Some(60), vec![sid]));
        assert!(second.reaped.is_empty(), "the claimed copy is spared");
        hub.terminate(sid, EndReason::AdminTerminated).unwrap();
        assert!(hub.session_snapshot(sid).is_none());

        // The claim takes the slot again once its commit has won, and hands
        // it in with the session.
        let r = ResumedSession {
            session_id: sid,
            tenant_id: tenant,
            controller_user_id: user,
            permissions: Permissions::VIEW,
            created_at: DateTime::now(),
            started_at: DateTime::now(),
            attach_seq: 1,
            max_duration: None,
            external: false,
            slot: Some(lease_of(tenant, sid, user, agent)),
            resume_secs: 60,
        };
        assert_eq!(hub.resume_claimed(agent, &second.tx, r), Resumed::Rebuilt);
        assert!(hub.session_snapshot(sid).is_some(), "held here now");
        assert!(
            hub.inner.slotted.contains_key(&sid),
            "its lease renewed here"
        );
        let count = |hub: &Hub| hub.inner.agents.get(&agent).map(|a| a.active_sessions);
        assert_eq!(count(&hub), Some(1), "counted once");

        hub.terminate(sid, EndReason::ControllerHangup).unwrap();
        assert!(
            !hub.inner.slotted.contains_key(&sid),
            "its end gives it back"
        );
        assert_eq!(count(&hub), Some(0));
    }

    /// The announce reaches only a connection that advertises the verb, and
    /// 0 withdraws the window, so the next drop ends as today.
    #[tokio::test]
    async fn an_announce_needs_the_verb_and_zero_withdraws_it() {
        let hub = hub().await;
        let (agent, tenant) = (ObjectId::new(), ObjectId::new());
        let mut reg = register(
            &hub,
            agent,
            tenant,
            2,
            ResumeHello {
                advertised: false,
                window: None,
                kept: Vec::new(),
            },
        );
        assert!(!hub.announce_resume_window(agent, 60));
        assert!(drain(&mut reg.rx).is_empty(), "never sent blind");

        let mut reg = register(&hub, agent, tenant, 2, hello(Some(60), Vec::new()));
        assert_eq!(hub.agent_resume_window(agent), Some(60));
        assert!(hub.announce_resume_window(agent, 0));
        assert_eq!(hub.agent_resume_window(agent), None);
        assert!(
            drain(&mut reg.rx)
                .iter()
                .any(|m| matches!(m, ServerMsg::AgentResumeWindow { secs: 0 }))
        );
    }
}
