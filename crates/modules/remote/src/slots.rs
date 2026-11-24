// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-115 P3b — claiming a cluster-wide session slot before the hub creates
//! a session (`docs/fr/FR-115-pricing-reshape.md`, *P3b, as proposed*).
//!
//! The hub is synchronous and holds no Redis connection, so the claim runs
//! here, in the async caller on the pod that owns the device, and the hub is
//! handed the lease (`DispatchCtx::slot`, `create_session_full`'s `slot`).
//! From then on the hub renews it and gives it back when the session ends;
//! a slot that no session took is given back here ([`release_unused`]).
//!
//! Never refuse on a guess:
//! * when Redis cannot answer, a same-org request falls back to P3's count on
//!   the hub that owns the device, and an external one runs as it did before
//!   P3b (uncapped), counted in `rc_slot_claim_failed_total`;
//! * a full set whose holder THIS pod claimed but no longer holds is a stale
//!   lease (its release failed, or never ran): this pod is the one that would
//!   know, so it drops it and claims once more. That is what keeps a Free org
//!   from being locked out for a whole lease after a failed release, e.g. on
//!   its viewer's reconnect. Another pod's holders are never judged here.
//!   FR-130 (review 1, M5) — above window 0 a session no hub holds may be
//!   detached, waiting for its device's claim, and its lease is its slot: the
//!   holder's row is read first (once per such holder, only when the set is
//!   full), and the lease is kept only while the row can still be resumed
//!   (PR D's review, MEDIUM 1): live with a `resume_by` no more than 10 s
//!   past, or live with no `resume_by` on a device in the resume scope, whose
//!   detach may not have reached the row yet. Anything else is dropped as
//!   before, so a dead pod's lease of a device outside the scope frees its
//!   org at once. At window 0 nothing is read, as before.

use std::sync::LazyLock;

use bson::{DateTime, oid::ObjectId};
use dashmap::DashSet;
use meshharbor_core::cluster::metrics::{RC_SLOT_CLAIM_FAILED_TOTAL, RC_SLOT_FULL_TOTAL, bump};
use meshharbor_core::cluster::session_slots::{
    Lease, SLOT_KEEP_PAST_RESUME_MS, SlotClaim, SlotHolder, SlotScope,
};
use meshharbor_remote_control::models::SessionPhase;
use meshharbor_services::dao::base::DaoError;
use tracing::{debug, warn};

use crate::RemoteState;

/// Sessions whose slot this process claimed and whose hub has not created
/// them yet: the window between the claim and `create_session_full`'s insert.
/// The stale check must never drop one of these; it is live, only not in the
/// hub YET. Cleared by [`release_unused`], which every claimed path calls.
static PENDING: LazyLock<DashSet<ObjectId>> = LazyLock::new(DashSet::new);

/// What a claim decided.
#[derive(Debug, Clone)]
pub enum SlotDecision {
    /// Create the session under this lease, with no hub-side cap.
    Claimed(Lease),
    /// Redis could not answer: decide as before P3b.
    Fallback,
    /// Every slot is held: refuse, naming one holder (hex ids; empty when
    /// the holder's record had already expired).
    Full {
        cap: u32,
        holder_user: String,
        holder_agent: String,
    },
}

/// Are slots on? `rc.session_slots`, with the P3 cap's own gates (its kill
/// switch, and a server that sells plans) and a Redis to keep them in.
pub fn enabled(state: &RemoteState) -> bool {
    state.settings.rc.session_slots
        && state.settings.rc.org_session_cap
        && state.plans_sold
        && state.session_slots.is_some()
}

/// A holder this pod claimed is stale when its hub does not hold the session
/// and no claim of this process is still creating it.
fn stale_here(state: &RemoteState, session_hex: &str) -> Option<ObjectId> {
    let id = ObjectId::parse_str(session_hex).ok()?;
    (state.fleet.rc_hub.session_snapshot(id).is_none() && !PENDING.contains(&id)).then_some(id)
}

/// The holders of a full set that this pod may drop as stale: claimed here,
/// [`stale_here`], and, above window 0, over by their row (review 1, M5).
async fn stale_holders(
    state: &RemoteState,
    scope: SlotScope,
    holders: &[SlotHolder],
    pod: &str,
) -> Vec<ObjectId> {
    let mut stale = Vec::new();
    for h in holders.iter().filter(|h| h.pod == pod) {
        let Some(id) = stale_here(state, &h.session) else {
            continue;
        };
        if crate::row_end::enabled(state) && !over(state, scope, id).await {
            debug!(?scope, session = %id, "session slot: a lease this pod no longer holds is kept; its session may still be resumed");
            continue;
        }
        stale.push(id);
    }
    stale
}

/// Review 1, M5 — whether the session behind a lease no hub here holds is
/// over, by its row. It may still be resumed only while it is live and
/// either detached, with a `resume_by` no more than [`SLOT_KEEP_PAST_RESUME_MS`]
/// past (a claim that began before the deadline may commit just after it;
/// PR D's review, LOW 4), or has no `resume_by` while its device is in the
/// resume scope: a detach whose write has not reached the row yet (PR D's
/// review, MEDIUM 1). Everything else is over and dropped, as before FR-130:
/// ended, not live, past the grace, no row in the org, or live with no
/// deadline on a device outside the scope (a session of a pod that died
/// without writing its ends, which nothing will resume). A row or a scope
/// that cannot be read is no evidence either way, and its lease is kept. An
/// account in no org runs only external sessions, which a device never keeps
/// (D3): over, with no read.
async fn over(state: &RemoteState, scope: SlotScope, session: ObjectId) -> bool {
    let SlotScope::Org(tenant_id) = scope else {
        return true;
    };
    let row = match state
        .remote_sessions
        .find_in_tenant(tenant_id, session)
        .await
    {
        Ok(row) => row,
        Err(DaoError::NotFound) => return true,
        Err(e) => {
            warn!(?scope, %session, %e, "session slot: the row of a lease this pod no longer holds could not be read; the lease is kept");
            return false;
        }
    };
    if row.ended_at.is_some() || row.phase != SessionPhase::Active {
        return true;
    }
    if let Some(by) = row.resume_by {
        return by
            .timestamp_millis()
            .saturating_add(SLOT_KEEP_PAST_RESUME_MS)
            <= DateTime::now().timestamp_millis();
    }
    match state
        .fleet
        .rc_resume_scope
        .covers(tenant_id, row.agent_id)
        .await
    {
        Ok(covered) => !covered,
        Err(e) => {
            warn!(?scope, %session, %e, "session slot: the resume scope could not be read for a lease this pod no longer holds; the lease is kept");
            false
        }
    }
}

/// Claim one of `scope`'s `cap` slots for a new session `user` starts on
/// `device`, under a freshly minted session id.
pub async fn claim(
    state: &RemoteState,
    scope: SlotScope,
    user: ObjectId,
    device: ObjectId,
    cap: u32,
) -> SlotDecision {
    claim_for(state, scope, ObjectId::new(), user, device, cap).await
}

/// [`claim`], under `session`'s own id: FR-130's claim takes a resumed
/// session's slot again, finding its own lease (renewed) or claiming a new
/// one. Pending from here until [`release_unused`] or [`settle`].
pub async fn claim_for(
    state: &RemoteState,
    scope: SlotScope,
    session: ObjectId,
    user: ObjectId,
    device: ObjectId,
    cap: u32,
) -> SlotDecision {
    let Some(slots) = &state.session_slots else {
        return SlotDecision::Fallback;
    };
    let pod = state.pod.pod_id.clone();
    PENDING.insert(session);
    let mut retried = false;
    loop {
        match slots.claim(scope, session, user, device, cap, &pod).await {
            Ok(SlotClaim::Claimed | SlotClaim::Renewed) => {
                debug!(?scope, %session, cap, "session slot claimed");
                return SlotDecision::Claimed(Lease {
                    scope,
                    session,
                    user,
                    device,
                });
            }
            Ok(SlotClaim::Full(holders)) => {
                if !retried {
                    let stale = stale_holders(state, scope, &holders, &pod).await;
                    if !stale.is_empty() {
                        for id in &stale {
                            warn!(?scope, session = %id, "session slot: dropping a stale lease this pod no longer holds");
                            if let Err(e) = slots.release(scope, *id).await {
                                warn!(%e, "session slot: the stale lease was not dropped");
                            }
                        }
                        retried = true;
                        continue;
                    }
                }
                PENDING.remove(&session);
                bump(&RC_SLOT_FULL_TOTAL);
                let (holder_user, holder_agent) = holders
                    .into_iter()
                    .next()
                    .map(|h| (h.user, h.device))
                    .unwrap_or_default();
                return SlotDecision::Full {
                    cap,
                    holder_user,
                    holder_agent,
                };
            }
            Err(e) => {
                PENDING.remove(&session);
                bump(&RC_SLOT_CLAIM_FAILED_TOTAL);
                warn!(?scope, %e, "session slot: the claim failed; deciding as before P3b");
                return SlotDecision::Fallback;
            }
        }
    }
}

/// After the hub ran: the claim is no longer pending, and a slot no session
/// took (the hub refused, or coalesced the request into an existing session,
/// so `created` is another id) goes back. The lease's TTL backs this up.
pub async fn release_unused(state: &RemoteState, lease: &Lease, created: Option<ObjectId>) {
    PENDING.remove(&lease.session);
    if created == Some(lease.session) {
        return; // the hub holds it now, and gives it back when the session ends
    }
    if let Some(slots) = &state.session_slots
        && let Err(e) = slots.release(lease.scope, lease.session).await
    {
        warn!(session = %lease.session, %e, "session slot: an unused slot was not given back; it expires on its own");
    }
}

/// FR-130 — the claim is no longer pending, and the slot stays held: the hub
/// holds the session now, or another claim of it will take the lease again.
pub fn settle(lease: &Lease) {
    PENDING.remove(&lease.session);
}

/// FR-130 — give back the slot of a session a claim found ended, or ended
/// itself: the claim holds no lease of its own (it takes one only once its
/// commit has won), and nobody holds the session, so its lease, which the
/// detach kept, goes back by the session's id. Idempotent.
pub async fn release_ended(state: &RemoteState, tenant_id: ObjectId, session: ObjectId) {
    if !enabled(state) {
        return;
    }
    let Some(slots) = &state.session_slots else {
        return;
    };
    if let Err(e) = slots.release(SlotScope::Org(tenant_id), session).await {
        warn!(%session, %e, "session slot: an ended session's slot was not given back; it expires on its own");
    }
}

/// Review 1, L2 — keep a detached session's lease until `resume_by` plus
/// 10 s, as the hub's detach does: the claim that wrote the detach back holds
/// no session, so nobody renews it. A lease that already lapsed stays lapsed.
pub async fn keep(
    state: &RemoteState,
    tenant_id: ObjectId,
    session: ObjectId,
    resume_by: DateTime,
) {
    if !enabled(state) {
        return;
    }
    let Some(slots) = &state.session_slots else {
        return;
    };
    let until = resume_by
        .timestamp_millis()
        .saturating_add(SLOT_KEEP_PAST_RESUME_MS);
    if let Err(e) = slots.keep(SlotScope::Org(tenant_id), session, until).await {
        warn!(%session, %e, "session slot: a detached session's lease was not kept; it lapses at its own expiry");
    }
}
