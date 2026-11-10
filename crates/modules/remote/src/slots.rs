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

use std::sync::LazyLock;

use bson::oid::ObjectId;
use dashmap::DashSet;
use meshharbor_core::cluster::metrics::{RC_SLOT_CLAIM_FAILED_TOTAL, RC_SLOT_FULL_TOTAL, bump};
use meshharbor_core::cluster::session_slots::{Lease, SlotClaim, SlotScope};
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

/// Claim one of `scope`'s `cap` slots for a new session `user` starts on
/// `device`, under a freshly minted session id.
pub async fn claim(
    state: &RemoteState,
    scope: SlotScope,
    user: ObjectId,
    device: ObjectId,
    cap: u32,
) -> SlotDecision {
    let Some(slots) = &state.session_slots else {
        return SlotDecision::Fallback;
    };
    let session = ObjectId::new();
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
                let stale: Vec<ObjectId> = holders
                    .iter()
                    .filter(|h| h.pod == pod)
                    .filter_map(|h| stale_here(state, &h.session))
                    .collect();
                if !retried && !stale.is_empty() {
                    for id in &stale {
                        warn!(?scope, session = %id, "session slot: dropping a stale lease this pod no longer holds");
                        if let Err(e) = slots.release(scope, *id).await {
                            warn!(%e, "session slot: the stale lease was not dropped");
                        }
                    }
                    retried = true;
                    continue;
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
