// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2c-3a — the server's half of membership: the joins it sends a
//! session's members, and what it learns back, each member's answer and the
//! tip of its copy (spec §3b, "What the server learns").
//!
//! | When | What |
//! |---|---|
//! | the primary accepts a start | each member placement chose is sent `rc:hive.replica.join` ([`send_joins`]) |
//! | a device that holds copies connects | every join it has still to answer is sent again ([`reconcile_joins`]) |
//! | a session gains its first member after it started (P2c-4) | its primary is sent `join {role: primary}`, and checkpoints from then on |
//! | the primary connects | the primary's join it has still to answer `joined` is sent again ([`reconcile_joins`]) |
//! | `rc:hive.replica.join_ack` | the member is `joined`, or `refused` with the device's word ([`on_join_ack`]) |
//! | `rc:hive.replica.tip`, and each entry of `rc:hive.replica.manifest` | the member's tip is kept ([`on_tip`]) |
//! | P2g-3c — a copy `rc:hive.replica.manifest` says the device's own clock purged | that member's row is refused `purged` ([`on_copy_purged`]) |
//!
//! ⚠️ A member's join is pushed only to a connection advertising
//! `hive-replica`: the device answers it, and its owner lets it hold copies.
//! Any other connection receives nothing, and the join waits, pending, for
//! one that does. The primary's goes to a connection that runs Hive: it holds
//! no copy of another device's session, so its `hive_replica` is not asked.
//! P2f-1 — and a teleport's target's to a connection advertising
//! `hive-teleport`: it takes the copy it will run, which its prepare
//! admitted, whatever its owner says of holding copies.
//! ⚠️ Everything a device says here is a claim, applied only where the record
//! names that device as a member: a frame about someone else's session, or
//! from a device placement did not choose, matches nothing.

use bson::{DateTime, oid::ObjectId};
use meshharbor_remote_control::{
    hive::{
        HiveCopyPurged, HiveFenceMark, HiveJoinRefusal, HiveReplicaManifestEntry, HiveReplicaRole,
        is_hash_hex, replica_limits, retain_limits,
    },
    signaling::ServerMsg,
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::HiveState;
use crate::agent_socket::clamp_words;
use crate::model::{AgentSession, FenceMark, MemberState, MemberTip, past_end};
use crate::placement::MemberRole;

/// The role a member was placed in, as the join names it. `None` for a word
/// this build cannot name.
pub(crate) fn wire_role(role: &str) -> Option<HiveReplicaRole> {
    if role == MemberRole::Archive.as_str() {
        Some(HiveReplicaRole::Archive)
    } else if role == MemberRole::Owner.as_str() {
        Some(HiveReplicaRole::Owner)
    } else if role == MemberRole::Primary.as_str() {
        Some(HiveReplicaRole::Primary)
    } else if role == MemberRole::Teleport.as_str() {
        Some(HiveReplicaRole::Teleport)
    } else {
        None
    }
}

/// Whether the session's start tells its primary to checkpoint: placement
/// chose at least one member besides it.
pub(crate) fn replicated(s: &AgentSession) -> bool {
    s.replicaset.as_ref().is_some_and(|r| {
        r.members
            .iter()
            .any(|m| m.role != MemberRole::Primary.as_str())
    })
}

/// The joins of `s` still to send: its members that have not answered, each
/// with its role. The primary is among them only once it is owed one (P2c-4:
/// `pending`, while the session has a member besides it).
fn pending(s: &AgentSession) -> Vec<(ObjectId, HiveReplicaRole)> {
    let Some(r) = &s.replicaset else {
        return Vec::new();
    };
    let has_members = replicated(s);
    r.members
        .iter()
        .filter(|m| m.state == MemberState::Pending)
        .filter(|m| has_members || m.role != MemberRole::Primary.as_str())
        .filter_map(|m| Some((m.device_id, wire_role(&m.role)?)))
        .collect()
}

/// P2d-5 — the member whose copy serves a view of `s` when its primary
/// cannot: of the members that took their copy (`joined`, never the
/// primary) and that `serves` says can serve one, the freshest by the tip it
/// last reported, the fence first and then the seq; an archive replica on a
/// tie (design §5.2), then the lowest device id, so the choice is the same
/// every time. A member that has reported no tip ranks below any that has.
/// Its tip is the device's claim, which only orders the members: it reads
/// its own copy, and the device serves what it holds.
pub(crate) fn freshest_copy(
    s: &AgentSession,
    serves: impl Fn(ObjectId) -> bool,
) -> Option<ObjectId> {
    let primary = s.location.device_id;
    s.replicaset
        .as_ref()?
        .members
        .iter()
        .filter(|m| {
            m.device_id != primary
                && m.role != MemberRole::Primary.as_str()
                && m.state == MemberState::Joined
        })
        .filter(|m| serves(m.device_id))
        .max_by_key(|m| {
            (
                m.tip.as_ref().map(|t| (t.fence, t.seq)),
                m.role == MemberRole::Archive.as_str(),
                std::cmp::Reverse(m.device_id),
            )
        })
        .map(|m| m.device_id)
}

/// Push one join, at the record's fence. `false` = it did not leave: the
/// device is not connected here, or this connection does not take it (a
/// member's that holds no copies, a primary's that runs no Hive). It stays
/// owed either way, and goes when a connection that takes it asks.
///
/// P2e-5b — it carries the record's `fences`, every time: a member that joins
/// after a move holds a floor above every event the session had, and takes
/// them only up to where each superseded fence ended. Taking the RECORD, not
/// its fields, is what keeps a new caller from sending a join without them.
pub(crate) fn push_join(
    state: &HiveState,
    s: &AgentSession,
    device_id: ObjectId,
    role: HiveReplicaRole,
) -> bool {
    let Some(session_id) = s.id else {
        return false;
    };
    let tenant_id = s.tenant_id;
    let msg = ServerMsg::HiveReplicaJoin {
        session_id,
        fence: u64::try_from(s.fence).unwrap_or_default(),
        role: Some(role),
        fences: fence_marks(s),
    };
    let hub = &state.fleet.rc_hub;
    // P2f-1 — a teleport's target is no device that holds copies by its
    // owner's word: its join goes to a connection that takes a teleport.
    let pushed = match role {
        HiveReplicaRole::Primary => hub.push_hive(device_id, tenant_id, msg),
        HiveReplicaRole::Teleport => hub.push_hive_teleport(device_id, tenant_id, msg),
        HiveReplicaRole::Archive | HiveReplicaRole::Owner => {
            hub.push_hive_replica(device_id, tenant_id, msg)
        }
    };
    match pushed {
        Ok(()) => {
            info!(
                session = %session_id, device = %device_id, role = role.as_str(),
                "hive: join sent"
            );
            true
        }
        Err(e) => {
            debug!(session = %session_id, device = %device_id, %e, "hive: join not sent — it stays pending");
            false
        }
    }
}

/// P2e-5b — the record's `fences` as a join carries them, oldest first. A
/// mark no promotion could have written (a negative number) is left out,
/// never sent wrapped: that fence's events are then refused below the
/// floor, as every one was before P2e-5b.
pub(crate) fn fence_marks(s: &AgentSession) -> Vec<HiveFenceMark> {
    s.fences
        .iter()
        .filter_map(|m| {
            Some(HiveFenceMark {
                fence: u64::try_from(m.fence).ok()?,
                seq: u64::try_from(m.seq).ok()?,
                hash: m.hash.clone(),
            })
        })
        .collect()
}

/// The primary accepted the session's start: send each member placement
/// chose its join. Before that the session may never run, and a member would
/// hold a copy of nothing.
pub(crate) async fn send_joins(state: &HiveState, session_id: ObjectId) {
    let s = match state.sessions.find(session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return,
        Err(e) => {
            warn!(session = %session_id, %e, "hive: a session's members were not read — its joins wait");
            return;
        }
    };
    for (device_id, role) in pending(&s) {
        push_join(state, &s, device_id, role);
    }
}

/// A device connected: send it every join it has still to answer — as the
/// primary of a session it runs, if THIS connection runs Hive (P2c-4), and
/// as a member, if THIS connection holds copies. `conn` is the connection's
/// sender in the hub, read as `reconcile_on_connect` reads it: a connection a
/// newer one displaced decides nothing.
pub(crate) async fn reconcile_joins(
    state: &HiveState,
    tenant_id: ObjectId,
    device_id: ObjectId,
    conn: &mpsc::Sender<ServerMsg>,
) {
    let hub = &state.fleet.rc_hub;
    if hub.agent_supports_hive_on(device_id, conn) == Some(true) {
        match state
            .sessions
            .primary_joins_owed(tenant_id, device_id)
            .await
        {
            Ok(sessions) => {
                for s in sessions {
                    push_join(state, &s, device_id, HiveReplicaRole::Primary);
                }
            }
            Err(e) => {
                warn!(device = %device_id, %e, "hive: the primary's joins were not read");
            }
        }
    }
    // P2f-1 — a teleport's target's join goes to a connection that takes a
    // teleport, whatever its owner says of holding copies; every other
    // member's to one that holds copies.
    let holds = hub.agent_supports_hive_replica_on(device_id, conn) == Some(true);
    let teleports = hub.agent_supports_hive_teleport_on(device_id, conn) == Some(true);
    if !holds && !teleports {
        return;
    }
    let sessions = match state.sessions.pending_joins(tenant_id, device_id).await {
        Ok(s) => s,
        Err(e) => {
            warn!(device = %device_id, %e, "hive: the device's pending joins were not read");
            return;
        }
    };
    for s in sessions {
        for (member, role) in pending(&s) {
            let taken = if role == HiveReplicaRole::Teleport {
                teleports
            } else {
                holds
            };
            if member == device_id && taken {
                push_join(state, &s, device_id, role);
            }
        }
    }
}

/// `rc:hive.replica.join_ack` — the member's answer, kept on the record.
pub(crate) async fn on_join_ack(
    state: &HiveState,
    device_id: ObjectId,
    session_id: ObjectId,
    fence: u64,
    refused: Option<HiveJoinRefusal>,
    detail: Option<String>,
) {
    let detail = clamp_words(
        detail,
        meshharbor_remote_control::hive::hive_limits::MAX_DETAIL_LEN,
    );
    match state
        .sessions
        .member_answer(
            session_id,
            device_id,
            fence,
            refused.map(HiveJoinRefusal::as_str),
        )
        .await
    {
        Ok(true) => {
            info!(
                session = %session_id, device = %device_id,
                refused = refused.map(HiveJoinRefusal::as_str), detail = detail.as_deref(),
                "hive: a member answered its join"
            );
            // P2f-1 — a teleport joining, if one waits on this answer.
            crate::promote::on_join_answer(state, session_id, device_id).await;
        }
        Ok(false) => debug!(
            session = %session_id, device = %device_id, fence,
            "hive: a join answer matched no member — not this device's, or a stale fence"
        ),
        Err(e) => warn!(session = %session_id, %e, "hive: a join answer was not recorded"),
    }
}

/// `rc:hive.replica.tip`, or one entry of a manifest: the member's tip, kept
/// on the record. A hash that is not one is dropped with its report, never
/// stored.
pub(crate) async fn on_tip(state: &HiveState, device_id: ObjectId, tip: HiveReplicaManifestEntry) {
    let well_formed =
        is_hash_hex(&tip.hash) && tip.checkpoint.as_ref().is_none_or(|c| is_hash_hex(&c.hash));
    if !well_formed {
        debug!(session = %tip.session_id, device = %device_id, "hive: a tip with a malformed hash — dropped");
        return;
    }
    let stored = MemberTip {
        fence: i64::try_from(tip.fence).unwrap_or(i64::MAX),
        seq: i64::try_from(tip.seq).unwrap_or(i64::MAX),
        hash: tip.hash,
        checkpoint_seq: tip
            .checkpoint
            .as_ref()
            .map(|c| i64::try_from(c.seq).unwrap_or(i64::MAX)),
        checkpoint_hash: tip.checkpoint.map(|c| c.hash),
        at: DateTime::now(),
    };
    // P2k-5 — the record as it was before this tip: where its fences ended,
    // and what the record said this member's copy held.
    let before = match state.sessions.find(tip.session_id).await {
        Ok(s) => s,
        Err(e) => {
            debug!(session = %tip.session_id, %e, "hive: the session was not read before a tip");
            None
        }
    };
    match state
        .sessions
        .member_tip(tip.session_id, device_id, &stored)
        .await
    {
        Ok(true) => {
            debug!(
                session = %tip.session_id, device = %device_id, seq = stored.seq,
                "hive: a member's tip"
            );
            if let Some(s) = &before {
                note_tail(state, s, device_id, &stored).await;
            }
            // P2e-3 — the promotion moving the session to this member, if
            // one is syncing, may move the lease now.
            crate::promote::on_tip(state, tip.session_id, device_id).await;
            // P2g-4b — and the copies elsewhere may now be enough for a
            // member that leaves to be purged.
            crate::purge::settle_session(state, tip.session_id).await;
        }
        Ok(false) => debug!(
            session = %tip.session_id, device = %device_id,
            "hive: a tip from a device the session does not hold as a member"
        ),
        Err(e) => warn!(session = %tip.session_id, %e, "hive: a tip was not recorded"),
    }
}

/// FR-90 P2k-5 — a member whose copy is found past where its fence ended:
/// events a primary cut off went on writing after the session moved away
/// from it (P2e-6a), which did not carry over. The room says how many, once:
/// only when the tip the record held for the member before was not already
/// past that same fence's end. `s` is the record as it was before `now`.
async fn note_tail(state: &HiveState, s: &AgentSession, device_id: ObjectId, now: &MemberTip) {
    let held = s
        .replicaset
        .as_ref()
        .and_then(|r| r.members.iter().find(|m| m.device_id == device_id))
        .and_then(|m| m.tip.as_ref());
    let events = newly_past(&s.fences, held, now);
    if events == 0 {
        return;
    }
    let name = match state
        .fleet
        .agents
        .find_live_in_tenant(s.tenant_id, device_id)
        .await
    {
        Ok(a) => a.name,
        Err(_) => String::new(),
    };
    info!(
        session = ?s.id, device = %device_id, fence = now.fence, events,
        "hive: a copy past where its fence ended — its events did not carry over"
    );
    crate::room::note(state, s, crate::room::tail_note(&name, events)).await;
}

/// FR-90 P2k-5 — how many events `now` holds past where its fence ended,
/// when the tip held before it (`held`) was not already past that same
/// fence's end; else 0. A tail is said once: a tip again at that fence says
/// nothing more, while a tail at another fence is a new one.
fn newly_past(fences: &[FenceMark], held: Option<&MemberTip>, now: &MemberTip) -> i64 {
    let events = past_end(fences, now.fence, now.seq);
    if events <= 0
        || held.is_some_and(|t| t.fence == now.fence && past_end(fences, t.fence, t.seq) > 0)
    {
        return 0;
    }
    events
}

/// `rc:hive.replica.manifest` — every session the device holds a copy of,
/// each tip kept as [`on_tip`] keeps one; and (P2g-3c) each copy the
/// device's own clock purged, which it no longer holds ([`on_copy_purged`]).
/// An oversized list is no device's, and changes nothing.
pub(crate) async fn on_manifest(
    state: &HiveState,
    device_id: ObjectId,
    sessions: Vec<HiveReplicaManifestEntry>,
    purged: Vec<HiveCopyPurged>,
) {
    if sessions.len() > replica_limits::MAX_REPLICA_MANIFEST
        || purged.len() > retain_limits::MAX_COPY_PURGED
    {
        warn!(
            device = %device_id, entries = sessions.len(), purged = purged.len(),
            "hive: an oversized replica manifest — ignored"
        );
        return;
    }
    for tip in sessions {
        on_tip(state, device_id, tip).await;
    }
    for p in purged {
        on_copy_purged(state, device_id, p).await;
    }
}

/// FR-90 P2g-3c — the device purged its copy of a session on its own clock:
/// its member row, while the replicaset counts on it, is refused `purged`, as
/// a join it answered so would be. Placement no longer counts the copy, and
/// the session's purge closes that part at once ([`crate::purge::holds_nothing`]).
/// The primary's row is left alone: what a primary's own run left is its
/// hosted manifest's to say (P1b).
async fn on_copy_purged(state: &HiveState, device_id: ObjectId, p: HiveCopyPurged) {
    match state.sessions.member_purged(p.session_id, device_id).await {
        Ok(true) => info!(
            session = %p.session_id, device = %device_id, at_ms = p.at_ms,
            "hive: a member's own clock purged its copy — it is no longer counted"
        ),
        Ok(false) => debug!(
            session = %p.session_id, device = %device_id,
            "hive: a copy purged on a device's own clock that no replicaset counts on"
        ),
        Err(e) => {
            warn!(session = %p.session_id, %e, "hive: a copy purged on a device's own clock was not recorded")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        HarnessRef, ReplicaMember, Replicaset, SessionLocation, SessionOrigin, SessionStatus,
    };

    /// FR-90 P2k-5 — a tail past a fence's end is said once: when the tip
    /// held before was not already past that same fence's end. A tip within
    /// its end, or at the current fence, says nothing; a tail at another
    /// fence is a new one.
    #[test]
    fn a_tail_past_a_fences_end_is_said_once() {
        let fences = [
            FenceMark {
                fence: 1,
                seq: 5,
                hash: "a".repeat(64),
            },
            FenceMark {
                fence: 2,
                seq: 12,
                hash: "b".repeat(64),
            },
        ];
        let at = |fence, seq| MemberTip {
            fence,
            seq,
            hash: "c".repeat(64),
            checkpoint_seq: None,
            checkpoint_hash: None,
            at: DateTime::now(),
        };
        assert_eq!(
            newly_past(&fences, None, &at(1, 9)),
            4,
            "first heard: four past"
        );
        assert_eq!(
            newly_past(&fences, Some(&at(1, 3)), &at(1, 9)),
            4,
            "held within its end before"
        );
        assert_eq!(
            newly_past(&fences, Some(&at(1, 9)), &at(1, 9)),
            0,
            "the same tail again: said already"
        );
        assert_eq!(
            newly_past(&fences, Some(&at(1, 9)), &at(2, 15)),
            3,
            "a tail at another fence is a new one"
        );
        assert_eq!(newly_past(&fences, None, &at(1, 5)), 0, "at its end");
        assert_eq!(
            newly_past(&fences, None, &at(3, 40)),
            0,
            "the current fence"
        );
    }

    fn member(role: MemberRole, state: MemberState) -> ReplicaMember {
        ReplicaMember {
            device_id: ObjectId::new(),
            role: role.as_str().into(),
            state,
            refusal: None,
            answered_at: None,
            tip: None,
            purging: None,
            forking: None,
        }
    }

    fn session(members: Vec<ReplicaMember>) -> AgentSession {
        let now = DateTime::now();
        AgentSession {
            id: Some(ObjectId::new()),
            tenant_id: ObjectId::new(),
            owner_id: ObjectId::new(),
            drivers: Vec::new(),
            title: "t".into(),
            room_id: None,
            last_turn: None,
            harness: HarnessRef {
                id: "claude-code".into(),
                session: "u".into(),
            },
            location: SessionLocation {
                device_id: members[0].device_id,
                device_name: String::new(),
                folder: "/src".into(),
                account: None,
            },
            status: SessionStatus::Idle,
            fence: 1,
            accepted_at: Some(now),
            refusal: None,
            end_reason: None,
            detail: None,
            created_at: now,
            updated_at: now,
            ended_at: None,
            brain_rev: None,
            vault_role: None,
            origin: SessionOrigin::Started,
            replicaset: Some(Replicaset {
                policy_revision: 0,
                min: 2,
                max: 4,
                restricted_tags: Vec::new(),
                members,
                short: None,
                placed_at: now,
            }),
            promotion: None,
            fences: Vec::new(),
            moved: None,
            parent: None,
            from_terminal: None,
            path_map: Vec::new(),
            purged: None,
        }
    }

    /// A member in `role`, `state`, whose copy last ended at `fence`, `seq`.
    fn tipped(role: MemberRole, state: MemberState, fence: i64, seq: i64) -> ReplicaMember {
        ReplicaMember {
            tip: Some(MemberTip {
                fence,
                seq,
                hash: "0".repeat(64),
                checkpoint_seq: None,
                checkpoint_hash: None,
                at: DateTime::now(),
            }),
            ..member(role, state)
        }
    }

    /// P2d-5 — the copy that serves a view: of the joined members that can
    /// serve, the freshest, the fence before the seq; one with no tip below
    /// any with one; an archive replica on a tie, then the lowest device id.
    /// Never the device the session runs on, a row whose role says primary,
    /// or a member still pending or leaving: each asked about on its own, so
    /// that no one rule hides another.
    #[test]
    fn the_freshest_member_that_can_serve_reads_the_copy() {
        use MemberRole::{Archive, Owner, Primary};
        use MemberState::{Joined, Leaving, Pending};
        let all = |_: ObjectId| true;
        // The rows that may never serve rank below every other: a rule left
        // out shows only where it is asked about.
        let s = session(vec![
            tipped(Primary, Joined, 1, 1),
            tipped(Owner, Joined, 1, 80),
            tipped(Owner, Joined, 2, 10),
            tipped(Owner, Pending, 1, 1),
            tipped(Owner, Leaving, 1, 1),
            member(Owner, Joined),
        ]);
        let m = &s.replicaset.as_ref().unwrap().members;
        // The member with no tip stays out of these two: where it ranks is
        // asked about below, on its own.
        let tipped_only = |d: ObjectId| d != m[5].device_id;
        assert_eq!(
            freshest_copy(&s, tipped_only),
            Some(m[2].device_id),
            "a newer fence before a higher seq"
        );
        assert_eq!(
            freshest_copy(&s, |d| tipped_only(d) && d != m[2].device_id),
            Some(m[1].device_id),
            "the next freshest, when the freshest cannot serve"
        );
        assert_eq!(
            freshest_copy(&s, |d| d == m[1].device_id || d == m[5].device_id),
            Some(m[1].device_id),
            "one with no tip below any with one"
        );
        assert_eq!(
            freshest_copy(&s, |d| d == m[5].device_id),
            Some(m[5].device_id),
            "and chosen when it is all there is"
        );
        assert_eq!(
            freshest_copy(&s, |d| d == m[3].device_id || d == m[4].device_id),
            None,
            "never a member pending or leaving"
        );

        // The device it runs on, whatever its row says; a row that says
        // primary, wherever the session runs.
        let mut moved = session(vec![
            tipped(Primary, Joined, 1, 5),
            tipped(Owner, Joined, 1, 9),
        ]);
        let (row, runs_on) = {
            let mm = &moved.replicaset.as_ref().unwrap().members;
            (mm[0].device_id, mm[1].device_id)
        };
        moved.location.device_id = runs_on;
        assert_eq!(
            freshest_copy(&moved, |d| d == runs_on),
            None,
            "never the device it runs on, whatever its member row says"
        );
        assert_eq!(
            freshest_copy(&moved, |d| d == row),
            None,
            "never a row whose role says primary"
        );

        let tie = session(vec![
            tipped(Primary, Joined, 1, 5),
            tipped(Owner, Joined, 1, 5),
            tipped(Archive, Joined, 1, 5),
            tipped(Owner, Joined, 1, 5),
        ]);
        let t = &tie.replicaset.as_ref().unwrap().members;
        assert_eq!(
            freshest_copy(&tie, all),
            Some(t[2].device_id),
            "an archive replica on a tie"
        );
        assert_eq!(
            freshest_copy(&tie, |d| d != t[2].device_id),
            Some(t[1].device_id.min(t[3].device_id)),
            "then the lowest device id"
        );
        let mut unplaced = tie.clone();
        unplaced.replicaset = None;
        assert_eq!(
            freshest_copy(&unplaced, all),
            None,
            "no replicaset, no copy"
        );
    }

    /// A session alone on its primary is not replicated; one with any other
    /// member is, whatever that member answered.
    #[test]
    fn a_session_is_replicated_when_it_has_another_member() {
        let alone = session(vec![member(MemberRole::Primary, MemberState::Joined)]);
        assert!(!replicated(&alone));
        let mut unplaced = alone.clone();
        unplaced.replicaset = None;
        assert!(!replicated(&unplaced));
        let two = session(vec![
            member(MemberRole::Primary, MemberState::Joined),
            member(MemberRole::Owner, MemberState::Refused),
        ]);
        assert!(replicated(&two));
    }

    /// Only members still pending get a join, each in its own role, never
    /// one that answered. The primary gets one only while it is owed one
    /// (P2c-4): pending, with a member besides it.
    #[test]
    fn pending_members_are_joined_and_the_primary_only_when_owed_one() {
        let s = session(vec![
            member(MemberRole::Primary, MemberState::Pending),
            member(MemberRole::Archive, MemberState::Pending),
            member(MemberRole::Owner, MemberState::Joined),
            member(MemberRole::Owner, MemberState::Refused),
            member(MemberRole::Owner, MemberState::Pending),
        ]);
        let m = &s.replicaset.as_ref().unwrap().members;
        assert_eq!(
            pending(&s),
            [
                (m[0].device_id, HiveReplicaRole::Primary),
                (m[1].device_id, HiveReplicaRole::Archive),
                (m[4].device_id, HiveReplicaRole::Owner),
            ]
        );

        let told = session(vec![
            member(MemberRole::Primary, MemberState::Joined),
            member(MemberRole::Owner, MemberState::Pending),
        ]);
        let m = &told.replicaset.as_ref().unwrap().members;
        assert_eq!(
            pending(&told),
            [(m[1].device_id, HiveReplicaRole::Owner)],
            "a primary the start told is owed nothing"
        );

        // A primary with no member besides it holds nothing to tell: one
        // placed before P2c-3 has no state, and reads as pending.
        let alone = session(vec![member(MemberRole::Primary, MemberState::Pending)]);
        assert!(pending(&alone).is_empty());
    }

    /// P2e-5b — a join carries the record's `fences` as they stand, oldest
    /// first, and leaves out a mark no promotion could have written rather
    /// than send it wrapped.
    #[test]
    fn a_join_carries_the_records_fence_ends() {
        let mut s = session(vec![member(MemberRole::Primary, MemberState::Joined)]);
        assert!(fence_marks(&s).is_empty(), "never moved: none");
        let mark = |fence, seq| crate::model::FenceMark {
            fence,
            seq,
            hash: format!("{fence:02x}").repeat(32),
        };
        s.fences = vec![mark(1, 5), mark(2, 9), mark(-3, 9), mark(4, -1)];
        assert_eq!(
            fence_marks(&s),
            [
                HiveFenceMark {
                    fence: 1,
                    seq: 5,
                    hash: "01".repeat(32),
                },
                HiveFenceMark {
                    fence: 2,
                    seq: 9,
                    hash: "02".repeat(32),
                },
            ],
            "a mark no promotion could have written is left out"
        );
    }
}
