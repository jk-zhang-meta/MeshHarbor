// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2c-3b — the device's half of membership: its own gates on
//! `rc:hive.replica.join`, the membership its store keeps, and what it tells
//! the server back, each copy's tip (spec §3b).
//!
//! | Gate, in order | Refused with | Why |
//! |---|---|---|
//! | the primary enrollment's connection | `secondary_org` | a device holds copies for its primary organization only: another org's admin must not place its sessions on the owner's disk |
//! | P2f-1a — a teleport's join: a teleport's prepare passed here for the session, naming the fence after the join's, within `TELEPORT_ADMISSION` | `not_prepared` | the gates that let a device RUN a session (`hive_enabled`, the account, the folder) are the prepare's; a device that passed them takes the copy it will run whatever its `hive_replica` |
//! | the owner's `hive_replica`, for every other role | `replica_disabled` | the gate that survives a compromised server |
//! | a role this build can name | `other` | a newer server's word is still a refusal, never a copy held for a reason nobody here read |
//! | the owner's `hive_archive`, for an archive | `archive_disabled` | an administrator designates; the device's owner offers |
//! | the fences' ends (P2e-5b), each one readable | `other` | below the floor an end is the one way an older fence's events are taken: one the device cannot read whole is never taken in part |
//! | the store, open | `other` | |
//! | `hive_store_quota_mib` | `quota` | |
//! | not purged here | `purged` | removal is final |
//! | not below the floor | `stale_fence` | a join from before a promotion must not take the session back |
//!
//! A join that passes raises the floor to its fence and keeps the membership,
//! in one transaction (`Store::join`). The copy itself arrives with the
//! carrier (P2d).
//!
//! P2e-5b — **the fences' ends.** After a promotion every event the session
//! had is of an older fence than the floor a join raises, so a member that
//! joins then would refuse the whole history. A join carries where each
//! superseded fence ended (`fences`, the record's), kept in the same
//! transaction: the store takes such a fence's events up to its end, and at
//! the end only the event it ended with. ⚠️ Checked whole before the store
//! is asked: at most [`replica_limits::MAX_FENCE_MARKS`], each older than the
//! join's fence, in order, its hash readable. A primary's join does not read
//! them: the device runs the session, and took its history before the move.

use bson::oid::ObjectId;
use meshharbor_remote_control::hive::{
    HiveCheckpointMark, HiveCopyTip, HiveFenceMark, HiveJoinRefusal, HiveReplicaManifestEntry,
    HiveReplicaRole, is_hash_hex, replica_limits,
};
use meshharbor_remote_control::signaling::ClientMsg;
use meshharbor_hive_node::store::StoreError;
use meshharbor_hive_node::{FenceEnd, GENESIS};
use std::sync::atomic::Ordering;
use tracing::{info, warn};

use super::Supervisor;
use crate::hive::gates::HiveConfig;
use crate::hive::store::{StoreHandle, WriterError};

const MIB: u64 = 1024 * 1024;

/// The device's answer to a join: no refusal means it holds the session now;
/// otherwise the gate, and a few words for the owner.
pub(super) type JoinAnswer = (Option<HiveJoinRefusal>, Option<String>);

/// The device's own gates on a join, in order, then the join itself.
/// `prepared`: a teleport's prepare passed here for this join (P2f-1a,
/// [`Supervisor::teleport_admitted`]), which a join in the teleport's role
/// needs, and which admits nothing else.
#[allow(clippy::too_many_arguments)]
pub(super) async fn decide(
    cfg: &HiveConfig,
    store: Result<&StoreHandle, &String>,
    primary: bool,
    session: ObjectId,
    fence: u64,
    role: Option<HiveReplicaRole>,
    fences: &[HiveFenceMark],
    prepared: bool,
) -> JoinAnswer {
    let refuse = |word: HiveJoinRefusal, why: String| (Some(word), Some(why));
    if !primary {
        return refuse(
            HiveJoinRefusal::SecondaryOrg,
            "this device holds copies for its primary organization only".into(),
        );
    }
    if role == Some(HiveReplicaRole::Teleport) {
        if !prepared {
            return refuse(
                HiveJoinRefusal::NotPrepared,
                "this device was not prepared to run the session here".into(),
            );
        }
    } else if !cfg.replica {
        return refuse(
            HiveJoinRefusal::ReplicaDisabled,
            "hive_replica is off on this device".into(),
        );
    }
    let Some(role) = role else {
        return refuse(
            HiveJoinRefusal::Other,
            "a role this build cannot name".into(),
        );
    };
    // P2c-4 — the primary's join is not a member's: `answer_join` takes it
    // to `take_up_replication`, and no copy is ever held in that role.
    if role == HiveReplicaRole::Primary {
        return refuse(
            HiveJoinRefusal::Other,
            "a primary's join is not a member's".into(),
        );
    }
    if role == HiveReplicaRole::Archive && !cfg.archive {
        return refuse(
            HiveJoinRefusal::ArchiveDisabled,
            "hive_archive is off on this device".into(),
        );
    }
    let ends = match fence_ends(fence, fences) {
        Ok(ends) => ends,
        Err(why) => return refuse(HiveJoinRefusal::Other, why),
    };
    let store = match store {
        Ok(s) => s,
        Err(e) => {
            return refuse(
                HiveJoinRefusal::Other,
                format!("the replica store is unavailable: {e}"),
            );
        }
    };
    if let Some(quota) = cfg.store_quota_mib {
        match store.size_bytes().await {
            Ok(size) if size >= u64::from(quota) * MIB => {
                return refuse(
                    HiveJoinRefusal::Quota,
                    format!("the replica store is at its quota ({quota} MiB)"),
                );
            }
            Ok(_) => {}
            Err(e) => {
                return refuse(
                    HiveJoinRefusal::Other,
                    format!("the replica store's size could not be read: {e}"),
                );
            }
        }
    }
    match store
        .join_with_ends(&session.to_hex(), role.as_str(), fence, ends)
        .await
    {
        Ok(_) => (None, None),
        Err(WriterError::Store(StoreError::Purged { .. })) => refuse(
            HiveJoinRefusal::Purged,
            "this device purged the session, and removal is final".into(),
        ),
        Err(WriterError::Store(StoreError::StaleJoin { floor, .. })) => refuse(
            HiveJoinRefusal::StaleFence,
            format!("this device holds the session at fence {floor}"),
        ),
        Err(e) => refuse(
            HiveJoinRefusal::Other,
            format!("the replica store refused the join: {e}"),
        ),
    }
}

/// P2e-5b — a join's `fences` as the store keeps them, or why the join is
/// refused whole: more than [`replica_limits::MAX_FENCE_MARKS`], a fence not
/// older than the join's, two out of order or twice, or a hash that is not
/// one. A server of this build sends none of those; a join that carries one
/// is not a join this device can read, and no part of it is taken.
fn fence_ends(fence: u64, marks: &[HiveFenceMark]) -> Result<Vec<FenceEnd>, String> {
    if marks.len() > replica_limits::MAX_FENCE_MARKS {
        return Err(format!(
            "the join names {} fences' ends, more than {}",
            marks.len(),
            replica_limits::MAX_FENCE_MARKS
        ));
    }
    let mut ends: Vec<FenceEnd> = Vec::with_capacity(marks.len());
    for m in marks {
        if m.fence >= fence {
            return Err(format!(
                "the join at fence {fence} names the end of fence {}, not an older one",
                m.fence
            ));
        }
        if ends.last().is_some_and(|prev| prev.fence >= m.fence) {
            return Err("the join names its fences' ends out of order".into());
        }
        let mut hash = [0u8; 32];
        if !is_hash_hex(&m.hash) || hex::decode_to_slice(&m.hash, &mut hash).is_err() {
            return Err(format!("the end of fence {} is not a hash", m.fence));
        }
        ends.push(FenceEnd {
            fence: m.fence,
            seq: m.seq,
            hash,
        });
    }
    Ok(ends)
}

/// Where this device's copy of `session` ends, as the replica frames carry
/// it: the tip, and the newest checkpoint. A member that holds nothing yet
/// says `seq` 0 at its floor, which is how the server learns it joined and
/// waits for the carrier.
pub(super) async fn tip_of(
    store: &StoreHandle,
    session: ObjectId,
) -> Option<HiveReplicaManifestEntry> {
    let sid = session.to_hex();
    let (fence, seq, hash) = match store.chain_tip(&sid).await {
        Ok(Some(t)) => (t.fence, t.seq, t.hash),
        Ok(None) => (store.floor(&sid).await.ok().flatten()?, 0, GENESIS),
        Err(e) => {
            warn!(session = %session, %e, "hive: a copy's tip could not be read");
            return None;
        }
    };
    let checkpoint = store
        .last_of_kind(&sid, "checkpoint")
        .await
        .ok()
        .flatten()
        .map(|env| HiveCheckpointMark {
            seq: env.seq,
            hash: hex::encode(env.hash()),
        });
    Some(HiveReplicaManifestEntry {
        session_id: session,
        fence,
        seq,
        hash: hex::encode(hash),
        checkpoint,
    })
}

impl Supervisor {
    /// The device's answer to a join, from its config and store, logged. A
    /// primary's (P2c-4) is about a session it runs, not a copy it holds, so
    /// the fences' ends (P2e-5b) are a member's alone.
    pub(super) async fn answer_join(
        &self,
        primary: bool,
        session: ObjectId,
        fence: u64,
        role: Option<HiveReplicaRole>,
        fences: &[HiveFenceMark],
    ) -> JoinAnswer {
        let answer = match role {
            Some(HiveReplicaRole::Primary) => {
                self.take_up_replication(primary, session, fence).await
            }
            member => {
                let prepared = member == Some(HiveReplicaRole::Teleport)
                    && self.teleport_admitted(session, fence);
                decide(
                    &self.cfg,
                    self.store.as_ref(),
                    primary,
                    session,
                    fence,
                    member,
                    fences,
                    prepared,
                )
                .await
            }
        };
        info!(
            session = %session, fence, role = role.map(HiveReplicaRole::as_str), ends = fences.len(),
            refused = answer.0.map(HiveJoinRefusal::as_str), detail = answer.1.as_deref(),
            "hive: a join answered"
        );
        // P2g-3d — a copy this device holds now, or a session it runs that
        // has members now: what keeps it.
        if answer.0.is_none() {
            self.ask_retain(vec![session]);
        }
        answer
    }

    /// P2c-4 — `join {role: primary}`: the session this device runs has
    /// members now, so each turn's end is checkpointed from here on, and
    /// after a restart too. Idempotent. Refused on a secondary org's
    /// connection, and when this device runs the session at another fence.
    /// `hive_replica` is not asked: the device holds no copy of another's
    /// session, only its own run. P2e-5c — one for a session it does not
    /// run yet is a promotion's, ahead of its start ([`Self::ahead_of_start`]).
    /// P2f-1a — the run here is told: its first checkpoint now when no turn
    /// runs, and where its copy ends either way ([`Self::tell_replicated`]).
    ///
    /// ⚠️ The record, then the live session, then the record again if it was
    /// not there yet. A session resuming now reads its record once it is live
    /// (`launch`); a new one writes its record from the live flag, under the
    /// record's lock. Either way a join that lands between the two is kept.
    pub(super) async fn take_up_replication(
        &self,
        primary: bool,
        session: ObjectId,
        fence: u64,
    ) -> JoinAnswer {
        let refuse = |word: HiveJoinRefusal, why: String| (Some(word), Some(why));
        if !primary {
            return refuse(
                HiveJoinRefusal::SecondaryOrg,
                "agent sessions run only for this device's primary organization".into(),
            );
        }
        // Its record would not keep the change: the next daemon is asked
        // again, at its first connection.
        if self.going_down() {
            return refuse(HiveJoinRefusal::Other, "this device is restarting".into());
        }
        let sid = session.to_hex();
        let mark = || {
            let mut held = None;
            self.hosted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .update(&sid, |h| {
                    held = Some(h.fence);
                    if h.fence == fence {
                        h.replicated = true;
                    }
                });
            held
        };
        let hosted_at = mark();
        // P2f-1a — the run at the join's fence, its input, and whether this
        // join is what turned it replicated.
        let live = self
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&session)
            .map(|l| {
                let here = (l.fence == fence).then(|| {
                    let turned = !l.replicated.swap(true, Ordering::SeqCst);
                    (l.input.clone(), turned)
                });
                (l.fence, here)
            });
        if hosted_at.is_none() {
            mark();
        }
        let live_at = live.as_ref().map(|(f, _)| *f);
        match live_at.or(hosted_at) {
            Some(f) if f == fence => {
                if let Some((_, Some((input, turned)))) = live {
                    self.tell_replicated(session, &input, turned).await;
                }
                (None, None)
            }
            Some(f) if f > fence => refuse(
                HiveJoinRefusal::StaleFence,
                format!("this device runs the session at fence {f}"),
            ),
            Some(f) => refuse(
                HiveJoinRefusal::Other,
                format!("this device runs the session at fence {f}, before the join's"),
            ),
            None => self.ahead_of_start(session, fence).await,
        }
    }

    /// P2f-1a — a primary's join was taken up for the run here: one it
    /// turned replicated takes its first checkpoint now when no turn runs
    /// (`checkpoint_now`), and says where its copy ends with it; one that was
    /// replicated already says so at once. Either way the server hears how
    /// far a member that joins now has to catch up, which a teleport waits
    /// for before it drains the session. A run whose input is full is told
    /// nothing, and says where its copy ends at once.
    async fn tell_replicated(
        &self,
        session: ObjectId,
        input: &tokio::sync::mpsc::Sender<super::Input>,
        turned: bool,
    ) {
        if turned && input.try_send(super::Input::Replicated).is_ok() {
            return;
        }
        self.report_tip(session).await;
    }

    /// P2e-5c — `join {role: primary}` for a session this device does not
    /// run yet: a promotion's target hears it before its start, and so does
    /// the device a refused moved start moves the session back to
    /// (`promote::before_start` on the server). Taken up when the device
    /// holds the session's copy: its floor rises to the join's fence first,
    /// so nothing of an older fence is taken from here on, before the start
    /// at that fence writes (spec §3b, "every member's floor is the new fence
    /// before the new primary writes: the target's with its join"). The
    /// start says `replicated` itself, so nothing else is marked.
    ///
    /// ⚠️ Before P2e-5c this was refused (`other`, "this device does not
    /// run the session"), and after every real move the target's own row read
    /// refused until it next connected. A device that holds nothing of the
    /// session, or holds it at a newer floor, is still refused.
    async fn ahead_of_start(&self, session: ObjectId, fence: u64) -> JoinAnswer {
        let refuse = |word: HiveJoinRefusal, why: String| (Some(word), Some(why));
        let not_here = || {
            refuse(
                HiveJoinRefusal::Other,
                "this device does not run the session".into(),
            )
        };
        let Ok(store) = &self.store else {
            return not_here();
        };
        let sid = session.to_hex();
        match store.chain_tip(&sid).await {
            Ok(Some(_)) => {}
            Ok(None) => return not_here(),
            Err(e) => {
                return refuse(
                    HiveJoinRefusal::Other,
                    format!("the replica store could not be read: {e}"),
                );
            }
        }
        match store.raise_floor(&sid, fence).await {
            Ok(floor) if floor > fence => refuse(
                HiveJoinRefusal::StaleFence,
                format!("this device holds the session at fence {floor}"),
            ),
            Ok(_) => (None, None),
            Err(WriterError::Store(StoreError::Purged { .. })) => refuse(
                HiveJoinRefusal::Purged,
                "this device purged the session, and removal is final".into(),
            ),
            Err(e) => refuse(
                HiveJoinRefusal::Other,
                format!("the replica store refused the floor: {e}"),
            ),
        }
    }

    /// Whether this device has copies to tell the server about: its owner
    /// lets it hold copies, or it runs a replicated session, or (P2f-1a) it
    /// was prepared for a teleport, whose copy it takes. Every other device
    /// sends no replica frame, so a server from before P2c-3 never hears a
    /// word it cannot read.
    pub(super) fn reports_copies(&self) -> bool {
        self.cfg.replica
            || self
                .live
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .any(|l| l.replicated.load(Ordering::SeqCst))
            || self.prepared_for_teleport()
    }

    /// Every session this device holds a copy of, as a member or as the
    /// replicated session's primary, each with its tip: what
    /// `rc:hive.replica.manifest` carries. Newest first, at most
    /// [`replica_limits::MAX_REPLICA_MANIFEST`].
    pub(super) async fn replica_manifest(&self) -> Vec<HiveReplicaManifestEntry> {
        let Ok(store) = &self.store else {
            return Vec::new();
        };
        let mut ids: Vec<ObjectId> = self
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(_, l)| l.replicated.load(Ordering::SeqCst))
            .map(|(id, _)| *id)
            .collect();
        match store.memberships().await {
            Ok(held) => ids.extend(
                held.iter()
                    .filter_map(|m| ObjectId::parse_str(&m.session).ok()),
            ),
            Err(e) => warn!(%e, "hive: the memberships could not be read for the manifest"),
        }
        // An ObjectId sorts by when it was made: newest first.
        ids.sort_unstable_by(|a, b| b.cmp(a));
        ids.dedup();
        ids.truncate(replica_limits::MAX_REPLICA_MANIFEST);
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(tip) = tip_of(store, id).await {
                out.push(tip);
            }
        }
        out
    }

    /// P2e-6a — where this device's copy of `session` ends, as
    /// `rc:hive.prepare_ack` names it: what a promotion away from an
    /// unreachable primary moves the lease to.
    pub(super) async fn copy_tip(&self, session: ObjectId) -> Option<HiveCopyTip> {
        let Ok(store) = &self.store else {
            return None;
        };
        tip_of(store, session).await.map(|t| HiveCopyTip {
            fence: t.fence,
            seq: t.seq,
            hash: t.hash,
        })
    }

    /// A replicated session's checkpoint was kept: tell the server where its
    /// copy ends now (`rc:hive.replica.tip`).
    pub(super) async fn report_tip(&self, session: ObjectId) {
        let Ok(store) = &self.store else {
            return;
        };
        let Some(tip) = tip_of(store, session).await else {
            return;
        };
        let tx = self
            .reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(tx) = tx {
            let _ = tx.try_send(ClientMsg::HiveReplicaTip {
                session_id: tip.session_id,
                fence: tip.fence,
                seq: tip.seq,
                hash: tip.hash,
                checkpoint: tip.checkpoint,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_hive_node::{EventEnvelope, TranscriptEvent};

    fn cfg(replica: bool, archive: bool, quota: Option<u32>) -> HiveConfig {
        let mut agent = crate::config::test_fixture();
        agent.hive_replica = replica;
        agent.hive_archive = archive;
        agent.hive_store_quota_mib = quota;
        HiveConfig::from_agent(&agent)
    }

    async fn answer(
        cfg: &HiveConfig,
        store: &StoreHandle,
        primary: bool,
        session: ObjectId,
        fence: u64,
        role: Option<HiveReplicaRole>,
    ) -> Option<HiveJoinRefusal> {
        decide(cfg, Ok(store), primary, session, fence, role, &[], false)
            .await
            .0
    }

    /// Each gate in order, and a join that passes them keeps the membership
    /// and raises the floor.
    #[tokio::test]
    async fn a_join_passes_the_devices_own_gates_or_names_the_one_it_failed() {
        let store = StoreHandle::spawn(None).unwrap();
        let sid = ObjectId::new();
        let owner = Some(HiveReplicaRole::Owner);
        let archive = Some(HiveReplicaRole::Archive);
        let on = cfg(true, false, None);
        assert_eq!(
            answer(&on, &store, false, sid, 1, owner).await,
            Some(HiveJoinRefusal::SecondaryOrg)
        );
        assert_eq!(
            answer(&cfg(false, false, None), &store, true, sid, 1, owner).await,
            Some(HiveJoinRefusal::ReplicaDisabled)
        );
        assert_eq!(
            answer(&on, &store, true, sid, 1, None).await,
            Some(HiveJoinRefusal::Other),
            "a role this build cannot name"
        );
        assert_eq!(
            answer(&on, &store, true, sid, 1, Some(HiveReplicaRole::Primary)).await,
            Some(HiveJoinRefusal::Other),
            "a primary's join is never a member's"
        );
        assert_eq!(
            answer(&on, &store, true, sid, 1, archive).await,
            Some(HiveJoinRefusal::ArchiveDisabled)
        );
        let missing = "no store".to_string();
        assert_eq!(
            decide(&on, Err(&missing), true, sid, 1, owner, &[], false)
                .await
                .0,
            Some(HiveJoinRefusal::Other)
        );
        assert_eq!(
            answer(&cfg(true, false, Some(0)), &store, true, sid, 1, owner).await,
            Some(HiveJoinRefusal::Quota),
            "a quota the store is already at"
        );
        assert!(
            store.memberships().await.unwrap().is_empty(),
            "nothing refused was kept"
        );

        assert_eq!(answer(&on, &store, true, sid, 2, owner).await, None);
        assert_eq!(store.floor(&sid.to_hex()).await.unwrap(), Some(2));
        assert_eq!(
            answer(&cfg(true, true, None), &store, true, sid, 2, archive).await,
            None,
            "an archive whose owner offers it"
        );
        assert_eq!(
            answer(&on, &store, true, sid, 1, owner).await,
            Some(HiveJoinRefusal::StaleFence),
            "a join from before the floor"
        );
        store.purge(&sid.to_hex()).await.unwrap();
        assert_eq!(
            answer(&on, &store, true, sid, 3, owner).await,
            Some(HiveJoinRefusal::Purged)
        );
    }

    /// P2f-1a — a join in the teleport's role passes only where a teleport's
    /// prepare passed for it, and then whatever the owner's `hive_replica`:
    /// `hive_replica` on is no prepare, a prepare admits no other role, and
    /// a secondary org's connection takes nothing. The store's own gates
    /// still apply, and the membership it keeps is the teleport's.
    #[tokio::test]
    async fn a_teleports_join_passes_only_where_its_prepare_did() {
        let store = StoreHandle::spawn(None).unwrap();
        let sid = ObjectId::new();
        let teleport = Some(HiveReplicaRole::Teleport);
        let off = cfg(false, false, None);
        let at = |cfg: HiveConfig, primary: bool, role, prepared: bool| {
            let store = store.clone();
            async move {
                decide(&cfg, Ok(&store), primary, sid, 1, role, &[], prepared)
                    .await
                    .0
            }
        };
        assert_eq!(
            at(off.clone(), true, teleport, false).await,
            Some(HiveJoinRefusal::NotPrepared),
            "nobody prepared it"
        );
        assert_eq!(
            at(cfg(true, false, None), true, teleport, false).await,
            Some(HiveJoinRefusal::NotPrepared),
            "hive_replica on is no prepare"
        );
        assert_eq!(
            at(off.clone(), false, teleport, true).await,
            Some(HiveJoinRefusal::SecondaryOrg)
        );
        assert_eq!(
            at(off.clone(), true, Some(HiveReplicaRole::Owner), true).await,
            Some(HiveJoinRefusal::ReplicaDisabled),
            "a prepare admits the teleport's role only"
        );
        assert_eq!(
            at(cfg(false, false, Some(0)), true, teleport, true).await,
            Some(HiveJoinRefusal::Quota),
            "the store's quota still holds"
        );
        assert!(
            store.memberships().await.unwrap().is_empty(),
            "nothing refused was kept"
        );
        assert_eq!(
            at(off, true, teleport, true).await,
            None,
            "prepared: it takes the copy it will run, hive_replica off"
        );
        let held = store.memberships().await.unwrap();
        assert_eq!(
            held.iter()
                .map(|m| (m.session.as_str(), m.role.as_str(), m.fence))
                .collect::<Vec<_>>(),
            [(sid.to_hex().as_str(), "teleport", 1)]
        );
    }

    /// P2e-5b — a join after a move names where the fence it superseded
    /// ended: the member takes that fence's events below its new floor up to
    /// there, and none past it. Ends it cannot read whole refuse the join,
    /// and nothing of it is kept.
    #[tokio::test]
    async fn a_join_keeps_the_fences_ends_or_refuses_them_whole() {
        let on = cfg(true, false, None);
        let owner = Some(HiveReplicaRole::Owner);
        let sid = ObjectId::new();
        let s = sid.to_hex();
        let note = |tip, n: &str| {
            EventEnvelope::next(&s, tip, 1, 1, &TranscriptEvent::Note { text: n.into() })
        };
        let first = note(None, "one");
        let second = note(Some(first.tip()), "two");
        let end = |seq, hash: String| HiveFenceMark {
            fence: 1,
            seq,
            hash,
        };
        let ended = [end(2, hex::encode(second.hash()))];

        // One end for each fence below a join far above them, in order: only
        // their number is wrong.
        let many: Vec<HiveFenceMark> = (1..=replica_limits::MAX_FENCE_MARKS as u64 + 1)
            .map(|fence| HiveFenceMark {
                fence,
                ..ended[0].clone()
            })
            .collect();

        let store = StoreHandle::spawn(None).unwrap();
        for (case, at, marks) in [
            ("more than a join may name", 1000, many),
            (
                "not older than the join",
                2,
                vec![HiveFenceMark {
                    fence: 2,
                    ..ended[0].clone()
                }],
            ),
            ("twice", 2, vec![ended[0].clone(), ended[0].clone()]),
            ("not a hash", 2, vec![end(2, "AB".repeat(32))]),
            ("short", 2, vec![end(2, "ab".repeat(31))]),
        ] {
            let (word, why) = decide(&on, Ok(&store), true, sid, at, owner, &marks, false).await;
            assert_eq!(word, Some(HiveJoinRefusal::Other), "{case}: {why:?}");
            assert!(why.is_some(), "{case}: says why");
            assert!(store.memberships().await.unwrap().is_empty(), "{case}");
            assert_eq!(store.floor(&s).await.unwrap(), None, "{case}: no floor");
        }

        assert_eq!(
            decide(&on, Ok(&store), true, sid, 2, owner, &ended, false).await,
            (None, None)
        );
        store
            .apply(first.clone())
            .await
            .expect("below the floor, fence 1 is taken up to its end");
        store.apply(second.clone()).await.unwrap();
        let late = note(Some(second.tip()), "the old primary, past its end");
        assert!(
            matches!(
                store.apply(late).await,
                Err(WriterError::Store(StoreError::Chain(
                    meshharbor_hive_node::ChainError::StaleFence { .. }
                )))
            ),
            "past its end, the old primary's late write"
        );

        // Before P2e-5b: the same join naming no end, the history refused.
        let without = StoreHandle::spawn(None).unwrap();
        assert_eq!(
            decide(&on, Ok(&without), true, sid, 2, owner, &[], false).await,
            (None, None)
        );
        assert!(
            without.apply(first).await.is_err(),
            "before P2e-5b: the history below the floor, refused"
        );
    }

    /// A member that holds nothing yet says `seq` 0 at its floor; one that
    /// holds events says its tip and its newest checkpoint.
    #[tokio::test]
    async fn a_copys_tip_is_its_chain_end_and_newest_checkpoint() {
        let store = StoreHandle::spawn(None).unwrap();
        let sid = ObjectId::new();
        assert!(tip_of(&store, sid).await.is_none(), "not held at all");
        store.join(&sid.to_hex(), "owner", 3).await.unwrap();
        let empty = tip_of(&store, sid).await.unwrap();
        assert_eq!(
            (
                empty.fence,
                empty.seq,
                empty.hash.as_str(),
                empty.checkpoint
            ),
            (3, 0, "0".repeat(64).as_str(), None)
        );

        let first = EventEnvelope::next(
            &sid.to_hex(),
            None,
            3,
            1,
            &TranscriptEvent::Note { text: "one".into() },
        );
        let tip = store.apply(first).await.unwrap();
        let held = tip_of(&store, sid).await.unwrap();
        assert_eq!((held.fence, held.seq), (3, 1));
        assert_eq!(held.hash, hex::encode(tip.hash));
        assert!(meshharbor_remote_control::hive::is_hash_hex(&held.hash));
        assert_eq!(held.checkpoint, None, "no checkpoint yet");
    }
}
