// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2g-3d — the device's own clock (spec §3b, "Purges and retention";
//! design §4.4: a device that misses a purge must not keep the content by
//! staying offline).
//!
//! The server says what keeps each copy this device holds (`rc:hive.retain`,
//! P2g-3c): the organization's days and, once the session is over, its end.
//! The device keeps that word in its store and purges a copy once it has
//! passed ([`deadline_ms`]), through the same parts as `rc:hive.purge`
//! (P2g-1), with no purge id. Its next manifests say so.
//!
//! | The word | The copy goes |
//! |---|---|
//! | `days` `0` | never |
//! | the session is over | `days` after its end, online or not: when the server's sweep would purge it |
//! | the session is live | never while the device is connected; offline, `days` after it last was |
//! | none (a server before P2g-3c, the switch off) | never, as before |
//!
//! | When | What |
//! |---|---|
//! | each connection, once the copies are told | it asks what keeps every session it holds ([`Supervisor::ask_retain_all`]) |
//! | a join answered `joined`, a start accepted | it asks about that session |
//! | the answer | each word for a session it holds is kept, and the clock runs at once ([`Supervisor::retain_heard`]) |
//! | every [`RETAIN_TICK`] | the clock runs ([`Supervisor::retention_tick`]); connected, it records the contact, and once a day it asks again |
//!
//! ⚠️ Never a session this device holds nothing of: purging an id is final,
//! so an unheld one would refuse every later join of it. Its word is
//! forgotten instead.
//! ⚠️ The device's own clock decides, as any expiry on a device does: one
//! set far ahead purges early, as one offline that long would.

use std::sync::Arc;
use std::time::Duration;

use bson::oid::ObjectId;
use meshharbor_hive_node::store::RetainWord;
use meshharbor_remote_control::hive::{
    HiveCopyPurged, HiveRetainWord, replica_limits, retain_limits,
};
use meshharbor_remote_control::signaling::ClientMsg;
use tracing::{debug, info, warn};

use super::Supervisor;

/// How often the clock runs: well inside any word's day.
pub(crate) const RETAIN_TICK: Duration = Duration::from_secs(10 * 60);

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// When the copy `w` keeps goes, by this device's clock (ms since the epoch):
/// `None` = not while things stay as they are. `contact_ms` is when the
/// device was last connected, as its store recorded it; `connected` whether
/// it is now.
pub(crate) fn deadline_ms(w: &RetainWord, contact_ms: Option<i64>, connected: bool) -> Option<i64> {
    if w.days == 0 {
        return None;
    }
    let span = i64::from(w.days).saturating_mul(DAY_MS);
    match w.ended_ms {
        Some(end) => Some(end.saturating_add(span)),
        None if connected => None,
        // A word is only ever heard while connected, so it is a contact too.
        None => Some(
            contact_ms
                .unwrap_or(w.said_ms)
                .max(w.said_ms)
                .saturating_add(span),
        ),
    }
}

/// This device's clock, in ms since the epoch.
pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

impl Supervisor {
    /// Whether the primary enrollment's connection is up now.
    pub(super) fn is_connected(&self) -> bool {
        self.reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|tx| !tx.is_closed())
            && self.offline_for().is_none()
    }

    /// Whether this device holds anything of `session`: its store's copy or
    /// workplace, a run of it, or a hosted entry that would resume it.
    async fn holds_here(&self, session: ObjectId) -> bool {
        let sid = session.to_hex();
        if self
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&session)
            || self
                .hosted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&sid)
                .is_some()
            || self
                .to_resume
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|h| h.session == sid)
        {
            return true;
        }
        match &self.store {
            Ok(store) => store.holds(&sid).await.unwrap_or(false),
            Err(_) => false,
        }
    }

    /// `rc:hive.retain`: each word kept for a session this device holds, a
    /// word for one it holds nothing of ignored, and the clock run at once.
    pub(crate) async fn retain_heard(self: &Arc<Self>, words: Vec<HiveRetainWord>) {
        let Ok(store) = &self.store else {
            return;
        };
        let mut kept = 0;
        for w in words {
            if !self.holds_here(w.session_id).await {
                continue;
            }
            match store
                .put_retain(&w.session_id.to_hex(), w.days, w.ended_at_ms)
                .await
            {
                Ok(()) => kept += 1,
                Err(e) => {
                    warn!(session = %w.session_id, %e, "hive: a retention word was not kept")
                }
            }
        }
        debug!(kept, "hive: retention words heard");
        self.retention_tick(now_ms()).await;
    }

    /// Ask what keeps `sessions`' copies (`rc:hive.retain_ask`), on the
    /// connection that is up now: nothing while none is.
    pub(crate) fn ask_retain(&self, sessions: Vec<ObjectId>) {
        let tx = self
            .reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(tx) = tx else {
            return;
        };
        for chunk in sessions.chunks(retain_limits::MAX_RETAIN_ASK) {
            if tx
                .try_send(ClientMsg::HiveRetainAsk {
                    sessions: chunk.to_vec(),
                })
                .is_err()
            {
                debug!("hive: a retention ask was not sent — it goes at the next connection");
                return;
            }
        }
    }

    /// Ask what keeps every session this device holds anything of.
    pub(crate) async fn ask_retain_all(&self) {
        let ids = self.held_ids().await;
        if !ids.is_empty() {
            self.ask_retain(ids);
        }
    }

    /// Every session this device holds anything of, as [`Self::holds_here`]
    /// reads one: its store's (a copy, a workplace), a run, a hosted entry,
    /// one waiting to resume. A store that cannot be read adds none.
    pub(super) async fn held_ids(&self) -> Vec<ObjectId> {
        let mut ids: Vec<ObjectId> = match &self.store {
            Ok(store) => match store.held_sessions().await {
                Ok(held) => held
                    .iter()
                    .filter_map(|s| ObjectId::parse_str(s).ok())
                    .collect(),
                Err(e) => {
                    warn!(%e, "hive: the sessions the store holds were not read");
                    Vec::new()
                }
            },
            Err(_) => Vec::new(),
        };
        ids.extend(
            self.live
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .keys()
                .copied(),
        );
        ids.extend(
            self.hosted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .sessions()
                .iter()
                .filter_map(|h| ObjectId::parse_str(&h.session).ok()),
        );
        ids.extend(
            self.to_resume
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter_map(|h| ObjectId::parse_str(&h.session).ok()),
        );
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// One run of the clock at `now_ms`, by this device's clock: connected,
    /// the contact recorded; each copy past its word purged (P2g-1's parts,
    /// under the start lock) and noted for the next manifests, and those
    /// told at once while connected. How many it purged.
    pub(crate) async fn retention_tick(self: &Arc<Self>, now_ms: i64) -> usize {
        let Ok(store) = &self.store else {
            return 0;
        };
        let connected = self.is_connected();
        if connected && let Err(e) = store.set_contact(now_ms).await {
            warn!(%e, "hive: the contact was not recorded");
        }
        let contact = store.contact().await.ok().flatten();
        let words = match store.retains().await {
            Ok(w) => w,
            Err(e) => {
                warn!(%e, "hive: the retention words were not read — the clock waits");
                return 0;
            }
        };
        let mut purged = 0;
        for w in words {
            let Some(due) = deadline_ms(&w, contact, connected) else {
                continue;
            };
            if now_ms < due {
                continue;
            }
            let Ok(session) = ObjectId::parse_str(&w.session) else {
                continue;
            };
            let parts = {
                let _serial = self.start_lock.lock().await;
                // Under the lock, so a purge that just took it is seen.
                if self.holds_here(session).await {
                    Some(self.purge_parts(session, true).await)
                } else {
                    None
                }
            };
            let Some((store_part, account, detail)) = parts else {
                if let Err(e) = store.drop_retain(&w.session).await {
                    warn!(session = %session, %e, "hive: a word for nothing held was not forgotten");
                }
                continue;
            };
            info!(
                session = %session, days = w.days, ended_ms = w.ended_ms, due_ms = due,
                store = store_part.as_str(), account = account.as_str(),
                detail = detail.as_deref().unwrap_or(""),
                "hive: purged by retention, on this device's own clock"
            );
            if let Err(e) = store.note_copy_purge(&w.session, now_ms).await {
                warn!(session = %session, %e, "hive: a copy purged on the clock was not noted for the manifest");
            }
            purged += 1;
        }
        if purged > 0 && connected {
            self.tell_copies().await;
        }
        purged
    }

    /// `rc:hive.replica.manifest`, when this device has copies to tell of or
    /// a copy its clock purged still to name: `None` otherwise.
    pub(super) async fn replica_manifest_frame(&self) -> Option<ClientMsg> {
        let pending = match &self.store {
            Ok(store) => store.has_copy_purge_reports().await.unwrap_or(false),
            Err(_) => false,
        };
        if !self.reports_copies() && !pending {
            return None;
        }
        let sessions = self.replica_manifest().await;
        let purged = match (&self.store, pending) {
            (Ok(store), true) => store
                .take_copy_purge_reports(
                    retain_limits::MAX_COPY_PURGED,
                    retain_limits::COPY_PURGED_REPORTS,
                )
                .await
                .unwrap_or_default()
                .into_iter()
                .filter_map(|(s, at_ms)| {
                    Some(HiveCopyPurged {
                        session_id: ObjectId::parse_str(&s).ok()?,
                        at_ms,
                    })
                })
                .collect(),
            _ => Vec::new(),
        };
        debug_assert!(sessions.len() <= replica_limits::MAX_REPLICA_MANIFEST);
        Some(ClientMsg::HiveReplicaManifest { sessions, purged })
    }

    /// The manifest, sent now on the connection that is up.
    async fn tell_copies(&self) {
        let Some(frame) = self.replica_manifest_frame().await else {
            return;
        };
        let tx = self
            .reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(tx) = tx {
            let _ = tx.try_send(frame);
        }
    }

    /// The clock: every [`RETAIN_TICK`] a run, and once a day, while
    /// connected, every word asked for again.
    pub(crate) fn spawn_retention_clock(self: &Arc<Self>) {
        let me = Arc::downgrade(self);
        tokio::spawn(async move {
            let every = Duration::from_secs(retain_limits::RETAIN_ASK_EVERY_SECS);
            let mut asked = tokio::time::Instant::now();
            loop {
                tokio::time::sleep(RETAIN_TICK).await;
                let Some(sup) = me.upgrade() else {
                    return;
                };
                sup.retention_tick(now_ms()).await;
                if sup.is_connected() && asked.elapsed() >= every {
                    sup.ask_retain_all().await;
                    asked = tokio::time::Instant::now();
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(days: u32, ended_ms: Option<i64>, said_ms: i64) -> RetainWord {
        RetainWord {
            session: ObjectId::new().to_hex(),
            days,
            ended_ms,
            said_ms,
        }
    }

    /// A copy goes `days` after its session's end, connected or not; a live
    /// session's copy never while connected, and offline `days` after the
    /// later of the contact and the word; `0` keeps it for ever.
    #[test]
    fn a_copy_goes_days_after_its_end_or_after_the_last_contact() {
        let day = DAY_MS;
        let over = word(30, Some(10 * day), day);
        assert_eq!(deadline_ms(&over, None, true), Some(40 * day));
        assert_eq!(deadline_ms(&over, Some(99 * day), false), Some(40 * day));

        let live = word(30, None, 5 * day);
        assert_eq!(
            deadline_ms(&live, Some(20 * day), true),
            None,
            "a live session's copy is kept while connected"
        );
        assert_eq!(deadline_ms(&live, Some(20 * day), false), Some(50 * day));
        assert_eq!(
            deadline_ms(&live, Some(2 * day), false),
            Some(35 * day),
            "a word is itself a contact"
        );
        assert_eq!(deadline_ms(&live, None, false), Some(35 * day));

        for forever in [word(0, Some(day), day), word(0, None, day)] {
            assert_eq!(deadline_ms(&forever, Some(day), false), None);
            assert_eq!(deadline_ms(&forever, Some(day), true), None);
        }
        assert_eq!(
            deadline_ms(&word(u32::MAX, Some(i64::MAX - 1), 0), None, false),
            Some(i64::MAX),
            "never a wrap"
        );
    }
}

/// The clock on a supervisor, as the daemon runs it: words heard, copies
/// purged on this device's own clock, and what the server is told.
#[cfg(all(test, unix))]
mod rig_tests {
    use super::*;
    use crate::hive::supervisor::tests::{Rig, rig};
    use tokio::sync::mpsc;

    /// A copy of `sid` this device holds: a membership in its store.
    async fn hold(r: &Rig, sid: ObjectId) {
        r.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
    }

    fn told(session_id: ObjectId, days: u32, ended_at_ms: Option<i64>) -> HiveRetainWord {
        HiveRetainWord {
            session_id,
            days,
            ended_at_ms,
        }
    }

    /// The first frame on `rx` that `pick` takes, within 10 s; `what` is the
    /// failure's words when none does.
    async fn frame<T>(
        rx: &mut mpsc::Receiver<ClientMsg>,
        what: &str,
        mut pick: impl FnMut(ClientMsg) -> Option<T>,
    ) -> T {
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .unwrap_or_else(|_| panic!("{what}: none within 10 s"))
                .expect("the connection is open");
            if let Some(t) = pick(msg) {
                return t;
            }
        }
    }

    /// What the manifest on `rx` says this device's clock purged.
    async fn purged_told(rx: &mut mpsc::Receiver<ClientMsg>) -> Vec<ObjectId> {
        frame(rx, "a manifest", |m| match m {
            ClientMsg::HiveReplicaManifest { purged, .. } => {
                Some(purged.iter().map(|p| p.session_id).collect())
            }
            _ => None,
        })
        .await
    }

    /// A word is kept only for a session held here; one for a session the
    /// device holds nothing of is ignored.
    #[tokio::test]
    async fn a_word_is_kept_only_for_a_session_held_here() {
        let r = rig(true, 4);
        let (held, other) = (ObjectId::new(), ObjectId::new());
        hold(&r, held).await;
        r.sup
            .retain_heard(vec![told(held, 90, None), told(other, 90, None)])
            .await;
        let kept: Vec<String> = r
            .store
            .retains()
            .await
            .unwrap()
            .into_iter()
            .map(|w| w.session)
            .collect();
        assert_eq!(kept, [held.to_hex()], "a word only for a session held here");
    }

    /// A copy of a session that is over goes once its days have passed since
    /// its end, at once on hearing so, and the manifest names it although
    /// the device holds no other copy; one within its days is kept, and so
    /// is one its organization keeps for ever.
    #[tokio::test]
    async fn an_ended_copy_goes_after_its_days_and_the_manifest_says_so() {
        let mut r = rig(true, 4);
        let (old, recent, forever) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        for s in [old, recent, forever] {
            hold(&r, s).await;
        }
        let ended = now_ms() - 2 * DAY_MS;
        r.sup
            .retain_heard(vec![
                told(old, 1, Some(ended)),
                told(recent, 30, Some(ended)),
                told(forever, 0, Some(ended)),
            ])
            .await;
        assert!(
            r.store.is_purged(&old.to_hex()).await.unwrap(),
            "past its days"
        );
        assert!(!r.store.holds(&old.to_hex()).await.unwrap());
        for kept in [recent, forever] {
            assert!(
                r.store.holds(&kept.to_hex()).await.unwrap(),
                "a copy within its days, or kept for ever, is kept"
            );
        }
        assert_eq!(
            purged_told(&mut r.reports).await,
            [old],
            "the manifest says so at once"
        );
        let words: Vec<String> = r
            .store
            .retains()
            .await
            .unwrap()
            .into_iter()
            .map(|w| w.session)
            .collect();
        assert!(!words.contains(&old.to_hex()), "its word went with it");
    }

    /// A live session's copy is kept while the device is connected, however
    /// long; offline, it goes once its days have passed since the device was
    /// last connected.
    #[tokio::test]
    async fn a_live_copy_goes_only_offline_after_its_days() {
        let r = rig(true, 4);
        let live = ObjectId::new();
        hold(&r, live).await;
        r.sup.retain_heard(vec![told(live, 1, None)]).await;
        let later = now_ms() + 3 * DAY_MS;
        assert_eq!(r.sup.retention_tick(later).await, 0, "connected: kept");
        assert!(r.store.holds(&live.to_hex()).await.unwrap());

        // The connection goes: the device is offline from then on.
        let Rig {
            sup,
            store,
            reports,
            root: _root,
            user: _,
        } = r;
        drop(reports);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while sup.offline_for().is_none() {
            assert!(tokio::time::Instant::now() < deadline, "never offline");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!sup.is_connected());
        let contact = store
            .contact()
            .await
            .unwrap()
            .expect("the contact the clock kept");
        assert_eq!(
            sup.retention_tick(contact + DAY_MS / 2).await,
            0,
            "offline within its days"
        );
        assert_eq!(
            sup.retention_tick(contact + 2 * DAY_MS).await,
            1,
            "offline past its days"
        );
        assert!(store.is_purged(&live.to_hex()).await.unwrap());
    }

    /// A word for a session the device holds nothing of when its time comes
    /// is forgotten, never purged: purging an id is final, and would refuse
    /// every later join of it.
    #[tokio::test]
    async fn a_word_past_its_days_for_nothing_held_purges_nothing() {
        let r = rig(true, 4);
        let gone = ObjectId::new();
        r.store
            .put_retain(&gone.to_hex(), 1, Some(now_ms() - 2 * DAY_MS))
            .await
            .unwrap();
        assert_eq!(
            r.sup.retention_tick(now_ms()).await,
            0,
            "the clock purges nothing it holds nothing of: never an unheld id"
        );
        assert!(
            !r.store.is_purged(&gone.to_hex()).await.unwrap(),
            "never an unheld id"
        );
        assert!(
            r.store.retains().await.unwrap().is_empty(),
            "its word forgotten"
        );
    }

    /// Until an `rc:hive.retain_ask` on `rx` names `want`, in any order;
    /// `what` if none does within 10 s. Others are passed by: the
    /// connection's own ask runs in a task of its own, and may come late.
    async fn asks_for(rx: &mut mpsc::Receiver<ClientMsg>, want: &[ObjectId], what: &str) {
        let mut want = want.to_vec();
        want.sort_unstable();
        frame(rx, what, |m| match m {
            ClientMsg::HiveRetainAsk { mut sessions } => {
                sessions.sort_unstable();
                (sessions == want).then_some(())
            }
            _ => None,
        })
        .await
    }

    /// A session this device takes up asks at once what keeps it: a start
    /// accepted, and a join answered `joined`.
    #[tokio::test]
    async fn a_start_and_a_join_ask_what_keeps_their_session() {
        let mut r = crate::hive::supervisor::tests::rig_with(true, 4, |c| c.replica = true, |s| s);
        // The rig's own connection says what it says at connecting first (its
        // manifest, then an ask about what it holds, nothing yet): what
        // follows is this test's alone.
        frame(&mut r.reports, "the rig's connection manifest", |m| {
            matches!(m, ClientMsg::HiveManifest { .. }).then_some(())
        })
        .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let o = crate::hive::supervisor::tests::order(&r);
        let sid = o.session_id;
        assert!(r.sup.start(o, true).await.refused.is_none());
        asks_for(&mut r.reports, &[sid], "a start accepted asks").await;

        let copy = ObjectId::new();
        let answer = r
            .sup
            .answer_join(
                true,
                copy,
                1,
                Some(meshharbor_remote_control::hive::HiveReplicaRole::Owner),
                &[],
            )
            .await;
        assert_eq!(answer, (None, None), "joined");
        asks_for(&mut r.reports, &[copy], "a join answered joined asks").await;
        r.sup.stop(sid, 1, "owner".into());
    }

    /// Each connection asks what keeps every session the device holds, once
    /// the copies are told.
    #[tokio::test]
    async fn a_connection_asks_what_keeps_each_session_held() {
        let r = rig(true, 4);
        let (a, b) = (ObjectId::new(), ObjectId::new());
        hold(&r, a).await;
        hold(&r, b).await;
        let (tx, mut rx) = mpsc::channel(64);
        r.sup.connected(tx);
        asks_for(
            &mut rx,
            &[a, b],
            "a connection asks about every session held",
        )
        .await;
    }
}
