// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-27 — the live remote-control session registry.
//!
//! "Who is watching my screen, and how do I stop them" existed only inside the
//! Windows-native overlay: the daemon knew, but nothing else could ask. There
//! was no LocalAPI verb for a live session, so the desktop companion could not
//! render a banner on any platform and no thin client could offer a Disconnect.
//!
//! This is the shared handle that fixes that. One instance per daemon, created
//! in `run_cmd` and given to BOTH the LocalAPI's `DaemonState` (which reads it)
//! and every signalling loop's [`crate::indicator::ViewerIndicator`] (which
//! writes it, at the same two call sites that already raise and clear the
//! on-screen indicator — so a session cannot appear in one and not the other).
//!
//! ⚠️ Each entry carries its OWN loop's kill channel, not a process-global one.
//! A multi-org daemon runs one signalling loop per enrollment, and a session
//! belongs to exactly one of them; a single shared sender would have to guess.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use bson::oid::ObjectId;
use tunnel_core::localapi::RcSessionInfo;

/// FR-93 P6h — sessions whose capture is parked on the desktop's own dialog,
/// with how many live marks hold each. Process-global rather than a registry
/// field: the capture open that knows it runs far from the registry's owner,
/// and an `ObjectId` names one session daemon-wide.
static ASKING: LazyLock<Mutex<HashMap<ObjectId, usize>>> = LazyLock::new(Mutex::default);

/// `ROOMLERD_BANNER_WAITS_FOR_DIALOG=0` — never mark a session as asking, so
/// the banner shows from the session's start, as before P6h.
fn asking_marks_enabled() -> bool {
    tunnel_core::env::flag("BANNER_WAITS_FOR_DIALOG", true)
}

/// While one lives, `session` lists with `asking` set: the desktop's own
/// dialog is asking the person at the screen to share it, so nothing is
/// shared yet. Dropping it — the open returned, or moved on to another
/// wait — takes the mark away.
pub struct AskingMark(Option<ObjectId>);

impl AskingMark {
    pub fn new(session: ObjectId) -> Self {
        if !asking_marks_enabled() {
            return Self(None);
        }
        *ASKING
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(session)
            .or_default() += 1;
        Self(Some(session))
    }
}

impl Drop for AskingMark {
    fn drop(&mut self) {
        let Some(session) = self.0 else {
            return;
        };
        let mut map = ASKING.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = map.get_mut(&session) {
            *n -= 1;
            if *n == 0 {
                map.remove(&session);
            }
        }
    }
}

fn asking(session: &ObjectId) -> bool {
    ASKING
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains_key(session)
}

/// The channel a signalling loop polls for "the person at this device wants
/// this session gone" — the same one the Windows overlay's Disconnect button
/// fires through, so a LocalAPI disconnect and an overlay click take the
/// identical teardown path.
pub type KillSender = tokio::sync::mpsc::Sender<ObjectId>;

#[derive(Clone)]
struct Entry {
    controller_name: String,
    permissions: String,
    org: String,
    started_at_ms: u64,
    kill: KillSender,
    /// FR-85 P3 — this controller is recording the screen.
    recording: bool,
    /// FR-85 P3b-3 — the session ended while recording, and the entry stays
    /// for the recording's re-attach grace: the banner says "reconnecting".
    detached: bool,
}

/// Cheap to clone; every clone sees the same map.
#[derive(Clone, Default)]
pub struct RcSessionRegistry {
    inner: Arc<Mutex<HashMap<ObjectId, Entry>>>,
}

impl RcSessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// A session became visible on this device. Idempotent — a re-announce
    /// replaces the entry rather than duplicating it, matching
    /// `ViewerIndicator::show_session`.
    pub fn insert(
        &self,
        session: ObjectId,
        controller_name: String,
        permissions: String,
        org: String,
        kill: KillSender,
    ) {
        let started_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut map = self.inner.lock().unwrap();
        // ⚠️ A re-announce must not clear a recording in progress: the banner
        // saying "recording" is the host's only notice of it.
        let recording = map.get(&session).is_some_and(|e| e.recording);
        map.insert(
            session,
            Entry {
                controller_name,
                permissions,
                org,
                started_at_ms,
                kill,
                recording,
                detached: false,
            },
        );
    }

    pub fn remove(&self, session: &ObjectId) {
        self.inner.lock().unwrap().remove(session);
    }

    /// FR-85 P3b-3 — `session` ended. Its entry goes, UNLESS it is recording:
    /// a remote recording outlives its session for the re-attach grace, and
    /// the banner must keep saying so. `true` = the entry was kept (detached).
    pub fn session_ended(&self, session: &ObjectId) -> bool {
        let mut map = self.inner.lock().unwrap();
        match map.get_mut(session) {
            Some(e) if e.recording => {
                e.detached = true;
                true
            }
            _ => {
                map.remove(session);
                false
            }
        }
    }

    /// FR-85 P3b-3 — the recording of `session` ended, or moved to its
    /// controller's next session. The entry stops saying "recording"; one
    /// that was kept only for the recording (its session gone) is removed.
    /// `true` = removed.
    pub fn recording_ended(&self, session: &ObjectId) -> bool {
        let mut map = self.inner.lock().unwrap();
        match map.get_mut(session) {
            Some(e) if e.detached => {
                map.remove(session);
                true
            }
            Some(e) => {
                e.recording = false;
                false
            }
            None => false,
        }
    }

    /// FR-85 P3 — mark `session` as recording (or not). `false` = no such
    /// live session, which the caller must treat as "nothing on screen says
    /// so" — a recording is never started behind a banner that is not there.
    pub fn set_recording(&self, session: &ObjectId, recording: bool) -> bool {
        match self.inner.lock().unwrap().get_mut(session) {
            Some(e) => {
                e.recording = recording;
                true
            }
            None => false,
        }
    }

    /// Snapshot for the LocalAPI, oldest first — a banner listing several
    /// viewers should not reorder itself between polls.
    pub fn list(&self) -> Vec<RcSessionInfo> {
        let mut out: Vec<(u64, RcSessionInfo)> = self
            .inner
            .lock()
            .unwrap()
            .iter()
            .map(|(id, e)| {
                (
                    e.started_at_ms,
                    RcSessionInfo {
                        session_id: id.to_hex(),
                        controller_name: e.controller_name.clone(),
                        permissions: e.permissions.clone(),
                        org: e.org.clone(),
                        started_at_ms: e.started_at_ms,
                        recording: e.recording,
                        reconnecting: e.detached,
                        asking: asking(id),
                    },
                )
            })
            .collect();
        out.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| a.1.session_id.cmp(&b.1.session_id))
        });
        out.into_iter().map(|(_, s)| s).collect()
    }

    /// Ask the owning signalling loop to tear `session` down. `false` = no such
    /// live session (already gone, or never on this device).
    ///
    /// Deliberately does NOT remove the entry: the signalling loop owns the
    /// lifecycle and clears it through `hide_session` once the peer is
    /// actually closed. Removing it here would make the banner disappear
    /// before the session had, which is the wrong way round for a control the
    /// operator is watching for an effect.
    pub fn disconnect(&self, session: &ObjectId) -> bool {
        // FR-85 P3b-3 — a DETACHED entry has no session left to tear down
        // (only its recording remains, which the banner's Stop ends).
        let Some(kill) = self
            .inner
            .lock()
            .unwrap()
            .get(session)
            .filter(|e| !e.detached)
            .map(|e| e.kill.clone())
        else {
            return false;
        };
        // `try_send` on purpose: this runs on the LocalAPI's sync dispatch, and
        // a full 4-slot kill queue means several teardowns are already in
        // flight — reporting that honestly beats blocking the control socket.
        match kill.try_send(*session) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(%session, %e, "rc disconnect could not be queued");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg_with(
        n: usize,
    ) -> (
        RcSessionRegistry,
        Vec<ObjectId>,
        tokio::sync::mpsc::Receiver<ObjectId>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let reg = RcSessionRegistry::new();
        let ids: Vec<ObjectId> = (0..n).map(|_| ObjectId::new()).collect();
        for (i, id) in ids.iter().enumerate() {
            reg.insert(
                *id,
                format!("viewer{i}"),
                "VIEW | INPUT".into(),
                String::new(),
                tx.clone(),
            );
        }
        (reg, ids, rx)
    }

    #[tokio::test]
    async fn disconnect_routes_to_the_owning_loop() {
        let (reg, ids, mut rx) = reg_with(2);
        assert!(reg.disconnect(&ids[1]));
        assert_eq!(rx.recv().await, Some(ids[1]));
        // The entry SURVIVES the request — the signalling loop clears it once
        // the peer is really closed, so the banner does not vanish early.
        assert_eq!(reg.list().len(), 2);
    }

    #[tokio::test]
    async fn disconnecting_an_unknown_session_is_a_clean_false() {
        let (reg, _ids, _rx) = reg_with(1);
        assert!(!reg.disconnect(&ObjectId::new()));
    }

    /// A dead loop (its receiver dropped) must report failure rather than
    /// silently swallowing the click — the operator is watching for an effect.
    #[tokio::test]
    async fn a_closed_kill_channel_reports_failure() {
        let (reg, ids, rx) = reg_with(1);
        drop(rx);
        assert!(!reg.disconnect(&ids[0]));
    }

    #[test]
    fn list_is_stable_and_carries_the_grant() {
        let (reg, ids, _rx) = reg_with(3);
        let a = reg.list();
        let b = reg.list();
        assert_eq!(a, b, "two polls must not reorder the banner");
        assert_eq!(a.len(), 3);
        assert!(a.iter().all(|s| s.permissions == "VIEW | INPUT"));
        let listed: std::collections::HashSet<String> =
            a.iter().map(|s| s.session_id.clone()).collect();
        for id in &ids {
            assert!(listed.contains(&id.to_hex()));
        }
    }

    #[test]
    fn remove_drops_the_session() {
        let (reg, ids, _rx) = reg_with(2);
        reg.remove(&ids[0]);
        let left = reg.list();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].session_id, ids[1].to_hex());
    }

    /// FR-85 P3 — the banner's "recording" follows the session, survives a
    /// re-announce (which would otherwise hide a recording in progress), and
    /// cannot be set on a session the banner does not show.
    #[test]
    fn recording_is_marked_per_session_and_survives_a_re_announce() {
        let (reg, ids, _rx) = reg_with(2);
        assert!(reg.list().iter().all(|s| !s.recording));
        assert!(reg.set_recording(&ids[1], true));
        let listed = reg.list();
        assert!(!listed[0].recording && listed[1].recording);

        let (tx, _rx2) = tokio::sync::mpsc::channel(1);
        reg.insert(ids[1], "viewer1".into(), "VIEW".into(), String::new(), tx);
        assert!(
            reg.list()[1].recording,
            "a re-announce cleared a recording the host must still see"
        );

        assert!(reg.set_recording(&ids[1], false));
        assert!(reg.list().iter().all(|s| !s.recording));
        assert!(
            !reg.set_recording(&ObjectId::new(), true),
            "no banner, no recording"
        );
    }

    /// FR-85 P3b-3 — a session that ends while RECORDING keeps its banner
    /// entry, marked reconnecting, for as long as the recording lasts; one
    /// that was only watching goes at once. When the recording ends (or moves
    /// to the controller's next session), the kept entry goes too.
    #[test]
    fn a_recording_keeps_its_banner_after_its_session_ends() {
        let (reg, ids, _rx) = reg_with(2);
        assert!(reg.set_recording(&ids[1], true));
        assert!(!reg.session_ended(&ids[0]), "a watcher's entry is not kept");
        assert!(reg.session_ended(&ids[1]), "a recording's entry is kept");
        let listed = reg.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].session_id, ids[1].to_hex());
        assert!(listed[0].recording && listed[0].reconnecting, "{listed:?}");
        // Nothing to disconnect: the session is gone, only the recording is
        // left, and the banner's Stop ends that.
        assert!(!reg.disconnect(&ids[1]));

        assert!(
            reg.recording_ended(&ids[1]),
            "the kept entry goes with its recording"
        );
        assert!(reg.list().is_empty());
    }

    /// The same ending on a LIVE session only clears "recording": the session
    /// itself is still there to be shown.
    #[test]
    fn a_recording_that_ends_on_a_live_session_leaves_the_session() {
        let (reg, ids, _rx) = reg_with(1);
        assert!(reg.set_recording(&ids[0], true));
        assert!(!reg.recording_ended(&ids[0]));
        let listed = reg.list();
        assert_eq!(listed.len(), 1);
        assert!(!listed[0].recording && !listed[0].reconnecting);
        // An unknown session is nothing to end.
        assert!(!reg.recording_ended(&ObjectId::new()));
    }

    #[test]
    fn a_reconnecting_entry_is_said_on_the_wire_and_absent_otherwise() {
        let (reg, ids, _rx) = reg_with(1);
        let plain = serde_json::to_value(&reg.list()[0]).unwrap();
        assert!(plain.get("reconnecting").is_none(), "{plain}");
        reg.set_recording(&ids[0], true);
        reg.session_ended(&ids[0]);
        let kept = serde_json::to_value(&reg.list()[0]).unwrap();
        assert_eq!(kept["reconnecting"], true, "{kept}");
    }

    /// FR-93 P6h — a session lists as asking while a mark for it lives, and
    /// stops the moment the last one goes: a second wait replacing the first
    /// (the open moving on) must not make it flicker off in between.
    #[test]
    fn a_session_is_asking_while_its_mark_lives() {
        let (reg, ids, _rx) = reg_with(2);
        let asking = |reg: &RcSessionRegistry| -> Vec<bool> {
            reg.list().iter().map(|s| s.asking).collect()
        };
        assert_eq!(asking(&reg), [false, false]);
        let first = AskingMark::new(ids[0]);
        assert_eq!(asking(&reg), [true, false]);
        let second = AskingMark::new(ids[0]);
        drop(first);
        assert_eq!(
            asking(&reg),
            [true, false],
            "a replaced mark still holds it"
        );
        drop(second);
        assert_eq!(asking(&reg), [false, false]);
        // Additive on the wire: a session nobody asks about carries no field.
        let row = serde_json::to_value(&reg.list()[0]).unwrap();
        assert!(row.get("asking").is_none(), "{row}");
    }
}
