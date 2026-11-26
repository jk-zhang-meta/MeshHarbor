// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-130 P1b-2 — the hub's half of a session that outlives its VIEWER's
//! socket (`docs/fr/FR-130-the-session-outlives-its-control-socket.md`
//! §4.4, "The controller's side stays in memory" and "A held session never
//! costs its own viewer the slot"; §4.5). The device's half is
//! [`super::resume`].
//!
//! * **The hold** ([`Hub::viewer_gone`]): a session its viewer may hold (told
//!   `resume_secs`, live, not external) on a device whose connection here
//!   still holds a window outlives the viewer's socket. The hub keeps it with
//!   no controller, tells the device nothing and writes nothing to the row,
//!   until the viewer rejoins or the window ends, when it ends as the socket's
//!   loss ended it before: `controller_hangup`, marked `limit: hold_expired`
//!   ([`LIMIT_HOLD_EXPIRED`]) so a reader can tell a resume its viewer never
//!   rejoined from a hangup.
//! * **The rejoin** ([`Hub::rejoin`]): the viewer's new socket is bound to the
//!   session. The caller has checked the row names that person and run the
//!   gate a request runs. A late call for the socket it replaced finds a
//!   different sender and changes nothing.
//! * **`replaces`** ([`Hub::end_replaced`]): a redial names the held session
//!   it gives up, which ends before every capacity gate when it names the
//!   same person and the same device. The remote module calls it, before it
//!   claims the org's slot for the redial.
//! * **The orphan reap** spares a held session only against another person's
//!   request ([`held_for_viewer`]), and never reads a session with no
//!   controller as an orphan. Its own person's request reaps it before the
//!   org's slot is claimed ([`Hub::reap_held_for`]).
//!
//! With the window at 0 no session is created resumable, so none of this
//! changes anything: a viewer's socket loss ends its sessions as it always
//! has.

use std::time::Duration;

use bson::DateTime;
use bson::oid::ObjectId;
use meshharbor_core::cluster::session_slots::Lease;
use meshharbor_remote_control::error::{Error, Result};
use meshharbor_remote_control::models::{EndReason, SessionPhase};
use meshharbor_remote_control::session::{ClientTx, LiveSession};
use meshharbor_remote_control::signaling::ServerMsg;
use tracing::info;

use super::{EndWrite, Hub, ptr_eq};

/// Review 2, N17 — the `limit` a held session ends with when its window ends
/// with no rejoin, on the device's `rc:terminate` and in the audit's
/// `session_ended`. The reason stays `controller_hangup`, as the viewer's
/// socket loss ended it before FR-130; the mark is what tells a resume lost
/// this way (a cached page that never rejoins, a session re-attached on
/// another pod) from a person's hangup, and AC7's read counts it
/// (`scripts/fr130-roll-read.sh`). Not an `end_source`: the session's time is
/// real, not inferred, so its hours count. The device only logs a limit.
pub(super) const LIMIT_HOLD_EXPIRED: &str = "hold_expired";

/// A session its viewer may hold through the loss of the viewer's own socket:
/// its viewer was told `resume_secs` (or a device's claim rebuilt it), it is
/// live, and it is not external (D3).
pub(super) fn held_for_viewer(s: &LiveSession) -> bool {
    s.resume_secs.is_some() && s.phase == SessionPhase::Active && !s.external
}

/// When a hold that starts now ends: `window_secs` from now.
pub(super) fn due_in(window_secs: u32) -> DateTime {
    DateTime::from_millis(
        DateTime::now()
            .timestamp_millis()
            .saturating_add(i64::from(window_secs) * 1000),
    )
}

/// What became of a session whose viewer's socket went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ViewerGone {
    /// Kept with no controller, for its viewer to rejoin.
    Held,
    /// Ended `controller_hangup`, as before FR-130 (or already gone).
    Ended,
    /// Left alone: a newer socket of its viewer already holds it.
    Rebound,
}

/// Who a session this hub holds belongs to, for the rejoin's checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldParties {
    pub agent_id: ObjectId,
    pub tenant_id: ObjectId,
    pub controller_user_id: ObjectId,
    /// What the session holds now: the ceiling a personal or temporary
    /// device's holder set is checked against it at a rejoin.
    pub permissions: meshharbor_remote_control::permissions::Permissions,
    /// When the hold ends unless the viewer rejoins; `None` for a session
    /// that was never held.
    pub held_until: Option<DateTime>,
}

impl Hub {
    /// The viewer's socket `departing` went, and `session_id` was its own
    /// (or one whose sender already closed). A session its viewer may hold,
    /// on a device whose connection here still holds a window, is kept with
    /// no controller, its device told nothing and its row left as it is,
    /// until the viewer rejoins or the window ends. Anything else ends as
    /// before FR-130: `controller_hangup`, fenced at the number held.
    pub(super) fn viewer_gone(&self, session_id: ObjectId, departing: &ClientTx) -> ViewerGone {
        let Some(arc) = self
            .inner
            .sessions
            .get(&session_id)
            .map(|e| e.value().clone())
        else {
            return ViewerGone::Ended;
        };
        // The device's window is read with no session lock held: an agent
        // entry's guard is never taken while a session's lock is.
        let (agent_id, may_hold) = {
            let s = arc.lock();
            (s.agent_id, held_for_viewer(&s))
        };
        let window = if may_hold {
            self.agent_resume_window(agent_id)
        } else {
            None
        };
        // No runtime, no timer to end it at the window: never held then.
        let window = window.filter(|_| tokio::runtime::Handle::try_current().is_ok());
        let mut s = arc.lock();
        let departing_still = s
            .controller_tx
            .as_ref()
            .is_some_and(|t| ptr_eq(t, departing) || t.is_closed());
        if !departing_still {
            return ViewerGone::Rebound;
        }
        let Some(window) = window.filter(|_| held_for_viewer(&s)) else {
            drop(s);
            let _ = self.end_own(session_id, EndReason::ControllerHangup, None);
            return ViewerGone::Ended;
        };
        s.controller_tx = None;
        s.controller_gen = s.controller_gen.wrapping_add(1);
        s.held_until = Some(due_in(window));
        let (turn, attach_seq, user) = (s.controller_gen, s.attach_seq, s.controller_user_id);
        drop(s);
        self.arm_viewer_wait(session_id, turn, attach_seq, window);
        info!(
            session = %session_id.to_hex(),
            %agent_id,
            %user,
            window_secs = window,
            "rc session held for its viewer: the viewer's socket dropped, and it may rejoin within the window"
        );
        ViewerGone::Held
    }

    /// End `session_id` at `window_secs` from now unless its viewer came back
    /// meanwhile: it still has no controller, at the same count of comings and
    /// goings (`turn`, the session's `controller_gen`) and the same fencing
    /// number. Armed when a viewer's socket goes and when a device's claim
    /// rebuilds a session.
    pub(super) fn arm_viewer_wait(
        &self,
        session_id: ObjectId,
        turn: u32,
        attach_seq: u32,
        window_secs: u32,
    ) {
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let hub = self.clone();
        rt.spawn(async move {
            tokio::time::sleep(Duration::from_secs(u64::from(window_secs))).await;
            let waiting = hub.inner.sessions.get(&session_id).is_some_and(|e| {
                let s = e.value().lock();
                s.controller_tx.is_none() && s.controller_gen == turn && s.attach_seq == attach_seq
            });
            if waiting {
                info!(
                    session = %session_id.to_hex(),
                    window_secs,
                    "rc session held for its viewer: the window ended with no rejoin — ending it"
                );
                let _ = hub.end_own(
                    session_id,
                    EndReason::ControllerHangup,
                    Some(LIMIT_HOLD_EXPIRED),
                );
            }
        });
    }

    /// FR-130 — who a session this hub holds belongs to.
    pub fn held_parties(&self, session_id: ObjectId) -> Option<HeldParties> {
        self.inner.sessions.get(&session_id).map(|e| {
            let s = e.value().lock();
            HeldParties {
                agent_id: s.agent_id,
                tenant_id: s.tenant_id,
                controller_user_id: s.controller_user_id,
                permissions: s.permissions(),
                held_until: s.held_until,
            }
        })
    }

    /// FR-130 — `rc:session.rejoin`: bind `tx`, the viewer's new socket, to
    /// the session it holds, and tell it `rc:session.resumed`. The caller has
    /// already checked that the row names `user_id` and run the gate a
    /// request runs (the remote module, on the pod the viewer's socket is on,
    /// before any relay). Refused for another person's session and for one
    /// its viewer may not hold. Binding moves the count on, so the wait a
    /// departure armed no longer ends it, and the old socket's late
    /// unregistration finds another sender and leaves it.
    pub fn rejoin(&self, session_id: ObjectId, user_id: ObjectId, tx: &ClientTx) -> Result<()> {
        let arc = self
            .inner
            .sessions
            .get(&session_id)
            .map(|e| e.value().clone())
            .ok_or_else(|| Error::SessionNotFound(session_id.to_hex()))?;
        {
            let mut s = arc.lock();
            if s.controller_user_id != user_id {
                return Err(Error::PermissionDenied("not a party to this session"));
            }
            if !held_for_viewer(&s) {
                return Err(Error::BadPhase(session_id.to_hex(), "not_held"));
            }
            s.controller_tx = Some(tx.clone());
            s.controller_gen = s.controller_gen.wrapping_add(1);
        }
        let _ = tx.try_send(ServerMsg::SessionResumed { session_id });
        // A session a device's claim rebuilt has no file child transports any
        // more (`resume_claimed`), and its viewer was on no socket when the
        // device was told: it hears it here, and falls back to the session's
        // own file channel.
        if arc.lock().is_file_children_revoked() {
            let _ = tx.try_send(ServerMsg::FileChildRevoke {
                session_id,
                reason: super::resume::FILE_CHILDREN_REVOKED_AT_RESUME.to_string(),
            });
        }
        info!(session = %session_id.to_hex(), %user_id, "rc session rejoined: its viewer is back");
        Ok(())
    }

    /// FR-130 — a rejoin the gate refused: the viewer may no longer control
    /// the device. When this hub holds the session for that person it ends
    /// with `reason`, fenced at the number held (both ends told), and `tx`,
    /// the socket that asked, is told too: once, when the end already told
    /// it as the session's controller.
    pub fn refuse_rejoin(
        &self,
        session_id: ObjectId,
        user_id: ObjectId,
        tx: &ClientTx,
        reason: EndReason,
    ) {
        let (theirs, bound) = self
            .inner
            .sessions
            .get(&session_id)
            .map(|e| {
                let s = e.value().lock();
                (
                    s.controller_user_id == user_id,
                    s.controller_tx.as_ref().is_some_and(|t| ptr_eq(t, tx)),
                )
            })
            .unwrap_or((false, false));
        if theirs {
            info!(session = %session_id.to_hex(), %user_id, ?reason, "rc session rejoin refused by the gate — ending it");
            let _ = self.end_own(session_id, reason, None);
        }
        if !(theirs && bound) {
            let _ = tx.try_send(ServerMsg::Terminate {
                session_id,
                reason,
                limit: None,
            });
        }
    }

    /// FR-130 — `replaces` on a redial's `rc:session.request`: the held
    /// session the page gives up ends as `controller_hangup` (an end its
    /// controller asked for), when this hub holds it and it names the same
    /// person and the same device. Only a session its viewer was told it may
    /// hold (`resume_secs`): no page names any other, so at window 0 this
    /// never ends anything.
    ///
    /// The remote module calls it BEFORE every capacity gate a request
    /// meets, the org's FR-115 slot included, which it claims before the
    /// hub's own dispatch. So the session's slot lease is handed back to the
    /// caller, which gives it back and waits for that before it claims one
    /// for the redial. `None` = nothing ended; `Some(lease)` = ended, with
    /// the slot it held, when it held one.
    pub fn end_replaced(
        &self,
        session_id: ObjectId,
        user_id: ObjectId,
        agent_id: ObjectId,
    ) -> Option<Option<Lease>> {
        let named = self.inner.sessions.get(&session_id).is_some_and(|e| {
            let s = e.value().lock();
            s.controller_user_id == user_id && s.agent_id == agent_id && s.resume_secs.is_some()
        });
        if !named {
            return None;
        }
        info!(
            session = %session_id.to_hex(),
            %user_id,
            %agent_id,
            "rc session replaced by its viewer's redial — ending it before the capacity gate"
        );
        // Out of the map first, so the end below does not give it back on a
        // task of its own: the caller waits for that.
        let lease = self.inner.slotted.remove(&session_id).map(|(_, l)| l);
        let _ = self.end_session(
            session_id,
            EndReason::ControllerHangup,
            None,
            EndWrite::Asked,
        );
        Some(lease)
    }

    /// FR-130 — the orphan reap's half for its own person, run by the remote
    /// module BEFORE it claims the org's slot for `user_id`'s request to
    /// `agent_id`: every session held for that person on that device (its
    /// viewer's socket gone, or rebuilt by a claim with no viewer yet) ends
    /// as the reap ends an orphan, `controller_hangup` fenced at the number
    /// held. Each one's slot lease comes back for the caller to give back
    /// and wait on, as [`Self::end_replaced`]'s does. Another person's held
    /// sessions are left alone.
    pub fn reap_held_for(&self, user_id: ObjectId, agent_id: ObjectId) -> Vec<Option<Lease>> {
        // Collected first: the map is written below.
        let held: Vec<ObjectId> = self
            .inner
            .sessions
            .iter()
            .filter_map(|e| {
                let s = e.value().lock();
                (s.agent_id == agent_id
                    && s.controller_user_id == user_id
                    && held_for_viewer(&s)
                    && s.controller_tx.as_ref().is_none_or(|t| t.is_closed()))
                .then_some(*e.key())
            })
            .collect();
        held.into_iter()
            .map(|session_id| {
                info!(
                    session = %session_id.to_hex(),
                    %user_id,
                    %agent_id,
                    "rc session held for its viewer: the same person asks for the device again — ending it"
                );
                let lease = self.inner.slotted.remove(&session_id).map(|(_, l)| l);
                let _ = self.end_own(session_id, EndReason::ControllerHangup, None);
                lease
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::{DispatchCtx, OrgPolicy, ResumeHello, Resumed, ResumedSession};
    use super::*;
    use bson::DateTime;
    use meshharbor_remote_control::audit::AuditSink;
    use meshharbor_remote_control::models::{ConsentMode, OsKind, SessionPolicy};
    use meshharbor_remote_control::permissions::Permissions;
    use meshharbor_remote_control::signaling::{ClientMsg, Role};
    use mongodb::Client;
    use tokio::sync::mpsc;

    async fn hub() -> Hub {
        // As the hub's own tests: Mongo is never contacted unless the sink
        // flushes, and a failed write there is only logged.
        let client = Client::with_uri_str("mongodb://localhost:27017")
            .await
            .expect("mongo for tests");
        let (audit, _h) = AuditSink::spawn(client.database("rc_test"));
        Hub::new(audit, None)
    }

    /// A device connected under `window` (`None`: no window), allowing `max`
    /// sessions; its receiver.
    fn device(
        hub: &Hub,
        agent: ObjectId,
        max: u8,
        window: Option<u32>,
    ) -> mpsc::Receiver<ServerMsg> {
        hub.register_agent_resuming(
            agent,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            max,
            true,
            false,
            ResumeHello {
                advertised: true,
                window,
                kept: Vec::new(),
            },
        )
        .rx
    }

    /// A session `user` asked for on `tx`; its id, or the refusal.
    fn ask(hub: &Hub, agent: ObjectId, user: ObjectId, tx: &ClientTx) -> Result<ObjectId> {
        hub.create_session(
            agent,
            user,
            "Viewer".into(),
            tx.clone(),
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

    fn created_resume_secs(msgs: &[ServerMsg], sid: ObjectId) -> Option<Option<u32>> {
        msgs.iter().find_map(|m| match m {
            ServerMsg::SessionCreated {
                session_id,
                resume_secs,
                ..
            } if *session_id == sid => Some(*resume_secs),
            _ => None,
        })
    }

    fn controller_of(hub: &Hub, sid: ObjectId) -> Option<ClientTx> {
        hub.with_session(sid, |s| Ok(s.controller_tx.clone()))
            .ok()
            .flatten()
    }

    /// A controller's dispatch context, for `user` on `tx`.
    fn controller_ctx(user: ObjectId, tx: &ClientTx) -> DispatchCtx {
        DispatchCtx {
            role: Role::Controller,
            user_id: Some(user),
            agent_id: None,
            controller_name: Some("Viewer".into()),
            controller_tx: Some(tx.clone()),
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
        }
    }

    /// A viewer's socket loss keeps the live session its viewer may hold (no
    /// controller, the device told nothing) and ends, as before, one that is
    /// not live yet. The viewer is told `resume_secs` at the creation. The
    /// pending one is on a second device: a second request on the same
    /// socket to the same device is #1045's duplicate, coalesced.
    #[tokio::test]
    async fn a_viewers_socket_loss_holds_a_live_session_and_ends_the_rest() {
        let hub = hub().await;
        let (agent, other_agent, user) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let mut to_agent = device(&hub, agent, 4, Some(60));
        let mut to_other = device(&hub, other_agent, 4, Some(60));
        let (tx, mut rx) = hub.register_controller(user);
        let held = ask(&hub, agent, user, &tx).unwrap();
        live(&hub, held).await;
        let pending = ask(&hub, other_agent, user, &tx).unwrap();
        assert_ne!(pending, held);
        let told = drain(&mut rx);
        assert_eq!(created_resume_secs(&told, held), Some(Some(60)), "{told:?}");
        drain(&mut to_agent);
        drain(&mut to_other);

        assert_eq!(hub.held_parties(held).unwrap().held_until, None);
        hub.unregister_controller(user, &tx);

        assert!(hub.session_snapshot(held).is_some(), "the live one is held");
        assert!(controller_of(&hub, held).is_none(), "with no controller");
        // Until the window from now: what a rejoin the gate could not decide
        // is told.
        let until = hub.held_parties(held).unwrap().held_until.unwrap();
        let left = until.timestamp_millis() - DateTime::now().timestamp_millis();
        assert!((59_000..=60_000).contains(&left), "{left} ms");
        assert!(
            hub.session_snapshot(pending).is_none(),
            "the pending one ends"
        );
        let to_agent = drain(&mut to_agent);
        assert_eq!(terminated(&to_agent, held), None, "{to_agent:?}");
        assert_eq!(
            terminated(&drain(&mut to_other), pending),
            Some(EndReason::ControllerHangup)
        );
    }

    /// A session opened through a device share is an outsider's, as FR-52's
    /// external one is: its viewer is told no `resume_secs` whatever the
    /// window, its device's socket loss ends it immediately (`AgentDisconnect`,
    /// never detached), and its controller's socket loss ends it immediately
    /// (`ControllerHangup`, never held for rejoin). A share lives on a lease
    /// the centre renews every few seconds, which a gap cannot.
    #[tokio::test]
    async fn a_session_opened_through_a_device_share_is_never_held() {
        let hub = hub().await;
        let (agent, user) = (ObjectId::new(), ObjectId::new());
        let reg = hub.register_agent_resuming(
            agent,
            ObjectId::new(),
            ObjectId::new(),
            OsKind::Linux,
            4,
            true,
            false,
            ResumeHello {
                advertised: true,
                window: Some(60),
                kept: Vec::new(),
            },
        );
        let open_share = |hub: &Hub, user: ObjectId, tx: &ClientTx| {
            let request = ClientMsg::SessionRequest {
                two_factor_code: None,
                agent_id: agent,
                share_grant_id: Some(ObjectId::new()),
                permissions: Permissions::VIEW,
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
            };
            hub.dispatch(&controller_ctx(user, tx), request).unwrap();
        };

        // Case 1: viewer disconnects -> ended immediately as ControllerHangup, never held.
        let mut to_agent = reg.rx;
        let (tx1, mut rx1) = hub.register_controller(user);
        open_share(&hub, user, &tx1);
        let told1 = drain(&mut rx1);
        let sid1 = told1
            .iter()
            .find_map(|m| match m {
                ServerMsg::SessionCreated { session_id, .. } => Some(*session_id),
                _ => None,
            })
            .expect("the share's session is created");
        assert_eq!(created_resume_secs(&told1, sid1), Some(None), "{told1:?}");
        assert!(hub.with_session(sid1, |s| Ok(s.external)).unwrap());
        live(&hub, sid1).await;
        assert!(
            !hub.with_session(sid1, |s| Ok(held_for_viewer(s))).unwrap(),
            "never one to hold"
        );
        drain(&mut to_agent);
        hub.unregister_controller(user, &tx1);
        assert!(
            hub.session_snapshot(sid1).is_none(),
            "controller loss ends a share session immediately"
        );
        assert_eq!(
            terminated(&drain(&mut to_agent), sid1),
            Some(EndReason::ControllerHangup),
            "device receives ControllerHangup immediately"
        );

        // Case 2: device disconnects -> ended immediately as AgentDisconnect, never detached.
        let (tx2, mut rx2) = hub.register_controller(user);
        open_share(&hub, user, &tx2);
        let told2 = drain(&mut rx2);
        let sid2 = told2
            .iter()
            .find_map(|m| match m {
                ServerMsg::SessionCreated { session_id, .. } => Some(*session_id),
                _ => None,
            })
            .expect("the second share's session is created");
        assert_eq!(created_resume_secs(&told2, sid2), Some(None), "{told2:?}");
        assert!(hub.with_session(sid2, |s| Ok(s.external)).unwrap());
        live(&hub, sid2).await;

        assert!(hub.unregister_agent(agent, Some(&reg.tx)));
        assert!(hub.session_snapshot(sid2).is_none());
        let told = drain(&mut rx2);
        assert_eq!(
            terminated(&told, sid2),
            Some(EndReason::AgentDisconnect),
            "{told:?}"
        );
        assert!(
            !told
                .iter()
                .any(|m| matches!(m, ServerMsg::SessionDetached { .. })),
            "ended, not detached: {told:?}"
        );
    }

    /// With no window on the device's connection, the viewer is told no
    /// `resume_secs` and its socket's loss ends the session as it always has.
    #[tokio::test]
    async fn with_no_window_the_viewers_socket_loss_ends_the_session_as_today() {
        let hub = hub().await;
        let (agent, user) = (ObjectId::new(), ObjectId::new());
        let mut to_agent = device(&hub, agent, 2, None);
        let (tx, mut rx) = hub.register_controller(user);
        let sid = ask(&hub, agent, user, &tx).unwrap();
        live(&hub, sid).await;
        assert_eq!(created_resume_secs(&drain(&mut rx), sid), Some(None));
        drain(&mut to_agent);

        hub.unregister_controller(user, &tx);
        assert!(hub.session_snapshot(sid).is_none());
        assert_eq!(
            terminated(&drain(&mut to_agent), sid),
            Some(EndReason::ControllerHangup)
        );
    }

    /// A held session nobody rejoins ends at the window, `controller_hangup`.
    #[tokio::test]
    async fn the_window_ends_a_held_session_its_viewer_never_rejoined() {
        let hub = hub().await;
        let (agent, user) = (ObjectId::new(), ObjectId::new());
        let mut to_agent = device(&hub, agent, 2, Some(1));
        let (tx, _rx) = hub.register_controller(user);
        let sid = ask(&hub, agent, user, &tx).unwrap();
        live(&hub, sid).await;
        drain(&mut to_agent);
        hub.unregister_controller(user, &tx);
        assert!(hub.session_snapshot(sid).is_some());
        tokio::time::sleep(Duration::from_millis(1400)).await;
        assert!(hub.session_snapshot(sid).is_none(), "ended at the window");
        assert_eq!(
            terminated(&drain(&mut to_agent), sid),
            Some(EndReason::ControllerHangup)
        );
    }

    /// The rejoin binds the new socket and tells it `rc:session.resumed`; the
    /// device's frames reach it. The old socket's late unregistration finds
    /// another sender and leaves the session, and the wait the departure
    /// armed no longer ends it.
    #[tokio::test]
    async fn a_rejoin_binds_the_new_socket_and_the_old_ones_late_call_is_fenced() {
        let hub = hub().await;
        let (agent, user) = (ObjectId::new(), ObjectId::new());
        let mut to_agent = device(&hub, agent, 2, Some(1));
        let (old, _old_rx) = hub.register_controller(user);
        let sid = ask(&hub, agent, user, &old).unwrap();
        live(&hub, sid).await;
        hub.unregister_controller(user, &old);

        let (new, mut new_rx) = hub.register_controller(user);
        hub.rejoin(sid, user, &new).unwrap();
        assert!(
            drain(&mut new_rx).iter().any(
                |m| matches!(m, ServerMsg::SessionResumed { session_id } if *session_id == sid)
            ),
            "the rejoin is answered resumed"
        );
        hub.forward_ice(Role::Agent, sid, serde_json::json!({"candidate": "c"}))
            .unwrap();
        assert!(
            drain(&mut new_rx)
                .iter()
                .any(|m| matches!(m, ServerMsg::Ice { session_id, .. } if *session_id == sid)),
            "the device's frames reach the rejoined socket"
        );

        hub.unregister_controller(user, &old);
        assert!(
            controller_of(&hub, sid).is_some_and(|t| ptr_eq(&t, &new)),
            "a late call for the old socket is fenced by the sender"
        );
        tokio::time::sleep(Duration::from_millis(1400)).await;
        assert!(
            hub.session_snapshot(sid).is_some(),
            "the departure's wait is void once the viewer is back"
        );
        assert_eq!(terminated(&drain(&mut to_agent), sid), None);
    }

    /// The rejoin names its own person and a session its viewer may hold.
    #[tokio::test]
    async fn a_rejoin_is_refused_for_another_person_and_for_a_session_not_held() {
        let hub = hub().await;
        let (agent, user) = (ObjectId::new(), ObjectId::new());
        let _to_agent = device(&hub, agent, 2, Some(60));
        let (tx, _rx) = hub.register_controller(user);
        let sid = ask(&hub, agent, user, &tx).unwrap();
        live(&hub, sid).await;
        hub.unregister_controller(user, &tx);
        let (stranger, _srx) = hub.register_controller(ObjectId::new());
        assert!(matches!(
            hub.rejoin(sid, ObjectId::new(), &stranger),
            Err(Error::PermissionDenied(_))
        ));
        assert!(controller_of(&hub, sid).is_none(), "nothing bound");

        let other_agent = ObjectId::new();
        let _to_other = device(&hub, other_agent, 2, None);
        let (tx2, _rx2) = hub.register_controller(user);
        let not_held = ask(&hub, other_agent, user, &tx2).unwrap();
        live(&hub, not_held).await;
        assert!(matches!(
            hub.rejoin(not_held, user, &tx2),
            Err(Error::BadPhase(_, "not_held"))
        ));
        assert!(matches!(
            hub.rejoin(ObjectId::new(), user, &tx2),
            Err(Error::SessionNotFound(_))
        ));
    }

    /// A rejoin the gate refused ends the session for its person, telling
    /// the device and the socket that asked.
    #[tokio::test]
    async fn a_refused_rejoin_ends_the_session_and_tells_both() {
        let hub = hub().await;
        let (agent, user) = (ObjectId::new(), ObjectId::new());
        let mut to_agent = device(&hub, agent, 2, Some(60));
        let (tx, _rx) = hub.register_controller(user);
        let sid = ask(&hub, agent, user, &tx).unwrap();
        live(&hub, sid).await;
        hub.unregister_controller(user, &tx);
        drain(&mut to_agent);

        let (asking, mut asking_rx) = hub.register_controller(user);
        hub.refuse_rejoin(sid, user, &asking, EndReason::AdminTerminated);
        assert!(hub.session_snapshot(sid).is_none());
        assert_eq!(
            terminated(&drain(&mut to_agent), sid),
            Some(EndReason::AdminTerminated)
        );
        assert_eq!(
            terminated(&drain(&mut asking_rx), sid),
            Some(EndReason::AdminTerminated)
        );
    }

    /// Each rejoin gets one answer: a refused rejoin from the socket the
    /// session is already bound to is told by the end itself, once.
    #[tokio::test]
    async fn a_refused_rejoin_tells_a_bound_socket_once() {
        let hub = hub().await;
        let (agent, user) = (ObjectId::new(), ObjectId::new());
        let _to_agent = device(&hub, agent, 2, Some(60));
        let (tx, mut rx) = hub.register_controller(user);
        let sid = ask(&hub, agent, user, &tx).unwrap();
        live(&hub, sid).await;
        drain(&mut rx);

        hub.refuse_rejoin(sid, user, &tx, EndReason::AdminTerminated);
        let told = drain(&mut rx);
        let ends = told
            .iter()
            .filter(|m| matches!(m, ServerMsg::Terminate { session_id, .. } if *session_id == sid))
            .count();
        assert_eq!(ends, 1, "{told:?}");
    }

    /// The orphan reap spares a held session against another person's
    /// request (refused busy on a device that allows one), and reaps it for
    /// its own person's request, which then gets the device.
    #[tokio::test]
    async fn the_orphan_reap_spares_a_held_session_only_against_another_person() {
        let hub = hub().await;
        let (agent, user, other) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let _to_agent = device(&hub, agent, 1, Some(60));
        let (tx, _rx) = hub.register_controller(user);
        let sid = ask(&hub, agent, user, &tx).unwrap();
        live(&hub, sid).await;
        hub.unregister_controller(user, &tx);

        let (otx, _orx) = hub.register_controller(other);
        assert!(
            matches!(ask(&hub, agent, other, &otx), Err(Error::AgentBusy)),
            "another person's request is refused busy"
        );
        assert!(hub.session_snapshot(sid).is_some(), "and spares it");

        let (tx2, _rx2) = hub.register_controller(user);
        let next = ask(&hub, agent, user, &tx2).expect("its own person gets the device");
        assert!(hub.session_snapshot(sid).is_none(), "reaped as before");
        assert!(hub.session_snapshot(next).is_some());
    }

    /// P1b-1's seam: a session a device's claim rebuilt has no controller
    /// until its viewer rejoins. Another person's request spares it (before
    /// P1b-2 the orphan reap ended it at the next request to the device), and
    /// its own person's request reaps it.
    #[tokio::test]
    async fn a_resumed_session_with_no_controller_is_spared_against_another_person() {
        let hub = hub().await;
        let (agent, tenant, user, other) = (
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
        );
        let sid = ObjectId::new();
        let reg = hub.register_agent_resuming(
            agent,
            tenant,
            ObjectId::new(),
            OsKind::Linux,
            2,
            true,
            false,
            ResumeHello {
                advertised: true,
                window: Some(60),
                kept: vec![sid],
            },
        );
        hub.resume_claimed(
            agent,
            &reg.tx,
            ResumedSession {
                session_id: sid,
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
            },
        );
        assert!(hub.confirm_resumed(agent, &reg.tx, sid, 1));
        assert!(controller_of(&hub, sid).is_none());

        let (otx, _orx) = hub.register_controller(other);
        ask(&hub, agent, other, &otx).expect("the second place is free");
        assert!(
            hub.session_snapshot(sid).is_some(),
            "another person's request spares the resumed session"
        );

        // The rejoin's dispatch arm, as a relayed rejoin reaches it.
        let (tx, mut rx) = hub.register_controller(user);
        hub.dispatch(
            &controller_ctx(user, &tx),
            ClientMsg::SessionRejoin { session_id: sid },
        )
        .expect("its viewer rejoins");
        assert!(
            drain(&mut rx)
                .iter()
                .any(|m| matches!(m, ServerMsg::SessionResumed { .. }))
        );
        assert!(controller_of(&hub, sid).is_some_and(|t| ptr_eq(&t, &tx)));
    }

    /// `replaces` and its own person's request: the remote module ends the
    /// held session a redial names, or every one held for that person on the
    /// device, before any capacity gate, and takes each one's slot lease
    /// back. Another person's request, or one for another device, ends
    /// nothing.
    #[tokio::test]
    async fn replaces_and_the_same_persons_request_end_what_is_held_for_them() {
        let hub = hub().await;
        let (agent, user, other) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let mut to_agent = device(&hub, agent, 1, Some(60));
        let (tx, _rx) = hub.register_controller(user);
        let held = ask(&hub, agent, user, &tx).unwrap();
        live(&hub, held).await;
        hub.unregister_controller(user, &tx);
        drain(&mut to_agent);

        assert!(
            hub.end_replaced(held, other, agent).is_none(),
            "another person's"
        );
        assert!(
            hub.end_replaced(held, user, ObjectId::new()).is_none(),
            "another device"
        );
        assert!(
            hub.reap_held_for(other, agent).is_empty(),
            "another person's"
        );
        assert!(hub.session_snapshot(held).is_some());

        assert!(
            matches!(hub.end_replaced(held, user, agent), Some(None)),
            "ended; it held no slot"
        );
        assert!(hub.session_snapshot(held).is_none());
        assert_eq!(
            terminated(&drain(&mut to_agent), held),
            Some(EndReason::ControllerHangup)
        );

        let (tx2, _rx2) = hub.register_controller(user);
        let next = ask(&hub, agent, user, &tx2).expect("the place is free again");
        live(&hub, next).await;
        hub.unregister_controller(user, &tx2);
        let reaped = hub.reap_held_for(user, agent);
        assert_eq!(reaped.len(), 1, "the same person's request reaps it");
        assert!(reaped.iter().all(Option::is_none));
        assert!(hub.session_snapshot(next).is_none());
        assert_eq!(
            terminated(&drain(&mut to_agent), next),
            Some(EndReason::ControllerHangup)
        );
    }

    /// Review 2, N8 — the viewer's socket goes and the session is held; then
    /// the device is displaced here, on the same pod, and its claim
    /// re-attaches the session at the next number. The wait the viewer's
    /// departure armed is void once the number moves, so the claim arms the
    /// hold again: a page that never rejoins does not keep the session, its
    /// place and its slot for good, and the hold still ends at the window.
    #[tokio::test]
    async fn a_claim_that_reattaches_a_held_session_arms_its_hold_again() {
        let hub = hub().await;
        let (agent, tenant, user) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let connect = |kept: Vec<ObjectId>| {
            hub.register_agent_resuming(
                agent,
                tenant,
                ObjectId::new(),
                OsKind::Linux,
                2,
                true,
                false,
                ResumeHello {
                    advertised: true,
                    window: Some(1),
                    kept,
                },
            )
        };
        let _first = connect(Vec::new());
        let (tx, _rx) = hub.register_controller(user);
        let sid = ask(&hub, agent, user, &tx).unwrap();
        live(&hub, sid).await;
        hub.unregister_controller(user, &tx);
        assert!(controller_of(&hub, sid).is_none(), "held for its viewer");

        let second = connect(vec![sid]);
        let resumed = hub.resume_claimed(
            agent,
            &second.tx,
            ResumedSession {
                session_id: sid,
                tenant_id: tenant,
                controller_user_id: user,
                permissions: Permissions::VIEW,
                created_at: DateTime::now(),
                started_at: DateTime::now(),
                attach_seq: 1,
                max_duration: None,
                external: false,
                slot: None,
                resume_secs: 1,
            },
        );
        assert_eq!(resumed, Resumed::Reattached);
        assert!(hub.confirm_resumed(agent, &second.tx, sid, 1));
        assert!(controller_of(&hub, sid).is_none(), "still no viewer");

        tokio::time::sleep(Duration::from_millis(1400)).await;
        assert!(
            hub.session_snapshot(sid).is_none(),
            "the hold ends at the window"
        );
    }
}
