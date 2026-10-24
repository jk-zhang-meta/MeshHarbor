// SPDX-License-Identifier: AGPL-3.0-only
//! Short, monotonic, shared-session-only authority. The timer is independent of
//! the signalling pump and belongs to the process which owns the actual peer.
use bson::oid::ObjectId;
use roomler_ai_remote_control::{
    models::EndReason,
    signaling::{ClientMsg, ServerMsg, SharedSessionLease},
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::mpsc, time::Instant};
use tokio_util::sync::CancellationToken;

const WINDOW: Duration = Duration::from_secs(12);
const INTERVAL: Duration = Duration::from_secs(2);
// Includes ended tombstones, never evicted on this authenticated connection.
// A 65th distinct shared session fails closed until a full connection reset.
const MAX_SESSIONS: usize = 64;
const MAX_PENDING: usize = 8;
type Stop = Arc<dyn Fn() + Send + Sync>;

struct Clock {
    deadline: Instant,
    next: u64,
    acknowledged: u64,
    pending: VecDeque<(u64, Instant)>,
    expired: bool,
    confirmed: bool,
}
impl Clock {
    fn new(now: Instant) -> Self {
        Self {
            deadline: now + WINDOW,
            next: 0,
            acknowledged: 0,
            pending: VecDeque::new(),
            expired: false,
            confirmed: false,
        }
    }
    fn alive(&mut self, now: Instant) -> bool {
        if now >= self.deadline {
            self.expired = true;
        }
        !self.expired
    }
    fn issue(&mut self, now: Instant) -> Option<u64> {
        if !self.alive(now) {
            return None;
        }
        let Some(id) = self.next.checked_add(1) else {
            self.expired = true;
            return None;
        };
        self.next = id;
        self.pending.retain(|(_, t)| now < *t + WINDOW);
        if self.pending.len() == MAX_PENDING {
            self.pending.pop_front();
        }
        self.pending.push_back((id, now));
        Some(id)
    }
    fn accept(&mut self, id: u64, now: Instant) -> bool {
        if !self.alive(now) || id <= self.acknowledged {
            return false;
        }
        let Some((_, issued)) = self.pending.iter().find(|(i, _)| *i == id).copied() else {
            return false;
        };
        if now >= issued + WINDOW {
            return false;
        }
        // Anchored to the LOCAL issue time, never the delayed reply's arrival.
        self.deadline = self.deadline.max(issued + WINDOW);
        self.acknowledged = id;
        self.confirmed = true;
        self.pending.retain(|(i, _)| *i > id);
        true
    }
}
struct Live {
    clock: Option<Clock>,
    pending_offer: Option<ServerMsg>,
    pending_ice: Vec<serde_json::Value>,
    stop: Option<Stop>,
    expired: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum LeaseService {
    Desktop,
    Ssh,
}
struct Entry {
    service: LeaseService,
    scope: SharedSessionLease,
    state: Mutex<Live>,
    cancel: CancellationToken,
}
impl Entry {
    fn end(&self) {
        let stop = {
            let mut s = self.state.lock().expect("shared lease mutex");
            s.expired = true;
            if let Some(c) = &mut s.clock {
                c.expired = true;
            }
            s.pending_offer.take();
            s.pending_ice.clear();
            s.stop.take()
        };
        if let Some(stop) = stop {
            stop();
        }
        self.cancel.cancel();
    }
}
#[derive(Default)]
pub struct SharedLeases {
    entries: HashMap<ObjectId, Arc<Entry>>,
}
impl Drop for SharedLeases {
    fn drop(&mut self) {
        for e in self.entries.values() {
            e.end();
        }
    }
}
impl SharedLeases {
    /// Request and delegated Params only record context, never start a duplicate timer.
    pub fn note(&mut self, sid: ObjectId, scope: SharedSessionLease) -> bool {
        self.note_service(sid, scope, LeaseService::Desktop)
    }
    pub fn note_ssh(&mut self, sid: ObjectId, scope: SharedSessionLease) -> bool {
        self.note_service(sid, scope, LeaseService::Ssh)
    }
    fn note_service(
        &mut self,
        sid: ObjectId,
        scope: SharedSessionLease,
        service: LeaseService,
    ) -> bool {
        if scope.lease_epoch.len() != 36
            || !scope.lease_epoch.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
        {
            return false;
        }
        if let Some(e) = self.entries.get(&sid) {
            if e.scope != scope || e.service != service {
                e.end();
                return false;
            }
            return !e.state.lock().expect("shared lease mutex").expired;
        }
        if self.entries.len() >= MAX_SESSIONS {
            return false;
        }
        self.entries.insert(
            sid,
            Arc::new(Entry {
                service,
                scope,
                state: Mutex::new(Live {
                    clock: None,
                    pending_offer: None,
                    pending_ice: Vec::new(),
                    stop: None,
                    expired: false,
                }),
                cancel: CancellationToken::new(),
            }),
        );
        true
    }
    /// The actual Request/GUI Params seam. Missing scope cannot overwrite an
    /// existing shared identity, including an ended tombstone.
    pub fn note_optional(&mut self, sid: ObjectId, scope: Option<&SharedSessionLease>) -> bool {
        match scope {
            Some(s) => self.note(sid, s.clone()),
            None => !self.entries.contains_key(&sid),
        }
    }
    pub fn contains(&self, sid: ObjectId) -> bool {
        self.entries.contains_key(&sid)
    }
    pub fn end(&mut self, sid: ObjectId) {
        if let Some(e) = self.entries.get(&sid) {
            e.end();
        }
    }
    /// Called AFTER GUI delegation, by the actual peer-owning process only.
    /// The first offer waits for a fresh center PDP response before any peer exists.
    pub fn offer(&mut self, sid: ObjectId, msg: &ServerMsg, tx: &mpsc::Sender<ClientMsg>) -> bool {
        let (shared_lease, service) = match msg {
            ServerMsg::SdpOffer { shared_lease, .. } => (shared_lease, LeaseService::Desktop),
            ServerMsg::TunnelSdpOffer { shared_lease, .. } => (shared_lease, LeaseService::Ssh),
            _ => return false,
        };
        let Some(e) = self.entries.get(&sid).cloned() else {
            // Unknown Some is a refused/missing Request or Params, not legacy.
            return shared_lease.is_none();
        };
        if shared_lease.as_ref() != Some(&e.scope) || e.service != service {
            e.end();
            return false;
        }
        let mut s = e.state.lock().expect("shared lease mutex");
        if s.expired {
            return false;
        }
        if let Some(c) = &mut s.clock {
            if c.alive(Instant::now()) && c.confirmed {
                return true;
            }
            if c.expired {
                drop(s);
                e.end();
            }
            return false;
        }
        s.clock = Some(Clock::new(Instant::now()));
        s.pending_offer = Some(msg.clone()); // exactly one bounded deferred offer
        drop(s);
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                let deadline = {
                    let s = e.state.lock().expect("shared lease mutex");
                    if s.expired {
                        return;
                    }
                    s.clock.as_ref().expect("active lease").deadline
                };
                tokio::select! {
                    _ = e.cancel.cancelled() => return,
                    _ = tokio::time::sleep_until(deadline) => {
                        let expired = {
                            let mut s = e.state.lock().expect("shared lease mutex");
                            !s.clock.as_mut().expect("active lease").alive(Instant::now())
                        };
                        if expired { break; }
                    }
                    _ = tick.tick() => {
                        let id = {
                            let mut s = e.state.lock().expect("shared lease mutex");
                            s.clock.as_mut().expect("active lease").issue(Instant::now())
                        };
                        let Some(challenge_id) = id else { break; };
                        // No await on a blocked signalling channel; no progress means expiry.
                        let challenge=match e.service {
                            LeaseService::Desktop=>ClientMsg::SharedLeaseChallenge {session_id:sid,grant_id:e.scope.grant_id,lease_epoch:e.scope.lease_epoch.clone(),challenge_id},
                            LeaseService::Ssh=>ClientMsg::SharedSshLeaseChallenge {session_id:sid,grant_id:e.scope.grant_id,lease_epoch:e.scope.lease_epoch.clone(),challenge_id},
                        };
                        let _ = tx.try_send(challenge);
                    }
                }
            }
            // Cancels channels/input and aborts media BEFORE any asynchronous PC close.
            e.end();
            let ended = match e.service {
                LeaseService::Desktop => ClientMsg::Terminate {
                    session_id: sid,
                    reason: EndReason::AdminTerminated,
                    limit: None,
                },
                LeaseService::Ssh => ClientMsg::TunnelTerminate {
                    session_id: sid,
                    reason: roomler_ai_remote_control::signaling::CloseReason::IoError,
                },
            };
            let _ = tx.try_send(ended);
        });
        false
    }
    /// ICE arriving while the initial offer waits for fresh PDP is bounded,
    /// retained, and applied only after that same peer negotiates its offer.
    pub fn hold_ice(&mut self, sid: ObjectId, candidate: &serde_json::Value) -> bool {
        let Some(e) = self.entries.get(&sid) else {
            return false;
        };
        let mut s = e.state.lock().expect("shared lease mutex");
        if s.expired {
            return true;
        }
        if s.stop.is_none() {
            if s.pending_ice.len() < 32 {
                s.pending_ice.push(candidate.clone());
            }
            return true;
        }
        false
    }
    pub fn take_ice(&mut self, sid: ObjectId) -> Vec<serde_json::Value> {
        self.entries
            .get(&sid)
            .map(|e| std::mem::take(&mut e.state.lock().expect("shared lease mutex").pending_ice))
            .unwrap_or_default()
    }
    pub fn renew(
        &mut self,
        sid: ObjectId,
        grant: ObjectId,
        epoch: &str,
        id: u64,
    ) -> Option<ServerMsg> {
        self.renew_service(sid, grant, epoch, id, LeaseService::Desktop)
    }
    pub fn renew_ssh(
        &mut self,
        sid: ObjectId,
        grant: ObjectId,
        epoch: &str,
        id: u64,
    ) -> Option<ServerMsg> {
        self.renew_service(sid, grant, epoch, id, LeaseService::Ssh)
    }
    fn renew_service(
        &mut self,
        sid: ObjectId,
        grant: ObjectId,
        epoch: &str,
        id: u64,
        service: LeaseService,
    ) -> Option<ServerMsg> {
        let e = self.entries.get(&sid)?;
        if e.scope.grant_id != grant || e.scope.lease_epoch != epoch || e.service != service {
            return None;
        }
        let mut s = e.state.lock().expect("shared lease mutex");
        if s.expired {
            return None;
        }
        if !s.clock.as_mut()?.accept(id, Instant::now()) {
            return None;
        }
        s.pending_offer.take()
    }
    /// Installed BEFORE offer negotiation can open any channel. A construction
    /// which outlived the deadline cannot insert or resurrect a serving peer.
    pub fn attach(&self, sid: ObjectId, scope: Option<&SharedSessionLease>, stop: Stop) -> bool {
        let Some(e) = self.entries.get(&sid) else {
            if scope.is_some() {
                stop();
                return false;
            }
            return true;
        };
        if scope != Some(&e.scope) {
            stop();
            e.end();
            return false;
        }
        let mut s = e.state.lock().expect("shared lease mutex");
        if s.expired
            || s.clock
                .as_mut()
                .is_none_or(|c| !c.alive(Instant::now()) || !c.confirmed)
        {
            drop(s);
            stop();
            e.end();
            return false;
        }
        s.stop = Some(stop);
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn scope() -> SharedSessionLease {
        SharedSessionLease {
            grant_id: ObjectId::new(),
            lease_epoch: "11111111-1111-4111-8111-111111111111".to_string(),
        }
    }
    #[test]
    fn shared_lease_delayed_echo_is_anchored_and_no_replay_or_resurrection() {
        let t = Instant::now();
        let mut c = Clock::new(t);
        let first = c.issue(t).unwrap();
        assert!(c.accept(first, t + Duration::from_secs(10)));
        assert_eq!(c.deadline, t + WINDOW);
        assert!(!c.accept(first, t + Duration::from_secs(11)));
        let second = c.issue(t + Duration::from_secs(11)).unwrap();
        assert!(!c.accept(second, t + WINDOW));
        assert!(!c.accept(second, t + Duration::from_secs(13)));
    }
    #[test]
    fn shared_lease_pending_and_context_are_bounded_and_old_scope_cannot_replace() {
        let t = Instant::now();
        let mut c = Clock::new(t);
        for _ in 0..100 {
            c.issue(t);
        }
        assert_eq!(c.pending.len(), MAX_PENDING);
        c.next = u64::MAX;
        assert!(c.issue(t).is_none());
        assert!(c.expired);
        let mut r = SharedLeases::default();
        let sid = ObjectId::new();
        assert!(r.note(sid, scope()));
        assert!(!r.note(sid, scope()));
        for _ in 1..MAX_SESSIONS {
            assert!(r.note(ObjectId::new(), scope()));
        }
        assert!(!r.note(ObjectId::new(), scope()));
    }
    #[tokio::test(start_paused = true)]
    async fn shared_lease_real_offer_challenge_gate_and_independent_hard_stop() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let sid = ObjectId::new();
        let scope = scope();
        let mut r = SharedLeases::default();
        assert!(r.note(sid, scope.clone()));
        let offer = ServerMsg::SdpOffer {
            shared_lease: Some(scope.clone()),
            session_id: sid,
            sdp: "not negotiated in this lifecycle test".into(),
            ice_servers: vec![],
            extauth_mac: None,
            peer_auth: None,
        };
        let (tx, mut rx) = mpsc::channel(8);
        assert!(!r.offer(sid, &offer, &tx));
        let ClientMsg::SharedLeaseChallenge { challenge_id, .. } = rx.recv().await.unwrap() else {
            panic!("actual challenge")
        };
        assert!(
            r.renew(sid, ObjectId::new(), &scope.lease_epoch, challenge_id)
                .is_none()
        );
        assert!(
            r.renew(sid, scope.grant_id, "wrong", challenge_id)
                .is_none()
        );
        assert!(matches!(
            r.renew(sid, scope.grant_id, &scope.lease_epoch, challenge_id),
            Some(ServerMsg::SdpOffer { .. })
        ));
        assert!(r.offer(sid, &offer, &tx));
        let stopped = Arc::new(AtomicBool::new(false));
        let flag = stopped.clone();
        assert!(r.attach(
            sid,
            Some(&scope),
            Arc::new(move || {
                flag.store(true, Ordering::SeqCst);
            })
        ));
        // Do not pump signalling. Timer must still stop all serving after 12s.
        tokio::time::advance(WINDOW).await;
        tokio::task::yield_now().await;
        assert!(stopped.load(Ordering::SeqCst));
        assert!(!r.offer(sid, &offer, &tx));
        assert!(
            r.renew(sid, scope.grant_id, &scope.lease_epoch, challenge_id)
                .is_none()
        );
    }
}

#[cfg(test)]
mod shared_lease_scope_regressions {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    fn scope() -> SharedSessionLease {
        SharedSessionLease {
            grant_id: ObjectId::new(),
            lease_epoch: "11111111-1111-4111-8111-111111111111".into(),
        }
    }
    fn offer(sid: ObjectId, scope: Option<SharedSessionLease>) -> ServerMsg {
        ServerMsg::SdpOffer {
            session_id: sid,
            shared_lease: scope,
            sdp: String::new(),
            ice_servers: vec![],
            extauth_mac: None,
            peer_auth: None,
        }
    }
    fn stop_flag() -> (Arc<AtomicBool>, Stop) {
        let flag = Arc::new(AtomicBool::new(false));
        let f = flag.clone();
        (
            flag,
            Arc::new(move || {
                f.store(true, Ordering::SeqCst);
            }),
        )
    }
    #[tokio::test]
    async fn shared_lease_end_late_offer_attach_and_params_never_downgrade_or_revive() {
        let mut r = SharedLeases::default();
        let sid = ObjectId::new();
        let scope = scope();
        let (tx, _) = mpsc::channel(8);
        assert!(r.note_optional(sid, Some(&scope)));
        r.end(sid);
        assert!(r.contains(sid), "end retains bounded tombstone");
        assert!(
            !r.note_optional(sid, Some(&scope)),
            "late GUI Params cannot revive same epoch"
        );
        assert!(
            !r.note_optional(sid, None),
            "old/missing GUI Params cannot downgrade shared"
        );
        assert!(!r.offer(sid, &offer(sid, Some(scope.clone())), &tx));
        assert!(!r.offer(sid, &offer(sid, None), &tx));
        for bound in [Some(&scope), None] {
            let (flag, stop) = stop_flag();
            assert!(!r.attach(sid, bound, stop));
            assert!(flag.load(Ordering::SeqCst));
        }
        assert!(
            r.renew(sid, scope.grant_id, &scope.lease_epoch, 1)
                .is_none()
        );
        assert!(
            r.offer(ObjectId::new(), &offer(ObjectId::new(), None), &tx),
            "genuine legacy remains unchanged"
        );
    }
    #[tokio::test]
    async fn shared_lease_rejected_note_capacity_format_and_conflict_offer_stay_failclosed() {
        let mut r = SharedLeases::default();
        let (tx, _) = mpsc::channel(8);
        for _ in 0..MAX_SESSIONS {
            let sid = ObjectId::new();
            assert!(r.note(sid, scope()));
            r.end(sid);
        }
        let sid = ObjectId::new();
        let scope = scope();
        assert!(!r.note_optional(sid, Some(&scope)));
        assert!(!r.offer(sid, &offer(sid, Some(scope.clone())), &tx));
        let (flag, stop) = stop_flag();
        assert!(!r.attach(sid, Some(&scope), stop));
        assert!(flag.load(Ordering::SeqCst));
        assert_eq!(r.entries.len(), MAX_SESSIONS, "no tombstone eviction");
        let mut r = SharedLeases::default();
        let mut bad = scope.clone();
        bad.lease_epoch = "bad".into();
        assert!(!r.note_optional(sid, Some(&bad)));
        assert!(!r.offer(sid, &offer(sid, Some(bad)), &tx));
        assert!(r.note_optional(sid, Some(&scope)));
        let mut conflict = scope.clone();
        conflict.grant_id = ObjectId::new();
        assert!(!r.note_optional(sid, Some(&conflict)));
        assert!(!r.note_optional(sid, Some(&scope)));
        assert!(!r.offer(sid, &offer(sid, Some(scope)), &tx));
    }
}

#[cfg(test)]
mod shared_ssh_lease_tests {
    use super::*;
    #[tokio::test]
    async fn shared_ssh_lease_actual_tunnel_offer_service_correlation_and_no_downgrade() {
        let sid = ObjectId::new();
        let scope = SharedSessionLease {
            grant_id: ObjectId::new(),
            lease_epoch: "11111111-1111-4111-8111-111111111111".into(),
        };
        let mut r = SharedLeases::default();
        assert!(r.note_ssh(sid, scope.clone()));
        let offer = ServerMsg::TunnelSdpOffer {
            session_id: sid,
            sdp: "fixture-only".into(),
            shared_lease: Some(scope.clone()),
        };
        let (tx, mut rx) = mpsc::channel(8);
        assert!(!r.offer(sid, &offer, &tx));
        let ClientMsg::SharedSshLeaseChallenge { challenge_id, .. } = rx.recv().await.unwrap()
        else {
            panic!("SSH-specific challenge")
        };
        assert!(
            r.renew(sid, scope.grant_id, &scope.lease_epoch, challenge_id)
                .is_none(),
            "desktop ACK cannot release an SSH offer"
        );
        assert!(matches!(
            r.renew_ssh(sid, scope.grant_id, &scope.lease_epoch, challenge_id),
            Some(ServerMsg::TunnelSdpOffer { .. })
        ));
        r.end(sid);
        assert!(!r.note_ssh(sid, scope.clone()));
        assert!(!r.offer(sid, &offer, &tx));
        assert!(!r.offer(
            sid,
            &ServerMsg::TunnelSdpOffer {
                session_id: sid,
                sdp: String::new(),
                shared_lease: None
            },
            &tx
        ));
        let unknown = ObjectId::new();
        assert!(!r.offer(
            unknown,
            &ServerMsg::TunnelSdpOffer {
                session_id: unknown,
                sdp: String::new(),
                shared_lease: Some(scope)
            },
            &tx
        ));
    }
}
