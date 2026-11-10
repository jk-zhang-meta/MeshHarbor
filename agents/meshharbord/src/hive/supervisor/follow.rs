// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2d-3b — the member's wants (spec §3b, "The carrier"): for each
//! session this device holds a copy of, it asks the server for a stream
//! (`rc:hive.replica.want`) on one rung of the ladder at a time, and acts on
//! the answer. A dial it follows ([`super::stream`]); a refusal, or a stream
//! that ends, it answers by asking again, climbing down a rung, waiting, or
//! letting the session be.
//!
//! | Outcome | Next |
//! |---|---|
//! | refused `path_unavailable` or `no_answer`, or a stream that never got past its opening exchange (`unreachable`, `no_turn`, `allocate_failed`, `no_derp`, `auth_failed`, …) | the next rung down at once; past the bottom, wait, then the top |
//! | refused `source_offline`, `busy`, `rate_limited`, or a word this build does not know; a stream that ended for its data | wait, then the same rung |
//! | refused `source_unsupported` or `not_held`; a stream ended `diverged_at_floor` | wait long |
//! | a stream that carried and ended (`expired`, the source let go) | at once, from the top |
//! | a stream ended `caught_up`: the copy holds all of a session that is over | nothing more: parked |
//! | refused `not_a_member` or `stale_fence`; the server's close `member_left` or `device_removed` | stopped, until the next join |
//! | P2e-5c: any of the last two, when a newer join came after the ask that got it | at once, from the top, at the new fence: that answer was about the fence the session left |
//!
//! P2d-4 — **renewals.** A grant lives `ttl_secs` (10 min). At half its life
//! the member asks for the session again, from the top of the ladder, beside
//! the stream it follows, and climbs down a rung for that renewal as for any
//! ask. The renewal's stream is followed beside the old one; once it answers,
//! it is the stream followed and the old one is let go (`renewed`), so a copy
//! is never without a stream at its grant's end (make-before-break). A
//! renewal that finds no rung leaves the old stream to carry on to its end,
//! and the follow asks again then.
//!
//! ⚠️ **Never ratchet.** A rung that carried is not remembered: every new
//! ask, and every renewal, starts from `direct` again, so a member that fell
//! to `derp` is back on a direct path at the first ask that finds one.
//!
//! ⚠️ At most [`MAX_FOLLOWING`] sessions are asked for or followed at once,
//! each with its renewal beside it at most, as many streams as a member
//! follows; the rest wait their turn, in order. A device holds copies of every session its owner ran, most of them
//! over, and a session over that the copy holds whole is let be, so the
//! slots go to the sessions that move.
//!
//! ⚠️ Only the primary organization's connection asks: a device holds copies
//! for its primary organization alone (P2c-3), and the connection that
//! starts this is that one's (`on_connected`).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use bson::oid::ObjectId;
use meshharbor_hive_node::GENESIS;
use meshharbor_remote_control::hive::{HiveStreamPath, HiveStreamRefusal};
use meshharbor_remote_control::signaling::ClientMsg;
use tracing::{debug, info, warn};

use super::Supervisor;
use super::stream::MAX_FOLLOWING;

/// The first wait, after one outcome that carried nothing; each one after
/// doubles it, up to [`WAIT_MAX`].
const WAIT_MIN: Duration = if cfg!(test) {
    Duration::from_millis(50)
} else {
    Duration::from_secs(5)
};
const WAIT_MAX: Duration = if cfg!(test) {
    Duration::from_millis(400)
} else {
    Duration::from_secs(5 * 60)
};
/// The wait after an answer that will not change soon: a source whose build
/// carries no stream, one that does not hold the session, a copy at the
/// current fence the source does not hold.
const WAIT_LONG: Duration = if cfg!(test) {
    Duration::from_millis(800)
} else {
    Duration::from_secs(30 * 60)
};
/// The wait after `rate_limited`: the server counts a minute.
const WAIT_RATE: Duration = if cfg!(test) {
    Duration::from_millis(200)
} else {
    Duration::from_secs(60)
};
/// How long an ask waits for its answer before it is taken for `no_answer`:
/// the server's own wait for the source (30 s), and some.
pub(super) const WANT_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_secs(5)
} else {
    Duration::from_secs(45)
};

/// What this device is doing about one session it holds a copy of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Asked on this rung; the answer is a dial or a refusal.
    Wanting(HiveStreamPath),
    /// Following this grant's stream.
    Following(ObjectId),
    /// Waiting until the next ask.
    Waiting,
    /// Waiting for a slot: as many are asked for or followed as may be.
    Queued,
    /// The copy holds all of a session that is over.
    Parked,
    /// The server says this device is no member of it, or holds it at
    /// another fence: asked for again only at the next join.
    Stopped,
}

/// One session held as a member.
struct Follow {
    /// The membership's fence, which every ask names.
    fence: u64,
    /// P2e-5c — the fence the last ask named. A newer join raises `fence`
    /// while that ask, or the stream it got, is still out: its verdict is
    /// about a fence the session has left.
    asked_fence: u64,
    /// The rung the next ask tries, into [`Supervisor::ladder`].
    rung: usize,
    /// Outcomes in a row that carried nothing: each doubles the wait.
    misses: u32,
    phase: Phase,
    /// Moved on at every change of phase, so a timer or an answer meant for
    /// an earlier one finds this has moved on and does nothing.
    generation: u64,
    /// P2d-4 — the renewal of the stream followed, beside it. Only while
    /// one is followed: every other phase is entered through
    /// [`Supervisor::next`], which lets it go.
    renewal: Option<Renewal>,
    /// P2d-4 — renewal asks so far: each one's own generation.
    renewals: u64,
}

/// P2d-4 — the renewal of a stream followed: asked for at half its grant's
/// life, from the top of the ladder, while the old stream carries on;
/// followed once its own stream answers, and the old one let go then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Renewal {
    /// The rung it asks on, into [`Supervisor::ladder`].
    rung: usize,
    /// Which ask it is: a timeout meant for an earlier one moves nothing.
    generation: u64,
    state: Renewing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Renewing {
    /// Asked on this rung.
    Wanting(HiveStreamPath),
    /// Its dial came: this grant's stream, followed once it answers.
    Dialed { grant: ObjectId, ttl_secs: u32 },
}

impl Follow {
    fn new(fence: u64) -> Self {
        Self {
            fence,
            asked_fence: fence,
            rung: 0,
            misses: 0,
            phase: Phase::Waiting,
            generation: 0,
            renewal: None,
            renewals: 0,
        }
    }
}

/// Every session followed, and those waiting for a slot, in order.
#[derive(Default)]
pub(crate) struct Follows {
    map: HashMap<ObjectId, Follow>,
    queue: VecDeque<ObjectId>,
}

impl Follows {
    /// FR-90 P2g-1 — `session` was purged here: no ask, follow or wait for
    /// it is kept, and none is queued.
    pub(super) fn forget(&mut self, session: ObjectId) {
        self.map.remove(&session);
        self.queue.retain(|s| *s != session);
    }

    /// Sessions asked for or followed now: what the slots count.
    fn active(&self) -> usize {
        self.map
            .values()
            .filter(|f| matches!(f.phase, Phase::Wanting(_) | Phase::Following(_)))
            .count()
    }
}

/// Whose ask an answer is.
enum Asked {
    Follow,
    /// P2d-4.
    Renewal,
}

/// What to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Next {
    /// Ask at once, from the top of the ladder.
    Again,
    /// Ask at once, a rung down; past the bottom, wait, then the top.
    Down,
    /// Wait, then ask on the same rung.
    Later,
    /// Wait long, then ask from the top.
    LongLater,
    /// Wait a minute, then ask on the same rung.
    RateLater,
    Park,
    Stop,
}

/// A refusal's next step.
fn after_refusal(reason: Option<HiveStreamRefusal>) -> Next {
    match reason {
        Some(HiveStreamRefusal::PathUnavailable | HiveStreamRefusal::NoAnswer) => Next::Down,
        Some(HiveStreamRefusal::NotAMember | HiveStreamRefusal::StaleFence) => Next::Stop,
        Some(HiveStreamRefusal::SourceUnsupported | HiveStreamRefusal::NotHeld) => Next::LongLater,
        Some(HiveStreamRefusal::RateLimited) => Next::RateLater,
        // `source_offline`, `busy`, and a word this build cannot read.
        _ => Next::Later,
    }
}

/// A member stream's end's next step: the reason it ended in, and whether it
/// got past its opening exchange (the rung carried).
fn after_stream(reason: &str, answered: bool) -> Next {
    match reason {
        "caught_up" => Next::Park,
        // The device's own word, or the server's close.
        "not_a_member" | "secondary_org" | "member_left" | "device_removed" => Next::Stop,
        "diverged_at_floor" => Next::LongLater,
        // The grant ran out, or the source let go (its daemon restarted, it
        // was the last to receive): ask again, from the top.
        "expired" | "closed" | "source_closed" if answered => Next::Again,
        // Never past the opening exchange: this rung does not carry.
        "unreachable" | "no_address" | "no_turn" | "allocate_failed" | "no_derp"
        | "no_derp_key" | "auth_failed" | "no_answer" | "source_gone" | "path_unavailable"
        | "expired" | "closed" | "source_closed"
            if !answered =>
        {
            Next::Down
        }
        // Its data (a frame, a blob, the chain), a busy member, the store.
        _ => Next::Later,
    }
}

/// `wait`, give or take a fifth, so devices that lost the same source do
/// not all ask again at once.
fn jittered(wait: Duration) -> Duration {
    let fifth = wait.as_millis() as u64 / 5;
    if fifth == 0 {
        return wait;
    }
    let off = rand::random::<u64>() % (2 * fifth + 1);
    wait - Duration::from_millis(fifth) + Duration::from_millis(off)
}

/// The wait after `misses` outcomes in a row that carried nothing.
fn backoff(misses: u32) -> Duration {
    let doubled = WAIT_MIN.saturating_mul(1 << misses.saturating_sub(1).min(16));
    jittered(doubled.min(WAIT_MAX))
}

impl Supervisor {
    /// The rungs this device can ask on, top first: `derp` only while it has
    /// a live DERP connection, whose key the ask names.
    fn ladder(&self) -> Vec<HiveStreamPath> {
        let mut rungs = vec![HiveStreamPath::Direct, HiveStreamPath::Relay];
        if self.derp_handle().is_some() {
            rungs.push(HiveStreamPath::Derp);
        }
        rungs
    }

    /// At the primary organization's connection: every session held as a
    /// member is followed. One followed, queued or waiting already is left
    /// as it is; one asked for is asked again (its answer would have come on
    /// the connection that went), and so is a renewal asked for (P2d-4); one
    /// parked or stopped stays so.
    pub(super) async fn follow_all(self: &Arc<Self>) {
        let Ok(store) = &self.store else {
            return;
        };
        let held = match store.memberships().await {
            Ok(m) => m,
            Err(e) => return warn!(%e, "hive: the memberships could not be read to follow them"),
        };
        enum Again {
            Follow,
            Renewal(HiveStreamPath, u64, u64),
        }
        for m in held {
            let Ok(session) = ObjectId::parse_str(&m.session) else {
                continue;
            };
            let again = {
                let mut follows = self.follows.lock().unwrap_or_else(|e| e.into_inner());
                match follows.map.get_mut(&session) {
                    None => {
                        follows.map.insert(session, Follow::new(m.fence));
                        Some(Again::Follow)
                    }
                    Some(f) => {
                        f.fence = f.fence.max(m.fence);
                        match (f.phase, f.renewal.map(|r| r.state)) {
                            (Phase::Wanting(_), _) => Some(Again::Follow),
                            (Phase::Following(_), Some(Renewing::Wanting(path))) => {
                                // A new generation: the ask that went with the
                                // connection times out moving nothing.
                                f.renewals += 1;
                                let generation = f.renewals;
                                if let Some(r) = f.renewal.as_mut() {
                                    r.generation = generation;
                                }
                                Some(Again::Renewal(path, f.fence, generation))
                            }
                            _ => None,
                        }
                    }
                }
            };
            match again {
                Some(Again::Follow) => self.ask(session),
                Some(Again::Renewal(path, fence, generation)) => {
                    self.send_renewal(session, fence, path, generation)
                }
                None => {}
            }
        }
    }

    /// FR-90 P2f-1b — at the primary organization's connection, on a device
    /// whose owner holds no copies: only the copies of the teleports it was
    /// prepared for (P2f-1a) are followed, each at the fence its join named.
    /// Every other copy it holds is left as it is: a leftover of a teleport
    /// that is over, which the purge takes (P2g).
    pub(super) async fn follow_teleports(self: &Arc<Self>) {
        let Ok(store) = &self.store else {
            return;
        };
        let held = match store.memberships().await {
            Ok(m) => m,
            Err(e) => {
                return warn!(%e, "hive: the memberships could not be read to follow a teleport's");
            }
        };
        for m in held {
            let Ok(session) = ObjectId::parse_str(&m.session) else {
                continue;
            };
            if self.teleport_admitted(session, m.fence) {
                self.follow_joined(session, m.fence);
            }
        }
    }

    /// A join this device passed as a member, at `fence`: the session is
    /// followed from the top, whatever it was doing, unless it is followed
    /// or asked for already, which the new fence goes to.
    ///
    /// P2e-5c — an ask out at an older fence is asked again now, at the new
    /// one: the session moved, and that ask's answer can only name where it
    /// was. A grant toward its old location is ended by the server at the
    /// move, before its dial, and a member never hears of a grant it was not
    /// dialed for, so it would wait out the ask's whole timeout. The old
    /// ask's answer then moves nothing: a refusal names its fence, and a
    /// timer its generation.
    pub(super) fn follow_joined(self: &Arc<Self>, session: ObjectId, fence: u64) {
        let ask = {
            let mut follows = self.follows.lock().unwrap_or_else(|e| e.into_inner());
            let f = follows.map.entry(session).or_insert(Follow::new(fence));
            f.fence = f.fence.max(fence);
            match f.phase {
                Phase::Wanting(_) if f.fence > f.asked_fence => {
                    f.rung = 0;
                    f.misses = 0;
                    true
                }
                Phase::Wanting(_) | Phase::Following(_) | Phase::Queued => false,
                Phase::Waiting | Phase::Parked | Phase::Stopped => {
                    f.rung = 0;
                    f.misses = 0;
                    true
                }
            }
        };
        if ask {
            self.ask(session);
        }
    }

    /// Ask for `session`'s stream now, on its rung, or queue it when every
    /// slot is taken. The ask itself goes from a task of its own: it reads
    /// the copy's tip from the store.
    fn ask(self: &Arc<Self>, session: ObjectId) {
        let ladder = self.ladder();
        let asked = {
            let mut follows = self.follows.lock().unwrap_or_else(|e| e.into_inner());
            // Its own slot, if it held one (an ask again), is its to keep.
            let others = follows
                .map
                .iter()
                .filter(|(s, f)| {
                    **s != session && matches!(f.phase, Phase::Wanting(_) | Phase::Following(_))
                })
                .count();
            let full = others >= MAX_FOLLOWING;
            let Some(f) = follows.map.get_mut(&session) else {
                return;
            };
            f.generation += 1;
            if full {
                f.phase = Phase::Queued;
                if !follows.queue.contains(&session) {
                    follows.queue.push_back(session);
                }
                return debug!(session = %session, "hive: every follow slot is taken — queued");
            }
            if f.rung >= ladder.len() {
                f.rung = 0;
            }
            let path = ladder[f.rung];
            f.phase = Phase::Wanting(path);
            f.asked_fence = f.fence;
            (path, f.fence, f.generation)
        };
        let (path, fence, generation) = asked;
        let sup = Arc::clone(self);
        tokio::spawn(async move {
            sup.send_want(session, fence, path).await;
            // No answer at all: taken for one the source never gave.
            tokio::time::sleep(WANT_TIMEOUT).await;
            if sup.still(session, generation) {
                debug!(session = %session, path = path.as_str(), "hive: an ask went unanswered");
                sup.next(session, Next::Down);
            }
        });
    }

    /// `rc:hive.replica.want`, with where the copy ends now, on the primary
    /// organization's connection. Nothing goes while it is down: the next
    /// connection asks again.
    async fn send_want(&self, session: ObjectId, fence: u64, path: HiveStreamPath) {
        let Ok(store) = &self.store else {
            return;
        };
        let (seq, hash) = match store.chain_tip(&session.to_hex()).await {
            Ok(Some(t)) => (t.seq, hex::encode(t.hash)),
            Ok(None) => (0, hex::encode(GENESIS)),
            Err(e) => {
                return warn!(session = %session, %e, "hive: a copy's tip could not be read to ask for it");
            }
        };
        let derp_pubkey = match path {
            HiveStreamPath::Derp => self.derp_handle().map(|h| h.self_pubkey_hex.clone()),
            HiveStreamPath::Direct | HiveStreamPath::Relay => None,
        };
        let tx = self
            .reporter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let want = ClientMsg::HiveReplicaWant {
            session_id: session,
            fence,
            seq,
            hash,
            path: Some(path),
            derp_pubkey,
        };
        info!(session = %session, fence, seq, path = path.as_str(), "hive: asking for a stream");
        if let Some(tx) = tx {
            let _ = tx.try_send(want);
        }
    }

    /// Whether `session`'s follow is still where `generation` left it.
    fn still(&self, session: ObjectId, generation: u64) -> bool {
        self.follows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .get(&session)
            .is_some_and(|f| f.generation == generation)
    }

    /// `rc:hive.replica.refused`, for the ask in flight on `path` at
    /// `fence`: the follow's own, or its renewal's (P2d-4). One for any other
    /// moves nothing.
    pub(super) fn on_refused(
        self: &Arc<Self>,
        session: ObjectId,
        fence: u64,
        path: Option<HiveStreamPath>,
        reason: Option<HiveStreamRefusal>,
    ) {
        let asked = self
            .follows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .get(&session)
            .filter(|f| f.fence == fence)
            .and_then(|f| match (f.phase, f.renewal.map(|r| r.state)) {
                (Phase::Wanting(p), _) if path == Some(p) => Some(Asked::Follow),
                (Phase::Following(_), Some(Renewing::Wanting(p))) if path == Some(p) => {
                    Some(Asked::Renewal)
                }
                _ => None,
            });
        match asked {
            Some(Asked::Follow) => self.next(session, after_refusal(reason)),
            Some(Asked::Renewal) => self.renewal_next(session, after_refusal(reason)),
            None => debug!(session = %session, "hive: a refusal for no ask in flight — ignored"),
        }
    }

    /// A dial came for `session`. While a stream of it is followed, the dial
    /// is that stream's renewal (P2d-4), or one that came late: it is
    /// followed beside it and takes its place once it answers
    /// ([`Self::on_answered`]). A renewal dialed already is let go for it
    /// (`replaced`), as the server's third grant replaces its oldest: the
    /// newest is the one to follow. Otherwise the session is followed on
    /// `grant_id`'s stream, renewed at half its grant's life.
    pub(super) fn on_dialed(
        self: &Arc<Self>,
        session: ObjectId,
        grant_id: ObjectId,
        ttl_secs: u32,
    ) {
        enum Dialed {
            Followed(u64),
            Renewal(Option<ObjectId>),
        }
        let dialed = {
            let mut follows = self.follows.lock().unwrap_or_else(|e| e.into_inner());
            let Some(f) = follows.map.get_mut(&session) else {
                return;
            };
            if f.phase == Phase::Following(grant_id) {
                // A replay of the dial followed: renewed as it was.
                return;
            }
            if let Phase::Following(_) = f.phase {
                let replaced = match f.renewal.map(|r| r.state) {
                    Some(Renewing::Dialed { grant, .. }) if grant != grant_id => Some(grant),
                    _ => None,
                };
                let (rung, generation) = match f.renewal {
                    Some(r) => (r.rung, r.generation),
                    None => {
                        f.renewals += 1;
                        (0, f.renewals)
                    }
                };
                f.renewal = Some(Renewal {
                    rung,
                    generation,
                    state: Renewing::Dialed {
                        grant: grant_id,
                        ttl_secs,
                    },
                });
                Dialed::Renewal(replaced)
            } else {
                f.generation += 1;
                f.phase = Phase::Following(grant_id);
                f.renewal = None;
                let generation = f.generation;
                follows.queue.retain(|s| *s != session);
                Dialed::Followed(generation)
            }
        };
        match dialed {
            Dialed::Followed(generation) => {
                self.renew_later(session, grant_id, generation, ttl_secs)
            }
            Dialed::Renewal(Some(older)) => self.end_stream(older, "replaced"),
            Dialed::Renewal(None) => {}
        }
    }

    /// P2d-4 — a member stream of `session` got past its opening exchange.
    /// When it is the renewal's, it is the stream followed from now on, and
    /// the one it renews is let go (`renewed`): make-before-break.
    pub(super) fn on_answered(self: &Arc<Self>, session: ObjectId, grant_id: ObjectId) {
        let renewed = {
            let mut follows = self.follows.lock().unwrap_or_else(|e| e.into_inner());
            let Some(f) = follows.map.get_mut(&session) else {
                return;
            };
            match (f.phase, f.renewal) {
                (
                    Phase::Following(old),
                    Some(Renewal {
                        rung,
                        state: Renewing::Dialed { grant, ttl_secs },
                        ..
                    }),
                ) if grant == grant_id => {
                    f.generation += 1;
                    f.phase = Phase::Following(grant_id);
                    f.rung = rung;
                    f.renewal = None;
                    Some((old, f.generation, ttl_secs))
                }
                _ => None,
            }
        };
        if let Some((old, generation, ttl_secs)) = renewed {
            info!(session = %session, old = %old, new = %grant_id, "hive: a stream renewed — the old one let go");
            self.end_stream(old, "renewed");
            self.renew_later(session, grant_id, generation, ttl_secs);
        }
    }

    /// P2d-4 — at half `grant_id`'s life, its renewal, if it is still the
    /// stream followed (`generation`) and nothing renews it yet.
    fn renew_later(
        self: &Arc<Self>,
        session: ObjectId,
        grant_id: ObjectId,
        generation: u64,
        ttl_secs: u32,
    ) {
        let half = Duration::from_millis(u64::from(ttl_secs) * 500);
        let sup = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(half).await;
            sup.renew(session, grant_id, generation);
        });
    }

    /// P2d-4 — ask for `session`'s stream again from the top of the ladder,
    /// beside `grant_id`'s, which carries on until the new one does. Never
    /// ratchet: a member that fell to `derp` asks for `direct` first at every
    /// renewal.
    fn renew(self: &Arc<Self>, session: ObjectId, grant_id: ObjectId, generation: u64) {
        let ladder = self.ladder();
        let asked = {
            let mut follows = self.follows.lock().unwrap_or_else(|e| e.into_inner());
            let Some(f) = follows.map.get_mut(&session) else {
                return;
            };
            if f.generation != generation
                || f.phase != Phase::Following(grant_id)
                || f.renewal.is_some()
            {
                return;
            }
            f.renewals += 1;
            let path = ladder[0];
            f.renewal = Some(Renewal {
                rung: 0,
                generation: f.renewals,
                state: Renewing::Wanting(path),
            });
            (path, f.fence, f.renewals)
        };
        let (path, fence, generation) = asked;
        info!(session = %session, grant = %grant_id, "hive: renewing a stream at half its grant's life");
        self.send_renewal(session, fence, path, generation);
    }

    /// P2d-4 — a renewal's ask, `generation`, and its timeout: no answer at
    /// all is taken for one the source never gave, as the follow's own.
    fn send_renewal(
        self: &Arc<Self>,
        session: ObjectId,
        fence: u64,
        path: HiveStreamPath,
        generation: u64,
    ) {
        let sup = Arc::clone(self);
        tokio::spawn(async move {
            sup.send_want(session, fence, path).await;
            tokio::time::sleep(WANT_TIMEOUT).await;
            let unanswered = sup
                .follows
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .map
                .get(&session)
                .and_then(|f| f.renewal)
                .is_some_and(|r| {
                    r.generation == generation && matches!(r.state, Renewing::Wanting(_))
                });
            if unanswered {
                debug!(session = %session, path = path.as_str(), "hive: a renewal's ask went unanswered");
                sup.renewal_next(session, Next::Down);
            }
        });
    }

    /// P2d-4 — a renewal's answer. A rung that does not carry: the next one
    /// down, while there is one. Anything else: no renewal this time. The
    /// stream followed carries on to its end either way, and the follow
    /// asks again then.
    fn renewal_next(self: &Arc<Self>, session: ObjectId, next: Next) {
        let ladder = self.ladder();
        let again = {
            let mut follows = self.follows.lock().unwrap_or_else(|e| e.into_inner());
            let Some(f) = follows.map.get_mut(&session) else {
                return;
            };
            let Some(r) = f.renewal.as_mut() else {
                return;
            };
            if next == Next::Down && r.rung + 1 < ladder.len() {
                f.renewals += 1;
                r.rung += 1;
                r.generation = f.renewals;
                r.state = Renewing::Wanting(ladder[r.rung]);
                Some((ladder[r.rung], f.fence, r.generation))
            } else {
                f.renewal = None;
                None
            }
        };
        match again {
            Some((path, fence, generation)) => self.send_renewal(session, fence, path, generation),
            None => {
                info!(session = %session, ?next, "hive: no renewal this time — the stream followed carries on to its end")
            }
        }
    }

    /// A dial this device turned away before following it (`busy`, a rung
    /// this build cannot name): the answer to the ask in flight, the
    /// follow's or its renewal's, if one is.
    pub(super) fn on_dial_dropped(self: &Arc<Self>, session: ObjectId, reason: &str) {
        let asked = self
            .follows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .get(&session)
            .and_then(|f| match (f.phase, f.renewal.map(|r| r.state)) {
                (Phase::Wanting(_), _) => Some(Asked::Follow),
                (Phase::Following(_), Some(Renewing::Wanting(_))) => Some(Asked::Renewal),
                _ => None,
            });
        match asked {
            Some(Asked::Follow) => self.next(session, after_stream(reason, false)),
            Some(Asked::Renewal) => self.renewal_next(session, after_stream(reason, false)),
            None => {}
        }
    }

    /// A member stream of `session` ended, in `reason`, past its opening
    /// exchange (`answered`) or not.
    ///
    /// | The stream | Next |
    /// |---|---|
    /// | the one followed, its renewal dialed | the renewal is the stream followed (P2d-4) |
    /// | the one followed, its end one that lets the session be (parked, stopped) | the renewal's stream, if dialed, is let go too |
    /// | the one followed, no renewal dialed | the follow moves on |
    /// | the renewal's, before it answered | the renewal's answer |
    /// | any other (an older one, let go for its renewal) | nothing |
    pub(super) fn on_stream_over(
        self: &Arc<Self>,
        session: ObjectId,
        grant_id: ObjectId,
        reason: &str,
        answered: bool,
    ) {
        enum Ended {
            HandedOver(ObjectId, u64, u32),
            Followed(Option<ObjectId>),
            Renewal,
        }
        let next = after_stream(reason, answered);
        let over = {
            let mut follows = self.follows.lock().unwrap_or_else(|e| e.into_inner());
            let Some(f) = follows.map.get_mut(&session) else {
                return;
            };
            let dialed = match f.renewal {
                Some(Renewal {
                    rung,
                    state: Renewing::Dialed { grant, ttl_secs },
                    ..
                }) => Some((rung, grant, ttl_secs)),
                _ => None,
            };
            match (f.phase, dialed) {
                (Phase::Following(g), Some((rung, grant, ttl_secs)))
                    if g == grant_id && !matches!(next, Next::Park | Next::Stop) =>
                {
                    f.generation += 1;
                    f.phase = Phase::Following(grant);
                    f.rung = rung;
                    f.renewal = None;
                    Ended::HandedOver(grant, f.generation, ttl_secs)
                }
                (Phase::Following(g), dialed) if g == grant_id => {
                    Ended::Followed(dialed.map(|(_, grant, _)| grant))
                }
                (Phase::Following(_), Some((_, grant, _))) if grant == grant_id => Ended::Renewal,
                _ => return,
            }
        };
        match over {
            Ended::HandedOver(grant, generation, ttl_secs) => {
                info!(session = %session, old = %grant_id, new = %grant, %reason, "hive: a stream ended — its renewal follows on");
                self.renew_later(session, grant, generation, ttl_secs);
            }
            Ended::Followed(renewal) => {
                if let Some(grant) = renewal {
                    self.end_stream(grant, reason);
                }
                self.next(session, next);
            }
            Ended::Renewal => self.renewal_next(session, next),
        }
    }

    /// Act on `next` for `session`, and give a slot this frees to the
    /// session that waited longest for one.
    fn next(self: &Arc<Self>, session: ObjectId, next: Next) {
        let ladder_len = self.ladder().len();
        let (ask_now, wait, generation, next) = {
            let mut follows = self.follows.lock().unwrap_or_else(|e| e.into_inner());
            let Some(f) = follows.map.get_mut(&session) else {
                return;
            };
            f.generation += 1;
            // P2e-5c — a session parked or stopped by the answer to an ask
            // that a newer join overtook is asked for again, from the top, at
            // its new fence: that answer was about the fence the session
            // left. A move is the one way to a newer join, and a session that
            // moves runs on.
            let next = if matches!(next, Next::Park | Next::Stop) && f.fence > f.asked_fence {
                Next::Again
            } else {
                next
            };
            // Out of its stream or its ask either way: the slot is free
            // until the next ask takes it. A renewal asked for goes with it
            // (P2d-4): its answer, should it come, is taken for the next
            // ask's.
            f.phase = Phase::Waiting;
            f.renewal = None;
            let (ask_now, wait) = match next {
                Next::Again => {
                    f.rung = 0;
                    f.misses = 0;
                    (true, None)
                }
                Next::Down if f.rung + 1 < ladder_len => {
                    f.rung += 1;
                    (true, None)
                }
                Next::Down => {
                    f.rung = 0;
                    f.misses += 1;
                    (false, Some(backoff(f.misses)))
                }
                Next::Later => {
                    f.misses += 1;
                    (false, Some(backoff(f.misses)))
                }
                Next::LongLater => {
                    f.rung = 0;
                    f.misses += 1;
                    (false, Some(jittered(WAIT_LONG)))
                }
                Next::RateLater => (false, Some(jittered(WAIT_RATE))),
                Next::Park => {
                    f.phase = Phase::Parked;
                    (false, None)
                }
                Next::Stop => {
                    f.phase = Phase::Stopped;
                    (false, None)
                }
            };
            (ask_now, wait, f.generation, next)
        };
        info!(session = %session, ?next, wait_ms = wait.map(|w| w.as_millis() as u64), "hive: a follow moves on");
        if ask_now {
            self.ask(session);
        } else if let Some(wait) = wait {
            let sup = Arc::clone(self);
            tokio::spawn(async move {
                tokio::time::sleep(wait).await;
                if sup.still(session, generation) {
                    sup.ask(session);
                }
            });
        }
        self.dequeue();
    }

    /// Give each free slot to the session queued longest.
    fn dequeue(self: &Arc<Self>) {
        loop {
            let next = {
                let mut follows = self.follows.lock().unwrap_or_else(|e| e.into_inner());
                if follows.active() >= MAX_FOLLOWING {
                    return;
                }
                let Some(session) = follows.queue.pop_front() else {
                    return;
                };
                match follows.map.get(&session) {
                    Some(f) if f.phase == Phase::Queued => session,
                    _ => continue,
                }
            };
            self.ask(next);
        }
    }

    /// What this device is doing about `session` now.
    #[cfg(all(test, unix))]
    pub(super) fn follow_phase(&self, session: ObjectId) -> Option<Phase> {
        self.follows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .get(&session)
            .map(|f| f.phase)
    }

    /// P2d-4 — what renews the stream followed of `session` now, if
    /// anything does: the renewal's rung, and how far it is.
    #[cfg(all(test, unix))]
    pub(super) fn follow_renewal(&self, session: ObjectId) -> Option<(usize, Renewing)> {
        self.follows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .get(&session)
            .and_then(|f| f.renewal)
            .map(|r| (r.rung, r.state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each answer's next step, as the module's table says.
    #[test]
    fn each_answer_has_its_next_step() {
        use HiveStreamRefusal as R;
        for (word, next) in [
            (Some(R::PathUnavailable), Next::Down),
            (Some(R::NoAnswer), Next::Down),
            (Some(R::NotAMember), Next::Stop),
            (Some(R::StaleFence), Next::Stop),
            (Some(R::SourceUnsupported), Next::LongLater),
            (Some(R::NotHeld), Next::LongLater),
            (Some(R::RateLimited), Next::RateLater),
            (Some(R::SourceOffline), Next::Later),
            (Some(R::Busy), Next::Later),
            (Some(R::Other), Next::Later),
            (None, Next::Later),
        ] {
            assert_eq!(after_refusal(word), next, "{word:?}");
        }
        for (reason, answered, next) in [
            ("caught_up", true, Next::Park),
            ("member_left", true, Next::Stop),
            ("device_removed", false, Next::Stop),
            ("not_a_member", false, Next::Stop),
            ("replaced", true, Next::Later),
            ("diverged_at_floor", true, Next::LongLater),
            ("expired", true, Next::Again),
            ("source_closed", true, Next::Again),
            ("expired", false, Next::Down),
            ("unreachable", false, Next::Down),
            ("allocate_failed", false, Next::Down),
            ("no_derp", false, Next::Down),
            ("auth_failed", false, Next::Down),
            ("bad_frame", true, Next::Later),
            ("source:blob_missing", true, Next::Later),
            ("busy", false, Next::Later),
            ("refused", false, Next::Later),
        ] {
            assert_eq!(after_stream(reason, answered), next, "{reason} {answered}");
        }
    }

    /// A wait doubles with each miss, up to its ceiling, give or take a
    /// fifth.
    #[test]
    fn a_wait_doubles_to_its_ceiling() {
        for (misses, base) in [
            (1, WAIT_MIN),
            (2, WAIT_MIN * 2),
            (3, WAIT_MIN * 4),
            (30, WAIT_MAX),
        ] {
            let base = base.min(WAIT_MAX);
            for _ in 0..50 {
                let w = backoff(misses);
                assert!(
                    w >= base - base / 5 && w <= base + base / 5,
                    "{misses}: {w:?} around {base:?}"
                );
            }
        }
    }
}
