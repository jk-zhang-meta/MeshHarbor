// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-19 P2b — the relay session table and the forwarding decision.
//!
//! One pure function decides what a relay does with an inbound datagram, so
//! every property below is testable without a socket, a clock, or a fleet.
//! [`SessionTable::decide`] takes `now` explicitly for the same reason the
//! probe gate does: lifetimes and expiry are then exercised deterministically
//! rather than by sleeping.
//!
//! # What the relay is, and is not
//!
//! It forwards **WireGuard ciphertext** between two addresses bound to one
//! VNI. It holds no key that decrypts anything, exactly as DERP does not —
//! that is what lets an org run one without becoming a party to the traffic.
//!
//! # The invariants this module exists to hold
//!
//! * **Forward only between the two bound addresses.** A datagram on a known
//!   VNI from anywhere else is dropped and counted, never forwarded. Without
//!   this the relay is an open UDP proxy that rewrites the source to the org's
//!   own address — IP laundering ending in the customer's address being
//!   blocklisted.
//! * **A session dies on its own.** `idle_deadline` is refreshed by traffic,
//!   so it is not a bound at all while a WireGuard keepalive runs every 25 s;
//!   `max_lifetime` is the one that actually expires a busy session, and both
//!   are checked here rather than trusted to a sweeper.
//! * **Re-bind is authenticated, and it is required.** The target population
//!   is behind symmetric NAT, so a mapping change is normal and must not need
//!   a control-plane round trip to recover — but an unauthenticated re-bind
//!   would be a hijack primitive. Both directions are tested.
//! * **The table has a ceiling and refuses rather than grows.** Sessions are
//!   minted by the server, so this is a bound on what an org can ask of its
//!   own relay, not on what an attacker can do — but a relay that could be
//!   handed unbounded state by its control plane is a relay whose host has no
//!   say in its own resource use.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use super::bind::{BindOutcome, BindRefusal, BindSecret, BindVerifier, Mac, Nonce};

/// Default ceiling on concurrent sessions per relay. FR-19's `relay_max_sessions`.
pub const MAX_SESSIONS: usize = 64;

/// One party to a session: its WireGuard public key (identity, as the mint
/// names it) and the secret proving it is that party.
pub struct Member {
    pub wg_public: [u8; 32],
    pub secret: BindSecret,
}

/// A minted relay session. Created by the server, never by an inbound packet —
/// which is why an unauthenticated datagram can never grow this table.
pub struct Session {
    pub vni: u32,
    pub generation: u64,
    pub members: [Member; 2],
    /// Each member's bound source address, learned during the handshake.
    pub bound: [Option<SocketAddr>; 2],
    /// Hard stop, independent of traffic.
    pub max_lifetime: Instant,
    /// Refreshed on every forwarded datagram.
    pub idle_deadline: Instant,
    /// Both members must bind before this, or the session is dead.
    pub bind_deadline: Instant,
}

impl Session {
    fn is_bound(&self) -> bool {
        self.bound[0].is_some() && self.bound[1].is_some()
    }

    /// Which member index this address is bound as, if any.
    fn index_of(&self, addr: &SocketAddr) -> Option<usize> {
        self.bound.iter().position(|b| b.as_ref() == Some(addr))
    }

    fn expired(&self, now: Instant) -> Option<DropReason> {
        if now >= self.max_lifetime {
            return Some(DropReason::SessionExpired);
        }
        if !self.is_bound() && now >= self.bind_deadline {
            return Some(DropReason::BindDeadlinePassed);
        }
        if self.is_bound() && now >= self.idle_deadline {
            return Some(DropReason::SessionIdle);
        }
        None
    }
}

/// Why a datagram was not acted on. One variant per cause: during a flood the
/// cause is the whole diagnostic, and a single "dropped" total cannot separate
/// an attack from a misconfigured peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// No session with this VNI. The commonest case for stray traffic.
    UnknownVni,
    /// A data packet from a source that is not one of the two bound addresses.
    UnboundSource,
    /// Data arrived before both members had bound.
    NotYetBound,
    SessionExpired,
    SessionIdle,
    BindDeadlinePassed,
    Bind(BindRefusal),
}

/// What the relay should do with this datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayAction {
    /// Send this cookie back to the sender as the challenge.
    Challenge(Mac),
    /// The sender is now bound; nothing to send.
    Bound,
    /// Forward the frame verbatim to the other party.
    Forward {
        to: SocketAddr,
    },
    Drop(DropReason),
}

/// The inbound datagram, already parsed out of its framing by the caller.
pub enum Inbound<'a> {
    /// Control: step 1 of the handshake.
    Bind { nonce: Nonce, tag1: Mac },
    /// Control: step 3 of the handshake.
    Answer {
        nonce: Nonce,
        cookie: Mac,
        tag2: Mac,
    },
    /// Data to relay. The bytes are never inspected beyond being forwarded.
    Data(&'a [u8]),
}

/// The table refused a new session because it is at [`MAX_SESSIONS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapReached;

pub struct SessionTable {
    by_vni: HashMap<u32, Session>,
    verifier: BindVerifier,
    cap: usize,
}

impl SessionTable {
    pub fn new(verifier: BindVerifier) -> Self {
        Self {
            by_vni: HashMap::new(),
            verifier,
            cap: MAX_SESSIONS,
        }
    }

    /// Install a minted session, refusing at the cap rather than growing. A
    /// re-mint for a VNI already present replaces it (the server's `lamport`
    /// ordering has already decided that the newer one wins).
    pub fn insert(&mut self, s: Session) -> Result<(), CapReached> {
        if !self.by_vni.contains_key(&s.vni) && self.by_vni.len() >= self.cap {
            return Err(CapReached);
        }
        self.by_vni.insert(s.vni, s);
        Ok(())
    }

    /// Revoke a session immediately.
    ///
    /// ⚠️ Revocation is a **push**, not an expiry. Without it, flipping the org
    /// switch off would leave a live session forwarding until its idle deadline
    /// — which, refreshed by traffic under a 25 s keepalive, is never.
    /// A delayed revoke must not tear down a reminted generation of this VNI.
    pub fn revoke(&mut self, vni: u32, generation: u64) -> bool {
        if self
            .by_vni
            .get(&vni)
            .is_some_and(|s| s.generation == generation)
        {
            self.by_vni.remove(&vni);
            true
        } else {
            false
        }
    }

    pub fn len(&self) -> usize {
        self.by_vni.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_vni.is_empty()
    }

    /// Drop every session that has passed a deadline, returning how many went.
    pub fn reap(&mut self, now: Instant) -> usize {
        let before = self.by_vni.len();
        self.by_vni.retain(|_, s| s.expired(now).is_none());
        before - self.by_vni.len()
    }

    /// The whole relay decision, as a pure function of the table, the datagram
    /// and the clock.
    pub fn decide(
        &mut self,
        vni: u32,
        from: SocketAddr,
        msg: Inbound<'_>,
        now: Instant,
    ) -> RelayAction {
        let Some(s) = self.by_vni.get_mut(&vni) else {
            return RelayAction::Drop(DropReason::UnknownVni);
        };
        if let Some(why) = s.expired(now) {
            return RelayAction::Drop(why);
        }

        match msg {
            Inbound::Bind { nonce, tag1 } => {
                // Try each member: the sender proves WHICH party it is by
                // which secret verifies, so the relay never has to be told.
                for m in &s.members {
                    if let BindOutcome::Challenge(c) =
                        self.verifier
                            .on_bind(&m.secret, vni, s.generation, &nonce, &from, &tag1)
                    {
                        return RelayAction::Challenge(c);
                    }
                }
                RelayAction::Drop(DropReason::Bind(BindRefusal::BadTag1))
            }
            Inbound::Answer {
                nonce,
                cookie,
                tag2,
            } => {
                let mut refusal = BindRefusal::BadCookie;
                for (i, m) in s.members.iter().enumerate() {
                    match self
                        .verifier
                        .on_answer(&m.secret, vni, &nonce, &from, &cookie, &tag2)
                    {
                        BindOutcome::Bound => {
                            // Re-bind is deliberate: a symmetric-NAT peer whose
                            // mapping moved recovers here rather than needing a
                            // control-plane round trip -- and it is safe only
                            // because reaching this arm required the member
                            // secret.
                            s.bound[i] = Some(from);
                            return RelayAction::Bound;
                        }
                        BindOutcome::Refused(r) => refusal = r,
                        BindOutcome::Challenge(_) => {}
                    }
                }
                RelayAction::Drop(DropReason::Bind(refusal))
            }
            Inbound::Data(_) => {
                if !s.is_bound() {
                    return RelayAction::Drop(DropReason::NotYetBound);
                }
                let Some(i) = s.index_of(&from) else {
                    // The invariant that keeps this from being an open UDP
                    // proxy. Mutation-verified: relaxing it to a default index
                    // fails `two_bound_members_relay_to_each_other_and_nobody_else`.
                    return RelayAction::Drop(DropReason::UnboundSource);
                };
                let other = s.bound[1 - i].expect("is_bound checked both");
                s.idle_deadline = now + IDLE_REFRESH;
                RelayAction::Forward { to: other }
            }
        }
    }
}

/// How far a forwarded datagram pushes the idle deadline out.
pub const IDLE_REFRESH: std::time::Duration = std::time::Duration::from_secs(300);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::orgrelay::bind::{CookieKey, tag1, tag2};
    use std::time::Duration;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }
    const N: Nonce = [3u8; 16];

    fn session(vni: u32, now: Instant) -> Session {
        Session {
            vni,
            generation: 1,
            members: [
                Member {
                    wg_public: [0xA; 32],
                    secret: BindSecret::from_bytes([0xA1; 32]),
                },
                Member {
                    wg_public: [0xB; 32],
                    secret: BindSecret::from_bytes([0xB1; 32]),
                },
            ],
            bound: [None, None],
            max_lifetime: now + Duration::from_secs(3600),
            idle_deadline: now + IDLE_REFRESH,
            bind_deadline: now + Duration::from_secs(30),
        }
    }

    fn table() -> (SessionTable, Instant) {
        let now = Instant::now();
        let mut t = SessionTable::new(BindVerifier::new(CookieKey::from_bytes([1u8; 32]), None));
        t.insert(session(42, now)).expect("under cap");
        (t, now)
    }

    /// Drive one member all the way to bound — as the CLIENT would, knowing
    /// nothing about its own mapped address.
    fn bind_member(t: &mut SessionTable, key: u8, a: SocketAddr, now: Instant) {
        let s = BindSecret::from_bytes([key; 32]);
        let t1 = tag1(&s, 42, 1, &N);
        let RelayAction::Challenge(cookie) =
            t.decide(42, a, Inbound::Bind { nonce: N, tag1: t1 }, now)
        else {
            panic!("a valid bind must be challenged");
        };
        let t2 = tag2(&s, &cookie, &N);
        assert_eq!(
            t.decide(
                42,
                a,
                Inbound::Answer {
                    nonce: N,
                    cookie,
                    tag2: t2
                },
                now
            ),
            RelayAction::Bound
        );
    }

    #[test]
    fn two_bound_members_relay_to_each_other_and_nobody_else() {
        let (mut t, now) = table();
        let a = addr("198.51.100.1:5000");
        let b = addr("203.0.113.9:6000");
        bind_member(&mut t, 0xA1, a, now);
        bind_member(&mut t, 0xB1, b, now);

        assert_eq!(
            t.decide(42, a, Inbound::Data(b"x"), now),
            RelayAction::Forward { to: b }
        );
        assert_eq!(
            t.decide(42, b, Inbound::Data(b"x"), now),
            RelayAction::Forward { to: a }
        );

        // The invariant that stops this being an open UDP proxy: a third party
        // on a KNOWN vni is dropped, not forwarded.
        let intruder = addr("192.0.2.66:7000");
        assert_eq!(
            t.decide(42, intruder, Inbound::Data(b"x"), now),
            RelayAction::Drop(DropReason::UnboundSource)
        );
    }

    #[test]
    fn data_before_both_members_bind_is_dropped() {
        let (mut t, now) = table();
        let a = addr("198.51.100.1:5000");
        bind_member(&mut t, 0xA1, a, now);
        assert_eq!(
            t.decide(42, a, Inbound::Data(b"x"), now),
            RelayAction::Drop(DropReason::NotYetBound)
        );
    }

    #[test]
    fn an_unknown_vni_is_dropped_and_creates_nothing() {
        let (mut t, now) = table();
        let before = t.len();
        assert_eq!(
            t.decide(
                99,
                addr("192.0.2.1:1"),
                Inbound::Bind {
                    nonce: N,
                    tag1: [0u8; 16]
                },
                now
            ),
            RelayAction::Drop(DropReason::UnknownVni)
        );
        assert_eq!(
            t.len(),
            before,
            "an inbound packet must never mint a session"
        );
    }

    /// The target population is behind symmetric NAT, so a mapping change is
    /// routine and must recover without a control-plane round trip -- but only
    /// with the member secret, or re-bind is a hijack.
    #[test]
    fn an_authenticated_rebind_moves_the_address_and_an_unauthenticated_one_does_not() {
        let (mut t, now) = table();
        let a = addr("198.51.100.1:5000");
        let b = addr("203.0.113.9:6000");
        bind_member(&mut t, 0xA1, a, now);
        bind_member(&mut t, 0xB1, b, now);

        // A's NAT mapping moves; A re-binds from the new address.
        let a2 = addr("198.51.100.1:5555");
        bind_member(&mut t, 0xA1, a2, now);
        assert_eq!(
            t.decide(42, b, Inbound::Data(b"x"), now),
            RelayAction::Forward { to: a2 },
            "traffic must follow the re-bound address"
        );

        // An attacker with no secret cannot move it: their forged tag1 is
        // refused outright, so they never even reach a challenge here.
        let evil = addr("192.0.2.66:7000");
        let bogus = tag1(&BindSecret::from_bytes([0xEE; 32]), 42, 1, &N);
        assert_eq!(
            t.decide(
                42,
                evil,
                Inbound::Bind {
                    nonce: N,
                    tag1: bogus
                },
                now
            ),
            RelayAction::Drop(DropReason::Bind(BindRefusal::BadTag1))
        );
        assert_eq!(
            t.decide(42, b, Inbound::Data(b"x"), now),
            RelayAction::Forward { to: a2 },
            "a refused bind must not have moved anything"
        );
    }

    /// A REPLAYED tag1 from an attacker earns a challenge (one frame, to the
    /// attacker's own address) but cannot be answered, so nothing moves. This
    /// is the posture the address-at-step-3 design accepts on purpose.
    #[test]
    fn a_replayed_tag1_is_challenged_but_cannot_rebind() {
        let (mut t, now) = table();
        let a = addr("198.51.100.1:5000");
        let b = addr("203.0.113.9:6000");
        bind_member(&mut t, 0xA1, a, now);
        bind_member(&mut t, 0xB1, b, now);

        let evil = addr("192.0.2.66:7000");
        let captured = tag1(&BindSecret::from_bytes([0xA1; 32]), 42, 1, &N);
        let RelayAction::Challenge(cookie) = t.decide(
            42,
            evil,
            Inbound::Bind {
                nonce: N,
                tag1: captured,
            },
            now,
        ) else {
            panic!("a replayed tag1 earns exactly one challenge");
        };
        // No secret ⇒ no valid tag2 ⇒ refused, and A's binding is untouched.
        let forged = tag2(&BindSecret::from_bytes([0xEE; 32]), &cookie, &N);
        assert_eq!(
            t.decide(
                42,
                evil,
                Inbound::Answer {
                    nonce: N,
                    cookie,
                    tag2: forged
                },
                now
            ),
            RelayAction::Drop(DropReason::Bind(BindRefusal::BadTag2))
        );
        assert_eq!(
            t.decide(42, b, Inbound::Data(b"x"), now),
            RelayAction::Forward { to: a }
        );
    }

    /// `idle_deadline` is refreshed by traffic, so under a 25 s WireGuard
    /// keepalive it never fires. `max_lifetime` is the bound that actually
    /// ends a busy session -- which is why both exist.
    #[test]
    fn a_busy_session_still_ends_at_max_lifetime() {
        let (mut t, now) = table();
        let a = addr("198.51.100.1:5000");
        let b = addr("203.0.113.9:6000");
        bind_member(&mut t, 0xA1, a, now);
        bind_member(&mut t, 0xB1, b, now);

        // Traffic every 25 s keeps the idle deadline ahead forever...
        let mut clock = now;
        for _ in 0..100 {
            clock += Duration::from_secs(25);
            assert!(matches!(
                t.decide(42, a, Inbound::Data(b"x"), clock),
                RelayAction::Forward { .. }
            ));
        }
        // ...but the hard stop still lands.
        let past = now + Duration::from_secs(3601);
        assert_eq!(
            t.decide(42, a, Inbound::Data(b"x"), past),
            RelayAction::Drop(DropReason::SessionExpired)
        );
    }

    #[test]
    fn an_idle_session_expires_and_is_reaped() {
        let (mut t, now) = table();
        let a = addr("198.51.100.1:5000");
        let b = addr("203.0.113.9:6000");
        bind_member(&mut t, 0xA1, a, now);
        bind_member(&mut t, 0xB1, b, now);

        let late = now + IDLE_REFRESH + Duration::from_secs(1);
        assert_eq!(
            t.decide(42, a, Inbound::Data(b"x"), late),
            RelayAction::Drop(DropReason::SessionIdle)
        );
        assert_eq!(t.reap(late), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn a_session_nobody_binds_dies_at_the_bind_deadline() {
        let (mut t, now) = table();
        let late = now + Duration::from_secs(31);
        assert_eq!(
            t.decide(
                42,
                addr("198.51.100.1:5000"),
                Inbound::Bind {
                    nonce: N,
                    tag1: [0u8; 16]
                },
                late
            ),
            RelayAction::Drop(DropReason::BindDeadlinePassed)
        );
        assert_eq!(t.reap(late), 1);
    }

    /// Revocation must kill a LIVE, traffic-carrying session immediately --
    /// waiting for a deadline that traffic keeps refreshing is not revocation.
    #[test]
    fn revoke_kills_a_live_session_at_once() {
        let (mut t, now) = table();
        let a = addr("198.51.100.1:5000");
        let b = addr("203.0.113.9:6000");
        bind_member(&mut t, 0xA1, a, now);
        bind_member(&mut t, 0xB1, b, now);
        assert!(matches!(
            t.decide(42, a, Inbound::Data(b"x"), now),
            RelayAction::Forward { .. }
        ));

        assert!(t.revoke(42, 1));
        assert_eq!(
            t.decide(42, a, Inbound::Data(b"x"), now),
            RelayAction::Drop(DropReason::UnknownVni)
        );
        assert!(
            !t.revoke(42, 1),
            "revoking twice is not an error, just false"
        );
    }

    #[test]
    fn stale_revoke_preserves_a_new_generation_on_the_serving_relay() {
        let (mut table, now) = table();
        let mut replacement = session(42, now);
        replacement.generation = 2;
        table.insert(replacement).unwrap();
        assert!(!table.revoke(42, 1), "a delayed revoke is stale");
        assert_eq!(table.len(), 1);
        assert!(table.revoke(42, 2));
        assert!(table.is_empty());
    }

    /// One member's secret must not bind the other's slot: the relay learns
    /// WHICH party a sender is from which secret verifies, so a mix-up here
    /// would let one party occupy both ends.
    #[test]
    fn each_member_binds_its_own_slot() {
        let (mut t, now) = table();
        let a = addr("198.51.100.1:5000");
        let a2 = addr("198.51.100.1:5001");
        bind_member(&mut t, 0xA1, a, now);
        // The SAME member binding again from another address moves its own
        // slot rather than filling the peer's -- so the session is still not
        // fully bound and data is refused.
        bind_member(&mut t, 0xA1, a2, now);
        assert_eq!(
            t.decide(42, a2, Inbound::Data(b"x"), now),
            RelayAction::Drop(DropReason::NotYetBound)
        );
    }

    /// The ceiling refuses rather than grows — and a re-mint of an EXISTING
    /// VNI is not a new session, so it is admitted at the cap.
    #[test]
    fn the_cap_refuses_new_sessions_but_admits_a_remint() {
        let now = Instant::now();
        let mut t = SessionTable::new(BindVerifier::new(CookieKey::from_bytes([1u8; 32]), None));
        for vni in 1..=MAX_SESSIONS as u32 {
            t.insert(session(vni, now)).expect("under cap");
        }
        assert_eq!(t.len(), MAX_SESSIONS);
        assert_eq!(t.insert(session(9999, now)), Err(CapReached));
        assert_eq!(
            t.len(),
            MAX_SESSIONS,
            "a refused insert must not grow the table"
        );
        // Re-minting VNI 1 replaces, it does not add.
        assert_eq!(t.insert(session(1, now)), Ok(()));
        assert_eq!(t.len(), MAX_SESSIONS);
    }
}
