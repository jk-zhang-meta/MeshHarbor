// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Local B8 consent, session-bound peer consent, and authenticated leg proof.
//!
//! This protocol never establishes WireGuard sessions or selects a primary.
//! Its owner supplies only transcripts/frames actually authenticated by the
//! current peer's one Tunn. A normal disco pong cannot authorize a leg.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

use super::multipath::MultipathMode;

pub(crate) const LEN: usize = 192;
const DOMAIN: &[u8] = b"meshharbor/multipath/v1";
const WAIT: Duration = Duration::from_secs(2);
const LEASE: Duration = Duration::from_secs(30);
const GLOBAL_HOLD_LIMIT: usize = 4 * 1024 * 1024;
const PEER_HOLD_BYTES: usize = 256 * 1024;
const PEER_HOLD_PACKETS: usize = 64;
const HOLD_TIME: Duration = Duration::from_secs(40);
static HELD_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Includes packets currently draining, until the owner drops the packet.
pub(crate) struct HeldPacket {
    bytes: Vec<u8>,
    budget: Arc<HoldBudget>,
}
#[derive(Default)]
struct HoldBudget {
    bytes: AtomicUsize,
    packets: AtomicUsize,
}
impl HeldPacket {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl Drop for HeldPacket {
    fn drop(&mut self) {
        let len = self.bytes.len();
        self.bytes.fill(0);
        self.budget.bytes.fetch_sub(len, Ordering::AcqRel);
        self.budget.packets.fetch_sub(1, Ordering::AcqRel);
        HELD_BYTES.fetch_sub(len, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct HoldSnapshot {
    pub packets: usize,
    pub bytes: usize,
    pub global_bytes: usize,
    pub overflow: u64,
    pub expired: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Kind {
    Offer = 0x20,
    Ack = 0x21,
    Challenge = 0x22,
    Proof = 0x23,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Frame {
    pub kind: Kind,
    pub mode: MultipathMode,
    pub nonce: [u8; 16],
    pub transcript: [u8; 32],
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    pub session_generation: u64,
    pub role_generation: u64,
}

/// Shape only. A mux may drop unowned control without knowing any WG key.
pub(crate) fn shaped(bytes: &[u8]) -> bool {
    bytes.len() == LEN
        && bytes.starts_with(super::disco::MAGIC)
        && matches!(bytes[8], 0x20..=0x23)
        && bytes[9] == 1
        && matches!(bytes[10], 1..=3)
        && bytes[11..16] == [0; 5]
}

pub(crate) fn claimed_sender(bytes: &[u8]) -> Option<[u8; 32]> {
    shaped(bytes).then(|| bytes[16..48].try_into().expect("fixed shape"))
}

fn nonce() -> [u8; 16] {
    loop {
        let mut value = [0; 16];
        rand::rng().fill_bytes(&mut value);
        if value != [0; 16] {
            return value;
        }
    }
}

fn fresh(now: Instant, at: Instant, lifetime: Duration) -> bool {
    now.checked_duration_since(at)
        .is_some_and(|age| age < lifetime)
}

fn derive(shared: &[u8; 32]) -> Option<[u8; 32]> {
    if shared == &[0; 32] {
        return None;
    }
    let mut h = <Hmac<Sha256> as Mac>::new_from_slice(shared).ok()?;
    h.update(DOMAIN);
    Some(h.finalize().into_bytes().into())
}

pub(crate) fn encode(
    frame: &Frame,
    sender: &[u8; 32],
    recipient: &[u8; 32],
    shared: &[u8; 32],
) -> Option<Vec<u8>> {
    if frame.mode == MultipathMode::Off
        || frame.nonce == [0; 16]
        || frame.transcript == [0; 32]
        || matches!(frame.kind, Kind::Offer | Kind::Ack) && frame.digest != [0; 32]
        || matches!(frame.kind, Kind::Challenge | Kind::Proof) && frame.digest == [0; 32]
    {
        return None;
    }
    let key = derive(shared)?;
    let mut out = vec![0; LEN];
    out[..8].copy_from_slice(super::disco::MAGIC);
    out[8] = frame.kind as u8;
    out[9] = 1;
    out[10] = frame.mode as u8;
    out[16..48].copy_from_slice(sender);
    out[48..80].copy_from_slice(recipient);
    out[80..96].copy_from_slice(&frame.nonce);
    out[96..128].copy_from_slice(&frame.transcript);
    out[128..160].copy_from_slice(&frame.digest);
    let mut h = <Hmac<Sha256> as Mac>::new_from_slice(&key).ok()?;
    h.update(&out[..160]);
    out[160..].copy_from_slice(&h.finalize().into_bytes());
    Some(out)
}

pub(crate) fn decode(
    bytes: &[u8],
    sender: &[u8; 32],
    recipient: &[u8; 32],
    shared: &[u8; 32],
) -> Option<Frame> {
    if !shaped(bytes) || bytes[16..48] != *sender || bytes[48..80] != *recipient {
        return None;
    }
    let key = derive(shared)?;
    let mut h = <Hmac<Sha256> as Mac>::new_from_slice(&key).ok()?;
    h.update(&bytes[..160]);
    h.verify_slice(&bytes[160..]).ok()?;
    let frame = Frame {
        kind: match bytes[8] {
            0x20 => Kind::Offer,
            0x21 => Kind::Ack,
            0x22 => Kind::Challenge,
            0x23 => Kind::Proof,
            _ => return None,
        },
        mode: MultipathMode::from_u8(bytes[10]),
        nonce: bytes[80..96].try_into().ok()?,
        transcript: bytes[96..128].try_into().ok()?,
        digest: bytes[128..160].try_into().ok()?,
    };
    if frame.nonce == [0; 16]
        || frame.transcript == [0; 32]
        || matches!(frame.kind, Kind::Offer | Kind::Ack) && frame.digest != [0; 32]
        || matches!(frame.kind, Kind::Challenge | Kind::Proof) && frame.digest == [0; 32]
    {
        return None;
    }
    Some(frame)
}

#[derive(Clone)]
struct Session {
    local_index: u32,
    remote_index: u32,
    digest: [u8; 32],
    generation: u64,
    response_sent: [Option<Instant>; 2],
    round_trip: [Option<Instant>; 2],
}

struct Handshake {
    bytes: Vec<u8>,
    legs: [Option<Instant>; 2],
}

struct Pending {
    nonce: [u8; 16],
    digest: [u8; 32],
    at: Instant,
    binding: Binding,
}

#[derive(Default)]
struct State {
    retired: bool,
    sent: VecDeque<Handshake>,
    received: VecDeque<Handshake>,
    sessions: VecDeque<Session>,
    active: Option<Session>,
    generation: u64,
    role_generation: u64,
    offer: Option<Pending>,
    offer_attempts: u8,
    peer_until: Option<Instant>,
    challenge: Option<Pending>,
    primary_challenge: Option<Pending>,
    primary_answered: Option<Instant>,
    primary_started: Option<Instant>,
    primary_fallback: bool,
    challenge_attempts: u8,
    last_challenge: Option<Instant>,
    proven: bool,
    had_proven_secondary: bool,
    recent: VecDeque<(u32, [u8; 32], Instant)>,
    holding: bool,
    hold_since: Option<Instant>,
    held: VecDeque<HeldPacket>,
    hold_budget: Option<Arc<HoldBudget>>,
    hold_overflow: u64,
    hold_expired: u64,
}

/// Per installed peer; dropped/retired with its exact owner. Off peers never
/// allocate one. The lock protects only bounded metadata, never a socket I/O.
pub(crate) struct Control {
    mode: MultipathMode,
    local: [u8; 32],
    peer: [u8; 32],
    shared: [u8; 32],
    state: Mutex<State>,
}

impl Control {
    pub(crate) fn new(
        mode: MultipathMode,
        local: [u8; 32],
        peer: [u8; 32],
        shared: [u8; 32],
    ) -> Self {
        Self {
            mode,
            local,
            peer,
            shared,
            state: Mutex::new(State::default()),
        }
    }

    pub(crate) fn mode(&self) -> MultipathMode {
        self.mode
    }

    pub(crate) fn retire(&self) {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = State {
            retired: true,
            ..State::default()
        };
    }

    fn reset_proof(st: &mut State) {
        st.offer = None;
        st.offer_attempts = 0;
        st.peer_until = None;
        st.challenge = None;
        st.primary_challenge = None;
        st.primary_answered = None;
        st.challenge_attempts = 0;
        st.last_challenge = None;
        st.proven = false;
        st.recent.clear();
    }

    fn current_binding(st: &State) -> Option<Binding> {
        (!st.retired).then_some(())?;
        Some(Binding {
            session_generation: st.active.as_ref()?.generation,
            role_generation: st.role_generation,
        })
    }

    pub(crate) fn binding(&self) -> Option<Binding> {
        Self::current_binding(&self.state.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Shape/session attribution only; caller MUST already have AEAD or an
    /// exact-full-ciphertext authenticated duplicate receipt on this owner.
    pub(crate) fn is_current_transport(&self, bytes: &[u8]) -> bool {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        !st.retired
            && bytes.len() >= 32
            && bytes[..4] == [4, 0, 0, 0]
            && st
                .active
                .as_ref()
                .is_some_and(|s| bytes[4..8] == s.local_index.to_le_bytes())
    }

    /// The caller already committed the physical carrier role transaction.
    /// No old normalized-leg evidence may survive that remapping.
    pub(crate) fn role_changed(&self) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.retired || self.mode == MultipathMode::Off {
            return;
        }
        let Some(next) = st.role_generation.checked_add(1) else {
            st.retired = true;
            Self::reset_proof(&mut st);
            st.held.clear();
            return;
        };
        st.role_generation = next;
        Self::reset_proof(&mut st);
        st.primary_started = None;
        st.primary_fallback = false;
        st.had_proven_secondary = false;
        st.sent.clear();
        st.received.clear();
        st.sessions.clear();
        if let Some(session) = st.active.as_mut() {
            session.response_sent = [None; 2];
            session.round_trip = [None; 2];
            let session = session.clone();
            st.sessions.push_back(session);
        }
    }

    fn start_hold(st: &mut State, now: Instant) {
        if !st.holding {
            st.holding = true;
            st.hold_since = Some(now);
            st.hold_budget = Some(Arc::new(HoldBudget::default()));
        }
    }

    fn activate(st: &mut State, session: Session, now: Instant) {
        if st
            .active
            .as_ref()
            .is_none_or(|old| session.generation > old.generation)
        {
            // Close the send admission gap before invalidating the secondary.
            if st.active.is_some() && st.had_proven_secondary {
                Self::start_hold(st, now);
            }
            Self::reset_proof(st);
            st.active = Some(session);
        } else if st
            .active
            .as_ref()
            .is_some_and(|old| old.generation == session.generation)
        {
            st.active = Some(session);
        }
    }

    fn remember(queue: &mut VecDeque<Handshake>, bytes: &[u8], leg: usize, now: Instant) {
        if let Some(old) = queue.iter_mut().find(|old| old.bytes == bytes) {
            old.legs[leg] = Some(now);
            return;
        }
        if queue.len() == 4 {
            queue.pop_front();
        }
        let mut legs = [None; 2];
        legs[leg] = Some(now);
        queue.push_back(Handshake {
            bytes: bytes.to_vec(),
            legs,
        });
    }

    /// Handshake sends are tentative until matching authenticated response /
    /// transport evidence. Call before the send to avoid a fast-response race.
    pub(crate) fn note_tx_handshake(&self, bytes: &[u8], leg: u32, now: Instant) {
        if self.mode == MultipathMode::Off || leg > 1 {
            return;
        }
        let leg = leg as usize;
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.retired {
            return;
        }
        if bytes.len() == 148 && bytes[..4] == [1, 0, 0, 0] {
            Self::remember(&mut st.sent, bytes, leg, now);
        } else if bytes.len() == 92
            && bytes[..4] == [2, 0, 0, 0]
            && let Some((init, same_leg)) = st
                .received
                .iter()
                .find(|p| p.bytes[4..8] == bytes[8..12])
                .map(|p| {
                    (
                        p.bytes.clone(),
                        p.legs[leg].is_some_and(|at| fresh(now, at, WAIT)),
                    )
                })
            && let Some(mut session) = Self::record_session(&mut st, &init, bytes, false)
        {
            if same_leg {
                session.response_sent[leg] = Some(now);
            }
            Self::store_session(&mut st, session);
        }
    }

    fn record_session(
        st: &mut State,
        init: &[u8],
        response: &[u8],
        initiator: bool,
    ) -> Option<Session> {
        let mut h = Sha256::new();
        h.update(init);
        h.update(response);
        let digest: [u8; 32] = h.finalize().into();
        if let Some(session) = st.sessions.iter().find(|s| s.digest == digest) {
            return Some(session.clone());
        }
        let Some(next) = st.generation.checked_add(1) else {
            st.retired = true;
            Self::reset_proof(st);
            st.held.clear();
            return None;
        };
        st.generation = next;
        Some(Session {
            local_index: u32::from_le_bytes(if initiator {
                init[4..8].try_into().expect("init")
            } else {
                response[4..8].try_into().expect("response")
            }),
            remote_index: u32::from_le_bytes(if initiator {
                response[4..8].try_into().expect("response")
            } else {
                init[4..8].try_into().expect("init")
            }),
            digest,
            generation: st.generation,
            response_sent: [None; 2],
            round_trip: [None; 2],
        })
    }

    fn store_session(st: &mut State, session: Session) {
        if let Some(existing) = st.sessions.iter_mut().find(|s| s.digest == session.digest) {
            *existing = session;
            return;
        }
        if st.sessions.len() == 4 {
            st.sessions.pop_front();
        }
        st.sessions.push_back(session);
    }

    /// Call ONLY after this owner's Tunn cryptographically accepts the actual
    /// nonempty packet. A static HMAC or an old tunnel never enters here.
    pub(crate) fn note_authenticated(&self, bytes: &[u8], leg: u32, now: Instant) {
        if self.mode == MultipathMode::Off || leg > 1 {
            return;
        }
        let leg_index = leg as usize;
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.retired {
            return;
        }
        if bytes.len() == 148 && bytes[..4] == [1, 0, 0, 0] {
            Self::remember(&mut st.received, bytes, leg_index, now);
        } else if bytes.len() == 92 && bytes[..4] == [2, 0, 0, 0] {
            if let Some((init, same_leg)) = st
                .sent
                .iter()
                .find(|p| p.bytes[4..8] == bytes[8..12])
                .map(|p| {
                    (
                        p.bytes.clone(),
                        p.legs[leg_index].is_some_and(|at| fresh(now, at, WAIT)),
                    )
                })
                && let Some(mut session) = Self::record_session(&mut st, &init, bytes, true)
            {
                if same_leg {
                    session.round_trip[leg_index] = Some(now);
                }
                Self::store_session(&mut st, session.clone());
                Self::activate(&mut st, session, now);
            }
        } else if bytes.len() >= 32 && bytes[..4] == [4, 0, 0, 0] {
            let receiver = u32::from_le_bytes(bytes[4..8].try_into().expect("transport"));
            if let Some(session) = st
                .sessions
                .iter()
                .rev()
                .find(|s| s.local_index == receiver)
                .cloned()
            {
                let mut session = session;
                if session.response_sent[leg_index].is_some_and(|at| fresh(now, at, WAIT)) {
                    session.round_trip[leg_index] = Some(now);
                    // Consume the responder's round-trip witness once.
                    session.response_sent[leg_index] = None;
                }
                Self::store_session(&mut st, session.clone());
                Self::activate(&mut st, session, now);
            }
            if leg <= 1
                && st
                    .active
                    .as_ref()
                    .is_some_and(|s| s.local_index == receiver)
            {
                if st.recent.len() == 8 {
                    st.recent.pop_front();
                }
                st.recent
                    .push_back((leg, Sha256::digest(bytes).into(), now));
            }
        }
    }

    pub(crate) fn peer_on(&self, now: Instant) -> bool {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        !st.retired && st.peer_until.is_some_and(|until| now < until)
    }

    pub(crate) fn ready(&self, now: Instant) -> bool {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        !st.retired && st.proven && st.peer_until.is_some_and(|until| now < until)
    }

    pub(crate) fn exhausted(&self, now: Instant) -> bool {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.retired
            || (st.offer_attempts >= 3
                && st
                    .offer
                    .as_ref()
                    .is_some_and(|p| now.saturating_duration_since(p.at) >= WAIT)
                && st.peer_until.is_none_or(|until| now >= until))
            || (st.challenge_attempts >= 3
                && st
                    .last_challenge
                    .is_some_and(|at| now.saturating_duration_since(at) >= WAIT)
                && !st.proven)
    }

    pub(crate) fn offer(&self, now: Instant) -> Option<Vec<u8>> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let transcript = st.active.as_ref()?.digest;
        let binding = Self::current_binding(&st)?;
        if st.retired
            || self.mode == MultipathMode::Off
            || st.offer.as_ref().is_some_and(|p| fresh(now, p.at, WAIT))
            || st
                .peer_until
                .is_some_and(|until| until.saturating_duration_since(now) > Duration::from_secs(10))
            || st.offer_attempts >= 3
        {
            return None;
        }
        let n = nonce();
        st.offer_attempts += 1;
        st.offer = Some(Pending {
            nonce: n,
            digest: [0; 32],
            at: now,
            binding,
        });
        encode(
            &Frame {
                kind: Kind::Offer,
                mode: self.mode,
                nonce: n,
                transcript,
                digest: [0; 32],
            },
            &self.local,
            &self.peer,
            &self.shared,
        )
    }

    /// Only after explicit peer-on proof; caller first sends the shared-session
    /// empty Type-4 frame on the candidate and supplies its exact wire bytes.
    pub(crate) fn challenge(&self, bytes: &[u8], now: Instant) -> Option<Vec<u8>> {
        self.challenge_on(bytes, 1, now)
    }

    pub(crate) fn primary_challenge(&self, bytes: &[u8], now: Instant) -> Option<Vec<u8>> {
        self.challenge_on(bytes, 0, now)
    }

    fn challenge_on(&self, bytes: &[u8], leg: u32, now: Instant) -> Option<Vec<u8>> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let session = st.active.as_ref()?;
        let binding = Self::current_binding(&st)?;
        if st.retired
            || leg == 1 && st.proven
            || st.peer_until.is_none_or(|until| now >= until)
            || bytes.len() != 32
            || bytes[..4] != [4, 0, 0, 0]
            || bytes[4..8] != session.remote_index.to_le_bytes()
            || leg == 1 && st.challenge_attempts >= 3
            || leg == 1 && st.last_challenge.is_some_and(|at| fresh(now, at, WAIT))
            || leg == 0
                && st
                    .primary_challenge
                    .as_ref()
                    .is_some_and(|p| fresh(now, p.at, WAIT))
        {
            return None;
        }
        let transcript = session.digest;
        let digest = Sha256::digest(bytes).into();
        let n = nonce();
        let pending = Pending {
            nonce: n,
            digest,
            at: now,
            binding,
        };
        if leg == 0 {
            st.primary_challenge = Some(pending);
            st.primary_started.get_or_insert(now);
        } else {
            st.challenge_attempts += 1;
            st.last_challenge = Some(now);
            st.challenge = Some(pending);
        }
        encode(
            &Frame {
                kind: Kind::Challenge,
                mode: self.mode,
                nonce: n,
                transcript,
                digest,
            },
            &self.local,
            &self.peer,
            &self.shared,
        )
    }

    /// A valid offer is accepted only on the current direct primary. Capability
    /// is never probed over DERP. Leg proof must arrive on the candidate leg.
    pub(crate) fn receive(&self, bytes: &[u8], leg: u32, now: Instant) -> Option<Vec<u8>> {
        if self.mode == MultipathMode::Off || leg > 1 {
            return None;
        }
        let frame = decode(bytes, &self.peer, &self.local, &self.shared)?;
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.retired
            || self.mode == MultipathMode::Off
            || st.active.as_ref()?.digest != frame.transcript
        {
            return None;
        }
        let binding = Self::current_binding(&st)?;
        let kind = match frame.kind {
            Kind::Offer if leg == 0 => Kind::Ack,
            Kind::Ack if leg == 0 => {
                let pending = st.offer.as_ref()?;
                if pending.nonce != frame.nonce
                    || pending.binding != binding
                    || !fresh(now, pending.at, WAIT)
                {
                    return None;
                }
                if st.peer_until.is_none_or(|until| now >= until) {
                    st.proven = false;
                    st.challenge = None;
                    st.challenge_attempts = 0;
                    st.last_challenge = None;
                }
                st.offer = None;
                st.offer_attempts = 0;
                st.peer_until = Some(now + LEASE);
                return None;
            }
            Kind::Challenge if leg <= 1 => {
                if st.peer_until.is_none_or(|until| now >= until) {
                    return None;
                }
                let i = st.recent.iter().position(|(seen_leg, digest, at)| {
                    *seen_leg == leg && *digest == frame.digest && fresh(now, *at, WAIT)
                })?;
                st.recent.remove(i); // one real authenticated frame cannot attest two challenges
                Kind::Proof
            }
            Kind::Proof if leg <= 1 => {
                if st.peer_until.is_none_or(|until| now >= until) {
                    return None;
                }
                let pending = if leg == 0 {
                    st.primary_challenge.as_ref()?
                } else {
                    st.challenge.as_ref()?
                };
                if pending.nonce != frame.nonce
                    || pending.digest != frame.digest
                    || pending.binding != binding
                    || !fresh(now, pending.at, WAIT)
                {
                    return None;
                }
                if leg == 0 {
                    st.primary_challenge = None;
                    st.primary_answered = Some(now);
                    st.peer_until = Some(now + LEASE);
                } else {
                    st.challenge = None;
                    st.proven = true;
                    st.had_proven_secondary = true;
                }
                return None;
            }
            _ => return None,
        };
        encode(
            &Frame {
                kind,
                mode: self.mode,
                ..frame
            },
            &self.local,
            &self.peer,
            &self.shared,
        )
    }
}

impl Control {
    /// Prior proof permits retention/ordinary WG recovery control only.
    /// It never grants secondary business authorization in the new session.
    pub(crate) fn recovery_allowed(&self) -> bool {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        !st.retired && st.had_proven_secondary
    }

    pub(crate) fn recovery_ready(&self, now: Instant) -> bool {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        !st.retired
            && st.had_proven_secondary
            && st
                .active
                .as_ref()
                .is_some_and(|s| s.round_trip[1].is_some_and(|at| fresh(now, at, WAIT)))
    }

    /// Healthy-primary recovery authorizes ordinary single-path business only.
    pub(crate) fn current_primary_roundtrip(&self, now: Instant) -> bool {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        !st.retired
            && st
                .active
                .as_ref()
                .is_some_and(|s| s.round_trip[0].is_some_and(|at| fresh(now, at, WAIT)))
    }

    pub(crate) fn primary_answered_since(&self, since: Instant) -> bool {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        !st.retired && st.primary_answered.is_some_and(|at| at >= since)
    }

    pub(crate) fn primary_answer_age(&self, now: Instant) -> Option<Duration> {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.retired {
            return None;
        }
        now.checked_duration_since(st.primary_answered?)
    }

    pub(crate) fn clear_primary_probe(&self) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.primary_started = None;
        st.primary_challenge = None;
        st.primary_answered = None;
        st.primary_fallback = false;
    }

    /// Mandatory restart fallback: same existing PokeArm/deadline, one INIT
    /// after the existing retap cycle. Never re-arm a new deadline here.
    pub(crate) fn take_primary_fallback(&self, now: Instant, cycle: Duration) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.retired
            || st.primary_fallback
            || st
                .primary_started
                .is_none_or(|at| now.saturating_duration_since(at) < cycle)
        {
            return false;
        }
        st.primary_fallback = true;
        true
    }

    pub(crate) fn should_validate_secondary(&self, now: Instant) -> bool {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        !st.retired
            && !st.proven
            && st.peer_until.is_some_and(|until| now < until)
            && st.challenge_attempts < 3
            && st
                .last_challenge
                .is_none_or(|at| now.saturating_duration_since(at) >= WAIT)
    }

    pub(crate) fn retired(&self) -> bool {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).retired
    }

    pub(crate) fn begin_hold(&self, now: Instant) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !st.retired && self.mode != MultipathMode::Off && !st.holding {
            Self::start_hold(&mut st, now);
        }
    }

    pub(crate) fn holding(&self) -> bool {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        !st.retired && st.holding
    }

    fn expire_hold_locked(st: &mut State, now: Instant) -> bool {
        if !st.holding
            || st
                .hold_since
                .is_none_or(|at| now.saturating_duration_since(at) < HOLD_TIME)
        {
            return false;
        }
        st.hold_expired = st.hold_expired.saturating_add(st.held.len() as u64);
        st.held.clear();
        true
    }

    pub(crate) fn expire_hold(&self, now: Instant) -> bool {
        Self::expire_hold_locked(
            &mut self.state.lock().unwrap_or_else(|e| e.into_inner()),
            now,
        )
    }

    /// None = ordinary send; true = retained; false = counted failure.
    pub(crate) fn queue_if_held(&self, bytes: &[u8], now: Instant) -> Option<bool> {
        if self.mode == MultipathMode::Off {
            return None;
        }
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.retired {
            return Some(false);
        }
        if !st.holding {
            return None;
        }
        if Self::expire_hold_locked(&mut st, now) {
            st.hold_expired = st.hold_expired.saturating_add(1);
            return Some(false);
        }
        let Some(budget) = st.hold_budget.clone() else {
            return Some(false);
        };
        if budget.packets.load(Ordering::Acquire) >= PEER_HOLD_PACKETS
            || budget
                .bytes
                .load(Ordering::Acquire)
                .saturating_add(bytes.len())
                > PEER_HOLD_BYTES
            || HELD_BYTES
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(bytes.len())
                        .filter(|next| *next <= GLOBAL_HOLD_LIMIT)
                })
                .is_err()
        {
            st.hold_overflow = st.hold_overflow.saturating_add(1);
            return Some(false);
        }
        budget.bytes.fetch_add(bytes.len(), Ordering::AcqRel);
        budget.packets.fetch_add(1, Ordering::AcqRel);
        st.held.push_back(HeldPacket {
            bytes: bytes.to_vec(),
            budget,
        });
        Some(true)
    }

    #[cfg(test)]
    pub(crate) fn pop_held(&self) -> Option<HeldPacket> {
        self.pop_held_at(Instant::now())
    }

    pub(crate) fn pop_held_at(&self, now: Instant) -> Option<HeldPacket> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.retired || Self::expire_hold_locked(&mut st, now) {
            return None;
        }
        st.held.pop_front()
    }

    pub(crate) fn requeue_held(&self, packet: HeldPacket) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.retired {
            return;
        }
        if Self::expire_hold_locked(&mut st, Instant::now()) {
            st.hold_expired = st.hold_expired.saturating_add(1);
            return;
        }
        if st.holding
            && st
                .hold_budget
                .as_ref()
                .is_some_and(|owner| Arc::ptr_eq(owner, &packet.budget))
        {
            st.held.push_front(packet);
        } else {
            // Rejected stale/foreign lease is an explicit admission failure.
            st.hold_overflow = st.hold_overflow.saturating_add(1);
        }
    }

    pub(crate) fn finish_hold(&self) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.retired
            || !st.held.is_empty()
            || st
                .hold_budget
                .as_ref()
                .is_some_and(|b| b.packets.load(Ordering::Acquire) != 0)
        {
            return false;
        }
        st.holding = false;
        st.hold_since = None;
        st.hold_budget = None;
        true
    }

    pub(crate) fn hold_snapshot(&self) -> HoldSnapshot {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        HoldSnapshot {
            packets: st
                .hold_budget
                .as_ref()
                .map_or(0, |b| b.packets.load(Ordering::Acquire)),
            bytes: st
                .hold_budget
                .as_ref()
                .map_or(0, |b| b.bytes.load(Ordering::Acquire)),
            global_bytes: HELD_BYTES.load(Ordering::Acquire),
            overflow: st.hold_overflow,
            expired: st.hold_expired,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints() -> (Control, Control) {
        let a = Control::new(MultipathMode::Aggregate, [1; 32], [2; 32], [9; 32]);
        let b = Control::new(MultipathMode::Redundant, [2; 32], [1; 32], [9; 32]);
        // Synthetic transcript metadata tests only. Integration must exercise
        // the hooks after actual Tunn authentication, never call them by shape.
        let mut init = vec![0; 148];
        init[0] = 1;
        init[4..8].copy_from_slice(&17u32.to_le_bytes());
        let mut response = vec![0; 92];
        response[0] = 2;
        response[4..8].copy_from_slice(&29u32.to_le_bytes());
        response[8..12].copy_from_slice(&17u32.to_le_bytes());
        let now = Instant::now();
        a.note_tx_handshake(&init, 0, now);
        b.note_authenticated(&init, 0, now);
        b.note_tx_handshake(&response, 0, now);
        a.note_authenticated(&response, 0, now);
        b.note_authenticated(&transport(29, 0), 0, now);
        (a, b)
    }

    fn transport(receiver: u32, counter: u64) -> Vec<u8> {
        let mut wire = vec![0; 32];
        wire[0] = 4;
        wire[4..8].copy_from_slice(&receiver.to_le_bytes());
        wire[8..16].copy_from_slice(&counter.to_le_bytes());
        wire
    }

    fn consent(a: &Control, b: &Control, now: Instant) {
        let offer_a = a.offer(now).unwrap();
        let offer_b = b.offer(now).unwrap();
        let ack_a = b.receive(&offer_a, 0, now).unwrap();
        let ack_b = a.receive(&offer_b, 0, now).unwrap();
        assert!(a.receive(&ack_a, 0, now).is_none());
        assert!(b.receive(&ack_b, 0, now).is_none());
        assert!(a.peer_on(now));
        assert!(b.peer_on(now));
    }

    fn secondary(a: &Control, b: &Control, now: Instant, counter: u64) {
        let wire = transport(29, counter);
        let challenge = a.challenge(&wire, now).unwrap();
        b.note_authenticated(&wire, 1, now);
        let proof = b.receive(&challenge, 1, now).unwrap();
        a.receive(&proof, 1, now);
        assert!(a.ready(now));
    }

    fn handshake(init_index: u32, response_index: u32) -> (Vec<u8>, Vec<u8>) {
        let mut init = vec![0; 148];
        init[0] = 1;
        init[4..8].copy_from_slice(&init_index.to_le_bytes());
        let mut response = vec![0; 92];
        response[0] = 2;
        response[4..8].copy_from_slice(&response_index.to_le_bytes());
        response[8..12].copy_from_slice(&init_index.to_le_bytes());
        (init, response)
    }

    fn start_session(a: &Control, b: &Control, leg: u32, now: Instant) {
        let (init, response) = handshake(31, 43);
        a.note_tx_handshake(&init, leg, now);
        b.note_authenticated(&init, leg, now);
        b.note_tx_handshake(&response, leg, now);
        a.note_authenticated(&response, leg, now);
        b.note_authenticated(&transport(43, 0), leg, now);
    }

    #[test]
    fn wire_authentication_is_identity_and_domain_bound() {
        let frame = Frame {
            kind: Kind::Offer,
            mode: MultipathMode::Aggregate,
            nonce: [3; 16],
            transcript: [4; 32],
            digest: [0; 32],
        };
        let raw = encode(&frame, &[1; 32], &[2; 32], &[9; 32]).unwrap();
        assert!(shaped(&raw));
        assert_eq!(decode(&raw, &[1; 32], &[2; 32], &[9; 32]), Some(frame));
        assert!(decode(&raw, &[2; 32], &[1; 32], &[9; 32]).is_none());
        assert!(decode(&raw, &[1; 32], &[2; 32], &[8; 32]).is_none());
        assert!(decode(&raw, &[1; 32], &[2; 32], &[0; 32]).is_none());
        assert!(!super::super::disco::is_disco_shaped(&raw));
        assert!(!super::super::disco::derp_follow::shaped(&raw));
        for offset in [8usize, 9, 10, 11, 16, 48, 80, 96, 128, 160, 191] {
            let mut changed = raw.clone();
            changed[offset] ^= 1;
            assert!(decode(&changed, &[1; 32], &[2; 32], &[9; 32]).is_none());
        }
    }

    #[test]
    fn fresh_primary_ack_is_required_and_secondary_ack_cannot_substitute() {
        let (a, b) = endpoints();
        let now = Instant::now();
        let offer = a.offer(now).unwrap();
        assert!(b.receive(&offer, 1, now).is_none());
        let ack = b.receive(&offer, 0, now).unwrap();
        a.receive(&ack, 1, now);
        assert!(!a.peer_on(now));
        a.receive(&ack, 0, now + WAIT);
        assert!(!a.peer_on(now + WAIT));
        let offer = a.offer(now + WAIT).unwrap();
        let ack = b.receive(&offer, 0, now + WAIT).unwrap();
        a.receive(&ack, 0, now + WAIT);
        assert!(a.peer_on(now + WAIT));
        // Consumed nonce cannot extend the lease on replay.
        a.receive(&ack, 0, now + WAIT + LEASE);
        assert!(!a.peer_on(now + WAIT + LEASE));
    }

    #[test]
    fn exact_authenticated_shared_session_frame_on_exact_leg_is_required() {
        let (a, b) = endpoints();
        let now = Instant::now();
        consent(&a, &b, now);
        let wire = transport(29, 4);
        let challenge = a.challenge(&wire, now).unwrap();
        // A valid static MAC alone cannot prove shared-session authentication.
        assert!(b.receive(&challenge, 1, now).is_none());
        b.note_authenticated(&wire, 0, now);
        assert!(b.receive(&challenge, 1, now).is_none());
        b.note_authenticated(&wire, 1, now);
        assert!(b.receive(&challenge, 2, now).is_none());
        let proof = b.receive(&challenge, 1, now).unwrap();
        a.receive(&proof, 0, now);
        assert!(!a.ready(now));
        a.receive(&proof, 1, now);
        assert!(a.ready(now));
        assert!(b.receive(&challenge, 1, now).is_none());
        assert!(!a.ready(now + LEASE));
    }

    #[test]
    fn off_and_retired_peers_never_consent_or_prove() {
        let (a, b) = endpoints();
        let now = Instant::now();
        let offer = a.offer(now).unwrap();
        let off = Control::new(MultipathMode::Off, [2; 32], [1; 32], [9; 32]);
        assert!(off.offer(now).is_none());
        assert!(off.receive(&offer, 0, now).is_none());
        b.retire();
        assert!(b.receive(&offer, 0, now).is_none());
        assert!(!b.ready(now));
        assert!(b.exhausted(now));
    }

    #[test]
    fn role_and_session_binding_invalidate_old_nonce_and_proof() {
        let (a, b) = endpoints();
        let now = Instant::now();
        let before = a.binding().unwrap();
        let offer = a.offer(now).unwrap();
        let ack = b.receive(&offer, 0, now).unwrap();
        a.role_changed();
        let changed = a.binding().unwrap();
        assert_eq!(changed.session_generation, before.session_generation);
        assert!(changed.role_generation > before.role_generation);
        a.receive(&ack, 0, now);
        assert!(!a.peer_on(now));
        let offer = a.offer(now).unwrap();
        let ack = b.receive(&offer, 0, now).unwrap();
        start_session(&a, &b, 0, now);
        assert!(a.binding().unwrap().session_generation > changed.session_generation);
        a.receive(&ack, 0, now);
        assert!(!a.peer_on(now));
        assert!(!a.holding()); // Never proved a secondary, so initial/rekey work cannot hold.
    }

    #[test]
    fn rekey_closes_business_proof_and_starts_hold_before_returning() {
        let (a, b) = endpoints();
        let now = Instant::now();
        consent(&a, &b, now);
        secondary(&a, &b, now, 7);
        let old = a.binding().unwrap();
        start_session(&a, &b, 1, now + Duration::from_millis(10));
        assert_ne!(a.binding(), Some(old));
        assert!(!a.ready(now));
        assert!(!a.peer_on(now));
        assert!(a.holding());
        assert!(a.recovery_allowed());
        assert!(a.recovery_ready(now + Duration::from_millis(10)));
        assert!(!a.recovery_ready(now + WAIT + Duration::from_millis(10)));
        assert!(!a.current_primary_roundtrip(now + Duration::from_millis(10)));
        a.role_changed();
        assert!(!a.recovery_allowed());
        assert!(!a.recovery_ready(now + Duration::from_millis(10)));
        assert!(a.holding()); // Only caller's committed primary can release FIFO.
    }

    #[test]
    fn candidate_one_way_data_cannot_prove_new_session_outbound() {
        let (a, b) = endpoints();
        let now = Instant::now();
        consent(&a, &b, now);
        secondary(&a, &b, now, 8);
        start_session(&a, &b, 0, now);
        a.note_authenticated(&transport(31, 2), 1, now);
        assert!(a.is_current_transport(&transport(31, 2)));
        assert!(!a.is_current_transport(&transport(17, 2)));
        assert!(!a.recovery_ready(now));
        assert!(a.current_primary_roundtrip(now));
        assert!(a.holding());
    }

    #[test]
    fn same_init_sent_on_both_legs_keeps_actual_roundtrip_attribution() {
        let (a, b) = endpoints();
        let now = Instant::now();
        consent(&a, &b, now);
        secondary(&a, &b, now, 9);
        let (init, response) = handshake(31, 43);
        a.note_tx_handshake(&init, 0, now);
        a.note_tx_handshake(&init, 1, now);
        b.note_authenticated(&init, 1, now);
        b.note_tx_handshake(&response, 1, now);
        a.note_authenticated(&response, 1, now);
        assert!(a.recovery_ready(now));
        assert!(!a.current_primary_roundtrip(now));
    }

    #[test]
    fn responder_needs_same_leg_response_then_authenticated_transport() {
        let (a, b) = endpoints();
        let now = Instant::now();
        consent(&a, &b, now);
        secondary(&a, &b, now, 10);
        let (init, response) = handshake(31, 43);
        b.note_tx_handshake(&init, 1, now);
        a.note_authenticated(&init, 1, now);
        a.note_tx_handshake(&response, 1, now);
        assert!(!a.recovery_ready(now));
        a.note_authenticated(&transport(43, 1), 0, now);
        assert!(!a.recovery_ready(now));
        a.note_authenticated(&transport(43, 2), 1, now);
        assert!(a.recovery_ready(now));
    }

    #[test]
    fn primary_proof_wrong_leg_cannot_answer_or_renew_and_role_reset_clears_stamp() {
        let (a, b) = endpoints();
        let now = Instant::now();
        consent(&a, &b, now);
        let wire = transport(29, 90);
        let challenge = a.primary_challenge(&wire, now).unwrap();
        b.note_authenticated(&wire, 0, now);
        let proof = b.receive(&challenge, 0, now).unwrap();
        a.receive(&proof, 1, now);
        assert!(a.primary_answer_age(now).is_none());
        a.receive(&proof, 0, now);
        assert!(a.primary_answered_since(now));
        assert_eq!(a.primary_answer_age(now + WAIT), Some(WAIT));
        a.role_changed();
        assert!(!a.primary_answered_since(now));
        assert!(a.primary_answer_age(now).is_none());
    }

    #[test]
    fn restart_fallback_preserves_original_arm_time_across_session_change() {
        let (a, b) = endpoints();
        let now = Instant::now();
        consent(&a, &b, now);
        a.primary_challenge(&transport(29, 91), now).unwrap();
        let cycle = Duration::from_millis(800);
        assert!(!a.take_primary_fallback(now + Duration::from_millis(799), cycle));
        start_session(&a, &b, 1, now + Duration::from_millis(400));
        assert!(a.take_primary_fallback(now + cycle, cycle));
        assert!(!a.take_primary_fallback(now + cycle + cycle, cycle));
        a.clear_primary_probe();
        assert!(!a.take_primary_fallback(now + cycle + cycle, cycle));
    }

    #[test]
    fn expired_lease_ack_cannot_resurrect_old_secondary_proof() {
        let (a, b) = endpoints();
        let now = Instant::now();
        consent(&a, &b, now);
        secondary(&a, &b, now, 11);
        let later = now + LEASE;
        assert!(!a.ready(later));
        consent(&a, &b, later);
        assert!(!a.ready(later));
        assert!(a.recovery_allowed());
    }

    static HOLD_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn hold_fifo_and_per_peer_limits_include_popped_inflight_packets() {
        let _serial = HOLD_TEST_LOCK.lock().unwrap();
        let now = Instant::now();
        let control = Control::new(MultipathMode::Redundant, [1; 32], [2; 32], [9; 32]);
        control.begin_hold(now);
        for i in 0..PEER_HOLD_PACKETS {
            assert_eq!(control.queue_if_held(&[i as u8], now), Some(true));
        }
        let packet = control.pop_held_at(now).unwrap();
        assert_eq!(packet.bytes(), [0]);
        assert_eq!(control.hold_snapshot().packets, PEER_HOLD_PACKETS);
        assert_eq!(control.queue_if_held(&[99], now), Some(false));
        assert!(!control.finish_hold());
        control.requeue_held(packet);
        assert_eq!(control.hold_snapshot().packets, PEER_HOLD_PACKETS);
        for i in 0..PEER_HOLD_PACKETS {
            let packet = control.pop_held_at(now).unwrap();
            assert_eq!(packet.bytes(), [i as u8]);
            if i + 1 == PEER_HOLD_PACKETS {
                assert!(!control.finish_hold());
            }
            drop(packet);
        }
        assert!(control.finish_hold());
        assert_eq!(control.hold_snapshot().bytes, 0);
        assert_eq!(control.queue_if_held(&[1], now), None);

        control.begin_hold(now);
        assert_eq!(
            control.queue_if_held(&vec![1; PEER_HOLD_BYTES], now),
            Some(true)
        );
        let packet = control.pop_held_at(now).unwrap();
        assert_eq!(control.hold_snapshot().bytes, PEER_HOLD_BYTES);
        assert_eq!(control.queue_if_held(&[1], now), Some(false));
        drop(packet);
        assert!(control.finish_hold());
    }

    #[test]
    fn hold_expiry_is_checked_at_drain_without_further_enqueue() {
        let _serial = HOLD_TEST_LOCK.lock().unwrap();
        let now = Instant::now();
        let control = Control::new(MultipathMode::Redundant, [1; 32], [2; 32], [9; 32]);
        control.begin_hold(now);
        assert_eq!(control.queue_if_held(&[1], now), Some(true));
        assert!(control.pop_held_at(now + HOLD_TIME).is_none());
        assert_eq!(control.hold_snapshot().expired, 1);
        assert_eq!(control.queue_if_held(&[2], now + HOLD_TIME), Some(false));
        assert_eq!(control.hold_snapshot().expired, 2);
        assert!(control.finish_hold());
    }

    #[test]
    fn global_limit_spans_peers_and_releases_reserved_bytes_on_retirement() {
        let _serial = HOLD_TEST_LOCK.lock().unwrap();
        let now = Instant::now();
        let controls: Vec<_> = (0..17)
            .map(|_| {
                let c = Control::new(MultipathMode::Redundant, [1; 32], [2; 32], [9; 32]);
                c.begin_hold(now);
                c
            })
            .collect();
        let payload = vec![7; 4096];
        let mut refused = 0;
        for c in &controls {
            for _ in 0..PEER_HOLD_PACKETS {
                if c.queue_if_held(&payload, now) == Some(false) {
                    refused += 1;
                }
                assert!(c.hold_snapshot().global_bytes <= GLOBAL_HOLD_LIMIT);
            }
        }
        assert!(refused >= PEER_HOLD_PACKETS);
        let before = controls
            .iter()
            .map(|c| c.hold_snapshot().bytes)
            .sum::<usize>();
        assert!(before <= GLOBAL_HOLD_LIMIT);
        for c in &controls {
            c.retire();
        }
        assert!(controls.iter().all(|c| c.hold_snapshot().bytes == 0));
    }

    #[test]
    fn off_hold_allocates_nothing_and_retired_inflight_lease_cannot_reenter() {
        let _serial = HOLD_TEST_LOCK.lock().unwrap();
        let now = Instant::now();
        let off = Control::new(MultipathMode::Off, [1; 32], [2; 32], [9; 32]);
        off.begin_hold(now);
        assert!(off.pop_held().is_none());
        off.note_tx_handshake(&handshake(1, 2).0, 0, now);
        assert_eq!(off.queue_if_held(&[1], now), None);
        let state = off.state.lock().unwrap();
        assert!(state.hold_budget.is_none());
        assert!(state.sent.is_empty());
        assert!(state.sessions.is_empty());
        drop(state);
        let c = Control::new(MultipathMode::Redundant, [1; 32], [2; 32], [9; 32]);
        c.begin_hold(now);
        c.queue_if_held(&[1, 2, 3], now);
        let packet = c.pop_held_at(now).unwrap();
        c.retire();
        assert_eq!(packet.bytes(), [1, 2, 3]);
        c.requeue_held(packet); // Drop returns both permits; no retired queue resurrection.
        assert!(c.pop_held_at(now).is_none());
        assert_eq!(c.queue_if_held(&[1], now), Some(false));
    }
}
