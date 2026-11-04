// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Staged in-process, all-or-none relay slot and VNI reservation.
//!
//! This book can arbitrate only participants which use it. It MUST NOT be used
//! for production admission until ordinary mints, trials and N-hop mints all
//! use the same owner, and distributed ownership and relay expiry are resolved.

use bson::oid::ObjectId;
use meshharbor_remote_control::models::peer_relay_limits as limits;
use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
    time::Instant,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ReservationId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReservationError {
    EmptyPath,
    DuplicateRelay,
    Expired,
    NoCapacity,
    NoVni,
    IdExhausted,
    NotFound,
    AlreadyPublished,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReservedPath {
    pub id: ReservationId,
    pub legs: Vec<(ObjectId, u32)>,
}

struct Entry {
    legs: Vec<(ObjectId, u32)>,
    expires_at: Instant,
    published: bool,
}

#[derive(Default)]
struct State {
    next_id: u64,
    next_vni: HashMap<ObjectId, u32>,
    entries: HashMap<ReservationId, Entry>,
}

/// All mutations, including pruning, are serialized under one lock. No async
/// operation, policy decision, DB access or network send runs under this lock.
pub(super) struct ReservationBook {
    state: Mutex<State>,
    per_relay_limit: usize,
}

impl ReservationBook {
    pub fn new(per_relay_limit: usize) -> Self {
        Self {
            state: Mutex::new(State::default()),
            per_relay_limit,
        }
    }

    /// Tentatively reserve one slot and one per-node VNI for every distinct
    /// relay. On failure no live reservation or VNI cursor is changed (expired
    /// entries may be pruned). No fixed path length is imposed.
    pub fn reserve(
        &self,
        relays: &[ObjectId],
        expires_at: Instant,
    ) -> Result<ReservedPath, ReservationError> {
        self.reserve_at(relays, Instant::now(), expires_at)
    }

    fn reserve_at(
        &self,
        relays: &[ObjectId],
        now: Instant,
        expires_at: Instant,
    ) -> Result<ReservedPath, ReservationError> {
        if relays.is_empty() {
            return Err(ReservationError::EmptyPath);
        }
        if expires_at <= now {
            return Err(ReservationError::Expired);
        }
        let mut distinct = HashSet::with_capacity(relays.len());
        if relays.iter().any(|id| !distinct.insert(*id)) {
            return Err(ReservationError::DuplicateRelay);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReservationError::Unavailable)?;
        // A caller may have waited for this lock after sampling its clock.
        // Re-check under the lock so a stale sample cannot admit an expired lease.
        let now = now.max(Instant::now());
        if expires_at <= now {
            return Err(ReservationError::Expired);
        }
        state.entries.retain(|_, entry| entry.expires_at > now);
        let next_id = state
            .next_id
            .checked_add(1)
            .ok_or(ReservationError::IdExhausted)?;
        let mut used_by_relay: HashMap<ObjectId, HashSet<u32>> = HashMap::new();
        for (node, vni) in state.entries.values().flat_map(|entry| entry.legs.iter()) {
            if distinct.contains(node) {
                used_by_relay.entry(*node).or_default().insert(*vni);
            }
        }
        let empty = HashSet::new();
        let mut legs = Vec::with_capacity(relays.len());
        let mut cursors = Vec::with_capacity(relays.len());
        for relay in relays {
            let used = used_by_relay.get(relay).unwrap_or(&empty);
            if used.len() >= self.per_relay_limit {
                return Err(ReservationError::NoCapacity);
            }
            let mut candidate = state.next_vni.get(relay).copied().unwrap_or(1);
            let mut found = None;
            // Only used values plus the one reserved STUN VNI can block the
            // next candidate. Never walk more than the wire's VNI space.
            for _ in 0..used.len().saturating_add(2).min(limits::VNI_MAX as usize) {
                let current = candidate;
                candidate = if current >= limits::VNI_MAX {
                    1
                } else {
                    current + 1
                };
                if current != limits::STUN_COOKIE_VNI && !used.contains(&current) {
                    found = Some(current);
                    break;
                }
            }
            let vni = found.ok_or(ReservationError::NoVni)?;
            legs.push((*relay, vni));
            cursors.push((*relay, candidate));
        }
        let id = ReservationId(next_id);
        state.next_id = next_id;
        state.next_vni.extend(cursors);
        state.entries.insert(
            id,
            Entry {
                legs: legs.clone(),
                expires_at,
                published: false,
            },
        );
        Ok(ReservedPath { id, legs })
    }

    /// Mark before the first control message can escape. Published allocations
    /// cannot be rolled back early: relay-side termination has no ack here.
    pub fn publish(&self, id: ReservationId) -> Result<(), ReservationError> {
        self.publish_at(id, Instant::now())
    }

    fn publish_at(&self, id: ReservationId, now: Instant) -> Result<(), ReservationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReservationError::Unavailable)?;
        let now = now.max(Instant::now());
        let entry = state
            .entries
            .get_mut(&id)
            .ok_or(ReservationError::NotFound)?;
        if entry.expires_at <= now {
            state.entries.remove(&id);
            return Err(ReservationError::Expired);
        }
        if entry.published {
            return Err(ReservationError::AlreadyPublished);
        }
        entry.published = true;
        Ok(())
    }

    /// Cancel only before publishing. Repeated/stale tokens cannot cancel a
    /// different allocation; published slots remain held until expiry.
    pub fn cancel(&self, id: ReservationId) -> Result<(), ReservationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReservationError::Unavailable)?;
        let entry = state.entries.get(&id).ok_or(ReservationError::NotFound)?;
        if entry.published {
            return Err(ReservationError::AlreadyPublished);
        }
        state.entries.remove(&id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{Arc, Barrier},
        thread,
        time::Duration,
    };

    #[test]
    fn all_or_none_and_cancel_does_not_touch_other_leases() {
        let book = ReservationBook::new(1);
        let now = Instant::now();
        let expiry = now + Duration::from_secs(60);
        let [a, b, c] = [ObjectId::new(), ObjectId::new(), ObjectId::new()];
        let held = book.reserve_at(&[b], now, expiry).unwrap();
        assert_eq!(
            book.reserve_at(&[a, b, c], now, expiry),
            Err(ReservationError::NoCapacity)
        );
        assert!(
            !book.state.lock().unwrap().next_vni.contains_key(&a),
            "failed path must not advance any cursor"
        );
        let ac = book.reserve_at(&[a, c], now, expiry).unwrap();
        book.cancel(held.id).unwrap();
        assert_eq!(book.cancel(held.id), Err(ReservationError::NotFound));
        assert_eq!(
            book.reserve_at(&[a], now, expiry),
            Err(ReservationError::NoCapacity)
        );
        book.cancel(ac.id).unwrap();
        assert!(book.reserve_at(&[a, b, c], now, expiry).is_ok());
    }

    #[test]
    fn publication_is_irreversible_until_expiry_and_old_token_cannot_remove_reuse() {
        let book = ReservationBook::new(1);
        let now = Instant::now();
        let expiry = now + Duration::from_secs(3);
        let relay = ObjectId::new();
        let old = book.reserve_at(&[relay], now, expiry).unwrap();
        book.publish_at(old.id, now).unwrap();
        assert_eq!(book.cancel(old.id), Err(ReservationError::AlreadyPublished));
        assert_eq!(
            book.publish_at(old.id, now),
            Err(ReservationError::AlreadyPublished)
        );
        assert_eq!(
            book.reserve_at(&[relay], now, expiry),
            Err(ReservationError::NoCapacity)
        );
        let new = book
            .reserve_at(&[relay], expiry, expiry + Duration::from_secs(1))
            .unwrap();
        assert_ne!(old.id, new.id);
        assert_eq!(book.cancel(old.id), Err(ReservationError::NotFound));
        assert_eq!(
            book.reserve_at(&[relay], expiry, expiry + Duration::from_secs(1)),
            Err(ReservationError::NoCapacity)
        );
    }

    #[test]
    fn vnis_are_unique_per_relay_skip_reserved_and_wrap() {
        let book = ReservationBook::new(4);
        let now = Instant::now();
        let expiry = now + Duration::from_secs(60);
        let [a, b] = [ObjectId::new(), ObjectId::new()];
        {
            let mut s = book.state.lock().unwrap();
            s.next_vni.insert(a, limits::STUN_COOKIE_VNI);
            s.next_vni.insert(b, limits::VNI_MAX);
        }
        let first = book.reserve_at(&[a, b], now, expiry).unwrap();
        assert_eq!(
            first.legs,
            vec![(a, limits::STUN_COOKIE_VNI + 1), (b, limits::VNI_MAX)]
        );
        let second = book.reserve_at(&[a, b], now, expiry).unwrap();
        assert_ne!(first.legs[0].1, second.legs[0].1);
        assert_eq!(second.legs[1].1, 1);
        {
            let mut s = book.state.lock().unwrap();
            s.next_vni.insert(a, first.legs[0].1);
        }
        let third = book.reserve_at(&[a], now, expiry).unwrap();
        assert_ne!(third.legs[0].1, first.legs[0].1);
        assert_ne!(third.legs[0].1, second.legs[0].1);
    }

    #[test]
    fn invalid_and_long_paths() {
        let book = ReservationBook::new(1);
        let now = Instant::now();
        let relay = ObjectId::new();
        assert_eq!(
            book.reserve_at(&[], now, now + Duration::from_secs(1)),
            Err(ReservationError::EmptyPath)
        );
        assert_eq!(
            book.reserve_at(&[relay, relay], now, now + Duration::from_secs(1)),
            Err(ReservationError::DuplicateRelay)
        );
        assert_eq!(
            book.reserve_at(&[relay], now, now),
            Err(ReservationError::Expired)
        );
        let path: Vec<_> = (0..128).map(|_| ObjectId::new()).collect();
        let reserved = book
            .reserve_at(&path, now, now + Duration::from_secs(1))
            .unwrap();
        assert_eq!(reserved.legs.len(), path.len());
        assert!(
            reserved
                .legs
                .iter()
                .zip(path)
                .all(|((actual, _), expected)| *actual == expected)
        );
    }

    #[test]
    fn live_clock_entry_points_publish_and_hold_a_lease() {
        let book = ReservationBook::new(1);
        let relay = ObjectId::new();
        let expiry = Instant::now() + Duration::from_secs(30);
        let path = book.reserve(&[relay], expiry).unwrap();
        book.publish(path.id).unwrap();
        assert_eq!(
            book.cancel(path.id),
            Err(ReservationError::AlreadyPublished)
        );
        assert_eq!(
            book.reserve(&[relay], expiry),
            Err(ReservationError::NoCapacity)
        );
    }

    #[test]
    fn stale_caller_clock_does_not_reserve_or_publish_expired_entry() {
        let book = ReservationBook::new(1);
        let now = Instant::now();
        let old = now - Duration::from_secs(3);
        let expired = now - Duration::from_secs(1);
        let relay = ObjectId::new();
        assert_eq!(
            book.reserve_at(&[relay], old, expired),
            Err(ReservationError::Expired)
        );
        let path = book
            .reserve_at(&[relay], now, now + Duration::from_secs(30))
            .unwrap();
        book.state
            .lock()
            .unwrap()
            .entries
            .get_mut(&path.id)
            .unwrap()
            .expires_at = expired;
        assert_eq!(
            book.publish_at(path.id, old),
            Err(ReservationError::Expired)
        );
        assert_eq!(book.cancel(path.id), Err(ReservationError::NotFound));
    }

    #[test]
    fn poisoned_lock_and_identifier_exhaustion_fail_closed() {
        let now = Instant::now();
        let expiry = now + Duration::from_secs(10);
        let book = Arc::new(ReservationBook::new(1));
        let relay = ObjectId::new();
        let other = Arc::clone(&book);
        assert!(
            thread::spawn(move || {
                let _guard = other.state.lock().unwrap();
                panic!("simulate a failed mutation while holding the lock");
            })
            .join()
            .is_err()
        );
        assert_eq!(
            book.reserve_at(&[relay], now, expiry),
            Err(ReservationError::Unavailable)
        );
        assert_eq!(
            book.publish_at(ReservationId(1), now),
            Err(ReservationError::Unavailable)
        );
        assert_eq!(
            book.cancel(ReservationId(1)),
            Err(ReservationError::Unavailable)
        );
        let exhausted = ReservationBook::new(1);
        exhausted.state.lock().unwrap().next_id = u64::MAX;
        assert_eq!(
            exhausted.reserve_at(&[relay], now, expiry),
            Err(ReservationError::IdExhausted)
        );
        assert!(exhausted.state.lock().unwrap().entries.is_empty());
    }

    #[test]
    fn simultaneous_overlapping_paths_never_oversubscribe() {
        let book = Arc::new(ReservationBook::new(7));
        let now = Instant::now();
        let expiry = now + Duration::from_secs(60);
        let shared = ObjectId::new();
        let barrier = Arc::new(Barrier::new(64));
        let threads: Vec<_> = (0..64)
            .map(|_| {
                let (book, barrier) = (Arc::clone(&book), Arc::clone(&barrier));
                thread::spawn(move || {
                    let unique = ObjectId::new();
                    barrier.wait();
                    book.reserve_at(&[unique, shared], now, expiry)
                })
            })
            .collect();
        let outcomes: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let successes: Vec<_> = outcomes.iter().filter_map(|r| r.as_ref().ok()).collect();
        assert_eq!(successes.len(), 7);
        assert!(
            outcomes
                .iter()
                .filter_map(|r| r.as_ref().err())
                .all(|e| *e == ReservationError::NoCapacity)
        );
        assert_eq!(
            successes
                .iter()
                .map(|r| r.legs[1].1)
                .collect::<HashSet<_>>()
                .len(),
            7
        );
        assert_eq!(book.state.lock().unwrap().entries.len(), 7);
    }
}
