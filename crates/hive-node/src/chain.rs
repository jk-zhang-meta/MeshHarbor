// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! How a session's events are numbered, fenced and chained.
//!
//! Every event carries the session's `seq` (gapless from 1), the `fence` of the
//! lease that wrote it, and `prev_hash` — the BLAKE3 hash of the event before
//! it. That gives the replicaset three properties without a coordinator in the
//! data path:
//!
//! - **One writer.** A member refuses an event whose fence is older than the
//!   newest fence it has seen, so a partitioned old primary cannot append after
//!   a promotion moved the lease (`fence + 1`). The newest fence seen is the
//!   tip's, or the session's floor when the server raised one first
//!   ([`check_next_with_floor`], FR-90 P2a).
//! - **No holes.** An event is accepted only as the direct successor of the
//!   member's tip.
//! - **Provable sameness.** Two members holding the same `(seq, hash)` hold the
//!   same history up to that point; the server compares those in acks without
//!   ever seeing an event.

use serde::{Deserialize, Serialize};

use crate::event::TranscriptEvent;

/// The `prev_hash` of a session's first event.
pub const GENESIS: [u8; 32] = [0; 32];

/// Domain separation for the event hash; bump the version if the hashed fields
/// ever change, so an old and a new member cannot agree on a hash by accident.
const HASH_CONTEXT: &str = "meshharbor hive transcript event v1";

/// One event as it is stored and replicated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// The Hive session id — the server's `agent_sessions` id, as hex. Not
    /// the harness's own UUID, which the launch spec carries separately.
    pub session: String,
    /// 1-based, gapless within the session.
    pub seq: u64,
    /// The lease generation that wrote this event.
    pub fence: u64,
    /// Wall-clock milliseconds since the Unix epoch, as the writer saw them.
    pub ts_ms: i64,
    /// The hash of the previous event, or [`GENESIS`] for `seq == 1`.
    #[serde(with = "hex32")]
    pub prev_hash: [u8; 32],
    /// The event's exact JSON text. Hashed and forwarded byte for byte, never
    /// re-serialised — so a member that cannot parse a newer kind still chains
    /// it, and no JSON key-order question can make two members disagree.
    pub event_json: String,
}

impl EventEnvelope {
    /// Wrap `event` as the successor of `tip` (or as the first event when
    /// `tip` is `None`), written under `fence`.
    pub fn next(
        session: &str,
        tip: Option<ChainTip>,
        fence: u64,
        ts_ms: i64,
        event: &TranscriptEvent,
    ) -> Self {
        let (seq, prev_hash) = match tip {
            Some(t) => (t.seq + 1, t.hash),
            None => (1, GENESIS),
        };
        Self {
            session: session.to_string(),
            seq,
            fence,
            ts_ms,
            prev_hash,
            event_json: event.to_json(),
        }
    }

    /// The hash the next event's `prev_hash` must equal.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key(HASH_CONTEXT);
        put(&mut h, self.session.as_bytes());
        h.update(&self.seq.to_le_bytes());
        h.update(&self.fence.to_le_bytes());
        h.update(&self.ts_ms.to_le_bytes());
        h.update(&self.prev_hash);
        put(&mut h, self.event_json.as_bytes());
        *h.finalize().as_bytes()
    }

    /// The typed view of the event, or `None` for a kind this build doesn't know.
    pub fn event(&self) -> Option<TranscriptEvent> {
        TranscriptEvent::from_json(&self.event_json)
    }

    /// This event as the new tip of its session.
    pub fn tip(&self) -> ChainTip {
        ChainTip {
            seq: self.seq,
            hash: self.hash(),
            fence: self.fence,
        }
    }
}

/// Length-prefix a variable-length field, so no two different field splits can
/// produce the same byte stream.
fn put(h: &mut blake3::Hasher, bytes: &[u8]) {
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}

/// The newest event a member holds for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainTip {
    pub seq: u64,
    pub hash: [u8; 32],
    /// The fence of the event at `seq` — an event with an older one is
    /// refused. A session's floor ([`check_next_with_floor`]) can be newer.
    pub fence: u64,
}

/// Why an event cannot follow a member's tip.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    #[error("seq {got} does not follow the tip (expected {expected})")]
    Gap { expected: u64, got: u64 },
    #[error("prev_hash of seq {seq} does not match the hash of the event before it")]
    Broken { seq: u64 },
    #[error("fence {got} is older than the newest fence seen, {current}: a stale writer")]
    StaleFence { current: u64, got: u64 },
    /// FR-90 P2e-5b: at the very `seq` a superseded fence ended with, another
    /// event: this copy of the history is not the record's.
    #[error("seq {seq} is where fence {fence} ended, and this is not the event it ended with")]
    NotFenceEnd { fence: u64, seq: u64 },
}

/// FR-90 P2e-5b — where a fence a promotion superseded ended, as the record
/// keeps it (`rc:hive.replica.join`'s `fences`): the `seq` of its last event,
/// and that event's hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FenceEnd {
    pub fence: u64,
    pub seq: u64,
    pub hash: [u8; 32],
}

/// Can `next` follow `tip` — or start the session, when `tip` is `None`?
///
/// The fence check comes first: a stale writer is the failure that matters
/// most, and naming it beats reporting the gap it usually also causes.
pub fn check_next(tip: Option<ChainTip>, next: &EventEnvelope) -> Result<(), ChainError> {
    match tip {
        None => {
            if next.seq != 1 {
                return Err(ChainError::Gap {
                    expected: 1,
                    got: next.seq,
                });
            }
            if next.prev_hash != GENESIS {
                return Err(ChainError::Broken { seq: 1 });
            }
            Ok(())
        }
        Some(tip) => {
            if next.fence < tip.fence {
                return Err(ChainError::StaleFence {
                    current: tip.fence,
                    got: next.fence,
                });
            }
            if next.seq != tip.seq + 1 {
                return Err(ChainError::Gap {
                    expected: tip.seq + 1,
                    got: next.seq,
                });
            }
            if next.prev_hash != tip.hash {
                return Err(ChainError::Broken { seq: next.seq });
            }
            Ok(())
        }
    }
}

/// FR-90 P2a — [`check_next`], with the session's fence FLOOR as well: the
/// newest fence the server has said exists, raised before any event of that
/// fence does. The tip's fence moves only when an event lands, so without a
/// floor a member keeps taking a stale writer's late events until the new
/// primary's first one arrives; with it, an event of a fence older than the
/// floor is refused at once, and for a session this member holds nothing of
/// yet. `None` is no floor, and then this is exactly [`check_next`].
///
/// The floor is checked first, against the newer of it and the tip's fence,
/// for the reason [`check_next`] checks the fence first.
pub fn check_next_with_floor(
    tip: Option<ChainTip>,
    floor: Option<u64>,
    next: &EventEnvelope,
) -> Result<(), ChainError> {
    // `None` orders below every `Some`, so this is the newest fence seen.
    check_next_with_ends(tip, floor, &[], next)
}

/// FR-90 P2e-5b — [`check_next_with_floor`], with where each superseded fence
/// ended: an event of a fence older than the floor is still taken up to that
/// fence's end, so a member that joins after a move, or was behind at it,
/// syncs the history below its floor; at the end itself only the very event
/// it names. An older fence's event past its end, or of a fence with no end,
/// is a stale writer's.
pub fn check_next_with_ends(
    tip: Option<ChainTip>,
    floor: Option<u64>,
    ends: &[FenceEnd],
    next: &EventEnvelope,
) -> Result<(), ChainError> {
    // `None` orders below every `Some`, so this is the newest fence seen.
    if let Some(current) = tip.map(|t| t.fence).max(floor)
        && next.fence < current
    {
        let stale = ChainError::StaleFence {
            current,
            got: next.fence,
        };
        let Some(end) = ends.iter().find(|e| e.fence == next.fence) else {
            return Err(stale);
        };
        if next.seq > end.seq {
            return Err(stale);
        }
        check_next(tip, next)?;
        if next.seq == end.seq && next.hash() != end.hash {
            return Err(ChainError::NotFenceEnd {
                fence: end.fence,
                seq: end.seq,
            });
        }
        return Ok(());
    }
    check_next(tip, next)
}

/// `[u8; 32]` as lowercase hex in JSON: an envelope's `prev_hash`, and an
/// `events` frame's (P2d-3).
pub(crate) mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(64);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        let raw = text.as_bytes();
        if raw.len() != 64 {
            return Err(D::Error::custom("a hash is 64 hex characters"));
        }
        let mut out = [0u8; 32];
        for (i, pair) in raw.chunks(2).enumerate() {
            let pair = std::str::from_utf8(pair).map_err(D::Error::custom)?;
            out[i] = u8::from_str_radix(pair, 16).map_err(D::Error::custom)?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(text: &str) -> TranscriptEvent {
        TranscriptEvent::Note { text: text.into() }
    }

    fn chain_of(n: usize, fence: u64) -> Vec<EventEnvelope> {
        let mut out: Vec<EventEnvelope> = Vec::new();
        for i in 0..n {
            let tip = out.last().map(EventEnvelope::tip);
            out.push(EventEnvelope::next(
                "s1",
                tip,
                fence,
                1_000 + i as i64,
                &note(&format!("e{i}")),
            ));
        }
        out
    }

    #[test]
    fn a_built_chain_verifies_end_to_end() {
        let chain = chain_of(5, 7);
        let mut tip = None;
        for ev in &chain {
            check_next(tip, ev).unwrap();
            tip = Some(ev.tip());
        }
        assert_eq!(tip.unwrap().seq, 5);
    }

    #[test]
    fn the_first_event_must_be_seq_1_from_genesis() {
        let mut first = chain_of(1, 1).remove(0);
        first.seq = 2;
        assert_eq!(
            check_next(None, &first),
            Err(ChainError::Gap {
                expected: 1,
                got: 2
            })
        );
        let mut first = chain_of(1, 1).remove(0);
        first.prev_hash = [1; 32];
        assert_eq!(check_next(None, &first), Err(ChainError::Broken { seq: 1 }));
    }

    #[test]
    fn a_gap_is_refused() {
        let chain = chain_of(3, 1);
        assert_eq!(
            check_next(Some(chain[0].tip()), &chain[2]),
            Err(ChainError::Gap {
                expected: 2,
                got: 3
            })
        );
    }

    #[test]
    fn a_rewritten_event_breaks_the_chain_after_it() {
        let mut chain = chain_of(3, 1);
        // Tamper with event 2's body: its hash changes, so event 3 no longer follows it.
        chain[1].event_json = note("rewritten").to_json();
        assert_eq!(
            check_next(Some(chain[1].tip()), &chain[2]),
            Err(ChainError::Broken { seq: 3 })
        );
    }

    #[test]
    fn a_stale_fence_is_refused_and_a_newer_one_continues_the_chain() {
        let chain = chain_of(2, 5);
        let tip = chain[1].tip();
        // The old primary (fence 4) after a promotion moved the lease to 5.
        let stale = EventEnvelope::next("s1", Some(tip), 4, 9, &note("late"));
        assert_eq!(
            check_next(Some(tip), &stale),
            Err(ChainError::StaleFence { current: 5, got: 4 })
        );
        // The promoted primary (fence 6) continues the same chain.
        let promoted = EventEnvelope::next("s1", Some(tip), 6, 9, &note("resumed"));
        check_next(Some(tip), &promoted).unwrap();
        assert_eq!(promoted.tip().fence, 6);
    }

    #[test]
    fn field_boundaries_cannot_be_shifted_to_forge_a_hash() {
        // Same concatenated bytes, different split between session and body.
        let a = EventEnvelope {
            session: "ab".into(),
            seq: 1,
            fence: 1,
            ts_ms: 0,
            prev_hash: GENESIS,
            event_json: "c".into(),
        };
        let b = EventEnvelope {
            session: "a".into(),
            event_json: "bc".into(),
            ..a.clone()
        };
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn the_envelope_round_trips_with_a_hex_hash() {
        let ev = chain_of(2, 3).remove(1);
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains(&format!(
            "\"prev_hash\":\"{}\"",
            ev.prev_hash
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )));
        let back: EventEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
        assert_eq!(back.hash(), ev.hash());
    }

    /// P2a — the case the floor exists for: the promotion moved the lease to
    /// fence 2, no event of fence 2 exists yet, and the old primary (fence 1)
    /// sends its next event. The tip alone would take it.
    #[test]
    fn the_floor_refuses_an_older_fence_before_any_event_of_the_new_one() {
        let chain = chain_of(2, 1);
        let tip = chain[1].tip();
        let late = EventEnvelope::next("s1", Some(tip), 1, 9, &note("late"));
        check_next(Some(tip), &late).expect("the tip alone takes the stale writer's event");
        assert_eq!(
            check_next_with_floor(Some(tip), Some(2), &late),
            Err(ChainError::StaleFence { current: 2, got: 1 })
        );
        // The new primary's first event continues the same chain.
        let first = EventEnvelope::next("s1", Some(tip), 2, 9, &note("resumed"));
        check_next_with_floor(Some(tip), Some(2), &first).unwrap();
    }

    /// P2a — a floor holds for a session this member holds nothing of yet:
    /// a joiner's floor arrives before its first event.
    #[test]
    fn the_floor_holds_before_the_first_event() {
        let at_1 = chain_of(1, 1).remove(0);
        assert_eq!(
            check_next_with_floor(None, Some(3), &at_1),
            Err(ChainError::StaleFence { current: 3, got: 1 })
        );
        let at_3 = chain_of(1, 3).remove(0);
        check_next_with_floor(None, Some(3), &at_3).unwrap();
        // The floor never excuses what check_next refuses.
        let mut not_first = at_3.clone();
        not_first.seq = 2;
        assert_eq!(
            check_next_with_floor(None, Some(3), &not_first),
            Err(ChainError::Gap {
                expected: 1,
                got: 2
            })
        );
    }

    /// P2a — the newer of the floor and the tip's fence is what counts, so a
    /// floor below the tip's fence changes nothing, and no floor is exactly
    /// `check_next`.
    #[test]
    fn the_newer_of_the_floor_and_the_tip_counts_and_no_floor_is_check_next() {
        let chain = chain_of(2, 5);
        let tip = chain[1].tip();
        let stale = EventEnvelope::next("s1", Some(tip), 4, 9, &note("late"));
        let ok = EventEnvelope::next("s1", Some(tip), 5, 9, &note("next"));
        let mut gap = ok.clone();
        gap.seq = 9;
        for floor in [None, Some(1), Some(5)] {
            assert_eq!(
                check_next_with_floor(Some(tip), floor, &stale),
                Err(ChainError::StaleFence { current: 5, got: 4 }),
                "floor {floor:?}"
            );
            check_next_with_floor(Some(tip), floor, &ok).unwrap();
        }
        for next in [&stale, &ok, &gap, &chain[0]] {
            assert_eq!(
                check_next_with_floor(Some(tip), None, next),
                check_next(Some(tip), next)
            );
            assert_eq!(
                check_next_with_floor(None, None, next),
                check_next(None, next)
            );
        }
    }

    /// P2e-5b — a member that joined after a move, its floor at fence 2 with
    /// nothing held yet, takes fence 1's history up to where fence 1 ended,
    /// at the end only the very event it ended with, and nothing of fence 1
    /// past it; then fence 2's events, as any.
    #[test]
    fn below_the_floor_a_fence_is_taken_up_to_its_end_and_no_further() {
        let mut chain = chain_of(3, 1);
        let end = FenceEnd {
            fence: 1,
            seq: 3,
            hash: chain[2].hash(),
        };
        let ends = [end];
        let mut tip = None;
        for ev in &chain {
            assert_eq!(
                check_next_with_floor(tip, Some(2), ev),
                Err(ChainError::StaleFence { current: 2, got: 1 }),
                "without its end, fence 1 is all a stale writer's"
            );
            check_next_with_ends(tip, Some(2), &ends, ev)
                .unwrap_or_else(|e| panic!("below the floor, fence 1 is taken up to its end: {e}"));
            tip = Some(ev.tip());
        }
        let late = EventEnvelope::next("s1", tip, 1, 9, &note("late"));
        assert_eq!(
            check_next_with_ends(tip, Some(2), &ends, &late),
            Err(ChainError::StaleFence { current: 2, got: 1 }),
            "past its end, an old primary's late write"
        );
        let resumed = EventEnvelope::next("s1", tip, 2, 9, &note("resumed"));
        check_next_with_ends(tip, Some(2), &ends, &resumed).unwrap();

        // At the end, another event: this copy is not the record's.
        let other = EventEnvelope::next("s1", Some(chain[1].tip()), 1, 9, &note("other"));
        assert_eq!(
            check_next_with_ends(Some(chain[1].tip()), Some(2), &ends, &other),
            Err(ChainError::NotFenceEnd { fence: 1, seq: 3 }),
            "at its end, only the event it ended with"
        );
        // An end never excuses what check_next refuses.
        chain[1].prev_hash = [7; 32];
        assert_eq!(
            check_next_with_ends(Some(chain[0].tip()), Some(2), &ends, &chain[1]),
            Err(ChainError::Broken { seq: 2 }),
            "an end never excuses what check_next refuses"
        );
        // Another fence's end is no end of this one.
        let elsewhere = [FenceEnd { fence: 3, ..end }];
        assert_eq!(
            check_next_with_ends(None, Some(4), &elsewhere, &chain_of(1, 1)[0]),
            Err(ChainError::StaleFence { current: 4, got: 1 }),
            "another fence's end is no end of this one"
        );
    }

    #[test]
    fn an_unknown_kind_still_chains() {
        // A newer member's event this build cannot parse.
        let first = EventEnvelope {
            session: "s1".into(),
            seq: 1,
            fence: 1,
            ts_ms: 0,
            prev_hash: GENESIS,
            event_json: r#"{"kind":"from_the_future","x":1}"#.into(),
        };
        assert_eq!(first.event(), None);
        check_next(None, &first).unwrap();
        let second = EventEnvelope::next("s1", Some(first.tip()), 1, 1, &note("after"));
        check_next(Some(first.tip()), &second).unwrap();
    }
}
