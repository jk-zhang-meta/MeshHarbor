// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2d — the replica stream between a member and its source (spec §3b,
//! "The stream"): one QUIC connection per session, opened by the member, so a
//! member that was away catches up from where it stopped. This module is the
//! part with no I/O: the messages, their framing, and each side's half of
//! the opening exchange, read from a store.
//!
//! On the member's stream (both ways):
//!
//! | Message | From | Says |
//! |---|---|---|
//! | `hello {v, session, fence, tip, floor, checkpoints}` | member | where its copy ends, and the `(seq, hash)` of its newest checkpoints |
//! | `hello {v, tip, live}` | source | the member's copy is a prefix of its chain; the stream goes on from the member's tip. `live`: the session is not over on the source (P2d-3b) |
//! | `diverged {at, tip, live}` | source | the member's tip is not in its chain: the newest checkpoint both hold, past which the member sets its copy aside |
//! | `refused {reason}` | source | it cannot serve: a version it does not speak, a session it does not hold |
//! | `events {events: [{seq, fence, ts_ms, prev_hash, len}]}`, then each event's JSON, `len` bytes | source | envelopes in `seq` order (P2d-3): from where the opening exchange left the member, then the live tail as it is appended |
//! | `need {blobs}` | member | the blobs the next event names that it does not hold, by hash |
//! | `ack {seq, hash}` | member | applied and on disk: the events up to `seq`, and every blob they name |
//! | `want_pack {commit, haves}` | member | P2f-2b, in place of `need` for a checkpoint's whole pack, and only to a source whose hello said `packs`: the pack that brings `commit` into a repository holding `haves`. P2f-2c — no haves: the whole pack made again, for one the source's hello lists among its `stand_ins` (the whole packs it holds only a substitute for) |
//!
//! On a stream of its own, one per blob the member asked for:
//!
//! | Message | From | Says |
//! |---|---|---|
//! | `blob {hash, len}`, then its bytes | source | one blob of the `need` |
//! | `pack {commit, against, chunks}` | source | P2f-2b, the answer to `want_pack`: the pack's chunks, kept by the source as blobs of the session for the member to `need` as any blob, and the commits it is thin against |
//! | `no_pack {commit, why}` | source | P2f-2b: it cannot answer, and the member takes the whole pack |
//!
//! ⚠️ **A member asks for a blob; it is never pushed one.** A blob pushed
//! ahead of the event that names it would reach the member before it could
//! know the name, so a source could fill its disk with bytes nothing names;
//! and a member that could not read a pushed blob at once (its memory budget
//! spent) would leave it filling the connection's flow-control window, under
//! the data that would free the budget. A member asks only for what it lacks,
//! and only once it has the memory for it, so a reconnect sends nothing it
//! holds already: a checkpoint larger than one grant can carry still lands,
//! a grant at a time.
//!
//! ⚠️ An event's JSON follows its frame byte for byte, never as a JSON string
//! inside it: its hash is over those bytes, and a string would be escaped
//! (up to twice the size) and read back through another parser.
//!
//! ⚠️ A frame announces its length before its body, and a reader refuses a
//! length past [`MAX_FRAME`] before it allocates; an event past
//! [`MAX_EVENT_BYTES`] or a blob past [`MAX_STREAM_BLOB`] likewise: the other
//! side is a device of the org, not a trusted one.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::chain::{EventEnvelope, GENESIS};
use crate::checkpoint::{CHUNK_MAX, Chunk, Digest};
use crate::event::TranscriptEvent;
use crate::store::{Store, StoreError, hex};

/// The stream's version. A source refuses a hello of any other.
pub const STREAM_V: u32 = 1;
/// The largest frame either side reads.
pub const MAX_FRAME: usize = 1024 * 1024;
/// How many of its newest checkpoints a member names in its hello: enough
/// to find one both sides hold after a divergence a promotion left behind.
pub const MAX_CHECKPOINTS: usize = 8;
/// P2d-3 — the most events one `events` frame lists, as a viewer's page does
/// (`agents/meshharbord/src/hive/view.rs` `PAGE_MAX`).
pub const MAX_BATCH: usize = 500;
/// P2d-3 — the event bytes one `events` frame carries before its batch is
/// cut; an event larger than this comes alone.
pub const BATCH_BYTES: usize = 1024 * 1024;
/// P2d-3 — the largest event the stream carries, refused before it is read.
/// Twice the largest a device records: a checkpoint, whose manifest the
/// daemon reads up to 16 MiB (`agents/meshharbord/src/hive/checkpointer.rs`
/// `MAX_HEADER`), and a stream-json line, read up to 8 MiB. A source holding
/// a larger one cannot stream past it, and says so.
pub const MAX_EVENT_BYTES: usize = 32 * 1024 * 1024;
/// P2d-3 — the largest blob the stream carries: a chunk. A producer chunks
/// anything larger ([`crate::checkpoint::chunk_bytes`]).
pub const MAX_STREAM_BLOB: usize = CHUNK_MAX;
/// P2d-3 — the most blobs one `need` asks for.
pub const MAX_NEED: usize = 64;
/// P2f-2b — the most commits a `want_pack` names, as many as the account's
/// git is asked about (`MAX_HAVES` in the daemon's workspace).
pub const MAX_WANT_HAVES: usize = 16;
/// P2f-2b — the most chunks a `pack` answer lists: a pack of the largest a
/// checkpoint carries (512 MiB), in chunks of [`CHUNK_MAX`].
pub const MAX_PACK_CHUNKS: usize = 512 * 1024 * 1024 / CHUNK_MAX + 1;
/// P2f-2b — the `want_pack`s one stream carries: one per commit, and at most
/// this many. A member asks once for each whole pack it takes, and a chain
/// holds few; each want costs the source a read of the chain's checkpoints,
/// and one for a pack of its own a run of the account's git. P2f-2c — as
/// many stand-ins as a source's hello lists.
pub const MAX_WANTS: usize = 16;

/// A point in a session's chain: an event's `seq`, and its hash as
/// lowercase hex. Seq 0 is before the first event, at [`GENESIS`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    pub seq: u64,
    pub hash: String,
}

impl Mark {
    /// Before the first event: where every chain starts.
    pub fn genesis() -> Self {
        Self {
            seq: 0,
            hash: hex(&GENESIS),
        }
    }

    fn of(seq: u64, hash: &[u8; 32]) -> Self {
        Self {
            seq,
            hash: hex(hash),
        }
    }
}

/// What the member sends.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum MemberMsg {
    /// The first frame: where the member's copy ends.
    Hello {
        v: u32,
        session: String,
        fence: u64,
        tip: Mark,
        floor: u64,
        /// Newest first, at most [`MAX_CHECKPOINTS`].
        checkpoints: Vec<Mark>,
    },
    /// P2d-3 — the blobs the next event names that the member lacks, at
    /// most [`MAX_NEED`]: each comes back on a stream of its own.
    Need { blobs: Vec<Digest> },
    /// P2d-3 — applied and on disk: the events up to `seq`, whose hash is
    /// `hash`, and every blob they name.
    Ack { seq: u64, hash: String },
    /// P2f-2b — in place of `need` for a checkpoint's whole pack: the pack
    /// that brings `commit` into a repository holding `haves` (git's have
    /// and want). Answered on a stream of its own ([`BlobMsg::Pack`] or
    /// [`BlobMsg::NoPack`]); sent only to a source whose hello said `packs`.
    WantPack { commit: String, haves: Vec<String> },
}

/// What the source sends.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum SourceMsg {
    /// The member's copy is a prefix of the source's chain, which ends at
    /// `tip`.
    Hello {
        v: u32,
        tip: Mark,
        /// P2d-3b — the session is not over on the source: it runs there,
        /// or will resume there. A member caught up with one that is over
        /// lets the stream go. Absent (an older source) = live.
        #[serde(default = "live_unless_said")]
        live: bool,
        /// P2f-2b — it answers `want_pack`. Absent (an older source) = it
        /// does not: a member asks it for a whole pack's blobs.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        packs: bool,
        /// P2f-2c — the commits of the chain's whole packs it holds only a
        /// substitute for, at most [`MAX_WANTS`]: it cannot serve their
        /// blobs, and a member asks `want_pack` for them instead, with no
        /// haves where it holds none. Absent (an older source, or none) =
        /// every whole pack's blobs are there.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        stand_ins: Vec<String>,
    },
    /// The member's tip is not in the source's chain: `at` is the newest
    /// checkpoint both hold (genesis, if none), past which the member sets
    /// its copy aside and takes the source's events.
    Diverged {
        at: Mark,
        /// P2d-3b — where the source's chain ends, as in `hello`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tip: Option<Mark>,
        /// P2d-3b — as in `hello`.
        #[serde(default = "live_unless_said")]
        live: bool,
        /// P2f-2b — as in `hello`.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        packs: bool,
        /// P2f-2c — as in `hello`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        stand_ins: Vec<String>,
    },
    /// The source cannot serve this stream.
    Refused { reason: String },
    /// P2d-3 — the next events, in `seq` order; each one's JSON follows the
    /// frame, `len` bytes, in the order listed.
    Events { events: Vec<EventMeta> },
}

/// What a source that does not say is taken to mean: the session is live,
/// so the member keeps following.
fn live_unless_said() -> bool {
    true
}

/// P2d-3 — one event as an `events` frame lists it: its envelope but the
/// session, which is the stream's, and the JSON, which follows the frame.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EventMeta {
    pub seq: u64,
    pub fence: u64,
    pub ts_ms: i64,
    #[serde(with = "crate::chain::hex32")]
    pub prev_hash: [u8; 32],
    /// The length of the event's JSON, in bytes.
    pub len: u64,
}

impl EventMeta {
    /// How `env` is listed.
    pub fn of(env: &EventEnvelope) -> Self {
        Self {
            seq: env.seq,
            fence: env.fence,
            ts_ms: env.ts_ms,
            prev_hash: env.prev_hash,
            len: env.event_json.len() as u64,
        }
    }

    /// The envelope this listing and the JSON that followed it make, in the
    /// stream's `session`: the very one the source holds, whose hash is
    /// over these bytes.
    pub fn envelope(&self, session: &str, event_json: String) -> EventEnvelope {
        EventEnvelope {
            session: session.to_string(),
            seq: self.seq,
            fence: self.fence,
            ts_ms: self.ts_ms,
            prev_hash: self.prev_hash,
            event_json,
        }
    }
}

/// P2d-3 — the first frame of a blob's own stream, which the source opens
/// for each blob a member asked for: its name and length. Its bytes follow.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum BlobMsg {
    Blob {
        hash: Digest,
        len: u64,
    },
    /// P2f-2b — the answer to `want_pack`: the pack that brings `commit` into a
    /// repository holding `against`, as chunks the source keeps as blobs of
    /// the session, for the member to `need` as any blob. Nothing follows.
    Pack {
        commit: String,
        against: Vec<String>,
        chunks: Vec<Chunk>,
    },
    /// P2f-2b — `want_pack` cannot be answered: the member takes the whole
    /// pack, by its blobs.
    NoPack {
        commit: String,
        why: String,
    },
}

/// P2d-3 — the blobs `env` names, each once, with its length: a
/// checkpoint's ([`crate::checkpoint::Checkpoint::blobs`]). Every other kind
/// names none, and so does a kind this build does not know.
///
/// ⚠️ A new kind that names blobs bumps [`STREAM_V`]. A member that cannot
/// read the kind would apply it, and ack it, without them: a copy that says
/// it is whole and is not.
pub fn blobs_named(env: &EventEnvelope) -> Vec<(Digest, u64)> {
    match env.event() {
        Some(TranscriptEvent::Checkpoint(cp)) => cp.blobs(),
        _ => Vec::new(),
    }
}

/// Why a frame could not be read.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("a frame of {0} bytes is past the {MAX_FRAME}-byte limit")]
    TooLong(usize),
    #[error("an empty frame")]
    Empty,
    #[error("a frame that is not one: {0}")]
    Malformed(String),
    /// P2d-3 — an `events` frame listing none, or more than [`MAX_BATCH`].
    #[error("an events frame of {0} events: one at least, {MAX_BATCH} at most")]
    Batch(usize),
    /// P2d-3 — an event announced past [`MAX_EVENT_BYTES`].
    #[error("an event of {0} bytes is past the {MAX_EVENT_BYTES}-byte limit")]
    EventTooLong(u64),
    /// P2d-3 — a blob announced past [`MAX_STREAM_BLOB`].
    #[error("a blob of {0} bytes is past the {MAX_STREAM_BLOB}-byte limit")]
    BlobTooLong(u64),
    /// P2d-3 — a `need` asking for none, or more than [`MAX_NEED`].
    #[error("a need of {0} blobs: one at least, {MAX_NEED} at most")]
    Need(usize),
    /// P2f-2b — a `want_pack`, or its `pack` answer, that is not one.
    #[error("a pack's have and want that is not one: {0}")]
    Pack(String),
}

/// P2d-3 — an `events` frame's listing, checked before any of its JSON is
/// read: one event at least, [`MAX_BATCH`] at most, none past
/// [`MAX_EVENT_BYTES`]. Their order and their chain are the store's to
/// check, as it applies each.
pub fn check_events(events: &[EventMeta]) -> Result<(), FrameError> {
    if events.is_empty() || events.len() > MAX_BATCH {
        return Err(FrameError::Batch(events.len()));
    }
    match events.iter().find(|e| e.len > MAX_EVENT_BYTES as u64) {
        Some(e) => Err(FrameError::EventTooLong(e.len)),
        None => Ok(()),
    }
}

/// P2d-3 — a blob's announced length, refused before it is read when past
/// [`MAX_STREAM_BLOB`].
pub fn check_blob_len(len: u64) -> Result<usize, FrameError> {
    if len > MAX_STREAM_BLOB as u64 {
        return Err(FrameError::BlobTooLong(len));
    }
    Ok(len as usize)
}

/// P2d-3 — a `need`'s size: one blob at least, [`MAX_NEED`] at most.
pub fn check_need(blobs: &[Digest]) -> Result<(), FrameError> {
    if blobs.is_empty() || blobs.len() > MAX_NEED {
        return Err(FrameError::Need(blobs.len()));
    }
    Ok(())
}

/// P2f-2b — an object id as git prints one: 40 or 64 lowercase hex digits.
fn is_commit_id(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// P2f-2b — a `want_pack`'s names: a commit id each, at most
/// [`MAX_WANT_HAVES`] haves, the commit not among them. P2f-2c — none is a
/// want for a whole pack, made again from the source's repository: what a
/// member asks for a pack the source holds only a substitute for.
pub fn check_want_pack(commit: &str, haves: &[String]) -> Result<(), FrameError> {
    if !is_commit_id(commit) {
        return Err(FrameError::Pack(format!("{commit:?} is not a commit id")));
    }
    if haves.len() > MAX_WANT_HAVES {
        return Err(FrameError::Pack(format!(
            "{} haves: {MAX_WANT_HAVES} at most",
            haves.len()
        )));
    }
    match haves.iter().find(|h| !is_commit_id(h) || *h == commit) {
        Some(h) => Err(FrameError::Pack(format!("{h:?} is not a have"))),
        None => Ok(()),
    }
}

/// P2f-2c — a source's stand-ins, as its hello lists them: a commit id each,
/// each once, at most [`MAX_WANTS`].
pub fn check_stand_ins(stand_ins: &[String]) -> Result<(), FrameError> {
    if stand_ins.len() > MAX_WANTS {
        return Err(FrameError::Pack(format!(
            "{} stand-ins: {MAX_WANTS} at most",
            stand_ins.len()
        )));
    }
    for (i, c) in stand_ins.iter().enumerate() {
        if !is_commit_id(c) || stand_ins[..i].contains(c) {
            return Err(FrameError::Pack(format!("{c:?} is not a stand-in")));
        }
    }
    Ok(())
}

/// P2f-2b — a `pack` answer held to the `want_pack` it answers: the same
/// commit, thin only against commits the want named, and chunks that follow
/// one another from offset 0, each a blob the stream carries, at most
/// [`MAX_PACK_CHUNKS`]. The bytes are the blobs' to check, as they arrive.
pub fn check_pack(
    wanted: &str,
    haves: &[String],
    commit: &str,
    against: &[String],
    chunks: &[Chunk],
) -> Result<(), FrameError> {
    if commit != wanted {
        return Err(FrameError::Pack(format!(
            "a pack of {commit:?}, for {wanted:?}"
        )));
    }
    if let Some(a) = against.iter().find(|a| !haves.contains(a)) {
        return Err(FrameError::Pack(format!(
            "a pack against {a:?}, which was no have"
        )));
    }
    if chunks.is_empty() || chunks.len() > MAX_PACK_CHUNKS {
        return Err(FrameError::Pack(format!(
            "a pack of {} chunks",
            chunks.len()
        )));
    }
    let mut offset = 0u64;
    for c in chunks {
        if c.offset != offset || c.len == 0 || c.len > MAX_STREAM_BLOB as u64 {
            return Err(FrameError::Pack(
                "its chunks do not follow one another".into(),
            ));
        }
        offset += c.len;
    }
    Ok(())
}

/// P2d-3 — the member's ack once it has applied up to `tip`.
pub fn ack_of(tip: &crate::chain::ChainTip) -> MemberMsg {
    MemberMsg::Ack {
        seq: tip.seq,
        hash: hex(&tip.hash),
    }
}

/// One frame: a little-endian `u32` length, then that many bytes of JSON.
pub fn encode<T: Serialize>(msg: &T) -> Vec<u8> {
    let body = serde_json::to_vec(msg).expect("a stream message always serializes");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// The body length a frame's header announces, refused before the reader
/// allocates it when it is past [`MAX_FRAME`].
pub fn frame_len(header: [u8; 4]) -> Result<usize, FrameError> {
    let len = u32::from_le_bytes(header) as usize;
    match len {
        0 => Err(FrameError::Empty),
        n if n > MAX_FRAME => Err(FrameError::TooLong(n)),
        n => Ok(n),
    }
}

/// A frame's body, as a message.
pub fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, FrameError> {
    serde_json::from_slice(body).map_err(|e| FrameError::Malformed(e.to_string()))
}

/// The member's hello for `session`, from its own store.
pub fn member_hello(store: &Store, session: &str, fence: u64) -> Result<MemberMsg, StoreError> {
    let tip = store
        .tip(session)?
        .map_or_else(Mark::genesis, |t| Mark::of(t.seq, &t.hash));
    let floor = store.floor(session)?.unwrap_or(0);
    let checkpoints = store
        .checkpoint_marks(session, MAX_CHECKPOINTS)?
        .into_iter()
        .map(|(seq, hash)| Mark::of(seq, &hash))
        .collect();
    Ok(MemberMsg::Hello {
        v: STREAM_V,
        session: session.to_string(),
        fence,
        tip,
        floor,
        checkpoints,
    })
}

/// The source's answer to a member's hello, from its own store. A first
/// frame that is not a hello is refused (`not_a_hello`). `live` is the
/// source's own word that the session is not over there (P2d-3b): it runs
/// there, or will resume there. Both answers carry it, and the source's tip.
pub fn answer_hello(store: &Store, hello: &MemberMsg, live: bool) -> Result<SourceMsg, StoreError> {
    let MemberMsg::Hello {
        v,
        session,
        tip,
        checkpoints,
        ..
    } = hello
    else {
        return Ok(SourceMsg::Refused {
            reason: "not_a_hello".into(),
        });
    };
    if *v != STREAM_V {
        return Ok(SourceMsg::Refused {
            reason: "version".into(),
        });
    }
    let Some(own) = store.tip(session)? else {
        return Ok(SourceMsg::Refused {
            reason: "not_held".into(),
        });
    };
    let own = Mark::of(own.seq, &own.hash);
    // P2f-2c — what it cannot serve by blobs, so a member asks for it.
    let stand_ins = store.stand_ins(session, MAX_WANTS)?;
    if holds(store, session, tip)? {
        return Ok(SourceMsg::Hello {
            v: STREAM_V,
            tip: own,
            live,
            packs: true,
            stand_ins,
        });
    }
    // Newest first, as the member listed them; at most as many as it may.
    let mut at = Mark::genesis();
    for cp in checkpoints.iter().take(MAX_CHECKPOINTS) {
        if holds(store, session, cp)? {
            at = cp.clone();
            break;
        }
    }
    Ok(SourceMsg::Diverged {
        at,
        tip: Some(own),
        live,
        packs: true,
        stand_ins,
    })
}

/// Whether the source's chain holds `mark`: genesis always, and otherwise
/// its event at `mark.seq`, hashed to `mark.hash`.
fn holds(store: &Store, session: &str, mark: &Mark) -> Result<bool, StoreError> {
    if mark.seq == 0 {
        return Ok(mark.hash == hex(&GENESIS));
    }
    Ok(store
        .event_at(session, mark.seq)?
        .is_some_and(|e| hex(&e.hash()) == mark.hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append `n` notes to `session` at `fence`, each chained on the last.
    fn grow(store: &mut Store, session: &str, fence: u64, n: usize) {
        for i in 0..n {
            let tip = store.tip(session).unwrap();
            let env = EventEnvelope::next(
                session,
                tip,
                fence,
                0,
                &TranscriptEvent::Note {
                    text: format!("note {i}"),
                },
            );
            store.append(&env).unwrap();
        }
    }

    fn hello(tip: Mark, checkpoints: Vec<Mark>) -> MemberMsg {
        MemberMsg::Hello {
            v: STREAM_V,
            session: "s".into(),
            fence: 1,
            tip,
            floor: 1,
            checkpoints,
        }
    }

    fn mark_at(store: &Store, seq: u64) -> Mark {
        let env = store.event_at("s", seq).unwrap().unwrap();
        Mark::of(seq, &env.hash())
    }

    /// The wire is locked: each message's shape, tagged by `t`.
    #[test]
    fn the_stream_messages_are_locked() {
        let m = hello(Mark::genesis(), vec![]);
        assert_eq!(
            serde_json::to_value(&m).unwrap(),
            serde_json::json!({
                "t": "hello", "v": 1, "session": "s", "fence": 1,
                "tip": {"seq": 0, "hash": "0".repeat(64)}, "floor": 1, "checkpoints": []
            })
        );
        let zero = serde_json::json!({"seq": 0, "hash": "0".repeat(64)});
        let a = SourceMsg::Diverged {
            at: Mark::genesis(),
            tip: Some(Mark::genesis()),
            live: false,
            packs: false,
            stand_ins: Vec::new(),
        };
        assert_eq!(
            serde_json::to_value(&a).unwrap(),
            serde_json::json!({"t": "diverged", "at": zero, "tip": zero, "live": false})
        );
        let h = SourceMsg::Hello {
            v: 1,
            tip: Mark::genesis(),
            live: true,
            packs: false,
            stand_ins: Vec::new(),
        };
        assert_eq!(
            serde_json::to_value(&h).unwrap(),
            serde_json::json!({"t": "hello", "v": 1, "tip": zero, "live": true})
        );
        // P2d-3b — an answer that does not say whether the session is live
        // (a source of P2d-3a) is taken as live, and so followed.
        assert_eq!(
            serde_json::from_value::<SourceMsg>(
                serde_json::json!({"t": "hello", "v": 1, "tip": zero})
            )
            .unwrap(),
            h
        );
        assert_eq!(
            serde_json::from_value::<SourceMsg>(serde_json::json!({"t": "diverged", "at": zero}))
                .unwrap(),
            SourceMsg::Diverged {
                at: Mark::genesis(),
                tip: None,
                live: true,
                packs: false,
                stand_ins: Vec::new(),
            }
        );
        assert_eq!(
            serde_json::to_value(SourceMsg::Refused {
                reason: "not_held".into()
            })
            .unwrap(),
            serde_json::json!({"t": "refused", "reason": "not_held"})
        );
    }

    /// A frame is its length, then its body; a length past the limit, or
    /// none, is refused before anything is read into memory.
    #[test]
    fn a_frame_announces_its_length_and_a_long_one_is_refused_first() {
        let m = hello(Mark::genesis(), vec![]);
        let bytes = encode(&m);
        let len = frame_len(bytes[..4].try_into().unwrap()).unwrap();
        assert_eq!(len, bytes.len() - 4);
        assert_eq!(decode::<MemberMsg>(&bytes[4..]).unwrap(), m);
        assert_eq!(
            frame_len(((MAX_FRAME + 1) as u32).to_le_bytes()),
            Err(FrameError::TooLong(MAX_FRAME + 1))
        );
        assert_eq!(frame_len([0; 4]), Err(FrameError::Empty));
        assert!(matches!(
            decode::<MemberMsg>(b"{\"t\":\"goodbye\"}"),
            Err(FrameError::Malformed(_))
        ));
    }

    /// A member's copy that is a prefix of the source's chain is answered
    /// `hello` with the source's tip: an empty copy, one part of the way,
    /// and one at the very end.
    #[test]
    fn a_prefix_is_answered_hello_with_the_sources_tip() {
        let mut store = Store::open_in_memory().unwrap();
        grow(&mut store, "s", 1, 5);
        let own = mark_at(&store, 5);
        for tip in [Mark::genesis(), mark_at(&store, 3), own.clone()] {
            assert_eq!(
                answer_hello(&store, &hello(tip, vec![]), true).unwrap(),
                SourceMsg::Hello {
                    v: STREAM_V,
                    tip: own.clone(),
                    live: true,
                    packs: true,
                    stand_ins: Vec::new(),
                }
            );
        }
        // P2d-3b — the source's word on whether the session is over goes
        // with it.
        assert_eq!(
            answer_hello(&store, &hello(own.clone(), vec![]), false).unwrap(),
            SourceMsg::Hello {
                v: STREAM_V,
                tip: own,
                live: false,
                packs: true,
                stand_ins: Vec::new(),
            }
        );
    }

    /// A tip the source's chain does not hold is answered `diverged`, at
    /// the newest of the member's checkpoints the source holds too, or at
    /// genesis when it holds none of them.
    #[test]
    fn a_tip_not_in_the_chain_is_answered_diverged_at_the_newest_common_checkpoint() {
        let mut store = Store::open_in_memory().unwrap();
        grow(&mut store, "s", 1, 6);
        let foreign = Mark {
            seq: 4,
            hash: "ee".repeat(32),
        };
        let common = mark_at(&store, 2);
        let own = Some(mark_at(&store, 6));
        let theirs = Mark {
            seq: 3,
            hash: "dd".repeat(32),
        };
        assert_eq!(
            answer_hello(
                &store,
                &hello(foreign.clone(), vec![theirs.clone(), common.clone()]),
                true
            )
            .unwrap(),
            SourceMsg::Diverged {
                at: common,
                tip: own.clone(),
                live: true,
                packs: true,
                stand_ins: Vec::new(),
            },
            "the newest checkpoint both hold, and where the source's chain ends"
        );
        assert_eq!(
            answer_hello(&store, &hello(foreign.clone(), vec![theirs]), false).unwrap(),
            SourceMsg::Diverged {
                at: Mark::genesis(),
                tip: own.clone(),
                live: false,
                packs: true,
                stand_ins: Vec::new(),
            },
            "none both hold"
        );
        let ahead = Mark {
            seq: 9,
            hash: "aa".repeat(32),
        };
        assert_eq!(
            answer_hello(&store, &hello(ahead, vec![]), true).unwrap(),
            SourceMsg::Diverged {
                at: Mark::genesis(),
                tip: own,
                live: true,
                packs: true,
                stand_ins: Vec::new(),
            },
            "a tip past the source's own end is not in its chain"
        );
    }

    /// A version the source does not speak, or a session it does not hold,
    /// is refused in words.
    #[test]
    fn a_version_or_session_the_source_cannot_serve_is_refused() {
        let mut store = Store::open_in_memory().unwrap();
        grow(&mut store, "s", 1, 1);
        let MemberMsg::Hello {
            session,
            fence,
            tip,
            floor,
            checkpoints,
            ..
        } = hello(Mark::genesis(), vec![])
        else {
            unreachable!("a hello")
        };
        let older = MemberMsg::Hello {
            v: STREAM_V + 1,
            session: session.clone(),
            fence,
            tip: tip.clone(),
            floor,
            checkpoints: checkpoints.clone(),
        };
        assert_eq!(
            answer_hello(&store, &older, true).unwrap(),
            SourceMsg::Refused {
                reason: "version".into()
            }
        );
        let elsewhere = MemberMsg::Hello {
            v: STREAM_V,
            session: "other".into(),
            fence,
            tip,
            floor,
            checkpoints,
        };
        assert_eq!(
            answer_hello(&store, &elsewhere, true).unwrap(),
            SourceMsg::Refused {
                reason: "not_held".into()
            }
        );
    }

    /// P2f-2c — a source's `hello` and its `diverged` list the whole packs it
    /// holds only a substitute for, so a member asks for them by `want_pack`.
    #[test]
    fn a_sources_answer_lists_its_stand_ins() {
        use crate::checkpoint::{Checkpoint, RepoKind, WorkspaceSnap, chunk_bytes};
        use crate::store::Substitute;
        let mut store = Store::open_in_memory().unwrap();
        let c = "c".repeat(40);
        let cp = Checkpoint {
            n: 1,
            turn: 1,
            files: Vec::new(),
            skipped: Vec::new(),
            workspace: Some(WorkspaceSnap {
                repo: RepoKind::Own,
                prefix: String::new(),
                tree: "e".repeat(40),
                commit: c.clone(),
                base: None,
                head: None,
                pack: chunk_bytes(b"the whole pack").0,
            }),
        };
        let env = EventEnvelope::next("s", None, 1, 0, &TranscriptEvent::Checkpoint(cp));
        store.append(&env).unwrap();
        store.put_blob("s", b"stood in").unwrap();
        let sub = Substitute {
            commit: c.clone(),
            against: Vec::new(),
            chunks: chunk_bytes(b"stood in").0,
        };
        store.put_substitute("s", &sub).unwrap();
        let own = mark_at(&store, 1);
        let answer = answer_hello(&store, &hello(own, vec![]), true).unwrap();
        assert!(
            matches!(&answer, SourceMsg::Hello { stand_ins, .. } if *stand_ins == [c.clone()]),
            "{answer:?}"
        );
        let foreign = Mark {
            seq: 1,
            hash: "ee".repeat(32),
        };
        let answer = answer_hello(&store, &hello(foreign, vec![]), true).unwrap();
        assert!(
            matches!(&answer, SourceMsg::Diverged { stand_ins, .. } if *stand_ins == [c.clone()]),
            "{answer:?}"
        );
    }

    /// A member's hello says where its copy ends: genesis when it holds
    /// nothing yet, its tip, its floor, and its newest checkpoints first.
    #[test]
    fn a_members_hello_reads_its_own_store() {
        let mut store = Store::open_in_memory().unwrap();
        store.join("s", "owner", 2, &[]).unwrap();
        assert_eq!(
            member_hello(&store, "s", 2).unwrap(),
            MemberMsg::Hello {
                v: STREAM_V,
                session: "s".into(),
                fence: 2,
                tip: Mark::genesis(),
                floor: 2,
                checkpoints: vec![],
            }
        );
        grow(&mut store, "s", 2, 2);
        let MemberMsg::Hello { tip, .. } = member_hello(&store, "s", 2).unwrap() else {
            unreachable!("a hello")
        };
        assert_eq!(tip, mark_at(&store, 2));
    }

    /// A first frame that is not a hello is refused in words, never taken
    /// for one.
    #[test]
    fn a_first_frame_that_is_not_a_hello_is_refused() {
        let mut store = Store::open_in_memory().unwrap();
        grow(&mut store, "s", 1, 1);
        let ack = ack_of(&store.tip("s").unwrap().unwrap());
        assert_eq!(
            answer_hello(&store, &ack, true).unwrap(),
            SourceMsg::Refused {
                reason: "not_a_hello".into()
            }
        );
    }

    /// P2d-3 — what follows the opening exchange is locked too.
    #[test]
    fn the_messages_after_the_opening_exchange_are_locked() {
        let mut store = Store::open_in_memory().unwrap();
        grow(&mut store, "s", 3, 1);
        let env = store.event_at("s", 1).unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(SourceMsg::Events {
                events: vec![EventMeta::of(&env)]
            })
            .unwrap(),
            serde_json::json!({"t": "events", "events": [{
                "seq": 1, "fence": 3, "ts_ms": 0, "prev_hash": "0".repeat(64),
                "len": env.event_json.len()
            }]})
        );
        let d = Digest::of(b"x");
        assert_eq!(
            serde_json::to_value(MemberMsg::Need { blobs: vec![d] }).unwrap(),
            serde_json::json!({"t": "need", "blobs": [d.to_string()]})
        );
        assert_eq!(
            serde_json::to_value(ack_of(&env.tip())).unwrap(),
            serde_json::json!({"t": "ack", "seq": 1, "hash": hex(&env.hash())})
        );
        assert_eq!(
            serde_json::to_value(BlobMsg::Blob { hash: d, len: 1 }).unwrap(),
            serde_json::json!({"t": "blob", "hash": d.to_string(), "len": 1})
        );
    }

    /// P2d-3 — an event crosses the stream as its listing and its JSON, and
    /// comes out the very envelope, hash and all.
    #[test]
    fn an_event_crosses_as_the_very_envelope() {
        let mut store = Store::open_in_memory().unwrap();
        grow(&mut store, "s", 2, 3);
        for env in store.page("s", 0, 10).unwrap() {
            let meta: EventMeta =
                serde_json::from_value(serde_json::to_value(EventMeta::of(&env)).unwrap()).unwrap();
            assert_eq!(meta.len, env.event_json.len() as u64);
            let back = meta.envelope("s", env.event_json.clone());
            assert_eq!(back, env);
            assert_eq!(back.hash(), env.hash());
        }
    }

    /// P2d-3 — a listing, a blob's length and a need are each checked before
    /// anything they announce is read.
    #[test]
    fn what_a_frame_announces_is_checked_before_it_is_read() {
        let meta = |len: u64| EventMeta {
            seq: 1,
            fence: 1,
            ts_ms: 0,
            prev_hash: GENESIS,
            len,
        };
        assert_eq!(check_events(&[]), Err(FrameError::Batch(0)));
        assert_eq!(
            check_events(&vec![meta(2); MAX_BATCH + 1]),
            Err(FrameError::Batch(MAX_BATCH + 1))
        );
        assert_eq!(check_events(&vec![meta(2); MAX_BATCH]), Ok(()));
        let past = MAX_EVENT_BYTES as u64 + 1;
        assert_eq!(
            check_events(&[meta(2), meta(past)]),
            Err(FrameError::EventTooLong(past))
        );
        assert_eq!(check_events(&[meta(MAX_EVENT_BYTES as u64)]), Ok(()));
        assert_eq!(check_blob_len(0), Ok(0), "an empty file's blob");
        assert_eq!(check_blob_len(MAX_STREAM_BLOB as u64), Ok(MAX_STREAM_BLOB));
        let past = MAX_STREAM_BLOB as u64 + 1;
        assert_eq!(check_blob_len(past), Err(FrameError::BlobTooLong(past)));
        let d = Digest::of(b"x");
        assert_eq!(check_need(&[]), Err(FrameError::Need(0)));
        assert_eq!(check_need(&vec![d; MAX_NEED]), Ok(()));
        assert_eq!(
            check_need(&vec![d; MAX_NEED + 1]),
            Err(FrameError::Need(MAX_NEED + 1))
        );
    }

    /// P2d-3 — a checkpoint names each blob it adds once, with its length:
    /// its files' chunks, then its pack's. Any other kind names none, and so
    /// does a kind this build cannot read.
    #[test]
    fn a_checkpoint_names_each_blob_it_adds_once() {
        use crate::checkpoint::{
            Checkpoint, RepoKind, WorkspaceSnap, chunk_bytes, snapshot_append, snapshot_whole,
        };
        let (history, _) = snapshot_append("h.jsonl", 0o600, b"one\ntwo\n", None);
        let (same, _) = snapshot_whole("copy.jsonl", 0o600, b"one\ntwo\n", None);
        let (empty, _) = snapshot_whole("CLAUDE.md", 0o600, b"", None);
        let (pack, _) = chunk_bytes(b"PACK");
        let cp = Checkpoint {
            n: 1,
            turn: 1,
            files: vec![history.clone(), same, empty.clone()],
            skipped: vec![],
            workspace: Some(WorkspaceSnap {
                repo: RepoKind::Shadow,
                prefix: String::new(),
                tree: "t".into(),
                commit: "c".into(),
                base: None,
                head: None,
                pack: pack.clone(),
            }),
        };
        let mut store = Store::open_in_memory().unwrap();
        let env = EventEnvelope::next("s", None, 1, 0, &TranscriptEvent::Checkpoint(cp));
        store.append(&env).unwrap();
        assert_eq!(
            blobs_named(&env),
            vec![
                (history.chunks[0].hash, history.chunks[0].len),
                (empty.chunks[0].hash, 0),
                (pack[0].hash, 4),
            ],
            "the second copy of the history's bytes is named once"
        );
        grow(&mut store, "s", 1, 1);
        let note = store.event_at("s", 2).unwrap().unwrap();
        assert!(blobs_named(&note).is_empty(), "a note names no blob");
        let unknown = EventEnvelope {
            event_json: r#"{"kind":"from_the_future","blobs":["ab"]}"#.into(),
            ..note
        };
        assert!(
            blobs_named(&unknown).is_empty(),
            "a kind this build cannot read"
        );
    }

    /// P2f-2b — the have and want's frames, by name; a source's hello says
    /// it answers them, and one that does not say (an older source) does not.
    #[test]
    fn the_have_and_wants_frames_are_named_and_an_older_source_takes_none() {
        let (c, h) = ("c".repeat(40), "a".repeat(40));
        let want = MemberMsg::WantPack {
            commit: c.clone(),
            haves: vec![h.clone()],
        };
        assert_eq!(
            serde_json::to_value(&want).unwrap(),
            serde_json::json!({"t": "want_pack", "commit": c, "haves": [h]})
        );
        let chunk = Chunk {
            offset: 0,
            len: 3,
            hash: Digest::of(b"abc"),
        };
        let pack = BlobMsg::Pack {
            commit: c.clone(),
            against: vec![h.clone()],
            chunks: vec![chunk],
        };
        assert_eq!(
            serde_json::to_value(&pack).unwrap()["t"],
            serde_json::json!("pack")
        );
        assert_eq!(
            serde_json::to_value(BlobMsg::NoPack {
                commit: c.clone(),
                why: "not_live".into()
            })
            .unwrap(),
            serde_json::json!({"t": "no_pack", "commit": c, "why": "not_live"})
        );
        let zero = serde_json::json!({"seq": 0, "hash": hex(&GENESIS)});
        let says =
            serde_json::json!({"t": "hello", "v": 1, "tip": zero, "live": true, "packs": true});
        assert!(matches!(
            serde_json::from_value::<SourceMsg>(says).unwrap(),
            SourceMsg::Hello { packs: true, .. }
        ));
        assert!(
            matches!(
                serde_json::from_value::<SourceMsg>(
                    serde_json::json!({"t": "hello", "v": 1, "tip": zero})
                )
                .unwrap(),
                SourceMsg::Hello { packs: false, ref stand_ins, .. } if stand_ins.is_empty()
            ),
            "an older source answers no want_pack, and stands in for nothing"
        );
        // P2f-2c — the whole packs a source holds only a substitute for, said
        // when there are any, and absent otherwise.
        let standing = SourceMsg::Hello {
            v: STREAM_V,
            tip: Mark::genesis(),
            live: true,
            packs: true,
            stand_ins: vec![c.clone()],
        };
        assert_eq!(
            serde_json::to_value(&standing).unwrap(),
            serde_json::json!({"t": "hello", "v": 1, "tip": zero, "live": true, "packs": true,
                               "stand_ins": [c]})
        );
        let none = SourceMsg::Diverged {
            at: Mark::genesis(),
            tip: None,
            live: true,
            packs: true,
            stand_ins: Vec::new(),
        };
        assert!(
            serde_json::to_value(&none)
                .unwrap()
                .get("stand_ins")
                .is_none()
        );
    }

    /// P2f-2c — a source's stand-ins are commit ids, each once, at most
    /// [`MAX_WANTS`].
    #[test]
    fn a_sources_stand_ins_are_commit_ids_each_once() {
        let (c, h) = ("c".repeat(40), "a".repeat(40));
        assert!(check_stand_ins(&[]).is_ok());
        assert!(check_stand_ins(&[c.clone(), h.clone()]).is_ok());
        let many: Vec<String> = (0..=MAX_WANTS).map(|i| format!("{i:040x}")).collect();
        assert!(check_stand_ins(&many[..MAX_WANTS]).is_ok());
        for (case, list) in [
            ("not an id", vec!["HEAD".to_string()]),
            ("twice", vec![c.clone(), c.clone()]),
            ("past MAX_WANTS", many),
        ] {
            assert!(
                matches!(check_stand_ins(&list), Err(FrameError::Pack(_))),
                "{case}"
            );
        }
    }

    /// P2f-2b — a want names commit ids, at most [`MAX_WANT_HAVES`] haves,
    /// never the commit itself (P2f-2c: none, for a whole pack); a pack
    /// answers that want alone, thin against its haves only, in chunks that
    /// follow one another.
    #[test]
    fn a_want_and_its_pack_are_held_to_each_other() {
        let (c, h, x) = ("c".repeat(40), "a".repeat(40), "b".repeat(40));
        assert!(check_want_pack(&c, std::slice::from_ref(&h)).is_ok());
        assert!(check_want_pack(&c, &[]).is_ok(), "a whole pack's want");
        assert!(
            check_pack(
                &c,
                &[],
                &c,
                &[],
                &[Chunk {
                    offset: 0,
                    len: 4,
                    hash: Digest::of(b"x"),
                }]
            )
            .is_ok(),
            "and its pack, against nothing"
        );
        for (commit, haves) in [
            ("HEAD".to_string(), vec![h.clone()]),
            (c.clone(), vec![c.clone()]),
            (c.clone(), vec!["--all".to_string()]),
            (c.clone(), vec![h.clone(); MAX_WANT_HAVES + 1]),
        ] {
            assert!(
                matches!(check_want_pack(&commit, &haves), Err(FrameError::Pack(_))),
                "{commit} {haves:?}"
            );
        }
        let chunk = |offset: u64, len: u64| Chunk {
            offset,
            len,
            hash: Digest::of(b"x"),
        };
        let haves = vec![h.clone()];
        let whole = [chunk(0, 4), chunk(4, 2)];
        assert!(check_pack(&c, &haves, &c, std::slice::from_ref(&h), &whole).is_ok());
        assert!(
            check_pack(&c, &haves, &c, &[], &whole).is_ok(),
            "a whole pack"
        );
        for (commit, against, chunks) in [
            (x.clone(), vec![h.clone()], whole.to_vec()),
            (c.clone(), vec![x.clone()], whole.to_vec()),
            (c.clone(), vec![h.clone()], vec![]),
            (c.clone(), vec![h.clone()], vec![chunk(1, 4)]),
            (c.clone(), vec![h.clone()], vec![chunk(0, 4), chunk(5, 2)]),
            (
                c.clone(),
                vec![h.clone()],
                vec![chunk(0, MAX_STREAM_BLOB as u64 + 1)],
            ),
        ] {
            assert!(
                matches!(
                    check_pack(&c, &haves, &commit, &against, &chunks),
                    Err(FrameError::Pack(_))
                ),
                "{commit} {against:?} {chunks:?}"
            );
        }
    }
}
