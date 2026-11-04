// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! The replica store's one writer: a thread that owns the SQLite connection.
//!
//! SQLite writes block, and a session's stdout reader must never stall the
//! runtime on one; one thread owning the connection also gives the chain its
//! one-writer rule for free — every append reads the tip and extends it inside
//! the store's own transaction, in the order the sessions sent them.
//!
//! P0d-2 reads go through the same thread (a viewer's page, a grant's "do I
//! hold this session"), answered on a oneshot so an async caller awaits
//! without blocking the runtime. And every append that lands is PUBLISHED to
//! the live feed: the writer is the only place that knows the `seq` an event
//! got, so it is the only place a viewer can learn it from without a gap.
//!
//! FR-90 P2a adds what a member of a replicaset needs ([`Member`]): apply an
//! envelope another member sent, the fence floor, setting aside an older
//! fence's tail, blobs, purge, and search. Each goes through this same thread
//! and is answered on its oneshot with the store's own word, so a caller can
//! tell `purged` from a stale fence. An applied envelope is published like an
//! appended one. The join (P2c-3) is the first to send one: it keeps the
//! membership and raises the floor in one transaction, and the tips read the
//! chain's end. The stream (P2d-3) applies what a source sends, an event
//! held already taken as held (`apply_unless_held`), and keeps the blobs a
//! member asks for. The purge (P2g-1) goes through it, and so does the
//! device's own clock (P2g-3d): what keeps each copy, the contact, and the
//! copies the clock purged. An archive replica's search (P2i) comes next.

use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc;

use meshharbor_hive_node::store::{
    Membership, RetainWord, SearchHit, Store, StoreError, Substitute, WorkplaceRecord,
};
use meshharbor_hive_node::{ChainTip, EventEnvelope, FenceEnd, TranscriptEvent};
use tokio::sync::{broadcast, oneshot};
use tracing::warn;

/// Appended events buffered per subscriber before a slow one lags. A lagging
/// viewer re-reads the store from its last `seq`, so nothing is lost by
/// dropping here — only re-fetched.
const FEED_CAPACITY: usize = 1024;

enum Cmd {
    Append {
        session: String,
        fence: u64,
        event: TranscriptEvent,
    },
    Page {
        session: String,
        after: u64,
        limit: usize,
        /// P2d-3 — the page cut before its events' JSON passes this.
        max_bytes: usize,
        reply: oneshot::Sender<Result<Vec<EventEnvelope>, String>>,
    },
    Tip {
        session: String,
        reply: oneshot::Sender<Option<u64>>,
    },
    /// FR-90 P2b-3b — a session's newest event of a kind.
    LastOfKind {
        session: String,
        kind: &'static str,
        reply: oneshot::Sender<Result<Option<EventEnvelope>, String>>,
    },
    /// FR-90 P2e-5 — every event of a session of a kind, oldest first.
    OfKind {
        session: String,
        kind: &'static str,
        limit: usize,
        reply: oneshot::Sender<Result<Vec<EventEnvelope>, String>>,
    },
    /// FR-90 P2a.
    #[cfg_attr(not(test), allow(dead_code))]
    Member(Member),
    #[cfg(all(test, unix))]
    Events {
        session: String,
        reply: mpsc::Sender<Vec<TranscriptEvent>>,
    },
}

/// How a member command is answered: the store's own word.
type Reply<T> = oneshot::Sender<Result<T, StoreError>>;

/// FR-90 P2a — what a member's store does, each answered on its oneshot.
/// Built only by the [`StoreHandle`] methods below, which nothing outside
/// tests calls until the join (P2c) and the stream (P2d).
#[cfg_attr(not(test), allow(dead_code))]
enum Member {
    Apply {
        env: EventEnvelope,
        reply: Reply<ChainTip>,
    },
    /// P2d-3 — apply, or nothing for an event held already.
    ApplyUnlessHeld {
        env: EventEnvelope,
        reply: Reply<bool>,
    },
    RaiseFloor {
        session: String,
        fence: u64,
        reply: Reply<u64>,
    },
    Floor {
        session: String,
        reply: Reply<Option<u64>>,
    },
    SetAsideAfter {
        session: String,
        seq: u64,
        reply: Reply<u64>,
    },
    PutBlob {
        session: String,
        bytes: Vec<u8>,
        /// The name a peer sent it under, checked against the bytes.
        named: Option<[u8; 32]>,
        reply: Reply<[u8; 32]>,
    },
    GetBlob {
        session: String,
        hash: [u8; 32],
        reply: Reply<Option<Vec<u8>>>,
    },
    HasBlob {
        session: String,
        hash: [u8; 32],
        reply: Reply<bool>,
    },
    /// FR-90 P2f-2a — a pack kept in place of a checkpoint's whole pack.
    PutSubstitute {
        session: String,
        sub: Substitute,
        reply: Reply<()>,
    },
    Substitute {
        session: String,
        commit: String,
        reply: Reply<Option<Substitute>>,
    },
    /// FR-90 P2f-2c — the whole packs kept only as substitutes.
    StandIns {
        session: String,
        limit: usize,
        reply: Reply<Vec<String>>,
    },
    /// FR-90 P2f-2c — where a session is worked on here.
    PutWorkplace {
        session: String,
        workplace: WorkplaceRecord,
        reply: Reply<()>,
    },
    Workplace {
        session: String,
        reply: Reply<Option<WorkplaceRecord>>,
    },
    Purge {
        session: String,
        reply: Reply<u64>,
    },
    PurgeCopy {
        session: String,
        reply: Reply<u64>,
    },
    IsPurged {
        session: String,
        reply: Reply<bool>,
    },
    Holds {
        session: String,
        reply: Reply<bool>,
    },
    PurgeDebt {
        session: String,
        reply: Reply<Option<WorkplaceRecord>>,
    },
    ClearPurgeDebt {
        session: String,
        reply: Reply<()>,
    },
    /// FR-90 P2g-3d — the device's own clock.
    PutRetain {
        session: String,
        days: u32,
        ended_ms: Option<i64>,
        reply: Reply<()>,
    },
    Retains {
        reply: Reply<Vec<RetainWord>>,
    },
    DropRetain {
        session: String,
        reply: Reply<()>,
    },
    Contact {
        reply: Reply<Option<i64>>,
    },
    SetContact {
        at_ms: i64,
        reply: Reply<()>,
    },
    HeldSessions {
        reply: Reply<Vec<String>>,
    },
    NoteCopyPurge {
        session: String,
        at_ms: i64,
        reply: Reply<()>,
    },
    TakeCopyPurgeReports {
        limit: usize,
        max: u32,
        reply: Reply<Vec<(String, i64)>>,
    },
    HasCopyPurgeReports {
        reply: Reply<bool>,
    },
    Search {
        query: String,
        sessions: Vec<String>,
        limit: usize,
        reply: Reply<Vec<SearchHit>>,
    },
    /// P2c-3 — hold a session as a member, at a fence; P2e-5b — and keep
    /// where each fence a promotion superseded ended.
    Join {
        session: String,
        role: &'static str,
        fence: u64,
        ends: Vec<FenceEnd>,
        reply: Reply<u64>,
    },
    /// P2c-3 — every session held as a member.
    Memberships {
        reply: Reply<Vec<Membership>>,
    },
    /// P2c-3 — a session's tip, whole: `seq`, hash and fence.
    TipOf {
        session: String,
        reply: Reply<Option<ChainTip>>,
    },
    /// P2c-3 — the store's size, for the quota.
    SizeBytes {
        reply: Reply<u64>,
    },
    /// P2d — a member's stream hello: where its copy of a session ends.
    HelloOf {
        session: String,
        fence: u64,
        reply: Reply<meshharbor_hive_node::stream::MemberMsg>,
    },
    /// P2d — the source's answer to a member's hello, read against its
    /// chain in one go on this thread.
    AnswerHello {
        hello: meshharbor_hive_node::stream::MemberMsg,
        /// P2d-3b — the session is not over on this device.
        live: bool,
        reply: Reply<meshharbor_hive_node::stream::SourceMsg>,
    },
}

/// FR-90 P2a — why a member command did not do what it asked.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, thiserror::Error)]
pub(crate) enum WriterError {
    /// The store's own word: `purged`, a stale fence, a gap, a broken link, a
    /// blob that does not hash to its name, or SQLite's own error.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The writer is gone, or went before it answered.
    #[error("the replica store is closed")]
    Closed,
}

/// The writer's address. Cheap to clone; the thread ends when every handle
/// is gone.
#[derive(Clone)]
pub(crate) struct StoreHandle {
    tx: mpsc::Sender<Cmd>,
    feed: broadcast::Sender<Arc<EventEnvelope>>,
}

impl StoreHandle {
    /// Open the store at `path` (`None` = in memory) and start its writer.
    pub(crate) fn spawn(path: Option<&Path>) -> Result<Self, String> {
        let store = match path {
            Some(p) => Store::open(p),
            None => Store::open_in_memory(),
        }
        .map_err(|e| format!("opening the replica store: {e}"))?;
        let (tx, rx) = mpsc::channel();
        let (feed, _) = broadcast::channel(FEED_CAPACITY);
        let publish = feed.clone();
        std::thread::Builder::new()
            .name("hive-store".into())
            .spawn(move || writer(store, rx, publish))
            .map_err(|e| format!("starting the replica store writer: {e}"))?;
        Ok(Self { tx, feed })
    }

    /// Append `event` to `session`'s chain under `fence`. Never blocks: the
    /// writer orders and applies it.
    pub(crate) fn append(&self, session: &str, fence: u64, event: TranscriptEvent) {
        let _ = self.tx.send(Cmd::Append {
            session: session.to_string(),
            fence,
            event,
        });
    }

    /// Events of `session` after `after`, oldest first, at most `limit`.
    pub(crate) async fn page(
        &self,
        session: &str,
        after: u64,
        limit: usize,
    ) -> Result<Vec<EventEnvelope>, String> {
        self.page_within(session, after, limit, usize::MAX).await
    }

    /// FR-90 P2d-3 — [`Self::page`], cut before its events' JSON passes
    /// `max_bytes`, and never empty while an event follows `after`
    /// (`Store::page_within`): one replica stream frame.
    pub(crate) async fn page_within(
        &self,
        session: &str,
        after: u64,
        limit: usize,
        max_bytes: usize,
    ) -> Result<Vec<EventEnvelope>, String> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Cmd::Page {
                session: session.to_string(),
                after,
                limit,
                max_bytes,
                reply,
            })
            .map_err(|_| "the replica store is closed".to_string())?;
        rx.await
            .map_err(|_| "the replica store did not answer".to_string())?
    }

    /// FR-90 P2b-3b — `session`'s newest event of `kind`, if it has one.
    pub(crate) async fn last_of_kind(
        &self,
        session: &str,
        kind: &'static str,
    ) -> Result<Option<EventEnvelope>, String> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Cmd::LastOfKind {
                session: session.to_string(),
                kind,
                reply,
            })
            .map_err(|_| "the replica store is closed".to_string())?;
        rx.await
            .map_err(|_| "the replica store did not answer".to_string())?
    }

    /// FR-90 P2e-5 — every event of `session` of `kind`, oldest first; more
    /// than `limit` is refused whole.
    pub(crate) async fn of_kind(
        &self,
        session: &str,
        kind: &'static str,
        limit: usize,
    ) -> Result<Vec<EventEnvelope>, String> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Cmd::OfKind {
                session: session.to_string(),
                kind,
                limit,
                reply,
            })
            .map_err(|_| "the replica store is closed".to_string())?;
        rx.await
            .map_err(|_| "the replica store did not answer".to_string())?
    }

    /// The newest `seq` this store holds for `session`; `None` = nothing.
    pub(crate) async fn tip(&self, session: &str) -> Option<u64> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Cmd::Tip {
                session: session.to_string(),
                reply,
            })
            .ok()?;
        rx.await.ok().flatten()
    }

    /// Every event appended from now on, of every session — a subscriber
    /// filters for its own. Subscribe BEFORE reading the store, so an event
    /// that lands in between is in one or the other.
    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Arc<EventEnvelope>> {
        self.feed.subscribe()
    }

    /// Everything recorded for `session`, in order — tests only.
    #[cfg(all(test, unix))]
    pub(crate) fn events(&self, session: &str) -> Vec<TranscriptEvent> {
        let (reply, rx) = mpsc::channel();
        let _ = self.tx.send(Cmd::Events {
            session: session.to_string(),
            reply,
        });
        rx.recv().unwrap_or_default()
    }
}

/// FR-90 P2a — the member's store, on the one writer. Nothing outside tests
/// calls these yet; the join (P2c), the stream (P2d), the purge (P2g) and an
/// archive replica's search (P2i) will.
#[cfg_attr(not(test), allow(dead_code))]
impl StoreHandle {
    async fn ask<T>(&self, cmd: impl FnOnce(Reply<T>) -> Member) -> Result<T, WriterError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Cmd::Member(cmd(reply)))
            .map_err(|_| WriterError::Closed)?;
        Ok(rx.await.map_err(|_| WriterError::Closed)??)
    }

    /// Apply an envelope another member sent, exactly as it came, through
    /// the chain's check and the floor (`Store::apply`). Answered once it is
    /// committed, so this is what the stream acks. That survives a daemon
    /// crash, not a power cut (`synchronous = NORMAL`): after a restart, the
    /// tip the member reports is what counts. Published to the live feed like
    /// an append once it lands, so a viewer follows a session from a replica;
    /// a refused envelope is published nowhere.
    ///
    /// ⚠️ The envelope names its own session. The caller checks it is the one
    /// its stream carries before it gets here.
    pub(crate) async fn apply(&self, env: EventEnvelope) -> Result<ChainTip, WriterError> {
        self.ask(|reply| Member::Apply { env, reply }).await
    }

    /// FR-90 P2d-3 — [`Self::apply`], or nothing for an event this store
    /// holds already, the same `seq` hashed the same, which another stream
    /// of the session applied first (`Store::apply_unless_held`). Published
    /// to the live feed only when it was applied here. `true` when it was.
    pub(crate) async fn apply_unless_held(&self, env: EventEnvelope) -> Result<bool, WriterError> {
        self.ask(|reply| Member::ApplyUnlessHeld { env, reply })
            .await
    }

    /// Raise `session`'s fence floor to `fence`; the floor after it is
    /// returned (it only rises).
    pub(crate) async fn raise_floor(&self, session: &str, fence: u64) -> Result<u64, WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::RaiseFloor {
            session,
            fence,
            reply,
        })
        .await
    }

    /// `session`'s fence floor, if one was raised.
    pub(crate) async fn floor(&self, session: &str) -> Result<Option<u64>, WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::Floor { session, reply }).await
    }

    /// Set aside the older fence's tail after `seq`; how many events moved.
    pub(crate) async fn set_aside_after(
        &self,
        session: &str,
        seq: u64,
    ) -> Result<u64, WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::SetAsideAfter {
            session,
            seq,
            reply,
        })
        .await
    }

    /// Keep `bytes` as a blob of `session`; its name (BLAKE3) is returned.
    pub(crate) async fn put_blob(
        &self,
        session: &str,
        bytes: Vec<u8>,
    ) -> Result<[u8; 32], WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::PutBlob {
            session,
            bytes,
            named: None,
            reply,
        })
        .await
    }

    /// Keep bytes a peer sent as the blob `hash`: refused unless they hash
    /// to it.
    pub(crate) async fn put_named_blob(
        &self,
        session: &str,
        hash: [u8; 32],
        bytes: Vec<u8>,
    ) -> Result<(), WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::PutBlob {
            session,
            bytes,
            named: Some(hash),
            reply,
        })
        .await
        .map(|_| ())
    }

    /// The blob `hash`, if `session` holds it.
    pub(crate) async fn get_blob(
        &self,
        session: &str,
        hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::GetBlob {
            session,
            hash,
            reply,
        })
        .await
    }

    /// Whether `session` holds the blob `hash`.
    pub(crate) async fn has_blob(
        &self,
        session: &str,
        hash: [u8; 32],
    ) -> Result<bool, WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::HasBlob {
            session,
            hash,
            reply,
        })
        .await
    }

    /// FR-90 P2f-2a — keep `sub` for `session`, its blobs kept first.
    pub(crate) async fn put_substitute(
        &self,
        session: &str,
        sub: Substitute,
    ) -> Result<(), WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::PutSubstitute {
            session,
            sub,
            reply,
        })
        .await
    }

    /// FR-90 P2f-2a — the substitute kept for `commit` of `session`.
    pub(crate) async fn substitute(
        &self,
        session: &str,
        commit: &str,
    ) -> Result<Option<Substitute>, WriterError> {
        let (session, commit) = (session.to_string(), commit.to_string());
        self.ask(|reply| Member::Substitute {
            session,
            commit,
            reply,
        })
        .await
    }

    /// FR-90 P2f-2c — the commits of `session`'s whole packs kept here only
    /// as substitutes, at most `limit`: what this copy cannot serve by blobs.
    pub(crate) async fn stand_ins(
        &self,
        session: &str,
        limit: usize,
    ) -> Result<Vec<String>, WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::StandIns {
            session,
            limit,
            reply,
        })
        .await
    }

    /// FR-90 P2f-2c — keep where `session` is worked on here.
    pub(crate) async fn put_workplace(
        &self,
        session: &str,
        workplace: WorkplaceRecord,
    ) -> Result<(), WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::PutWorkplace {
            session,
            workplace,
            reply,
        })
        .await
    }

    /// FR-90 P2f-2c — where `session` was last worked on here.
    pub(crate) async fn workplace(
        &self,
        session: &str,
    ) -> Result<Option<WorkplaceRecord>, WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::Workplace { session, reply }).await
    }

    /// Purge `session` and keep its id; how many events were removed.
    pub(crate) async fn purge(&self, session: &str) -> Result<u64, WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::Purge { session, reply }).await
    }

    /// FR-90 P2k-3 — purge this device's copy of `session` as a leaving
    /// member's, keeping nothing of it, its id included; how many events
    /// were removed.
    pub(crate) async fn purge_copy(&self, session: &str) -> Result<u64, WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::PurgeCopy { session, reply }).await
    }

    /// Whether `session` was purged here.
    pub(crate) async fn is_purged(&self, session: &str) -> Result<bool, WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::IsPurged { session, reply }).await
    }

    /// FR-90 P2g-1 — whether this store holds anything of `session`.
    pub(crate) async fn holds(&self, session: &str) -> Result<bool, WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::Holds { session, reply }).await
    }

    /// FR-90 P2g-1 — what the account still holds of a purged `session`.
    pub(crate) async fn purge_debt(
        &self,
        session: &str,
    ) -> Result<Option<WorkplaceRecord>, WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::PurgeDebt { session, reply }).await
    }

    /// FR-90 P2g-1 — the account's part of `session`'s purge is done.
    pub(crate) async fn clear_purge_debt(&self, session: &str) -> Result<(), WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::ClearPurgeDebt { session, reply })
            .await
    }

    /// FR-90 P2g-3d — keep what the server says keeps `session`'s copy.
    pub(crate) async fn put_retain(
        &self,
        session: &str,
        days: u32,
        ended_ms: Option<i64>,
    ) -> Result<(), WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::PutRetain {
            session,
            days,
            ended_ms,
            reply,
        })
        .await
    }

    /// FR-90 P2g-3d — every word kept.
    pub(crate) async fn retains(&self) -> Result<Vec<RetainWord>, WriterError> {
        self.ask(|reply| Member::Retains { reply }).await
    }

    /// FR-90 P2g-3d — forget `session`'s word.
    pub(crate) async fn drop_retain(&self, session: &str) -> Result<(), WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::DropRetain { session, reply })
            .await
    }

    /// FR-90 P2g-3d — when this device was last connected, by its clock.
    pub(crate) async fn contact(&self) -> Result<Option<i64>, WriterError> {
        self.ask(|reply| Member::Contact { reply }).await
    }

    /// FR-90 P2g-3d — the device is connected now.
    pub(crate) async fn set_contact(&self, at_ms: i64) -> Result<(), WriterError> {
        self.ask(|reply| Member::SetContact { at_ms, reply }).await
    }

    /// FR-90 P2g-3d — every session this store holds anything of.
    pub(crate) async fn held_sessions(&self) -> Result<Vec<String>, WriterError> {
        self.ask(|reply| Member::HeldSessions { reply }).await
    }

    /// FR-90 P2g-3d — the device's own clock purged `session`'s copy.
    pub(crate) async fn note_copy_purge(
        &self,
        session: &str,
        at_ms: i64,
    ) -> Result<(), WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::NoteCopyPurge {
            session,
            at_ms,
            reply,
        })
        .await
    }

    /// FR-90 P2g-3d — the copies its clock purged that a manifest names now.
    pub(crate) async fn take_copy_purge_reports(
        &self,
        limit: usize,
        max: u32,
    ) -> Result<Vec<(String, i64)>, WriterError> {
        self.ask(|reply| Member::TakeCopyPurgeReports { limit, max, reply })
            .await
    }

    /// FR-90 P2g-3d — whether such a copy is still to be named.
    pub(crate) async fn has_copy_purge_reports(&self) -> Result<bool, WriterError> {
        self.ask(|reply| Member::HasCopyPurgeReports { reply })
            .await
    }

    /// Full-text search over the sessions named, best first. An empty list
    /// finds nothing, never everything: a viewer's grant names what it may
    /// read, and only those are searched.
    pub(crate) async fn search(
        &self,
        query: &str,
        sessions: Vec<String>,
        limit: usize,
    ) -> Result<Vec<SearchHit>, WriterError> {
        let query = query.to_string();
        self.ask(|reply| Member::Search {
            query,
            sessions,
            limit,
            reply,
        })
        .await
    }

    /// FR-90 P2c-3 — hold `session` as a member placed in `role`, at
    /// `fence`: the floor rises to it in the same transaction
    /// (`Store::join`). Refused for a purged session, and below the floor.
    ///
    /// P2e-5b — with `ends`, where each fence a promotion superseded ended,
    /// kept in that same transaction: below the floor, such a fence's events
    /// are still taken up to there. A join names the ones the server holds.
    pub(crate) async fn join_with_ends(
        &self,
        session: &str,
        role: &'static str,
        fence: u64,
        ends: Vec<FenceEnd>,
    ) -> Result<u64, WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::Join {
            session,
            role,
            fence,
            ends,
            reply,
        })
        .await
    }

    /// A join that names no fence's end: a session no promotion has moved.
    /// ⚠️ Tests only — a device's join takes the server's ends, every time
    /// ([`Self::join_with_ends`]).
    #[cfg(test)]
    pub(crate) async fn join(
        &self,
        session: &str,
        role: &'static str,
        fence: u64,
    ) -> Result<u64, WriterError> {
        self.join_with_ends(session, role, fence, Vec::new()).await
    }

    /// FR-90 P2c-3 — every session this device holds as a member.
    pub(crate) async fn memberships(&self) -> Result<Vec<Membership>, WriterError> {
        self.ask(|reply| Member::Memberships { reply }).await
    }

    /// FR-90 P2c-3 — `session`'s tip, whole: what a tip report carries.
    pub(crate) async fn chain_tip(&self, session: &str) -> Result<Option<ChainTip>, WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::TipOf { session, reply }).await
    }

    /// FR-90 P2c-3 — the store's size, as `hive_store_quota_mib` reads it.
    pub(crate) async fn size_bytes(&self) -> Result<u64, WriterError> {
        self.ask(|reply| Member::SizeBytes { reply }).await
    }

    /// FR-90 P2d — the member's stream hello for `session`, at `fence`.
    pub(crate) async fn member_hello(
        &self,
        session: &str,
        fence: u64,
    ) -> Result<meshharbor_hive_node::stream::MemberMsg, WriterError> {
        let session = session.to_string();
        self.ask(|reply| Member::HelloOf {
            session,
            fence,
            reply,
        })
        .await
    }

    /// FR-90 P2d — the source's answer to a member's stream hello; `live`,
    /// the device's word that the session is not over here (P2d-3b), goes
    /// with it.
    pub(crate) async fn answer_hello(
        &self,
        hello: meshharbor_hive_node::stream::MemberMsg,
        live: bool,
    ) -> Result<meshharbor_hive_node::stream::SourceMsg, WriterError> {
        self.ask(|reply| Member::AnswerHello { hello, live, reply })
            .await
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

fn writer(
    mut store: Store,
    rx: mpsc::Receiver<Cmd>,
    publish: broadcast::Sender<Arc<EventEnvelope>>,
) {
    while let Ok(cmd) = rx.recv() {
        match cmd {
            Cmd::Append {
                session,
                fence,
                event,
            } => {
                let tip = match store.tip(&session) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(%session, %e, "hive: replica store tip unreadable — event dropped");
                        continue;
                    }
                };
                let env = EventEnvelope::next(&session, tip, fence, now_ms(), &event);
                match store.append(&env) {
                    // No subscriber is not an error: nobody is watching.
                    Ok(_) => {
                        let _ = publish.send(Arc::new(env));
                    }
                    Err(e) => warn!(%session, %e, "hive: replica store refused an event"),
                }
            }
            Cmd::Page {
                session,
                after,
                limit,
                max_bytes,
                reply,
            } => {
                let page = store
                    .page_within(&session, after, limit, max_bytes)
                    .map_err(|e| format!("reading the replica store: {e}"));
                let _ = reply.send(page);
            }
            Cmd::LastOfKind {
                session,
                kind,
                reply,
            } => {
                let last = store
                    .last_of_kind(&session, kind)
                    .map_err(|e| format!("reading the replica store: {e}"));
                let _ = reply.send(last);
            }
            Cmd::OfKind {
                session,
                kind,
                limit,
                reply,
            } => {
                let all = store
                    .of_kind(&session, kind, limit)
                    .map_err(|e| format!("reading the replica store: {e}"));
                let _ = reply.send(all);
            }
            Cmd::Tip { session, reply } => {
                let _ = reply.send(store.tip(&session).ok().flatten().map(|t| t.seq));
            }
            Cmd::Member(cmd) => member(&mut store, &publish, cmd),
            #[cfg(all(test, unix))]
            Cmd::Events { session, reply } => {
                let events = store
                    .page(&session, 0, 100_000)
                    .map(|envs| envs.iter().filter_map(EventEnvelope::event).collect())
                    .unwrap_or_default();
                let _ = reply.send(events);
            }
        }
    }
}

/// FR-90 P2a — one member command. A caller that stopped waiting is no
/// error: the store did what it was asked all the same.
fn member(store: &mut Store, publish: &broadcast::Sender<Arc<EventEnvelope>>, cmd: Member) {
    match cmd {
        Member::Apply { env, reply } => {
            let landed = store.apply(&env);
            // Published before the answer, so whoever the answer reaches can
            // already find it on the feed.
            if landed.is_ok() {
                let _ = publish.send(Arc::new(env));
            }
            let _ = reply.send(landed);
        }
        Member::ApplyUnlessHeld { env, reply } => {
            let landed = store.apply_unless_held(&env);
            // Held already: on the feed since it first landed.
            if matches!(landed, Ok(true)) {
                let _ = publish.send(Arc::new(env));
            }
            let _ = reply.send(landed);
        }
        Member::RaiseFloor {
            session,
            fence,
            reply,
        } => {
            let _ = reply.send(store.raise_floor(&session, fence));
        }
        Member::Floor { session, reply } => {
            let _ = reply.send(store.floor(&session));
        }
        Member::SetAsideAfter {
            session,
            seq,
            reply,
        } => {
            let _ = reply.send(store.set_aside_after(&session, seq));
        }
        Member::PutBlob {
            session,
            bytes,
            named,
            reply,
        } => {
            let kept = match named {
                Some(hash) => store.put_named_blob(&session, &hash, &bytes).map(|()| hash),
                None => store.put_blob(&session, &bytes),
            };
            let _ = reply.send(kept);
        }
        Member::GetBlob {
            session,
            hash,
            reply,
        } => {
            let _ = reply.send(store.get_blob(&session, &hash));
        }
        Member::HasBlob {
            session,
            hash,
            reply,
        } => {
            let _ = reply.send(store.has_blob(&session, &hash));
        }
        Member::PutSubstitute {
            session,
            sub,
            reply,
        } => {
            let _ = reply.send(store.put_substitute(&session, &sub));
        }
        Member::Substitute {
            session,
            commit,
            reply,
        } => {
            let _ = reply.send(store.substitute(&session, &commit));
        }
        Member::StandIns {
            session,
            limit,
            reply,
        } => {
            let _ = reply.send(store.stand_ins(&session, limit));
        }
        Member::PutWorkplace {
            session,
            workplace,
            reply,
        } => {
            let _ = reply.send(store.put_workplace(&session, &workplace));
        }
        Member::Workplace { session, reply } => {
            let _ = reply.send(store.workplace(&session));
        }
        Member::Purge { session, reply } => {
            let _ = reply.send(store.purge(&session));
        }
        Member::PurgeCopy { session, reply } => {
            let _ = reply.send(store.purge_copy(&session));
        }
        Member::IsPurged { session, reply } => {
            let _ = reply.send(store.is_purged(&session));
        }
        Member::Holds { session, reply } => {
            let _ = reply.send(store.holds(&session));
        }
        Member::PurgeDebt { session, reply } => {
            let _ = reply.send(store.purge_debt(&session));
        }
        Member::ClearPurgeDebt { session, reply } => {
            let _ = reply.send(store.clear_purge_debt(&session));
        }
        Member::PutRetain {
            session,
            days,
            ended_ms,
            reply,
        } => {
            let _ = reply.send(store.put_retain(&session, days, ended_ms));
        }
        Member::Retains { reply } => {
            let _ = reply.send(store.retains());
        }
        Member::DropRetain { session, reply } => {
            let _ = reply.send(store.drop_retain(&session));
        }
        Member::Contact { reply } => {
            let _ = reply.send(store.contact());
        }
        Member::SetContact { at_ms, reply } => {
            let _ = reply.send(store.set_contact(at_ms));
        }
        Member::HeldSessions { reply } => {
            let _ = reply.send(store.held_sessions());
        }
        Member::NoteCopyPurge {
            session,
            at_ms,
            reply,
        } => {
            let _ = reply.send(store.note_copy_purge(&session, at_ms));
        }
        Member::TakeCopyPurgeReports { limit, max, reply } => {
            let _ = reply.send(store.take_copy_purge_reports(limit, max));
        }
        Member::HasCopyPurgeReports { reply } => {
            let _ = reply.send(store.has_copy_purge_reports());
        }
        Member::Search {
            query,
            sessions,
            limit,
            reply,
        } => {
            let _ = reply.send(store.search(&query, Some(&sessions), limit));
        }
        Member::Join {
            session,
            role,
            fence,
            ends,
            reply,
        } => {
            let _ = reply.send(store.join(&session, role, fence, &ends));
        }
        Member::Memberships { reply } => {
            let _ = reply.send(store.memberships());
        }
        Member::TipOf { session, reply } => {
            let _ = reply.send(store.tip(&session));
        }
        Member::SizeBytes { reply } => {
            let _ = reply.send(store.size_bytes());
        }
        Member::HelloOf {
            session,
            fence,
            reply,
        } => {
            let _ = reply.send(meshharbor_hive_node::stream::member_hello(
                store, &session, fence,
            ));
        }
        Member::AnswerHello { hello, live, reply } => {
            let _ = reply.send(meshharbor_hive_node::stream::answer_hello(store, &hello, live));
        }
    }
}

/// FR-90 P2a — the member's commands on a real writer thread. Unlike the
/// supervisor's tests these hold nothing Unix-shaped, so they run wherever
/// `hive` builds: Linux, macOS and Windows CI (`hive::`).
#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_hive_node::ChainError;
    use meshharbor_hive_node::store::blob_hash;

    fn note(text: &str) -> TranscriptEvent {
        TranscriptEvent::Note { text: text.into() }
    }

    /// The primary's envelopes for `texts`, as a member is sent them.
    fn sent(
        session: &str,
        mut tip: Option<ChainTip>,
        fence: u64,
        texts: &[&str],
    ) -> Vec<EventEnvelope> {
        let mut out = Vec::new();
        for (i, t) in texts.iter().enumerate() {
            let env = EventEnvelope::next(session, tip, fence, 7 + i as i64, &note(t));
            tip = Some(env.tip());
            out.push(env);
        }
        out
    }

    fn is_purged(r: Result<(), WriterError>) -> bool {
        matches!(r, Err(WriterError::Store(StoreError::Purged { .. })))
    }

    #[tokio::test]
    async fn an_applied_envelope_lands_as_sent_and_reaches_the_live_feed() {
        let store = StoreHandle::spawn(None).unwrap();
        let mut feed = store.subscribe();
        let envs = sent("s1", None, 1, &["one", "two"]);
        for env in &envs {
            let tip = store.apply(env.clone()).await.unwrap();
            assert_eq!(tip, env.tip());
            // On the feed by the time the answer came: exactly what was sent.
            let got = feed.try_recv().expect("published once it landed");
            assert_eq!(*got, *env);
        }
        assert_eq!(store.page("s1", 0, 10).await.unwrap(), envs);
        assert_eq!(store.tip("s1").await, Some(2));
    }

    #[tokio::test]
    async fn a_refused_apply_is_answered_and_published_nowhere() {
        let store = StoreHandle::spawn(None).unwrap();
        let mut feed = store.subscribe();
        let envs = sent("s1", None, 1, &["one", "two"]);
        // The second without the first: a gap.
        let err = store.apply(envs[1].clone()).await.unwrap_err();
        assert!(
            matches!(
                err,
                WriterError::Store(StoreError::Chain(ChainError::Gap {
                    expected: 1,
                    got: 2
                }))
            ),
            "{err}"
        );
        assert!(matches!(
            feed.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
        assert_eq!(store.tip("s1").await, None);
    }

    #[tokio::test]
    async fn an_answered_apply_is_committed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hive.db");
        let store = StoreHandle::spawn(Some(&path)).unwrap();
        let envs = sent("s1", None, 1, &["on disk"]);
        store.apply(envs[0].clone()).await.unwrap();
        // Another connection to the file sees it once the answer came.
        let other = Store::open(&path).unwrap();
        assert_eq!(other.tip("s1").unwrap(), Some(envs[0].tip()));
    }

    #[tokio::test]
    async fn the_floor_refuses_the_devices_own_append_and_an_applied_event() {
        let store = StoreHandle::spawn(None).unwrap();
        let envs = sent("s1", None, 1, &["one"]);
        store.apply(envs[0].clone()).await.unwrap();
        assert_eq!(store.raise_floor("s1", 2).await.unwrap(), 2);
        assert_eq!(
            store.raise_floor("s1", 1).await.unwrap(),
            2,
            "it only rises"
        );
        assert_eq!(store.floor("s1").await.unwrap(), Some(2));

        // This device's own event at the old fence: the writer drops it.
        store.append("s1", 1, note("own, late"));
        // One a member is sent at the old fence: refused, and said so.
        let late = sent("s1", Some(envs[0].tip()), 1, &["sent, late"]).remove(0);
        assert!(matches!(
            store.apply(late).await,
            Err(WriterError::Store(StoreError::Chain(
                ChainError::StaleFence { current: 2, got: 1 }
            )))
        ));
        // The writer answers in order, so the append was handled by now.
        assert_eq!(store.tip("s1").await, Some(1));
        // At the floor's fence, both land.
        store.append("s1", 2, note("own, at the floor"));
        assert_eq!(store.tip("s1").await, Some(2));
    }

    #[tokio::test]
    async fn the_writer_sets_aside_an_older_fences_tail_and_never_the_floors() {
        let store = StoreHandle::spawn(None).unwrap();
        let envs = sent("s1", None, 1, &["one", "two", "three"]);
        for env in &envs {
            store.apply(env.clone()).await.unwrap();
        }
        store.raise_floor("s1", 2).await.unwrap();
        assert_eq!(store.set_aside_after("s1", 1).await.unwrap(), 2);
        assert_eq!(store.tip("s1").await, Some(1));
        let again = sent("s1", Some(envs[0].tip()), 2, &["two again"]).remove(0);
        store.apply(again).await.unwrap();
        // That tail is the floor's own fence now.
        assert!(matches!(
            store.set_aside_after("s1", 1).await,
            Err(WriterError::Store(StoreError::NotOlderThanFloor { .. }))
        ));
        assert_eq!(store.tip("s1").await, Some(2));
    }

    #[tokio::test]
    async fn the_writer_keeps_blobs_by_name_and_refuses_a_wrong_one() {
        let store = StoreHandle::spawn(None).unwrap();
        let hash = store.put_blob("s1", b"chunk".to_vec()).await.unwrap();
        assert_eq!(hash, blob_hash(b"chunk"));
        assert!(store.has_blob("s1", hash).await.unwrap());
        assert_eq!(
            store.get_blob("s1", hash).await.unwrap(),
            Some(b"chunk".to_vec())
        );
        assert_eq!(store.get_blob("s2", hash).await.unwrap(), None, "not s2's");
        let wrong = blob_hash(b"something else");
        assert!(matches!(
            store.put_named_blob("s1", wrong, b"chunk".to_vec()).await,
            Err(WriterError::Store(StoreError::BlobMismatch { .. }))
        ));
        assert!(!store.has_blob("s1", wrong).await.unwrap());
        store
            .put_named_blob("s1", hash, b"chunk".to_vec())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_writer_purges_keeps_the_id_and_refuses_what_would_bring_it_back() {
        let store = StoreHandle::spawn(None).unwrap();
        let envs = sent("s1", None, 1, &["purgeme", "two"]);
        store.apply(envs[0].clone()).await.unwrap();
        let hash = store.put_blob("s1", b"chunk".to_vec()).await.unwrap();
        assert!(!store.is_purged("s1").await.unwrap());
        assert_eq!(store.purge("s1").await.unwrap(), 1);
        assert!(store.is_purged("s1").await.unwrap());

        assert!(is_purged(store.apply(envs[1].clone()).await.map(|_| ())));
        assert!(is_purged(store.apply(envs[0].clone()).await.map(|_| ())));
        assert!(is_purged(store.raise_floor("s1", 2).await.map(|_| ())));
        assert!(is_purged(store.set_aside_after("s1", 0).await.map(|_| ())));
        assert!(is_purged(
            store.put_blob("s1", b"chunk".to_vec()).await.map(|_| ())
        ));
        store.append("s1", 1, note("own"));

        assert_eq!(store.tip("s1").await, None, "nothing came back");
        assert!(store.page("s1", 0, 10).await.unwrap().is_empty());
        assert!(!store.has_blob("s1", hash).await.unwrap());
        assert!(
            store
                .search("purgeme", vec!["s1".into()], 10)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_writer_searches_only_the_sessions_named() {
        let store = StoreHandle::spawn(None).unwrap();
        for s in ["s1", "s2"] {
            let env = sent(s, None, 1, &["kubelet restarted"]).remove(0);
            store.apply(env).await.unwrap();
        }
        let hits = store
            .search("kubelet", vec!["s2".into()], 10)
            .await
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].session, "s2");
        assert!(
            store
                .search("kubelet", Vec::new(), 10)
                .await
                .unwrap()
                .is_empty(),
            "an empty list is nothing, never everything"
        );
    }

    /// FR-90 P2c-3 — a join on the writer: the membership kept, the floor
    /// raised, a stale or purged join refused in the store's own word; the
    /// tip whole, and the size the quota reads.
    #[tokio::test]
    async fn the_writer_joins_and_answers_in_the_stores_word() {
        let store = StoreHandle::spawn(None).unwrap();
        assert_eq!(store.join("s1", "owner", 2).await.unwrap(), 2);
        assert_eq!(store.floor("s1").await.unwrap(), Some(2));
        let held = store.memberships().await.unwrap();
        assert_eq!(
            held.iter()
                .map(|m| (m.session.as_str(), m.role.as_str(), m.fence))
                .collect::<Vec<_>>(),
            [("s1", "owner", 2)]
        );
        assert!(matches!(
            store.join("s1", "owner", 1).await,
            Err(WriterError::Store(StoreError::StaleJoin { .. }))
        ));
        assert_eq!(
            store.chain_tip("s1").await.unwrap(),
            None,
            "nothing held yet"
        );
        let env = sent("s1", None, 2, &["one"]).remove(0);
        let tip = store.apply(env).await.unwrap();
        assert_eq!(store.chain_tip("s1").await.unwrap(), Some(tip));
        store.purge("s1").await.unwrap();
        assert!(store.memberships().await.unwrap().is_empty());
        assert!(matches!(
            store.join("s1", "owner", 3).await,
            Err(WriterError::Store(StoreError::Purged { .. }))
        ));
        assert!(store.size_bytes().await.unwrap() > 0);
    }
}
