// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! The replica store every member of a session's replicaset keeps.
//!
//! One SQLite database per device holds the events of every session the device
//! carries — the same choice Hermes Agent makes with its single `state.db` —
//! plus an FTS5 index over their text, which is what full-text session search
//! runs on (design §10.4). The daemon owns the file; no local user can read it.
//!
//! Every append is checked against the session's chain tip
//! ([`crate::chain::check_next`]) inside one transaction with its index row, so
//! the store can never hold a gap, a broken link or a stale writer's event, and
//! the index never disagrees with the events.
//!
//! # What a member keeps (FR-90 P2a)
//!
//! A member that does not run a session keeps the same events, applied as the
//! primary sent them ([`Store::apply`]), and four things beside them, each in a
//! table of its own:
//!
//! - `floors`: each session's fence floor ([`Store::raise_floor`]), which
//!   refuses a stale writer before the new primary's first event lands;
//! - `divergent`: an older fence's tail that a promotion cut off
//!   ([`Store::set_aside_after`]), the one rewrite the store allows;
//! - `blobs` and `blob_refs`: content-addressed bytes (a history's chunks, a
//!   checkpoint's pack), each kept for the sessions that hold it
//!   ([`Store::put_blob`]);
//! - `purged`: the ids of sessions purged here, so none is ever taken back
//!   ([`Store::purge`]).
//!
//! ⚠️ They are NEW tables, and `user_version` stays 1. A daemon from before
//! P2a, which the updater's crash-loop rollback can put back on a device at
//! any time, opens the file, serves the events it holds and never looks at
//! them. A new column on `events` would cost it every transcript.
//!
//! FR-90 P2g-3d adds the device's own clock, in tables of its own as well:
//! what keeps each copy, as the server last said it ([`Store::put_retain`]);
//! when the device was last connected ([`Store::set_contact`]); and the
//! copies the clock purged, which its next manifests name
//! ([`Store::note_copy_purge`]).

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Transaction, params, params_from_iter};

use crate::chain::{ChainError, ChainTip, EventEnvelope, FenceEnd, check_next_with_ends};
use crate::checkpoint::Chunk;
use crate::event::TranscriptEvent;

/// The schema this build writes. A newer file is refused rather than written
/// with an older idea of its shape.
///
/// ⚠️ Still 1 with P2a's tables: every daemon before P2a refuses a file whose
/// version is higher, so raising it would strand a rolled-back daemon's
/// transcripts. New state goes in new tables instead ([`P2A_TABLES`]).
const SCHEMA_VERSION: i64 = 1;

/// P0a's tables: all a daemon from before P2a knows. ⚠️ Never change these
/// statements. A rolled-back daemon runs its own copy of them on this file
/// (the test `a_daemon_from_before_p2a_reads_what_p2a_wrote`).
const P0A_TABLES: &str = "CREATE TABLE IF NOT EXISTS events (
                 session    TEXT    NOT NULL,
                 seq        INTEGER NOT NULL,
                 fence      INTEGER NOT NULL,
                 ts_ms      INTEGER NOT NULL,
                 prev_hash  BLOB    NOT NULL,
                 hash       BLOB    NOT NULL,
                 kind       TEXT,
                 event_json TEXT    NOT NULL,
                 PRIMARY KEY (session, seq)
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS tips (
                 session TEXT PRIMARY KEY,
                 seq     INTEGER NOT NULL,
                 hash    BLOB    NOT NULL,
                 fence   INTEGER NOT NULL
             ) WITHOUT ROWID;
             CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                 text,
                 session UNINDEXED,
                 seq UNINDEXED,
                 tokenize = 'unicode61 remove_diacritics 2'
             );";

/// FR-90 P2a: what a member keeps beside its events. Each table is new and
/// made only when missing, so the file stays one a daemon before P2a opens.
const P2A_TABLES: &str = "CREATE TABLE IF NOT EXISTS floors (
                 session TEXT    PRIMARY KEY,
                 fence   INTEGER NOT NULL
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS divergent (
                 session      TEXT    NOT NULL,
                 seq          INTEGER NOT NULL,
                 fence        INTEGER NOT NULL,
                 ts_ms        INTEGER NOT NULL,
                 prev_hash    BLOB    NOT NULL,
                 hash         BLOB    NOT NULL,
                 kind         TEXT,
                 event_json   TEXT    NOT NULL,
                 set_aside_ms INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS divergent_session ON divergent (session, seq);
             CREATE TABLE IF NOT EXISTS blobs (
                 hash BLOB NOT NULL PRIMARY KEY,
                 data BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS blob_refs (
                 session TEXT NOT NULL,
                 hash    BLOB NOT NULL,
                 PRIMARY KEY (session, hash)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS blob_refs_hash ON blob_refs (hash);
             CREATE TABLE IF NOT EXISTS purged (
                 session   TEXT    PRIMARY KEY,
                 purged_ms INTEGER NOT NULL
             ) WITHOUT ROWID;";

/// FR-90 P2c-3: the sessions this device holds a copy of as a member, as the
/// server joined it: the role it was placed in and the join's fence. New and
/// made only when missing, like P2a's tables, so `user_version` stays 1.
const P2C_TABLES: &str = "CREATE TABLE IF NOT EXISTS memberships (
                 session   TEXT    PRIMARY KEY,
                 role      TEXT    NOT NULL,
                 fence     INTEGER NOT NULL,
                 joined_ms INTEGER NOT NULL
             ) WITHOUT ROWID;";

/// FR-90 P2e-5b: where each fence a promotion superseded ended, as the
/// server's joins carry it. Below the floor, that fence's events are still
/// taken up to there. New and made only when missing, like P2a's tables, so
/// `user_version` stays 1 and a daemon before P2e-5b opens the file.
const P2E_TABLES: &str = "CREATE TABLE IF NOT EXISTS fence_ends (
                 session TEXT    NOT NULL,
                 fence   INTEGER NOT NULL,
                 seq     INTEGER NOT NULL,
                 hash    BLOB    NOT NULL,
                 PRIMARY KEY (session, fence)
             ) WITHOUT ROWID;";

/// FR-90 P2f-2a: packs that stand in for a checkpoint's own whole pack. A
/// substitute brings the same commit's objects into a repository that holds
/// every commit in `against` (none: anywhere). New and made only when
/// missing, like P2a's tables, so `user_version` stays 1.
const P2F_TABLES: &str = "CREATE TABLE IF NOT EXISTS substitutes (
                 session   TEXT    NOT NULL,
                 commit_id TEXT    NOT NULL,
                 against   TEXT    NOT NULL,
                 chunks    TEXT    NOT NULL,
                 kept_ms   INTEGER NOT NULL,
                 PRIMARY KEY (session, commit_id)
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS workplaces (
                 session   TEXT    PRIMARY KEY,
                 account   TEXT    NOT NULL,
                 folder    TEXT    NOT NULL,
                 state_dir TEXT    NOT NULL,
                 kept_ms   INTEGER NOT NULL
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS purge_debts (
                 session   TEXT    PRIMARY KEY,
                 account   TEXT    NOT NULL,
                 folder    TEXT    NOT NULL,
                 state_dir TEXT    NOT NULL,
                 since_ms  INTEGER NOT NULL
             ) WITHOUT ROWID;";

/// FR-90 P2g-3d: the device's own clock. What keeps each copy, as the server
/// last said it (`retains`); when the device was last connected (`contact`,
/// one row); and the copies the clock purged that its next manifests name
/// (`copy_purges`). New and made only when missing, like P2a's tables, so
/// `user_version` stays 1.
const P2G_TABLES: &str = "CREATE TABLE IF NOT EXISTS retains (
                 session  TEXT    PRIMARY KEY,
                 days     INTEGER NOT NULL,
                 ended_ms INTEGER,
                 said_ms  INTEGER NOT NULL
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS contact (
                 id    INTEGER PRIMARY KEY CHECK (id = 1),
                 at_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS copy_purges (
                 session TEXT    PRIMARY KEY,
                 at_ms   INTEGER NOT NULL,
                 reports INTEGER NOT NULL
             ) WITHOUT ROWID;";

/// FR-90 P2g-3d — what keeps this device's copy of a session, as the server
/// last said it (`rc:hive.retain`): the organization's days (`0` keeps it for
/// ever), the session's end once it is over, and when it was said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainWord {
    pub session: String,
    pub days: u32,
    pub ended_ms: Option<i64>,
    pub said_ms: i64,
}

/// FR-90 P2f-2a — a pack kept in place of a checkpoint's own whole pack: the
/// one that brings `commit` into a repository holding every commit of
/// `against`, as `chunks` of blobs this session holds. Git checks it where it
/// is used, as it checks every pack, and the checkpoint's tree is held to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Substitute {
    pub commit: String,
    pub against: Vec<String>,
    pub chunks: Vec<Chunk>,
}

/// FR-90 P2f-2c — where on this device a session it ran is worked on: the
/// account it ran as, its folder and its state directory, as its launch
/// resolved them. What a source packs from for a member once the session
/// does not run here, and is no longer hosted once it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkplaceRecord {
    pub account: String,
    pub folder: String,
    pub state_dir: String,
}

/// FR-90 P2c-3 — one session this device holds a copy of as a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub session: String,
    /// The role it was placed in: `archive` or `owner`; FR-90 P2f-1a,
    /// `teleport` for a copy taken to run the session here.
    pub role: String,
    /// The fence of the newest join.
    pub fence: u64,
    /// When it first joined.
    pub joined_ms: i64,
}

/// At most this many sessions per search filter — a view grant names sessions
/// explicitly, and a filter larger than this is a caller bug.
pub const MAX_SEARCH_SESSIONS: usize = 500;

/// The most one blob holds. A blob is a chunk (of a history, a pack, a file),
/// not a whole of any size: the store's one writer holds it in memory and
/// writes it in one transaction, so a producer chunks anything larger.
pub const MAX_BLOB_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(
        "the store was written by a newer build (schema {found}, this build knows {SCHEMA_VERSION})"
    )]
    NewerSchema { found: i64 },
    #[error("a stored event of session {session} seq {seq} has a malformed hash")]
    CorruptHash { session: String, seq: u64 },
    #[error("a search may name at most {MAX_SEARCH_SESSIONS} sessions, not {0}")]
    TooManySessions(usize),
    /// P2a: the session was purged here, and removal is final.
    #[error("session {session} was purged on this device: removal is final")]
    Purged { session: String },
    /// P2a: a set-aside needs a floor; without one no fence is older than it.
    #[error("session {session} has no fence floor: no tail is older than it, so none is set aside")]
    NoFloor { session: String },
    /// P2a: the tail holds an event of the floor's fence or a newer one.
    #[error(
        "event {seq} of session {session} is of fence {fence}, not older than the floor ({floor}): it is never set aside"
    )]
    NotOlderThanFloor {
        session: String,
        seq: u64,
        fence: u64,
        floor: u64,
    },
    /// P2a: a set-aside past what the store holds.
    #[error("session {session} holds no event {seq} (its tip is {tip})")]
    NotHeld { session: String, seq: u64, tip: u64 },
    /// P2a: bytes a peer sent under a name they do not hash to.
    #[error("bytes that hash to {actual} came as the blob {named}")]
    BlobMismatch { named: String, actual: String },
    /// P2a: a stored blob's bytes no longer hash to its name.
    #[error("the blob {hash} no longer hashes to its name")]
    CorruptBlob { hash: String },
    #[error("a blob holds at most {MAX_BLOB_BYTES} bytes, not {0}")]
    BlobTooLarge(usize),
    /// P2c-3: a join at a fence older than the floor this device holds.
    #[error("session {session}'s floor is fence {floor}: a join at fence {fence} is older")]
    StaleJoin {
        session: String,
        floor: u64,
        fence: u64,
    },
    /// P2e-5: more events of a kind than the caller would hold.
    #[error("session {session} holds more than {limit} {kind} events")]
    TooMany {
        session: String,
        kind: String,
        limit: usize,
    },
    /// P2f-2a: a substitute names a blob the session does not hold: one is
    /// kept only once every byte of it is.
    #[error(
        "a substitute for {commit} names the blob {hash}, which session {session} does not hold"
    )]
    SubstituteBlobMissing {
        session: String,
        commit: String,
        hash: String,
    },
    /// P2f-2a: a kept substitute that no longer reads as one.
    #[error("the substitute kept for {commit} of session {session} does not read: {why}")]
    CorruptSubstitute {
        session: String,
        commit: String,
        why: String,
    },
}

/// One full-text match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    pub session: String,
    pub seq: u64,
    /// The matching text around the hit, with matches wrapped in `[` `]`.
    pub snippet: String,
}

/// The name a blob is kept under: the BLAKE3 hash of its bytes, as `b3sum`
/// prints it.
pub fn blob_hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// The replica store.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (or create) the store at `path`.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        // WAL: a reader (a viewer paging a transcript) never blocks the
        // primary's appends. NORMAL is durable at WAL checkpoints, which is the
        // right trade for a replica that also exists on other devices.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        Self::init(conn)
    }

    /// An in-memory store, for tests and dry runs.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, StoreError> {
        let found: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if found > SCHEMA_VERSION {
            return Err(StoreError::NewerSchema { found });
        }
        conn.execute_batch(P0A_TABLES)?;
        conn.execute_batch(P2A_TABLES)?;
        conn.execute_batch(P2C_TABLES)?;
        conn.execute_batch(P2E_TABLES)?;
        conn.execute_batch(P2F_TABLES)?;
        conn.execute_batch(P2G_TABLES)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(Self { conn })
    }

    /// FR-90 P2c-3: hold `session` as a member, placed in `role`, at `fence`.
    /// The floor rises to `fence` in the same transaction, so from the join on
    /// an event of an older fence is refused here, whoever sends it. A join
    /// below the floor is refused ([`StoreError::StaleJoin`]), as is one for
    /// a purged session. A later join moves the role and fence, and keeps
    /// when the first was made. Returns the floor.
    ///
    /// P2e-5b — and where each fence a promotion superseded ended (`ends`),
    /// in the same transaction, so no event finds the floor risen without
    /// them: below the floor, such a fence's events are still taken up to
    /// there ([`check_next_with_ends`]). They are kept, never dropped by a
    /// later join: a fence's end never changes once it is superseded, and a
    /// join from a server that names none takes none away.
    pub fn join(
        &mut self,
        session: &str,
        role: &str,
        fence: u64,
        ends: &[FenceEnd],
    ) -> Result<u64, StoreError> {
        let tx = self.conn.transaction()?;
        if Self::purged_in(&tx, session)? {
            return Err(StoreError::Purged {
                session: session.to_string(),
            });
        }
        if let Some(floor) = Self::floor_in(&tx, session)?
            && floor > fence
        {
            return Err(StoreError::StaleJoin {
                session: session.to_string(),
                floor,
                fence,
            });
        }
        tx.execute(
            "INSERT INTO floors (session, fence) VALUES (?1, ?2)
             ON CONFLICT(session) DO UPDATE SET fence = ?2",
            params![session, fence as i64],
        )?;
        tx.execute(
            "INSERT INTO memberships (session, role, fence, joined_ms) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(session) DO UPDATE SET role = ?2, fence = ?3",
            params![session, role, fence as i64, now_ms()],
        )?;
        for end in ends {
            tx.execute(
                "INSERT INTO fence_ends (session, fence, seq, hash) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(session, fence) DO UPDATE SET seq = ?3, hash = ?4",
                params![
                    session,
                    end.fence as i64,
                    end.seq as i64,
                    end.hash.as_slice()
                ],
            )?;
        }
        tx.commit()?;
        Ok(fence)
    }

    /// FR-90 P2e-5b: where each fence a promotion superseded ended, for
    /// `session`, oldest fence first.
    pub fn fence_ends(&self, session: &str) -> Result<Vec<FenceEnd>, StoreError> {
        Self::fence_ends_in(&self.conn, session)
    }

    fn fence_ends_in(conn: &Connection, session: &str) -> Result<Vec<FenceEnd>, StoreError> {
        let mut stmt = conn
            .prepare("SELECT fence, seq, hash FROM fence_ends WHERE session = ?1 ORDER BY fence")?;
        let rows = stmt.query_map(params![session], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (fence, seq, hash) = row?;
            out.push(FenceEnd {
                fence: fence as u64,
                seq: seq as u64,
                hash: to_hash(&hash, session, seq as u64)?,
            });
        }
        Ok(out)
    }

    /// The end of `fence` alone: the one an event of that fence is checked
    /// against, read by its key, so an apply never reads them all.
    fn fence_end_in(
        conn: &Connection,
        session: &str,
        fence: u64,
    ) -> Result<Option<FenceEnd>, StoreError> {
        let row: Option<(i64, Vec<u8>)> = conn
            .query_row(
                "SELECT seq, hash FROM fence_ends WHERE session = ?1 AND fence = ?2",
                params![session, fence as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        row.map(|(seq, hash)| {
            Ok(FenceEnd {
                fence,
                seq: seq as u64,
                hash: to_hash(&hash, session, seq as u64)?,
            })
        })
        .transpose()
    }

    /// FR-90 P2c-3: every session this device holds as a member, by id.
    pub fn memberships(&self) -> Result<Vec<Membership>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT session, role, fence, joined_ms FROM memberships ORDER BY session")?;
        let rows = stmt.query_map([], |r| {
            Ok(Membership {
                session: r.get(0)?,
                role: r.get(1)?,
                fence: r.get::<_, i64>(2)? as u64,
                joined_ms: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// FR-90 P2c-3: the store's size, as SQLite counts its pages: what
    /// `hive_store_quota_mib` is held to. The write-ahead log is not counted;
    /// it is folded back at each checkpoint.
    pub fn size_bytes(&self) -> Result<u64, StoreError> {
        let pages: i64 = self.conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let page: i64 = self.conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        Ok(pages.max(0) as u64 * page.max(0) as u64)
    }

    /// The newest event this store holds for `session`.
    pub fn tip(&self, session: &str) -> Result<Option<ChainTip>, StoreError> {
        Self::tip_in(&self.conn, session)
    }

    fn tip_in(conn: &Connection, session: &str) -> Result<Option<ChainTip>, StoreError> {
        let row: Option<(i64, Vec<u8>, i64)> = conn
            .query_row(
                "SELECT seq, hash, fence FROM tips WHERE session = ?1",
                params![session],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        row.map(|(seq, hash, fence)| {
            Ok(ChainTip {
                seq: seq as u64,
                hash: to_hash(&hash, session, seq as u64)?,
                fence: fence as u64,
            })
        })
        .transpose()
    }

    /// Append one of this device's own events: checked against the tip and
    /// the session's floor, written with its index row and the new tip in one
    /// transaction. Refused for a purged session.
    pub fn append(&mut self, env: &EventEnvelope) -> Result<ChainTip, StoreError> {
        self.extend(env)
    }

    /// FR-90 P2a: apply an event another member sent, exactly as it came.
    /// Its JSON and its hash are the primary's, never re-wrapped, so this copy
    /// chains to the same `(seq, hash)` as the primary's own store. The checks
    /// are [`Self::append`]'s: a gap, a broken link, a fence older than the
    /// tip's or the floor, or a purged session is refused, and nothing of it
    /// is kept.
    pub fn apply(&mut self, env: &EventEnvelope) -> Result<ChainTip, StoreError> {
        self.extend(env)
    }

    /// FR-90 P2d-3 — [`Self::apply`], or nothing at all for an event this
    /// store holds already: the same `seq`, hashed the same. Two streams of
    /// one session reach a member at once while a renewal comes up beside
    /// the stream it replaces (make-before-break), and the later of the two
    /// to carry an event finds it applied. Any other event at a `seq` held
    /// is refused as `apply` refuses it, and so is any event of a purged
    /// session, which holds none. `true` when it was applied here.
    ///
    /// The look and the apply are one call on `&mut self`: nothing else
    /// writes this store between them.
    pub fn apply_unless_held(&mut self, env: &EventEnvelope) -> Result<bool, StoreError> {
        if Self::tip_in(&self.conn, &env.session)?.is_some_and(|t| env.seq <= t.seq) {
            let held: Option<Vec<u8>> = self
                .conn
                .query_row(
                    "SELECT hash FROM events WHERE session = ?1 AND seq = ?2",
                    params![env.session, env.seq as i64],
                    |r| r.get(0),
                )
                .optional()?;
            if held.as_deref() == Some(env.hash().as_slice()) {
                return Ok(false);
            }
        }
        self.extend(env).map(|_| true)
    }

    fn extend(&mut self, env: &EventEnvelope) -> Result<ChainTip, StoreError> {
        let tx = self.conn.transaction()?;
        if Self::purged_in(&tx, &env.session)? {
            return Err(StoreError::Purged {
                session: env.session.clone(),
            });
        }
        let tip = Self::tip_in(&tx, &env.session)?;
        let floor = Self::floor_in(&tx, &env.session)?;
        let end = Self::fence_end_in(&tx, &env.session, env.fence)?;
        check_next_with_ends(tip, floor, end.as_slice(), env)?;
        let next = env.tip();
        Self::insert(&tx, env, &next)?;
        tx.commit()?;
        Ok(next)
    }

    fn insert(
        tx: &Transaction<'_>,
        env: &EventEnvelope,
        next: &ChainTip,
    ) -> Result<(), StoreError> {
        let event = env.event();
        tx.execute(
            "INSERT INTO events (session, seq, fence, ts_ms, prev_hash, hash, kind, event_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                env.session,
                env.seq as i64,
                env.fence as i64,
                env.ts_ms,
                env.prev_hash.as_slice(),
                next.hash.as_slice(),
                event.as_ref().map(TranscriptEvent::kind),
                env.event_json,
            ],
        )?;
        if let Some(text) = event.as_ref().and_then(TranscriptEvent::search_text) {
            tx.execute(
                "INSERT INTO events_fts (text, session, seq) VALUES (?1, ?2, ?3)",
                params![text, env.session, env.seq as i64],
            )?;
        }
        tx.execute(
            "INSERT INTO tips (session, seq, hash, fence) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(session) DO UPDATE SET seq = ?2, hash = ?3, fence = ?4",
            params![
                env.session,
                next.seq as i64,
                next.hash.as_slice(),
                next.fence as i64
            ],
        )?;
        Ok(())
    }

    /// FR-90 P2a: the session's fence floor, if the server raised one.
    pub fn floor(&self, session: &str) -> Result<Option<u64>, StoreError> {
        Self::floor_in(&self.conn, session)
    }

    fn floor_in(conn: &Connection, session: &str) -> Result<Option<u64>, StoreError> {
        let fence: Option<i64> = conn
            .query_row(
                "SELECT fence FROM floors WHERE session = ?1",
                params![session],
                |r| r.get(0),
            )
            .optional()?;
        Ok(fence.map(|f| f as u64))
    }

    /// FR-90 P2a: raise the session's fence floor to `fence`, the newest
    /// fence the server says exists. It is raised before any event of that
    /// fence exists, so from here on an event of an older fence is refused
    /// whoever writes it: this device's own append, or one another member
    /// sends. The floor only rises: the higher of the two is kept and
    /// returned. Refused for a purged session.
    pub fn raise_floor(&mut self, session: &str, fence: u64) -> Result<u64, StoreError> {
        let tx = self.conn.transaction()?;
        if Self::purged_in(&tx, session)? {
            return Err(StoreError::Purged {
                session: session.to_string(),
            });
        }
        // Compared here, as u64: SQLite would compare the stored i64s.
        let floor = Self::floor_in(&tx, session)?.map_or(fence, |f| f.max(fence));
        tx.execute(
            "INSERT INTO floors (session, fence) VALUES (?1, ?2)
             ON CONFLICT(session) DO UPDATE SET fence = ?2",
            params![session, floor as i64],
        )?;
        tx.commit()?;
        Ok(floor)
    }

    /// FR-90 P2a: set aside the tail a promotion cut off. The events after
    /// `seq` leave `events` and the index for the `divergent` table, kept as
    /// they were, and the event at `seq` is the tip again (`seq` 0 leaves the
    /// session with no events). Returns how many moved.
    ///
    /// ⚠️ This is the only rewrite the store allows, and only of an OLDER
    /// fence's tail: every event after `seq` must be of a fence below the
    /// session's floor. One of the floor's fence or a newer one is the
    /// current primary's and is never set aside; the call is refused and
    /// nothing moves. Without a floor no fence is older than it, so nothing
    /// is set aside either. Refused for a purged session.
    pub fn set_aside_after(&mut self, session: &str, seq: u64) -> Result<u64, StoreError> {
        let tx = self.conn.transaction()?;
        if Self::purged_in(&tx, session)? {
            return Err(StoreError::Purged {
                session: session.to_string(),
            });
        }
        let tip = Self::tip_in(&tx, session)?.map_or(0, |t| t.seq);
        if seq > tip {
            return Err(StoreError::NotHeld {
                session: session.to_string(),
                seq,
                tip,
            });
        }
        if seq == tip {
            return Ok(0);
        }
        let Some(floor) = Self::floor_in(&tx, session)? else {
            return Err(StoreError::NoFloor {
                session: session.to_string(),
            });
        };
        // Every fence of the tail, compared here, as u64.
        let first_not_older = {
            let mut stmt = tx.prepare(
                "SELECT seq, fence FROM events WHERE session = ?1 AND seq > ?2 ORDER BY seq",
            )?;
            let rows = stmt.query_map(params![session, seq as i64], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64))
            })?;
            let mut found = None;
            for row in rows {
                let (at, fence) = row?;
                if fence >= floor {
                    found = Some((at, fence));
                    break;
                }
            }
            found
        };
        if let Some((at, fence)) = first_not_older {
            return Err(StoreError::NotOlderThanFloor {
                session: session.to_string(),
                seq: at,
                fence,
                floor,
            });
        }
        let moved = tx.execute(
            "INSERT INTO divergent
                 (session, seq, fence, ts_ms, prev_hash, hash, kind, event_json, set_aside_ms)
             SELECT session, seq, fence, ts_ms, prev_hash, hash, kind, event_json, ?3
             FROM events WHERE session = ?1 AND seq > ?2",
            params![session, seq as i64, now_ms()],
        )?;
        tx.execute(
            "DELETE FROM events WHERE session = ?1 AND seq > ?2",
            params![session, seq as i64],
        )?;
        tx.execute(
            "DELETE FROM events_fts WHERE session = ?1 AND seq > ?2",
            params![session, seq as i64],
        )?;
        if seq == 0 {
            tx.execute("DELETE FROM tips WHERE session = ?1", params![session])?;
        } else {
            let (hash, fence): (Vec<u8>, i64) = tx.query_row(
                "SELECT hash, fence FROM events WHERE session = ?1 AND seq = ?2",
                params![session, seq as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let hash = to_hash(&hash, session, seq)?;
            tx.execute(
                "UPDATE tips SET seq = ?2, hash = ?3, fence = ?4 WHERE session = ?1",
                params![session, seq as i64, hash.as_slice(), fence],
            )?;
        }
        tx.commit()?;
        Ok(moved as u64)
    }

    /// FR-90 P2a: keep `bytes` as a blob of `session`, named by their BLAKE3
    /// hash, which is returned. Bytes another session already holds are
    /// stored once. Refused for a purged session.
    pub fn put_blob(&mut self, session: &str, bytes: &[u8]) -> Result<[u8; 32], StoreError> {
        self.keep_blob(session, bytes, None)
    }

    /// FR-90 P2a: keep bytes a peer sent as the blob `hash`. Refused unless
    /// they hash to it, and then nothing is kept under either name: what a
    /// name holds here is always what the name says.
    pub fn put_named_blob(
        &mut self,
        session: &str,
        hash: &[u8; 32],
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        self.keep_blob(session, bytes, Some(hash)).map(|_| ())
    }

    /// The one way a blob is written: its name is computed here, from the
    /// bytes, whatever name it came under.
    fn keep_blob(
        &mut self,
        session: &str,
        bytes: &[u8],
        named: Option<&[u8; 32]>,
    ) -> Result<[u8; 32], StoreError> {
        if bytes.len() > MAX_BLOB_BYTES {
            return Err(StoreError::BlobTooLarge(bytes.len()));
        }
        let hash = blob_hash(bytes);
        if let Some(named) = named
            && *named != hash
        {
            return Err(StoreError::BlobMismatch {
                named: hex(named),
                actual: hex(&hash),
            });
        }
        let tx = self.conn.transaction()?;
        if Self::purged_in(&tx, session)? {
            return Err(StoreError::Purged {
                session: session.to_string(),
            });
        }
        // Already here and intact: kept as it is. Here but not these bytes
        // (damaged on disk): replaced by bytes that do hash to its name.
        let held: Option<Vec<u8>> = tx
            .query_row(
                "SELECT data FROM blobs WHERE hash = ?1",
                params![hash.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        if held.as_deref() != Some(bytes) {
            tx.execute(
                "INSERT INTO blobs (hash, data) VALUES (?1, ?2)
                 ON CONFLICT(hash) DO UPDATE SET data = excluded.data",
                params![hash.as_slice(), bytes],
            )?;
        }
        tx.execute(
            "INSERT INTO blob_refs (session, hash) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
            params![session, hash.as_slice()],
        )?;
        tx.commit()?;
        Ok(hash)
    }

    /// FR-90 P2a: the blob `hash`, if `session` holds it. A blob another
    /// session holds is not this one's to read. Checked as it is read: bytes
    /// that no longer hash to their name are an error, never handed out.
    pub fn get_blob(&self, session: &str, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        let data: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT b.data FROM blob_refs r JOIN blobs b ON b.hash = r.hash
                 WHERE r.session = ?1 AND r.hash = ?2",
                params![session, hash.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        match data {
            Some(bytes) if blob_hash(&bytes) != *hash => {
                Err(StoreError::CorruptBlob { hash: hex(hash) })
            }
            data => Ok(data),
        }
    }

    /// FR-90 P2a: whether `session` holds the blob `hash`.
    pub fn has_blob(&self, session: &str, hash: &[u8; 32]) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM blob_refs r JOIN blobs b ON b.hash = r.hash
                 WHERE r.session = ?1 AND r.hash = ?2",
                params![session, hash.as_slice()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// FR-90 P2f-2a: keep `sub` for `session`, in place of whatever was kept
    /// for the same commit. Its blobs come first ([`Self::put_named_blob`]):
    /// a substitute naming one this session does not hold is refused, so one
    /// kept here always has every byte. Refused for a purged session.
    pub fn put_substitute(&mut self, session: &str, sub: &Substitute) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        if Self::purged_in(&tx, session)? {
            return Err(StoreError::Purged {
                session: session.to_string(),
            });
        }
        for chunk in &sub.chunks {
            let held = tx
                .query_row(
                    "SELECT 1 FROM blob_refs WHERE session = ?1 AND hash = ?2",
                    params![session, chunk.hash.0.as_slice()],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !held {
                return Err(StoreError::SubstituteBlobMissing {
                    session: session.to_string(),
                    commit: sub.commit.clone(),
                    hash: hex(&chunk.hash.0),
                });
            }
        }
        let corrupt = |e: serde_json::Error| StoreError::CorruptSubstitute {
            session: session.to_string(),
            commit: sub.commit.clone(),
            why: e.to_string(),
        };
        let against = serde_json::to_string(&sub.against).map_err(corrupt)?;
        let chunks = serde_json::to_string(&sub.chunks).map_err(corrupt)?;
        tx.execute(
            "INSERT INTO substitutes (session, commit_id, against, chunks, kept_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(session, commit_id) DO UPDATE SET
                 against = excluded.against, chunks = excluded.chunks, kept_ms = excluded.kept_ms",
            params![session, sub.commit, against, chunks, now_ms()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// FR-90 P2f-2a: the substitute kept for `commit` of `session`, if any.
    pub fn substitute(
        &self,
        session: &str,
        commit: &str,
    ) -> Result<Option<Substitute>, StoreError> {
        let row: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT against, chunks FROM substitutes WHERE session = ?1 AND commit_id = ?2",
                params![session, commit],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((against, chunks)) = row else {
            return Ok(None);
        };
        let corrupt = |e: serde_json::Error| StoreError::CorruptSubstitute {
            session: session.to_string(),
            commit: commit.to_string(),
            why: e.to_string(),
        };
        Ok(Some(Substitute {
            commit: commit.to_string(),
            against: serde_json::from_str(&against).map_err(corrupt)?,
            chunks: serde_json::from_str(&chunks).map_err(corrupt)?,
        }))
    }

    /// FR-90 P2f-2c: the commits of `session`'s whole packs this store keeps
    /// a substitute for and not every blob of the pack itself, the oldest
    /// kept first, at most `limit`: what a source of this copy cannot serve
    /// by blobs. A substitute no whole pack of the chain names stands in for
    /// nothing.
    pub fn stand_ins(&self, session: &str, limit: usize) -> Result<Vec<String>, StoreError> {
        let commits: Vec<String> = self
            .conn
            .prepare(
                "SELECT commit_id FROM substitutes WHERE session = ?1
                 ORDER BY kept_ms, commit_id",
            )?
            .query_map(params![session], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::new();
        for commit in commits {
            if out.len() == limit {
                break;
            }
            // Only the checkpoints that name it are read.
            let jsons: Vec<String> = self
                .conn
                .prepare(
                    "SELECT event_json FROM events
                     WHERE session = ?1 AND kind = 'checkpoint' AND instr(event_json, ?2) > 0",
                )?
                .query_map(params![session, commit], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            let pack =
                jsons.iter().find_map(|json| {
                    match crate::event::TranscriptEvent::from_json(json) {
                        Some(crate::event::TranscriptEvent::Checkpoint(cp)) => cp
                            .workspace
                            .filter(|ws| {
                                ws.commit == commit && ws.base.is_none() && !ws.pack.is_empty()
                            })
                            .map(|ws| ws.pack),
                        _ => None,
                    }
                });
            let Some(pack) = pack else { continue };
            let mut whole = true;
            for chunk in &pack {
                if !self.has_blob(session, &chunk.hash.0)? {
                    whole = false;
                    break;
                }
            }
            if !whole {
                out.push(commit);
            }
        }
        Ok(out)
    }

    /// FR-90 P2f-2c: keep where `session` is worked on here, in place of
    /// what an earlier launch kept. Refused for a purged session.
    pub fn put_workplace(&mut self, session: &str, w: &WorkplaceRecord) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        if Self::purged_in(&tx, session)? {
            return Err(StoreError::Purged {
                session: session.to_string(),
            });
        }
        tx.execute(
            "INSERT INTO workplaces (session, account, folder, state_dir, kept_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(session) DO UPDATE SET
                 account = excluded.account, folder = excluded.folder,
                 state_dir = excluded.state_dir, kept_ms = excluded.kept_ms",
            params![session, w.account, w.folder, w.state_dir, now_ms()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// FR-90 P2f-2c: where `session` was last worked on here, if anywhere.
    pub fn workplace(&self, session: &str) -> Result<Option<WorkplaceRecord>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT account, folder, state_dir FROM workplaces WHERE session = ?1",
                params![session],
                |r| {
                    Ok(WorkplaceRecord {
                        account: r.get(0)?,
                        folder: r.get(1)?,
                        state_dir: r.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    /// FR-90 P2b-3b — the newest event of `session` whose kind is `kind`: where
    /// a resumed session's next checkpoint starts. The `kind` column is set by
    /// a build that knows the kind, so a checkpoint an older daemon stored is
    /// not found, and the next one takes everything again: more bytes, never a
    /// wrong checkpoint.
    pub fn last_of_kind(
        &self,
        session: &str,
        kind: &str,
    ) -> Result<Option<EventEnvelope>, StoreError> {
        let row = self
            .conn
            .query_row(
                "SELECT seq, fence, ts_ms, prev_hash, event_json FROM events
                 WHERE session = ?1 AND kind = ?2 ORDER BY seq DESC LIMIT 1",
                params![session, kind],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((seq, fence, ts_ms, prev, event_json)) = row else {
            return Ok(None);
        };
        Ok(Some(EventEnvelope {
            session: session.to_string(),
            seq: seq as u64,
            fence: fence as u64,
            ts_ms,
            prev_hash: to_hash(&prev, session, seq as u64)?,
            event_json,
        }))
    }

    /// FR-90 P2e-5 — every event of `session` whose kind is `kind`, oldest
    /// first: a moved session's checkpoint chain, which its new primary
    /// materializes. More than `limit` is refused whole, never a chain cut
    /// short.
    pub fn of_kind(
        &self,
        session: &str,
        kind: &str,
        limit: usize,
    ) -> Result<Vec<EventEnvelope>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, fence, ts_ms, prev_hash, event_json FROM events
             WHERE session = ?1 AND kind = ?2 ORDER BY seq ASC LIMIT ?3",
        )?;
        let past = i64::try_from(limit).unwrap_or(i64::MAX).saturating_add(1);
        let rows = stmt.query_map(params![session, kind, past], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, fence, ts_ms, prev, event_json) = row?;
            if out.len() == limit {
                return Err(StoreError::TooMany {
                    session: session.to_string(),
                    kind: kind.to_string(),
                    limit,
                });
            }
            out.push(EventEnvelope {
                session: session.to_string(),
                seq: seq as u64,
                fence: fence as u64,
                ts_ms,
                prev_hash: to_hash(&prev, session, seq as u64)?,
                event_json,
            });
        }
        Ok(out)
    }

    /// Events of `session` after `after_seq`, oldest first, at most `limit`.
    pub fn page(
        &self,
        session: &str,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<EventEnvelope>, StoreError> {
        self.page_within(session, after_seq, limit, usize::MAX)
    }

    /// FR-90 P2d-3 — [`Self::page`], cut before the events' JSON would pass
    /// `max_bytes`, and never empty while an event follows `after_seq`: one
    /// `events` frame of the replica stream, read without holding more than
    /// it. An event larger than `max_bytes` comes alone.
    pub fn page_within(
        &self,
        session: &str,
        after_seq: u64,
        limit: usize,
        max_bytes: usize,
    ) -> Result<Vec<EventEnvelope>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, fence, ts_ms, prev_hash, event_json FROM events
             WHERE session = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![session, after_seq as i64, limit as i64], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for row in rows {
            let (seq, fence, ts_ms, prev, event_json) = row?;
            bytes = bytes.saturating_add(event_json.len());
            if !out.is_empty() && bytes > max_bytes {
                break;
            }
            out.push(EventEnvelope {
                session: session.to_string(),
                seq: seq as u64,
                fence: fence as u64,
                ts_ms,
                prev_hash: to_hash(&prev, session, seq as u64)?,
                event_json,
            });
        }
        Ok(out)
    }

    /// FR-90 P2d — the event of `session` at `seq`, when the store holds it.
    /// Never one of the divergent table's: what was set aside is not the
    /// chain.
    pub fn event_at(&self, session: &str, seq: u64) -> Result<Option<EventEnvelope>, StoreError> {
        if seq == 0 {
            return Ok(None);
        }
        Ok(self
            .page(session, seq - 1, 1)?
            .into_iter()
            .find(|e| e.seq == seq))
    }

    /// FR-90 P2d — the newest `limit` checkpoints of `session`, newest first,
    /// each as the `seq` and hash of its event: what a member names in its
    /// stream's hello, and how a source finds one both hold.
    pub fn checkpoint_marks(
        &self,
        session: &str,
        limit: usize,
    ) -> Result<Vec<(u64, [u8; 32])>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, fence, ts_ms, prev_hash, event_json FROM events
             WHERE session = ?1 AND kind = 'checkpoint' ORDER BY seq DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![session, limit as i64], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (seq, fence, ts_ms, prev, event_json) = row?;
            let env = EventEnvelope {
                session: session.to_string(),
                seq: seq as u64,
                fence: fence as u64,
                ts_ms,
                prev_hash: to_hash(&prev, session, seq as u64)?,
                event_json,
            };
            out.push((env.seq, env.hash()));
        }
        Ok(out)
    }

    /// Full-text search, best matches first (FTS5 `rank`). `sessions` limits
    /// the search to the sessions a view grant names; `None` searches
    /// everything this store holds (the daemon's own use, never a viewer's).
    ///
    /// The query is taken as plain words — each becomes a quoted FTS5 phrase,
    /// all of which must match — so a viewer's search box can never inject FTS
    /// syntax or fail on a stray quote.
    pub fn search(
        &self,
        query: &str,
        sessions: Option<&[String]>,
        limit: usize,
    ) -> Result<Vec<SearchHit>, StoreError> {
        let Some(fts_query) = plain_words_query(query) else {
            return Ok(Vec::new());
        };
        if let Some(list) = sessions {
            if list.is_empty() {
                return Ok(Vec::new());
            }
            if list.len() > MAX_SEARCH_SESSIONS {
                return Err(StoreError::TooManySessions(list.len()));
            }
        }
        let mut sql = String::from(
            "SELECT session, seq, snippet(events_fts, 0, '[', ']', '…', 12)
             FROM events_fts WHERE events_fts MATCH ?1",
        );
        let mut args: Vec<rusqlite::types::Value> = vec![fts_query.into()];
        if let Some(list) = sessions {
            sql.push_str(" AND session IN (");
            for (i, s) in list.iter().enumerate() {
                if i > 0 {
                    sql.push(',');
                }
                sql.push_str(&format!("?{}", i + 2));
                args.push(s.clone().into());
            }
            sql.push(')');
        }
        sql.push_str(&format!(" ORDER BY rank LIMIT {}", limit.min(1_000)));
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), |r| {
            Ok(SearchHit {
                session: r.get(0)?,
                seq: r.get::<_, i64>(1)? as u64,
                snippet: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Delete everything this store holds for `session` — the purge a tombstone
    /// orders — and keep its id, with when (FR-90 P2a). From then on an
    /// append, an apply, a floor, a set-aside or a blob for it is refused
    /// (`purged`), so a member that comes back with an old stream cannot bring
    /// it back. Returns how many events were removed, set-aside ones included.
    ///
    /// A blob goes with the last session that holds it; one another session
    /// holds too stays.
    pub fn purge(&mut self, session: &str) -> Result<u64, StoreError> {
        self.purge_with(session, true)
    }

    /// FR-90 P2k-3 — delete this store's copy of `session` as a member that
    /// leaves it (P2g-4b): everything [`Self::purge`] deletes, the account's
    /// part owed the same way, but nothing kept of its id. A later join of
    /// it starts a copy from nothing, as of a session never held here: the
    /// session goes on elsewhere, and placement may choose this device again.
    /// A session already purged for good here stays so.
    pub fn purge_copy(&mut self, session: &str) -> Result<u64, StoreError> {
        self.purge_with(session, false)
    }

    fn purge_with(&mut self, session: &str, keep_id: bool) -> Result<u64, StoreError> {
        let tx = self.conn.transaction()?;
        let n = tx.execute("DELETE FROM events WHERE session = ?1", params![session])?;
        let set_aside = tx.execute("DELETE FROM divergent WHERE session = ?1", params![session])?;
        tx.execute(
            "DELETE FROM events_fts WHERE session = ?1",
            params![session],
        )?;
        tx.execute("DELETE FROM tips WHERE session = ?1", params![session])?;
        tx.execute("DELETE FROM floors WHERE session = ?1", params![session])?;
        tx.execute(
            "DELETE FROM fence_ends WHERE session = ?1",
            params![session],
        )?;
        tx.execute(
            "DELETE FROM memberships WHERE session = ?1",
            params![session],
        )?;
        tx.execute(
            "DELETE FROM substitutes WHERE session = ?1",
            params![session],
        )?;
        // FR-90 P2g-1 — what the account holds of the session outlives the
        // store's copy: where it was worked on becomes a debt, in this same
        // transaction, until the account's part is done ([`Self::purge_debt`]).
        tx.execute(
            "INSERT INTO purge_debts (session, account, folder, state_dir, since_ms)
             SELECT session, account, folder, state_dir, ?2 FROM workplaces WHERE session = ?1
             ON CONFLICT(session) DO NOTHING",
            params![session, now_ms()],
        )?;
        tx.execute(
            "DELETE FROM workplaces WHERE session = ?1",
            params![session],
        )?;
        tx.execute(
            "DELETE FROM blobs WHERE hash IN (SELECT hash FROM blob_refs WHERE session = ?1)
               AND hash NOT IN (SELECT hash FROM blob_refs WHERE session <> ?1)",
            params![session],
        )?;
        tx.execute("DELETE FROM blob_refs WHERE session = ?1", params![session])?;
        // FR-90 P2g-3d — the word that kept the copy goes with it.
        tx.execute("DELETE FROM retains WHERE session = ?1", params![session])?;
        // The first purge's time is kept; a repeated one changes nothing.
        if keep_id {
            tx.execute(
                "INSERT INTO purged (session, purged_ms) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
                params![session, now_ms()],
            )?;
        }
        tx.commit()?;
        Ok((n + set_aside) as u64)
    }

    /// FR-90 P2g-1 — whether this store holds anything of `session`: its
    /// events, a set-aside tail, a tip or a floor, a membership, a substitute,
    /// a blob reference, or where it was worked on.
    pub fn holds(&self, session: &str) -> Result<bool, StoreError> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE session = ?1)
                 OR EXISTS(SELECT 1 FROM divergent WHERE session = ?1)
                 OR EXISTS(SELECT 1 FROM tips WHERE session = ?1)
                 OR EXISTS(SELECT 1 FROM floors WHERE session = ?1)
                 OR EXISTS(SELECT 1 FROM memberships WHERE session = ?1)
                 OR EXISTS(SELECT 1 FROM substitutes WHERE session = ?1)
                 OR EXISTS(SELECT 1 FROM blob_refs WHERE session = ?1)
                 OR EXISTS(SELECT 1 FROM workplaces WHERE session = ?1)",
            params![session],
            |r| r.get::<_, bool>(0),
        )?)
    }

    /// FR-90 P2g-1 — what the account still holds of a purged `session`:
    /// where it was worked on, kept from its workplace by [`Self::purge`]
    /// until the account's part is done.
    pub fn purge_debt(&self, session: &str) -> Result<Option<WorkplaceRecord>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT account, folder, state_dir FROM purge_debts WHERE session = ?1",
                params![session],
                |r| {
                    Ok(WorkplaceRecord {
                        account: r.get(0)?,
                        folder: r.get(1)?,
                        state_dir: r.get(2)?,
                    })
                },
            )
            .optional()?)
    }

    /// FR-90 P2g-1 — the account's part of `session`'s purge is done.
    pub fn clear_purge_debt(&mut self, session: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM purge_debts WHERE session = ?1",
            params![session],
        )?;
        Ok(())
    }

    /// FR-90 P2a: whether `session` was purged here.
    pub fn is_purged(&self, session: &str) -> Result<bool, StoreError> {
        Self::purged_in(&self.conn, session)
    }

    fn purged_in(conn: &Connection, session: &str) -> Result<bool, StoreError> {
        Ok(conn
            .query_row(
                "SELECT 1 FROM purged WHERE session = ?1",
                params![session],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Every session this store holds, with its tip.
    pub fn sessions(&self) -> Result<Vec<(String, ChainTip)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT session, seq, hash, fence FROM tips ORDER BY session")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (session, seq, hash, fence) = row?;
            let hash = to_hash(&hash, &session, seq as u64)?;
            out.push((
                session,
                ChainTip {
                    seq: seq as u64,
                    hash,
                    fence: fence as u64,
                },
            ));
        }
        Ok(out)
    }

    /// FR-90 P2g-3d — every session this store holds anything of, as
    /// [`Self::holds`] reads it: what the device asks the server's word for.
    /// A purged session holds nothing.
    pub fn held_sessions(&self) -> Result<Vec<String>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT session FROM events
             UNION SELECT session FROM divergent
             UNION SELECT session FROM tips
             UNION SELECT session FROM floors
             UNION SELECT session FROM memberships
             UNION SELECT session FROM substitutes
             UNION SELECT session FROM blob_refs
             UNION SELECT session FROM workplaces
             ORDER BY 1",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// FR-90 P2g-3d — keep what the server says keeps `session`'s copy, said
    /// now, over any word before it. None for a purged session: it holds
    /// nothing to keep.
    pub fn put_retain(
        &mut self,
        session: &str,
        days: u32,
        ended_ms: Option<i64>,
    ) -> Result<(), StoreError> {
        let tx = self.conn.transaction()?;
        if !Self::purged_in(&tx, session)? {
            tx.execute(
                "INSERT INTO retains (session, days, ended_ms, said_ms) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(session) DO UPDATE SET
                     days = excluded.days, ended_ms = excluded.ended_ms, said_ms = excluded.said_ms",
                params![session, i64::from(days), ended_ms, now_ms()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// FR-90 P2g-3d — every word kept.
    pub fn retains(&self) -> Result<Vec<RetainWord>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT session, days, ended_ms, said_ms FROM retains ORDER BY session")?;
        let rows = stmt.query_map([], |r| {
            Ok(RetainWord {
                session: r.get(0)?,
                days: u32::try_from(r.get::<_, i64>(1)?).unwrap_or(u32::MAX),
                ended_ms: r.get(2)?,
                said_ms: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// FR-90 P2g-3d — forget `session`'s word: a session this device no
    /// longer holds anything of.
    pub fn drop_retain(&mut self, session: &str) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM retains WHERE session = ?1", params![session])?;
        Ok(())
    }

    /// FR-90 P2g-3d — when this device was last connected, by its own clock.
    pub fn contact(&self) -> Result<Option<i64>, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT at_ms FROM contact WHERE id = 1", [], |r| r.get(0))
            .optional()?)
    }

    /// FR-90 P2g-3d — the device is connected now (`at_ms`, its own clock).
    pub fn set_contact(&mut self, at_ms: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO contact (id, at_ms) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET at_ms = excluded.at_ms",
            params![at_ms],
        )?;
        Ok(())
    }

    /// FR-90 P2g-3d — the device's own clock purged its copy of `session` at
    /// `at_ms`: its next manifests name it ([`Self::take_copy_purge_reports`]).
    /// The first time is kept.
    pub fn note_copy_purge(&mut self, session: &str, at_ms: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO copy_purges (session, at_ms, reports) VALUES (?1, ?2, 0)
             ON CONFLICT(session) DO NOTHING",
            params![session, at_ms],
        )?;
        Ok(())
    }

    /// FR-90 P2g-3d — the copies the device's own clock purged that a manifest
    /// is to name, oldest first, at most `limit`, each with when. Each one
    /// taken counts one report, and one that has now been named in `max`
    /// manifests is forgotten.
    pub fn take_copy_purge_reports(
        &mut self,
        limit: usize,
        max: u32,
    ) -> Result<Vec<(String, i64)>, StoreError> {
        let tx = self.conn.transaction()?;
        let taken: Vec<(String, i64)> = {
            let mut stmt = tx.prepare(
                "SELECT session, at_ms FROM copy_purges ORDER BY at_ms, session LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![i64::try_from(limit).unwrap_or(i64::MAX)], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for (session, _) in &taken {
            tx.execute(
                "UPDATE copy_purges SET reports = reports + 1 WHERE session = ?1",
                params![session],
            )?;
        }
        tx.execute(
            "DELETE FROM copy_purges WHERE reports >= ?1",
            params![i64::from(max)],
        )?;
        tx.commit()?;
        Ok(taken)
    }

    /// FR-90 P2g-3d — whether a copy the device's own clock purged is still to
    /// be named in a manifest.
    pub fn has_copy_purge_reports(&self) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT EXISTS(SELECT 1 FROM copy_purges)", [], |r| {
                r.get::<_, bool>(0)
            })?)
    }
}

fn to_hash(raw: &[u8], session: &str, seq: u64) -> Result<[u8; 32], StoreError> {
    raw.try_into().map_err(|_| StoreError::CorruptHash {
        session: session.to_string(),
        seq,
    })
}

pub(crate) fn hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

/// Plain words → an FTS5 query: every whitespace-separated word becomes a quoted
/// phrase (an embedded `"` doubled), all required. `None` when there are none.
fn plain_words_query(query: &str) -> Option<String> {
    let terms: Vec<String> = query
        .split_whitespace()
        .map(|w| format!("\"{}\"", w.replace('"', "\"\"")))
        .collect();
    (!terms.is_empty()).then(|| terms.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::GENESIS;

    fn ev(text: &str) -> TranscriptEvent {
        TranscriptEvent::AssistantText { text: text.into() }
    }

    fn append_all(store: &mut Store, session: &str, fence: u64, texts: &[&str]) -> ChainTip {
        let mut tip = store.tip(session).unwrap();
        for (i, t) in texts.iter().enumerate() {
            let env = EventEnvelope::next(session, tip, fence, i as i64, &ev(t));
            tip = Some(store.append(&env).unwrap());
        }
        tip.unwrap()
    }

    #[test]
    fn appends_chain_and_pages_back_byte_for_byte() {
        let mut s = Store::open_in_memory().unwrap();
        let tip = append_all(&mut s, "s1", 1, &["one", "two", "three"]);
        assert_eq!(tip.seq, 3);
        let page = s.page("s1", 0, 10).unwrap();
        assert_eq!(page.len(), 3);
        assert_eq!(page[0].prev_hash, GENESIS);
        assert_eq!(page[1].prev_hash, page[0].hash());
        assert_eq!(page[2].hash(), tip.hash);
        assert_eq!(s.page("s1", 2, 10).unwrap().len(), 1);
        assert_eq!(s.page("s1", 0, 2).unwrap().len(), 2);
    }

    /// FR-90 P2d-3 — a page within a byte budget is cut before the events'
    /// JSON passes it, never empty while an event follows: one larger than
    /// the budget comes alone. The limit still holds, and a budget nothing
    /// passes is the page itself.
    #[test]
    fn a_page_within_a_budget_is_cut_but_never_empty() {
        let mut s = Store::open_in_memory().unwrap();
        let big = "x".repeat(300);
        append_all(&mut s, "s1", 1, &["a", "b", &big, "c", "d"]);
        let len = |seq: u64| s.event_at("s1", seq).unwrap().unwrap().event_json.len();
        let two = len(1) + len(2);
        let seqs = |p: Vec<EventEnvelope>| p.iter().map(|e| e.seq).collect::<Vec<_>>();
        assert_eq!(seqs(s.page_within("s1", 0, 10, two).unwrap()), [1, 2]);
        assert_eq!(seqs(s.page_within("s1", 0, 10, two - 1).unwrap()), [1]);
        assert_eq!(
            seqs(s.page_within("s1", 2, 10, 10).unwrap()),
            [3],
            "an event past the budget comes alone"
        );
        assert_eq!(seqs(s.page_within("s1", 0, 2, usize::MAX).unwrap()), [1, 2]);
        assert_eq!(
            s.page_within("s1", 0, 10, usize::MAX).unwrap(),
            s.page("s1", 0, 10).unwrap()
        );
        assert!(s.page_within("s1", 5, 10, 1).unwrap().is_empty());
    }

    /// FR-90 P2d-3 — an event held already, the same `seq` hashed the same,
    /// is taken as held and nothing is written; any other at a `seq` held is
    /// refused as `apply` refuses it, and the next one is applied.
    #[test]
    fn an_event_held_already_is_not_applied_twice() {
        let mut primary = Store::open_in_memory().unwrap();
        append_all(&mut primary, "s1", 1, &["one", "two", "three"]);
        let envs = primary.page("s1", 0, 10).unwrap();
        let mut m = Store::open_in_memory().unwrap();
        for env in &envs[..2] {
            assert!(
                m.apply_unless_held(env).unwrap(),
                "applied: seq {}",
                env.seq
            );
        }
        for env in &envs[..2] {
            assert!(!m.apply_unless_held(env).unwrap(), "held: seq {}", env.seq);
        }
        assert_eq!(
            m.page("s1", 0, 10).unwrap(),
            envs[..2],
            "nothing written twice"
        );
        let other = EventEnvelope {
            event_json: ev("not the primary's").to_json(),
            ..envs[1].clone()
        };
        assert!(
            matches!(
                m.apply_unless_held(&other),
                Err(StoreError::Chain(ChainError::Gap { .. }))
            ),
            "another event at a seq held"
        );
        assert!(m.apply_unless_held(&envs[2]).unwrap(), "the next one");
        assert_eq!(m.tip("s1").unwrap().unwrap().hash, envs[2].hash());
        m.purge("s1").unwrap();
        assert!(
            matches!(
                m.apply_unless_held(&envs[0]),
                Err(StoreError::Purged { .. })
            ),
            "a purged session holds nothing, and takes nothing back"
        );
    }

    /// FR-90 P2b-3b — the newest event of a kind, by session: none before one
    /// is appended, then always the latest, and never another session's.
    #[test]
    fn the_last_event_of_a_kind_is_the_newest_and_the_sessions_own() {
        let mut s = Store::open_in_memory().unwrap();
        assert!(s.last_of_kind("s1", "note").unwrap().is_none());
        let note = |t: &str| TranscriptEvent::Note { text: t.into() };
        let mut tip = None;
        for (i, e) in [ev("a"), note("n1"), ev("b"), note("n2"), ev("c")]
            .iter()
            .enumerate()
        {
            let env = EventEnvelope::next("s1", tip, 1, i as i64, e);
            tip = Some(s.append(&env).unwrap());
        }
        s.append(&EventEnvelope::next("s2", None, 1, 0, &note("theirs")))
            .unwrap();
        let last = s.last_of_kind("s1", "note").unwrap().unwrap();
        assert_eq!(last.seq, 4);
        assert_eq!(
            TranscriptEvent::from_json(&last.event_json),
            Some(note("n2"))
        );
        assert_eq!(s.last_of_kind("s2", "note").unwrap().unwrap().seq, 1);
        assert!(s.last_of_kind("s1", "checkpoint").unwrap().is_none());
    }

    /// FR-90 P2e-5 — every event of a kind, oldest first and the session's
    /// own; more than the caller would hold is refused whole.
    #[test]
    fn every_event_of_a_kind_comes_oldest_first_and_too_many_is_refused() {
        let mut s = Store::open_in_memory().unwrap();
        let note = |t: &str| TranscriptEvent::Note { text: t.into() };
        let mut tip = None;
        for (i, e) in [note("n1"), ev("a"), note("n2"), ev("b"), note("n3")]
            .iter()
            .enumerate()
        {
            let env = EventEnvelope::next("s1", tip, 1, i as i64, e);
            tip = Some(s.append(&env).unwrap());
        }
        s.append(&EventEnvelope::next("s2", None, 1, 0, &note("theirs")))
            .unwrap();
        let notes = s.of_kind("s1", "note", 10).unwrap();
        assert_eq!(notes.iter().map(|e| e.seq).collect::<Vec<_>>(), [1, 3, 5]);
        assert_eq!(
            TranscriptEvent::from_json(&notes[0].event_json),
            Some(note("n1"))
        );
        assert_eq!(s.of_kind("s1", "note", 3).unwrap().len(), 3, "the limit");
        assert!(
            matches!(
                s.of_kind("s1", "note", 2),
                Err(StoreError::TooMany { limit: 2, .. })
            ),
            "never a chain cut short"
        );
        assert!(s.of_kind("s1", "checkpoint", 10).unwrap().is_empty());
    }

    #[test]
    fn refuses_what_does_not_follow_the_tip_and_keeps_the_index_consistent() {
        let mut s = Store::open_in_memory().unwrap();
        let tip = append_all(&mut s, "s1", 3, &["a", "b"]);
        // A stale writer: refused, and nothing of it is indexed.
        let stale = EventEnvelope::next("s1", Some(tip), 2, 9, &ev("ghostword"));
        assert!(matches!(
            s.append(&stale),
            Err(StoreError::Chain(ChainError::StaleFence { .. }))
        ));
        assert!(s.search("ghostword", None, 10).unwrap().is_empty());
        // A gap: refused.
        let mut gap = EventEnvelope::next("s1", Some(tip), 3, 9, &ev("c"));
        gap.seq = 5;
        assert!(matches!(
            s.append(&gap),
            Err(StoreError::Chain(ChainError::Gap { .. }))
        ));
        assert_eq!(s.tip("s1").unwrap(), Some(tip), "the tip did not move");
    }

    #[test]
    fn a_promotion_continues_the_chain_under_the_new_fence() {
        let mut s = Store::open_in_memory().unwrap();
        let tip = append_all(&mut s, "s1", 1, &["before"]);
        let after = EventEnvelope::next("s1", Some(tip), 2, 5, &ev("after"));
        let tip = s.append(&after).unwrap();
        assert_eq!((tip.seq, tip.fence), (2, 2));
    }

    #[test]
    fn search_finds_words_scoped_to_granted_sessions() {
        let mut s = Store::open_in_memory().unwrap();
        append_all(&mut s, "s1", 1, &["the kubelet restarted on node-a"]);
        append_all(&mut s, "s2", 1, &["kubelet logs were clean"]);
        let all = s.search("kubelet", None, 10).unwrap();
        assert_eq!(all.len(), 2);
        let only_s2 = s.search("kubelet", Some(&["s2".into()]), 10).unwrap();
        assert_eq!(only_s2.len(), 1);
        assert_eq!(only_s2[0].session, "s2");
        assert!(only_s2[0].snippet.contains("[kubelet]"), "{:?}", only_s2[0]);
        // Every word must match.
        assert_eq!(s.search("kubelet node-a", None, 10).unwrap().len(), 1);
        // An empty grant searches nothing — never "everything".
        assert!(s.search("kubelet", Some(&[]), 10).unwrap().is_empty());
    }

    #[test]
    fn search_input_cannot_inject_fts_syntax() {
        let mut s = Store::open_in_memory().unwrap();
        append_all(&mut s, "s1", 1, &["NEAR and OR are words here"]);
        // Each of these is FTS5 syntax that would error or change the meaning if
        // passed through raw.
        for q in ["\"unbalanced", "NEAR(", "a OR", "*", "col:x", "-"] {
            s.search(q, None, 10)
                .unwrap_or_else(|e| panic!("query {q:?} errored: {e}"));
        }
        assert_eq!(s.search("OR", None, 10).unwrap().len(), 1);
        assert!(s.search("   ", None, 10).unwrap().is_empty());
    }

    #[test]
    fn an_unknown_kind_is_stored_and_chained_but_not_indexed() {
        let mut s = Store::open_in_memory().unwrap();
        let env = EventEnvelope {
            session: "s1".into(),
            seq: 1,
            fence: 1,
            ts_ms: 0,
            prev_hash: GENESIS,
            event_json: r#"{"kind":"from_the_future","text":"zebra"}"#.into(),
        };
        s.append(&env).unwrap();
        assert_eq!(s.page("s1", 0, 10).unwrap(), vec![env]);
        assert!(s.search("zebra", None, 10).unwrap().is_empty());
    }

    #[test]
    fn purge_removes_events_index_and_tip_of_one_session_only() {
        let mut s = Store::open_in_memory().unwrap();
        append_all(&mut s, "s1", 1, &["alpha", "beta"]);
        append_all(&mut s, "s2", 1, &["alpha"]);
        assert_eq!(s.purge("s1").unwrap(), 2);
        assert_eq!(s.tip("s1").unwrap(), None);
        assert!(s.page("s1", 0, 10).unwrap().is_empty());
        let hits = s.search("alpha", None, 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].session, "s2");
        assert_eq!(s.sessions().unwrap().len(), 1);
    }

    #[test]
    fn a_file_store_survives_reopen_and_refuses_a_newer_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hive.db");
        {
            let mut s = Store::open(&path).unwrap();
            append_all(&mut s, "s1", 1, &["persisted"]);
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(s.tip("s1").unwrap().map(|t| t.seq), Some(1));
        assert_eq!(s.search("persisted", None, 5).unwrap().len(), 1);
        drop(s);
        {
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
                .unwrap();
        }
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::NewerSchema { .. })
        ));
    }

    // ---- FR-90 P2a: the member's store ----

    /// The primary's envelopes for `texts`, under `fence`, after `tip`: what a
    /// member is sent.
    fn sent(
        session: &str,
        mut tip: Option<ChainTip>,
        fence: u64,
        texts: &[&str],
    ) -> Vec<EventEnvelope> {
        let mut out = Vec::new();
        for (i, t) in texts.iter().enumerate() {
            let env = EventEnvelope::next(session, tip, fence, 1_000 + i as i64, &ev(t));
            tip = Some(env.tip());
            out.push(env);
        }
        out
    }

    fn apply_all(store: &mut Store, envs: &[EventEnvelope]) -> ChainTip {
        let mut tip = None;
        for env in envs {
            tip = Some(store.apply(env).unwrap());
        }
        tip.expect("at least one envelope")
    }

    fn count(s: &Store, sql: &str) -> i64 {
        s.conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn an_applied_envelope_is_kept_exactly_as_it_came() {
        // The primary's own store, and its first event as it would be sent:
        // an odd key order and spacing, and the primary's clock.
        let mut primary = Store::open_in_memory().unwrap();
        let first = EventEnvelope {
            session: "s1".into(),
            seq: 1,
            fence: 1,
            ts_ms: 42,
            prev_hash: GENESIS,
            event_json: r#"{"text":"kept as sent" ,  "kind":"note"}"#.into(),
        };
        primary.append(&first).unwrap();
        append_all(&mut primary, "s1", 1, &["two", "three"]);
        let envs = primary.page("s1", 0, 10).unwrap();

        let mut member = Store::open_in_memory().unwrap();
        let tip = apply_all(&mut member, &envs);
        assert_eq!(member.page("s1", 0, 10).unwrap(), envs, "byte for byte");
        assert_eq!(
            tip,
            primary.tip("s1").unwrap().unwrap(),
            "the same (seq, hash)"
        );
        assert_eq!(tip.hash, envs[2].hash());
        // Indexed as it would be on the primary.
        assert_eq!(member.search("kept", None, 10).unwrap().len(), 1);
    }

    #[test]
    fn apply_refuses_a_gap_a_broken_link_and_a_stale_fence() {
        let mut s = Store::open_in_memory().unwrap();
        let tip = apply_all(&mut s, &sent("s1", None, 3, &["a", "b"]));

        let mut gap = sent("s1", Some(tip), 3, &["ghostgap"]).remove(0);
        gap.seq = 4;
        assert!(matches!(
            s.apply(&gap),
            Err(StoreError::Chain(ChainError::Gap {
                expected: 3,
                got: 4
            }))
        ));

        let mut broken = sent("s1", Some(tip), 3, &["ghostbroken"]).remove(0);
        broken.prev_hash = [7; 32];
        assert!(matches!(
            s.apply(&broken),
            Err(StoreError::Chain(ChainError::Broken { seq: 3 }))
        ));

        let stale = sent("s1", Some(tip), 2, &["ghoststale"]).remove(0);
        assert!(matches!(
            s.apply(&stale),
            Err(StoreError::Chain(ChainError::StaleFence {
                current: 3,
                got: 2
            }))
        ));

        assert_eq!(s.tip("s1").unwrap(), Some(tip), "the tip did not move");
        assert_eq!(s.page("s1", 0, 10).unwrap().len(), 2);
        for word in ["ghostgap", "ghostbroken", "ghoststale"] {
            assert!(s.search(word, None, 10).unwrap().is_empty(), "{word}");
        }
    }

    #[test]
    fn the_floor_refuses_an_older_fence_from_an_apply_and_from_an_append() {
        let mut s = Store::open_in_memory().unwrap();
        let tip = apply_all(&mut s, &sent("s1", None, 1, &["one", "two"]));
        assert_eq!(s.raise_floor("s1", 2).unwrap(), 2);

        // The old primary's next event: fence 1 still follows the tip's, but
        // not the floor.
        let late = sent("s1", Some(tip), 1, &["latecomer"]).remove(0);
        assert!(matches!(
            s.apply(&late),
            Err(StoreError::Chain(ChainError::StaleFence {
                current: 2,
                got: 1
            }))
        ));
        // This device's own event at the old fence: the same.
        assert!(matches!(
            s.append(&late),
            Err(StoreError::Chain(ChainError::StaleFence {
                current: 2,
                got: 1
            }))
        ));
        assert_eq!(s.tip("s1").unwrap(), Some(tip));
        assert!(s.search("latecomer", None, 10).unwrap().is_empty());

        // The new primary's first event continues the chain.
        let next = sent("s1", Some(tip), 2, &["resumed"]).remove(0);
        assert_eq!(s.apply(&next).unwrap().seq, 3);
    }

    #[test]
    fn a_floor_raised_before_any_event_holds_for_the_first() {
        let mut s = Store::open_in_memory().unwrap();
        s.raise_floor("s1", 3).unwrap();
        let at_2 = sent("s1", None, 2, &["early"]).remove(0);
        assert!(matches!(
            s.apply(&at_2),
            Err(StoreError::Chain(ChainError::StaleFence {
                current: 3,
                got: 2
            }))
        ));
        let at_3 = sent("s1", None, 3, &["first"]).remove(0);
        assert_eq!(s.apply(&at_3).unwrap().seq, 1);
    }

    #[test]
    fn the_floor_only_rises() {
        let mut s = Store::open_in_memory().unwrap();
        assert_eq!(s.floor("s1").unwrap(), None);
        assert_eq!(s.raise_floor("s1", 3).unwrap(), 3);
        assert_eq!(s.raise_floor("s1", 2).unwrap(), 3, "a lower word keeps it");
        assert_eq!(s.floor("s1").unwrap(), Some(3));
        assert_eq!(s.raise_floor("s1", 5).unwrap(), 5);
        assert_eq!(s.floor("s2").unwrap(), None, "per session");
    }

    #[test]
    fn a_purged_session_is_refused_with_purged_and_cannot_come_back() {
        let mut s = Store::open_in_memory().unwrap();
        let envs = sent("s1", None, 1, &["one", "two", "three"]);
        apply_all(&mut s, &envs[..2]);
        s.purge("s1").unwrap();
        assert!(s.is_purged("s1").unwrap());
        assert!(!s.is_purged("s2").unwrap());

        let purged = |r: Result<_, StoreError>| matches!(r, Err(StoreError::Purged { .. }));
        // The stream it had, resumed where it stopped, or replayed from the start.
        assert!(purged(s.apply(&envs[2]).map(|_| ())));
        assert!(purged(s.apply(&envs[0]).map(|_| ())));
        // The device's own append, a floor, a set-aside, a blob.
        let own = EventEnvelope::next("s1", None, 1, 0, &ev("own"));
        assert!(purged(s.append(&own).map(|_| ())));
        assert!(purged(s.raise_floor("s1", 2).map(|_| ())));
        assert!(purged(s.set_aside_after("s1", 0).map(|_| ())));
        assert!(purged(s.put_blob("s1", b"chunk").map(|_| ())));
        assert!(purged(s.put_named_blob(
            "s1",
            &blob_hash(b"chunk"),
            b"chunk"
        )));

        assert_eq!(s.tip("s1").unwrap(), None, "nothing came back");
        assert!(s.page("s1", 0, 10).unwrap().is_empty());
        assert!(s.sessions().unwrap().is_empty());
        assert_eq!(s.floor("s1").unwrap(), None);
    }

    /// FR-90 P2k-3 — a leaving member's copy, purged: everything the session
    /// held goes as with a purge, but not its id, so the same stream from the
    /// start is taken again as a copy from nothing. A session purged for good
    /// stays so, whatever a copy's purge says after.
    #[test]
    fn a_leaving_members_copy_goes_whole_and_may_be_taken_again() {
        let mut s = Store::open_in_memory().unwrap();
        let envs = sent("s1", None, 1, &["one", "two", "three"]);
        apply_all(&mut s, &envs[..2]);
        s.raise_floor("s1", 2).unwrap();
        s.put_blob("s1", b"s1 alone").unwrap();
        assert_eq!(s.purge_copy("s1").unwrap(), 2, "its two events");
        assert!(!s.is_purged("s1").unwrap(), "no id kept: not gone for good");
        assert!(!s.holds("s1").unwrap(), "nothing of it held");
        for table in ["events", "tips", "floors", "blob_refs"] {
            assert_eq!(
                count(
                    &s,
                    &format!("SELECT count(*) FROM {table} WHERE session = 's1'")
                ),
                0,
                "{table}"
            );
        }

        apply_all(&mut s, &envs);
        assert_eq!(
            s.tip("s1").unwrap().map(|t| t.seq),
            Some(3),
            "taken again, whole"
        );

        s.purge("s1").unwrap();
        s.purge_copy("s1").unwrap();
        assert!(
            s.is_purged("s1").unwrap(),
            "a removal that was final stays final"
        );
    }

    #[test]
    fn purge_keeps_the_id_and_when_and_removes_all_the_session_held() {
        let mut s = Store::open_in_memory().unwrap();
        apply_all(&mut s, &sent("s1", None, 1, &["one", "two", "cutword"]));
        s.raise_floor("s1", 2).unwrap();
        assert_eq!(s.set_aside_after("s1", 2).unwrap(), 1);
        let only_mine = s.put_blob("s1", b"s1 alone").unwrap();
        let shared = s.put_blob("s1", b"both").unwrap();
        append_all(&mut s, "s2", 1, &["other"]);
        s.put_blob("s2", b"both").unwrap();

        assert_eq!(s.purge("s1").unwrap(), 3, "two events and one set aside");
        let when: i64 = s
            .conn
            .query_row(
                "SELECT purged_ms FROM purged WHERE session = 's1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(when > 1_700_000_000_000, "{when}");
        for table in ["events", "divergent", "tips", "floors", "blob_refs"] {
            assert_eq!(
                count(
                    &s,
                    &format!("SELECT count(*) FROM {table} WHERE session = 's1'")
                ),
                0,
                "{table}"
            );
        }
        assert_eq!(
            count(&s, "SELECT count(*) FROM events_fts WHERE session = 's1'"),
            0
        );
        // A blob only s1 held is gone; one s2 holds too stays, for s2.
        assert!(!s.has_blob("s1", &only_mine).unwrap());
        assert!(!s.has_blob("s1", &shared).unwrap());
        assert!(s.has_blob("s2", &shared).unwrap());
        assert_eq!(count(&s, "SELECT count(*) FROM blobs"), 1);
        assert_eq!(s.tip("s2").unwrap().map(|t| t.seq), Some(1));

        // Purging again changes nothing, and keeps the first time.
        assert_eq!(s.purge("s1").unwrap(), 0);
        let again: i64 = s
            .conn
            .query_row(
                "SELECT purged_ms FROM purged WHERE session = 's1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(again, when);
    }

    /// FR-90 P2g-3d — a word is kept per session, the newest over the one
    /// before, never for a purged session, and goes with its purge. The
    /// device's contact is one row, and the held sessions are every one the
    /// store holds anything of, none purged.
    #[test]
    fn a_word_is_kept_per_held_session_and_goes_with_its_purge() {
        let mut s = Store::open_in_memory().unwrap();
        assert!(s.retains().unwrap().is_empty());
        s.put_retain("s1", 90, None).unwrap();
        s.put_retain("s1", 30, Some(5_000)).unwrap();
        s.put_retain("s2", 0, None).unwrap();
        let words = s.retains().unwrap();
        assert_eq!(
            words
                .iter()
                .map(|w| (w.session.as_str(), w.days, w.ended_ms))
                .collect::<Vec<_>>(),
            [("s1", 30, Some(5_000)), ("s2", 0, None)],
            "the newest word over the one before"
        );
        assert!(words.iter().all(|w| w.said_ms > 1_700_000_000_000));
        s.purge("s1").unwrap();
        assert_eq!(s.retains().unwrap().len(), 1, "the purge took its word");
        s.put_retain("s1", 90, None).unwrap();
        assert_eq!(s.retains().unwrap().len(), 1, "a purged session keeps none");
        s.drop_retain("s2").unwrap();
        assert!(s.retains().unwrap().is_empty());

        assert_eq!(s.contact().unwrap(), None);
        s.set_contact(1_000).unwrap();
        s.set_contact(2_000).unwrap();
        assert_eq!(s.contact().unwrap(), Some(2_000));

        append_all(&mut s, "s3", 1, &["one"]);
        s.join("s4", "owner", 1, &[]).unwrap();
        assert_eq!(s.held_sessions().unwrap(), ["s3", "s4"], "s1 is purged");
    }

    /// FR-90 P2g-3d — a copy the device's clock purged is named in at most
    /// `max` manifests, oldest first and `limit` at a time, its first time
    /// kept, then forgotten.
    #[test]
    fn a_copy_purged_on_the_clock_is_named_in_its_next_manifests() {
        let mut s = Store::open_in_memory().unwrap();
        assert!(!s.has_copy_purge_reports().unwrap());
        s.note_copy_purge("b", 20).unwrap();
        s.note_copy_purge("a", 10).unwrap();
        s.note_copy_purge("a", 99).unwrap();
        assert!(s.has_copy_purge_reports().unwrap());
        let named = |v: &[(&str, i64)]| -> Vec<(String, i64)> {
            v.iter().map(|(s, t)| (s.to_string(), *t)).collect()
        };
        assert_eq!(
            s.take_copy_purge_reports(1, 3).unwrap(),
            named(&[("a", 10)]),
            "the oldest first, at its first time"
        );
        assert_eq!(
            s.take_copy_purge_reports(8, 3).unwrap(),
            named(&[("a", 10), ("b", 20)])
        );
        assert_eq!(
            s.take_copy_purge_reports(8, 3).unwrap(),
            named(&[("a", 10), ("b", 20)])
        );
        assert_eq!(
            s.take_copy_purge_reports(8, 3).unwrap(),
            named(&[("b", 20)]),
            "a has been named in three manifests"
        );
        assert!(
            !s.has_copy_purge_reports().unwrap(),
            "each named in three manifests, then forgotten"
        );
    }

    /// FR-90 P2f-2a — a substitute is kept only once its blobs are, replaces
    /// one kept for the same commit, is the session's alone, and goes with
    /// the purge; a purged session keeps none.
    #[test]
    fn a_substitute_is_kept_only_with_its_blobs_and_goes_with_the_purge() {
        use crate::checkpoint::Digest;
        let mut s = Store::open_in_memory().unwrap();
        let held = s.put_blob("s1", b"pack bytes").unwrap();
        let chunk = |hash: [u8; 32], len: u64| Chunk {
            offset: 0,
            len,
            hash: Digest(hash),
        };
        let sub = Substitute {
            commit: "c".repeat(40),
            against: vec!["a".repeat(40)],
            chunks: vec![chunk(held, 10)],
        };
        let missing = Substitute {
            chunks: vec![chunk(blob_hash(b"never kept"), 10)],
            ..sub.clone()
        };
        let refused =
            |r: Result<(), StoreError>| matches!(r, Err(StoreError::SubstituteBlobMissing { .. }));
        assert!(
            refused(s.put_substitute("s1", &missing)),
            "a substitute without its blob is refused"
        );
        assert_eq!(s.substitute("s1", &sub.commit).unwrap(), None);
        assert!(
            refused(s.put_substitute("s2", &sub)),
            "another session's blob is not this one's"
        );

        s.put_substitute("s1", &sub).unwrap();
        assert_eq!(s.substitute("s1", &sub.commit).unwrap(), Some(sub.clone()));
        assert_eq!(s.substitute("s1", &"d".repeat(40)).unwrap(), None);
        assert_eq!(s.substitute("s2", &sub.commit).unwrap(), None);
        let whole = Substitute {
            against: Vec::new(),
            ..sub.clone()
        };
        s.put_substitute("s1", &whole).unwrap();
        assert_eq!(
            s.substitute("s1", &sub.commit).unwrap(),
            Some(whole),
            "replaced, not added beside"
        );

        s.purge("s1").unwrap();
        assert_eq!(
            count(&s, "SELECT count(*) FROM substitutes"),
            0,
            "the purge takes them"
        );
        assert_eq!(s.substitute("s1", &sub.commit).unwrap(), None);
        assert!(matches!(
            s.put_substitute("s1", &sub),
            Err(StoreError::Purged { .. })
        ));
    }

    /// FR-90 P2f-2c — a whole pack this store keeps a substitute for and not
    /// every blob of is a stand-in, the oldest kept first, at most the limit;
    /// a whole pack whose blobs are all here, a thin pack's commit and a
    /// substitute no whole pack names are not. Where a session is worked on
    /// is kept per session, a later launch's in its place, and goes with the
    /// purge.
    #[test]
    fn a_stand_in_is_a_whole_pack_held_only_as_a_substitute() {
        use crate::checkpoint::{Checkpoint, RepoKind, WorkspaceSnap, chunk_bytes};
        use crate::event::TranscriptEvent;
        let mut s = Store::open_in_memory().unwrap();
        let (one, two, thin, four) = (
            "1".repeat(40),
            "2".repeat(40),
            "3".repeat(40),
            "4".repeat(40),
        );
        let ws = |commit: &str, base: Option<&str>, bytes: &[u8]| WorkspaceSnap {
            repo: RepoKind::Own,
            prefix: String::new(),
            tree: "e".repeat(40),
            commit: commit.to_string(),
            base: base.map(str::to_string),
            head: None,
            pack: chunk_bytes(bytes).0,
        };
        let packs = [
            ws(&one, None, b"whole one"),
            ws(&two, None, b"whole two"),
            ws(&thin, Some(&two), b"thin three"),
            ws(&four, None, b"whole four"),
        ];
        for (n, w) in (1..).zip(packs) {
            let cp = Checkpoint {
                n,
                turn: 1,
                files: Vec::new(),
                skipped: Vec::new(),
                workspace: Some(w),
            };
            let tip = s.tip("s1").unwrap();
            let env = EventEnvelope::next("s1", tip, 1, 0, &TranscriptEvent::Checkpoint(cp));
            s.append(&env).unwrap();
        }
        // Whole two's own blob is here; whole one's and four's are not.
        s.put_blob("s1", b"whole two").unwrap();
        for (commit, bytes) in [
            (&one, &b"for one"[..]),
            (&two, b"for two"),
            (&thin, b"for three"),
            (&four, b"for four"),
            (&"9".repeat(40), b"for nothing"),
        ] {
            s.put_blob("s1", bytes).unwrap();
            let sub = Substitute {
                commit: commit.clone(),
                against: Vec::new(),
                chunks: chunk_bytes(bytes).0,
            };
            s.put_substitute("s1", &sub).unwrap();
        }
        assert_eq!(
            s.stand_ins("s1", crate::stream::MAX_WANTS).unwrap(),
            vec![one.clone(), four.clone()],
            "the whole packs held only as substitutes"
        );
        assert_eq!(
            s.stand_ins("s1", 1).unwrap(),
            vec![one.clone()],
            "the limit"
        );
        assert!(
            s.stand_ins("s2", crate::stream::MAX_WANTS)
                .unwrap()
                .is_empty()
        );

        let w = WorkplaceRecord {
            account: "dev".into(),
            folder: "/srv/app".into(),
            state_dir: "/var/lib/meshharbor/hive/s1".into(),
        };
        assert_eq!(s.workplace("s1").unwrap(), None);
        s.put_workplace("s1", &w).unwrap();
        assert_eq!(s.workplace("s1").unwrap(), Some(w.clone()));
        let later = WorkplaceRecord {
            folder: "/srv/elsewhere".into(),
            ..w.clone()
        };
        s.put_workplace("s1", &later).unwrap();
        assert_eq!(
            s.workplace("s1").unwrap(),
            Some(later),
            "a later launch's, in its place"
        );
        assert_eq!(s.workplace("s2").unwrap(), None);

        assert!(s.holds("s1").unwrap() && !s.holds("s9").unwrap());
        assert_eq!(s.purge_debt("s1").unwrap(), None, "no purge yet: no debt");
        s.purge("s1").unwrap();
        assert_eq!(s.workplace("s1").unwrap(), None, "the purge takes it");
        assert!(!s.holds("s1").unwrap(), "nothing of it is held");
        assert!(
            s.stand_ins("s1", crate::stream::MAX_WANTS)
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            s.put_workplace("s1", &w),
            Err(StoreError::Purged { .. })
        ));
        // P2g-1 — and where it was worked on outlives it, as the account's
        // debt, until the account's part is done; a purge again keeps it.
        let later = WorkplaceRecord {
            folder: "/srv/elsewhere".into(),
            ..w.clone()
        };
        assert_eq!(s.purge_debt("s1").unwrap(), Some(later.clone()));
        s.purge("s1").unwrap();
        assert_eq!(s.purge_debt("s1").unwrap(), Some(later), "kept");
        s.clear_purge_debt("s1").unwrap();
        assert_eq!(s.purge_debt("s1").unwrap(), None, "settled");
        assert_eq!(s.purge_debt("s2").unwrap(), None, "never worked on here");
    }

    #[test]
    fn an_older_fences_tail_is_set_aside_and_the_chain_goes_on_at_the_floor() {
        let mut s = Store::open_in_memory().unwrap();
        let envs = sent(
            "s1",
            None,
            1,
            &["one", "two", "three", "cutfour", "cutfive"],
        );
        apply_all(&mut s, &envs);
        s.raise_floor("s1", 2).unwrap();

        assert_eq!(s.set_aside_after("s1", 3).unwrap(), 2);
        let tip = s.tip("s1").unwrap().unwrap();
        assert_eq!(tip, envs[2].tip(), "the event at seq 3 is the tip again");
        assert_eq!(s.page("s1", 0, 10).unwrap(), envs[..3].to_vec());
        assert!(s.search("cutfour", None, 10).unwrap().is_empty());
        assert!(s.search("cutfive", None, 10).unwrap().is_empty());

        // The tail is kept as it was.
        let kept: Vec<(i64, i64, Vec<u8>, String)> = s
            .conn
            .prepare("SELECT seq, fence, hash, event_json FROM divergent WHERE session = 's1' ORDER BY seq")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(kept.len(), 2);
        for ((seq, fence, hash, json), env) in kept.iter().zip(&envs[3..]) {
            assert_eq!(*seq as u64, env.seq);
            assert_eq!(*fence as u64, env.fence);
            assert_eq!(hash.as_slice(), env.hash().as_slice());
            assert_eq!(json, &env.event_json);
        }

        // The new primary's events continue from seq 3, at the floor's fence.
        let after = sent("s1", Some(tip), 2, &["newfour"]);
        assert_eq!(s.apply(&after[0]).unwrap().seq, 4);
        assert_eq!(s.search("newfour", None, 10).unwrap().len(), 1);
    }

    #[test]
    fn a_tail_of_the_floors_fence_is_never_set_aside() {
        let mut s = Store::open_in_memory().unwrap();
        let old = sent("s1", None, 1, &["one", "two"]);
        let tip = apply_all(&mut s, &old);
        s.raise_floor("s1", 2).unwrap();
        // The current primary's events, at the floor's fence.
        apply_all(&mut s, &sent("s1", Some(tip), 2, &["three", "fourword"]));

        assert!(matches!(
            s.set_aside_after("s1", 1),
            Err(StoreError::NotOlderThanFloor {
                seq: 3,
                fence: 2,
                floor: 2,
                ..
            })
        ));
        // Nothing moved.
        assert_eq!(s.tip("s1").unwrap().map(|t| t.seq), Some(4));
        assert_eq!(s.page("s1", 0, 10).unwrap().len(), 4);
        assert_eq!(count(&s, "SELECT count(*) FROM divergent"), 0);
        assert_eq!(s.search("fourword", None, 10).unwrap().len(), 1);
        // A fence newer than the floor is the current primary's too.
        let mut t = Store::open_in_memory().unwrap();
        let tip = apply_all(&mut t, &sent("s1", None, 1, &["one"]));
        t.raise_floor("s1", 2).unwrap();
        apply_all(&mut t, &sent("s1", Some(tip), 3, &["newer"]));
        assert!(matches!(
            t.set_aside_after("s1", 1),
            Err(StoreError::NotOlderThanFloor {
                seq: 2,
                fence: 3,
                floor: 2,
                ..
            })
        ));
    }

    #[test]
    fn nothing_is_set_aside_without_a_floor_or_past_the_tip() {
        let mut s = Store::open_in_memory().unwrap();
        apply_all(&mut s, &sent("s1", None, 1, &["one", "two"]));
        assert!(matches!(
            s.set_aside_after("s1", 1),
            Err(StoreError::NoFloor { .. })
        ));
        s.raise_floor("s1", 2).unwrap();
        assert!(matches!(
            s.set_aside_after("s1", 3),
            Err(StoreError::NotHeld { seq: 3, tip: 2, .. })
        ));
        assert_eq!(
            s.set_aside_after("s1", 2).unwrap(),
            0,
            "nothing after the tip"
        );
        assert_eq!(s.tip("s1").unwrap().map(|t| t.seq), Some(2));
    }

    #[test]
    fn setting_aside_from_zero_leaves_no_events_and_a_chain_from_genesis() {
        let mut s = Store::open_in_memory().unwrap();
        apply_all(&mut s, &sent("s1", None, 1, &["one", "two"]));
        s.raise_floor("s1", 2).unwrap();
        assert_eq!(s.set_aside_after("s1", 0).unwrap(), 2);
        assert_eq!(s.tip("s1").unwrap(), None);
        assert!(s.sessions().unwrap().is_empty());
        let fresh = sent("s1", None, 2, &["first again"]).remove(0);
        assert_eq!(fresh.prev_hash, GENESIS);
        assert_eq!(s.apply(&fresh).unwrap().seq, 1);
    }

    #[test]
    fn a_blob_round_trips_under_its_blake3_name() {
        let mut s = Store::open_in_memory().unwrap();
        let bytes = b"a chunk of a session's history".to_vec();
        let hash = s.put_blob("s1", &bytes).unwrap();
        assert_eq!(hash, *blake3::hash(&bytes).as_bytes());
        assert!(s.has_blob("s1", &hash).unwrap());
        assert_eq!(s.get_blob("s1", &hash).unwrap(), Some(bytes.clone()));
        // The same bytes sent by a peer under their own name: kept, once.
        s.put_named_blob("s1", &hash, &bytes).unwrap();
        assert_eq!(count(&s, "SELECT count(*) FROM blobs"), 1);
        // An empty blob is a blob.
        let empty = s.put_blob("s1", b"").unwrap();
        assert_eq!(s.get_blob("s1", &empty).unwrap(), Some(Vec::new()));
        // Absent is absent.
        assert_eq!(s.get_blob("s1", &[9; 32]).unwrap(), None);
        assert!(!s.has_blob("s1", &[9; 32]).unwrap());
    }

    #[test]
    fn a_blob_that_does_not_hash_to_its_name_is_never_stored() {
        let mut s = Store::open_in_memory().unwrap();
        let bytes = b"what the peer sent";
        let named = blob_hash(b"what the event names");
        let err = s.put_named_blob("s1", &named, bytes).unwrap_err();
        assert!(matches!(err, StoreError::BlobMismatch { .. }), "{err}");
        // Under neither name.
        assert!(!s.has_blob("s1", &named).unwrap());
        assert!(!s.has_blob("s1", &blob_hash(bytes)).unwrap());
        assert_eq!(count(&s, "SELECT count(*) FROM blobs"), 0);
        assert_eq!(count(&s, "SELECT count(*) FROM blob_refs"), 0);
    }

    #[test]
    fn a_tampered_blob_is_refused_when_read_and_mended_by_its_bytes() {
        let mut s = Store::open_in_memory().unwrap();
        let bytes = b"checkpoint pack".to_vec();
        let hash = s.put_blob("s1", &bytes).unwrap();
        s.conn
            .execute(
                "UPDATE blobs SET data = ?1 WHERE hash = ?2",
                params![b"checkpoint pAck".as_slice(), hash.as_slice()],
            )
            .unwrap();
        assert!(matches!(
            s.get_blob("s1", &hash),
            Err(StoreError::CorruptBlob { .. })
        ));
        // The right bytes, put again, mend it.
        s.put_blob("s1", &bytes).unwrap();
        assert_eq!(s.get_blob("s1", &hash).unwrap(), Some(bytes));
    }

    #[test]
    fn a_blob_is_read_only_by_the_sessions_that_hold_it() {
        let mut s = Store::open_in_memory().unwrap();
        let hash = s.put_blob("s1", b"s1's history").unwrap();
        assert!(!s.has_blob("s2", &hash).unwrap());
        assert_eq!(s.get_blob("s2", &hash).unwrap(), None);
        s.put_blob("s2", b"s1's history").unwrap();
        assert!(s.has_blob("s2", &hash).unwrap());
        assert_eq!(count(&s, "SELECT count(*) FROM blobs"), 1, "stored once");
    }

    #[test]
    fn a_blob_over_the_limit_is_refused() {
        let mut s = Store::open_in_memory().unwrap();
        let big = vec![0u8; MAX_BLOB_BYTES + 1];
        assert!(matches!(
            s.put_blob("s1", &big),
            Err(StoreError::BlobTooLarge(n)) if n == MAX_BLOB_BYTES + 1
        ));
        assert_eq!(count(&s, "SELECT count(*) FROM blobs"), 0);
    }

    /// What a daemon from before P2a runs on the store it opens: P0a's own
    /// statements (`287b496b7`, the only schema a released daemon wrote),
    /// verbatim. ⚠️ Frozen on purpose: a rolled-back daemon runs ITS copy,
    /// not this build's, so never edit these to match the current code.
    mod p0a {
        use super::*;

        const INIT: &str = "CREATE TABLE IF NOT EXISTS events (
                 session    TEXT    NOT NULL,
                 seq        INTEGER NOT NULL,
                 fence      INTEGER NOT NULL,
                 ts_ms      INTEGER NOT NULL,
                 prev_hash  BLOB    NOT NULL,
                 hash       BLOB    NOT NULL,
                 kind       TEXT,
                 event_json TEXT    NOT NULL,
                 PRIMARY KEY (session, seq)
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS tips (
                 session TEXT PRIMARY KEY,
                 seq     INTEGER NOT NULL,
                 hash    BLOB    NOT NULL,
                 fence   INTEGER NOT NULL
             ) WITHOUT ROWID;
             CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                 text,
                 session UNINDEXED,
                 seq UNINDEXED,
                 tokenize = 'unicode61 remove_diacritics 2'
             );";

        /// P0a's `Store::open`: refuse a newer schema, make its tables, mark
        /// the file as schema 1.
        pub fn open(path: &Path) -> Connection {
            let conn = Connection::open(path).unwrap();
            conn.pragma_update(None, "journal_mode", "WAL").unwrap();
            conn.pragma_update(None, "synchronous", "NORMAL").unwrap();
            let found: i64 = conn
                .pragma_query_value(None, "user_version", |r| r.get(0))
                .unwrap();
            assert!(
                found <= 1,
                "a daemon from before P2a refuses schema {found}"
            );
            conn.execute_batch(INIT).unwrap();
            conn.pragma_update(None, "user_version", 1).unwrap();
            conn
        }

        pub fn tip(conn: &Connection, session: &str) -> Option<ChainTip> {
            conn.query_row(
                "SELECT seq, hash, fence FROM tips WHERE session = ?1",
                params![session],
                |r| {
                    Ok(ChainTip {
                        seq: r.get::<_, i64>(0)? as u64,
                        hash: r.get::<_, Vec<u8>>(1)?.try_into().unwrap(),
                        fence: r.get::<_, i64>(2)? as u64,
                    })
                },
            )
            .optional()
            .unwrap()
        }

        pub fn page(conn: &Connection, session: &str) -> Vec<EventEnvelope> {
            conn.prepare(
                "SELECT seq, fence, ts_ms, prev_hash, event_json FROM events
             WHERE session = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
            )
            .unwrap()
            .query_map(params![session, 0i64, 1_000i64], |r| {
                Ok(EventEnvelope {
                    session: session.to_string(),
                    seq: r.get::<_, i64>(0)? as u64,
                    fence: r.get::<_, i64>(1)? as u64,
                    ts_ms: r.get(2)?,
                    prev_hash: r.get::<_, Vec<u8>>(3)?.try_into().unwrap(),
                    event_json: r.get(4)?,
                })
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
        }

        pub fn search(conn: &Connection, word: &str) -> Vec<(String, u64)> {
            conn.prepare(
                "SELECT session, seq, snippet(events_fts, 0, '[', ']', '…', 12)
             FROM events_fts WHERE events_fts MATCH ?1 ORDER BY rank LIMIT 100",
            )
            .unwrap()
            .query_map(params![format!("\"{word}\"")], |r| {
                Ok((r.get(0)?, r.get::<_, i64>(1)? as u64))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
        }

        /// P0a's `Store::append`: the tip's check, then the three writes.
        pub fn append(conn: &mut Connection, env: &EventEnvelope) {
            let tx = conn.transaction().unwrap();
            let tip = tip(&tx, &env.session);
            crate::chain::check_next(tip, env).unwrap();
            let next = env.tip();
            let event = env.event();
            tx.execute(
                "INSERT INTO events (session, seq, fence, ts_ms, prev_hash, hash, kind, event_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    env.session,
                    env.seq as i64,
                    env.fence as i64,
                    env.ts_ms,
                    env.prev_hash.as_slice(),
                    next.hash.as_slice(),
                    event.as_ref().map(TranscriptEvent::kind),
                    env.event_json,
                ],
            )
            .unwrap();
            if let Some(text) = event.as_ref().and_then(TranscriptEvent::search_text) {
                tx.execute(
                    "INSERT INTO events_fts (text, session, seq) VALUES (?1, ?2, ?3)",
                    params![text, env.session, env.seq as i64],
                )
                .unwrap();
            }
            tx.execute(
                "INSERT INTO tips (session, seq, hash, fence) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(session) DO UPDATE SET seq = ?2, hash = ?3, fence = ?4",
                params![
                    env.session,
                    next.seq as i64,
                    next.hash.as_slice(),
                    next.fence as i64
                ],
            )
            .unwrap();
            tx.commit().unwrap();
        }
    }

    /// The updater's crash-loop rollback puts a daemon from before P2a back on
    /// a device whose store P2a wrote: a floor, a set-aside tail, a blob, a
    /// purged session. It must open the file, serve every event it holds,
    /// keep appending, and see none of the rest; and the next P2a daemon must
    /// find all of it again.
    #[test]
    fn a_daemon_from_before_p2a_reads_what_p2a_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hive.db");
        let blob;
        {
            let mut s = Store::open(&path).unwrap();
            let old = sent("s1", None, 1, &["alpha", "bravo", "charlie", "stalefour"]);
            apply_all(&mut s, &old);
            s.raise_floor("s1", 2).unwrap();
            assert_eq!(s.set_aside_after("s1", 3).unwrap(), 1);
            apply_all(&mut s, &sent("s1", Some(old[2].tip()), 2, &["newfour"]));
            blob = s.put_blob("s1", b"a history chunk").unwrap();
            append_all(&mut s, "s2", 1, &["purgeword"]);
            s.purge("s2").unwrap();
            // P2c-3 — and a membership.
            s.join("s3", "owner", 1, &[]).unwrap();
        }

        // The rolled-back daemon.
        {
            let mut old = p0a::open(&path);
            let events = p0a::page(&old, "s1");
            assert_eq!(events.len(), 4);
            let mut tip = None;
            for env in &events {
                crate::chain::check_next(tip, env).expect("a whole chain");
                tip = Some(env.tip());
            }
            assert_eq!(p0a::tip(&old, "s1"), tip, "its tip is the chain's end");
            assert_eq!(tip.map(|t| (t.seq, t.fence)), Some((4, 2)));
            assert_eq!(p0a::search(&old, "newfour"), vec![("s1".to_string(), 4)]);
            assert!(
                p0a::search(&old, "stalefour").is_empty(),
                "no stale index row"
            );
            assert!(p0a::search(&old, "purgeword").is_empty());
            assert_eq!(p0a::tip(&old, "s2"), None);
            // It keeps running its session.
            let fifth = EventEnvelope::next("s1", tip, 2, 5, &ev("fifthword"));
            p0a::append(&mut old, &fifth);
            assert_eq!(p0a::search(&old, "fifthword").len(), 1);
        }

        // The next P2a daemon finds everything again.
        let mut s = Store::open(&path).unwrap();
        assert_eq!(s.tip("s1").unwrap().map(|t| t.seq), Some(5));
        assert_eq!(s.page("s1", 0, 10).unwrap().len(), 5);
        assert_eq!(s.floor("s1").unwrap(), Some(2));
        assert_eq!(
            count(&s, "SELECT count(*) FROM divergent WHERE session = 's1'"),
            1
        );
        assert_eq!(
            s.get_blob("s1", &blob).unwrap(),
            Some(b"a history chunk".to_vec())
        );
        assert!(s.is_purged("s2").unwrap());
        assert_eq!(
            s.memberships()
                .unwrap()
                .iter()
                .map(|m| m.session.as_str())
                .collect::<Vec<_>>(),
            ["s3"],
            "the membership survives the rolled-back daemon"
        );
        let replay = sent("s2", None, 1, &["purgeword"]).remove(0);
        assert!(matches!(s.apply(&replay), Err(StoreError::Purged { .. })));
        let user_version: i64 = s
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(user_version, 1);
    }

    /// The other way: a device's P1 store, made by a daemon from before P2a,
    /// opens under P2a with every event, gains the new tables, and its
    /// sessions go on.
    #[test]
    fn a_store_from_before_p2a_opens_and_gains_the_new_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hive.db");
        let mut tip = None;
        {
            let mut old = p0a::open(&path);
            for (i, word) in ["oldone", "oldtwo"].iter().enumerate() {
                let env = EventEnvelope::next("s1", tip, 1, i as i64, &ev(word));
                p0a::append(&mut old, &env);
                tip = Some(env.tip());
            }
        }
        let mut s = Store::open(&path).unwrap();
        assert_eq!(s.tip("s1").unwrap(), tip);
        assert_eq!(s.page("s1", 0, 10).unwrap().len(), 2);
        assert_eq!(s.search("oldtwo", None, 10).unwrap().len(), 1);
        for table in [
            "floors",
            "divergent",
            "blobs",
            "blob_refs",
            "purged",
            "memberships",
        ] {
            assert_eq!(
                count(
                    &s,
                    &format!(
                        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = '{table}'"
                    )
                ),
                1,
                "{table}"
            );
        }
        assert_eq!(append_all(&mut s, "s1", 1, &["newthree"]).seq, 3);
    }

    /// FR-90 P2c-3 — a join raises the floor and records the membership; a
    /// later one moves the role and the fence, and keeps when the first was
    /// made.
    #[test]
    fn a_join_raises_the_floor_and_records_the_membership() {
        let mut s = Store::open_in_memory().unwrap();
        assert_eq!(s.join("s1", "owner", 2, &[]).unwrap(), 2);
        assert_eq!(s.floor("s1").unwrap(), Some(2));
        let first = s.memberships().unwrap();
        assert_eq!(
            first
                .iter()
                .map(|m| (m.session.as_str(), m.role.as_str(), m.fence))
                .collect::<Vec<_>>(),
            [("s1", "owner", 2)]
        );
        // From the join on, an event of an older fence is refused here.
        let old = EventEnvelope::next("s1", None, 1, 0, &ev("from fence one"));
        assert!(s.apply(&old).is_err(), "fence 1 is below the floor");
        assert_eq!(s.join("s1", "archive", 3, &[]).unwrap(), 3);
        let again = s.memberships().unwrap();
        assert_eq!(
            (again[0].role.as_str(), again[0].fence, again[0].joined_ms),
            ("archive", 3, first[0].joined_ms)
        );
        assert_eq!(s.floor("s1").unwrap(), Some(3));
    }

    /// A join older than the floor is refused and changes nothing; a purged
    /// session is never joined, and a purge ends a membership.
    #[test]
    fn a_stale_or_purged_join_is_refused_and_a_purge_ends_a_membership() {
        let mut s = Store::open_in_memory().unwrap();
        s.raise_floor("s1", 4).unwrap();
        assert!(matches!(
            s.join("s1", "owner", 3, &[]),
            Err(StoreError::StaleJoin {
                floor: 4,
                fence: 3,
                ..
            })
        ));
        assert!(s.memberships().unwrap().is_empty());
        assert_eq!(s.floor("s1").unwrap(), Some(4), "the floor never falls");
        s.join("s2", "owner", 1, &[]).unwrap();
        s.purge("s2").unwrap();
        assert!(s.memberships().unwrap().is_empty(), "a purge ends it");
        assert!(matches!(
            s.join("s2", "owner", 2, &[]),
            Err(StoreError::Purged { .. })
        ));
        assert!(s.size_bytes().unwrap() > 0);
    }

    /// FR-90 P2e-5b — a member that joins after a move syncs the history
    /// below its floor: the join keeps where fence 1 ended, and fence 1's
    /// events are taken up to there, then the new fence's. A later join that
    /// names no end takes none away; a purge does.
    #[test]
    fn a_join_after_a_move_takes_the_old_fences_history_up_to_its_end() {
        // The history as the primaries wrote it: three events at fence 1,
        // then the promoted primary's at fence 2.
        let mut src = Store::open_in_memory().unwrap();
        append_all(&mut src, "s1", 1, &["one", "two", "three"]);
        let end_tip = src.tip("s1").unwrap().unwrap();
        append_all(&mut src, "s1", 2, &["four"]);
        let history = src.page("s1", 0, 100).unwrap();

        let end = FenceEnd {
            fence: 1,
            seq: end_tip.seq,
            hash: end_tip.hash,
        };
        let mut m = Store::open_in_memory().unwrap();
        m.join("s1", "owner", 2, &[]).unwrap();
        assert!(
            matches!(
                m.apply(&history[0]),
                Err(StoreError::Chain(ChainError::StaleFence {
                    current: 2,
                    got: 1
                }))
            ),
            "before P2e-5b: the history below the floor, refused for good"
        );
        m.join("s1", "owner", 2, &[end]).unwrap();
        assert_eq!(
            m.fence_ends("s1").unwrap(),
            [end],
            "the join keeps fence 1's end"
        );
        for env in &history {
            m.apply(env).unwrap_or_else(|e| {
                panic!("below the floor, up to fence 1's end: seq {}: {e}", env.seq)
            });
        }
        assert_eq!(m.tip("s1").unwrap(), src.tip("s1").unwrap(), "all of it");

        // An old primary's late write past where its fence ended: refused.
        let mut behind = Store::open_in_memory().unwrap();
        behind.join("s1", "owner", 2, &[end]).unwrap();
        for env in &history[..3] {
            behind.apply(env).unwrap();
        }
        let late = EventEnvelope::next("s1", behind.tip("s1").unwrap(), 1, 9, &ev("late"));
        assert!(matches!(
            behind.apply(&late),
            Err(StoreError::Chain(ChainError::StaleFence { .. }))
        ));

        // A join that names no end keeps the ones held; a purge drops them.
        m.join("s1", "archive", 3, &[]).unwrap();
        assert_eq!(m.fence_ends("s1").unwrap(), [end], "never taken away");
        m.purge("s1").unwrap();
        assert!(m.fence_ends("s1").unwrap().is_empty(), "a purge drops them");
    }
}
