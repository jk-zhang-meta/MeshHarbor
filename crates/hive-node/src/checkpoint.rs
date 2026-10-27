// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2b — what a checkpoint takes of a session's config directory, and how
//! a member puts it back together.
//!
//! At each turn's end the primary checkpoints its session: the five allowlisted
//! paths of Claude Code's config directory ([`allowlist`]; a fork's eight,
//! [`allowlist_of`]), and later in P2b the workspace. The daemon never reads a
//! path the session's account controls, so
//! [`take`] runs AS THE ACCOUNT, in `meshharbord hive-checkpoint` (P2b-3). What it
//! produces is a [`Checkpoint`], recorded in the chain as a `checkpoint` event
//! (so two members at the same `(seq, hash)` hold the same files), and the
//! blobs it names, each BLAKE3-named as the replica store keeps them.
//!
//! Two shapes of file, as P2b's probes found Claude Code writes them (spec §8):
//!
//! | File | How Claude Code writes it | How a checkpoint takes it |
//! |---|---|---|
//! | the history `<id>.jsonl`, a sub-agent's `agent-<id>.jsonl` | only appended to (`O_APPEND`) | the bytes past the last checkpoint, up to the last whole line |
//! | everything else in the allowlist | replaced (a rename), or written once | whole, by hash, and only when it changed |
//!
//! The chain is the state: a file's `len` and `hash` in the last checkpoint are
//! where the next one starts ([`Previous`]), so nothing else is kept between
//! turns. A file that shrank, or changed before its last offset, is taken again
//! from its first byte, and the checkpoint says so.
//!
//! ⚠️ **An allowlist, never the directory.** The config directory's root holds a
//! `peerToken` beside the harness's messaging socket and a `machineID` (§3b's
//! probes). Nothing outside the allowlist's paths is ever opened.
//!
//! ⚠️ **A link is never followed.** The allowlist holds Claude Code's own files;
//! a link there to the account's `~/.ssh` would copy a key to every member. A
//! link, or a name that is not UTF-8, is listed in [`Checkpoint::skipped`] and
//! taken nowhere.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The most one chunk holds. Well under the store's blob limit
/// ([`crate::store::MAX_BLOB_BYTES`]), so a member carries and checks each one
/// in memory.
pub const CHUNK_MAX: usize = 4 * 1024 * 1024;

/// The most files one checkpoint lists: a session's tool results accumulate,
/// and a directory with more than this is not Claude Code's.
pub const MAX_FILES: usize = 10_000;

/// The most NEW bytes one checkpoint takes. A first checkpoint of a long
/// history is tens of MB at most; past this, something other than a session
/// is in the allowlist.
pub const MAX_NEW_BYTES: u64 = 512 * 1024 * 1024;

/// How deep a directory in the allowlist is walked, by [`take`] and by a
/// target clearing what a checkpoint no longer lists (P2b-4): the same depth,
/// so neither touches what the other cannot see.
pub const MAX_DEPTH: usize = 8;

/// A BLAKE3 hash, as `b3sum` prints it on the wire.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    /// The hash of `bytes`, which is also the name the store keeps them under
    /// ([`crate::store::blob_hash`]).
    pub fn of(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    fn of_hasher(h: &blake3::Hasher) -> Self {
        Self(*h.finalize().as_bytes())
    }

    /// The hash from its 64 lowercase hex digits.
    pub fn parse(hex: &str) -> Option<Self> {
        if hex.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
            let digit = |c: u8| match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                _ => None,
            };
            out[i] = digit(pair[0])? << 4 | digit(pair[1])?;
        }
        Some(Self(out))
    }
}

/// A [`Digest`] of bytes that arrive in pieces: how a target checks a file it
/// is streamed (P2b-4).
pub struct Hasher(blake3::Hasher);

impl Hasher {
    pub fn new() -> Self {
        Self(blake3::Hasher::new())
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    pub fn finish(&self) -> Digest {
        Digest::of_hasher(&self.0)
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({self})")
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).ok_or_else(|| serde::de::Error::custom("not a BLAKE3 hash"))
    }
}

/// One piece of a file, kept as a blob named by its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    /// Where in the file it starts.
    pub offset: u64,
    pub len: u64,
    pub hash: Digest,
}

/// How a file is taken ([`snapshot_append`], [`snapshot_whole`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Growth {
    /// Only ever appended to: the new bytes, up to the last whole line.
    Append,
    /// Replaced or written once: the whole file, when it changed.
    Whole,
}

/// One allowlisted file, as this checkpoint has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSnap {
    /// Relative to the config directory, `/`-separated on every OS.
    pub path: String,
    pub growth: Growth,
    /// Unix permission bits (at most `0o777`); 0 where the OS keeps none.
    pub mode: u32,
    /// The bytes this checkpoint covers: for an appended file, up to its last
    /// whole line, so a member never holds half a line.
    pub len: u64,
    /// The BLAKE3 hash of those bytes.
    pub hash: Digest,
    /// The blobs this checkpoint adds for the file: an appended file's new
    /// bytes, or a changed file whole. Empty when it is as the last checkpoint
    /// had it. A chunk at offset 0 starts the file over.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<Chunk>,
}

/// A file in the allowlist this checkpoint did not take, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    pub path: String,
    pub why: String,
}

/// Where a checkpoint's workspace commit is written (P2b-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoKind {
    /// The repository the folder is in: the commit is written there, under
    /// `refs/hive/<sid>/head`, and nothing else of the person's changes.
    Own,
    /// A folder in no repository: a private bare repository in the session's
    /// state directory, never a `.git` inside the person's folder.
    Shadow,
}

/// The workspace as one checkpoint has it (P2b-2): a git commit of the
/// folder's tree, written through a temporary index by the account's own git,
/// and the pack that carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceSnap {
    pub repo: RepoKind,
    /// The folder's place in its repository (`git rev-parse --show-prefix`),
    /// `/`-terminated; empty at the repository's top, and in a shadow.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prefix: String,
    /// The folder's tree, as git names it.
    pub tree: String,
    /// The commit `refs/hive/<sid>/head` points at: its tree is `tree`, and
    /// its parent the last checkpoint's commit. The first has no parent, so
    /// its pack holds the whole tree and no history.
    pub commit: String,
    /// The last checkpoint's commit, which this pack is thin against. A member
    /// applies the packs in order, so it holds every object the deltas name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// The person's `HEAD` when it was taken, in their own repository: where a
    /// teleport into a clone of it starts from (P2f).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    /// The pack, as blobs ([`chunk_bytes`]). Empty when the tree is the last
    /// checkpoint's: no commit is written for a turn that changed no file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pack: Vec<Chunk>,
}

/// What one checkpoint took ([`take`]): the `checkpoint` event's body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// 1 for a session's first checkpoint, one more each time after.
    pub n: u64,
    /// The turn it was taken after.
    pub turn: u32,
    /// Every allowlisted file there is now, in path order, changed or not: a
    /// member that holds them all at these hashes holds this checkpoint. A file
    /// the last checkpoint listed and this one does not was removed.
    pub files: Vec<FileSnap>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<Skipped>,
    /// The workspace, when one was taken (P2b-2). A device without `git`
    /// takes none, and `skipped` says why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<WorkspaceSnap>,
}

impl Checkpoint {
    /// FR-90 P2d-3 — every blob this checkpoint adds, each once, with its
    /// length: each file's chunks in path order, then the pack's. A member
    /// holds them all before it applies the checkpoint
    /// ([`crate::stream::blobs_named`]), so a copy whose tip is past a
    /// checkpoint holds its files too.
    pub fn blobs(&self) -> Vec<(Digest, u64)> {
        let mut seen = std::collections::BTreeSet::new();
        self.files
            .iter()
            .flat_map(|f| f.chunks.iter())
            .chain(self.workspace.iter().flat_map(|w| w.pack.iter()))
            .filter(|c| seen.insert(c.hash))
            .map(|c| (c.hash, c.len))
            .collect()
    }
}

/// `bytes` as chunks of at most [`CHUNK_MAX`] from offset 0, and their blobs:
/// how a whole thing, a pack among them, is carried.
pub fn chunk_bytes(bytes: &[u8]) -> (Vec<Chunk>, Vec<Vec<u8>>) {
    let mut chunks = Vec::new();
    let mut blobs = Vec::new();
    let mut offset = 0u64;
    for piece in bytes.chunks(CHUNK_MAX) {
        chunks.push(Chunk {
            offset,
            len: piece.len() as u64,
            hash: Digest::of(piece),
        });
        offset += piece.len() as u64;
        blobs.push(piece.to_vec());
    }
    (chunks, blobs)
}

/// The bytes `chunks` name, in order from offset 0, each checked against its
/// hash: how a member or a target reads a pack back.
pub fn join_chunks(
    what: &str,
    chunks: &[Chunk],
    blob: impl Fn(&Digest) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, CheckpointError> {
    let bad = |why: String| CheckpointError::Inconsistent {
        path: what.to_string(),
        why,
    };
    let mut bytes = Vec::new();
    for chunk in chunks {
        if chunk.offset != bytes.len() as u64 {
            return Err(bad(format!(
                "a chunk at {}, after {} bytes",
                chunk.offset,
                bytes.len()
            )));
        }
        let data =
            blob(&chunk.hash).ok_or_else(|| bad(format!("the blob {} is missing", chunk.hash)))?;
        if data.len() as u64 != chunk.len || Digest::of(&data) != chunk.hash {
            return Err(bad(format!(
                "the blob {} is not what was named",
                chunk.hash
            )));
        }
        bytes.extend_from_slice(&data);
    }
    Ok(bytes)
}

/// Where the last checkpoint left each file: its `len` and `hash`, by path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Previous {
    files: BTreeMap<String, (u64, Digest)>,
    workspace: Option<WorkspaceSnap>,
}

impl Previous {
    /// Nothing taken yet: a session's first checkpoint.
    pub fn none() -> Self {
        Self::default()
    }

    /// Where `last` left every file it listed, and its workspace.
    pub fn from_checkpoint(last: &Checkpoint) -> Self {
        Self {
            files: last
                .files
                .iter()
                .map(|f| (f.path.clone(), (f.len, f.hash)))
                .collect(),
            workspace: last.workspace.clone(),
        }
    }

    fn get(&self, path: &str) -> Option<(u64, Digest)> {
        self.files.get(path).copied()
    }

    /// The last checkpoint's workspace: the commit the next one's parent and
    /// pack base are (P2b-2).
    pub fn workspace(&self) -> Option<&WorkspaceSnap> {
        self.workspace.as_ref()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("{0:?} is not a harness session id (a UUID)")]
    BadSession(String),
    #[error("reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("the allowlist holds more than {MAX_FILES} files")]
    TooManyFiles,
    #[error("a checkpoint takes at most {MAX_NEW_BYTES} new bytes, and this one would take {0}")]
    TooLarge(u64),
    /// A member's side: what it holds for `path` does not add up.
    #[error("{path}: {why}")]
    Inconsistent { path: String, why: String },
}

/// One allowlisted path, relative to the config directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowEntry {
    pub rel: String,
    pub is_dir: bool,
}

/// The five paths a checkpoint takes, for the session whose HARNESS id is
/// `harness_session` (the pinned project directory is `hive-<id>`):
///
/// - `projects/hive-<id>/<id>.jsonl`, the history;
/// - `projects/hive-<id>/<id>/subagents/`, sub-agent transcripts and their metadata;
/// - `projects/hive-<id>/<id>/tool-results/`, outputs too large for the context;
/// - `projects/hive-<id>/memory/`, the auto-memory;
/// - `CLAUDE.md`, the session's own instructions (core memory, P1e).
///
/// The id must be a UUID, as Claude Code's `--session-id` requires: it is
/// part of every path, and nothing else may be.
pub fn allowlist(harness_session: &str) -> Result<[AllowEntry; 5], CheckpointError> {
    let id = harness_id(harness_session)?;
    let project = format!("projects/hive-{id}");
    Ok([
        AllowEntry {
            rel: format!("{project}/{id}.jsonl"),
            is_dir: false,
        },
        AllowEntry {
            rel: format!("{project}/{id}/subagents"),
            is_dir: true,
        },
        AllowEntry {
            rel: format!("{project}/{id}/tool-results"),
            is_dir: true,
        },
        AllowEntry {
            rel: format!("{project}/memory"),
            is_dir: true,
        },
        AllowEntry {
            rel: "CLAUDE.md".to_string(),
            is_dir: false,
        },
    ])
}

/// FR-90 P2f-3a — the paths a checkpoint takes for a session forked from the
/// session whose harness id is `fork_of`: its own five ([`allowlist`]), and
/// three of its parent's under the FORK's project directory, their names
/// kept:
///
/// - `projects/hive-<id>/<parent>.jsonl`, the history the fork's first launch
///   resumes from (`--resume <parent> --fork-session`);
/// - `projects/hive-<id>/<parent>/subagents/` and
///   `projects/hive-<id>/<parent>/tool-results/`, which the history the fork
///   writes still names: Claude Code copies neither (2.1.296, probed
///   2026-10-10).
///
/// Kept for the fork's life, so a copy of it starts anywhere from its own
/// chain, before its first prompt as after. The memory and `CLAUDE.md` are
/// one path for both. The parent's files are written once, by the fork's
/// first start, so [`growth_of`] takes each whole. `None` is [`allowlist`];
/// a parent that is the session itself is refused, as a malformed id is.
pub fn allowlist_of(
    harness_session: &str,
    fork_of: Option<&str>,
) -> Result<Vec<AllowEntry>, CheckpointError> {
    let mut entries = allowlist(harness_session)?.to_vec();
    if let Some(parent) = fork_of {
        let parent = harness_id(parent)?;
        if parent == harness_session {
            return Err(CheckpointError::BadSession(parent));
        }
        let project = format!("projects/hive-{harness_session}");
        entries.extend([
            AllowEntry {
                rel: format!("{project}/{parent}.jsonl"),
                is_dir: false,
            },
            AllowEntry {
                rel: format!("{project}/{parent}/subagents"),
                is_dir: true,
            },
            AllowEntry {
                rel: format!("{project}/{parent}/tool-results"),
                is_dir: true,
            },
        ]);
    }
    Ok(entries)
}

/// The id, in the lowercase hyphenated form Claude Code names files by.
fn harness_id(harness_session: &str) -> Result<String, CheckpointError> {
    let parsed = uuid::Uuid::parse_str(harness_session)
        .map_err(|_| CheckpointError::BadSession(harness_session.to_string()))?;
    let id = parsed.hyphenated().to_string();
    if id != harness_session {
        // Braced, simple or upper-case forms would name other files.
        return Err(CheckpointError::BadSession(harness_session.to_string()));
    }
    Ok(id)
}

/// How a file at `rel` is taken: the history and a sub-agent's transcript are
/// only appended to; everything else is taken whole.
pub fn growth_of(rel: &str, harness_session: &str) -> Growth {
    let project = format!("projects/hive-{harness_session}");
    let history = format!("{project}/{harness_session}.jsonl");
    let subagents = format!("{project}/{harness_session}/subagents/");
    let appended = rel == history
        || (rel.starts_with(&subagents)
            && rel.ends_with(".jsonl")
            && !rel[subagents.len()..].contains('/'));
    if appended {
        Growth::Append
    } else {
        Growth::Whole
    }
}

/// An appended file at this checkpoint, from `bytes` (all of it as it is now)
/// and where the last checkpoint left it. Returns the file's entry and the new
/// blobs, in chunk order.
///
/// The checkpoint covers up to the last `\n`: the bytes after it are a line the
/// harness is still writing, taken next time. When the file is shorter than the
/// last checkpoint's `len`, or its first `len` bytes no longer hash to the last
/// `hash`, the file is taken again from its first byte.
pub fn snapshot_append(
    path: &str,
    mode: u32,
    bytes: &[u8],
    prev: Option<(u64, Digest)>,
) -> (FileSnap, Vec<Vec<u8>>) {
    let mut hasher = blake3::Hasher::new();
    let mut start = 0usize;
    let mut restarted = false;
    if let Some((plen, phash)) = prev {
        match usize::try_from(plen) {
            Ok(plen) if plen <= bytes.len() => {
                hasher.update(&bytes[..plen]);
                if Digest::of_hasher(&hasher) == phash {
                    start = plen;
                } else {
                    hasher = blake3::Hasher::new();
                    restarted = plen > 0;
                }
            }
            _ => restarted = plen > 0,
        }
    }
    let rest = &bytes[start..];
    let covered = rest.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    let new = &rest[..covered];
    hasher.update(new);
    let mut chunks = Vec::new();
    let mut blobs = Vec::new();
    let mut offset = start as u64;
    for piece in split_lines(new, CHUNK_MAX) {
        chunks.push(Chunk {
            offset,
            len: piece.len() as u64,
            hash: Digest::of(piece),
        });
        offset += piece.len() as u64;
        blobs.push(piece.to_vec());
    }
    if restarted && chunks.is_empty() {
        // Started over with no whole line yet: one empty chunk at 0 still
        // tells a member to drop what it holds.
        chunks.push(Chunk {
            offset: 0,
            len: 0,
            hash: Digest::of(&[]),
        });
        blobs.push(Vec::new());
    }
    let snap = FileSnap {
        path: path.to_string(),
        growth: Growth::Append,
        mode,
        len: (start + covered) as u64,
        hash: Digest::of_hasher(&hasher),
        chunks,
    };
    (snap, blobs)
}

/// A whole file at this checkpoint: its entry, and its blobs when it is not
/// what the last checkpoint had.
pub fn snapshot_whole(
    path: &str,
    mode: u32,
    bytes: &[u8],
    prev: Option<(u64, Digest)>,
) -> (FileSnap, Vec<Vec<u8>>) {
    let hash = Digest::of(bytes);
    let len = bytes.len() as u64;
    let unchanged = prev == Some((len, hash));
    let mut chunks = Vec::new();
    let mut blobs = Vec::new();
    if !unchanged {
        (chunks, blobs) = chunk_bytes(bytes);
        if bytes.is_empty() {
            // An empty file still starts over: one empty chunk says so.
            chunks.push(Chunk {
                offset: 0,
                len: 0,
                hash,
            });
            blobs.push(Vec::new());
        }
    }
    let snap = FileSnap {
        path: path.to_string(),
        growth: Growth::Whole,
        mode,
        len,
        hash,
        chunks,
    };
    (snap, blobs)
}

/// `bytes` cut into pieces of at most `max`, each ending at a `\n` where one
/// is within reach; a line longer than `max` is cut where it must be.
fn split_lines(bytes: &[u8], max: usize) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        if rest.len() <= max {
            out.push(rest);
            break;
        }
        let cut = rest[..max]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(max, |i| i + 1);
        out.push(&rest[..cut]);
        rest = &rest[cut..];
    }
    out
}

/// Take a checkpoint of `config_dir` for the session whose harness id is
/// `harness_session` (P2f-3a: forked from `fork_of`'s): number `n`, after
/// turn `turn`, from where `prev` left each file. Returns the checkpoint and
/// its new blobs.
///
/// Runs as whoever calls it, which for a session is its account (P2b-3), and
/// opens nothing outside the allowlist ([`allowlist_of`]).
pub fn take(
    config_dir: &Path,
    harness_session: &str,
    fork_of: Option<&str>,
    n: u64,
    turn: u32,
    prev: &Previous,
) -> Result<(Checkpoint, Vec<Vec<u8>>), CheckpointError> {
    let entries = allowlist_of(harness_session, fork_of)?;
    let mut found: Vec<(String, std::path::PathBuf)> = Vec::new();
    let mut skipped = Vec::new();
    for entry in &entries {
        let full = config_dir.join(&entry.rel);
        let meta = match std::fs::symlink_metadata(&full) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io_err(&entry.rel, e)),
        };
        if meta.file_type().is_symlink() {
            skipped.push(Skipped {
                path: entry.rel.clone(),
                why: "a link".into(),
            });
        } else if entry.is_dir && meta.is_dir() {
            walk(&full, &entry.rel, 0, &mut found, &mut skipped)?;
        } else if !entry.is_dir && meta.is_file() {
            found.push((entry.rel.clone(), full));
        } else {
            skipped.push(Skipped {
                path: entry.rel.clone(),
                why: "not the kind of file the allowlist names".into(),
            });
        }
        if found.len() > MAX_FILES {
            return Err(CheckpointError::TooManyFiles);
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));

    let mut files = Vec::with_capacity(found.len());
    let mut blobs = Vec::new();
    let mut new_bytes = 0u64;
    for (rel, full) in found {
        let (snap, mut more) = take_file(&rel, &full, harness_session, prev.get(&rel))?;
        new_bytes += more.iter().map(|b| b.len() as u64).sum::<u64>();
        if new_bytes > MAX_NEW_BYTES {
            return Err(CheckpointError::TooLarge(new_bytes));
        }
        files.push(snap);
        blobs.append(&mut more);
    }
    skipped.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((
        Checkpoint {
            n,
            turn,
            files,
            skipped,
            workspace: None,
        },
        blobs,
    ))
}

fn take_file(
    rel: &str,
    full: &Path,
    harness_session: &str,
    prev: Option<(u64, Digest)>,
) -> Result<(FileSnap, Vec<Vec<u8>>), CheckpointError> {
    let meta = std::fs::symlink_metadata(full).map_err(|e| io_err(rel, e))?;
    let mode = mode_of(&meta);
    // Read whole: a history is MBs, and one read is one moment of the file,
    // so the prefix check and the new bytes cannot disagree.
    let bytes = std::fs::read(full).map_err(|e| io_err(rel, e))?;
    Ok(match growth_of(rel, harness_session) {
        Growth::Append => snapshot_append(rel, mode, &bytes, prev),
        Growth::Whole => snapshot_whole(rel, mode, &bytes, prev),
    })
}

/// The files under `dir` (relative path `rel`), depth-first in name order,
/// never through a link.
fn walk(
    dir: &Path,
    rel: &str,
    depth: usize,
    found: &mut Vec<(String, std::path::PathBuf)>,
    skipped: &mut Vec<Skipped>,
) -> Result<(), CheckpointError> {
    if depth >= MAX_DEPTH {
        skipped.push(Skipped {
            path: rel.to_string(),
            why: format!("deeper than {MAX_DEPTH} directories"),
        });
        return Ok(());
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| io_err(rel, e))? {
        let entry = entry.map_err(|e| io_err(rel, e))?;
        names.push(entry.file_name());
    }
    names.sort();
    for name in names {
        let Some(name_str) = name.to_str() else {
            skipped.push(Skipped {
                path: format!("{rel}/{}", name.to_string_lossy()),
                why: "a name that is not UTF-8".into(),
            });
            continue;
        };
        let child_rel = format!("{rel}/{name_str}");
        let child = dir.join(&name);
        let meta = std::fs::symlink_metadata(&child).map_err(|e| io_err(&child_rel, e))?;
        if meta.file_type().is_symlink() {
            skipped.push(Skipped {
                path: child_rel,
                why: "a link".into(),
            });
        } else if meta.is_dir() {
            walk(&child, &child_rel, depth + 1, found, skipped)?;
        } else if meta.is_file() {
            found.push((child_rel, child));
            if found.len() > MAX_FILES {
                return Err(CheckpointError::TooManyFiles);
            }
        } else {
            skipped.push(Skipped {
                path: child_rel,
                why: "not a regular file".into(),
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn mode_of(_meta: &std::fs::Metadata) -> u32 {
    0
}

fn io_err(path: &str, source: std::io::Error) -> CheckpointError {
    CheckpointError::Io {
        path: path.to_string(),
        source,
    }
}

/// The chunks that make `path` as the last of `checkpoints` (oldest first) has
/// it, in order from offset 0, and that checkpoint's entry for it: what
/// [`assemble`] joins, for a caller that streams the blobs instead of holding
/// the file (P2b-4, a target's materialize). A chunk at offset 0 starts the
/// file over, and so does a checkpoint that does not list it. Each chunk
/// follows the one before it, and they add up to the entry's `len`; each
/// blob's hash is the reader's to check, and the whole file's.
pub fn chunks_of<'a>(
    path: &str,
    checkpoints: impl IntoIterator<Item = &'a Checkpoint>,
) -> Result<(Vec<Chunk>, &'a FileSnap), CheckpointError> {
    let bad = |why: String| CheckpointError::Inconsistent {
        path: path.to_string(),
        why,
    };
    let mut chunks: Vec<Chunk> = Vec::new();
    let mut len = 0u64;
    let mut last: Option<&FileSnap> = None;
    for cp in checkpoints {
        let Some(snap) = cp.files.iter().find(|f| f.path == path) else {
            last = None;
            chunks.clear();
            len = 0;
            continue;
        };
        for chunk in &snap.chunks {
            if chunk.offset == 0 {
                chunks.clear();
                len = 0;
            }
            if chunk.offset != len {
                return Err(bad(format!(
                    "checkpoint {} has a chunk at {}, after {len} bytes",
                    cp.n, chunk.offset
                )));
            }
            len += chunk.len;
            chunks.push(chunk.clone());
        }
        last = Some(snap);
    }
    let Some(last) = last else {
        return Err(bad("the last checkpoint does not list it".into()));
    };
    if len != last.len {
        return Err(bad(format!(
            "the chunks add up to {len} bytes, and the last checkpoint's entry says {}",
            last.len
        )));
    }
    Ok((chunks, last))
}

/// A member's half: the bytes of `path` as of the last of `checkpoints`
/// (oldest first), from the chunks they name ([`chunks_of`]) and the blobs
/// `blob` finds. Each chunk must hash to its name and follow the one before
/// it, and the whole must hash to the last checkpoint's `hash`.
pub fn assemble<'a>(
    path: &str,
    checkpoints: impl IntoIterator<Item = &'a Checkpoint>,
    blob: impl Fn(&Digest) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, CheckpointError> {
    let bad = |why: String| CheckpointError::Inconsistent {
        path: path.to_string(),
        why,
    };
    let (chunks, last) = chunks_of(path, checkpoints)?;
    // Never sized from `len`: it is a member's word, and the blobs may not exist.
    let mut bytes: Vec<u8> = Vec::new();
    for chunk in &chunks {
        let data =
            blob(&chunk.hash).ok_or_else(|| bad(format!("the blob {} is missing", chunk.hash)))?;
        if data.len() as u64 != chunk.len || Digest::of(&data) != chunk.hash {
            return Err(bad(format!(
                "the blob {} is not what was named",
                chunk.hash
            )));
        }
        bytes.extend_from_slice(&data);
    }
    if Digest::of(&bytes) != last.hash {
        return Err(bad(format!(
            "the chunks add up to {} bytes that do not hash to the last checkpoint's",
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const ID: &str = "0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9";

    fn blobs_of(store: &mut HashMap<Digest, Vec<u8>>, blobs: Vec<Vec<u8>>) {
        for b in blobs {
            store.insert(Digest::of(&b), b);
        }
    }

    #[test]
    fn a_digest_prints_and_parses_as_b3sum_does() {
        let d = Digest::of(b"abc");
        let hex = d.to_string();
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, blake3::hash(b"abc").to_hex().as_str());
        assert_eq!(Digest::parse(&hex), Some(d));
        assert_eq!(Digest::parse(&hex.to_uppercase()), None, "lowercase only");
        assert_eq!(Digest::parse(&hex[..63]), None);
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, format!("\"{hex}\""));
        assert_eq!(serde_json::from_str::<Digest>(&json).unwrap(), d);
    }

    /// The five paths, under the pinned project name, and nothing at the
    /// config root but `CLAUDE.md`. Any id that is not a lowercase hyphenated
    /// UUID is refused, since it is part of every path.
    #[test]
    fn the_allowlist_is_five_named_paths_and_the_id_must_be_a_uuid() {
        let a = allowlist(ID).unwrap();
        let rels: Vec<&str> = a.iter().map(|e| e.rel.as_str()).collect();
        assert_eq!(
            rels,
            [
                format!("projects/hive-{ID}/{ID}.jsonl").as_str(),
                format!("projects/hive-{ID}/{ID}/subagents").as_str(),
                format!("projects/hive-{ID}/{ID}/tool-results").as_str(),
                format!("projects/hive-{ID}/memory").as_str(),
                "CLAUDE.md",
            ]
        );
        for bad in [
            "../etc",
            "",
            &ID.to_uppercase(),
            &format!("{{{ID}}}"),
            &ID.replace('-', ""),
        ] {
            assert!(
                matches!(allowlist(bad), Err(CheckpointError::BadSession(_))),
                "{bad:?}"
            );
        }
    }

    /// The session a fork was made from (P2f-3a).
    const PARENT: &str = "7d8e9fa0-b1c2-4d3e-8f40-5a6b7c8d9e0f";

    /// P2f-3a — a fork's allowlist is its own five and three of its parent's,
    /// under the FORK's project directory with their names kept; the memory
    /// and `CLAUDE.md` are one path for both. A parent that is the session
    /// itself, or no UUID, is refused.
    #[test]
    fn a_forks_allowlist_keeps_its_parents_history_beside_its_own() {
        let own = allowlist(ID).unwrap().to_vec();
        assert_eq!(allowlist_of(ID, None).unwrap(), own, "no parent: the five");
        let forked = allowlist_of(ID, Some(PARENT)).unwrap();
        assert_eq!(forked[..5], own[..], "its own five first");
        let p = format!("projects/hive-{ID}");
        let parents: Vec<(&str, bool)> = forked[5..]
            .iter()
            .map(|e| (e.rel.as_str(), e.is_dir))
            .collect();
        assert_eq!(
            parents,
            [
                (format!("{p}/{PARENT}.jsonl").as_str(), false),
                (format!("{p}/{PARENT}/subagents").as_str(), true),
                (format!("{p}/{PARENT}/tool-results").as_str(), true),
            ],
            "the parent's three, under the fork's project"
        );
        for bad in [ID, "../etc", "", &PARENT.to_uppercase()] {
            assert!(
                matches!(
                    allowlist_of(ID, Some(bad)),
                    Err(CheckpointError::BadSession(_))
                ),
                "{bad:?}"
            );
        }
        // Written once, by the fork's first start: taken whole.
        for rel in [
            format!("{p}/{PARENT}.jsonl"),
            format!("{p}/{PARENT}/subagents/agent-a1.jsonl"),
        ] {
            assert_eq!(growth_of(&rel, ID), Growth::Whole, "{rel}");
        }
    }

    #[test]
    fn the_history_and_a_subagents_transcript_are_appended_the_rest_whole() {
        let p = format!("projects/hive-{ID}");
        assert_eq!(growth_of(&format!("{p}/{ID}.jsonl"), ID), Growth::Append);
        assert_eq!(
            growth_of(&format!("{p}/{ID}/subagents/agent-a1.jsonl"), ID),
            Growth::Append
        );
        for whole in [
            format!("{p}/{ID}/subagents/agent-a1.meta.json"),
            format!("{p}/{ID}/subagents/deeper/agent-a1.jsonl"),
            format!("{p}/{ID}/tool-results/t1.txt"),
            format!("{p}/memory/MEMORY.md"),
            "CLAUDE.md".to_string(),
        ] {
            assert_eq!(growth_of(&whole, ID), Growth::Whole, "{whole}");
        }
    }

    /// An appended file is taken up to its last whole line, and the next
    /// checkpoint takes only what came after; a member's chunks add up to the
    /// file at each checkpoint.
    #[test]
    fn an_appended_file_is_taken_in_whole_lines_and_only_its_new_bytes() {
        let mut store = HashMap::new();
        let (one, b1) = snapshot_append("h", 0o600, b"{\"a\":1}\n{\"b\":", None);
        assert_eq!(one.len, 8, "the half line waits for the next checkpoint");
        assert_eq!(one.hash, Digest::of(b"{\"a\":1}\n"));
        assert_eq!(one.chunks.len(), 1);
        assert_eq!(one.chunks[0].offset, 0);
        blobs_of(&mut store, b1);

        let file = b"{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n";
        let (two, b2) = snapshot_append("h", 0o600, file, Some((one.len, one.hash)));
        assert_eq!(two.len, file.len() as u64);
        assert_eq!(two.chunks.len(), 1);
        assert_eq!(two.chunks[0].offset, 8, "only the new bytes");
        assert_eq!(two.chunks[0].len, file.len() as u64 - 8);
        blobs_of(&mut store, b2);

        let (three, b3) = snapshot_append("h", 0o600, file, Some((two.len, two.hash)));
        assert!(three.chunks.is_empty() && b3.is_empty(), "nothing new");
        assert_eq!((three.len, three.hash), (two.len, two.hash));

        let cps: Vec<Checkpoint> = [one, two, three]
            .into_iter()
            .enumerate()
            .map(|(i, f)| Checkpoint {
                n: i as u64 + 1,
                turn: i as u32 + 1,
                files: vec![f],
                skipped: vec![],
                workspace: None,
            })
            .collect();
        let got = assemble("h", &cps, |d| store.get(d).cloned()).unwrap();
        assert_eq!(got, file);
    }

    /// A history that shrank, or changed before its last offset, is taken again
    /// from its first byte, and a member starts it over.
    #[test]
    fn a_file_that_changed_behind_its_offset_is_taken_again_whole() {
        let (one, _) = snapshot_append("h", 0, b"aaa\nbbb\n", None);
        let (shrunk, _) = snapshot_append("h", 0, b"aaa\n", Some((one.len, one.hash)));
        assert_eq!(shrunk.chunks[0].offset, 0);
        assert_eq!(shrunk.len, 4);
        let (rewritten, blobs) =
            snapshot_append("h", 0, b"xxx\nbbb\nccc\n", Some((one.len, one.hash)));
        assert_eq!(rewritten.chunks[0].offset, 0, "same length, other bytes");
        assert_eq!(rewritten.len, 12);
        assert_eq!(blobs.concat(), b"xxx\nbbb\nccc\n");

        // Started over with no whole line yet: still a chunk at 0, empty, so a
        // member drops what it held instead of keeping the old bytes.
        let (partial, pblobs) = snapshot_append("h", 0, b"zz", Some((one.len, one.hash)));
        assert_eq!(partial.len, 0);
        assert_eq!(
            partial.chunks,
            vec![Chunk {
                offset: 0,
                len: 0,
                hash: Digest::of(b"")
            }]
        );
        let mut store = HashMap::new();
        let (_, b1) = snapshot_append("h", 0, b"aaa\nbbb\n", None);
        blobs_of(&mut store, b1);
        blobs_of(&mut store, pblobs);
        let cps = [one, partial].map(|f| Checkpoint {
            n: 1,
            turn: 1,
            files: vec![f],
            skipped: vec![],
            workspace: None,
        });
        assert_eq!(assemble("h", &cps, |d| store.get(d).cloned()).unwrap(), b"");
    }

    /// A large append is cut at line ends under the chunk limit; a line longer
    /// than the limit is cut where it must be, and the pieces still add up.
    #[test]
    fn a_large_append_is_cut_at_line_ends_and_a_huge_line_where_it_must() {
        let line = |c: u8, n: usize| {
            let mut l = vec![c; n];
            l.push(b'\n');
            l
        };
        let mut bytes = line(b'a', 10);
        bytes.extend(line(b'b', 10));
        bytes.extend(line(b'c', 30));
        let pieces = split_lines(&bytes, 25);
        assert_eq!(pieces[0], &bytes[..22], "two lines fit");
        assert!(pieces[1].len() <= 25, "the long line is cut");
        assert_eq!(pieces.concat(), bytes);
        assert!(pieces.iter().all(|p| p.len() <= 25));
    }

    /// A whole file is taken when it changed and not otherwise; an empty file
    /// is taken as one empty chunk, so a member writes it empty.
    #[test]
    fn a_whole_file_is_taken_only_when_it_changed() {
        let (one, b1) = snapshot_whole("m", 0o644, b"# memory\n", None);
        assert_eq!(one.chunks.len(), 1);
        assert_eq!(b1.concat(), b"# memory\n");
        let (same, b2) = snapshot_whole("m", 0o644, b"# memory\n", Some((one.len, one.hash)));
        assert!(same.chunks.is_empty() && b2.is_empty());
        let (empty, b3) = snapshot_whole("m", 0o644, b"", Some((one.len, one.hash)));
        assert_eq!(empty.chunks.len(), 1);
        assert_eq!(empty.chunks[0].len, 0);
        assert_eq!(b3, vec![Vec::<u8>::new()]);
        let mut store = HashMap::new();
        blobs_of(&mut store, b1);
        blobs_of(&mut store, b3);
        let cps = [one, same, empty].map(|f| Checkpoint {
            n: 1,
            turn: 1,
            files: vec![f],
            skipped: vec![],
            workspace: None,
        });
        assert_eq!(assemble("m", &cps, |d| store.get(d).cloned()).unwrap(), b"");
    }

    /// P2b-4 — the chunks a target streams are the ones `assemble` joins: from
    /// the last start-over on, and only since a removed file came back; they
    /// add up to the last entry, and an entry they do not reach is refused
    /// before a blob is read.
    #[test]
    fn the_chunks_a_target_streams_are_the_ones_assemble_joins() {
        let mut store = HashMap::new();
        let (a, ba) = snapshot_append("h", 0, b"one\n", None);
        let (b, bb) = snapshot_append("h", 0, b"one\ntwo\n", Some((a.len, a.hash)));
        // Shrank: taken again from its first byte.
        let (c, bc) = snapshot_append("h", 0, b"new\n", Some((b.len, b.hash)));
        let (d, bd) = snapshot_append("h", 0, b"new\nmore\n", Some((c.len, c.hash)));
        for blobs in [ba, bb, bc, bd] {
            blobs_of(&mut store, blobs);
        }
        let cp = |n: u64, files: Vec<FileSnap>| Checkpoint {
            n,
            turn: n as u32,
            files,
            skipped: vec![],
            workspace: None,
        };
        let chain = [
            cp(1, vec![a]),
            cp(2, vec![b]),
            cp(3, vec![c]),
            cp(4, vec![d]),
        ];
        let (chunks, last) = chunks_of("h", &chain).unwrap();
        assert_eq!(chunks.iter().map(|c| c.offset).collect::<Vec<_>>(), [0, 4]);
        assert_eq!(last.len, 9);
        let streamed: Vec<u8> = chunks.iter().flat_map(|c| store[&c.hash].clone()).collect();
        assert_eq!(
            streamed,
            assemble("h", &chain, |h| store.get(h).cloned()).unwrap()
        );
        assert_eq!(streamed, b"new\nmore\n");

        let (back, bback) = snapshot_append("h", 0, b"again\n", None);
        blobs_of(&mut store, bback);
        let returned: Vec<Checkpoint> = chain
            .iter()
            .cloned()
            .chain([cp(5, vec![]), cp(6, vec![back])])
            .collect();
        let (since, _) = chunks_of("h", &returned).unwrap();
        assert_eq!(since.len(), 1, "only since it came back");
        assert_eq!(store[&since[0].hash], b"again\n");
        assert!(
            chunks_of("h", &returned[..5]).is_err(),
            "the last does not list it"
        );
        assert!(
            chunks_of("h", &chain[3..]).is_err(),
            "a chunk past offset 0 with nothing before it"
        );

        let mut short = chain[0].clone();
        short.files[0].len = 99;
        let e = chunks_of("h", [&short]).unwrap_err();
        assert!(e.to_string().contains("entry says 99"), "{e}");
    }

    /// A member refuses what does not add up: a missing blob, a blob that is
    /// not what was named, a gap.
    #[test]
    fn a_member_refuses_chunks_that_do_not_add_up() {
        let (one, b1) = snapshot_append("h", 0, b"a\nb\n", None);
        let cp = Checkpoint {
            n: 1,
            turn: 1,
            files: vec![one.clone()],
            skipped: vec![],
            workspace: None,
        };
        let missing = assemble("h", [&cp], |_| None).unwrap_err();
        assert!(missing.to_string().contains("missing"), "{missing}");
        let wrong = assemble("h", [&cp], |_| Some(b"x\ny\n".to_vec())).unwrap_err();
        assert!(wrong.to_string().contains("not what was named"), "{wrong}");
        let mut gap = one;
        gap.chunks[0].offset = 2;
        let cp_gap = Checkpoint {
            n: 1,
            turn: 1,
            files: vec![gap],
            skipped: vec![],
            workspace: None,
        };
        let store: HashMap<Digest, Vec<u8>> = b1.into_iter().map(|b| (Digest::of(&b), b)).collect();
        let err = assemble("h", [&cp_gap], |d| store.get(d).cloned()).unwrap_err();
        assert!(err.to_string().contains("after 0 bytes"), "{err}");
    }

    fn write(dir: &Path, rel: &str, bytes: &[u8]) {
        let p = dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    /// A real config directory: the five paths are taken and nothing at the
    /// root is opened (`.claude.json`, `sessions/…key`); a second checkpoint
    /// takes only the history's new lines; a removed tool result drops out.
    #[test]
    fn take_walks_the_allowlist_and_nothing_else() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let p = format!("projects/hive-{ID}");
        write(dir, &format!("{p}/{ID}.jsonl"), b"{\"t\":1}\n");
        write(
            dir,
            &format!("{p}/{ID}/subagents/agent-a1.jsonl"),
            b"{\"s\":1}\n",
        );
        write(
            dir,
            &format!("{p}/{ID}/subagents/agent-a1.meta.json"),
            b"{}",
        );
        write(dir, &format!("{p}/{ID}/tool-results/t1.txt"), b"big output");
        write(dir, &format!("{p}/memory/MEMORY.md"), b"- a fact\n");
        write(dir, "CLAUDE.md", b"# rules\n");
        // Outside the allowlist: never opened, never listed.
        write(
            dir,
            ".claude.json",
            b"{\"machineID\":\"m\",\"userID\":\"u\"}",
        );
        write(dir, "sessions/123.abc.key", b"{\"peerToken\":\"secret\"}");
        write(dir, &format!("{p}/other.jsonl"), b"another session\n");

        let (one, blobs) = take(dir, ID, None, 1, 1, &Previous::none()).unwrap();
        let listed: Vec<&str> = one.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            listed,
            // Path order: the id (`0b1c…`) sorts before `memory`.
            [
                "CLAUDE.md",
                format!("{p}/{ID}.jsonl").as_str(),
                format!("{p}/{ID}/subagents/agent-a1.jsonl").as_str(),
                format!("{p}/{ID}/subagents/agent-a1.meta.json").as_str(),
                format!("{p}/{ID}/tool-results/t1.txt").as_str(),
                format!("{p}/memory/MEMORY.md").as_str(),
            ]
        );
        let all = blobs.concat();
        let has = |needle: &[u8]| all.windows(needle.len()).any(|w| w == needle);
        assert!(!has(b"peerToken") && !has(b"machineID") && !has(b"another session"));
        assert!(one.skipped.is_empty());

        // Turn 2: the history grows; a tool result goes.
        let hist = dir.join(format!("{p}/{ID}.jsonl"));
        std::fs::write(&hist, b"{\"t\":1}\n{\"t\":2}\n").unwrap();
        std::fs::remove_file(dir.join(format!("{p}/{ID}/tool-results/t1.txt"))).unwrap();
        let (two, blobs2) = take(dir, ID, None, 2, 2, &Previous::from_checkpoint(&one)).unwrap();
        let history = two
            .files
            .iter()
            .find(|f| f.path.ends_with(".jsonl") && !f.path.contains("subagents"))
            .unwrap();
        assert_eq!(history.chunks.len(), 1);
        assert_eq!(history.chunks[0].offset, 8);
        assert_eq!(blobs2.concat(), b"{\"t\":2}\n", "only the new line");
        assert!(
            two.files.iter().all(|f| !f.path.ends_with("t1.txt")),
            "a removed file drops out"
        );
        assert!(
            two.files
                .iter()
                .filter(|f| f.growth == Growth::Whole)
                .all(|f| f.chunks.is_empty()),
            "unchanged whole files carry no blobs"
        );

        // A member holding both rebuilds the history and every file.
        let mut store = HashMap::new();
        blobs_of(&mut store, blobs);
        blobs_of(&mut store, blobs2);
        let history_path = format!("{p}/{ID}.jsonl");
        let rebuilt = assemble(&history_path, [&one, &two], |d| store.get(d).cloned()).unwrap();
        assert_eq!(rebuilt, std::fs::read(&hist).unwrap());
        let claude = assemble("CLAUDE.md", [&one, &two], |d| store.get(d).cloned()).unwrap();
        assert_eq!(claude, b"# rules\n");
    }

    /// P2f-3a — a fork's checkpoint takes its own files and its parent's
    /// three under its own project directory, the parent's whole; nothing
    /// under the parent's own project directory, and nothing of a session
    /// further back: a fork of a fork resumes its parent's history, which
    /// holds those turns already.
    #[test]
    fn take_of_a_fork_keeps_its_parents_files_and_nothing_further_back() {
        const GRANDPARENT: &str = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let p = format!("projects/hive-{ID}");
        write(dir, &format!("{p}/{ID}.jsonl"), b"{\"t\":1}\n");
        write(dir, &format!("{p}/{PARENT}.jsonl"), b"{\"p\":1}\n");
        write(
            dir,
            &format!("{p}/{PARENT}/subagents/agent-a1.jsonl"),
            b"{\"s\":1}\n",
        );
        write(
            dir,
            &format!("{p}/{PARENT}/tool-results/t1.txt"),
            b"big output",
        );
        write(dir, "CLAUDE.md", b"# rules\n");
        write(dir, &format!("{p}/{GRANDPARENT}.jsonl"), b"further back\n");
        write(
            dir,
            &format!("projects/hive-{PARENT}/{PARENT}.jsonl"),
            b"the parent's own place\n",
        );

        let (cp, blobs) = take(dir, ID, Some(PARENT), 1, 1, &Previous::none()).unwrap();
        let listed: Vec<(&str, Growth)> = cp
            .files
            .iter()
            .map(|f| (f.path.as_str(), f.growth))
            .collect();
        let mut want = vec![
            ("CLAUDE.md".to_string(), Growth::Whole),
            (format!("{p}/{ID}.jsonl"), Growth::Append),
            (format!("{p}/{PARENT}.jsonl"), Growth::Whole),
            (
                format!("{p}/{PARENT}/subagents/agent-a1.jsonl"),
                Growth::Whole,
            ),
            (format!("{p}/{PARENT}/tool-results/t1.txt"), Growth::Whole),
        ];
        want.sort_by(|a, b| a.0.cmp(&b.0));
        let want: Vec<(&str, Growth)> = want.iter().map(|(p, g)| (p.as_str(), *g)).collect();
        assert_eq!(listed, want, "its own files and its parent's three");
        let all = blobs.concat();
        let has = |needle: &[u8]| all.windows(needle.len()).any(|w| w == needle);
        assert!(!has(b"further back") && !has(b"the parent's own place"));

        // Without the parent, the same directory is a session's own five.
        let (plain, _) = take(dir, ID, None, 1, 1, &Previous::none()).unwrap();
        assert!(
            plain.files.iter().all(|f| !f.path.contains(PARENT)),
            "{:?}",
            plain.files
        );
    }

    /// A link in the allowlist is listed as skipped and never followed, as a
    /// path or inside a directory.
    #[cfg(unix)]
    #[test]
    fn a_link_in_the_allowlist_is_never_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let secret = tmp.path().join("id_ed25519");
        std::fs::write(&secret, b"PRIVATE KEY").unwrap();
        let p = format!("projects/hive-{ID}");
        std::fs::create_dir_all(dir.join(format!("{p}/memory"))).unwrap();
        std::os::unix::fs::symlink(&secret, dir.join(format!("{p}/memory/MEMORY.md"))).unwrap();
        std::os::unix::fs::symlink(&secret, dir.join("CLAUDE.md")).unwrap();
        let (cp, blobs) = take(dir, ID, None, 1, 1, &Previous::none()).unwrap();
        assert!(cp.files.is_empty(), "{:?}", cp.files);
        assert!(blobs.is_empty());
        let skipped: Vec<(&str, &str)> = cp
            .skipped
            .iter()
            .map(|s| (s.path.as_str(), s.why.as_str()))
            .collect();
        assert_eq!(
            skipped,
            [
                ("CLAUDE.md", "a link"),
                (format!("{p}/memory/MEMORY.md").as_str(), "a link")
            ]
        );
    }

    /// A pack is carried as chunks from 0 and read back checked: a chunk out
    /// of place, missing or not what was named is refused.
    #[test]
    fn a_pack_is_carried_in_chunks_and_read_back_checked() {
        let pack: Vec<u8> = (0..(CHUNK_MAX + 10)).map(|i| (i % 251) as u8).collect();
        let (chunks, blobs) = chunk_bytes(&pack);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[1].offset, CHUNK_MAX as u64);
        let store: HashMap<Digest, Vec<u8>> =
            blobs.into_iter().map(|b| (Digest::of(&b), b)).collect();
        assert_eq!(
            join_chunks("pack", &chunks, |d| store.get(d).cloned()).unwrap(),
            pack
        );
        let swapped = [chunks[1].clone(), chunks[0].clone()];
        assert!(join_chunks("pack", &swapped, |d| store.get(d).cloned()).is_err());
        assert!(join_chunks("pack", &chunks, |_| None).is_err());
        assert_eq!(chunk_bytes(b"").0, vec![], "nothing to carry");
    }

    /// The checkpoint is the `checkpoint` event's body, and round-trips through
    /// its JSON with hashes as hex.
    #[test]
    fn a_checkpoint_round_trips_through_json() {
        let (f, _) = snapshot_append("h", 0o600, b"a\n", None);
        let cp = Checkpoint {
            n: 3,
            turn: 7,
            files: vec![f],
            skipped: vec![Skipped {
                path: "CLAUDE.md".into(),
                why: "a link".into(),
            }],
            workspace: Some(WorkspaceSnap {
                repo: RepoKind::Own,
                prefix: "sub/".into(),
                tree: "4b825dc642cb6eb9a060e54bf8d69288fbee4904".into(),
                commit: "1e1f7e0c3a2b4d5e6f708192a3b4c5d6e7f80912".into(),
                base: None,
                head: Some("aa".repeat(20)),
                pack: vec![Chunk {
                    offset: 0,
                    len: 2,
                    hash: Digest::of(b"PK"),
                }],
            }),
        };
        let json = serde_json::to_string(&cp).unwrap();
        assert!(json.contains(&Digest::of(b"a\n").to_string()), "{json}");
        assert_eq!(serde_json::from_str::<Checkpoint>(&json).unwrap(), cp);
    }
}
