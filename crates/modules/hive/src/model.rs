// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! What the server stores about an agent session — and, by omission, what it
//! does not. No field here holds a prompt, a tool call, an output or a line
//! of transcript; the session's content lives on the devices that run and
//! replicate it (`docs/meshharbor-hive-design.md` §3.3).

use bson::{DateTime, oid::ObjectId};
use serde::{Deserialize, Serialize};

/// Where a session is in its life, as far as the server knows.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// The start was sent; the harness is not up yet. `accepted_at` says
    /// whether the device has answered.
    Starting,
    /// The harness is up and waiting for a prompt.
    Idle,
    /// A turn is running.
    Running,
    /// A tool call is waiting for a person's answer.
    AwaitingApproval,
    /// A stop was ordered; the device has not confirmed the harness exited.
    Stopping,
    /// Over; `end_reason` says how.
    Ended,
    /// The device refused the start; `refusal` names its gate.
    Refused,
    /// The start was never answered and will not be sent again.
    Lost,
}

impl SessionStatus {
    /// The spelling on the wire and in the database. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Idle => "idle",
            Self::Running => "running",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Stopping => "stopping",
            Self::Ended => "ended",
            Self::Refused => "refused",
            Self::Lost => "lost",
        }
    }

    /// Nothing moves a session out of these.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Ended | Self::Refused | Self::Lost)
    }

    /// Every status a session can still leave — the filter every cascade and
    /// every stop matches on.
    pub const LIVE: [SessionStatus; 5] = [
        Self::Starting,
        Self::Idle,
        Self::Running,
        Self::AwaitingApproval,
        Self::Stopping,
    ];

    /// The statuses a device's run-state report may move a session out of.
    /// Not `stopping`: a stop is in flight, and an `idle` that crossed it on
    /// the wire must not undo it — only `ended` may follow.
    pub const REPORTABLE: [SessionStatus; 4] = [
        Self::Starting,
        Self::Idle,
        Self::Running,
        Self::AwaitingApproval,
    ];

    /// The live statuses only a device's own run-state report sets — its
    /// word that it launched the session, as good as its answer to the
    /// start: the state usually lands first, and the answer can be lost.
    pub const LAUNCHED: [SessionStatus; 3] = [Self::Idle, Self::Running, Self::AwaitingApproval];
}

/// The harness a session runs, and its own id for the conversation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HarnessRef {
    /// [`meshharbor_remote_control::hive::HARNESS_CLAUDE_CODE`] in P0.
    pub id: String,
    /// The harness's session id (a UUID), minted here so every replica
    /// resumes the same conversation.
    pub session: String,
}

/// Where a session runs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SessionLocation {
    pub device_id: ObjectId,
    /// The device's name when the session started — how the session's room
    /// names its author ("Claude · mars").
    #[serde(default)]
    pub device_name: String,
    /// As the starter typed it; the device resolves it and confines it to
    /// its own `hive_roots`.
    pub folder: String,
    /// The local account the device says it mapped the starter to — set on
    /// acceptance. A claim by the device; the server never chooses it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

/// One agent session (`agent_sessions`).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentSession {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    /// Who started it: always a driver, and the only one who may stop it or
    /// change who else drives.
    pub owner_id: ObjectId,
    /// FR-90 P1c — who ELSE drives it (may prompt it and answer its
    /// approvals): members of its room the owner named, each holding
    /// `HIVE_RUN` when named. The owner is never listed. At most
    /// [`MAX_DRIVERS`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub drivers: Vec<ObjectId>,
    pub title: String,
    /// The session's room (P0d): `Secret`, bound to this session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_id: Option<ObjectId>,
    /// The newest turn with a stub in the room, and that stub's message —
    /// the next report for the same turn updates it instead of adding one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_turn: Option<TurnStub>,
    pub harness: HarnessRef,
    pub location: SessionLocation,
    pub status: SessionStatus,
    /// The lease fence the device runs it under. BSON has no unsigned
    /// integer, so it is stored signed; it starts at 1 and only a promotion
    /// (P2) raises it.
    pub fence: i64,
    /// When the device accepted the start. `None` while `starting` means the
    /// start is still unanswered — what reconcile-on-connect re-sends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<DateTime>,
    /// The device's refusal word, for `refused`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    /// How it ended (or will end, once `stopping` completes): `stopped`,
    /// `exited`, `member_removed`, `device_removed`, `tenant_archived`,
    /// `never_answered`, `device_unsupported`, `not_on_device` (P1b: its
    /// device reconnected without it — a restart, or an end it never told),
    /// `purged` (P2g-2: the record is a purge's tombstone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_reason: Option<String>,
    /// The device's last few words about it (a refusal's or an exit's), capped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime>,
    /// FR-90 P1e — the org's brain revision the session's core memory was
    /// rendered from, pinned when it was created: a fact written later
    /// reaches the next session, never this one. Absent before P1e.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brain_rev: Option<i64>,
    /// FR-90 P3-2b — the vault role the session assumed at its start, as the
    /// vault's gate allowed it (`role:assume`), and decided again at every
    /// move and fork. Absent = no role: nothing in the vault is allowed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_role: Option<String>,
    /// FR-90 P1j — how the session came to be. Absent = started from MeshHarbor
    /// (every record before P1j).
    #[serde(default, skip_serializing_if = "SessionOrigin::is_started")]
    pub origin: SessionOrigin,
    /// FR-90 P2c-2b — the devices that hold its copies, as placement chose
    /// them at its start ([`crate::placement`]). Absent: placed nowhere — it
    /// started with `hive.replicaset` off, before P2, or as an adopted
    /// session, which is never placed until it is a managed one (P2f).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicaset: Option<Replicaset>,
    /// FR-90 P2e-3 — the promotion in flight, while its owner moves it to one
    /// of its members ([`crate::promote`]). Absent once it is done or has
    /// failed: the room says which, and the record says where it runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion: Option<Promotion>,
    /// FR-90 P2e-3 — where each fence a promotion superseded ended: its last
    /// event, as the drained primary reported it, oldest first. The
    /// session's history keeps those fences' events up to there, and a member
    /// whose floor rose past one still needs them: one behind the drained tip
    /// at the move, one that joins later (spec §3b, "Open for P2e"). Kept here
    /// at the move, the one moment the server holds it; what reads it is
    /// P2e-5's joins and store.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fences: Vec<FenceMark>,
    /// FR-90 P2e-6b — where the start the session's device holds now came
    /// from, as its `rc:hive.move` says: set at every move of the lease, and
    /// read when that start is sent again. A device takes a session from
    /// anywhere else over from its own copy, and one from itself back as it
    /// left it, so this must outlive the promotion that made the move: a
    /// move on from a device that never answered can fail, and that device
    /// still needs the start it was owed. Absent before P2e-6b.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moved: Option<MovedStart>,
    /// FR-90 P2f-3 — the session this one was forked from. Every start of
    /// it names that session ([`Self::fork_of`]), so a device starts it from
    /// that conversation and its checkpoints keep that history beside its
    /// own. Absent for every other session, and on every record before
    /// P2f-3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<ParentLink>,
    /// FR-90 P2f-4b — a terminal session made a managed one (decision 11's
    /// other half, [`crate::manage`]): who asked and when, and the adopted
    /// record's own end and folder, which a refusal restores. Kept once it is
    /// managed, as where the session began. Absent for every other session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_terminal: Option<FromTerminal>,
    /// FR-90 P2f-5 — every lease move, oldest first: where the session ran
    /// before and where it ran from the new fence. Old turns keep the paths
    /// they had, and a moved start is told where they live now
    /// ([`crate::promote::before_start`]). A move back takes its move's entry
    /// out: no run started there. Empty for a session never moved since
    /// P2f-5.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_map: Vec<PathMove>,
    /// FR-90 P2g-2 — the record is a purge's tombstone: its owner deleted
    /// it, and every read a person makes leaves it out. It stays until every
    /// device that held the session answered the purge it names, then goes.
    /// Absent on every other record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purged: Option<PurgedMark>,
}

/// FR-90 P2g-2 — the purge a tombstoned record is waiting on, who issued it
/// and when.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PurgedMark {
    pub purge_id: ObjectId,
    pub by: ObjectId,
    pub at: DateTime,
}

/// FR-90 P2f-4b — the asking to make an adopted session a managed one, as
/// its record keeps it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FromTerminal {
    /// The device that adopted it, where it is made managed.
    pub device_id: ObjectId,
    pub by: ObjectId,
    /// When it was asked: what this asking's start and its restore key on.
    pub at: DateTime,
    /// The adopted record's own end, put back should the device refuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The folder it ran in as an adopted session, put back too: the asking
    /// may name another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// The word its start was refused with, by the device or for never
    /// reaching it: the record is the adopted session it was again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refused_detail: Option<String>,
}

/// FR-90 P2e-6b — where a moved start came from, by whom, and when.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MovedStart {
    pub from: SessionLocation,
    pub by: ObjectId,
    pub at: DateTime,
}

/// FR-90 P2f-5 — one lease move, as the path map keeps it: the fence it
/// started, the place before and the place after (each with no account, which
/// the device names only at its answer), and when.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PathMove {
    pub fence: i64,
    pub from: SessionLocation,
    pub to: SessionLocation,
    pub at: DateTime,
}

/// FR-90 P2f-3 — the session a fork was made from: its record, and its
/// harness session, which the device resumes the fork's first launch from
/// (`--resume <it> --fork-session`). Kept whole on the fork, so its starts
/// never read the parent's record, which may be gone.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ParentLink {
    pub session_id: ObjectId,
    pub harness_session: String,
}

/// FR-90 P2e-3 — the last event of a fence a promotion superseded. BSON has
/// no unsigned integer, so the numbers are stored signed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FenceMark {
    pub fence: i64,
    pub seq: i64,
    pub hash: String,
}

/// P2e-6a — how much of the session's chain a copy that ends at
/// `(fence, seq)` holds, as a `seq`: every copy's chain is the one the record
/// knows, up to where each older fence ended (`fences`), so the `seq` orders
/// them. Past an end is a tail a move away from an unreachable primary cut
/// off, which the copy sets aside once it follows the session again (P2d-3):
/// it counts for nothing. Never `(fence, seq)` compared whole: an empty copy
/// says `seq` 0 at the fence it joined at, the newest of all. A promotion is
/// decided by it, and (P2j-1) the API answers it for each member as `holds`.
pub(crate) fn on_chain(fences: &[FenceMark], fence: i64, seq: i64) -> i64 {
    fences
        .iter()
        .find(|m| m.fence == fence)
        .map_or(seq, |end| seq.min(end.seq))
}

/// FR-90 P2k-5 — how many events a copy that ends at `(fence, seq)` holds
/// past where its fence ended: what a primary cut off went on writing after
/// the session moved away from it (P2e-6a), which no copy on the session's
/// chain holds, so it did not carry over. Zero at the current fence, and for
/// a copy within its fence's end.
pub(crate) fn past_end(fences: &[FenceMark], fence: i64, seq: i64) -> i64 {
    seq - on_chain(fences, fence, seq)
}

/// FR-90 P2e-3 — where a promotion is. Every step is a compare-and-set on the
/// state it leaves, so a frame that arrives twice, late, or on another pod
/// moves it once.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PromotionState {
    /// The member it moves to was sent `rc:hive.prepare`, and has not said
    /// it is ready.
    Preparing,
    /// FR-90 P2f-1 — a teleport's target is ready: it was added to the
    /// replicaset in the `teleport` role and sent its join, the primary its
    /// join as the primary; the target's copy catches up with the primary's
    /// while the session still runs.
    Joining,
    /// The member is ready; the primary was sent `rc:hive.drain`.
    Draining,
    /// The primary drained; the member's copy is to reach the drained tip.
    Syncing,
    /// The lease moved: the member was sent the start, and has not run it.
    Moving,
}

impl PromotionState {
    /// The spelling in the database and the API. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::Joining => "joining",
            Self::Draining => "draining",
            Self::Syncing => "syncing",
            Self::Moving => "moving",
        }
    }

    /// Before the lease moves: a failure here leaves the session where it
    /// was.
    pub const BEFORE_THE_MOVE: [PromotionState; 4] = [
        Self::Preparing,
        Self::Joining,
        Self::Draining,
        Self::Syncing,
    ];
}

/// FR-90 P2e-3 — the tip a drained primary's copy ends at. BSON has no
/// unsigned integer, so `seq` is stored signed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DrainedTip {
    pub seq: i64,
    pub hash: String,
}

/// FR-90 P2e-3 — a promotion in flight (`agent_sessions.promotion`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Promotion {
    pub id: ObjectId,
    /// The member it moves to, and its name for the room.
    pub to: ObjectId,
    #[serde(default)]
    pub to_name: String,
    /// The member's role before it, restored should its start be refused.
    pub to_role: String,
    /// The folder it will run in there.
    pub folder: String,
    /// Where it ran, and at which fence: the lease moves back here should the
    /// member refuse the start.
    pub from: SessionLocation,
    pub from_fence: i64,
    /// Who moved it: the session's owner.
    pub by: ObjectId,
    pub state: PromotionState,
    pub started_at: DateTime,
    /// When the state it is in runs out. Before the move, a promotion past it
    /// has failed, whether or not the pod that started it is still there to
    /// say so; in `moving`, it may be replaced once past it.
    pub deadline: DateTime,
    /// The primary's word on where its copy ends, once it drained. P2e-6a —
    /// for a primary that was unreachable, the member's own word on where
    /// its copy ends, from its ready answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drained: Option<DrainedTip>,
    /// FR-90 P2e-6a — the primary had been unreachable for
    /// `UNREACHABLE_SECS` when the promotion began: no drain is asked of it,
    /// and the lease moves to where the member's copy ends. Absent = a
    /// promotion that drains, every one before P2e-6a.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unreachable_from: bool,
    /// FR-90 P2e-6b — for a move on from a device that never answered its
    /// moved start: where that start came from. A start this move's member
    /// refuses moves the lease back to that device, which then still needs
    /// to take the session over from its copy: its start says so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior: Option<MovedStart>,
    /// FR-90 P2f-1 — a teleport: the device it moves to held no copy of the
    /// session, and takes one in the `joining` step before the drain. A
    /// failure before the move lets that copy go (`leaving`). Absent = a
    /// promotion to a member, every one before P2f-1.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub teleport: bool,
    /// FR-90 P2f-3c — a fork onto a device that held no copy: a teleport's
    /// steps up to the copy (the prepare, the join, the catching up), then
    /// the fork made there instead of the drain. The session itself never
    /// moves. Absent = a promotion or a teleport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fork: Option<ForkPlan>,
}

/// FR-90 P2f-3c — the fork a fork-joining move is for, made once its target's
/// copy caught up: by [`Promotion::by`], on [`Promotion::to`], in
/// [`Promotion::folder`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ForkPlan {
    pub title: String,
}

impl Promotion {
    /// Whether it still holds the session: not past its deadline, whatever
    /// its state.
    pub fn in_flight(&self, now: DateTime) -> bool {
        now < self.deadline
    }
}

/// FR-90 P2c-2b — where a session's copies go: its primary first, then the
/// members placement chose, never more than `max`. A plan until the joins
/// (P2c-3) say which members took it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Replicaset {
    /// The policy revision placement read; 0 is decision 2's defaults.
    pub policy_revision: i64,
    pub min: u32,
    pub max: u32,
    /// The restricted tags the session carries, in the policy's spelling.
    /// Sticky: a later placement adds to them and never takes one away, so
    /// a session that was restricted stays restricted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restricted_tags: Vec<String>,
    pub members: Vec<ReplicaMember>,
    /// Why it holds fewer than `min` copies, when it does
    /// ([`crate::placement::Short::as_str`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short: Option<String>,
    pub placed_at: DateTime,
}

/// One member of a session's replicaset.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReplicaMember {
    pub device_id: ObjectId,
    /// [`crate::placement::MemberRole::as_str`]: `primary` | `archive` |
    /// `owner` | `teleport` (P2f-1: a teleport's target, which takes the
    /// copy it will run).
    pub role: String,
    /// P2c-3 — whether it took its copy. The primary is `joined` from its
    /// placement: it runs the session. Absent on a record placed before
    /// P2c-3, and read as `pending`: its join is still to send.
    #[serde(default)]
    pub state: MemberState,
    /// The device's word, when it refused the join
    /// ([`meshharbor_remote_control::hive::HiveJoinRefusal::as_str`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    /// When the device answered its join.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_at: Option<DateTime>,
    /// P2c-3 — where its copy ends, from its last report: the device's
    /// claim, numbers and hashes only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip: Option<MemberTip>,
    /// FR-90 P2g-4b — the purge of this leaving member's copy, once issued:
    /// placement never takes the member back from then on, the purge is
    /// delivered only while the row names it, and its completion drops the
    /// row. Absent on every other member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purging: Option<ObjectId>,
    /// FR-90 P2g-4b — the fork being made from this leaving member's copy
    /// (P2f-3c): its first start puts the fork in place from that copy, so
    /// the copy is not purged while that start is out. Written with the
    /// leaving, in the write that ends the fork's move; at each look for a
    /// purge, the fork's own record says whether it still needs the copy.
    /// Absent on every other member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forking: Option<ObjectId>,
}

/// FR-90 P2c-3 — whether a member took its copy.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MemberState {
    /// Its join is still to send, or sent and unanswered: it is re-sent on
    /// every connection of the device that holds copies.
    #[default]
    Pending,
    /// The device holds the session: its floor is at the session's fence.
    Joined,
    /// The device refused; `refusal` says which of its gates.
    Refused,
    /// P2c-4 — placement no longer chooses it: a tag taken off, its owner
    /// changed, a smaller policy, the device removed. Its copy goes with the
    /// purge (P2g), once `min` holds elsewhere; until then it keeps what it
    /// holds, and placement choosing it again makes it `pending` again.
    /// P2g-4b — once that purge is issued ([`ReplicaMember::purging`]),
    /// placement never chooses it again: removal is final on the device.
    Leaving,
}

impl MemberState {
    /// The spelling in the database and the API. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Joined => "joined",
            Self::Refused => "refused",
            Self::Leaving => "leaving",
        }
    }
}

/// FR-90 P2c-3 — where a member's copy of a session ends, as it last said.
/// BSON has no unsigned integer, so the numbers are stored signed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MemberTip {
    /// The fence of the event at `seq`.
    pub fence: i64,
    pub seq: i64,
    /// That event's hash.
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_seq: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_hash: Option<String>,
    /// When the server heard it.
    pub at: DateTime,
}

/// FR-90 P1j — how a session came to be.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionOrigin {
    /// Its owner started it from MeshHarbor, through every start gate.
    #[default]
    Started,
    /// A terminal session its owner adopted on a device (`meshharbor hive
    /// adopt`, decision 11). Read-only: the terminal holds the harness, so
    /// nobody drives it from here, the owner included, and it passed none of
    /// the start gates.
    Adopted,
}

impl SessionOrigin {
    /// The spelling in the database and on the wire. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Adopted => "adopted",
        }
    }

    /// Serde's `skip_serializing_if`: a started session stores no origin, so
    /// its record reads as every record before P1j did.
    pub fn is_started(&self) -> bool {
        *self == Self::Started
    }
}

/// The most drivers a session may have besides its owner.
pub const MAX_DRIVERS: usize = 16;

impl AgentSession {
    pub const COLLECTION: &'static str = "agent_sessions";

    /// FR-90 P2f-3 — what every start of this session tells its device of
    /// the session it was forked from: `rc:hive.start`'s `fork_of`. `None`
    /// for a session that is no fork.
    pub fn fork_of(&self) -> Option<meshharbor_remote_control::hive::HiveForkOf> {
        self.parent
            .as_ref()
            .map(|p| meshharbor_remote_control::hive::HiveForkOf {
                session_id: p.session_id,
                harness_session: p.harness_session.clone(),
            })
    }

    /// FR-90 P2f-4b — a terminal session being made a managed one, whose
    /// start its device has not answered: every start of it says so
    /// (`rc:hive.start`'s `from_terminal`), and goes only to a connection
    /// that makes one (`hive-manage`).
    pub fn managing(&self) -> bool {
        self.status == SessionStatus::Starting
            && self.accepted_at.is_none()
            && self
                .from_terminal
                .as_ref()
                .is_some_and(|f| f.refused.is_none())
    }

    /// Whether `user` drives this session: its owner, or one the owner named.
    /// ⚠️ Not enough to prompt it: the session must be live and the driver
    /// still able to read it ([`crate::access`]).
    pub fn drives(&self, user: ObjectId) -> bool {
        user == self.owner_id || self.drivers.contains(&user)
    }

    /// Everyone who drives it: the owner first.
    pub fn all_drivers(&self) -> Vec<ObjectId> {
        let mut all = vec![self.owner_id];
        all.extend(self.drivers.iter().filter(|d| **d != self.owner_id));
        all
    }

    /// How the session authors its room's messages.
    pub fn author_display(&self) -> String {
        if self.location.device_name.is_empty() {
            "Claude".to_string()
        } else {
            format!("Claude · {}", self.location.device_name)
        }
    }
}

/// A turn's stub message in the session's room.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct TurnStub {
    pub turn: u32,
    pub message_id: ObjectId,
}

/// What the API answers about a session: ids as hex, times as RFC 3339.
/// Never the stored document itself — a `bson::DateTime` serialises to JSON as
/// an object, and a client reading it as a string gets something truthy and
/// wrong.
#[derive(Serialize, Debug, Clone)]
pub struct SessionView {
    pub id: String,
    pub owner_id: String,
    /// P1c — who else drives it (hex), the owner not listed.
    pub drivers: Vec<String>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room_id: Option<String>,
    pub harness: String,
    pub harness_session: String,
    pub device_id: String,
    /// The device's name when the session started (P0d-1), for a list that
    /// should not need a second lookup per row. Empty for an older record.
    pub device_name: String,
    pub folder: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    pub status: SessionStatus,
    pub fence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    /// P1e — the brain revision its core memory was rendered from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brain_rev: Option<i64>,
    /// P1j — `started` or `adopted` (read-only: nobody prompts it).
    pub origin: SessionOrigin,
    /// P2c-2b — where its copies go. Absent: placed nowhere.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replicaset: Option<ReplicasetView>,
    /// P2e-3 — the promotion in flight. Absent: none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub promotion: Option<PromotionView>,
    /// FR-90 P2f-3 — the session this one was forked from, hex. Absent: none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<String>,
    /// FR-90 P2f-4b — the session began in a terminal, and was made, or asked
    /// to be made, a managed one. Absent: neither.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_terminal: Option<FromTerminalView>,
}

/// [`FromTerminal`] as the API answers it: when it was asked, and the word a
/// refused asking left (the session is the adopted one it was).
#[derive(Serialize, Debug, Clone)]
pub struct FromTerminalView {
    pub at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refused: Option<String>,
}

/// [`Promotion`] as the API answers it.
#[derive(Serialize, Debug, Clone)]
pub struct PromotionView {
    pub id: String,
    pub to: String,
    pub to_name: String,
    pub folder: String,
    pub from: String,
    pub from_fence: i64,
    pub by: String,
    pub state: PromotionState,
    pub started_at: String,
    pub deadline: String,
    /// P2f-1 — a teleport, to a device that held no copy. Absent: a
    /// promotion to a member.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub teleport: bool,
    /// P2f-3c — a fork onto a device that held no copy: the session stays
    /// where it is. Absent: a move.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub fork: bool,
}

impl From<&Promotion> for PromotionView {
    fn from(p: &Promotion) -> Self {
        Self {
            id: p.id.to_hex(),
            to: p.to.to_hex(),
            to_name: p.to_name.clone(),
            folder: p.folder.clone(),
            from: p.from.device_id.to_hex(),
            from_fence: p.from_fence,
            by: p.by.to_hex(),
            state: p.state,
            started_at: rfc3339(p.started_at),
            deadline: rfc3339(p.deadline),
            teleport: p.teleport,
            fork: p.fork.is_some(),
        }
    }
}

/// [`Replicaset`] as the API answers it.
#[derive(Serialize, Debug, Clone)]
pub struct ReplicasetView {
    pub policy_revision: i64,
    pub min: u32,
    pub max: u32,
    pub restricted_tags: Vec<String>,
    pub members: Vec<ReplicaMemberView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short: Option<String>,
    pub placed_at: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct ReplicaMemberView {
    pub device_id: String,
    pub role: String,
    /// P2c-3 — `pending` | `joined` | `refused`.
    pub state: MemberState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answered_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tip: Option<MemberTipView>,
    /// P2j-1 — how much of the session's chain its copy holds, as a `seq`
    /// ([`on_chain`], the rule a promotion is decided by): the freshest copy
    /// holds the most. Absent while the member reported no tip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holds: Option<i64>,
}

/// [`MemberTip`] as the API answers it.
#[derive(Serialize, Debug, Clone)]
pub struct MemberTipView {
    pub fence: i64,
    pub seq: i64,
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_seq: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_hash: Option<String>,
    pub at: String,
}

impl ReplicasetView {
    /// `fences` are the session's own: what each member's copy holds is
    /// counted along them ([`on_chain`]).
    pub fn of(r: &Replicaset, fences: &[FenceMark]) -> Self {
        Self {
            policy_revision: r.policy_revision,
            min: r.min,
            max: r.max,
            restricted_tags: r.restricted_tags.clone(),
            members: r
                .members
                .iter()
                .map(|m| ReplicaMemberView {
                    device_id: m.device_id.to_hex(),
                    role: m.role.clone(),
                    state: m.state,
                    refusal: m.refusal.clone(),
                    answered_at: m.answered_at.map(rfc3339),
                    tip: m.tip.as_ref().map(|t| MemberTipView {
                        fence: t.fence,
                        seq: t.seq,
                        hash: t.hash.clone(),
                        checkpoint_seq: t.checkpoint_seq,
                        checkpoint_hash: t.checkpoint_hash.clone(),
                        at: rfc3339(t.at),
                    }),
                    holds: m.tip.as_ref().map(|t| on_chain(fences, t.fence, t.seq)),
                })
                .collect(),
            short: r.short.clone(),
            placed_at: rfc3339(r.placed_at),
        }
    }
}

fn rfc3339(t: DateTime) -> String {
    t.try_to_rfc3339_string().unwrap_or_default()
}

impl From<&AgentSession> for SessionView {
    fn from(s: &AgentSession) -> Self {
        Self {
            id: s.id.map(|i| i.to_hex()).unwrap_or_default(),
            owner_id: s.owner_id.to_hex(),
            drivers: s.drivers.iter().map(|d| d.to_hex()).collect(),
            title: s.title.clone(),
            room_id: s.room_id.map(|r| r.to_hex()),
            harness: s.harness.id.clone(),
            harness_session: s.harness.session.clone(),
            device_id: s.location.device_id.to_hex(),
            device_name: s.location.device_name.clone(),
            folder: s.location.folder.clone(),
            account: s.location.account.clone(),
            status: s.status,
            fence: u64::try_from(s.fence).unwrap_or_default(),
            refusal: s.refusal.clone(),
            end_reason: s.end_reason.clone(),
            detail: s.detail.clone(),
            created_at: rfc3339(s.created_at),
            updated_at: rfc3339(s.updated_at),
            accepted_at: s.accepted_at.map(rfc3339),
            ended_at: s.ended_at.map(rfc3339),
            brain_rev: s.brain_rev,
            origin: s.origin,
            replicaset: s
                .replicaset
                .as_ref()
                .map(|r| ReplicasetView::of(r, &s.fences)),
            promotion: s.promotion.as_ref().map(PromotionView::from),
            parent_session_id: s.parent.as_ref().map(|p| p.session_id.to_hex()),
            from_terminal: s.from_terminal.as_ref().map(|f| FromTerminalView {
                at: rfc3339(f.at),
                refused: f.refused.clone(),
            }),
        }
    }
}

/// FR-90 P1a-2 — one approval in a session (`agent_approvals`): that a tool
/// call waited for a driver, how it ended, who answered and when — and never
/// which tool or what it would do, which the device's frame cannot carry.
///
/// ⚠️ `answered_by` is the DEVICE's report of the grant whose answer it took:
/// the answer travels over the viewer peer, so no server decision stands
/// behind it the way one stands behind `hive_audit` (the `ssh_activity` rule).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentApproval {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    pub session_id: ObjectId,
    pub device_id: ObjectId,
    /// The device's id for it — unique within the session.
    pub approval_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn: Option<u32>,
    /// [`meshharbor_remote_control::hive::HiveApprovalStatus::as_str`].
    pub status: String,
    /// The stub in the session's room, edited when it ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<ObjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_by: Option<ObjectId>,
    pub requested_at: DateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime>,
}

impl AgentApproval {
    pub const COLLECTION: &'static str = "agent_approvals";
}

/// One server decision about a session (`hive_audit`): every start ATTEMPT,
/// refused or sent, every stop, every view, and every change of who takes
/// part. Written by the server from its own decision — authoritative, unlike
/// what a device reports. 90-day TTL.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HiveAuditEvent {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub tenant_id: ObjectId,
    /// The acting user.
    pub user_id: ObjectId,
    /// Whom the action was about, when not the actor: the participant added,
    /// changed or removed (P1c); the fact written (P1e). P2f-3 — for `fork`, the
    /// session it forks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<ObjectId>,
    /// The device a session event concerns, or a device-scope fact's device.
    /// Absent for an org or a user fact (P1e), which concern none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<ObjectId>,
    /// Absent for a start refused before a session was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<ObjectId>,
    /// `start` | `stop` | `view` | `participant` | `brain` | `policy` (P2c-2a) |
    /// `place` (P2c-2b) | `fork` (P2f-3: its `session_id` the fork, once it is
    /// made) | `purge` (P2g-2) | `search` (P2i-2: its `device_id` the archive
    /// replica asked, no `session_id`, and [`Self::sessions`]).
    pub action: String,
    /// `sent` | `queued` | `refused`; for `participant`, the role given —
    /// `driver` | `reader` — or `removed`; for `brain`, `added` | `edited` |
    /// `archived` | `refused`; for `policy`, `set` | `refused`; for `place`,
    /// `placed`, or `short` with why ([`crate::placement::Short`]); for
    /// `purge`, `issued` | `refused` | `complete`.
    pub outcome: String,
    /// Why, for `refused` and `short` — the server's own reason word.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// FR-90 P2i-2 — for `search`, how many sessions the grant named: the
    /// most the device could search. Never the query, which the server
    /// never has. Absent on every other row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<u32>,
    pub at: DateTime,
}

impl HiveAuditEvent {
    pub const COLLECTION: &'static str = "hive_audit";
}

/// FR-90 P2g-2 — one device's part of a purge.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PurgeEntryState {
    /// Not answered, or answered with a part that failed: sent again on
    /// each of the device's connections.
    Pending,
    /// Both parts done or not there, in the device's own words.
    Done,
    /// Closed by the server with no answer: `reason` says why nothing more
    /// can, or need, be asked of the device.
    Closed,
}

impl PurgeEntryState {
    /// The spelling in the database and the API. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Done => "done",
            Self::Closed => "closed",
        }
    }
}

/// FR-90 P2g-2 — why the server closed a device's part of a purge without
/// asking it.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PurgeClosed {
    /// The device was removed: its credentials are revoked, so it can never
    /// be asked. Its disk keeps what it held (spec §3b).
    DeviceRemoved,
    /// By its own word it holds nothing: it refused the session's join as
    /// a secondary organization's enrollment, or because it had purged the
    /// session already. A secondary connection ignores every Hive frame,
    /// a purge included, so waiting on it would never end.
    HoldsNothing,
}

impl PurgeClosed {
    /// The spelling in the database and the API. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeviceRemoved => "device_removed",
            Self::HoldsNothing => "holds_nothing",
        }
    }
}

/// FR-90 P2g-2 — one device a purge reaches, and what it said.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PurgeEntry {
    pub device_id: ObjectId,
    pub state: PurgeEntryState,
    /// Its words for each part, from its last answer
    /// ([`meshharbor_remote_control::hive::HivePurgePart::as_str`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Why a part failed, in the device's words, capped; or the server's
    /// own word for why it could not be sent (`device_unsupported`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered_at: Option<DateTime>,
    /// For `closed`: why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed: Option<PurgeClosed>,
}

impl PurgeEntry {
    pub fn pending(device_id: ObjectId) -> Self {
        Self {
            device_id,
            state: PurgeEntryState::Pending,
            store: None,
            account: None,
            detail: None,
            answered_at: None,
            closed: None,
        }
    }

    pub fn closed(device_id: ObjectId, why: PurgeClosed) -> Self {
        Self {
            state: PurgeEntryState::Closed,
            closed: Some(why),
            ..Self::pending(device_id)
        }
    }
}

/// FR-90 P2g-2 — a purge (`hive_purges`): the tombstone of a deleted
/// session, kept until every device that held it has answered (design
/// §4.4). Ids, words and times only: nothing of what the session was about.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HivePurge {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub tenant_id: ObjectId,
    pub session_id: ObjectId,
    /// The session's owner: who may read the purge.
    pub owner_id: ObjectId,
    /// Who issued it.
    pub by: ObjectId,
    /// `owner` (P2g-2), `retention` (P2g-3a), or `leaving` (P2g-4b, with
    /// [`Self::member`]). A device's removal writes none (P2g-4a).
    pub reason: String,
    /// The session's room, deleted with the purge; kept so its completion
    /// can delete it again should that first delete have failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_id: Option<ObjectId>,
    pub devices: Vec<PurgeEntry>,
    pub at: DateTime,
    /// When the last device's part closed. A completed purge is kept 90
    /// days, like the audit; one still pending is kept until it completes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done_at: Option<DateTime>,
    /// FR-90 P2g-4b — a member's leaving: the purge of that one device's
    /// copy, which makes no tombstone and leaves the session as it is. Absent
    /// on every purge of a whole session, so `{member: null}` finds those.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<ObjectId>,
}

impl HivePurge {
    pub const COLLECTION: &'static str = "hive_purges";

    /// Whether no device's part is still pending.
    pub fn complete(&self) -> bool {
        self.devices
            .iter()
            .all(|d| d.state != PurgeEntryState::Pending)
    }
}

/// [`HivePurge`] as the API answers it: ids as hex, times as RFC 3339.
#[derive(Serialize, Debug, Clone)]
pub struct PurgeView {
    pub id: String,
    pub session_id: String,
    pub reason: String,
    pub at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub done_at: Option<String>,
    pub devices: Vec<PurgeEntryView>,
}

#[derive(Serialize, Debug, Clone)]
pub struct PurgeEntryView {
    pub device_id: String,
    pub state: PurgeEntryState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answered_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed: Option<PurgeClosed>,
}

impl From<&HivePurge> for PurgeView {
    fn from(p: &HivePurge) -> Self {
        Self {
            id: p.id.to_hex(),
            session_id: p.session_id.to_hex(),
            reason: p.reason.clone(),
            at: rfc3339(p.at),
            done_at: p.done_at.map(rfc3339),
            devices: p
                .devices
                .iter()
                .map(|d| PurgeEntryView {
                    device_id: d.device_id.to_hex(),
                    state: d.state,
                    store: d.store.clone(),
                    account: d.account.clone(),
                    detail: d.detail.clone(),
                    answered_at: d.answered_at.map(rfc3339),
                    closed: d.closed,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-90 P2k-5 — what a copy holds past where its fence ended: nothing at
    /// the current fence or within its fence's end, the rest past it.
    #[test]
    fn a_copy_past_its_fences_end_holds_that_many_events_that_did_not_carry_over() {
        let fences = [FenceMark {
            fence: 1,
            seq: 5,
            hash: "a".repeat(64),
        }];
        assert_eq!(past_end(&fences, 2, 40), 0, "the current fence has no end");
        assert_eq!(past_end(&fences, 1, 3), 0, "within its fence's end");
        assert_eq!(past_end(&fences, 1, 5), 0, "at its fence's end");
        assert_eq!(past_end(&fences, 1, 9), 4, "four past where fence 1 ended");
    }

    #[test]
    fn status_spellings_are_locked_and_match_serde() {
        let all = [
            (SessionStatus::Starting, "starting"),
            (SessionStatus::Idle, "idle"),
            (SessionStatus::Running, "running"),
            (SessionStatus::AwaitingApproval, "awaiting_approval"),
            (SessionStatus::Stopping, "stopping"),
            (SessionStatus::Ended, "ended"),
            (SessionStatus::Refused, "refused"),
            (SessionStatus::Lost, "lost"),
        ];
        for (s, w) in all {
            assert_eq!(s.as_str(), w);
            assert_eq!(serde_json::to_value(s).unwrap(), serde_json::json!(w));
            assert_eq!(
                bson::to_bson(&s).unwrap(),
                bson::Bson::String(w.into()),
                "the database spelling is the filter spelling"
            );
        }
    }

    /// LIVE and the terminal set partition the statuses, and a run-state
    /// report can never move a session that is being stopped.
    #[test]
    fn live_and_terminal_partition_and_stopping_is_not_reportable() {
        for s in SessionStatus::LIVE {
            assert!(!s.is_terminal(), "{s:?}");
        }
        for s in [
            SessionStatus::Ended,
            SessionStatus::Refused,
            SessionStatus::Lost,
        ] {
            assert!(s.is_terminal());
            assert!(!SessionStatus::LIVE.contains(&s));
        }
        assert!(!SessionStatus::REPORTABLE.contains(&SessionStatus::Stopping));
        for s in SessionStatus::REPORTABLE {
            assert!(SessionStatus::LIVE.contains(&s));
        }
    }

    /// What counts as the device's word that it launched a session: only
    /// statuses its own report sets. Never `starting` (the server's, when it
    /// sends the start) nor `stopping` (the server's, when it orders the
    /// stop) — a start the device has said nothing about stays reconcile's.
    #[test]
    fn launched_is_what_only_a_device_report_sets() {
        for s in SessionStatus::LAUNCHED {
            assert!(SessionStatus::REPORTABLE.contains(&s), "{s:?}");
        }
        assert!(!SessionStatus::LAUNCHED.contains(&SessionStatus::Starting));
        assert!(!SessionStatus::LAUNCHED.contains(&SessionStatus::Stopping));
    }

    /// A started session with nothing else set.
    fn bare_session() -> AgentSession {
        let now = DateTime::now();
        AgentSession {
            id: Some(ObjectId::new()),
            tenant_id: ObjectId::new(),
            owner_id: ObjectId::new(),
            drivers: Vec::new(),
            title: "t".into(),
            room_id: None,
            last_turn: None,
            harness: HarnessRef {
                id: "claude-code".into(),
                session: "u".into(),
            },
            location: SessionLocation {
                device_id: ObjectId::new(),
                device_name: "mars".into(),
                folder: "/src".into(),
                account: None,
            },
            status: SessionStatus::Starting,
            fence: 1,
            accepted_at: None,
            refusal: None,
            end_reason: None,
            detail: None,
            created_at: now,
            updated_at: now,
            ended_at: None,
            brain_rev: None,
            vault_role: None,
            origin: SessionOrigin::Started,
            replicaset: None,
            promotion: None,
            fences: Vec::new(),
            moved: None,
            parent: None,
            from_terminal: None,
            path_map: Vec::new(),
            purged: None,
        }
    }

    /// FR-90 P2j-1 — each member's view says how much of the session's chain
    /// its copy holds, by the rule a promotion is decided by: a tail past
    /// where its fence ended counts for nothing, an empty copy at a newer
    /// fence is the least, and a member that reported no tip says nothing.
    #[test]
    fn a_members_view_says_how_much_of_the_chain_its_copy_holds() {
        let now = DateTime::now();
        let member = |role: &str, tip: Option<(i64, i64)>| ReplicaMember {
            device_id: ObjectId::new(),
            role: role.into(),
            state: if tip.is_some() {
                MemberState::Joined
            } else {
                MemberState::Pending
            },
            refusal: None,
            answered_at: None,
            tip: tip.map(|(fence, seq)| MemberTip {
                fence,
                seq,
                hash: "ab".repeat(32),
                checkpoint_seq: None,
                checkpoint_hash: None,
                at: now,
            }),
            purging: None,
            forking: None,
        };
        let s = AgentSession {
            fence: 2,
            replicaset: Some(Replicaset {
                policy_revision: 1,
                min: 2,
                max: 4,
                restricted_tags: Vec::new(),
                members: vec![
                    member("primary", Some((2, 8))),
                    member("owner", Some((1, 10))),
                    member("archive", Some((2, 0))),
                    member("owner", None),
                ],
                short: None,
                placed_at: now,
            }),
            // Fence 1 ended at 7: a copy's 8..=10 at fence 1 was cut off.
            fences: vec![FenceMark {
                fence: 1,
                seq: 7,
                hash: "cd".repeat(32),
            }],
            ..bare_session()
        };
        let v = SessionView::from(&s);
        let holds: Vec<Option<i64>> = v
            .replicaset
            .as_ref()
            .unwrap()
            .members
            .iter()
            .map(|m| m.holds)
            .collect();
        assert_eq!(
            holds,
            [Some(8), Some(7), Some(0), None],
            "the current fence whole, an older one up to its end, an empty copy the least"
        );
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["replicaset"]["members"][1]["holds"], 7);
        assert!(
            json["replicaset"]["members"][3].get("holds").is_none(),
            "no tip, no word: {json}"
        );
    }

    /// FR-90 P2f-4b — a terminal session is being made a managed one only
    /// while its start is unanswered: not another session's start, not once
    /// the device answered or it runs, not an asking that was refused. The
    /// record holds no `from_terminal` before one; the view says when it was
    /// asked, and the word a refused asking left.
    #[test]
    fn a_terminal_session_is_being_made_managed_only_until_its_device_answers() {
        let now = DateTime::now();
        let base = bare_session();
        assert!(!base.managing(), "a start of no terminal's");
        let from = FromTerminal {
            device_id: base.location.device_id,
            by: base.owner_id,
            at: now,
            ended_at: Some(now),
            end_reason: Some("exited".into()),
            detail: None,
            folder: Some(base.location.folder.clone()),
            refused: None,
            refused_detail: None,
        };
        let asked = AgentSession {
            from_terminal: Some(from.clone()),
            ..base.clone()
        };
        assert!(asked.managing());
        assert!(
            !AgentSession {
                accepted_at: Some(now),
                ..asked.clone()
            }
            .managing(),
            "answered"
        );
        assert!(
            !AgentSession {
                status: SessionStatus::Idle,
                ..asked.clone()
            }
            .managing(),
            "it runs"
        );
        let refused = AgentSession {
            status: SessionStatus::Ended,
            origin: SessionOrigin::Adopted,
            from_terminal: Some(FromTerminal {
                refused: Some("launch_failed".into()),
                ..from
            }),
            ..base.clone()
        };
        assert!(!refused.managing(), "refused: the adopted session it was");
        let stored = bson::to_document(&base).unwrap();
        assert!(stored.get("from_terminal").is_none(), "{stored}");
        let v = serde_json::to_value(SessionView::from(&refused)).unwrap();
        assert_eq!(v["from_terminal"]["refused"], "launch_failed", "{v}");
        assert!(v["from_terminal"]["at"].is_string(), "{v}");
        assert!(
            serde_json::to_value(SessionView::from(&base))
                .unwrap()
                .get("from_terminal")
                .is_none()
        );
    }

    #[test]
    fn the_view_renders_times_as_strings_and_ids_as_hex() {
        let now = DateTime::now();
        let s = AgentSession {
            id: Some(ObjectId::new()),
            tenant_id: ObjectId::new(),
            owner_id: ObjectId::new(),
            drivers: Vec::new(),
            title: "t".into(),
            room_id: None,
            last_turn: None,
            harness: HarnessRef {
                id: "claude-code".into(),
                session: "u".into(),
            },
            location: SessionLocation {
                device_id: ObjectId::new(),
                device_name: "mars".into(),
                folder: "/src".into(),
                account: None,
            },
            status: SessionStatus::Starting,
            fence: 1,
            accepted_at: None,
            refusal: None,
            end_reason: None,
            detail: None,
            created_at: now,
            updated_at: now,
            ended_at: None,
            brain_rev: None,
            vault_role: None,
            origin: SessionOrigin::Started,
            replicaset: None,
            promotion: None,
            fences: Vec::new(),
            moved: None,
            parent: None,
            from_terminal: None,
            path_map: Vec::new(),
            purged: None,
        };
        let v = serde_json::to_value(SessionView::from(&s)).unwrap();
        assert!(v["created_at"].is_string(), "{v}");
        assert_eq!(v["id"], s.id.unwrap().to_hex());
        assert_eq!(v["device_id"], s.location.device_id.to_hex());
        assert_eq!(v["fence"], 1);
        assert!(v.get("accepted_at").is_none(), "absent, not null: {v}");
        assert_eq!(v["drivers"], serde_json::json!([]), "always a list: {v}");
        assert_eq!(s.author_display(), "Claude · mars");
        let mut nameless = s.clone();
        nameless.location.device_name.clear();
        assert_eq!(nameless.author_display(), "Claude");
    }

    /// The owner always drives and is never stored as a driver; an older
    /// record with no `drivers` field reads as "the owner alone".
    #[test]
    fn the_owner_always_drives_and_others_only_when_named() {
        let owner = ObjectId::new();
        let named = ObjectId::new();
        let stranger = ObjectId::new();
        let raw = bson::doc! {
            "tenant_id": ObjectId::new(),
            "owner_id": owner,
            "title": "t",
            "harness": { "id": "claude-code", "session": "u" },
            "location": { "device_id": ObjectId::new(), "folder": "/src" },
            "status": "idle",
            "fence": 1_i64,
            "created_at": DateTime::now(),
            "updated_at": DateTime::now(),
        };
        let mut s: AgentSession = bson::from_document(raw).expect("a P0 record still reads");
        assert!(s.drivers.is_empty());
        assert!(s.drives(owner));
        assert!(!s.drives(named));
        assert_eq!(s.all_drivers(), vec![owner]);

        s.drivers.push(named);
        assert!(s.drives(named));
        assert!(!s.drives(stranger));
        assert_eq!(s.all_drivers(), vec![owner, named]);

        // An owner listed by mistake is not counted twice.
        s.drivers.push(owner);
        assert_eq!(s.all_drivers(), vec![owner, named]);
    }

    /// FR-90 P1j — the origin is stored only for an adopted session, so every
    /// started record reads as before; and an adopted one is driven by
    /// nobody, its owner included: the terminal holds the harness.
    #[test]
    fn an_adopted_session_is_driven_by_nobody_and_a_started_one_stores_no_origin() {
        let owner = ObjectId::new();
        let raw = bson::doc! {
            "tenant_id": ObjectId::new(),
            "owner_id": owner,
            "title": "t",
            "harness": { "id": "claude-code", "session": "u" },
            "location": { "device_id": ObjectId::new(), "folder": "/src" },
            "status": "idle",
            "fence": 1_i64,
            "created_at": DateTime::now(),
            "updated_at": DateTime::now(),
        };
        let mut s: AgentSession = bson::from_document(raw).expect("a record before P1j reads");
        assert_eq!(s.origin, SessionOrigin::Started);
        assert!(
            !bson::to_document(&s).unwrap().contains_key("origin"),
            "a started session stores no origin"
        );
        assert!(crate::access::drives_now(&s, owner));

        s.origin = SessionOrigin::Adopted;
        assert_eq!(
            bson::to_document(&s).unwrap().get_str("origin").unwrap(),
            "adopted"
        );
        assert!(
            !crate::access::drives_now(&s, owner),
            "its owner does not drive an adopted session"
        );
        assert_eq!(
            SessionView::from(&s).origin,
            SessionOrigin::Adopted,
            "and the UI is told"
        );
    }

    /// FR-90 P2e-3 — the promotion's words are locked and are what serde
    /// stores; a record before P2e-3 has none and stores none; the view
    /// renders its times as strings.
    #[test]
    fn a_promotion_is_stored_in_its_words_and_absent_before_p2e3() {
        let all = [
            PromotionState::Preparing,
            PromotionState::Joining,
            PromotionState::Draining,
            PromotionState::Syncing,
            PromotionState::Moving,
        ];
        assert_eq!(
            all.map(PromotionState::as_str),
            ["preparing", "joining", "draining", "syncing", "moving"]
        );
        for s in all {
            assert_eq!(
                bson::to_bson(&s).unwrap(),
                bson::Bson::String(s.as_str().into())
            );
        }
        assert!(!PromotionState::BEFORE_THE_MOVE.contains(&PromotionState::Moving));

        let raw = bson::doc! {
            "tenant_id": ObjectId::new(),
            "owner_id": ObjectId::new(),
            "title": "t",
            "harness": { "id": "claude-code", "session": "u" },
            "location": { "device_id": ObjectId::new(), "folder": "/src" },
            "status": "idle",
            "fence": 1_i64,
            "created_at": DateTime::now(),
            "updated_at": DateTime::now(),
        };
        let mut s: AgentSession = bson::from_document(raw).expect("a record before P2e-3 reads");
        assert!(s.promotion.is_none());
        assert!(!bson::to_document(&s).unwrap().contains_key("promotion"));

        let now = DateTime::now();
        let p = Promotion {
            id: ObjectId::new(),
            to: ObjectId::new(),
            to_name: "venus".into(),
            to_role: "owner".into(),
            folder: "/src".into(),
            from: s.location.clone(),
            from_fence: 1,
            by: s.owner_id,
            state: PromotionState::Syncing,
            started_at: now,
            deadline: DateTime::from_millis(now.timestamp_millis() + 1000),
            drained: Some(DrainedTip {
                seq: 9,
                hash: "ab".repeat(32),
            }),
            unreachable_from: false,
            prior: None,
            teleport: false,
            fork: None,
        };
        assert!(p.in_flight(now));
        assert!(
            !p.in_flight(p.deadline),
            "past its deadline it holds nothing"
        );
        s.promotion = Some(p.clone());
        let back: AgentSession = bson::from_document(bson::to_document(&s).unwrap()).unwrap();
        assert_eq!(back.promotion, Some(p.clone()));
        let stored = bson::to_document(&s).unwrap();
        assert!(
            !stored
                .get_document("promotion")
                .unwrap()
                .contains_key("teleport"),
            "a promotion stores no teleport word, as every one before P2f-1"
        );
        assert!(
            !stored
                .get_document("promotion")
                .unwrap()
                .contains_key("fork"),
            "nor a fork's plan"
        );
        let v = serde_json::to_value(SessionView::from(&s)).unwrap();
        assert_eq!(v["promotion"]["state"], "syncing", "{v}");
        assert!(v["promotion"]["deadline"].is_string(), "{v}");
        assert_eq!(v["promotion"]["to"], p.to.to_hex());
        assert!(v["promotion"].get("teleport").is_none(), "{v}");
        assert!(v["promotion"].get("fork").is_none(), "{v}");

        // P2f-1 — a teleport says so, stored and viewed.
        s.promotion = Some(Promotion {
            teleport: true,
            state: PromotionState::Joining,
            ..p.clone()
        });
        let back: AgentSession = bson::from_document(bson::to_document(&s).unwrap()).unwrap();
        assert!(back.promotion.as_ref().is_some_and(|p| p.teleport));
        let v = serde_json::to_value(SessionView::from(&s)).unwrap();
        assert_eq!(
            (&v["promotion"]["teleport"], &v["promotion"]["state"]),
            (&serde_json::json!(true), &serde_json::json!("joining")),
            "{v}"
        );

        // P2f-3c — and so does a fork onto a device that held no copy: its
        // plan stored whole, its view saying it is a fork.
        s.promotion = Some(Promotion {
            teleport: true,
            fork: Some(ForkPlan {
                title: "try it".into(),
            }),
            state: PromotionState::Joining,
            ..p
        });
        let stored = bson::to_document(&s).unwrap();
        assert_eq!(
            stored
                .get_document("promotion")
                .and_then(|p| p.get_document("fork"))
                .and_then(|f| f.get_str("title"))
                .ok(),
            Some("try it"),
            "{stored}"
        );
        let back: AgentSession = bson::from_document(stored).unwrap();
        assert_eq!(
            back.promotion.and_then(|p| p.fork).map(|f| f.title),
            Some("try it".to_string())
        );
        let v = serde_json::to_value(SessionView::from(&s)).unwrap();
        assert_eq!(v["promotion"]["fork"], true, "{v}");
    }

    /// FR-90 P2g-2 — a purge's words are locked and are what serde stores; a
    /// record before P2g-2 holds no tombstone and stores none; a purge is
    /// complete only once no device's part is pending; an entry stores no
    /// word it does not have; and the view renders times as strings.
    #[test]
    fn a_purge_is_complete_only_once_no_devices_part_is_pending() {
        let states = [
            PurgeEntryState::Pending,
            PurgeEntryState::Done,
            PurgeEntryState::Closed,
        ];
        assert_eq!(
            states.map(PurgeEntryState::as_str),
            ["pending", "done", "closed"]
        );
        for s in states {
            assert_eq!(
                bson::to_bson(&s).unwrap(),
                bson::Bson::String(s.as_str().into())
            );
        }
        let closed = [PurgeClosed::DeviceRemoved, PurgeClosed::HoldsNothing];
        assert_eq!(
            closed.map(PurgeClosed::as_str),
            ["device_removed", "holds_nothing"]
        );
        for c in closed {
            assert_eq!(
                bson::to_bson(&c).unwrap(),
                bson::Bson::String(c.as_str().into())
            );
        }
        assert!(
            !bson::to_document(&bare_session())
                .unwrap()
                .contains_key("purged"),
            "a record that is no tombstone stores none"
        );

        let (a, b) = (ObjectId::new(), ObjectId::new());
        let mut p = HivePurge {
            id: ObjectId::new(),
            tenant_id: ObjectId::new(),
            session_id: ObjectId::new(),
            owner_id: ObjectId::new(),
            by: ObjectId::new(),
            reason: "owner".into(),
            room_id: None,
            devices: vec![
                PurgeEntry::pending(a),
                PurgeEntry::closed(b, PurgeClosed::DeviceRemoved),
            ],
            at: DateTime::now(),
            done_at: None,
            member: None,
        };
        assert!(!p.complete(), "a's part is pending");
        let stored = bson::to_document(&p).unwrap();
        assert!(
            !stored.contains_key("member"),
            "a whole session's purge stores no member, so `{{member: null}}` finds it: {stored}"
        );
        let first = stored.get_array("devices").unwrap()[0]
            .as_document()
            .unwrap()
            .clone();
        for word in ["store", "account", "detail", "answered_at", "closed"] {
            assert!(!first.contains_key(word), "{word}: {first}");
        }
        let back: HivePurge = bson::from_document(stored).unwrap();
        assert_eq!(back.devices, p.devices);

        p.devices[0].state = PurgeEntryState::Done;
        p.devices[0].store = Some("done".into());
        p.devices[0].account = Some("not_there".into());
        assert!(p.complete(), "done and closed: nothing pending");
        let v = serde_json::to_value(PurgeView::from(&p)).unwrap();
        assert!(v["at"].is_string(), "{v}");
        assert!(v.get("done_at").is_none(), "{v}");
        assert_eq!(v["devices"][0]["state"], "done", "{v}");
        assert_eq!(v["devices"][0]["account"], "not_there", "{v}");
        assert_eq!(v["devices"][1]["closed"], "device_removed", "{v}");
        assert_eq!(v["devices"][1]["device_id"], b.to_hex(), "{v}");
    }

    /// FR-90 P2c-3 — the member words are locked, and a member placed before
    /// P2c-3, with no state, reads as `pending`: its join is still to send.
    #[test]
    fn a_member_placed_before_p2c3_is_pending() {
        let all = [
            MemberState::Pending,
            MemberState::Joined,
            MemberState::Refused,
            MemberState::Leaving,
        ];
        assert_eq!(
            all.map(MemberState::as_str),
            ["pending", "joined", "refused", "leaving"]
        );
        for s in all {
            assert_eq!(
                bson::to_bson(&s).unwrap(),
                bson::Bson::String(s.as_str().into())
            );
        }
        let old = bson::doc! { "device_id": ObjectId::new(), "role": "owner" };
        let m: ReplicaMember = bson::from_document(old).expect("a P2c-2b member reads");
        assert_eq!(m.state, MemberState::Pending);
        assert_eq!((m.refusal, m.answered_at, m.tip), (None, None, None));
        // P2g-4b — and no purge of its copy was ever issued, nor any fork
        // made from it.
        assert_eq!((m.purging, m.forking), (None, None));
    }
}
