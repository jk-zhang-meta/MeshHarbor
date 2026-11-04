// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2e-3 — promotion, the server's half: the session's owner moves it
//! to one of its members (spec §3b "Promotion"; design §4.6, §6.2).
//!
//! The promotion lives ON THE RECORD (`agent_sessions.promotion`), and every
//! step is a compare-and-set on the state it leaves. A device's frame drives
//! each one, on whichever pod reads it, and a frame that arrives twice, late
//! or after the promotion ended matches nothing. The only pod-local piece is
//! one timer per promotion ([`watch`]), which fails a step that ran past its
//! bound. A promotion past its deadline counts as failed anywhere, so one
//! whose pod died strands nothing.
//!
//! | State | Entered when | Leaves when | Past its bound |
//! |---|---|---|---|
//! | `preparing` | the owner promotes: `rc:hive.prepare` to the member | the member's `rc:hive.prepare_ack`; away from an unreachable primary, a ready one goes straight to `syncing` at the member's own tip (P2e-6a) | failed, nothing moved |
//! | `joining` (P2f-1, a teleport only) | the target is ready: it joins the replicaset in the `teleport` role, and the target and the primary are each sent their join | both answered `joined`, the primary said where its copy ends since the teleport began, and the target's copy holds as much: `rc:hive.drain` to the primary | failed; the target lets its copy go (`leaving`) |
//! | `draining` | the member is ready: `rc:hive.drain` to the primary | the primary's `rc:hive.drained` | failed; the primary gets its lease word back |
//! | `syncing` | the primary drained, at `{seq, hash}` | the member's own tip equals it: the lease moves | failed, as above |
//! | `moving` | the lease moved: join, `rc:hive.move`, `rc:hive.start` to the member | its start's answer | nothing moves back on silence (P2e-6b) |
//!
//! | Rule | Why |
//! |---|---|
//! | prepare first, the lease last: the member passes every start gate before anything moves, and the lease moves only once its tip is the drained one | a refusal or a stalled sync leaves the session where it was |
//! | the lease moves to `fence + 1` in one compare-and-set, member roles with it | the fence is the one word every device checks; two promotions raced from two browsers move it once |
//! | the old primary is demoted at the move, before the member is started | from the move on nothing it does counts; stopping its harness before the next starts is what keeps two executors from overlapping (AC4) |
//! | a failure before the move gives the primary its lease word back (`rc:hive.lease` at its fence) | the word lifts the drain: the lease stayed |
//! | a start refused after the move moves the lease back, to `fence + 2` | a fence handed out once is never handed out again |
//! | the room carries every outcome, in its words | FR-83: a move that cannot happen says so, with the gate that said no |
//! | P2e-6a — a primary with no connection and no heartbeat for [`UNREACHABLE_SECS`], whose last build holds a leased session to the word, is moved away from with no drain, to the member that holds the most, at that member's own tip | it cannot drain; its sidecar stopped calling the model by then, and back, it runs nothing before it is demoted. What it wrote past that tip is set aside when it follows the new primary (P2d-3) |
//! | P2e-6a — a primary that did not drain in time keeps its socket | a link that carries one way only is closed already, by the device's receive deadline or the server's reaper; a slow drain on a healthy link (the device may take 120 s, the server waits 75 s) must not cost the device a reconnect |
//! | P2f-1 — a teleport moves a session to a device that holds no copy of it: `POST …/teleport`, never to a joined member (that is a promotion), between two connections advertising `hive-teleport`, with the primary online | the stream's only source is the primary, so a teleport away from an unreachable one has nothing to copy from |
//! | P2f-1 — the drain is asked only once the target's copy holds what the primary said it holds, after the teleport began | the whole copy moves while the session still runs; the drain moves only what it added |
//! | P2f-1 — a teleport that fails before the move, or whose start is refused after it, lets the target's copy go (`leaving`) | its owner never offered to hold copies: it took one only to run the session |

use std::time::Duration;

use axum::{
    Json,
    extract::{Path, State},
};
use bson::{DateTime, doc, oid::ObjectId};
use dashmap::DashMap;
use meshharbor_db::models::role::permissions;
use meshharbor_remote_control::{
    error::Error as HubError,
    hive::{
        HiveCopyTip, HiveDrainRefusal, HivePlace, HiveRefusal, HiveReplicaRole, hive_limits,
        is_hash_hex,
        promote_limits::{MAX_EARLIER_PLACES, UNREACHABLE_SECS},
        replica_limits,
    },
    models::{Agent, RpcCap},
    signaling::ServerMsg,
};
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use crate::HiveState;
use crate::model::{
    AgentSession, DrainedTip, ForkPlan, MemberState, MovedStart, Promotion, PromotionState,
    SessionLocation, SessionOrigin, SessionStatus, SessionView,
};
use crate::placement::MemberRole;
use crate::room;
use crate::routes::{Audit, clean_folder, device_refusal_message, member_tenant, parse_oid};

/// How long each step before the move may take
/// (`hive.promote_{prepare,join,drain,sync}_secs`).
#[derive(Debug, Clone, Copy)]
pub struct Bounds {
    pub prepare: Duration,
    /// P2f-1 — a teleport's target's copy catching up.
    pub join: Duration,
    pub drain: Duration,
    pub sync: Duration,
}

impl Bounds {
    pub fn of(settings: &meshharbor_config::HiveSettings) -> Self {
        Self {
            prepare: Duration::from_secs(settings.promote_prepare_secs),
            join: Duration::from_secs(settings.promote_join_secs),
            drain: Duration::from_secs(settings.promote_drain_secs),
            sync: Duration::from_secs(settings.promote_sync_secs),
        }
    }

    fn of_state(&self, s: PromotionState) -> Duration {
        match s {
            PromotionState::Preparing => self.prepare,
            PromotionState::Joining => self.join,
            PromotionState::Draining => self.drain,
            PromotionState::Syncing => self.sync,
            // Expiry only: a start the member never answered is re-sent on
            // its every connection for the start's own redelivery window.
            PromotionState::Moving => Duration::from_secs(
                u64::try_from(hive_limits::START_REDELIVERY_WINDOW_SECS).unwrap_or(600),
            ),
        }
    }
}

fn deadline_after(d: Duration) -> DateTime {
    let ms = i64::try_from(d.as_millis()).unwrap_or(i64::MAX / 2);
    DateTime::from_millis(DateTime::now().timestamp_millis().saturating_add(ms))
}

/// `POST …/session/{session_id}/promote`, and (P2f-1) `…/teleport`.
#[derive(Debug, Deserialize)]
pub struct PromoteBody {
    /// The member to move it to; for a teleport, a device that holds no copy.
    pub device_id: String,
    /// Where it runs there, as typed. Defaults to the folder it runs in now.
    #[serde(default)]
    pub folder: Option<String>,
}

/// Why the SERVER refused a promotion. The member's own refusals are the
/// start's [`HiveRefusal`] words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromoteDenyReason {
    OrgArchived,
    NoPermission,
    NotRunning,
    InProgress,
    MovedTooOften,
    NotAMember,
    /// P2f-1 — a teleport to a device that holds a copy already.
    AlreadyAMember,
    NotFreshest,
    AlreadyPrimary,
    DeviceOffline,
    DeviceUnsupported,
    PrimaryOffline,
    PrimaryUnsupported,
    RateLimited,
    /// FR-90 P3-2b — the session holds a vault role the vault's policies do
    /// not let this person take on the target device.
    RoleRefused,
    /// P3-2b — the session holds a role and no vault is mounted to decide it.
    VaultUnavailable,
    /// P3-2b — the vault could not decide (or record) it.
    RoleUndecided,
}

impl PromoteDenyReason {
    /// The spelling in the answer and the audit. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OrgArchived => "org_archived",
            Self::NoPermission => "no_permission",
            Self::NotRunning => "session_not_running",
            Self::InProgress => "promotion_in_progress",
            Self::MovedTooOften => "moved_too_often",
            Self::NotAMember => "not_a_member",
            Self::AlreadyAMember => "already_a_member",
            Self::NotFreshest => "not_freshest",
            Self::AlreadyPrimary => "already_primary",
            Self::DeviceOffline => "device_offline",
            Self::DeviceUnsupported => "device_unsupported",
            Self::PrimaryOffline => "primary_offline",
            Self::PrimaryUnsupported => "primary_unsupported",
            Self::RateLimited => "rate_limited",
            Self::RoleRefused => "role_refused",
            Self::VaultUnavailable => "vault_unavailable",
            Self::RoleUndecided => "role_undecided",
        }
    }

    /// What the person is told: each names its own next step.
    pub const fn message(self) -> &'static str {
        match self {
            Self::OrgArchived => "this organization is archived; its sessions do not move",
            Self::NoPermission => {
                "your role does not include \"Run agent sessions\" (HIVE_RUN); \
                 an owner can grant it"
            }
            Self::NotRunning => {
                "the session is not running: it is over, being stopped, not started yet, \
                 or adopted from a terminal"
            }
            Self::InProgress => "the session is being moved already",
            Self::MovedTooOften => {
                "the session has moved as many times as one session can; \
                 a new session can be moved again"
            }
            Self::NotAMember => {
                "the device holds no copy of the session: only a member of its replicaset \
                 that took its copy can run it — or teleport the session there"
            }
            Self::AlreadyAMember => {
                "the device holds a copy of the session already: promote the session to it"
            }
            Self::NotFreshest => {
                "the device the session runs on is unreachable, and another member holds more \
                 of the session than that device: move it to the member that holds the most"
            }
            Self::AlreadyPrimary => "the session runs on that device already",
            Self::DeviceOffline => "the device is offline",
            Self::DeviceUnsupported => {
                "the device's agent does not take part in moving sessions — update it"
            }
            Self::PrimaryOffline => {
                "the device the session runs on is offline, so it cannot hand the session over; \
                 once it has been unreachable for 230 s, the session can be moved away from it \
                 to a member of its replicaset"
            }
            Self::PrimaryUnsupported => {
                "the device the session runs on does not take part in moving sessions — update it"
            }
            Self::RateLimited => "too many sessions started on that device in the last minute",
            Self::RoleRefused => {
                "the session holds a vault role the vault's policies do not let you take on \
                 that device"
            }
            Self::VaultUnavailable => {
                "the session holds a vault role and the vault is not available here to decide it"
            }
            Self::RoleUndecided => "the vault could not decide the role just now — try again",
        }
    }

    pub const ALL: [PromoteDenyReason; 17] = [
        Self::OrgArchived,
        Self::NoPermission,
        Self::NotRunning,
        Self::InProgress,
        Self::MovedTooOften,
        Self::NotAMember,
        Self::AlreadyAMember,
        Self::NotFreshest,
        Self::AlreadyPrimary,
        Self::DeviceOffline,
        Self::DeviceUnsupported,
        Self::PrimaryOffline,
        Self::PrimaryUnsupported,
        Self::RateLimited,
        Self::RoleRefused,
        Self::VaultUnavailable,
        Self::RoleUndecided,
    ];
}

impl From<crate::vault_gate::RoleDeny> for PromoteDenyReason {
    fn from(d: crate::vault_gate::RoleDeny) -> Self {
        match d {
            crate::vault_gate::RoleDeny::Refused(_) => Self::RoleRefused,
            crate::vault_gate::RoleDeny::Unavailable => Self::VaultUnavailable,
            crate::vault_gate::RoleDeny::Undecided => Self::RoleUndecided,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PromoteResponse {
    /// `promoting` (the member is ready, and the primary drains), `refused`
    /// (by the server or the member — `reason` says which gate), or `pending`
    /// (the member has not answered yet; the session's `promotion` and its
    /// room say how it goes on).
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub session: SessionView,
}

impl PromoteResponse {
    fn refused(reason: &str, message: String, s: &AgentSession) -> Self {
        Self {
            outcome: "refused",
            reason: Some(reason.to_string()),
            message: Some(message),
            session: SessionView::from(s),
        }
    }
}

/// What the route that waits on a member's prepare is told.
#[derive(Debug, Clone)]
enum PrepareAnswer {
    Ready,
    /// The member's word, or the server's when the promotion failed first.
    Refused {
        reason: String,
        message: String,
    },
}

struct Waiter {
    device_id: ObjectId,
    tx: oneshot::Sender<PrepareAnswer>,
}

/// The routes waiting for a member's `rc:hive.prepare_ack`. Pod-local, like
/// the start's: the prepare is pushed only when the member's socket is on
/// this pod, and its answer arrives on that socket. Keyed by PROMOTION, not
/// by session: a route that gives up must never take the waiter of the next
/// promotion of the same session. Bound to the member, so another device's
/// answer wakes nobody.
#[derive(Default)]
pub struct PrepareAcks {
    waiters: DashMap<ObjectId, Waiter>,
}

impl PrepareAcks {
    pub fn new() -> Self {
        Self::default()
    }

    fn expect(&self, promotion: ObjectId, device_id: ObjectId) -> oneshot::Receiver<PrepareAnswer> {
        let (tx, rx) = oneshot::channel();
        self.waiters.insert(promotion, Waiter { device_id, tx });
        rx
    }

    fn deliver(&self, promotion: ObjectId, from_device: ObjectId, answer: PrepareAnswer) {
        if let Some((_, w)) = self
            .waiters
            .remove_if(&promotion, |_, w| w.device_id == from_device)
        {
            let _ = w.tx.send(answer);
        }
    }

    fn forget(&self, promotion: ObjectId) {
        self.waiters.remove(&promotion);
    }

    /// Routes waiting now. Tests and diagnostics only.
    pub fn pending(&self) -> usize {
        self.waiters.len()
    }
}

/// P2e-6a — where the session's primary is, as a promotion needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// Online here, and taking part in a promotion: it drains.
    Online,
    /// Unreachable for [`UNREACHABLE_SECS`]: no drain is asked of it.
    Unreachable,
}

/// P2e-6a — whether `row`'s device may be moved away from with no drain:
/// not heard from for [`UNREACHABLE_SECS`], and a build that, when it comes
/// back, holds a leased session to the server's word (`hive-lease` in what it
/// last advertised), so it calls the model for nothing before its demote.
/// `last_seen_at` is the moment the server stopped talking to it: an Offline
/// mark stamps it (a teardown, the read loop's reaper, a shutdown), and a
/// heartbeat, every 30 s on any pod, re-asserts Online over it.
fn unreachable_reach(row: &Agent, now: DateTime) -> Result<Reach, PromoteDenyReason> {
    let silent_ms = now.timestamp_millis() - row.last_seen_at.timestamp_millis();
    if silent_ms < i64::try_from(UNREACHABLE_SECS * 1000).unwrap_or(i64::MAX) {
        return Err(PromoteDenyReason::PrimaryOffline);
    }
    if !row.capabilities.has_rpc(RpcCap::HiveLease) {
        return Err(PromoteDenyReason::PrimaryUnsupported);
    }
    Ok(Reach::Unreachable)
}

/// P2e-6a — the joined member, other than `target` and the primary, whose
/// copy the server last heard holds more of the session's chain than a copy
/// that ends at `(fence, seq)` ([`on_chain`]), if one does.
fn fresher_than(s: &AgentSession, target: ObjectId, fence: i64, seq: i64) -> Option<ObjectId> {
    let holds = on_chain(s, fence, seq);
    s.replicaset.as_ref()?.members.iter().find_map(|m| {
        let t = m.tip.as_ref()?;
        (m.device_id != target
            && m.device_id != s.location.device_id
            && m.role != MemberRole::Primary.as_str()
            && m.state == MemberState::Joined
            && on_chain(s, t.fence, t.seq) > holds)
            .then_some(m.device_id)
    })
}

/// P2e-6a — how much of the session's chain a copy that ends at
/// `(fence, seq)` holds, as a `seq`: [`crate::model::on_chain`], the one rule
/// the API answers for each member too (P2j-1).
fn on_chain(s: &AgentSession, fence: i64, seq: i64) -> i64 {
    crate::model::on_chain(&s.fences, fence, seq)
}

/// P2e-6a — whether a copy that ends at `(fence, seq, hash)` ends on the
/// session's chain: at or before where its fence ended, and at the end
/// itself, on the same event. The lease never moves to a copy past an end:
/// the next fence would begin on a tail the record cut off.
fn within_ends(s: &AgentSession, fence: i64, seq: i64, hash: &str) -> bool {
    s.fences
        .iter()
        .find(|m| m.fence == fence)
        .is_none_or(|end| seq < end.seq || (seq == end.seq && hash == end.hash))
}

/// The member's own last report of where its copy ends, `(0, 0)` without one.
fn reported(s: &AgentSession, device: ObjectId) -> (i64, i64) {
    s.replicaset
        .as_ref()
        .and_then(|r| r.members.iter().find(|m| m.device_id == device))
        .and_then(|m| m.tip.as_ref())
        .map_or((0, 0), |t| (t.fence, t.seq))
}

/// FR-90 P2f-1 — what moves the session: a promotion to a member of its
/// replicaset, or a teleport to a device that holds no copy of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Promote,
    Teleport,
    /// P2f-3c — a fork onto a device that holds no copy: a teleport's steps
    /// up to the copy, then the fork made there. The session never moves.
    Fork,
}

impl Kind {
    /// The audit's action.
    const fn action(self) -> &'static str {
        match self {
            Self::Promote => "promote",
            Self::Teleport => "teleport",
            Self::Fork => "fork",
        }
    }

    fn of(p: &Promotion) -> Self {
        if p.fork.is_some() {
            Self::Fork
        } else if p.teleport {
            Self::Teleport
        } else {
            Self::Promote
        }
    }
}

/// Gates 4 on, past the session and the device lookups. The outer `Result`
/// is the infrastructure, the inner one the policy — as the start's. P2e-6a —
/// and where the primary is. P2f-1 — a teleport's target holds no copy yet,
/// and its primary must be online: the stream copies the session from it.
async fn authorize(
    state: &HiveState,
    s: &AgentSession,
    target: ObjectId,
    user_id: ObjectId,
    kind: Kind,
) -> Result<Result<Reach, PromoteDenyReason>, ApiError> {
    let tid = s.tenant_id;
    let tenant = state.tenants.base.find_by_id(tid).await?;
    if tenant.is_archived {
        return Ok(Err(PromoteDenyReason::OrgArchived));
    }
    let perms = state.tenants.get_member_permissions(tid, user_id).await?;
    if !permissions::has(perms, permissions::HIVE_RUN) {
        return Ok(Err(PromoteDenyReason::NoPermission));
    }
    // P2e-6b — a session waiting on a moved start its device never answered
    // runs nowhere yet. It is moved on as from any unreachable primary, and
    // only once that device is unreachable (below); the move that sent the
    // start is then replaced, in flight or not.
    let unanswered = unanswered_move(s);
    let launched =
        s.accepted_at.is_some() || SessionStatus::LAUNCHED.contains(&s.status) || unanswered;
    if !SessionStatus::REPORTABLE.contains(&s.status)
        || !launched
        || s.origin == SessionOrigin::Adopted
    {
        return Ok(Err(PromoteDenyReason::NotRunning));
    }
    let moving = s
        .promotion
        .as_ref()
        .filter(|p| p.in_flight(DateTime::now()));
    if let Some(p) = moving {
        // A teleport never replaces a move: it copies from the primary.
        let replaceable = kind == Kind::Promote
            && unanswered
            && p.state == PromotionState::Moving
            && p.to == s.location.device_id;
        if !replaceable {
            return Ok(Err(PromoteDenyReason::InProgress));
        }
    }
    // P2e-5b — a move keeps where one fence ended and a move back a second,
    // and a device takes a join naming at most MAX_FENCE_MARKS of them: one
    // more, and no member could ever join the session again.
    if moved_too_often(s) {
        return Ok(Err(PromoteDenyReason::MovedTooOften));
    }
    if target == s.location.device_id {
        return Ok(Err(PromoteDenyReason::AlreadyPrimary));
    }
    let hub = &state.fleet.rc_hub;
    let takes_part = match kind {
        Kind::Promote => {
            if member_role(s, target).is_none() {
                return Ok(Err(PromoteDenyReason::NotAMember));
            }
            hub.agent_supports_hive_promote(target, tid)
        }
        // P2f-1 — a device that holds a copy already is promoted to. P2f-3c —
        // a fork is gated by its own route, and would be as a teleport.
        Kind::Teleport | Kind::Fork => {
            if member_role(s, target).is_some() {
                return Ok(Err(PromoteDenyReason::AlreadyAMember));
            }
            hub.agent_supports_hive_teleport(target, tid)
        }
    };
    match takes_part {
        None => return Ok(Err(PromoteDenyReason::DeviceOffline)),
        Some(false) => return Ok(Err(PromoteDenyReason::DeviceUnsupported)),
        Some(true) => {}
    }
    // P2f-3 — a fork moves only to a device that starts forks: one that does
    // not would start it empty, or refuse its copy's names.
    if s.parent.is_some() && hub.agent_supports_hive_fork(target, tid) != Some(true) {
        return Ok(Err(PromoteDenyReason::DeviceUnsupported));
    }
    // P2f-1 — a teleport copies the session from its primary, which must
    // be online here: no copy elsewhere can stand in for it yet.
    if kind == Kind::Teleport {
        if unanswered {
            return Ok(Err(PromoteDenyReason::NotRunning));
        }
        match hub.agent_supports_hive_teleport(s.location.device_id, tid) {
            None => return Ok(Err(PromoteDenyReason::PrimaryOffline)),
            Some(false) => return Ok(Err(PromoteDenyReason::PrimaryUnsupported)),
            Some(true) => {}
        }
        if !state
            .start_limiter
            .check(user_id, target, hive_limits::START_RATE_PER_MINUTE)
        {
            return Ok(Err(PromoteDenyReason::RateLimited));
        }
        return Ok(Ok(Reach::Online));
    }
    // P2e-6a — an unreachable primary is waited out, then moved away from
    // with no drain, to the member that holds the most.
    let reach = match hub.agent_supports_hive_promote(s.location.device_id, tid) {
        // P2e-6b — online, a device that has not answered its start may yet:
        // the move that sent it is still under way, or the device runs nothing.
        Some(_) if unanswered => {
            return Ok(Err(if moving.is_some() {
                PromoteDenyReason::InProgress
            } else {
                PromoteDenyReason::NotRunning
            }));
        }
        Some(true) => Reach::Online,
        Some(false) => return Ok(Err(PromoteDenyReason::PrimaryUnsupported)),
        None => {
            let row = match state
                .fleet
                .agents
                .find_live_in_tenant(tid, s.location.device_id)
                .await
            {
                Ok(row) => row,
                Err(meshharbor_services::dao::base::DaoError::NotFound) => {
                    return Ok(Err(PromoteDenyReason::PrimaryOffline));
                }
                Err(e) => return Err(e.into()),
            };
            match unreachable_reach(&row, DateTime::now()) {
                Ok(reach) => reach,
                Err(reason) => return Ok(Err(reason)),
            }
        }
    };
    if reach == Reach::Unreachable {
        let (fence, seq) = reported(s, target);
        if fresher_than(s, target, fence, seq).is_some() {
            return Ok(Err(PromoteDenyReason::NotFreshest));
        }
    }
    // LAST: only a promotion that would reach the member spends a token.
    if !state
        .start_limiter
        .check(user_id, target, hive_limits::START_RATE_PER_MINUTE)
    {
        return Ok(Err(PromoteDenyReason::RateLimited));
    }
    Ok(Ok(reach))
}

/// FR-90 P2e-6b — whether `s` waits on a moved start its device never
/// answered: past the first fence, starting there, never accepted, and no
/// run state reported (one that lands before the answer counts as launched).
fn unanswered_move(s: &AgentSession) -> bool {
    s.fence > 1 && s.status == SessionStatus::Starting && s.accepted_at.is_none()
}

/// FR-90 P2e-6b — where the start `s` waits on came from: kept on the record
/// since P2e-6b, read from the move that sent it on a record from before.
fn prior_of(s: &AgentSession) -> Option<MovedStart> {
    s.moved.clone().or_else(|| {
        s.promotion
            .as_ref()
            .filter(|p| p.state == PromotionState::Moving && p.to == s.location.device_id)
            .map(|p| MovedStart {
                from: p.from.clone(),
                by: p.by,
                at: p.started_at,
            })
    })
}

/// Whether one more promotion could leave `s` with more fences' ends than a
/// device takes in one join ([`replica_limits::MAX_FENCE_MARKS`]): a move
/// keeps one, and the move back a refused start makes keeps a second.
fn moved_too_often(s: &AgentSession) -> bool {
    s.fences.len() + 2 > replica_limits::MAX_FENCE_MARKS
}

/// The role `device` holds a copy of `s` in, as a member that took it:
/// `joined`, never the primary.
fn member_role(s: &AgentSession, device: ObjectId) -> Option<String> {
    s.replicaset.as_ref()?.members.iter().find_map(|m| {
        (m.device_id == device
            && m.role != MemberRole::Primary.as_str()
            && m.state == MemberState::Joined)
            .then(|| m.role.clone())
    })
}

/// The audit row of a move, `promote` or (P2f-1) `teleport`. P2f-3c — a
/// `fork`'s rows name the session it forks as their target, and no session
/// of their own, as the fork route's rows do: the fork is not made yet.
fn audit(
    kind: Kind,
    s: &AgentSession,
    by: ObjectId,
    device: ObjectId,
    outcome: &'static str,
    reason: Option<&'static str>,
) -> Audit {
    let (target_id, session_id) = match kind {
        Kind::Fork => (s.id, None),
        Kind::Promote | Kind::Teleport => (None, s.id),
    };
    Audit {
        tenant_id: s.tenant_id,
        user_id: by,
        target_id,
        device_id: device,
        session_id,
        action: kind.action(),
        outcome,
        reason,
    }
}

/// `POST /api/tenant/{tenant_id}/hive/session/{session_id}/promote` — the
/// owner moves the session to a member of its replicaset. Answered once the
/// member said whether it is ready (or it has not, within the start's bound);
/// the rest goes on without the caller, and the room says how it ended.
pub async fn promote(
    State(state): State<HiveState>,
    auth: AuthUser,
    Path((tenant_id, session_id)): Path<(String, String)>,
    Json(body): Json<PromoteBody>,
) -> Result<Json<PromoteResponse>, ApiError> {
    begin(state, auth, &tenant_id, &session_id, body, Kind::Promote).await
}

/// FR-90 P2f-1 — `POST /api/tenant/{tenant_id}/hive/session/{session_id}/teleport`
/// — the owner moves the session to a device that holds no copy of it. The
/// device prepares, joins the replicaset for this one session and takes a
/// copy while the session still runs; then the promotion goes on as to any
/// member. Answered once the device said whether it is ready, as `promote`
/// is: `teleporting`, `refused` or `pending`.
pub async fn teleport(
    State(state): State<HiveState>,
    auth: AuthUser,
    Path((tenant_id, session_id)): Path<(String, String)>,
    Json(body): Json<PromoteBody>,
) -> Result<Json<PromoteResponse>, ApiError> {
    begin(state, auth, &tenant_id, &session_id, body, Kind::Teleport).await
}

/// A move's route, either kind: the gates, the record, the prepare, and the
/// target's answer.
async fn begin(
    state: HiveState,
    auth: AuthUser,
    tenant_id: &str,
    session_id: &str,
    body: PromoteBody,
    kind: Kind,
) -> Result<Json<PromoteResponse>, ApiError> {
    let tid = member_tenant(&state, tenant_id, &auth).await?;
    if !state.replicaset {
        return Err(ApiError::NotFound(
            "moving sessions is off on this server".into(),
        ));
    }
    let sid = parse_oid(session_id, "session_id")?;
    // The owner's alone: anyone else's read of the id is a 404.
    let mut s = state.sessions.find_owned(tid, auth.user_id, sid).await?;
    let target = parse_oid(&body.device_id, "device_id")?;
    let folder = clean_folder(body.folder.as_deref().unwrap_or(&s.location.folder))?;
    // LIVE in this org: a removed or foreign device answers like a bogus one.
    let device = state.fleet.agents.find_live_in_tenant(tid, target).await?;
    // P2f-1 — a teleport adds its target to the replicaset: a session that
    // has none yet (started before the switch, its device not back since)
    // is placed first, as its device's next connection would place it.
    if kind == Kind::Teleport && s.replicaset.is_none() {
        crate::placement::place_unplaced(&state, tid, s.location.device_id).await?;
        s = state.sessions.find_owned(tid, auth.user_id, sid).await?;
    }

    // P3-2b — a session that holds a vault role moves with it only as the
    // vault allows it for this person on the TARGET device: a policy may
    // grant a role on a build box and nowhere else.
    let decided = match (
        authorize(&state, &s, target, auth.user_id, kind).await?,
        s.vault_role.as_deref(),
    ) {
        (Ok(reach), Some(role)) => {
            match crate::vault_gate::assume(
                &state,
                tid,
                auth.user_id,
                role,
                sid,
                &device,
                kind.action(),
            )
            .await
            {
                Ok(()) => Ok(reach),
                Err(deny) => Err(PromoteDenyReason::from(deny)),
            }
        }
        (decided, _) => decided,
    };
    let reach = match decided {
        Ok(reach) => reach,
        Err(reason) => {
            info!(
                tenant = %tid, session = %sid, device = %target, user = %auth.user_id,
                reason = reason.as_str(), action = kind.action(), "hive: move refused"
            );
            audit(
                kind,
                &s,
                auth.user_id,
                target,
                "refused",
                Some(reason.as_str()),
            )
            .write(&state)
            .await;
            return Ok(Json(PromoteResponse::refused(
                reason.as_str(),
                reason.message().to_string(),
                &s,
            )));
        }
    };
    let to = MoveTo {
        target,
        device: &device,
        folder,
        fork: None,
    };
    let started = start_move(&state, &s, auth.user_id, to, kind, reach).await?;
    let s = state.sessions.find_owned(tid, auth.user_id, sid).await?;
    Ok(Json(match started {
        Started::Refused(reason) => {
            PromoteResponse::refused(reason.as_str(), reason.message().to_string(), &s)
        }
        Started::Ready => PromoteResponse {
            outcome: match kind {
                Kind::Promote => "promoting",
                Kind::Teleport | Kind::Fork => "teleporting",
            },
            reason: None,
            message: None,
            session: SessionView::from(&s),
        },
        Started::PrepareRefused { reason, message } => {
            PromoteResponse::refused(&reason, message, &s)
        }
        Started::Pending => PromoteResponse {
            outcome: "pending",
            reason: None,
            message: Some(
                "the device has not answered yet; the session says how the move goes on".into(),
            ),
            session: SessionView::from(&s),
        },
    }))
}

/// FR-90 P2f-3c — where a move whose gates passed goes: the device, the
/// folder it runs in there, and, for a fork, the fork it is for.
pub(crate) struct MoveTo<'a> {
    pub target: ObjectId,
    pub device: &'a Agent,
    pub folder: String,
    /// A fork's plan: present for a fork's move (`Kind::Fork`) and only for it.
    pub fork: Option<ForkPlan>,
}

/// What became of a move's start, its gates passed.
#[derive(Debug)]
pub(crate) enum Started {
    /// Refused in the server's words, at the record or the push: nothing
    /// reached the target.
    Refused(PromoteDenyReason),
    /// The target is ready.
    Ready,
    /// The target said no, in its words.
    PrepareRefused { reason: String, message: String },
    /// The target has not answered within the start's bound.
    Pending,
}

/// A move whose gates passed, of every kind: its record, its prepare, and its
/// target's answer, waited for within the start's bound. The rest goes on
/// without the caller, step by step on the devices' frames.
async fn start_move(
    state: &HiveState,
    s: &AgentSession,
    by: ObjectId,
    to: MoveTo<'_>,
    kind: Kind,
    reach: Reach,
) -> Result<Started, ApiError> {
    let Some(sid) = s.id else {
        return Err(ApiError::Internal("a session record without its id".into()));
    };
    let tid = s.tenant_id;
    let MoveTo {
        target,
        device,
        folder,
        fork,
    } = to;
    // P2f-3c — a fork's plan is what makes the move a fork's: without it, a
    // caught-up target would drain the session and move it.
    let fork = match kind {
        Kind::Fork => {
            Some(fork.ok_or_else(|| ApiError::Internal("a fork's move without its fork".into()))?)
        }
        Kind::Promote | Kind::Teleport => None,
    };
    let to_role = match kind {
        Kind::Promote => {
            member_role(s, target).unwrap_or_else(|| MemberRole::Owner.as_str().into())
        }
        Kind::Teleport | Kind::Fork => MemberRole::Teleport.as_str().into(),
    };
    let unanswered = kind == Kind::Promote && unanswered_move(s);
    // Read before the promotion begins: nothing after it may fail on the way
    // to the push, or the promotion would wait out its bound for nothing.
    let user = state.users.base.find_by_id(s.owner_id).await?;
    let now = DateTime::now();
    let p = Promotion {
        id: ObjectId::new(),
        to: target,
        to_name: device.name.clone(),
        to_role,
        folder: folder.clone(),
        from: s.location.clone(),
        from_fence: s.fence,
        by,
        state: PromotionState::Preparing,
        started_at: now,
        deadline: deadline_after(state.promote_bounds.prepare),
        drained: None,
        unreachable_from: reach == Reach::Unreachable,
        prior: unanswered.then(|| prior_of(s)).flatten(),
        teleport: kind != Kind::Promote,
        fork,
    };
    // P2f-3c — a fork's refusals are the fork route's to word and audit.
    let refused_row = |reason: PromoteDenyReason| {
        (kind != Kind::Fork).then(|| audit(kind, s, by, target, "refused", Some(reason.as_str())))
    };
    if !state
        .sessions
        .begin_promotion(tid, by, sid, &p, unanswered)
        .await?
    {
        // Another tab's promotion won, or the session moved on meanwhile.
        let held = state.sessions.find(sid).await?;
        let reason = if held.is_some_and(|h| h.promotion.is_some()) {
            PromoteDenyReason::InProgress
        } else {
            PromoteDenyReason::NotRunning
        };
        if let Some(row) = refused_row(reason) {
            row.write(state).await;
        }
        return Ok(Started::Refused(reason));
    }

    // The waiter before the push: the member's answer, however fast, must
    // find it.
    let answer = state.prepare_acks.expect(p.id, target);
    let fence = u64::try_from(s.fence + 1).unwrap_or_default();
    let msg = ServerMsg::HivePrepare {
        session_id: sid,
        fence,
        harness: s.harness.id.clone(),
        harness_session: s.harness.session.clone(),
        folder,
        user_id: s.owner_id,
        user_email: user.email,
        caller: user.display_name,
        teleport: p.teleport,
        // P2f-2b — the target may take the workspace against its clone: a
        // teleport's only (P2f-3c: a fork-joining one's too), and only once
        // the operator turned it on.
        have_want: p.teleport && state.teleport_have_want,
    };
    let hub = &state.fleet.rc_hub;
    let pushed = match kind {
        Kind::Promote => hub.push_hive_promote(target, tid, msg),
        Kind::Teleport | Kind::Fork => hub.push_hive_teleport(target, tid, msg),
    };
    if let Err(e) = pushed {
        // Gone, or reconnected as a build that takes no part, between the
        // gate and the push: nothing reached it.
        state.prepare_acks.forget(p.id);
        let _ = state
            .sessions
            .end_promotion(sid, p.id, &[PromotionState::Preparing])
            .await;
        let reason = match e {
            HubError::ExecUnsupported(_) => PromoteDenyReason::DeviceUnsupported,
            _ => PromoteDenyReason::DeviceOffline,
        };
        if let Some(row) = refused_row(reason) {
            row.write(state).await;
        }
        return Ok(Started::Refused(reason));
    }
    // P2f-3c — a fork's prepare is not yet the fork: its start is sent once
    // the target's copy caught up, and audited then.
    let sent = if kind == Kind::Fork {
        "joining"
    } else {
        "sent"
    };
    audit(kind, s, by, target, sent, None).write(state).await;
    info!(
        tenant = %tid, session = %sid, from = %s.location.device_id, to = %target,
        user = %by, action = kind.action(), "hive: move started — prepare sent"
    );
    tokio::spawn(watch(state.clone(), sid, p.id));

    let heard = tokio::time::timeout(
        Duration::from_secs(hive_limits::START_ACK_TIMEOUT_SECS),
        answer,
    )
    .await;
    state.prepare_acks.forget(p.id);
    Ok(match heard {
        Ok(Ok(PrepareAnswer::Ready)) => Started::Ready,
        Ok(Ok(PrepareAnswer::Refused { reason, message })) => {
            Started::PrepareRefused { reason, message }
        }
        _ => Started::Pending,
    })
}

/// FR-90 P2f-3c — a fork of `s` onto a device that holds no copy of it, the
/// fork route's gates passed: a teleport's steps up to the copy begin (the
/// record, the prepare, the target's answer). Once the target's copy caught
/// up with the primary, the fork is made there ([`make_fork`]).
pub(crate) async fn begin_fork_join(
    state: &HiveState,
    s: &AgentSession,
    by: ObjectId,
    to: MoveTo<'_>,
) -> Result<Started, ApiError> {
    start_move(state, s, by, to, Kind::Fork, Reach::Online).await
}

/// Why a promotion failed before the lease moved.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Failure {
    /// The member said no to the prepare, in the start's words.
    PrepareRefused {
        word: HiveRefusal,
        detail: Option<String>,
    },
    /// A step ran past its bound.
    Timeout(PromotionState),
    /// The primary did not drain, in its words.
    DrainRefused {
        word: HiveDrainRefusal,
        detail: Option<String>,
    },
    /// The primary's answer named no tip that can be read.
    DrainUnreadable,
    /// The member's copy is not the primary's: past the drained tip, or
    /// another event at it.
    Diverged,
    /// The primary could not be told to drain.
    PrimaryGone,
    /// The member no longer holds a joined copy.
    MemberLeft,
    /// P2e-6a — the member said it was ready without saying where its copy
    /// ends: a build from before P2e-6a, which a promotion away from an
    /// unreachable primary cannot move the lease to.
    NoCopyTip,
    /// P2e-6a — another member's copy, as last heard, ends past the
    /// member's own: moving to it would lose what only that one holds.
    NotFreshest,
    /// P2e-6a — the unreachable primary was heard from again before the
    /// lease moved.
    PrimaryBack,
    /// P2e-6a — the member's copy ends past where an older fence ended:
    /// it holds a tail a move cut off, which it has not set aside yet.
    CutOff,
    /// P2f-1 — the teleport's target refused its join, in its words
    /// ([`meshharbor_remote_control::hive::HiveJoinRefusal`]).
    JoinRefused { word: String },
    /// P2f-1 — the primary refused its join as the primary: it does not say
    /// where its copy ends, so the target has no tip to catch up with.
    PrimaryJoinRefused { word: String },
    /// P2f-1 — the session changed under the teleport before its target
    /// joined: the device took a copy meanwhile, or its row went.
    Changed,
}

/// P2f-1 — what a join refusal means, in the room's words.
fn join_refusal_message(word: &str) -> &'static str {
    match word {
        "not_prepared" => {
            "it was no longer prepared to run the session (its daemon may have restarted)"
        }
        "quota" => "its store is at its quota (hive_store_quota_mib)",
        "purged" => "it purged the session, and removal is final",
        "stale_fence" => "it holds the session at a newer fence",
        "secondary_org" => "the session is not its primary organization's",
        "replica_disabled" => "it does not hold copies (hive_replica)",
        "archive_disabled" => "it does not offer itself as an archive (hive_archive)",
        _ => "it said no",
    }
}

impl Failure {
    /// The audit's word.
    fn reason(&self) -> &'static str {
        match self {
            Self::PrepareRefused { word, .. } => word.as_str(),
            Self::Timeout(PromotionState::Preparing) => "prepare_timeout",
            Self::Timeout(PromotionState::Joining) => "join_timeout",
            Self::Timeout(PromotionState::Draining) => "drain_timeout",
            Self::Timeout(PromotionState::Syncing) => "sync_timeout",
            Self::Timeout(PromotionState::Moving) => "start_timeout",
            Self::DrainRefused {
                word: HiveDrainRefusal::NotRunning,
                ..
            } => "drain_not_running",
            Self::DrainRefused { .. } => "drain_refused",
            Self::DrainUnreadable => "drain_unreadable",
            Self::Diverged => "diverged",
            Self::PrimaryGone => "primary_offline",
            Self::MemberLeft => "member_left",
            Self::NoCopyTip => "no_copy_tip",
            Self::NotFreshest => "not_freshest",
            Self::PrimaryBack => "primary_back",
            Self::CutOff => "cut_off",
            Self::JoinRefused { .. } => "join_refused",
            Self::PrimaryJoinRefused { .. } => "primary_join_refused",
            Self::Changed => "changed",
        }
    }

    /// Why, for the room and the waiting caller, its names escaped.
    fn why(&self, p: &Promotion) -> String {
        let to = room::name_label(&p.to_name);
        let from = room::name_label(&p.from.device_name);
        let with = |detail: &Option<String>| {
            detail
                .as_deref()
                .map(|d| format!(" ({})", room::md_escape(d)))
                .unwrap_or_default()
        };
        match self {
            Self::PrepareRefused { word, detail } => format!(
                "{to} cannot run it: {}{}",
                device_refusal_message(word.as_str()),
                with(detail)
            ),
            Self::Timeout(PromotionState::Preparing) => format!("{to} did not answer in time"),
            Self::Timeout(PromotionState::Draining) => {
                format!("{from} did not finish its turn and hand the session over in time")
            }
            Self::Timeout(PromotionState::Joining)
            | Self::Timeout(PromotionState::Syncing)
            | Self::Timeout(PromotionState::Moving) => {
                format!("the copy on {to} did not catch up in time")
            }
            Self::DrainRefused {
                word: HiveDrainRefusal::NotRunning,
                detail,
            } => format!("{from} does not run the session{}", with(detail)),
            Self::DrainRefused { detail, .. } => {
                format!("{from} could not hand the session over{}", with(detail))
            }
            Self::DrainUnreadable => format!("{from} answered in a way that could not be read"),
            Self::Diverged => format!("the copy on {to} is not the one {from} holds"),
            Self::PrimaryGone => format!("{from} could not be reached"),
            Self::MemberLeft => format!("{to} no longer holds a copy of the session"),
            Self::NoCopyTip => {
                format!("{to} did not say where its copy ends: its agent needs an update")
            }
            Self::NotFreshest => format!("another member holds more of the session than {to}"),
            Self::PrimaryBack => format!("{from} came back before the session moved: try again"),
            Self::CutOff => format!(
                "the copy on {to} holds events an earlier move left out; it sets them aside \
                 once it follows the session again"
            ),
            Self::JoinRefused { word } => format!(
                "{to} did not take a copy of the session: {}",
                join_refusal_message(word)
            ),
            Self::PrimaryJoinRefused { word } => format!(
                "{from} did not say where its copy of the session ends: {}",
                join_refusal_message(word)
            ),
            Self::Changed => "the session changed while it was being moved: try again".into(),
        }
    }
}

/// End the promotion `p` names, if it is still in the state `p` says — the
/// one its caller read, so a step taken meanwhile is never failed in the name
/// of the one before it: the room told why, the audit written, a route still
/// waiting answered, and — once the primary was asked to drain, and unless
/// the caller sends it itself — the primary given its lease word back, which
/// lifts the drain.
pub(crate) async fn fail(
    state: &HiveState,
    session_id: ObjectId,
    p: &Promotion,
    failure: Failure,
    give_back: bool,
) {
    if !PromotionState::BEFORE_THE_MOVE.contains(&p.state) {
        return;
    }
    let before = match state
        .sessions
        .end_promotion(session_id, p.id, &[p.state])
        .await
    {
        Ok(Some(b)) => b,
        Ok(None) => return,
        Err(e) => {
            return warn!(session = %session_id, %e, "hive: a failed promotion was not ended");
        }
    };
    let Some(was) = before.promotion.clone() else {
        return;
    };
    // P2f-1 — a teleport's target, added at its joining step, took its copy
    // only to run the session.
    if was.teleport && was.state != PromotionState::Preparing {
        let_go(state, session_id, was.to).await;
    }
    // A session stopped or ended meanwhile: its end says so, and it holds
    // no lease to give back.
    let runs = SessionStatus::REPORTABLE.contains(&before.status);
    let fence = u64::try_from(was.from_fence).unwrap_or_default();
    if give_back
        && runs
        && matches!(
            was.state,
            PromotionState::Draining | PromotionState::Syncing
        )
    {
        crate::lease::push(
            state,
            before.tenant_id,
            was.from.device_id,
            session_id,
            fence,
        );
    }
    let why = failure.why(&was);
    info!(
        session = %session_id, to = %was.to, state = was.state.as_str(),
        reason = failure.reason(), "hive: promotion failed — nothing moved"
    );
    audit(
        Kind::of(&was),
        &before,
        was.by,
        was.to,
        "failed",
        Some(failure.reason()),
    )
    .write(state)
    .await;
    if runs {
        let note = match Kind::of(&was) {
            // P2f-3c — the session never moved: it is the fork that did not
            // happen.
            Kind::Fork => room::fork_failed_note(&was, &why),
            Kind::Promote | Kind::Teleport => room::move_failed_note(&was, &why),
        };
        room::note(state, &before, note).await;
    }
    let reason = match &failure {
        Failure::PrepareRefused { word, .. } => word.as_str().to_string(),
        other => other.reason().to_string(),
    };
    state.prepare_acks.deliver(
        was.id,
        was.to,
        PrepareAnswer::Refused {
            reason,
            message: why,
        },
    );
}

/// P2f-1 — a teleport that did not happen lets its target go (`leaving`), and
/// that target's streams of the session end: it took its copy only to run the
/// session. What it holds goes with its purge, once the session holds its
/// `min` copies without it (P2g-4b).
async fn let_go(state: &HiveState, sid: ObjectId, target: ObjectId) {
    if let Err(e) = state.sessions.mark_leaving(sid, target).await {
        warn!(session = %sid, device = %target, %e, "hive: a teleport's target was not let go");
    }
    crate::stream::end_for_member(state, sid, target, "teleport_ended");
}

/// The one timer of a promotion: a step that runs past its bound fails it.
/// It reads the record at each deadline, so a step taken meanwhile — on any
/// pod — only moves the deadline on. Gone once the lease moved: from there
/// the start's own redelivery governs, and nothing moves back on silence.
async fn watch(state: HiveState, session_id: ObjectId, pid: ObjectId) {
    loop {
        let p = match state.sessions.find(session_id).await {
            Ok(Some(s)) => match s.promotion {
                Some(p) if p.id == pid => p,
                _ => return,
            },
            Ok(None) => return,
            Err(e) => {
                warn!(session = %session_id, %e, "hive: a promotion's record was not read");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        if p.state == PromotionState::Moving {
            return;
        }
        let left = p.deadline.timestamp_millis() - DateTime::now().timestamp_millis();
        if left <= 0 {
            return fail(&state, session_id, &p, Failure::Timeout(p.state), true).await;
        }
        tokio::time::sleep(Duration::from_millis(u64::try_from(left).unwrap_or(0) + 10)).await;
    }
}

/// The promotion `s` holds, if it is in `state` and `device` is the one
/// that step waits on.
fn awaited(s: &AgentSession, state: PromotionState, device: ObjectId) -> Option<Promotion> {
    let p = s.promotion.as_ref()?;
    let waits_on = match state {
        PromotionState::Draining => p.from.device_id,
        _ => p.to,
    };
    (p.state == state && waits_on == device).then(|| p.clone())
}

/// `rc:hive.prepare_ack`: the member's answer to the prepare of the
/// promotion moving the session to it, at the fence the prepare named.
pub(crate) async fn on_prepare_ack(
    state: &HiveState,
    device_id: ObjectId,
    session_id: ObjectId,
    fence: u64,
    refused: Option<HiveRefusal>,
    detail: Option<String>,
    tip: Option<HiveCopyTip>,
) {
    let s = match state.sessions.find(session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return,
        Err(e) => {
            return warn!(session = %session_id, %e, "hive: a prepare answer's session was not read");
        }
    };
    let Some(p) = awaited(&s, PromotionState::Preparing, device_id)
        .filter(|p| u64::try_from(p.from_fence + 1).ok() == Some(fence))
    else {
        return debug!(
            session = %session_id, device = %device_id, fence,
            "hive: a prepare answer for no promotion preparing on this device at that fence"
        );
    };
    if let Some(word) = refused {
        let detail = crate::agent_socket::clamp_words(detail, hive_limits::MAX_DETAIL_LEN);
        return fail(
            state,
            session_id,
            &p,
            Failure::PrepareRefused { word, detail },
            true,
        )
        .await;
    }
    // P2f-1 — a teleport's target takes its copy before anything drains.
    if p.teleport {
        return begin_joining(state, &s, &p).await;
    }
    // P2e-6a — away from a primary that was unreachable: no drain. One
    // heard from again meanwhile drains after all.
    if p.unreachable_from && !primary_heard_from(state, &s, &p).await {
        return move_from_unreachable(state, &s, &p, device_id, tip).await;
    }
    if drain_primary(state, &s, &p, PromotionState::Preparing).await {
        state
            .prepare_acks
            .deliver(p.id, device_id, PrepareAnswer::Ready);
    }
}

/// The member is ready, or (P2f-1) a teleport's target caught up: the
/// promotion steps from `from` to `draining`, and the primary is told to
/// drain; one that cannot be told fails the promotion. `true` = the drain
/// was asked.
async fn drain_primary(
    state: &HiveState,
    s: &AgentSession,
    p: &Promotion,
    from: PromotionState,
) -> bool {
    let Some(session_id) = s.id else {
        return false;
    };
    match state
        .sessions
        .advance_promotion(
            session_id,
            p.id,
            from,
            PromotionState::Draining,
            deadline_after(state.promote_bounds.drain),
            doc! {},
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => return false,
        Err(e) => {
            warn!(session = %session_id, %e, "hive: a promotion did not take its next step");
            return false;
        }
    }
    let drain = ServerMsg::HiveDrain {
        session_id,
        fence: u64::try_from(p.from_fence).unwrap_or_default(),
    };
    if let Err(e) = state
        .fleet
        .rc_hub
        .push_hive_promote(p.from.device_id, s.tenant_id, drain)
    {
        debug!(session = %session_id, %e, "hive: the drain did not reach the primary");
        let draining = Promotion {
            state: PromotionState::Draining,
            ..p.clone()
        };
        fail(state, session_id, &draining, Failure::PrimaryGone, true).await;
        return false;
    }
    info!(session = %session_id, to = %p.to, "hive: the member is ready — the primary drains");
    let by = display_name(state, p.by).await;
    room::note(state, s, room::moving_note(p, &by)).await;
    true
}

/// FR-90 P2f-1 — a teleport's target is ready: it joins the replicaset in the
/// `teleport` role, and the teleport takes its `joining` step. The target is
/// sent its join, and the primary its join as the primary, which it answers
/// by saying where its copy ends; a session that ran alone is owed that
/// join, and leased from then on, as when placement gives it a first member
/// (P2c-4, P2e-2). The caller hears the target is ready; the drain waits for
/// the target's copy ([`check_joined`]).
async fn begin_joining(state: &HiveState, s: &AgentSession, p: &Promotion) {
    let Some(sid) = s.id else { return };
    // Before the target's row: whether the primary checkpoints already.
    let told = crate::replica::replicated(s);
    match state
        .sessions
        .begin_joining(sid, p.id, p.to, deadline_after(state.promote_bounds.join))
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            // Moved on by another frame, or the device took a copy meanwhile.
            if let Ok(Some(now)) = state.sessions.find(sid).await
                && let Some(q) = now
                    .promotion
                    .filter(|q| q.id == p.id && q.state == PromotionState::Preparing)
            {
                fail(state, sid, &q, Failure::Changed, false).await;
            }
            return;
        }
        Err(e) => return warn!(session = %sid, %e, "hive: a teleport's target did not join"),
    }
    let s = match state.sessions.find(sid).await {
        Ok(Some(s)) => s,
        _ => return warn!(session = %sid, "hive: a joining teleport's record was not read back"),
    };
    if !told {
        if let Err(e) = state.sessions.owe_primary_join(sid).await {
            warn!(session = %sid, %e, "hive: the primary was not owed its join");
        }
        let fence = u64::try_from(s.fence).unwrap_or_default();
        crate::lease::push(state, s.tenant_id, s.location.device_id, sid, fence);
    }
    crate::replica::push_join(state, &s, p.to, HiveReplicaRole::Teleport);
    crate::replica::push_join(state, &s, s.location.device_id, HiveReplicaRole::Primary);
    info!(session = %sid, to = %p.to, action = Kind::of(p).action(), "hive: the teleport's target is ready — it takes a copy first");
    let by = display_name(state, p.by).await;
    let note = match Kind::of(p) {
        Kind::Fork => room::fork_joining_note(p, &by),
        Kind::Promote | Kind::Teleport => room::teleporting_note(p, &by),
    };
    room::note(state, &s, note).await;
    state.prepare_acks.deliver(p.id, p.to, PrepareAnswer::Ready);
    // The answers may be in already.
    if let Ok(Some(now)) = state.sessions.find(sid).await {
        check_joined(state, &now).await;
    }
}

/// P2f-1 — where a teleport's joining step stands.
#[derive(Debug, PartialEq)]
enum Joined {
    /// Not yet: a join unanswered, no tip from the primary since the
    /// teleport began, or the target's copy behind that tip.
    Waiting,
    /// The target's copy holds what the primary said it holds: drain.
    CaughtUp,
    /// It cannot go on.
    Failed(Failure),
}

/// P2f-1 — the joining step of `p`, from the record: the target's row and
/// the primary's, their answers, and their tips. The primary's tip counts
/// only once heard since the teleport began: its join asks for it, and an
/// older one may predate what the session did since. Compared as
/// [`on_chain`] does, a tail past an ended fence counting for nothing.
fn joined_of(s: &AgentSession, p: &Promotion) -> Joined {
    let row = |device: ObjectId, primary: bool| {
        s.replicaset.as_ref().and_then(|r| {
            r.members.iter().find(|m| {
                m.device_id == device && (m.role == MemberRole::Primary.as_str()) == primary
            })
        })
    };
    let word =
        |m: &crate::model::ReplicaMember| m.refusal.clone().unwrap_or_else(|| "other".into());
    let Some(target) = row(p.to, false) else {
        return Joined::Failed(Failure::MemberLeft);
    };
    match target.state {
        MemberState::Refused => return Joined::Failed(Failure::JoinRefused { word: word(target) }),
        MemberState::Leaving => return Joined::Failed(Failure::MemberLeft),
        MemberState::Pending => return Joined::Waiting,
        MemberState::Joined => {}
    }
    let Some(primary) = row(s.location.device_id, true) else {
        return Joined::Failed(Failure::Changed);
    };
    match primary.state {
        MemberState::Refused => {
            return Joined::Failed(Failure::PrimaryJoinRefused {
                word: word(primary),
            });
        }
        MemberState::Pending | MemberState::Leaving => return Joined::Waiting,
        MemberState::Joined => {}
    }
    let Some(ends) = primary.tip.as_ref().filter(|t| t.at >= p.started_at) else {
        return Joined::Waiting;
    };
    let Some(holds) = target.tip.as_ref() else {
        return Joined::Waiting;
    };
    if on_chain(s, holds.fence, holds.seq) >= on_chain(s, ends.fence, ends.seq) {
        Joined::CaughtUp
    } else {
        Joined::Waiting
    }
}

/// P2f-1 — a teleport joining: on to the drain once its target caught up,
/// failed when it cannot go on, and nothing while it waits.
async fn check_joined(state: &HiveState, s: &AgentSession) {
    let (Some(sid), Some(p)) = (s.id, s.promotion.clone()) else {
        return;
    };
    if p.state != PromotionState::Joining {
        return;
    }
    match joined_of(s, &p) {
        Joined::Waiting => {}
        // P2f-3c — a fork's target caught up: the fork is made there, and the
        // session stays where it is.
        Joined::CaughtUp if Kind::of(&p) == Kind::Fork => {
            info!(session = %sid, to = %p.to, "hive: the fork's target caught up");
            make_fork(state, s, &p).await;
        }
        Joined::CaughtUp => {
            info!(session = %sid, to = %p.to, "hive: the teleport's target caught up");
            drain_primary(state, s, &p, PromotionState::Joining).await;
        }
        Joined::Failed(f) => fail(state, sid, &p, f, false).await,
    }
}

/// FR-90 P2f-3c — a fork's target caught up with the session's primary: the
/// fork-joining move ends, its target is let go from this session's
/// replicaset (it took its copy only to fork it), and the fork is made there
/// from that copy, as the fork route makes one on a device that held a copy
/// already. Off the frame's task: making it waits on the device's answer to
/// its start. P2g-4b — the move ends and the target is let go in ONE write,
/// its row naming the fork about to be made: the copy stays while that
/// fork may still need it, then goes with the target's purge.
async fn make_fork(state: &HiveState, s: &AgentSession, p: &Promotion) {
    let Some(sid) = s.id else { return };
    let fork = ObjectId::new();
    let before = match state.sessions.end_fork_joining(sid, p.id, p.to, fork).await {
        Ok(Some(before)) => before,
        // Another frame took the step, or failed it, first.
        Ok(None) => return,
        Err(e) => return warn!(session = %sid, %e, "hive: a fork's move was not ended"),
    };
    crate::stream::end_for_member(state, sid, p.to, "teleport_ended");
    let (state, p) = (state.clone(), p.clone());
    tokio::spawn(async move { crate::fork::make_joined(&state, &before, &p, fork).await });
}

/// P2f-1 — a join's answer landed (`rc:hive.replica.join_ack`): a teleport
/// joining, if one waits on that device, its target or its primary, may go
/// on.
pub(crate) async fn on_join_answer(state: &HiveState, session_id: ObjectId, device_id: ObjectId) {
    match state
        .sessions
        .base
        .find_one(doc! {
            "_id": session_id,
            "promotion.state": PromotionState::Joining.as_str(),
            "$or": [
                { "promotion.to": device_id },
                { "promotion.from.device_id": device_id },
            ],
        })
        .await
    {
        Ok(Some(s)) => check_joined(state, &s).await,
        Ok(None) => {}
        Err(e) => warn!(session = %session_id, %e, "hive: a join answer's teleport was not read"),
    }
}

/// P2e-6a — whether the promotion's primary has been heard from since it
/// was found unreachable: online on this pod, or its row's `last_seen_at` too
/// recent for it to be unreachable. A connection on any pod refreshes that
/// field (its hello, before the connection is registered, and every
/// heartbeat), so one on another pod is seen too.
async fn primary_heard_from(state: &HiveState, s: &AgentSession, p: &Promotion) -> bool {
    if state
        .fleet
        .rc_hub
        .agent_supports_hive_promote(p.from.device_id, s.tenant_id)
        .is_some()
    {
        return true;
    }
    match state
        .fleet
        .agents
        .find_live_in_tenant(s.tenant_id, p.from.device_id)
        .await
    {
        Ok(row) => unreachable_reach(&row, DateTime::now()).is_err(),
        // Removed meanwhile: it is never heard from again.
        Err(meshharbor_services::dao::base::DaoError::NotFound) => false,
        Err(e) => {
            warn!(session = ?s.id, %e, "hive: the primary's row was not read — taken as heard from");
            true
        }
    }
}

/// P2e-6a — the member is ready, and the primary has been unreachable for
/// [`UNREACHABLE_SECS`]: no drain. The lease moves to where the member says
/// its copy ends, which must be readable and no older than any other
/// member's, as last heard. Syncing first, its `drained` that tip, so a
/// primary that reconnects from here on is given no word; then the primary
/// is asked about once more, and one heard from meanwhile fails the
/// promotion and is given its word back.
async fn move_from_unreachable(
    state: &HiveState,
    s: &AgentSession,
    p: &Promotion,
    device_id: ObjectId,
    tip: Option<HiveCopyTip>,
) {
    let Some(sid) = s.id else { return };
    let tip = tip.and_then(|t| {
        let fence = i64::try_from(t.fence).ok()?;
        let seq = i64::try_from(t.seq).ok()?;
        (is_hash_hex(&t.hash) && fence <= p.from_fence).then_some((fence, seq, t.hash))
    });
    let Some((fence, seq, hash)) = tip else {
        return fail(state, sid, p, Failure::NoCopyTip, true).await;
    };
    if !within_ends(s, fence, seq, &hash) {
        return fail(state, sid, p, Failure::CutOff, true).await;
    }
    if fresher_than(s, device_id, fence, seq).is_some() {
        return fail(state, sid, p, Failure::NotFreshest, true).await;
    }
    match state
        .sessions
        .advance_promotion(
            sid,
            p.id,
            PromotionState::Preparing,
            PromotionState::Syncing,
            deadline_after(state.promote_bounds.sync),
            doc! { "promotion.drained": { "seq": seq, "hash": &hash } },
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => return,
        Err(e) => {
            return warn!(session = %sid, %e, "hive: a promotion did not take its next step");
        }
    }
    let now = match state.sessions.find(sid).await {
        Ok(Some(now)) => now,
        _ => return warn!(session = %sid, "hive: a promotion's record was not read back"),
    };
    let Some(syncing) = now
        .promotion
        .clone()
        .filter(|q| q.id == p.id && q.state == PromotionState::Syncing)
    else {
        return;
    };
    if primary_heard_from(state, &now, &syncing).await {
        return fail(state, sid, &syncing, Failure::PrimaryBack, true).await;
    }
    info!(
        session = %sid, to = %device_id, seq,
        "hive: the member is ready and the primary unreachable — the lease moves to the member's copy"
    );
    let by = display_name(state, p.by).await;
    room::note(state, &now, room::moving_unreachable_note(&syncing, &by)).await;
    move_lease(state, &now, &syncing).await;
    // After the move: a move that failed answered the route itself.
    state
        .prepare_acks
        .deliver(p.id, device_id, PrepareAnswer::Ready);
}

/// `rc:hive.drained`: the primary's answer to the drain, at the fence it runs
/// the session at. Its tip, once well formed, is what the member's copy must
/// reach before the lease moves.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn on_drained(
    state: &HiveState,
    device_id: ObjectId,
    session_id: ObjectId,
    fence: u64,
    seq: Option<u64>,
    hash: Option<String>,
    refused: Option<HiveDrainRefusal>,
    detail: Option<String>,
) {
    let s = match state.sessions.find(session_id).await {
        Ok(Some(s)) => s,
        Ok(None) => return,
        Err(e) => {
            return warn!(session = %session_id, %e, "hive: a drain answer's session was not read");
        }
    };
    let Some(p) = awaited(&s, PromotionState::Draining, device_id)
        .filter(|p| u64::try_from(p.from_fence).ok() == Some(fence))
    else {
        return debug!(
            session = %session_id, device = %device_id, fence,
            "hive: a drain answer for no promotion draining this device at that fence"
        );
    };
    if let Some(word) = refused {
        let detail = crate::agent_socket::clamp_words(detail, hive_limits::MAX_DETAIL_LEN);
        return fail(
            state,
            session_id,
            &p,
            Failure::DrainRefused { word, detail },
            true,
        )
        .await;
    }
    let tip = match (seq.and_then(|q| i64::try_from(q).ok()), hash) {
        (Some(seq), Some(hash)) if is_hash_hex(&hash) => DrainedTip { seq, hash },
        _ => return fail(state, session_id, &p, Failure::DrainUnreadable, true).await,
    };
    match state
        .sessions
        .advance_promotion(
            session_id,
            p.id,
            PromotionState::Draining,
            PromotionState::Syncing,
            deadline_after(state.promote_bounds.sync),
            doc! { "promotion.drained": { "seq": tip.seq, "hash": &tip.hash } },
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => return,
        Err(e) => {
            return warn!(session = %session_id, %e, "hive: a promotion did not take its next step");
        }
    }
    info!(session = %session_id, seq = tip.seq, "hive: the primary drained — the member's copy is to reach its tip");
    // The member may hold it already.
    if let Ok(Some(s)) = state.sessions.find(session_id).await {
        check_sync(state, &s).await;
    }
}

/// A member's tip landed (`rc:hive.replica.tip`, or a manifest's entry):
/// the promotion moving the session to that member, if one is syncing, may
/// move the lease now. P2f-1 — and a teleport joining may go on to the
/// drain, on its target's tip or on its primary's.
pub(crate) async fn on_tip(state: &HiveState, session_id: ObjectId, device_id: ObjectId) {
    match state
        .sessions
        .base
        .find_one(doc! {
            "_id": session_id,
            "$or": [
                {
                    "promotion.state": PromotionState::Syncing.as_str(),
                    "promotion.to": device_id,
                },
                {
                    "promotion.state": PromotionState::Joining.as_str(),
                    "$or": [
                        { "promotion.to": device_id },
                        { "promotion.from.device_id": device_id },
                    ],
                },
            ],
        })
        .await
    {
        Ok(Some(s)) => match s.promotion.as_ref().map(|p| p.state) {
            Some(PromotionState::Joining) => check_joined(state, &s).await,
            _ => check_sync(state, &s).await,
        },
        Ok(None) => {}
        Err(e) => warn!(session = %session_id, %e, "hive: a tip's promotion was not read"),
    }
}

/// Where the member's copy stands against the drained tip, for a promotion
/// that is syncing.
#[derive(Debug, PartialEq, Eq)]
enum Sync {
    /// Not there yet, or no tip reported.
    Behind,
    /// The same event: the lease may move.
    Reached,
    /// Past it, or another event at its `seq`: never promoted.
    Diverged,
}

fn sync_of(s: &AgentSession, p: &Promotion) -> Sync {
    let Some(d) = &p.drained else {
        return Sync::Behind;
    };
    let tip = s
        .replicaset
        .as_ref()
        .and_then(|r| r.members.iter().find(|m| m.device_id == p.to))
        .and_then(|m| m.tip.as_ref());
    match tip {
        Some(t) if t.seq == d.seq && t.hash == d.hash => Sync::Reached,
        Some(t) if t.seq >= d.seq => Sync::Diverged,
        _ => Sync::Behind,
    }
}

async fn check_sync(state: &HiveState, s: &AgentSession) {
    let (Some(sid), Some(p)) = (s.id, s.promotion.clone()) else {
        return;
    };
    if p.state != PromotionState::Syncing {
        return;
    }
    match sync_of(s, &p) {
        Sync::Behind => {}
        Sync::Diverged => fail(state, sid, &p, Failure::Diverged, true).await,
        Sync::Reached => move_lease(state, s, &p).await,
    }
}

/// The lease CAS, then everything that follows it, in this order: the old
/// primary's open approvals withdrawn, every view and stream of the session
/// ended, the old primary demoted, every member's join at the new fence,
/// and the member's own join, move and start.
async fn move_lease(state: &HiveState, s: &AgentSession, p: &Promotion) {
    let Some(sid) = s.id else { return };
    let (role, member_state) = match crate::placement::old_primary_role(state, s, p.to).await {
        Ok(r) => r,
        Err(e) => {
            warn!(session = %sid, %e, "hive: the old primary's place was not read — it leaves");
            (MemberRole::Owner, MemberState::Leaving)
        }
    };
    let deadline = deadline_after(state.promote_bounds.of_state(PromotionState::Moving));
    match state
        .sessions
        .move_lease(sid, p, role.as_str(), member_state, deadline)
        .await
    {
        Ok(true) => {}
        Ok(false) => return changed(state, sid, p).await,
        // The timer fails it at the sync's bound, should no next tip move it.
        Err(e) => return warn!(session = %sid, %e, "hive: the lease did not move"),
    }
    let s = match state.sessions.find(sid).await {
        Ok(Some(s)) => s,
        _ => return warn!(session = %sid, "hive: the moved session was not read back"),
    };
    let next = u64::try_from(s.fence).unwrap_or_default();
    info!(
        session = %sid, from = %p.from.device_id, to = %p.to, fence = next,
        old_primary = member_state.as_str(), "hive: the lease moved"
    );
    audit(Kind::of(p), &s, p.by, p.to, "moved", None)
        .write(state)
        .await;
    // What the old primary's run had open belongs to a run that is over.
    room::withdraw_approvals(state, &s).await;
    crate::view::end_grants_of_session(state, sid, "moved").await;
    crate::stream::end_for_session(state, sid, "moved");
    let demote = ServerMsg::HiveDemote {
        session_id: sid,
        fence: next,
        reason: "promoted".to_string(),
    };
    if let Err(e) = state
        .fleet
        .rc_hub
        .push_hive(p.from.device_id, s.tenant_id, demote)
    {
        // Told at its next report of the session, or its next manifest.
        debug!(session = %sid, %e, "hive: the old primary was not told it was demoted");
    }
    send_member_joins(state, &s);
    send_start(state, &s, &p.from, p.by).await;
}

/// The lease CAS missed: the session moved on. Stopped, or moved already by
/// a frame on another pod: nothing to say. Still on the primary at its
/// fence: the member no longer holds a joined copy.
async fn changed(state: &HiveState, session_id: ObjectId, p: &Promotion) {
    let Ok(Some(s)) = state.sessions.find(session_id).await else {
        return;
    };
    let still_there = SessionStatus::REPORTABLE.contains(&s.status)
        && s.location.device_id == p.from.device_id
        && s.fence == p.from_fence;
    if still_there {
        fail(state, session_id, p, Failure::MemberLeft, true).await;
    } else if let Err(e) = state
        .sessions
        .end_promotion(session_id, p.id, &PromotionState::BEFORE_THE_MOVE)
        .await
    {
        warn!(session = %session_id, %e, "hive: a promotion overtaken by a stop was not ended");
    }
}

/// Every member owed its join at the session's fence: each in its role, the
/// primary's own left to [`send_start`].
fn send_member_joins(state: &HiveState, s: &AgentSession) {
    let Some(r) = s.replicaset.as_ref() else {
        return;
    };
    for m in &r.members {
        if m.state != MemberState::Pending || m.role == MemberRole::Primary.as_str() {
            continue;
        }
        if let Some(role) = crate::replica::wire_role(&m.role) {
            crate::replica::push_join(state, s, m.device_id, role);
        }
    }
}

/// FR-90 P2f-5 — the places `s` ran before, as `rc:hive.move` names them:
/// its path map's, oldest first, one per folder (where it last ran in each),
/// the newest [`MAX_EARLIER_PLACES`].
pub(crate) fn earlier_places(s: &AgentSession) -> Vec<HivePlace> {
    let mut places: Vec<HivePlace> = Vec::new();
    for m in &s.path_map {
        places.retain(|p| p.folder != m.from.folder);
        places.push(HivePlace {
            device_name: m.from.device_name.clone(),
            folder: m.from.folder.clone(),
        });
    }
    let older = places.len().saturating_sub(MAX_EARLIER_PLACES);
    places.split_off(older)
}

/// What the device about to run `s` at its fence hears first: its join as
/// the primary, while it is owed one (its floor rises before it writes), and
/// the record's `rc:hive.move`. For a start at a fence past the first: a
/// promotion's, a move back's, or one of theirs re-sent on connect.
pub(crate) async fn before_start(
    state: &HiveState,
    s: &AgentSession,
    from: &SessionLocation,
    by: ObjectId,
) {
    let Some(sid) = s.id else { return };
    let device = s.location.device_id;
    let fence = u64::try_from(s.fence).unwrap_or_default();
    let owed = s.replicaset.as_ref().is_some_and(|r| {
        r.members.iter().any(|m| {
            m.device_id == device
                && m.role == MemberRole::Primary.as_str()
                && m.state == MemberState::Pending
        })
    });
    if owed {
        crate::replica::push_join(state, s, device, HiveReplicaRole::Primary);
    }
    // P2f-5 — when the lease moved, as the record keeps it: a start re-sent
    // at a later connection names the move, not the re-send.
    let at = s
        .moved
        .as_ref()
        .filter(|m| m.from.device_id == from.device_id)
        .map_or_else(DateTime::now, |m| m.at);
    let mv = ServerMsg::HiveMove {
        session_id: sid,
        fence,
        turns: s.last_turn.map(|t| t.turn).unwrap_or(0),
        from_device_id: from.device_id,
        from_device_name: from.device_name.clone(),
        from_folder: from.folder.clone(),
        moved_by: by,
        moved_by_name: display_name(state, by).await,
        moved_at_ms: u64::try_from(at.timestamp_millis()).unwrap_or_default(),
        earlier: earlier_places(s),
    };
    if let Err(e) = state
        .fleet
        .rc_hub
        .push_hive_promote(device, s.tenant_id, mv)
    {
        debug!(session = %sid, %e, "hive: the move did not reach the device");
    }
}

/// The start of `s` on the device it is located on now, at its fence, as a
/// resume: [`before_start`], the session's frozen core memory, then
/// `rc:hive.start`. Unanswered, it is re-sent on the device's every
/// connection, as every start is.
async fn send_start(state: &HiveState, s: &AgentSession, from: &SessionLocation, by: ObjectId) {
    let Some(sid) = s.id else { return };
    let device = s.location.device_id;
    let fence = u64::try_from(s.fence).unwrap_or_default();
    before_start(state, s, from, by).await;
    match state.brain.snapshot_of(sid).await {
        Ok(Some(m)) => {
            let frame = crate::routes::memory_frame(&m, fence);
            let _ = state
                .fleet
                .rc_hub
                .push_hive_memory(device, s.tenant_id, frame);
        }
        Ok(None) => {}
        Err(e) => debug!(session = %sid, %e, "hive: core memory not sent with the move"),
    }
    let owner = match state.users.base.find_by_id(s.owner_id).await {
        Ok(u) => u,
        Err(e) => {
            return warn!(session = %sid, %e, "hive: the moved start was not sent — its owner could not be read; it is re-sent on connect");
        }
    };
    let replicated = state.replicaset && crate::replica::replicated(s);
    let msg = ServerMsg::HiveStart {
        session_id: sid,
        harness: s.harness.id.clone(),
        harness_session: s.harness.session.clone(),
        fence,
        folder: s.location.folder.clone(),
        user_id: s.owner_id,
        user_email: owner.email,
        caller: owner.display_name,
        resume: true,
        replicated,
        lease: replicated
            && state
                .fleet
                .rc_hub
                .agent_supports_hive_lease(device, s.tenant_id)
                == Some(true),
        // P2f-3 — a fork's every start says what it was made from.
        fork_of: s.fork_of(),
        from_terminal: false,
    };
    match crate::routes::push_start(state, s, device, msg) {
        Ok(()) => info!(session = %sid, device = %device, fence, "hive: the moved start was sent"),
        Err(e) => {
            debug!(session = %sid, %e, "hive: the moved start was not sent — it is re-sent on connect")
        }
    }
}

/// The member answered the moved start `accepted`: the promotion is done,
/// and the room says where the session runs now. `true` when this answer
/// ended it (its note posted).
pub(crate) async fn on_launched(
    state: &HiveState,
    session_id: ObjectId,
    device_id: ObjectId,
    fence: u64,
) -> bool {
    let Ok(Some(s)) = state.sessions.find(session_id).await else {
        return false;
    };
    let Some(p) = awaited(&s, PromotionState::Moving, device_id)
        .filter(|p| u64::try_from(p.from_fence + 1).ok() == Some(fence))
    else {
        return false;
    };
    match state
        .sessions
        .end_promotion(session_id, p.id, &[PromotionState::Moving])
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return false,
        Err(e) => {
            warn!(session = %session_id, %e, "hive: a done promotion was not ended");
            return false;
        }
    }
    let s = match state.sessions.find(session_id).await {
        Ok(Some(after)) => after,
        _ => s,
    };
    info!(session = %session_id, device = %device_id, fence, "hive: promotion done — the session runs on its new primary");
    audit(Kind::of(&p), &s, p.by, p.to, "done", None)
        .write(state)
        .await;
    let by = display_name(state, p.by).await;
    room::note(state, &s, room::moved_note(&s, &p, &by)).await;
    true
}

/// The member refused the moved start: the lease moves back
/// ([`crate::dao::AgentSessionDao::move_lease_back`]) and the session starts
/// again where it ran. `true` when this answer was the promotion's, and
/// handled here: the session is NOT refused.
pub(crate) async fn on_start_refused(
    state: &HiveState,
    session_id: ObjectId,
    device_id: ObjectId,
    fence: u64,
    word: HiveRefusal,
    detail: Option<String>,
) -> bool {
    let Ok(Some(s)) = state.sessions.find(session_id).await else {
        return false;
    };
    let Some(p) = awaited(&s, PromotionState::Moving, device_id)
        .filter(|p| u64::try_from(p.from_fence + 1).ok() == Some(fence))
    else {
        return false;
    };
    match state.sessions.move_lease_back(session_id, &p).await {
        Ok(true) => {}
        Ok(false) => return false,
        Err(e) => {
            warn!(session = %session_id, %e, "hive: the lease did not move back");
            return false;
        }
    }
    let s = match state.sessions.find(session_id).await {
        Ok(Some(after)) => after,
        _ => return true,
    };
    info!(
        session = %session_id, refused = word.as_str(), back_to = %p.from.device_id,
        fence = s.fence, "hive: the member refused the moved start — the lease moved back"
    );
    audit(
        Kind::of(&p),
        &s,
        p.by,
        p.to,
        "moved_back",
        Some(word.as_str()),
    )
    .write(state)
    .await;
    // P2e-5c — and every view and stream of the session ends, as at the
    // move. The member never ran it: a stream it was asked to serve would
    // tell its member the session runs nowhere, and the member would park a
    // copy of a session that runs on.
    crate::view::end_grants_of_session(state, session_id, "moved").await;
    crate::stream::end_for_session(state, session_id, "moved");
    let detail = crate::agent_socket::clamp_words(detail, hive_limits::MAX_DETAIL_LEN);
    let why = Failure::PrepareRefused { word, detail }.why(&p);
    room::note(state, &s, room::move_failed_note(&p, &why)).await;
    send_member_joins(state, &s);
    // P2e-6b — from the device itself, back as it left it; or, for one that
    // never answered the start it was moved, from where that start came.
    let (from, by) = s
        .moved
        .clone()
        .map_or((s.location.clone(), p.by), |m| (m.from, m.by));
    send_start(state, &s, &from, by).await;
    true
}

/// P2e-2's word for a session a manifest names, during a promotion: none
/// while the primary is drained for the move (the lease is in motion); a
/// promotion past its deadline is failed here, with no word of its own —
/// the manifest's answer sends it.
pub(crate) async fn withholds_word(state: &HiveState, s: &AgentSession) -> bool {
    let (Some(sid), Some(p)) = (s.id, s.promotion.as_ref()) else {
        return false;
    };
    if !matches!(p.state, PromotionState::Draining | PromotionState::Syncing) {
        return false;
    }
    if p.in_flight(DateTime::now()) {
        return true;
    }
    fail(state, sid, p, Failure::Timeout(p.state), false).await;
    false
}

async fn display_name(state: &HiveState, user: ObjectId) -> String {
    state
        .users
        .find_display_names(&[user])
        .await
        .ok()
        .and_then(|m| m.get(&user).cloned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{HarnessRef, MemberTip, PathMove, ReplicaMember, Replicaset};

    /// FR-90 P2f-5 — the places a moved start names: the path map's, oldest
    /// first, one per folder (where it last ran in each), the newest
    /// [`MAX_EARLIER_PLACES`]; none for a session never moved since P2f-5.
    #[test]
    fn a_moved_start_names_each_earlier_folder_once_oldest_first() {
        let (mut s, _) = syncing(None, None);
        assert!(
            earlier_places(&s).is_empty(),
            "never moved: no earlier place"
        );
        let at = DateTime::now();
        let place = |name: &str, folder: &str| SessionLocation {
            device_id: ObjectId::new(),
            device_name: name.into(),
            folder: folder.into(),
            account: None,
        };
        let step = |fence, from, to| PathMove {
            fence,
            from,
            to,
            at,
        };
        s.path_map = vec![
            step(2, place("a", "/a"), place("b", "/b")),
            // On another device, in a folder it once ran in.
            step(3, place("b", "/b"), place("c", "/a")),
            step(4, place("c", "/a"), place("d", "/d")),
        ];
        let named: Vec<(String, String)> = earlier_places(&s)
            .into_iter()
            .map(|p| (p.device_name, p.folder))
            .collect();
        assert_eq!(
            named,
            [
                ("b".to_string(), "/b".to_string()),
                ("c".into(), "/a".into())
            ],
            "each folder once, where it last ran"
        );
        s.path_map = (0..40)
            .map(|i| step(i + 2, place("x", &format!("/f{i}")), place("y", "/y")))
            .collect();
        let kept = earlier_places(&s);
        assert_eq!(kept.len(), MAX_EARLIER_PLACES);
        assert_eq!(
            (
                kept[0].folder.as_str(),
                kept[MAX_EARLIER_PLACES - 1].folder.as_str()
            ),
            ("/f24", "/f39"),
            "the newest, oldest first"
        );
    }

    #[test]
    fn every_refusal_has_its_own_word() {
        let mut words: Vec<&str> = PromoteDenyReason::ALL.iter().map(|r| r.as_str()).collect();
        words.sort_unstable();
        words.dedup();
        assert_eq!(words.len(), PromoteDenyReason::ALL.len());
        for r in PromoteDenyReason::ALL {
            assert!(!r.message().is_empty(), "{r:?}");
        }
    }

    fn tip(seq: i64, fill: &str) -> MemberTip {
        MemberTip {
            fence: 1,
            seq,
            hash: fill.repeat(64 / fill.len()),
            checkpoint_seq: None,
            checkpoint_hash: None,
            at: DateTime::now(),
        }
    }

    fn syncing(
        member_tip: Option<MemberTip>,
        drained: Option<(i64, &str)>,
    ) -> (AgentSession, Promotion) {
        let now = DateTime::now();
        let (a, b) = (ObjectId::new(), ObjectId::new());
        let from = SessionLocation {
            device_id: a,
            device_name: "mars".into(),
            folder: "/src".into(),
            account: None,
        };
        let p = Promotion {
            id: ObjectId::new(),
            to: b,
            to_name: "venus".into(),
            to_role: "owner".into(),
            folder: "/src".into(),
            from: from.clone(),
            from_fence: 1,
            by: ObjectId::new(),
            state: PromotionState::Syncing,
            started_at: now,
            deadline: now,
            drained: drained.map(|(seq, fill)| DrainedTip {
                seq,
                hash: fill.repeat(64 / fill.len()),
            }),
            unreachable_from: false,
            prior: None,
            teleport: false,
            fork: None,
        };
        let member = |device_id, role: &str, tip| ReplicaMember {
            device_id,
            role: role.into(),
            state: MemberState::Joined,
            refusal: None,
            answered_at: None,
            tip,
            purging: None,
            forking: None,
        };
        let s = AgentSession {
            id: Some(ObjectId::new()),
            tenant_id: ObjectId::new(),
            owner_id: p.by,
            drivers: Vec::new(),
            title: "t".into(),
            room_id: None,
            last_turn: None,
            harness: HarnessRef {
                id: "claude-code".into(),
                session: "u".into(),
            },
            location: from,
            status: SessionStatus::Idle,
            fence: 1,
            accepted_at: Some(now),
            refusal: None,
            end_reason: None,
            detail: None,
            created_at: now,
            updated_at: now,
            ended_at: None,
            brain_rev: None,
            vault_role: None,
            origin: SessionOrigin::Started,
            replicaset: Some(Replicaset {
                policy_revision: 0,
                min: 2,
                max: 4,
                restricted_tags: Vec::new(),
                members: vec![
                    member(a, "primary", Some(tip(9, "ff"))),
                    member(b, "owner", member_tip),
                ],
                short: None,
                placed_at: now,
            }),
            promotion: Some(p.clone()),
            fences: Vec::new(),
            moved: None,
            parent: None,
            from_terminal: None,
            path_map: Vec::new(),
            purged: None,
        };
        (s, p)
    }

    /// The lease moves only on the member's OWN tip, and only at the drained
    /// event exactly: behind is waited for; past it, or another event at its
    /// seq, is a copy that is not the primary's. The primary's tip says
    /// nothing about the member's copy.
    #[test]
    fn the_lease_moves_only_once_the_members_own_tip_is_the_drained_one() {
        let (s, p) = syncing(Some(tip(9, "ab")), Some((9, "ab")));
        assert_eq!(
            sync_of(&s, &p),
            Sync::Reached,
            "the member's own tip at the drained one"
        );
        let (s, p) = syncing(Some(tip(8, "ab")), Some((9, "ab")));
        assert_eq!(sync_of(&s, &p), Sync::Behind, "behind it");
        let (s, p) = syncing(None, Some((9, "ff")));
        assert_eq!(
            sync_of(&s, &p),
            Sync::Behind,
            "no tip of its own: the primary's matching tip is not the member's"
        );
        let (s, p) = syncing(Some(tip(9, "cd")), Some((9, "ab")));
        assert_eq!(sync_of(&s, &p), Sync::Diverged, "another event at its seq");
        let (s, p) = syncing(Some(tip(10, "ab")), Some((9, "ab")));
        assert_eq!(sync_of(&s, &p), Sync::Diverged, "past the drained tip");
        let (s, p) = syncing(Some(tip(9, "ab")), None);
        assert_eq!(sync_of(&s, &p), Sync::Behind, "nothing drained yet");
    }

    /// P2e-5b — a promotion that could leave the session naming more fences'
    /// ends than a device takes in one join is refused before it begins: a
    /// move keeps one end, and the move back of a refused start a second.
    #[test]
    fn a_session_is_not_moved_past_the_ends_a_join_can_carry() {
        let max = replica_limits::MAX_FENCE_MARKS;
        let (mut s, _) = syncing(None, None);
        let mark = |fence: usize| crate::model::FenceMark {
            fence: fence as i64,
            seq: 1,
            hash: "ab".repeat(32),
        };
        assert!(!moved_too_often(&s), "never moved");
        s.fences = (1..=max - 2).map(mark).collect();
        assert!(!moved_too_often(&s), "room for a move and its move back");
        s.fences.push(mark(max - 1));
        assert!(
            moved_too_often(&s),
            "a move back would leave a join naming one end too many"
        );
    }

    /// An agent row as the fleet keeps it, last heard from `silent_ms` before
    /// `now`, its last hello advertising `rpc`.
    fn row(now: DateTime, silent_ms: i64, rpc: &[RpcCap]) -> Agent {
        let mut a: Agent = serde_json::from_str(
            r#"{
                "tenant_id":"000000000000000000000001",
                "owner_user_id":"000000000000000000000002",
                "name":"mars","machine_id":"m","os":"linux",
                "agent_version":"0.4.131","agent_token_hash":"",
                "status":"offline","last_seen_at":{"$date":{"$numberLong":"0"}},
                "created_at":{"$date":{"$numberLong":"0"}},
                "updated_at":{"$date":{"$numberLong":"0"}},
                "deleted_at":null
            }"#,
        )
        .unwrap();
        a.last_seen_at = DateTime::from_millis(now.timestamp_millis() - silent_ms);
        a.capabilities.rpc = rpc.iter().map(|c| c.wire().to_string()).collect();
        a
    }

    /// P2e-6a — a primary is moved away from with no drain only once the
    /// server has heard nothing from it for UNREACHABLE_SECS, by when its own
    /// clock stopped its model calls, and only if its build, back, runs the
    /// session to the server's word: one before P2e-2 would run it again on
    /// reconnect, before it hears it was demoted.
    #[test]
    fn a_primary_is_moved_away_from_only_once_it_is_unreachable() {
        let now = DateTime::now();
        let wait = i64::try_from(UNREACHABLE_SECS * 1000).unwrap();
        let leased = [RpcCap::Hive, RpcCap::HiveLease, RpcCap::HivePromote];
        assert_eq!(
            unreachable_reach(&row(now, wait - 1, &leased), now),
            Err(PromoteDenyReason::PrimaryOffline),
            "a millisecond short: its clock may still let it call the model"
        );
        assert_eq!(
            unreachable_reach(&row(now, wait, &leased), now),
            Ok(Reach::Unreachable)
        );
        assert_eq!(
            unreachable_reach(&row(now, wait, &[RpcCap::Hive, RpcCap::HiveReplica]), now),
            Err(PromoteDenyReason::PrimaryUnsupported),
            "no word to wait for: back, it would run the session at once"
        );
        assert!(
            PromoteDenyReason::PrimaryOffline
                .message()
                .contains(&format!("{UNREACHABLE_SECS} s")),
            "the refusal names the wait"
        );
    }

    /// P2e-6a — away from an unreachable primary, the lease moves only to
    /// the member that holds the most of the session's chain, as last heard;
    /// a tail past where an older fence ended counts for nothing, and an
    /// empty copy is the least, whatever fence it joined at.
    #[test]
    fn away_from_an_unreachable_primary_only_to_the_member_that_holds_the_most() {
        let (mut s, p) = syncing(Some(tip(9, "ab")), None);
        let c = ObjectId::new();
        let mut third = s.replicaset.as_ref().unwrap().members[1].clone();
        third.device_id = c;
        third.tip = Some(tip(8, "cd"));
        s.replicaset.as_mut().unwrap().members.push(third);
        let set_c = |s: &mut AgentSession, fence: i64, seq: i64| {
            let m = &mut s.replicaset.as_mut().unwrap().members[2];
            m.tip.as_mut().unwrap().fence = fence;
            m.tip.as_mut().unwrap().seq = seq;
        };
        assert_eq!(fresher_than(&s, p.to, 1, 9), None, "it holds the most");
        s.replicaset.as_mut().unwrap().members[0].tip = Some(tip(20, "ff"));
        assert_eq!(
            fresher_than(&s, p.to, 1, 9),
            None,
            "the primary's own copy is what is lost, never a reason to refuse"
        );
        set_c(&mut s, 1, 10);
        assert_eq!(fresher_than(&s, p.to, 1, 9), Some(c), "another holds more");
        s.replicaset.as_mut().unwrap().members[2].state = MemberState::Pending;
        assert_eq!(
            fresher_than(&s, p.to, 1, 9),
            None,
            "only a joined copy counts"
        );
        s.replicaset.as_mut().unwrap().members[2].state = MemberState::Joined;
        // An empty copy at a newer fence: seq 0, the least.
        set_c(&mut s, 2, 0);
        assert_eq!(
            fresher_than(&s, p.to, 1, 9),
            None,
            "an empty copy holds nothing"
        );
        // Fence 1 ended at 7: c's 1..=10 is cut off past 7, and b's 9 is too.
        s.fences.push(crate::model::FenceMark {
            fence: 1,
            seq: 7,
            hash: "ee".repeat(32),
        });
        set_c(&mut s, 1, 10);
        assert_eq!(on_chain(&s, 1, 10), 7, "fence 1 counts up to its end");
        assert_eq!(on_chain(&s, 2, 8), 8, "the current fence has no end");
        assert_eq!(
            fresher_than(&s, p.to, 1, 9),
            None,
            "both hold fence 1 up to its end"
        );
        set_c(&mut s, 2, 8);
        assert_eq!(
            fresher_than(&s, p.to, 1, 9),
            Some(c),
            "past the end, on the chain"
        );
        // Where the lease may move: never past an end, at it only on its event.
        assert!(within_ends(&s, 2, 30, "ab"), "the current fence");
        assert!(within_ends(&s, 1, 6, "ab"), "behind the end");
        assert!(
            within_ends(&s, 1, 7, &"ee".repeat(32)),
            "at the end, its event"
        );
        assert!(
            !within_ends(&s, 1, 7, &"ab".repeat(32)),
            "at the end, another event"
        );
        assert!(!within_ends(&s, 1, 8, &"ee".repeat(32)), "past it: cut off");
    }

    /// P2e-6b — a session waiting on a moved start its device never
    /// answered: past the first fence, starting, never accepted, and no run
    /// state reported. Where that start came from: the record's own word,
    /// else the move that sent it, on a record from before P2e-6b.
    #[test]
    fn a_moved_start_never_answered_is_known_and_so_is_where_it_came_from() {
        let (mut s, p) = syncing(None, None);
        assert!(!unanswered_move(&s), "running");
        s.fence = 2;
        s.status = SessionStatus::Starting;
        s.accepted_at = None;
        assert!(unanswered_move(&s), "a moved start, unanswered");
        s.fence = 1;
        assert!(!unanswered_move(&s), "a first start is no move");
        s.fence = 2;
        s.status = SessionStatus::Idle;
        assert!(!unanswered_move(&s), "a run state reported: it launched");
        s.status = SessionStatus::Starting;
        s.accepted_at = Some(DateTime::now());
        assert!(!unanswered_move(&s), "answered");
        s.accepted_at = None;

        s.location.device_id = p.to;
        let mut moving = p.clone();
        moving.state = PromotionState::Moving;
        s.promotion = Some(moving);
        assert_eq!(
            prior_of(&s).map(|m| m.from.device_id),
            Some(p.from.device_id),
            "a record from before P2e-6b: the move's"
        );
        let kept = MovedStart {
            from: SessionLocation {
                device_id: ObjectId::new(),
                ..p.from.clone()
            },
            by: p.by,
            at: DateTime::now(),
        };
        s.moved = Some(kept.clone());
        assert_eq!(prior_of(&s), Some(kept), "the record's own word first");
        s.moved = None;
        s.promotion = None;
        assert_eq!(prior_of(&s), None);
    }

    /// FR-90 P2f-1 — a teleport joining goes on to the drain only once its
    /// target joined, its primary joined and said where its copy ends since
    /// the teleport began, and the target's copy holds that much; a refused
    /// join or a target let go fails it, each in its own word.
    #[test]
    fn a_teleport_drains_only_once_its_target_holds_the_primarys_tip() {
        let (mut s, mut p) = syncing(None, None);
        p.teleport = true;
        p.state = PromotionState::Joining;
        p.started_at = DateTime::from_millis(DateTime::now().timestamp_millis() - 1000);
        fn at(s: &mut AgentSession, device: ObjectId) -> &mut ReplicaMember {
            s.replicaset
                .as_mut()
                .unwrap()
                .members
                .iter_mut()
                .find(|m| m.device_id == device)
                .unwrap()
        }
        at(&mut s, p.to).role = "teleport".into();
        // The primary joined and said where its copy ends since the teleport
        // began; the target holds as much, but has not answered its join.
        at(&mut s, p.from.device_id).tip = Some(tip(9, "ff"));
        at(&mut s, p.to).state = MemberState::Pending;
        at(&mut s, p.to).tip = Some(tip(9, "ab"));
        assert_eq!(
            joined_of(&s, &p),
            Joined::Waiting,
            "the target has not answered its join"
        );
        at(&mut s, p.to).state = MemberState::Joined;
        at(&mut s, p.from.device_id).state = MemberState::Pending;
        assert_eq!(
            joined_of(&s, &p),
            Joined::Waiting,
            "the primary has not answered its join"
        );
        at(&mut s, p.from.device_id).state = MemberState::Joined;
        // The primary's tip from before the teleport began.
        at(&mut s, p.from.device_id).tip = Some(MemberTip {
            at: DateTime::from_millis(p.started_at.timestamp_millis() - 1),
            ..tip(9, "ff")
        });
        assert_eq!(
            joined_of(&s, &p),
            Joined::Waiting,
            "the primary's tip predates the teleport"
        );
        at(&mut s, p.from.device_id).tip = Some(tip(14, "ff"));
        assert_eq!(
            joined_of(&s, &p),
            Joined::Waiting,
            "the target's copy is behind the primary's"
        );
        at(&mut s, p.to).tip = Some(tip(14, "ab"));
        assert_eq!(
            joined_of(&s, &p),
            Joined::CaughtUp,
            "the target holds what the primary said it holds"
        );

        at(&mut s, p.to).state = MemberState::Refused;
        at(&mut s, p.to).refusal = Some("not_prepared".into());
        assert_eq!(
            joined_of(&s, &p),
            Joined::Failed(Failure::JoinRefused {
                word: "not_prepared".into()
            }),
            "the target refused its join"
        );
        at(&mut s, p.to).state = MemberState::Leaving;
        assert_eq!(
            joined_of(&s, &p),
            Joined::Failed(Failure::MemberLeft),
            "the target was let go"
        );
        at(&mut s, p.to).state = MemberState::Joined;
        at(&mut s, p.from.device_id).state = MemberState::Refused;
        at(&mut s, p.from.device_id).refusal = Some("other".into());
        assert_eq!(
            joined_of(&s, &p),
            Joined::Failed(Failure::PrimaryJoinRefused {
                word: "other".into()
            }),
            "the primary refused its join"
        );
    }

    /// FR-90 P2f-1 — by default a teleport waits for its target's copy for
    /// less time than the target admits its join: a join re-sent after the
    /// admission ran out would be refused `not_prepared`.
    #[test]
    fn a_teleport_waits_less_than_its_target_admits_its_join() {
        use meshharbor_remote_control::hive::promote_limits::TELEPORT_ADMISSION_SECS;
        let defaults = meshharbor_config::HiveSettings::default();
        assert!(
            defaults.promote_join_secs < TELEPORT_ADMISSION_SECS,
            "{} s against {TELEPORT_ADMISSION_SECS} s",
            defaults.promote_join_secs
        );
    }

    /// The member's role, only as a joined member, never the primary's row.
    #[test]
    fn only_a_joined_member_can_be_promoted_to() {
        let (mut s, p) = syncing(None, None);
        assert_eq!(member_role(&s, p.to).as_deref(), Some("owner"));
        assert_eq!(member_role(&s, p.from.device_id), None, "the primary's row");
        assert_eq!(member_role(&s, ObjectId::new()), None, "a stranger");
        s.replicaset.as_mut().unwrap().members[1].state = MemberState::Pending;
        assert_eq!(member_role(&s, p.to), None, "pending: it holds no copy yet");
    }

    /// Each step waits on one device: the drain on the primary, every other
    /// on the member it moves to; and only in its own state.
    #[test]
    fn each_step_waits_on_its_own_device() {
        let (mut s, p) = syncing(None, None);
        assert!(
            awaited(&s, PromotionState::Syncing, p.to).is_some(),
            "the sync waits on the member"
        );
        assert!(
            awaited(&s, PromotionState::Syncing, p.from.device_id).is_none(),
            "not on the primary"
        );
        assert!(
            awaited(&s, PromotionState::Draining, p.to).is_none(),
            "another state"
        );
        s.promotion.as_mut().unwrap().state = PromotionState::Draining;
        assert!(
            awaited(&s, PromotionState::Draining, p.from.device_id).is_some(),
            "the drain waits on the primary"
        );
        assert!(
            awaited(&s, PromotionState::Draining, p.to).is_none(),
            "not on the member"
        );
    }

    /// Every failure has an audit word and a reason a person can read.
    #[test]
    fn every_failure_says_why_in_its_own_words() {
        let (_, p) = syncing(None, None);
        let all = [
            Failure::PrepareRefused {
                word: HiveRefusal::NoAccount,
                detail: Some("no *map*".into()),
            },
            Failure::Timeout(PromotionState::Preparing),
            Failure::Timeout(PromotionState::Draining),
            Failure::Timeout(PromotionState::Syncing),
            Failure::DrainRefused {
                word: HiveDrainRefusal::NotRunning,
                detail: None,
            },
            Failure::DrainRefused {
                word: HiveDrainRefusal::Other,
                detail: None,
            },
            Failure::DrainUnreadable,
            Failure::Diverged,
            Failure::PrimaryGone,
            Failure::MemberLeft,
            Failure::NoCopyTip,
            Failure::NotFreshest,
            Failure::PrimaryBack,
            Failure::CutOff,
            Failure::Timeout(PromotionState::Joining),
            Failure::JoinRefused {
                word: "not_prepared".into(),
            },
            Failure::PrimaryJoinRefused {
                word: "other".into(),
            },
            Failure::Changed,
        ];
        let mut words: Vec<&str> = all.iter().map(Failure::reason).collect();
        words.sort_unstable();
        words.dedup();
        assert_eq!(words.len(), all.len(), "{words:?}");
        let refused = all[0].why(&p);
        assert!(
            refused.starts_with("**venus** cannot run it: "),
            "{refused}"
        );
        assert!(refused.contains(r"(no \*map\*)"), "escaped: {refused}");
        assert_eq!(
            all[2].why(&p),
            "**mars** did not finish its turn and hand the session over in time"
        );
    }
}
