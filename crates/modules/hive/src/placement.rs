// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2c-2b — placement: which devices hold a session's copies (spec §3b,
//! "Membership and placement").
//!
//! [`place`] is a pure function over facts the server already holds, so every
//! rule below is a unit test; [`place_new`] reads those facts once, for a
//! session that is starting. A placement is a plan: the joins (P2c-3) say
//! which members took their copy, and the device's own `hive_replica` decides
//! that, whatever this chose.
//!
//! | Rule | Why |
//! |---|---|
//! | a candidate advertises `hive-replica` | its owner's `hive_replica` is on: the gate that survives a compromised server. A device advertises it only on its primary org's connection (P2c-3) |
//! | never an ephemeral device | FR-51 hard-deletes it once it goes quiet: it could keep nothing for the retention, and never acknowledge a purge |
//! | the owner's own devices are those whose `owner_user_id` AND `enrolled_by` both name the session's owner | `owner_user_id` is reassignable with `MANAGE_AGENTS` alone: a device manager who hands someone a device must not receive that person's sessions on it |
//! | an archive replica is designated by an `ADMINISTRATOR`, offers itself (`hive-archive`), and joins only while `archive` is on | the administrator's half and the device owner's half, either first |
//! | a restricted tag only ever takes a device out, and is compared without case | a guard that assumes a casing is no guard: a primary tagged `Prod` is restricted by `prod` |
//! | the primary, then archive replicas in the policy's order, then the owner's devices last seen first until `min`; never more than `max` | decision 2 |
//! | an adopted session is placed nowhere but where it was adopted | decision 11: only its owner sees it, and whoever runs an archive replica could read that disk |
//! | P2c-4: deciding again keeps a member that still qualifies before it takes another, and a smaller `min` keeps the first | a copy that need not move does not: tagging an unrelated device must not move anyone's session |

use bson::{DateTime, oid::ObjectId};
use meshharbor_remote_control::hive::HiveReplicaRole;
use meshharbor_remote_control::models::{Agent, RpcCap};
use meshharbor_services::dao::base::DaoResult;

use crate::HiveState;
use crate::model::{MemberState, ReplicaMember, Replicaset, SessionOrigin};
use crate::policy::{HivePolicy, ReplicasetRules};

/// The one word `prefer` may name today: the session owner's own devices.
const OWNER_DEVICES: &str = "owner_devices";

/// What placement knows about one device.
#[derive(Debug, Clone)]
pub struct DeviceFacts {
    pub id: ObjectId,
    pub owner_user_id: ObjectId,
    pub enrolled_by: Option<ObjectId>,
    pub tags: Vec<String>,
    pub ephemeral: bool,
    /// It advertises `hive-replica`: its owner lets it hold copies.
    pub replica: bool,
    /// It advertises `hive-archive`: its owner offers it as an archive.
    pub archive: bool,
    pub last_seen_at: DateTime,
}

impl DeviceFacts {
    /// From the stored row: its last hello's capabilities, so a device that
    /// is offline now is still placed, and joins when it connects.
    pub fn of(a: &Agent) -> Option<Self> {
        Some(Self {
            id: a.id?,
            owner_user_id: a.owner_user_id,
            enrolled_by: a.enrolled_by,
            tags: a.tags.clone(),
            ephemeral: a.ephemeral,
            replica: a.capabilities.has_rpc(RpcCap::HiveReplica),
            archive: a.capabilities.has_rpc(RpcCap::HiveArchive),
            last_seen_at: a.last_seen_at,
        })
    }
}

/// What placement knows about the session.
#[derive(Debug, Clone)]
pub struct SessionFacts<'a> {
    pub owner: ObjectId,
    pub primary: ObjectId,
    /// The primary device's tags.
    pub primary_tags: &'a [String],
    pub origin: SessionOrigin,
    /// The restricted tags it already carries, which a placement only adds to.
    pub restricted: &'a [String],
    /// P2c-4 — the devices it holds copies on now, in the order they were
    /// placed, the active before the leaving: a placement keeps one that still
    /// qualifies before it takes another, so deciding again moves no copy that
    /// need not move. Empty at a start.
    pub current: &'a [ObjectId],
}

/// Why a member holds a copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberRole {
    /// It runs the session.
    Primary,
    /// An archive replica the policy designates.
    Archive,
    /// One of the session owner's own devices.
    Owner,
    /// FR-90 P2f-1 — a teleport's target: no placement chooses it. It takes
    /// the copy it will run, and becomes the primary at the move; a teleport
    /// that fails before the move lets it go (`leaving`).
    Teleport,
}

impl MemberRole {
    /// The spelling in the database and the API. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Archive => "archive",
            Self::Owner => "owner",
            Self::Teleport => "teleport",
        }
    }
}

/// Why a session holds fewer copies than its `min`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Short {
    /// An adopted session is placed nowhere but where it was adopted.
    Adopted,
    /// A device that would hold a copy lacks a tag the session is restricted
    /// by.
    Restricted,
    /// No other device offers to hold one.
    NoDevice,
}

impl Short {
    /// The spelling in the database, the API and the audit. Locked by test.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Adopted => "adopted",
            Self::Restricted => "restricted",
            Self::NoDevice => "no_device",
        }
    }
}

/// What [`place`] chose.
#[derive(Debug, Clone, PartialEq)]
pub struct Placement {
    /// The primary first, then the rest in the order they were chosen.
    pub members: Vec<(ObjectId, MemberRole)>,
    pub restricted_tags: Vec<String>,
    pub short: Option<Short>,
}

fn same_tag(a: &str, b: &str) -> bool {
    a.trim().to_lowercase() == b.trim().to_lowercase()
}

/// Whether `tags` holds `tag`, compared without case: what a restricted tag
/// asks of every device that holds a copy, and (P2f-3) of a fork's device.
pub(crate) fn carries(tags: &[String], tag: &str) -> bool {
    tags.iter().any(|t| same_tag(t, tag))
}

/// The restricted tags a session carries: what it carries already, then
/// every policy tag its primary carries, each once.
fn restricted_of(rules: &ReplicasetRules, session: &SessionFacts<'_>) -> Vec<String> {
    let mut restricted: Vec<String> = Vec::new();
    let from_policy = rules
        .restricted_tags
        .iter()
        .filter(|t| carries(session.primary_tags, t));
    for t in session.restricted.iter().chain(from_policy) {
        if !carries(&restricted, t) {
            restricted.push(t.clone());
        }
    }
    restricted
}

/// FR-90 P2e-3 — the role `d` may hold a copy of the session in, by the same
/// rules as [`place`] but for one device and without `min` or `max`: an
/// archive replica the policy designates and that offers itself, while
/// `archive` is on; else one of the owner's own devices; else none. It must
/// offer to hold copies, be no ephemeral device and not the primary, and
/// carry every restricted tag. What a promotion asks of the primary it
/// moves from: one that may hold a copy stays a member, so moving back is a
/// promotion; one that may not leaves, and its copy goes with the purge.
pub fn eligible_role(
    rules: &ReplicasetRules,
    archive_devices: &[ObjectId],
    session: &SessionFacts<'_>,
    d: &DeviceFacts,
) -> Option<MemberRole> {
    if d.id == session.primary || !d.replica || d.ephemeral {
        return None;
    }
    let restricted = restricted_of(rules, session);
    if !restricted.iter().all(|t| carries(&d.tags, t)) {
        return None;
    }
    if rules.archive && d.archive && archive_devices.contains(&d.id) {
        return Some(MemberRole::Archive);
    }
    let owners = rules.prefer.iter().any(|p| p == OWNER_DEVICES)
        && d.owner_user_id == session.owner
        && d.enrolled_by == Some(session.owner);
    owners.then_some(MemberRole::Owner)
}

/// FR-90 P2e-3 — what the primary a session moves from becomes once its
/// lease is at `new_primary`: a member in the role [`eligible_role`] gives
/// it, owed its join at the new fence, or `leaving` (listed as `owner`, the
/// role it would hold) when it may hold no copy — its stored row, its owner
/// or its tags say so, or it was removed.
pub(crate) async fn old_primary_role(
    state: &HiveState,
    s: &crate::model::AgentSession,
    new_primary: ObjectId,
) -> DaoResult<(MemberRole, MemberState)> {
    let leaving = (MemberRole::Owner, MemberState::Leaving);
    let policy = state
        .policies
        .get(s.tenant_id)
        .await?
        .unwrap_or_else(|| HivePolicy::defaults(s.tenant_id));
    let fleet = &state.fleet.agents;
    let old = match fleet
        .find_live_in_tenant(s.tenant_id, s.location.device_id)
        .await
    {
        Ok(a) => a,
        Err(meshharbor_services::dao::base::DaoError::NotFound) => return Ok(leaving),
        Err(e) => return Err(e),
    };
    let new = fleet.find_live_in_tenant(s.tenant_id, new_primary).await?;
    let Some(facts) = DeviceFacts::of(&old) else {
        return Ok(leaving);
    };
    let restricted = s
        .replicaset
        .as_ref()
        .map(|r| r.restricted_tags.clone())
        .unwrap_or_default();
    let session = SessionFacts {
        owner: s.owner_id,
        primary: new_primary,
        primary_tags: &new.tags,
        origin: s.origin,
        restricted: &restricted,
        current: &[],
    };
    Ok(
        match eligible_role(
            &policy.replicaset,
            &policy.archive_devices,
            &session,
            &facts,
        ) {
            Some(role) => (role, MemberState::Pending),
            None => leaving,
        },
    )
}

/// The members of a session's replicaset, by the rules (module docs).
pub fn place(
    rules: &ReplicasetRules,
    archive_devices: &[ObjectId],
    session: &SessionFacts<'_>,
    devices: &[DeviceFacts],
) -> Placement {
    // What it already carries, then every policy tag its primary carries.
    let restricted = restricted_of(rules, session);
    let min = rules.min as usize;
    let max = rules.max as usize;
    let mut members = vec![(session.primary, MemberRole::Primary)];
    if session.origin == SessionOrigin::Adopted {
        let short = (members.len() < min).then_some(Short::Adopted);
        return Placement {
            members,
            restricted_tags: restricted,
            short,
        };
    }

    let offers = |d: &DeviceFacts| d.id != session.primary && d.replica && !d.ephemeral;
    let allowed = |d: &DeviceFacts| restricted.iter().all(|t| carries(&d.tags, t));
    let placed = |members: &[(ObjectId, MemberRole)], d: &DeviceFacts| {
        members.iter().any(|(m, _)| *m == d.id)
    };
    // A device that would hold a copy but for a restricted tag.
    let mut held_back = false;

    if rules.archive {
        // Those it holds already first, so a full replicaset keeps them.
        let held = |id: &&ObjectId| session.current.contains(id);
        let order = archive_devices
            .iter()
            .filter(held)
            .chain(archive_devices.iter().filter(|id| !held(id)));
        for id in order {
            if members.len() >= max {
                break;
            }
            let Some(d) = devices.iter().find(|d| d.id == *id) else {
                continue;
            };
            if !offers(d) || !d.archive || placed(&members, d) {
                continue;
            }
            if !allowed(d) {
                held_back = true;
                continue;
            }
            members.push((d.id, MemberRole::Archive));
        }
    }

    if rules.prefer.iter().any(|p| p == OWNER_DEVICES) {
        let mut owners: Vec<&DeviceFacts> = devices
            .iter()
            .filter(|d| {
                offers(d)
                    && d.owner_user_id == session.owner
                    && d.enrolled_by == Some(session.owner)
                    && !placed(&members, d)
            })
            .collect();
        // Those it holds already first, in their order; then the rest, last
        // seen first.
        let rank = |d: &DeviceFacts| session.current.iter().position(|c| *c == d.id);
        owners.sort_by(|a, b| match (rank(a), rank(b)) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => b
                .last_seen_at
                .cmp(&a.last_seen_at)
                .then_with(|| a.id.cmp(&b.id)),
        });
        owners.dedup_by_key(|d| d.id);
        for d in owners {
            if members.len() >= min.min(max) {
                break;
            }
            if !allowed(d) {
                held_back = true;
                continue;
            }
            members.push((d.id, MemberRole::Owner));
        }
    }

    let short = (members.len() < min).then_some(if held_back {
        Short::Restricted
    } else {
        Short::NoDevice
    });
    Placement {
        members,
        restricted_tags: restricted,
        short,
    }
}

/// The replicaset of a session `owner` is starting on `primary`, under the
/// organization's policy (or decision 2's defaults), from the devices'
/// stored rows; and why it is short of `min`, when it is. FR-90 P2f-3 —
/// `restricted` is what the session carries already: none for a new
/// session, its parent's for a fork, since a fork of a restricted session
/// is restricted.
pub async fn place_new(
    state: &HiveState,
    tid: ObjectId,
    owner: ObjectId,
    primary_id: ObjectId,
    primary: &Agent,
    restricted: &[String],
) -> DaoResult<(Replicaset, Option<Short>)> {
    let policy = state
        .policies
        .get(tid)
        .await?
        .unwrap_or_else(|| HivePolicy::defaults(tid));
    let rows = state
        .fleet
        .agents
        .list_replica_candidates(tid, owner, &policy.archive_devices)
        .await?;
    let devices: Vec<DeviceFacts> = rows.iter().filter_map(DeviceFacts::of).collect();
    let p = place(
        &policy.replicaset,
        &policy.archive_devices,
        &SessionFacts {
            owner,
            primary: primary_id,
            primary_tags: &primary.tags,
            origin: SessionOrigin::Started,
            restricted,
            current: &[],
        },
        &devices,
    );
    let replicaset = Replicaset {
        policy_revision: policy.revision,
        min: policy.replicaset.min,
        max: policy.replicaset.max,
        restricted_tags: p.restricted_tags,
        members: p
            .members
            .into_iter()
            .map(|(device_id, role)| ReplicaMember {
                device_id,
                role: role.as_str().to_string(),
                // P2c-3 — the primary holds the session by running it; every
                // other member's join is still to send.
                state: if role == MemberRole::Primary {
                    MemberState::Joined
                } else {
                    MemberState::Pending
                },
                refusal: None,
                answered_at: None,
                tip: None,
                purging: None,
                forking: None,
            })
            .collect(),
        short: p.short.map(|s| s.as_str().to_string()),
        placed_at: DateTime::now(),
    };
    Ok((replicaset, p.short))
}

/// FR-90 P2c-4 — decide again where `tid`'s live placed sessions are copied,
/// after something placement reads changed: the policy, a device's tags or
/// owner, or a member removed (`gone`, which no longer counts, though its row
/// is still there while the removal runs). Returns how many sessions'
/// members changed.
///
/// A member placement now chooses is added `pending`, or a leaving one made
/// `pending` again, and sent its join once the primary runs the session; one
/// it no longer chooses is `leaving`, and its copy goes with the purge (P2g).
/// Restricted tags only grow; a member that still qualifies is kept
/// ([`place`]'s `current`).
pub async fn replace_tenant(
    state: &HiveState,
    tid: ObjectId,
    gone: Option<ObjectId>,
) -> DaoResult<usize> {
    let policy = state
        .policies
        .get(tid)
        .await?
        .unwrap_or_else(|| HivePolicy::defaults(tid));
    let mut changed = 0;
    for s in state.sessions.live_placed(tid).await? {
        if replace_one(state, &policy, &s, gone).await? {
            changed += 1;
        }
    }
    Ok(changed)
}

/// One session of [`replace_tenant`]. `true` = its members changed.
async fn replace_one(
    state: &HiveState,
    policy: &HivePolicy,
    s: &crate::model::AgentSession,
    gone: Option<ObjectId>,
) -> DaoResult<bool> {
    let (Some(sid), Some(current)) = (s.id, s.replicaset.as_ref()) else {
        return Ok(false);
    };
    // The primary's tags as they stand now. A removed primary's sessions end
    // in its own cascade (`hooks`), so there is nothing to place.
    let primary = match state
        .fleet
        .agents
        .find_live_in_tenant(s.tenant_id, s.location.device_id)
        .await
    {
        Ok(a) => a,
        Err(meshharbor_services::dao::base::DaoError::NotFound) => return Ok(false),
        Err(e) => return Err(e),
    };
    let rows = state
        .fleet
        .agents
        .list_replica_candidates(s.tenant_id, s.owner_id, &policy.archive_devices)
        .await?;
    // P2g-4b — a member whose purge is under way is on its way out: placement
    // neither counts it nor chooses its device again (removal is final there).
    let purging: Vec<ObjectId> = current
        .members
        .iter()
        .filter(|m| m.purging.is_some())
        .map(|m| m.device_id)
        .collect();
    let devices: Vec<DeviceFacts> = rows
        .iter()
        .filter_map(DeviceFacts::of)
        .filter(|d| Some(d.id) != gone && !purging.contains(&d.id))
        .collect();
    // P2f-1 — the target of a teleport in flight is the teleport's: placement
    // neither counts it nor lets it go. One left from a teleport that is over
    // is any member: not chosen, it leaves.
    let teleporting = s
        .promotion
        .as_ref()
        .filter(|p| p.teleport && p.in_flight(bson::DateTime::now()))
        .map(|p| p.to);
    let others = || {
        current.members.iter().filter(move |m| {
            m.role != MemberRole::Primary.as_str() && Some(m.device_id) != teleporting
        })
    };
    // Active members first, then the leaving: one leaving still holds its
    // copy, so taking it back moves less than taking a stranger.
    let held: Vec<ObjectId> = others()
        .filter(|m| m.state != MemberState::Leaving)
        .chain(others().filter(|m| m.state == MemberState::Leaving))
        .map(|m| m.device_id)
        .collect();
    let p = place(
        &policy.replicaset,
        &policy.archive_devices,
        &SessionFacts {
            owner: s.owner_id,
            primary: s.location.device_id,
            primary_tags: &primary.tags,
            origin: s.origin,
            restricted: &current.restricted_tags,
            current: &held,
        },
        &devices,
    );
    let chosen: Vec<(ObjectId, MemberRole)> = p
        .members
        .iter()
        .filter(|(_, r)| *r != MemberRole::Primary)
        .copied()
        .collect();
    let fence = u64::try_from(s.fence).unwrap_or_default();
    // Joins go once the primary runs it; before that, its acceptance sends
    // them (`replica::send_joins`).
    let runs = s.accepted_at.is_some() || crate::model::SessionStatus::LAUNCHED.contains(&s.status);
    // Whether the primary checkpoints already: its start said `replicated`,
    // or it was owed its join when the first member came.
    let told = crate::replica::replicated(s);
    let mut moved = false;
    for (device, role) in &chosen {
        let added = match others().find(|m| m.device_id == *device) {
            None => {
                let m = ReplicaMember {
                    device_id: *device,
                    role: role.as_str().to_string(),
                    state: MemberState::Pending,
                    refusal: None,
                    answered_at: None,
                    tip: None,
                    purging: None,
                    forking: None,
                };
                state.sessions.add_member(sid, &m).await?
            }
            Some(m) if m.state == MemberState::Leaving => {
                state.sessions.rejoin(sid, *device, role.as_str()).await?
            }
            Some(_) => false,
        };
        if added {
            moved = true;
            if runs && let Some(r) = crate::replica::wire_role(role.as_str()) {
                crate::replica::push_join(state, s, *device, r);
            }
        }
    }
    // The first member of a session that started alone: its primary takes
    // no checkpoint until it is told, so a member would hold a copy of
    // nothing. Owed its join, sent once the primary runs the session, and
    // again at its every connection until it answers `joined`. (`moved` counts
    // only additions here: the leaving come below.)
    if moved && !told && state.sessions.owe_primary_join(sid).await? && runs {
        crate::replica::push_join(state, s, s.location.device_id, HiveReplicaRole::Primary);
    }
    // P2e-2 — and leased from its first member on: its device holds it to the
    // server's word from its next connection, not from the one after that.
    if moved && !told && runs {
        crate::lease::push(state, s.tenant_id, s.location.device_id, sid, fence);
    }
    for m in others().filter(|m| m.state != MemberState::Leaving) {
        if !chosen.iter().any(|(d, _)| *d == m.device_id)
            && state.sessions.mark_leaving(sid, m.device_id).await?
        {
            moved = true;
            // P2d — and its streams of the session end now, not at their
            // grant's end: a member let go for a tag taken off must stop
            // following at once. What it holds goes with the purge (P2g).
            crate::stream::end_for_member(state, sid, m.device_id, "member_left");
        }
    }
    let short = p.short.map(Short::as_str);
    state
        .sessions
        .set_placement(
            sid,
            &policy.replicaset,
            policy.revision,
            &p.restricted_tags,
            short,
        )
        .await?;
    if moved {
        // The system decided this, not a person: the row names the session's
        // owner, whose copies these are.
        crate::routes::Audit {
            tenant_id: s.tenant_id,
            user_id: s.owner_id,
            target_id: None,
            device_id: s.location.device_id,
            session_id: Some(sid),
            action: "place",
            outcome: "replaced",
            reason: short,
        }
        .write(state)
        .await;
    }
    // P2g-4b — each member that leaves, purged once min holds without it,
    // as the session stands after this placement. Best effort: a failed read
    // leaves it for the next tip, and never fails the placement.
    match state.sessions.with_leaving(sid).await {
        Ok(Some(now)) => {
            crate::purge::settle_leaving(state, &now, gone).await;
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(session = %sid, %e, "hive: the members that leave were not read — the next tip settles them")
        }
    }
    Ok(moved)
}

/// FR-90 P2c-4 — place what `device` runs that was never placed, now that it
/// connected with the switch on: a session started before P2, or while
/// `hive.replicaset` was off. Placed as at a start, except that it runs
/// already without `replicated`, so its primary is owed its join once
/// placement chose a member besides it. Returns how many were placed.
pub async fn place_unplaced(
    state: &HiveState,
    tid: ObjectId,
    device: ObjectId,
) -> DaoResult<usize> {
    let sessions = state.sessions.unplaced_on(tid, device).await?;
    if sessions.is_empty() {
        return Ok(0);
    }
    let primary = match state.fleet.agents.find_live_in_tenant(tid, device).await {
        Ok(a) => a,
        Err(meshharbor_services::dao::base::DaoError::NotFound) => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut placed = 0;
    for s in sessions {
        let Some(sid) = s.id else { continue };
        // P2f-3 — a session placed late is never a fork: a fork is placed
        // as its record is made, with its parent's restricted tags, or it
        // is not made.
        let (mut replicaset, short) =
            place_new(state, tid, s.owner_id, device, &primary, &[]).await?;
        let has_members = replicaset
            .members
            .iter()
            .any(|m| m.role != MemberRole::Primary.as_str());
        if has_members {
            for m in &mut replicaset.members {
                if m.role == MemberRole::Primary.as_str() {
                    m.state = MemberState::Pending;
                }
            }
        }
        // Another connection of the same device may have placed it first.
        if !state.sessions.place_unplaced(sid, &replicaset).await? {
            continue;
        }
        placed += 1;
        crate::routes::Audit {
            tenant_id: tid,
            user_id: s.owner_id,
            target_id: None,
            device_id: device,
            session_id: Some(sid),
            action: "place",
            outcome: if short.is_some() { "short" } else { "placed" },
            reason: short.map(Short::as_str),
        }
        .write(state)
        .await;
        // Its joins, the primary's among them, go once it runs; a start not
        // answered yet sends them with its acceptance.
        let runs =
            s.accepted_at.is_some() || crate::model::SessionStatus::LAUNCHED.contains(&s.status);
        if runs {
            crate::replica::send_joins(state, sid).await;
        }
    }
    Ok(placed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decision 2's defaults, with `min` and `max` as given.
    fn rules(min: u32, max: u32) -> ReplicasetRules {
        ReplicasetRules {
            min,
            max,
            ..HivePolicy::defaults(ObjectId::new()).replicaset
        }
    }

    struct Fleet {
        owner: ObjectId,
        primary: ObjectId,
        devices: Vec<DeviceFacts>,
    }

    impl Fleet {
        fn new() -> Self {
            Self {
                owner: ObjectId::new(),
                primary: ObjectId::new(),
                devices: Vec::new(),
            }
        }

        /// One of the owner's devices that offers to hold copies, last seen
        /// `ago` seconds back.
        fn owners(&mut self, ago: i64) -> ObjectId {
            let id = ObjectId::new();
            self.devices.push(DeviceFacts {
                id,
                owner_user_id: self.owner,
                enrolled_by: Some(self.owner),
                tags: Vec::new(),
                ephemeral: false,
                replica: true,
                archive: false,
                last_seen_at: DateTime::from_millis(1_000_000_000_000 - ago * 1000),
            });
            id
        }

        fn device(&mut self, id: ObjectId) -> &mut DeviceFacts {
            self.devices.iter_mut().find(|d| d.id == id).unwrap()
        }

        fn session(&self) -> SessionFacts<'static> {
            SessionFacts {
                owner: self.owner,
                primary: self.primary,
                primary_tags: &[],
                origin: SessionOrigin::Started,
                restricted: &[],
                current: &[],
            }
        }
    }

    fn ids(p: &Placement) -> Vec<(ObjectId, &'static str)> {
        p.members.iter().map(|(i, r)| (*i, r.as_str())).collect()
    }

    #[test]
    fn the_words_are_locked() {
        assert_eq!(
            [
                MemberRole::Primary,
                MemberRole::Archive,
                MemberRole::Owner,
                MemberRole::Teleport
            ]
            .map(MemberRole::as_str),
            ["primary", "archive", "owner", "teleport"]
        );
        assert_eq!(
            [Short::Adopted, Short::Restricted, Short::NoDevice].map(Short::as_str),
            ["adopted", "restricted", "no_device"]
        );
    }

    /// With no other device, the session is on its primary alone, and short.
    #[test]
    fn alone_it_is_short_of_min() {
        let f = Fleet::new();
        let p = place(&rules(2, 4), &[], &f.session(), &f.devices);
        assert_eq!(ids(&p), [(f.primary, "primary")]);
        assert_eq!(p.short, Some(Short::NoDevice));
        assert!(p.restricted_tags.is_empty());
        let p = place(&rules(1, 4), &[], &f.session(), &f.devices);
        assert_eq!(p.short, None, "one copy is all min 1 asks");
    }

    /// The owner's devices fill to `min`, last seen first, and never past it.
    #[test]
    fn the_owners_devices_fill_to_min_last_seen_first() {
        let mut f = Fleet::new();
        let old = f.owners(3600);
        let new = f.owners(10);
        let mid = f.owners(600);
        let p = place(&rules(3, 4), &[], &f.session(), &f.devices);
        assert_eq!(
            ids(&p),
            [(f.primary, "primary"), (new, "owner"), (mid, "owner")]
        );
        assert_eq!(p.short, None);
        assert!(!p.members.iter().any(|(i, _)| *i == old), "min is met");
    }

    /// A device the owner holds but did not enroll, one enrolled by them but
    /// handed to someone else, and someone else's: none is the owner's own.
    #[test]
    fn the_owners_own_means_owner_and_enroller_both() {
        let mut f = Fleet::new();
        let handed_to_owner = f.owners(1);
        f.device(handed_to_owner).enrolled_by = Some(ObjectId::new());
        let handed_away = f.owners(2);
        f.device(handed_away).owner_user_id = ObjectId::new();
        let unknown_enroller = f.owners(3);
        f.device(unknown_enroller).enrolled_by = None;
        let p = place(&rules(2, 4), &[], &f.session(), &f.devices);
        assert_eq!(ids(&p), [(f.primary, "primary")]);
        assert_eq!(p.short, Some(Short::NoDevice));
    }

    /// A device whose owner did not turn `hive_replica` on, an ephemeral
    /// one, and the primary itself are never members.
    #[test]
    fn only_a_permanent_device_that_offers_is_a_member() {
        let mut f = Fleet::new();
        let silent = f.owners(1);
        f.device(silent).replica = false;
        let ephemeral = f.owners(2);
        f.device(ephemeral).ephemeral = true;
        f.devices.push(DeviceFacts {
            id: f.primary,
            ..f.devices[0].clone()
        });
        f.device(f.primary).replica = true;
        let p = place(&rules(2, 4), &[], &f.session(), &f.devices);
        assert_eq!(ids(&p), [(f.primary, "primary")], "{p:?}");
    }

    /// Archive replicas come before the owner's devices, in the policy's
    /// order, only while `archive` is on and only those that offer
    /// themselves; one of them that is also the owner's is placed once.
    #[test]
    fn designated_archives_that_offer_come_first() {
        let mut f = Fleet::new();
        let laptop = f.owners(1);
        let nas = f.owners(5000);
        f.device(nas).archive = true;
        let other = ObjectId::new();
        f.devices.push(DeviceFacts {
            id: other,
            owner_user_id: ObjectId::new(),
            enrolled_by: Some(ObjectId::new()),
            tags: Vec::new(),
            ephemeral: false,
            replica: true,
            archive: true,
            last_seen_at: DateTime::from_millis(0),
        });
        let declined = f.owners(9);
        f.device(declined).enrolled_by = Some(ObjectId::new());
        let archives = [other, declined, nas];
        let p = place(&rules(4, 4), &archives, &f.session(), &f.devices);
        assert_eq!(
            ids(&p),
            [
                (f.primary, "primary"),
                (other, "archive"),
                (nas, "archive"),
                (laptop, "owner"),
            ],
            "`declined` is designated but does not offer itself"
        );
        let p = place(&rules(3, 4), &archives, &f.session(), &f.devices);
        assert_eq!(
            ids(&p),
            [(f.primary, "primary"), (other, "archive"), (nas, "archive")],
            "every archive the rules allow; the owner's devices only until min"
        );
        let mut off = rules(3, 4);
        off.archive = false;
        let p = place(&off, &archives, &f.session(), &f.devices);
        assert_eq!(
            ids(&p),
            [(f.primary, "primary"), (laptop, "owner"), (nas, "owner")],
            "archive off: only the owner's own, the NAS among them"
        );
        let p = place(&rules(2, 2), &archives, &f.session(), &f.devices);
        assert_eq!(
            ids(&p),
            [(f.primary, "primary"), (other, "archive")],
            "never more than max"
        );
    }

    /// With nothing to prefer, only archives join.
    #[test]
    fn an_empty_prefer_takes_none_of_the_owners_devices() {
        let mut f = Fleet::new();
        f.owners(1);
        let mut r = rules(2, 4);
        r.prefer.clear();
        let p = place(&r, &[], &f.session(), &f.devices);
        assert_eq!(ids(&p), [(f.primary, "primary")]);
    }

    /// A primary tagged with a restricted tag, in any case, restricts the
    /// session; then only devices carrying it too hold copies, and a session
    /// left short says why.
    #[test]
    fn a_restricted_tag_only_takes_devices_out() {
        let mut f = Fleet::new();
        let tagged = f.owners(100);
        f.device(tagged).tags = vec!["PROD".into()];
        let untagged = f.owners(1);
        let primary_tags = vec!["Prod".to_string(), "linux".to_string()];
        let s = SessionFacts {
            primary_tags: &primary_tags,
            ..f.session()
        };
        let p = place(&rules(2, 4), &[], &s, &f.devices);
        assert_eq!(p.restricted_tags, ["prod"], "the policy's spelling");
        assert_eq!(ids(&p), [(f.primary, "primary"), (tagged, "owner")]);
        assert!(!p.members.iter().any(|(i, _)| *i == untagged));
        f.device(tagged).tags.clear();
        let p = place(&rules(2, 4), &[], &s, &f.devices);
        assert_eq!(ids(&p), [(f.primary, "primary")]);
        assert_eq!(p.short, Some(Short::Restricted));
        let p = place(&rules(2, 4), &[], &f.session(), &f.devices);
        assert_eq!(
            ids(&p),
            [(f.primary, "primary"), (untagged, "owner")],
            "an untagged primary restricts nothing"
        );
    }

    /// A tag the session already carries stays, though its primary no longer
    /// carries it and the policy no longer names it.
    #[test]
    fn a_session_once_restricted_stays_restricted() {
        let mut f = Fleet::new();
        let untagged = f.owners(1);
        let pci = f.owners(2);
        f.device(pci).tags = vec!["pci".into()];
        let carried = vec!["pci".to_string()];
        let s = SessionFacts {
            restricted: &carried,
            ..f.session()
        };
        let p = place(&rules(2, 4), &[], &s, &f.devices);
        assert_eq!(p.restricted_tags, ["pci"]);
        assert_eq!(ids(&p), [(f.primary, "primary"), (pci, "owner")]);
        assert!(!p.members.iter().any(|(i, _)| *i == untagged));
    }

    /// An adopted session is placed where it was adopted and nowhere else.
    #[test]
    fn an_adopted_session_stays_where_it_was_adopted() {
        let mut f = Fleet::new();
        f.owners(1);
        let s = SessionFacts {
            origin: SessionOrigin::Adopted,
            ..f.session()
        };
        let p = place(&rules(2, 4), &[], &s, &f.devices);
        assert_eq!(ids(&p), [(f.primary, "primary")]);
        assert_eq!(p.short, Some(Short::Adopted));
    }

    /// Two devices seen at the same moment are taken in id order, so a
    /// placement is the same whenever it is computed.
    #[test]
    fn a_tie_is_broken_by_id() {
        let mut f = Fleet::new();
        let a = f.owners(5);
        let b = f.owners(5);
        let first = a.min(b);
        let p = place(&rules(2, 4), &[], &f.session(), &f.devices);
        assert_eq!(ids(&p), [(f.primary, "primary"), (first, "owner")]);
    }

    /// P2c-4 — deciding again keeps a member that still qualifies, though a
    /// device seen more recently qualifies too; replaces one that no longer
    /// qualifies; and a smaller `min` keeps the first. A full set of archive
    /// replicas keeps the ones it holds.
    #[test]
    fn a_placement_decided_again_keeps_what_still_qualifies() {
        let mut f = Fleet::new();
        let old = f.owners(3600);
        let fresh = f.owners(1);
        let held = vec![old];
        let s = SessionFacts {
            current: &held,
            ..f.session()
        };
        assert_eq!(
            ids(&place(&rules(2, 4), &[], &s, &f.devices)),
            [(f.primary, "primary"), (old, "owner")],
            "kept, though `fresh` was seen since"
        );
        f.device(old).replica = false;
        assert_eq!(
            ids(&place(&rules(2, 4), &[], &s, &f.devices)),
            [(f.primary, "primary"), (fresh, "owner")],
            "replaced once it no longer offers"
        );
        f.device(old).replica = true;
        let both = vec![old, fresh];
        let s = SessionFacts {
            current: &both,
            ..f.session()
        };
        assert_eq!(
            ids(&place(&rules(2, 4), &[], &s, &f.devices)),
            [(f.primary, "primary"), (old, "owner")],
            "a smaller min keeps the first"
        );

        let a1 = f.owners(10);
        let a2 = f.owners(20);
        for a in [a1, a2] {
            f.device(a).archive = true;
        }
        let archives = [a1, a2];
        let holds_a2 = vec![a2];
        let s = SessionFacts {
            current: &holds_a2,
            ..f.session()
        };
        assert_eq!(
            ids(&place(&rules(2, 2), &archives, &s, &f.devices)),
            [(f.primary, "primary"), (a2, "archive")],
            "the archive it holds, before the one the policy lists first"
        );
    }

    /// FR-90 P2e-3 — the role the old primary keeps, by placement's rules
    /// for one device and without `min`: the owner's own device that offers
    /// is a member though `min` is met; a designated archive is an archive;
    /// a device that does not offer, an ephemeral one, someone else's, the
    /// new primary itself and one missing a restricted tag keep none.
    #[test]
    fn the_old_primary_keeps_a_role_only_where_placement_would_give_one() {
        let mut f = Fleet::new();
        let old = f.owners(1);
        let s = f.session();
        let one = rules(1, 4);
        let role = |f: &Fleet, d: ObjectId, archives: &[ObjectId], s: &SessionFacts<'_>| {
            let dev = f.devices.iter().find(|x| x.id == d).unwrap();
            eligible_role(&one, archives, s, dev)
        };
        assert_eq!(
            role(&f, old, &[], &s),
            Some(MemberRole::Owner),
            "min 1 is met by the new primary alone, and the copy stays anyway"
        );
        f.device(old).archive = true;
        assert_eq!(role(&f, old, &[old], &s), Some(MemberRole::Archive));
        let mut off = rules(1, 4);
        off.archive = false;
        let dev = f.devices.iter().find(|x| x.id == old).unwrap().clone();
        assert_eq!(
            eligible_role(&off, &[old], &s, &dev),
            Some(MemberRole::Owner),
            "archive off: the owner's own"
        );

        f.device(old).replica = false;
        assert_eq!(role(&f, old, &[], &s), None, "it does not offer");
        f.device(old).replica = true;
        f.device(old).ephemeral = true;
        assert_eq!(role(&f, old, &[], &s), None, "ephemeral");
        f.device(old).ephemeral = false;
        f.device(old).owner_user_id = ObjectId::new();
        assert_eq!(role(&f, old, &[], &s), None, "someone else's");
        f.device(old).owner_user_id = f.owner;

        let as_primary = SessionFacts {
            primary: old,
            ..f.session()
        };
        assert_eq!(role(&f, old, &[], &as_primary), None, "the primary itself");

        let carried = vec!["pci".to_string()];
        let restricted = SessionFacts {
            restricted: &carried,
            ..f.session()
        };
        assert_eq!(role(&f, old, &[], &restricted), None, "a restricted tag");
        f.device(old).tags = vec!["PCI".into()];
        assert_eq!(
            role(&f, old, &[], &restricted),
            Some(MemberRole::Owner),
            "carried, in any case"
        );
    }
}
