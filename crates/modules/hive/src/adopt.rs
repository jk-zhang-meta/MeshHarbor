// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P1j — terminal sessions a person adopted on a device (`roomler hive
//! adopt`), offered by that device for a record (decision 11).
//!
//! A terminal session passed none of Hive's start gates: it is the person's
//! own work, in their own account. So an adopted session is theirs alone — a
//! Secret room with them in it, readers only if they name them, and no
//! drivers at all, the owner included, because the terminal holds the
//! harness ([`crate::access::drives_now`]). The record holds what any
//! session's holds: metadata, never content. No title is offered: a
//! terminal's first prompt is content, so the record is named after its
//! folder.
//!
//! | gate | owner | refusal |
//! |---|---|---|
//! | the device advertises `hive-adopt` | the device's owner (`hive_adopt`, never pushable) | dropped, unanswered |
//! | the org is one agent sessions serve | the server (`hive.tenants`, P1g) | `hive_not_enabled` |
//! | ≤ [`hive_limits::ADOPT_RATE_PER_MINUTE`] offers from the device | the server | `rate_limited` |
//! | the keys name exactly ONE person who exists | the device's `hive_accounts`, resolved here | `no_account` · `ambiguous_account` |
//! | that person is a member of the device's org | the server | `not_a_member` |
//! | ≤ [`hive_limits::MAX_ADOPTED_PER_DEVICE`] live adopted sessions there | the server | `at_capacity` |
//!
//! ⚠️ The keys are the device's `hive_accounts` keys for the account the
//! terminal runs as: the device owner's statement of who that account is.
//! EVERY key is resolved, member or not. A second real person behind the same
//! account makes it `ambiguous_account` — never "the one of them who is a
//! member", which would show one person's terminal to another.
//! ⚠️ Every offer is attributed afresh. One for a harness session this device
//! already holds a live adopted record for is answered with that record, for
//! the same person only: the device offers again after a restart, or when an
//! ack was lost, and a second record would split one terminal session in two.
//! Held for someone else, that record ends (`attribution_changed`): a remap
//! must never pour one person's terminal into another's record.

use std::collections::HashSet;

use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_remote_control::{
    hive::{HARNESS_CLAUDE_CODE, HiveAdoptRefusal, hive_limits},
    signaling::ServerMsg,
};
use meshharbor_services::dao::base::escape_regex;
use tracing::{info, warn};

use crate::model::{AgentSession, HarnessRef, SessionLocation, SessionOrigin, SessionStatus};
use crate::{HiveState, room, routes};

/// One `rc:hive.adopt`, as the device sent it.
pub(crate) struct Offer {
    pub adopt_id: String,
    pub harness_session: String,
    pub keys: Vec<String>,
    pub account: String,
    pub folder: String,
}

/// Answer one offer: a record and `rc:hive.adopt_ack {session_id}`, or the
/// refusal word. An offer from a connection that does not advertise
/// `hive-adopt`, or one too malformed to echo, is dropped unanswered.
pub(crate) async fn offer(state: &HiveState, tenant_id: ObjectId, device_id: ObjectId, o: Offer) {
    if state.fleet.rc_hub.agent_supports_hive_adopt(device_id) != Some(true) {
        warn!(
            device = %device_id,
            "hive: an adopt offer from a connection that does not advertise hive-adopt — dropped"
        );
        return;
    }
    let adopt_id = o.adopt_id.trim().to_string();
    if adopt_id.is_empty()
        || adopt_id.len() > hive_limits::MAX_ADOPT_ID_LEN
        || adopt_id.chars().any(char::is_control)
    {
        warn!(device = %device_id, "hive: an adopt offer with no usable id — dropped");
        return;
    }
    let answer = match decide(state, tenant_id, device_id, &o).await {
        Ok((session_id, fence)) => ServerMsg::HiveAdoptAck {
            adopt_id,
            session_id: Some(session_id),
            fence: Some(fence),
            refused: None,
        },
        Err(word) => {
            info!(
                device = %device_id, refused = word.as_str(),
                "hive: an adopt offer refused"
            );
            ServerMsg::HiveAdoptAck {
                adopt_id,
                session_id: None,
                fence: None,
                refused: Some(word),
            }
        }
    };
    if let Err(e) = state
        .fleet
        .rc_hub
        .push_hive_adopt(device_id, tenant_id, answer)
    {
        warn!(device = %device_id, %e, "hive: an adopt answer was not delivered");
    }
}

/// The gates, in order. `Ok` is the record's id and fence.
async fn decide(
    state: &HiveState,
    tenant_id: ObjectId,
    device_id: ObjectId,
    o: &Offer,
) -> Result<(ObjectId, u64), HiveAdoptRefusal> {
    if !state.scope.serves(tenant_id) {
        return Err(HiveAdoptRefusal::HiveNotEnabled);
    }
    // Keyed (device, device): a device's offers, whoever they name.
    if !state
        .adopt_limiter
        .check(device_id, device_id, hive_limits::ADOPT_RATE_PER_MINUTE)
    {
        return Err(HiveAdoptRefusal::RateLimited);
    }
    let folder = routes::clean_folder(&o.folder).map_err(|_| HiveAdoptRefusal::Other)?;
    let account = clean_account(&o.account).ok_or(HiveAdoptRefusal::Other)?;
    let harness_session =
        clean_harness_session(&o.harness_session).ok_or(HiveAdoptRefusal::Other)?;
    if o.keys.is_empty() || o.keys.len() > hive_limits::MAX_ADOPT_KEYS {
        return Err(HiveAdoptRefusal::NoAccount);
    }

    // Every offer is attributed afresh, a repeated one included: the device's
    // owner may have remapped the account since.
    let people = people(state, &o.keys).await.map_err(|e| {
        warn!(%e, "hive: an adopt offer's keys could not be resolved");
        HiveAdoptRefusal::Other
    })?;
    let owner = match people.len() {
        0 => return Err(HiveAdoptRefusal::NoAccount),
        1 => *people.iter().next().expect("one"),
        _ => return Err(HiveAdoptRefusal::AmbiguousAccount),
    };
    if !matches!(state.tenants.is_member(tenant_id, owner).await, Ok(true)) {
        return Err(HiveAdoptRefusal::NotAMember);
    }

    // Already held: the same record again — for the same person only. Held
    // for someone else, the account now names another person than the one
    // whose session it was: that record ends, and nothing more is mirrored
    // into it.
    let held = state
        .sessions
        .live_matching(doc! {
            "tenant_id": tenant_id,
            "location.device_id": device_id,
            "origin": SessionOrigin::Adopted.as_str(),
        })
        .await
        .map_err(|e| {
            warn!(%e, "hive: the device's adopted sessions could not be read");
            HiveAdoptRefusal::Other
        })?;
    if let Some(s) = held.iter().find(|s| s.harness.session == harness_session) {
        let sid = s.id.expect("a stored session has an id");
        if s.owner_id == owner {
            return Ok((sid, u64::try_from(s.fence).unwrap_or(1)));
        }
        warn!(
            session = %sid, device = %device_id,
            "hive: an adopted session's account now names someone else — ended"
        );
        if let Err(e) = state
            .sessions
            .end_now(
                sid,
                "attribution_changed",
                "the account now names someone else",
            )
            .await
        {
            warn!(session = %sid, %e, "hive: an adopted session was not ended");
        }
        audit(
            state,
            tenant_id,
            owner,
            device_id,
            Some(sid),
            "refused",
            Some("attribution_changed"),
        )
        .await;
        return Err(HiveAdoptRefusal::AmbiguousAccount);
    }
    if held.len() >= hive_limits::MAX_ADOPTED_PER_DEVICE {
        audit(
            state,
            tenant_id,
            owner,
            device_id,
            None,
            "refused",
            Some("at_capacity"),
        )
        .await;
        return Err(HiveAdoptRefusal::AtCapacity);
    }
    // LIVE: a removed device adopts nothing.
    let device = state
        .fleet
        .agents
        .find_live_in_tenant(tenant_id, device_id)
        .await
        .map_err(|_| HiveAdoptRefusal::Other)?;

    let sid = ObjectId::new();
    let title = routes::clean_title(None, &folder).map_err(|_| HiveAdoptRefusal::Other)?;
    let room_id = room::open(state, tenant_id, sid, &title, owner)
        .await
        .map_err(|e| {
            warn!(session = %sid, %e, "hive: an adopted session's room was not created");
            HiveAdoptRefusal::Other
        })?;
    let now = DateTime::now();
    let session = AgentSession {
        id: Some(sid),
        tenant_id,
        owner_id: owner,
        drivers: Vec::new(),
        title,
        room_id: Some(room_id),
        last_turn: None,
        harness: HarnessRef {
            id: HARNESS_CLAUDE_CODE.into(),
            session: harness_session,
        },
        location: SessionLocation {
            device_id,
            device_name: device.name.clone(),
            folder,
            account: Some(account),
        },
        // The terminal session is already running; its device reports turns
        // and its end from here on.
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
        origin: SessionOrigin::Adopted,
        // Placed nowhere: an adopted session stays where it was adopted
        // until P2f makes it a managed one.
        replicaset: None,
        promotion: None,
        fences: Vec::new(),
        moved: None,
        parent: None,
        from_terminal: None,
        path_map: Vec::new(),
        purged: None,
    };
    state.sessions.create(&session).await.map_err(|e| {
        warn!(session = %sid, %e, "hive: an adopted session was not recorded");
        HiveAdoptRefusal::Other
    })?;
    info!(
        session = %sid, device = %device_id, owner = %owner,
        "hive: a terminal session adopted"
    );
    audit(
        state,
        tenant_id,
        owner,
        device_id,
        Some(sid),
        "adopted",
        None,
    )
    .await;
    room::note(state, &session, room::adopted_note(&session)).await;
    Ok((sid, 1))
}

/// The people the keys name: each key a user id, or an address some account
/// PROVED (`users.email` holds an address only then — an unproven one holds a
/// `.invalid` placeholder, which an anchored match on a real address never
/// reaches, and which a key may not name). A key that names nobody is skipped.
async fn people(
    state: &HiveState,
    keys: &[String],
) -> Result<HashSet<ObjectId>, meshharbor_services::dao::base::DaoError> {
    let mut found = HashSet::new();
    for key in keys {
        let key = key.trim();
        if key.is_empty() || key.len() > hive_limits::MAX_ADOPT_KEY_LEN {
            continue;
        }
        let filter = if key.len() == 24
            && let Ok(id) = ObjectId::parse_str(key)
        {
            doc! { "_id": id, "deleted_at": null }
        } else if key.contains('@') && !key.to_ascii_lowercase().ends_with(".invalid") {
            // Addresses compare case-insensitively, as the device's own
            // `account_for` does.
            doc! {
                "email": { "$regex": format!("^{}$", escape_regex(key)), "$options": "i" },
                "deleted_at": null,
            }
        } else {
            continue;
        };
        if let Some(u) = state.users.base.find_one(filter).await?
            && let Some(id) = u.id
        {
            found.insert(id);
        }
    }
    Ok(found)
}

/// A local account name as the device reported it: short, one token.
fn clean_account(raw: &str) -> Option<String> {
    let a = raw.trim();
    (!a.is_empty()
        && a.len() <= hive_limits::MAX_ACCOUNT_LEN
        && !a.chars().any(|c| c.is_control() || c.is_whitespace()))
    .then(|| a.to_string())
}

/// Claude Code's session id: a UUID, or anything shaped like one.
fn clean_harness_session(raw: &str) -> Option<String> {
    let s = raw.trim();
    (!s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
        .then(|| s.to_ascii_lowercase())
}

/// `hive_audit` for an offer that named a person; refusals before one is
/// known are logged, not audited — there is no actor to attribute them to.
async fn audit(
    state: &HiveState,
    tenant_id: ObjectId,
    user_id: ObjectId,
    device_id: ObjectId,
    session_id: Option<ObjectId>,
    outcome: &'static str,
    reason: Option<&'static str>,
) {
    routes::Audit {
        tenant_id,
        user_id,
        target_id: None,
        device_id,
        session_id,
        action: "adopt",
        outcome,
        reason,
    }
    .write(state)
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_account_is_one_short_token() {
        assert_eq!(clean_account(" dev "), Some("dev".into()));
        assert_eq!(clean_account(""), None);
        assert_eq!(clean_account("two words"), None);
        assert_eq!(clean_account("line\nbreak"), None);
        assert_eq!(clean_account(&"a".repeat(65)), None);
    }

    #[test]
    fn a_harness_session_is_shaped_like_a_uuid() {
        assert_eq!(
            clean_harness_session("6F1C8A2E-3B7D-4E5F-9A10-2B3C4D5E6F70"),
            Some("6f1c8a2e-3b7d-4e5f-9a10-2b3c4d5e6f70".into())
        );
        assert_eq!(clean_harness_session("../../etc"), None);
        assert_eq!(clean_harness_session(""), None);
        assert_eq!(clean_harness_session(&"a".repeat(65)), None);
    }
}
