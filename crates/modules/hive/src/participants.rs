// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P1c — who takes part in a session besides its owner, and how.
//!
//! A session's room has members; a session has DRIVERS (design §4.5). The
//! owner names both: a READER joins the room, reads the session and talks in
//! the room; a DRIVER also prompts it and answers its approvals. Everything
//! anyone writes in the room is ordinary chat — only a driver's "ask the
//! agent" travels to the harness, over the driver's own viewer peer.
//!
//! | route | who | does |
//! |---|---|---|
//! | `GET …/session/{id}/participant` | anyone who may read it | the owner, the drivers, the readers |
//! | `PUT …/session/{id}/participant/{user}` `{role}` | the owner | `driver` or `reader`: in the room, and driving or not |
//! | `DELETE …/session/{id}/participant/{user}` | the owner | out of the room, driving nothing |
//!
//! ⚠️ A driver must hold `HIVE_RUN` when named. Driving is running code on
//! the device as the session's account (a driver answers its approvals too),
//! so an owner cannot hand it to a member the org has not trusted with it.
//! ⚠️ A change ends the person's open views of the session
//! (`role_changed`): a grant carries `may_prompt` as it was minted, and the
//! view they reopen is minted afresh.
//! ⚠️ The room hears every change: who may prompt the agent is something
//! everyone in the room should be able to see.

use axum::{
    Json,
    extract::{Path, State},
};
use bson::oid::ObjectId;
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use meshharbor_db::models::role::permissions;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::model::{AgentSession, MAX_DRIVERS, SessionOrigin};
use crate::routes::{Audit, member_tenant, parse_oid};
use crate::{HiveState, access, room, view};

/// `PUT …/participant/{user_id}`.
#[derive(Debug, Deserialize)]
pub struct SetBody {
    /// `driver` | `reader`.
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct Participant {
    pub user_id: String,
    pub display_name: String,
    /// `owner` | `driver` | `reader`.
    pub role: &'static str,
}

#[derive(Debug, Serialize)]
pub struct ParticipantsResponse {
    pub items: Vec<Participant>,
    /// Whether the caller may change them: the owner alone.
    pub may_manage: bool,
}

/// The session `sid` of `tid`, if `user` may read it; otherwise the 404 a
/// bogus id gets, so a session's existence does not leak to other members.
pub(crate) async fn readable(
    state: &HiveState,
    tid: ObjectId,
    sid: ObjectId,
    user: ObjectId,
) -> Result<AgentSession, ApiError> {
    let s = state.sessions.find_in_tenant(tid, sid).await?;
    if !access::may_read(state, &s, user).await {
        return Err(ApiError::NotFound("Resource not found".to_string()));
    }
    Ok(s)
}

/// The room's members, each with their part: the owner first, then the
/// drivers, then the readers, each group by name. A driver who left the room
/// is not listed — they read nothing and drive nothing.
async fn participants_of(
    state: &HiveState,
    s: &AgentSession,
) -> Result<Vec<Participant>, ApiError> {
    let mut ids = match s.room_id {
        Some(room) => state.chat.member_ids(room).await?,
        None => Vec::new(),
    };
    if !ids.contains(&s.owner_id) {
        ids.push(s.owner_id);
    }
    let names = state.users.find_display_names(&ids).await?;
    let mut items: Vec<Participant> = ids
        .into_iter()
        .map(|id| Participant {
            user_id: id.to_hex(),
            display_name: names.get(&id).cloned().unwrap_or_default(),
            role: if id == s.owner_id {
                "owner"
            } else if s.drivers.contains(&id) {
                "driver"
            } else {
                "reader"
            },
        })
        .collect();
    let rank = |r: &str| match r {
        "owner" => 0,
        "driver" => 1,
        _ => 2,
    };
    items.sort_by(|a, b| {
        rank(a.role).cmp(&rank(b.role)).then_with(|| {
            a.display_name
                .to_lowercase()
                .cmp(&b.display_name.to_lowercase())
        })
    });
    Ok(items)
}

/// `GET /api/tenant/{tenant_id}/hive/session/{session_id}/participant`.
pub async fn list(
    State(state): State<HiveState>,
    auth: AuthUser,
    Path((tenant_id, session_id)): Path<(String, String)>,
) -> Result<Json<ParticipantsResponse>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let sid = parse_oid(&session_id, "session_id")?;
    let s = readable(&state, tid, sid, auth.user_id).await?;
    Ok(Json(ParticipantsResponse {
        items: participants_of(&state, &s).await?,
        may_manage: s.owner_id == auth.user_id,
    }))
}

/// The session the caller OWNS, with a room, and a target who is someone
/// else in the org. Anyone but the owner gets the 404 a bogus id gets.
async fn owned_and_target(
    state: &HiveState,
    auth: &AuthUser,
    tenant_id: &str,
    session_id: &str,
    user_id: &str,
) -> Result<(ObjectId, AgentSession, ObjectId, ObjectId), ApiError> {
    let tid = member_tenant(state, tenant_id, auth).await?;
    let sid = parse_oid(session_id, "session_id")?;
    let target = parse_oid(user_id, "user_id")?;
    let s = state.sessions.find_owned(tid, auth.user_id, sid).await?;
    let Some(room) = s.room_id else {
        return Err(ApiError::BadRequest(
            "this session has no room, so nobody else can take part in it".into(),
        ));
    };
    if target == s.owner_id {
        return Err(ApiError::BadRequest(
            "the owner always drives their own session".into(),
        ));
    }
    Ok((tid, s, room, target))
}

fn audit(
    s: &AgentSession,
    tid: ObjectId,
    actor: ObjectId,
    target: ObjectId,
) -> impl Fn(&'static str, Option<&'static str>) -> Audit {
    let (device_id, session_id) = (s.location.device_id, s.id);
    move |outcome, reason| Audit {
        tenant_id: tid,
        user_id: actor,
        target_id: Some(target),
        device_id,
        session_id,
        action: "participant",
        outcome,
        reason,
    }
}

/// The name a note gives someone, escaped: a display name is not markdown.
async fn name_of(state: &HiveState, user: ObjectId) -> String {
    let name = state
        .users
        .find_display_names(&[user])
        .await
        .ok()
        .and_then(|m| m.get(&user).cloned())
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| "A member".to_string());
    room::md_escape(&name)
}

/// `PUT /api/tenant/{tenant_id}/hive/session/{session_id}/participant/{user_id}`
/// `{role: "driver" | "reader"}` — the owner names someone in the org.
pub async fn set(
    State(state): State<HiveState>,
    auth: AuthUser,
    Path((tenant_id, session_id, user_id)): Path<(String, String, String)>,
    Json(body): Json<SetBody>,
) -> Result<Json<ParticipantsResponse>, ApiError> {
    let drives = match body.role.as_str() {
        "driver" => true,
        "reader" => false,
        _ => return Err(ApiError::BadRequest("role is `driver` or `reader`".into())),
    };
    let (tid, s, room, target) =
        owned_and_target(&state, &auth, &tenant_id, &session_id, &user_id).await?;
    let sid = s.id.expect("a stored session has an id");
    let audit = audit(&s, tid, auth.user_id, target);

    // Someone in the org — a stranger's id answers like a bogus one.
    if !state.tenants.is_member(tid, target).await? {
        return Err(ApiError::NotFound("Resource not found".to_string()));
    }
    let was_driver = s.drivers.contains(&target);
    // P1j — an adopted session has no drivers: the terminal holds the harness,
    // and nothing typed here could reach it (decision 11). Readers it may have.
    if drives && s.origin == SessionOrigin::Adopted {
        audit("refused", Some("adopted_no_drivers"))
            .write(&state)
            .await;
        return Err(ApiError::Conflict(
            "an adopted session runs in a terminal, so nobody drives it from here — \
             add them as a reader"
                .into(),
        ));
    }
    if drives && !was_driver {
        let perms = state.tenants.get_member_permissions(tid, target).await?;
        if !permissions::has(perms, permissions::HIVE_RUN) {
            audit("refused", Some("no_permission")).write(&state).await;
            return Err(ApiError::Forbidden(
                "they cannot drive agent sessions: their role does not include \
                 \"Run agent sessions\" (HIVE_RUN) — add them as a reader, or ask \
                 an owner to grant it"
                    .into(),
            ));
        }
        if s.drivers.len() >= MAX_DRIVERS {
            audit("refused", Some("too_many_drivers"))
                .write(&state)
                .await;
            return Err(ApiError::Conflict(format!(
                "a session has at most {MAX_DRIVERS} drivers besides its owner"
            )));
        }
    }

    // The seat before the room: if another tab of the owner's filled the last
    // place meanwhile, NOTHING changed — no silent, unaudited reader. A crash
    // between the two leaves a driver outside the room, who reads nothing and
    // so drives nothing.
    if drives != was_driver
        && !state
            .sessions
            .set_driver(tid, auth.user_id, sid, target, drives)
            .await?
    {
        audit("refused", Some("too_many_drivers"))
            .write(&state)
            .await;
        return Err(ApiError::Conflict(format!(
            "a session has at most {MAX_DRIVERS} drivers besides its owner"
        )));
    }
    let joined = state
        .chat
        .add_bound_member(tid, room, room::MODULE, target)
        .await?;
    if drives != was_driver {
        // What their open views say about prompting is stale now.
        view::end_session_grants_of(&state, sid, target, "role_changed").await;
    }

    let changed = joined || drives != was_driver;
    if changed {
        let role = if drives { "driver" } else { "reader" };
        audit(role, None).write(&state).await;
        info!(tenant = %tid, session = %sid, user = %target, role, "hive: a participant's part changed");
        let name = name_of(&state, target).await;
        let text = if drives {
            format!(
                "👥 **{name}** drives this session now: they may prompt it and answer its approvals."
            )
        } else if was_driver {
            format!("👥 **{name}** no longer drives this session, and reads it.")
        } else {
            format!("👥 **{name}** joined to read this session.")
        };
        room::note(&state, &s, text).await;
    }

    let s = state.sessions.find_in_tenant(tid, sid).await?;
    Ok(Json(ParticipantsResponse {
        items: participants_of(&state, &s).await?,
        may_manage: true,
    }))
}

/// `DELETE /api/tenant/{tenant_id}/hive/session/{session_id}/participant/{user_id}`
/// — the owner takes someone out: out of the room, driving nothing.
/// Idempotent: someone who takes no part is answered with the list as it is.
pub async fn remove(
    State(state): State<HiveState>,
    auth: AuthUser,
    Path((tenant_id, session_id, user_id)): Path<(String, String, String)>,
) -> Result<Json<ParticipantsResponse>, ApiError> {
    let (tid, s, room, target) =
        owned_and_target(&state, &auth, &tenant_id, &session_id, &user_id).await?;
    let sid = s.id.expect("a stored session has an id");

    let was_driver = s.drivers.contains(&target);
    if was_driver {
        state
            .sessions
            .set_driver(tid, auth.user_id, sid, target, false)
            .await?;
    }
    let left = state
        .chat
        .remove_bound_member(tid, room, room::MODULE, target)
        .await?;
    if was_driver || left {
        view::end_session_grants_of(&state, sid, target, "removed").await;
        // FR-90 P2i-2 — and their searches that name it: out of its room,
        // they no longer read it.
        if left {
            view::end_searches_naming(&state, sid, target, "removed").await;
        }
        audit(&s, tid, auth.user_id, target)("removed", None)
            .write(&state)
            .await;
        info!(tenant = %tid, session = %sid, user = %target, "hive: a participant was removed");
        let name = name_of(&state, target).await;
        room::note(
            &state,
            &s,
            format!("👥 **{name}** no longer takes part in this session."),
        )
        .await;
    }

    let s = state.sessions.find_in_tenant(tid, sid).await?;
    Ok(Json(ParticipantsResponse {
        items: participants_of(&state, &s).await?,
        may_manage: true,
    }))
}
