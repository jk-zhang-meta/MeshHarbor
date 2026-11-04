// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2f-4b — an ended adopted session made a managed one (decision 11's
//! other half): `POST …/hive/session/{session_id}/manage`. The device's half
//! is P2f-4a: a start carrying `from_terminal` puts the terminal's own
//! history in place as the account it ran as, by the device's own record of
//! whose terminal it was, and resumes it.
//!
//! The SAME record becomes a managed session, at its fence, on the device
//! that adopted it ([`crate::dao::AgentSessionDao::make_managed`]): the
//! conversation stays one chain, so a member that joins later takes all of
//! it. Its start goes only to a connection that advertises `hive-manage`
//! ([`crate::routes::push_start`]).
//!
//! # Its gates, in order
//!
//! 1. membership, and the replicaset's switch (`hive.replicaset`): off, the
//!    route is not there (P2's switch, as for a fork and a teleport);
//! 2. the session, the caller's own — 404 otherwise: decision 11, nobody
//!    else learns that an adopted session exists;
//! 3. the org is not archived — `org_archived`; `HIVE_RUN` — `no_permission`;
//! 4. no asking of it in flight — `in_progress`;
//! 5. an adopted session — `not_adopted`; ended — `not_ended`; by its
//!    terminal's own end — `stopped` for a stop from Roomler, after which its
//!    terminal went on, `ended_otherwise` for any other end;
//! 6. the device that adopted it, live in the org, connected here, and making
//!    one (`hive-manage`) — `device_offline` / `device_unsupported`;
//! 7. the per-(user, device) ceiling — `rate_limited`, LAST.
//!
//! From 3 on, a refusal is a 200 carrying the reason, and is audited
//! (`manage`). The device's own gates (P2f-4a) answer its start. A start it
//! refuses, or one that never reaches it, leaves the record the adopted
//! session it was, the word kept on `from_terminal` ([`restore`]): never a
//! refused managed session that nothing could start again.

use axum::{
    Json,
    extract::{Path, State},
};
use bson::{DateTime, oid::ObjectId};
use meshharbor_db::models::role::permissions;
use meshharbor_remote_control::{
    error::Error as HubError,
    hive::{HiveRefusal, hive_limits},
    models::Agent,
    signaling::ServerMsg,
};
use meshharbor_services::dao::base::DaoError;
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use serde::Deserialize;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::HiveState;
use crate::model::{AgentSession, FromTerminal, SessionOrigin, SessionStatus, SessionView};
use crate::room;
use crate::routes::{Audit, StartResponse, clean_folder, member_tenant, memory_frame, parse_oid};

/// `POST …/hive/session/{session_id}/manage`.
#[derive(Debug, Deserialize)]
pub struct ManageBody {
    /// Where it runs on its device, as typed. Defaults to the folder its
    /// terminal ran in.
    #[serde(default)]
    pub folder: Option<String>,
}

/// Why the SERVER refused to make a terminal session a managed one. The
/// device's own refusals come back on its start, and are kept on the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManageDenyReason {
    OrgArchived,
    NoPermission,
    InProgress,
    NotAdopted,
    NotEnded,
    Stopped,
    EndedOtherwise,
    DeviceOffline,
    DeviceUnsupported,
    RateLimited,
}

impl ManageDenyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OrgArchived => "org_archived",
            Self::NoPermission => "no_permission",
            Self::InProgress => "in_progress",
            Self::NotAdopted => "not_adopted",
            Self::NotEnded => "not_ended",
            Self::Stopped => "stopped",
            Self::EndedOtherwise => "ended_otherwise",
            Self::DeviceOffline => "device_offline",
            Self::DeviceUnsupported => "device_unsupported",
            Self::RateLimited => "rate_limited",
        }
    }

    /// What the person is told — each names its own next step.
    pub const fn message(self) -> &'static str {
        match self {
            Self::OrgArchived => "this organization is archived; new sessions are blocked",
            Self::NoPermission => {
                "your role does not include \"Run agent sessions\" (HIVE_RUN); \
                 an owner can grant it"
            }
            Self::InProgress => {
                "the session is being made a managed one already; its room says how that goes"
            }
            Self::NotAdopted => {
                "only a session adopted from a terminal is made a managed one, and this one \
                 is not, or is one already"
            }
            Self::NotEnded => {
                "its terminal session still runs: it is made a managed one once that terminal \
                 session ends"
            }
            Self::Stopped => {
                "its mirroring was stopped from Roomler, and what its terminal did after that \
                 is not Roomler's to take"
            }
            Self::EndedOtherwise => {
                "it ended for another reason than its terminal's own end (its device, its \
                 person or its organization), and is not made a managed one"
            }
            Self::DeviceOffline => "the device it ran on is offline, or was removed",
            Self::DeviceUnsupported => {
                "the device's agent does not make terminal sessions managed — update it"
            }
            Self::RateLimited => "too many sessions started on this device in the last minute",
        }
    }
}

/// Gates 3 on, past the session lookup. The outer `Result` is the
/// infrastructure, the inner one the policy — as a start's.
async fn authorize(
    state: &HiveState,
    s: &AgentSession,
    user_id: ObjectId,
) -> Result<Result<Agent, ManageDenyReason>, ApiError> {
    let tid = s.tenant_id;
    let tenant = state.tenants.base.find_by_id(tid).await?;
    if tenant.is_archived {
        return Ok(Err(ManageDenyReason::OrgArchived));
    }
    let perms = state.tenants.get_member_permissions(tid, user_id).await?;
    if !permissions::has(perms, permissions::HIVE_RUN) {
        return Ok(Err(ManageDenyReason::NoPermission));
    }
    // Before the origin: an asking in flight has made the record a started one.
    if s.managing() {
        return Ok(Err(ManageDenyReason::InProgress));
    }
    if s.origin != SessionOrigin::Adopted {
        return Ok(Err(ManageDenyReason::NotAdopted));
    }
    if s.status != SessionStatus::Ended {
        return Ok(Err(ManageDenyReason::NotEnded));
    }
    // The terminal's own end is the device's `ended`, recorded `exited`; a
    // stop from Roomler records `stopped`, and its terminal went on after it.
    match s.end_reason.as_deref() {
        Some("exited") => {}
        Some("stopped") => return Ok(Err(ManageDenyReason::Stopped)),
        _ => return Ok(Err(ManageDenyReason::EndedOtherwise)),
    }
    let device_id = s.location.device_id;
    let device = match state.fleet.agents.find_live_in_tenant(tid, device_id).await {
        Ok(d) => d,
        Err(DaoError::NotFound) => return Ok(Err(ManageDenyReason::DeviceOffline)),
        Err(e) => return Err(e.into()),
    };
    match state
        .fleet
        .rc_hub
        .agent_supports_hive_manage(device_id, tid)
    {
        None => return Ok(Err(ManageDenyReason::DeviceOffline)),
        Some(false) => return Ok(Err(ManageDenyReason::DeviceUnsupported)),
        Some(true) => {}
    }
    // LAST: only an asking that would reach the device spends a token.
    if !state
        .start_limiter
        .check(user_id, device_id, hive_limits::START_RATE_PER_MINUTE)
    {
        return Ok(Err(ManageDenyReason::RateLimited));
    }
    Ok(Ok(device))
}

/// A refusal, with the session as it is.
fn refused_answer(reason: &str, message: &str, s: &AgentSession) -> StartResponse {
    StartResponse {
        outcome: "refused",
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        session: Some(SessionView::from(s)),
    }
}

/// `POST /api/tenant/{tenant_id}/hive/session/{session_id}/manage` — the
/// owner makes their ended adopted session a managed one, on the device that
/// adopted it. Answered as a start is, once the device said whether it
/// launched it (or has not, within the start's bound).
pub async fn manage(
    State(state): State<HiveState>,
    auth: AuthUser,
    Path((tenant_id, session_id)): Path<(String, String)>,
    Json(body): Json<ManageBody>,
) -> Result<Json<StartResponse>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    if !state.replicaset {
        return Err(ApiError::NotFound(
            "making terminal sessions managed is off on this server".into(),
        ));
    }
    let sid = parse_oid(&session_id, "session_id")?;
    // The owner's alone: anyone else's read of the id is a 404.
    let s = state.sessions.find_owned(tid, auth.user_id, sid).await?;
    let folder = clean_folder(body.folder.as_deref().unwrap_or(&s.location.folder))?;
    let device_id = s.location.device_id;
    let audit = |outcome: &'static str, reason: Option<&'static str>| Audit {
        tenant_id: tid,
        user_id: auth.user_id,
        target_id: None,
        device_id,
        session_id: Some(sid),
        action: "manage",
        outcome,
        reason,
    };
    let device = match authorize(&state, &s, auth.user_id).await? {
        Ok(device) => device,
        Err(reason) => {
            info!(
                tenant = %tid, session = %sid, device = %device_id, user = %auth.user_id,
                reason = reason.as_str(), "hive: making a terminal session managed refused"
            );
            audit("refused", Some(reason.as_str())).write(&state).await;
            return Ok(Json(refused_answer(reason.as_str(), reason.message(), &s)));
        }
    };

    let user = state.users.base.find_by_id(auth.user_id).await?;
    let hub = &state.fleet.rc_hub;
    // P1e — core memory, rendered now and frozen with the session, as for any
    // session that starts; only for a device that understands it.
    let memory = if hub.agent_supports_hive_memory(device_id) == Some(true) {
        match state
            .brain
            .snapshot(
                tid,
                sid,
                (auth.user_id, &user.display_name),
                (device_id, &device.name),
            )
            .await
        {
            Ok(m) => Some(m),
            Err(e) => {
                warn!(session = %sid, %e, "hive: core memory not rendered — the session starts without it");
                None
            }
        }
    } else {
        None
    };
    // P2c-2b — where its copies go, now that it follows the policy (decision
    // 11's half): replication never blocks a start, as for a new session.
    let (replicaset, short) = match crate::placement::place_new(
        &state,
        tid,
        auth.user_id,
        device_id,
        &device,
        &[],
    )
    .await
    {
        Ok((r, short)) => (Some(r), short),
        Err(e) => {
            warn!(session = %sid, %e, "hive: placement not read — the session runs on its device alone");
            (None, None)
        }
    };
    let at = DateTime::now();
    let from = FromTerminal {
        device_id,
        by: auth.user_id,
        at,
        ended_at: s.ended_at,
        end_reason: s.end_reason.clone(),
        detail: s.detail.clone(),
        folder: Some(s.location.folder.clone()),
        refused: None,
        refused_detail: None,
    };
    if !state
        .sessions
        .make_managed(
            sid,
            tid,
            auth.user_id,
            s.fence,
            &from,
            &folder,
            replicaset.as_ref(),
            memory.as_ref().map(|m| m.brain_rev),
        )
        .await?
    {
        // Another asking, or another change, came first: say which.
        let now = state.sessions.find(sid).await?.unwrap_or(s);
        let reason = if now.managing() {
            ManageDenyReason::InProgress
        } else if now.origin != SessionOrigin::Adopted {
            ManageDenyReason::NotAdopted
        } else {
            ManageDenyReason::NotEnded
        };
        audit("refused", Some(reason.as_str())).write(&state).await;
        return Ok(Json(refused_answer(
            reason.as_str(),
            reason.message(),
            &now,
        )));
    }
    let s = state
        .sessions
        .find(sid)
        .await?
        .ok_or_else(|| ApiError::Internal("the session record vanished".into()))?;
    room::note(&state, &s, room::managing_note(&s, &user.display_name)).await;
    if s.replicaset.is_some() {
        Audit {
            tenant_id: tid,
            user_id: auth.user_id,
            target_id: None,
            device_id,
            session_id: Some(sid),
            action: "place",
            outcome: if short.is_some() { "short" } else { "placed" },
            reason: short.map(crate::placement::Short::as_str),
        }
        .write(&state)
        .await;
    }
    let fence = u64::try_from(s.fence).unwrap_or(1);
    // P1e — the snapshot, kept for a re-send of the start, then sent ahead
    // of it on the same socket.
    if let Some(m) = &memory {
        if let Err(e) = state.brain.store_snapshot(m).await {
            warn!(session = %sid, %e, "hive: core memory not stored — a re-sent start goes without it");
        }
        if let Err(e) = hub.push_hive_memory(device_id, tid, memory_frame(m, fence)) {
            debug!(session = %sid, %e, "hive: core memory not sent");
        }
    }

    // The waiter before the push: the device's answer, however fast, must
    // find someone waiting.
    let pending = state.start_acks.expect(sid, device_id);
    let replicated = crate::replica::replicated(&s);
    let msg = ServerMsg::HiveStart {
        session_id: sid,
        harness: s.harness.id.clone(),
        harness_session: s.harness.session.clone(),
        fence,
        folder,
        user_id: auth.user_id,
        user_email: user.email,
        caller: user.display_name,
        resume: false,
        replicated,
        lease: replicated && hub.agent_supports_hive_lease(device_id, tid) == Some(true),
        fork_of: None,
        from_terminal: true,
    };
    if let Err(e) = crate::routes::push_start(&state, &s, device_id, msg) {
        // The device left, or reconnected as a build that does not make one,
        // between the gate and the push: nothing reached it.
        let reason = match e {
            HubError::ExecUnsupported(_) => ManageDenyReason::DeviceUnsupported,
            _ => ManageDenyReason::DeviceOffline,
        };
        restore(&state, &s, reason.as_str(), None).await;
        let now = state.sessions.find(sid).await?.unwrap_or(s);
        return Ok(Json(refused_answer(
            reason.as_str(),
            reason.message(),
            &now,
        )));
    }
    audit("sent", None).write(&state).await;
    info!(
        tenant = %tid, device = %device_id, user = %auth.user_id, session = %sid,
        "hive: a terminal session's start as a managed one sent"
    );
    pending
        .wait(Duration::from_secs(hive_limits::START_ACK_TIMEOUT_SECS))
        .await;
    let s = state
        .sessions
        .find(sid)
        .await?
        .ok_or_else(|| ApiError::Internal("the session record vanished".into()))?;
    Ok(Json(answer_of(&s, at)))
}

/// What the asking made at `at` came to, read off the record: refused (the
/// record is the adopted session it was, the word kept), or what any start's
/// answer says.
fn answer_of(s: &AgentSession, at: DateTime) -> StartResponse {
    match s.from_terminal.as_ref() {
        Some(f) if f.at == at && f.refused.is_some() => {
            let word = f.refused.as_deref().unwrap_or("other");
            refused_answer(word, crate::routes::device_refusal_message(word), s)
        }
        _ => StartResponse::from_record(s),
    }
}

/// The asking's start was refused, or never reached its device: the adopted
/// session it was again, its own end back, the word kept for whoever asked;
/// its room says why, the audit records it, and whoever waits on the start
/// is woken. `false` = the record changed first (the device took it after
/// all, or another asking replaced this one).
pub(crate) async fn restore(
    state: &HiveState,
    s: &AgentSession,
    word: &str,
    detail: Option<String>,
) -> bool {
    let (Some(sid), Some(from)) = (s.id, s.from_terminal.as_ref()) else {
        return false;
    };
    match state
        .sessions
        .restore_adopted(sid, from, word, detail.clone())
        .await
    {
        Ok(true) => {}
        Ok(false) => return false,
        Err(e) => {
            warn!(session = %sid, %e, "hive: a refused made-managed start was not restored");
            return false;
        }
    }
    info!(session = %sid, word, "hive: the terminal session is the adopted one it was again");
    if let Ok(Some(now)) = state.sessions.find(sid).await {
        room::note(
            state,
            &now,
            room::manage_refused_note(&now, word, detail.as_deref()),
        )
        .await;
    }
    Audit {
        tenant_id: s.tenant_id,
        user_id: from.by,
        target_id: None,
        device_id: from.device_id,
        session_id: Some(sid),
        action: "manage",
        outcome: "refused",
        // The audit's words are the server's and the device's own, by name.
        reason: Some(refusal_word(word)),
    }
    .write(state)
    .await;
    state.start_acks.deliver(sid, from.device_id);
    true
}

/// `word` as one of the audit's fixed words: the device's, or the server's
/// own for a start that never reached it.
fn refusal_word(word: &str) -> &'static str {
    HiveRefusal::ALL
        .into_iter()
        .map(HiveRefusal::as_str)
        .find(|w| *w == word)
        .unwrap_or(match word {
            "device_offline" => "device_offline",
            "device_unsupported" => "device_unsupported",
            "never_answered" => "never_answered",
            _ => "other",
        })
}

/// The device answered the asking's start with a refusal: the adopted
/// session it was again ([`restore`]). `false` = no asking of this session
/// waits on that device at that fence: the start's answer is anyone's.
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
    if !s.managing() || s.location.device_id != device_id || u64::try_from(s.fence) != Ok(fence) {
        return false;
    }
    restore(state, &s, word.as_str(), detail).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The server's words are a wire spelling: locked, and each says its
    /// next step.
    #[test]
    fn the_servers_refusal_words_are_locked() {
        let all = [
            (ManageDenyReason::OrgArchived, "org_archived"),
            (ManageDenyReason::NoPermission, "no_permission"),
            (ManageDenyReason::InProgress, "in_progress"),
            (ManageDenyReason::NotAdopted, "not_adopted"),
            (ManageDenyReason::NotEnded, "not_ended"),
            (ManageDenyReason::Stopped, "stopped"),
            (ManageDenyReason::EndedOtherwise, "ended_otherwise"),
            (ManageDenyReason::DeviceOffline, "device_offline"),
            (ManageDenyReason::DeviceUnsupported, "device_unsupported"),
            (ManageDenyReason::RateLimited, "rate_limited"),
        ];
        for (r, w) in all {
            assert_eq!(r.as_str(), w);
            assert!(!r.message().is_empty(), "{w}");
        }
    }

    /// The audit keeps a fixed word: the device's own, the server's for a
    /// start that never reached it, else `other` — never what a device of
    /// another build made up.
    #[test]
    fn the_audit_keeps_a_fixed_word() {
        assert_eq!(refusal_word("launch_failed"), "launch_failed");
        assert_eq!(refusal_word("no_account"), "no_account");
        assert_eq!(refusal_word("never_answered"), "never_answered");
        assert_eq!(refusal_word("device_unsupported"), "device_unsupported");
        assert_eq!(refusal_word("a word from a newer device"), "other");
    }
}
