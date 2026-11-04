// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! P3-4e — approvals: the person's yes a policy may ask for before a value
//! is released (`context has approval`, design §8.6).
//!
//! When Cedar denies a lease, the vault asks what a person could change:
//!
//! | Found for this very request | The vault |
//! |---|---|
//! | a driver's yes, still usable, for at least the TTL asked | decides again with them as the approver; an allow spends the yes |
//! | a card waiting for an answer | refuses `awaiting_approval`, naming it: no second card |
//! | a driver's no, within the card's deadline | refuses `denied` |
//! | nothing, and one of the session's drivers could lift the deny with a yes | posts a card into the session's room, pushes it to the drivers, and refuses `awaiting_approval` |
//! | nothing, and no driver could | refuses `denied`, as before P3-4e |
//!
//! "This very request" is one session at its fence on its device, one
//! secret's field, one mode, one audience ([`ApprovalKey`]), for at most the
//! TTL its card named: a yes to `env` toward `psql` for five minutes is no
//! yes to `file`, to another program, or to fifteen minutes.
//!
//! | Route | Does |
//! |---|---|
//! | `GET …/vault/approval/{id}` | an approval as the session's readers see it, and whether the caller may answer it |
//! | `POST …/vault/approval/{id}` | `{answer: "approve" \| "deny"}`: a driver's answer |
//!
//! Who answers: a driver who reads the session, while it is live — hive's
//! own rule for its approvals (`meshharbor_mod_hive::access::may_answer`) —
//! and whose yes the policy accepts. A policy may name its approvers
//! (`context.approval.approver in MeshHarbor::Group::"admin"`), so a yes is
//! decided by Cedar with the person as the approver when it is given, and
//! again when a lease would spend it; and a card is posted only when one of
//! the session's drivers could give a yes that counts.
//!
//! ⚠️ The card is a stub: the secret's handle, the mode, the audience and
//! the TTL, which the vault holds anyway — never why the session asked.
//! That step is in the transcript, which streams from a replica (design
//! §5.2).
//!
//! ⚠️ One yes, one lease: the lease spends the yes by compare-and-set
//! BEFORE its allow is recorded, so a lost race releases nothing, and a
//! failure after it only ever wastes a yes.
//!
//! ⚠️ An approval belongs to its session at its fence on its device. One
//! for a session that has moved or ended is withdrawn when it is next read
//! or answered, and one past its deadline expires then; a new card for the
//! same request first ends the stale one, which would otherwise hold the
//! request's one pending place.

use axum::{
    Json,
    extract::{Path, State},
};
use bson::{DateTime, oid::ObjectId};
use meshharbor_db::models::Binding;
use meshharbor_mod_hive::{access, model::AgentSession, room};
use meshharbor_remote_control::vault::lease_limits;
use meshharbor_services::dao::base::DaoError;
use meshharbor_core::{ApiError, extractors::auth::AuthUser};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::warn;

use crate::VaultState;
use crate::dao::ApprovalKey;
use crate::lease::{leasable, os_name, reason_of, use_ask};
use crate::model::{VaultApproval, VaultAuditEvent, approval_status as status};
use crate::policy::{self, ACTION_USE, Approver, Ask, DeviceFacts, Verdict};
use crate::policy_routes::{groups_of_member, org_set};
use crate::routes::{member_tenant, org_slug, rfc3339};
use crate::rrn::STATIC_FIELD;

/// The module id a card is bound to.
const MODULE: &str = "vault";

/// What a denied lease does next.
#[derive(Debug)]
pub(crate) enum Next {
    /// No yes could lift it: Cedar's deny stands.
    Deny,
    /// A driver's yes to this very request: decide again with them.
    Use {
        approval_id: ObjectId,
        approver: Approver,
    },
    /// A card waits for an answer — posted now, or earlier.
    Awaiting(ObjectId),
    /// A driver said no to this very request.
    Refused(ObjectId),
}

/// After Cedar denied `ask`, what an approval changes. An `Err` names what
/// could not be read or written; the lease is refused `unavailable`.
pub(crate) async fn after_deny(
    state: &VaultState,
    session: &AgentSession,
    key: &ApprovalKey<'_>,
    rrn: &str,
    ttl_s: i64,
    ask: &Ask,
) -> Result<Next, &'static str> {
    let now = DateTime::now();
    let live = state
        .approvals
        .live_for(key, now)
        .await
        .map_err(|_| "approval_unread")?;
    if let Some(a) = live
        .iter()
        .find(|a| a.status == status::APPROVED && a.ttl_s >= ttl_s)
        && let (Some(approval_id), Some(by)) = (a.id, a.answered_by)
    {
        let groups = groups_of_member(state, key.tenant_id, by)
            .await
            .map_err(|_| "approver_unread")?;
        return Ok(Next::Use {
            approval_id,
            approver: Approver { id: by, groups },
        });
    }
    if let Some(id) = live
        .iter()
        .find(|a| a.status == status::PENDING)
        .and_then(|a| a.id)
    {
        return Ok(Next::Awaiting(id));
    }
    if let Some(id) = live
        .iter()
        .find(|a| a.status == status::DENIED)
        .and_then(|a| a.id)
    {
        return Ok(Next::Refused(id));
    }
    if !a_driver_could_approve(state, session, ask).await? {
        return Ok(Next::Deny);
    }
    open(state, session, key, rrn, ttl_s, now).await
}

/// `ask`, with `id` (in `groups`) as the person who said yes.
fn with_approver(ask: &Ask, id: ObjectId, groups: Vec<String>) -> Ask {
    let mut ask = ask.clone();
    if let Ask::UseSecret { approver, .. } = &mut ask {
        *approver = Some(Approver { id, groups });
    }
    ask
}

/// Whether one of the session's drivers, each who may answer now, could
/// lift the deny with a yes — the policy decides, with them as the approver.
async fn a_driver_could_approve(
    state: &VaultState,
    session: &AgentSession,
    ask: &Ask,
) -> Result<bool, &'static str> {
    // A set that does not build denies everything, a yes included.
    let Ok((set, _)) = org_set(state, session.tenant_id).await else {
        return Ok(false);
    };
    for driver in session.all_drivers() {
        if !access::may_answer(&state.core, session, driver).await {
            continue;
        }
        let groups = groups_of_member(state, session.tenant_id, driver)
            .await
            .map_err(|_| "approver_unread")?;
        if policy::decide(&set, &with_approver(ask, driver, groups)).allow {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A new card for this very request: its row first, then the card, posted
/// as the session and pushed to its drivers. An ask that opened one a moment
/// earlier wins, and this one waits on theirs.
async fn open(
    state: &VaultState,
    session: &AgentSession,
    key: &ApprovalKey<'_>,
    rrn: &str,
    ttl_s: i64,
    now: DateTime,
) -> Result<Next, &'static str> {
    // A stale card holds the request's one pending place: ended first.
    let stale = state
        .approvals
        .stale_for(key, now)
        .await
        .map_err(|_| "approval_unread")?;
    for a in stale {
        end(state, session, a, status::EXPIRED).await;
    }
    let id = ObjectId::new();
    let row = VaultApproval {
        id: Some(id),
        tenant_id: key.tenant_id,
        session_id: key.session_id,
        fence: key.fence,
        device_id: key.device_id,
        owner_id: session.owner_id,
        secret_id: key.secret_id,
        rrn: rrn.to_string(),
        field: key.field.to_string(),
        mode: key.mode.to_string(),
        audience: key.audience.to_string(),
        ttl_s,
        status: status::PENDING.to_string(),
        requested_at: now,
        expires_at: after(now, lease_limits::APPROVAL_ANSWER_SECS),
        answered_by: None,
        answered_at: None,
        lease_id: None,
        used_at: None,
        room_id: None,
        message_id: None,
    };
    match state.approvals.insert_pending(&row).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            let live = state
                .approvals
                .live_for(key, now)
                .await
                .map_err(|_| "approval_unread")?;
            return live
                .iter()
                .find(|a| a.status == status::PENDING)
                .and_then(|a| a.id)
                .map(Next::Awaiting)
                .ok_or("approval_unread");
        }
        Err(_) => return Err("approval_unrecorded"),
    }
    // Best-effort: the approval stands whether or not its card shows, and
    // the session is told which one it waits on.
    if let Some((room_id, message_id)) = room::post_approval_card(
        &state.core,
        session,
        Binding::new(MODULE, id.to_hex()),
        card_text(&row, &Stage::Pending),
    )
    .await
        && let Err(e) = state.approvals.set_card(id, room_id, message_id).await
    {
        warn!(approval = %id, %e, "vault: an approval's card was not recorded");
    }
    Ok(Next::Awaiting(id))
}

/// A yes a lease just spent: its card says so. Best-effort.
pub(crate) async fn spent(state: &VaultState, session: &AgentSession, id: ObjectId) {
    let Ok(Some(a)) = state.approvals.find_in_tenant(session.tenant_id, id).await else {
        return;
    };
    let name = match a.answered_by {
        Some(by) => name_of(state, by).await,
        None => "a driver".to_string(),
    };
    edit_card(state, session, &a, &Stage::Used { by: &name }).await;
}

/// Where a card stands, as its text says it.
pub(crate) enum Stage<'a> {
    Pending,
    Approved {
        by: &'a str,
    },
    Used {
        by: &'a str,
    },
    Denied {
        by: &'a str,
    },
    /// Unanswered in time — or, with who said yes, unused in time.
    Expired {
        approved_by: Option<&'a str>,
    },
    Withdrawn,
}

/// The card as markdown, which any chat client renders: the secret's
/// handle, the mode, the audience, the TTL, and where it stands. The
/// audience and a name are escaped; the handle and the mode are words the
/// vault checked when they were written.
pub(crate) fn card_text(a: &VaultApproval, stage: &Stage<'_>) -> String {
    let path = a
        .rrn
        .split_once(":secret:")
        .map_or(a.rrn.as_str(), |(_, p)| p);
    let handle = if a.field.is_empty() || a.field == STATIC_FIELD {
        path.to_string()
    } else {
        format!("{path}#{}", a.field)
    };
    let toward = if a.audience.is_empty() {
        String::new()
    } else {
        format!(" toward {}", room::md_escape(&a.audience))
    };
    let what = format!(
        "{} in {} mode{toward}, for up to {}",
        code(&handle),
        code(&a.mode),
        duration(a.ttl_s)
    );
    let by = |name: &str| format!("**{}**", room::md_escape(name));
    match stage {
        Stage::Pending => format!(
            "🔐 **Approval needed** — the session asks to use {what} · a driver answers by {} UTC",
            hhmm(a.expires_at)
        ),
        Stage::Approved { by: name } => {
            format!("🔐 **Approval** — {what} — ✅ approved by {}", by(name))
        }
        Stage::Used { by: name } => {
            format!(
                "🔐 **Approval** — {what} — ✅ approved by {}, and used",
                by(name)
            )
        }
        Stage::Denied { by: name } => {
            format!("🔐 **Approval** — {what} — ⛔ denied by {}", by(name))
        }
        Stage::Expired {
            approved_by: Some(name),
        } => format!(
            "🔐 **Approval** — {what} — ⌛ approved by {}, but not used in time",
            by(name)
        ),
        Stage::Expired { approved_by: None } => {
            format!("🔐 **Approval** — {what} — ⌛ nobody answered in time")
        }
        Stage::Withdrawn => {
            format!("🔐 **Approval** — {what} — ⏹ withdrawn: the session moved or ended")
        }
    }
}

/// A word in a code span, unless a backtick would break out of it.
fn code(word: &str) -> String {
    if word.contains('`') {
        room::md_escape(word)
    } else {
        format!("`{word}`")
    }
}

fn duration(secs: i64) -> String {
    match (secs / 60, secs % 60) {
        (0, s) => format!("{s} s"),
        (m, 0) => format!("{m} min"),
        (m, s) => format!("{m} min {s} s"),
    }
}

/// `HH:MM` of an RFC 3339 time, in UTC.
fn hhmm(t: DateTime) -> String {
    rfc3339(t).get(11..16).unwrap_or_default().to_string()
}

fn after(t: DateTime, secs: u32) -> DateTime {
    DateTime::from_millis(t.timestamp_millis() + i64::from(secs) * 1000)
}

async fn name_of(state: &VaultState, user: ObjectId) -> String {
    state
        .users
        .find_display_names(&[user])
        .await
        .ok()
        .and_then(|m| m.get(&user).cloned())
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| "a driver".to_string())
}

async fn edit_card(
    state: &VaultState,
    session: &AgentSession,
    a: &VaultApproval,
    stage: &Stage<'_>,
) {
    if let (Some(room_id), Some(message_id)) = (a.room_id, a.message_id) {
        room::edit_approval_card(
            &state.core,
            session,
            room_id,
            message_id,
            card_text(a, stage),
        )
        .await;
    }
}

/// Whether the approval's session still runs where, and as, it asked: live,
/// at its fence, on its device.
fn stands(session: &AgentSession, a: &VaultApproval) -> bool {
    leasable(session.status)
        && session.fence == a.fence
        && session.location.device_id == a.device_id
}

/// End an open approval, and say so on its card — once, whichever call
/// wins. The approval as it now is.
async fn end(
    state: &VaultState,
    session: &AgentSession,
    a: VaultApproval,
    why: &str,
) -> VaultApproval {
    let Some(id) = a.id else {
        return a;
    };
    match state.approvals.end(id, why).await {
        Ok(Some(ended)) => {
            let approved_by = match a.answered_by.filter(|_| a.status == status::APPROVED) {
                Some(by) => Some(name_of(state, by).await),
                None => None,
            };
            let stage = if why == status::EXPIRED {
                Stage::Expired {
                    approved_by: approved_by.as_deref(),
                }
            } else {
                Stage::Withdrawn
            };
            edit_card(state, session, &ended, &stage).await;
            ended
        }
        // Another call ended or answered it first: as it is now.
        Ok(None) => state
            .approvals
            .find_in_tenant(a.tenant_id, id)
            .await
            .ok()
            .flatten()
            .unwrap_or(a),
        Err(e) => {
            warn!(approval = %id, %e, "vault: an approval was not ended");
            a
        }
    }
}

/// An open approval nothing can act on any more, ended now: past its
/// deadline (`expired`), or for a session that moved or ended
/// (`withdrawn`).
async fn settle(state: &VaultState, session: &AgentSession, a: VaultApproval) -> VaultApproval {
    if a.status != status::PENDING && a.status != status::APPROVED {
        return a;
    }
    let why = if a.expires_at <= DateTime::now() {
        status::EXPIRED
    } else if !stands(session, &a) {
        status::WITHDRAWN
    } else {
        return a;
    };
    end(state, session, a, why).await
}

/// The approval and its session, for a caller who reads the session; a 404
/// otherwise, like an id that names nothing.
async fn readable(
    state: &VaultState,
    tid: ObjectId,
    raw: &str,
    user: ObjectId,
) -> Result<(VaultApproval, AgentSession), ApiError> {
    let gone = || ApiError::NotFound("Resource not found".to_string());
    let id =
        ObjectId::parse_str(raw).map_err(|_| ApiError::BadRequest("Invalid approval id".into()))?;
    let a = state
        .approvals
        .find_in_tenant(tid, id)
        .await?
        .ok_or_else(gone)?;
    let session = match state.sessions.find_in_tenant(tid, a.session_id).await {
        Ok(s) => s,
        Err(DaoError::NotFound) => return Err(gone()),
        Err(e) => return Err(e.into()),
    };
    if !access::may_read_session(&state.core, &session, user).await {
        return Err(gone());
    }
    Ok((a, session))
}

/// Cedar's `secret:use` for the approval's request as things stand now —
/// the session, the secret and the device as their rows hold them — with
/// `approver` as the person saying yes.
async fn decide_with(
    state: &VaultState,
    session: &AgentSession,
    a: &VaultApproval,
    approver: ObjectId,
) -> Result<Verdict, ApiError> {
    let tid = a.tenant_id;
    let secret = match state.secrets.get_live(tid, a.secret_id).await {
        Ok(s) if !s.disabled => s,
        Ok(_) | Err(DaoError::NotFound) => {
            return Err(ApiError::Conflict(
                "the secret was disabled or deleted since the session asked".into(),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    let agent = match state.agents.find_live_in_tenant(tid, a.device_id).await {
        Ok(agent) => agent,
        Err(DaoError::NotFound) => {
            return Err(ApiError::Conflict(
                "the device was removed since the session asked".into(),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    let device = match DeviceFacts::new(os_name(agent.os), &agent.tags, agent.owner_user_id) {
        Ok(d) => d,
        Err(why) => return Ok(Verdict::deny(format!("device: {why}"))),
    };
    let slug = org_slug(state, tid).await?;
    let ask = use_ask(
        &slug,
        session,
        &secret,
        device,
        &a.mode,
        &a.audience,
        a.ttl_s,
    );
    let groups = groups_of_member(state, tid, approver).await?;
    let ask = with_approver(&ask, approver, groups);
    Ok(match org_set(state, tid).await {
        Ok((set, _)) => policy::decide(&set, &ask),
        Err(why) => Verdict::deny(why),
    })
}

/// Record a person's answer, or a refusal of it. Best-effort: the
/// approval's own row holds who answered and when, and the lease a yes
/// allows is recorded as its own decision.
async fn record(state: &VaultState, a: &VaultApproval, user: ObjectId, allow: bool, reason: &str) {
    let ev = VaultAuditEvent {
        id: None,
        tenant_id: a.tenant_id,
        principal: "user".into(),
        user_id: user,
        action: ACTION_USE.into(),
        op: "approval".into(),
        decision: if allow { "allow" } else { "deny" }.into(),
        reason: reason.into(),
        secret_id: Some(a.secret_id),
        rrn: Some(a.rrn.clone()),
        field: Some(a.field.clone()).filter(|f| !f.is_empty()),
        n: None,
        target: a.id.map(|id| format!("approval:{}", id.to_hex())),
        session_id: Some(a.session_id),
        device_id: Some(a.device_id),
        request: None,
        at: DateTime::now(),
    };
    if let Err(e) = state.audit.record(&ev).await {
        warn!(approval = ?a.id, %e, "vault: an approval's answer was not recorded");
    }
}

/// An approval as an answer shows it: `may_answer` when the caller drives
/// the session now, `may_approve` when the policy would also take their yes.
fn view(a: &VaultApproval, may_answer: bool, may_approve: bool) -> Value {
    json!({
        "id": a.id.map(|i| i.to_hex()),
        "session_id": a.session_id.to_hex(),
        "device_id": a.device_id.to_hex(),
        "secret_id": a.secret_id.to_hex(),
        "rrn": a.rrn,
        "field": a.field,
        "mode": a.mode,
        "audience": a.audience,
        "ttl_s": a.ttl_s,
        "status": a.status,
        "requested_at": rfc3339(a.requested_at),
        "expires_at": rfc3339(a.expires_at),
        "answered_by": a.answered_by.map(|i| i.to_hex()),
        "answered_at": a.answered_at.map(rfc3339),
        "lease_id": a.lease_id.map(|i| i.to_hex()),
        "used_at": a.used_at.map(rfc3339),
        "may_answer": may_answer,
        "may_approve": may_approve,
    })
}

/// `GET /api/tenant/{tenant_id}/vault/approval/{approval_id}` — an approval
/// as the session's readers see it, and whether the caller may answer it —
/// and say yes to it, which the policy decides as an answer's would.
pub async fn get(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path((tenant_id, approval_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let (a, session) = readable(&state, tid, &approval_id, auth.user_id).await?;
    let a = settle(&state, &session, a).await;
    let may = a.status == status::PENDING
        && access::may_answer(&state.core, &session, auth.user_id).await;
    let may_approve = may
        && matches!(
            decide_with(&state, &session, &a, auth.user_id).await,
            Ok(v) if v.allow
        );
    Ok(Json(view(&a, may, may_approve)))
}

#[derive(Debug, Deserialize)]
pub struct AnswerBody {
    pub answer: String,
}

/// `POST /api/tenant/{tenant_id}/vault/approval/{approval_id}`
/// `{answer: "approve" | "deny"}` — a driver's answer. A yes is decided by
/// Cedar with the caller as the approver first: one the policy does not
/// accept is refused, and the card waits on.
pub async fn answer(
    State(state): State<VaultState>,
    auth: AuthUser,
    Path((tenant_id, approval_id)): Path<(String, String)>,
    Json(body): Json<AnswerBody>,
) -> Result<Json<Value>, ApiError> {
    let tid = member_tenant(&state, &tenant_id, &auth).await?;
    let approve = match body.answer.as_str() {
        "approve" => true,
        "deny" => false,
        _ => {
            return Err(ApiError::BadRequest("answer is `approve` or `deny`".into()));
        }
    };
    let (a, session) = readable(&state, tid, &approval_id, auth.user_id).await?;
    let a = settle(&state, &session, a).await;
    let id = a.id.expect("a stored approval has an id");
    match a.status.as_str() {
        status::PENDING => {}
        status::EXPIRED => {
            return Err(ApiError::Conflict(
                "nobody answered this approval in time: the session asks again for a new one"
                    .into(),
            ));
        }
        status::WITHDRAWN => {
            return Err(ApiError::Conflict(
                "the session moved or ended since it asked: this approval is withdrawn".into(),
            ));
        }
        other => {
            return Err(ApiError::Conflict(format!(
                "this approval is {other} already"
            )));
        }
    }
    if !access::may_answer(&state.core, &session, auth.user_id).await {
        record(&state, &a, auth.user_id, false, "not_a_driver").await;
        return Err(ApiError::Forbidden(
            "only the session's drivers answer its approvals".into(),
        ));
    }
    if approve {
        let verdict = decide_with(&state, &session, &a, auth.user_id).await?;
        if !verdict.allow {
            let reason = format!("approver_refused: {}", reason_of(&verdict));
            record(&state, &a, auth.user_id, false, &reason).await;
            return Err(ApiError::Forbidden(
                "the vault's policies do not accept your approval of this use".into(),
            ));
        }
    }
    let Some(answered) = state
        .approvals
        .answer(
            id,
            approve,
            auth.user_id,
            DateTime::now(),
            lease_limits::APPROVAL_USE_SECS,
        )
        .await?
    else {
        return Err(ApiError::Conflict(
            "this approval was answered already, or nobody answered it in time".into(),
        ));
    };
    record(
        &state,
        &answered,
        auth.user_id,
        approve,
        if approve { "approved" } else { "denied" },
    )
    .await;
    let name = name_of(&state, auth.user_id).await;
    let stage = if approve {
        Stage::Approved { by: &name }
    } else {
        Stage::Denied { by: &name }
    };
    edit_card(&state, &session, &answered, &stage).await;
    Ok(Json(view(&answered, false, false)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approval(field: &str, audience: &str, ttl_s: i64) -> VaultApproval {
        let at = DateTime::parse_rfc3339_str("2026-10-19T14:05:00Z").unwrap();
        VaultApproval {
            id: Some(ObjectId::new()),
            tenant_id: ObjectId::new(),
            session_id: ObjectId::new(),
            fence: 1,
            device_id: ObjectId::new(),
            owner_id: ObjectId::new(),
            secret_id: ObjectId::new(),
            rrn: "rrn:grox:secret:db/main".into(),
            field: field.into(),
            mode: "env".into(),
            audience: audience.into(),
            ttl_s,
            status: status::PENDING.into(),
            requested_at: at,
            expires_at: at,
            answered_by: None,
            answered_at: None,
            lease_id: None,
            used_at: None,
            room_id: None,
            message_id: None,
        }
    }

    /// The card names the secret by the handle a session's tools use, the
    /// mode, the audience and the TTL — and when a driver must answer by.
    #[test]
    fn a_card_says_what_was_asked_and_by_when() {
        let text = card_text(&approval("value", "psql", 300), &Stage::Pending);
        assert_eq!(
            text,
            "🔐 **Approval needed** — the session asks to use `db/main` in `env` mode toward psql, for up to 5 min · a driver answers by 14:05 UTC"
        );
        let text = card_text(&approval("login", "", 90), &Stage::Pending);
        assert!(
            text.contains("`db/main#login` in `env` mode, for up to 1 min 30 s"),
            "{text}"
        );
    }

    /// What a session chose — the audience — and a person's name render as
    /// the text they are, never as markdown that changes what the card says.
    #[test]
    fn a_card_escapes_what_it_did_not_check() {
        let text = card_text(
            &approval("value", "[click](https://evil.example)", 300),
            &Stage::Denied { by: "*Mallory*" },
        );
        assert!(!text.contains("[click]("), "{text}");
        assert!(
            text.contains(r"\[click\]\(https://evil\.example\)"),
            "{text}"
        );
        assert!(text.contains(r"⛔ denied by **\*Mallory\***"), "{text}");
    }

    #[test]
    fn a_card_says_how_it_ended() {
        let a = approval("value", "psql", 300);
        for (stage, end) in [
            (Stage::Approved { by: "Ana" }, "✅ approved by **Ana**"),
            (
                Stage::Used { by: "Ana" },
                "✅ approved by **Ana**, and used",
            ),
            (
                Stage::Expired {
                    approved_by: Some("Ana"),
                },
                "⌛ approved by **Ana**, but not used in time",
            ),
            (
                Stage::Expired { approved_by: None },
                "⌛ nobody answered in time",
            ),
            (Stage::Withdrawn, "⏹ withdrawn: the session moved or ended"),
        ] {
            let text = card_text(&a, &stage);
            assert!(text.starts_with("🔐 **Approval** — `db/main`"), "{text}");
            assert!(text.ends_with(end), "{text}");
        }
    }

    #[test]
    fn a_backtick_never_breaks_out_of_a_code_span() {
        assert_eq!(code("db/main"), "`db/main`");
        assert_eq!(code("a`b"), r"a\`b");
    }
}
