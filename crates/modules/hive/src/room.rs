// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P0d — a session's room: where the org sees it happen.
//!
//! A session is a `Secret` room bound to `{module: "hive", ref: <session id>}`
//! — a non-member gets 404, not proof the session exists. The session itself
//! authors what appears in it: a note when it starts, is refused or ends, and
//! one STUB per turn — who asked, how it stands, how many steps, how long, what
//! it cost — updated in place as the turn finishes. Never what was asked or
//! answered: that streams to a viewer from a replica (P0d-2), and the stub is
//! built from `rc:hive.turn`, whose field set cannot carry it.
//!
//! Everything here is best-effort past the room's creation: a note that fails
//! to post is logged, never a reason to refuse a start or drop a report.

use bson::{DateTime, oid::ObjectId};
use meshharbor_core::Core;
use meshharbor_core::notify::{NotifyParams, PushTo};
use meshharbor_db::models::{Binding, NotificationSource, NotificationType};
use meshharbor_mod_chat::bound::BoundChat;
use meshharbor_remote_control::hive::{HiveApprovalStatus, HiveTurnStatus};
use tracing::{debug, warn};

use crate::HiveState;
use crate::model::{AgentApproval, AgentSession, Promotion, TurnStub};

/// The module id rooms and stubs are bound to.
pub(crate) const MODULE: &str = "hive";

/// The room's path: unique by construction (the session id), so a session
/// named like an existing room cannot collide with it.
pub(crate) fn room_path(session: ObjectId) -> String {
    format!("hive-{}", session.to_hex())
}

/// Open the session's room, with its owner as the only member.
pub(crate) async fn open(
    state: &HiveState,
    tenant_id: ObjectId,
    session: ObjectId,
    title: &str,
    owner: ObjectId,
) -> Result<ObjectId, meshharbor_services::dao::base::DaoError> {
    let room = state
        .chat
        .create_bound_room(
            tenant_id,
            title.to_string(),
            room_path(session),
            owner,
            Binding::new(MODULE, session.to_hex()),
        )
        .await?;
    Ok(room.id.expect("a stored room has an id"))
}

/// Post a note the session authors into its room. Best-effort.
pub(crate) async fn note(state: &HiveState, s: &AgentSession, text: String) {
    let (Some(sid), Some(room)) = (s.id, s.room_id) else {
        return;
    };
    if let Err(e) = state
        .chat
        .post_agent_message(
            s.tenant_id,
            room,
            sid,
            s.author_display(),
            Binding::new(MODULE, sid.to_hex()),
            text,
        )
        .await
    {
        warn!(session = %sid, %e, "hive: a note was not posted to the session's room");
    }
}

/// Post the ended note for a session the CALLER just ended on the server's
/// side. Call it only when the caller's compare-and-set applied, so one end
/// gets one note.
pub(crate) async fn note_ended(state: &HiveState, sid: ObjectId) {
    match state.sessions.find(sid).await {
        Ok(Some(s)) => {
            note(state, &s, ended_note(&s)).await;
            withdraw_approvals(state, &s).await;
        }
        Ok(None) => {}
        Err(e) => warn!(session = %sid, %e, "hive: the ended session was not read for its note"),
    }
}

fn device_label(s: &AgentSession) -> String {
    name_label(&s.location.device_name)
}

/// A device's name as a note shows it: bold and escaped, or "the device"
/// when the record holds none.
pub(crate) fn name_label(name: &str) -> String {
    if name.is_empty() {
        "the device".to_string()
    } else {
        format!("**{}**", md_escape(name))
    }
}

/// FR-90 P2e-3 — "moving": who moves it, where to, and that the primary
/// takes no new prompt meanwhile.
pub(crate) fn moving_note(p: &Promotion, by: &str) -> String {
    format!(
        "🔀 **{}** is moving the session to {} — {} takes no new prompt meanwhile",
        md_escape(by),
        name_label(&p.to_name),
        name_label(&p.from.device_name)
    )
}

/// FR-90 P2f-1 — "teleporting": who moves it, where to, and that the device
/// takes its copy first while the session runs on where it is.
pub(crate) fn teleporting_note(p: &Promotion, by: &str) -> String {
    format!(
        "🔀 **{}** is moving the session to {}, which holds no copy of it yet — {} takes a copy first, and the session runs on {} meanwhile",
        md_escape(by),
        name_label(&p.to_name),
        name_label(&p.to_name),
        name_label(&p.from.device_name)
    )
}

/// FR-90 P2e-6a — the move away from a primary that cannot be reached: the
/// session goes on from the member's copy, and what the primary did after
/// that copy ends is not in it.
pub(crate) fn moving_unreachable_note(p: &Promotion, by: &str) -> String {
    format!(
        "🔀 **{}** is moving the session to {} — {} cannot be reached, so the session goes on from the copy {} holds; anything {} did after that copy ends is not in it",
        md_escape(by),
        name_label(&p.to_name),
        name_label(&p.from.device_name),
        name_label(&p.to_name),
        name_label(&p.from.device_name)
    )
}

/// FR-90 P2e-3 — "moved": from where, to where, by whom, in which folder,
/// and as whom the device says it runs now. `s` is the record after the move.
pub(crate) fn moved_note(s: &AgentSession, p: &Promotion, by: &str) -> String {
    let mut t = format!(
        "🔀 Moved from {} to {} by **{}**, in {}",
        name_label(&p.from.device_name),
        device_label(s),
        md_escape(by),
        md_escape(&s.location.folder)
    );
    if let Some(account) = &s.location.account {
        t.push_str(&format!(" as **{}**", md_escape(account)));
    }
    t
}

/// FR-90 P2k-5 — a device's copy found past where its fence ended: `events`
/// it wrote after the session moved away from it (P2e-6a), which did not
/// carry over. The device sets them aside once it follows the session again.
pub(crate) fn tail_note(device_name: &str, events: i64) -> String {
    if events == 1 {
        format!(
            "↩️ {} holds 1 event it wrote after the session moved on from it — it did not carry over, and stays set aside there",
            name_label(device_name)
        )
    } else {
        format!(
            "↩️ {} holds {events} events it wrote after the session moved on from it — they did not carry over, and stay set aside there",
            name_label(device_name)
        )
    }
}

/// FR-90 P2e-3 — the move did not happen: why, and where the session
/// continues. `why` is composed by the caller, its names already escaped.
pub(crate) fn move_failed_note(p: &Promotion, why: &str) -> String {
    format!(
        "⛔ The move to {} did not happen: {why}. The session continues on {}",
        name_label(&p.to_name),
        name_label(&p.from.device_name)
    )
}

/// "Started" — where, and as whom the device says it runs.
pub(crate) fn started_note(s: &AgentSession) -> String {
    let mut t = format!(
        "▶️ Started on {} in {}",
        device_label(s),
        md_escape(&s.location.folder)
    );
    if let Some(account) = &s.location.account {
        t.push_str(&format!(" as **{}**", md_escape(account)));
    }
    t
}

/// P1j — "Adopted": a terminal session mirrored here, read-only.
pub(crate) fn adopted_note(s: &AgentSession) -> String {
    let mut t = format!(
        "📎 Adopted from a terminal on {} in {}",
        device_label(s),
        md_escape(&s.location.folder)
    );
    if let Some(account) = &s.location.account {
        t.push_str(&format!(" as **{}**", md_escape(account)));
    }
    t.push_str(" — read-only: it runs in the terminal, so nobody drives it from here");
    t
}

/// FR-90 P2f-4b — the owner asked that this terminal session be made a
/// managed one, on the device that adopted it.
pub(crate) fn managing_note(s: &AgentSession, by: &str) -> String {
    format!(
        "🧭 **{}** is making this terminal session a managed one on {}, in {}",
        md_escape(by),
        device_label(s),
        md_escape(&s.location.folder)
    )
}

/// FR-90 P2f-4b — "Made managed": it runs from its terminal's history now,
/// where and as whom the device says.
pub(crate) fn made_managed_note(s: &AgentSession) -> String {
    let mut t = format!(
        "▶️ Made a managed session on {} in {}",
        device_label(s),
        md_escape(&s.location.folder)
    );
    if let Some(account) = &s.location.account {
        t.push_str(&format!(" as **{}**", md_escape(account)));
    }
    t.push_str(" — it goes on from its terminal's conversation, and can be prompted from here");
    t
}

/// FR-90 P2f-4b — the device did not make it a managed one: why, in its
/// words; the session is the adopted one it was.
pub(crate) fn manage_refused_note(s: &AgentSession, word: &str, detail: Option<&str>) -> String {
    let mut t = format!(
        "⛔ {} did not make this terminal session a managed one: {}",
        device_label(s),
        crate::routes::device_refusal_message(word)
    );
    if let Some(detail) = detail {
        t.push_str(&format!(" — {}", md_escape(detail)));
    }
    t.push_str(". It is the adopted session it was");
    t
}

/// FR-90 P2f-3 — "Forked", in the parent's room: who made a fork of it, what
/// it is called and where it runs; the session itself goes on as it was.
pub(crate) fn forked_note(title: &str, device_name: &str, folder: &str, by: &str) -> String {
    format!(
        "🌿 **{}** forked the session into **{}** on {}, in {} — this session goes on as it was",
        md_escape(by),
        md_escape(title),
        name_label(device_name),
        md_escape(folder)
    )
}

/// FR-90 P2f-3 — a fork's room's first note: what it was made from, and by
/// whom. Its earlier turns are that session's, up to the last checkpoint the
/// device's copy held.
pub(crate) fn forked_from_note(parent: &AgentSession, by: &str) -> String {
    format!(
        "🌿 A fork of **{}**, made by **{}**: its earlier turns are that session's, up to the \
         last checkpoint the device held of it",
        md_escape(&parent.title),
        md_escape(by)
    )
}

/// FR-90 P2f-3c — a fork onto a device that holds no copy: the device takes a
/// copy of this session first, and the fork is made there once it has.
pub(crate) fn fork_joining_note(p: &Promotion, by: &str) -> String {
    let title = p.fork.as_ref().map(|f| f.title.as_str()).unwrap_or("");
    format!(
        "🌿 **{}** is forking the session into **{}** on {}, in {} — {} takes a copy of it \
         first; this session goes on as it was",
        md_escape(by),
        md_escape(title),
        name_label(&p.to_name),
        md_escape(&p.folder),
        name_label(&p.to_name)
    )
}

/// FR-90 P2f-3c — a fork onto a device that held no copy did not happen.
pub(crate) fn fork_failed_note(p: &Promotion, why: &str) -> String {
    format!(
        "⛔ The fork onto {} did not happen: {why}. This session goes on as it was",
        name_label(&p.to_name)
    )
}

/// "Refused" — which of the device's gates said no, in plain words.
pub(crate) fn refused_note(s: &AgentSession) -> String {
    let word = s.refusal.as_deref().unwrap_or("other");
    let mut t = format!(
        "⛔ {} refused the session: {}",
        device_label(s),
        crate::routes::device_refusal_message(word)
    );
    if let Some(detail) = &s.detail {
        t.push_str(&format!(" — {}", md_escape(detail)));
    }
    t
}

/// "Ended" — and why, by the record's `end_reason`.
pub(crate) fn ended_note(s: &AgentSession) -> String {
    let why = match s.end_reason.as_deref() {
        Some("stopped") => "stopped",
        Some("exited") => "the agent exited",
        Some("member_removed") => "its starter left the organization",
        Some("device_removed") => "its device was removed",
        Some("tenant_archived") => "the organization was archived",
        Some("hive_not_enabled") => "agent sessions are no longer available to the organization",
        Some("never_answered") => "the device never answered",
        Some("not_on_device") => "its device no longer runs it",
        Some("attribution_changed") => "its terminal's account now names someone else",
        _ => "ended",
    };
    let mut t = format!("⏹ Session ended — {why}");
    if let Some(detail) = &s.detail {
        t.push_str(&format!(": {}", md_escape(detail)));
    }
    t
}

/// What a turn report says, as the stub renders it.
pub(crate) struct TurnReport {
    pub turn: u32,
    pub status: Option<HiveTurnStatus>,
    pub prompted_by: Option<ObjectId>,
    pub steps: u32,
    pub duration_ms: Option<u64>,
    pub cost_usd: Option<f64>,
}

/// Create the turn's stub, or update it when this turn already has one.
/// Reports for a turn OLDER than the newest stubbed one change nothing.
pub(crate) async fn turn_stub(state: &HiveState, s: &AgentSession, r: TurnReport) {
    let (Some(sid), Some(room)) = (s.id, s.room_id) else {
        return;
    };
    // Who asked is the DEVICE's word, like who answered an approval: only a
    // driver's prompt is taken, so a stub never names anyone else (P1c).
    let asked_by = match r.prompted_by {
        Some(uid) if s.drives(uid) => state
            .users
            .find_display_names(&[uid])
            .await
            .ok()
            .and_then(|m| m.get(&uid).cloned()),
        Some(uid) => {
            warn!(session = %sid, by = %uid, "hive: a turn asked by someone who is not a driver — the claim is dropped");
            None
        }
        None => None,
    };
    let text = stub_text(&r, asked_by.as_deref());
    match s.last_turn {
        Some(t) if t.turn == r.turn => {
            match state
                .chat
                .update_agent_message(s.tenant_id, room, t.message_id, text)
                .await
            {
                Ok(true) => {}
                Ok(false) => debug!(session = %sid, turn = r.turn, "hive: the turn's stub is gone"),
                Err(e) => warn!(session = %sid, %e, "hive: a turn stub was not updated"),
            }
        }
        Some(t) if t.turn > r.turn => {
            debug!(session = %sid, turn = r.turn, newest = t.turn, "hive: a report for an older turn");
        }
        _ => {
            let posted = state
                .chat
                .post_agent_message(
                    s.tenant_id,
                    room,
                    sid,
                    s.author_display(),
                    Binding::new(MODULE, format!("{}#{}", sid.to_hex(), r.turn)),
                    text,
                )
                .await;
            match posted {
                Ok(message_id) => {
                    let stub = TurnStub {
                        turn: r.turn,
                        message_id,
                    };
                    if let Err(e) = state.sessions.set_last_turn(sid, stub).await {
                        warn!(session = %sid, %e, "hive: the newest turn was not recorded");
                    }
                }
                Err(e) => warn!(session = %sid, %e, "hive: a turn stub was not posted"),
            }
        }
    }
}

/// FR-90 P1a-2 — what an `rc:hive.approval` says, as its stub uses it.
pub(crate) struct ApprovalReport {
    pub approval_id: String,
    pub turn: Option<u32>,
    pub status: Option<HiveApprovalStatus>,
    pub answered_by: Option<ObjectId>,
}

/// Longest device approval id kept; the device's are 16 hex characters.
const MAX_APPROVAL_ID: usize = 64;

/// An approval opened or ended in `s`: its record in `agent_approvals` and
/// its stub in the room — posted and pushed to the session's drivers when it
/// opens, edited when it ends. Never which tool or what it would do: the
/// frame cannot carry them (AC5).
pub(crate) async fn approval(state: &HiveState, s: &AgentSession, r: ApprovalReport) {
    let (Some(sid), Some(room)) = (s.id, s.room_id) else {
        return;
    };
    let Some(status) = r.status else {
        debug!(session = %sid, "hive: an approval status this build cannot name");
        return;
    };
    let approval_id: String = r
        .approval_id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(MAX_APPROVAL_ID)
        .collect();
    if approval_id.is_empty() {
        return;
    }
    // Only a driver's answer is taken on the device — so a device naming
    // anyone else is not believed, and no stub says that person allowed
    // anything (P1c: the owner, or a driver the owner named).
    let answered_by = r.answered_by.filter(|by| {
        let driver = s.drives(*by);
        if !driver {
            warn!(session = %sid, by = %by, "hive: an approval answered by someone who is not a driver — the claim is dropped");
        }
        driver
    });
    if status == HiveApprovalStatus::Open {
        open_approval(state, s, sid, room, approval_id, r.turn).await;
    } else {
        end_approval(
            state,
            s,
            sid,
            room,
            approval_id,
            r.turn,
            status,
            answered_by,
        )
        .await;
    }
}

async fn open_approval(
    state: &HiveState,
    s: &AgentSession,
    sid: ObjectId,
    room: ObjectId,
    approval_id: String,
    turn: Option<u32>,
) {
    // Nothing opens in a session that is over.
    if s.status.is_terminal() {
        return;
    }
    let record = AgentApproval {
        id: None,
        tenant_id: s.tenant_id,
        session_id: sid,
        device_id: s.location.device_id,
        approval_id: approval_id.clone(),
        turn,
        status: HiveApprovalStatus::Open.as_str().to_string(),
        message_id: None,
        answered_by: None,
        requested_at: DateTime::now(),
        resolved_at: None,
    };
    match state.approvals.insert(&record).await {
        Ok(true) => {}
        Ok(false) => {
            return debug!(session = %sid, %approval_id, "hive: an approval already recorded");
        }
        Err(e) => return warn!(session = %sid, %e, "hive: an approval was not recorded"),
    }
    post_approval_stub(
        state,
        s,
        sid,
        room,
        &approval_id,
        approval_text(HiveApprovalStatus::Open, turn, None),
    )
    .await;
    notify_approval(state, s, sid, room).await;
}

#[allow(clippy::too_many_arguments)]
async fn end_approval(
    state: &HiveState,
    s: &AgentSession,
    sid: ObjectId,
    room: ObjectId,
    approval_id: String,
    turn: Option<u32>,
    status: HiveApprovalStatus,
    answered_by: Option<ObjectId>,
) {
    let name = match answered_by {
        Some(uid) => state
            .users
            .find_display_names(&[uid])
            .await
            .ok()
            .and_then(|m| m.get(&uid).cloned()),
        None => None,
    };
    let ended = state
        .approvals
        .resolve(sid, &approval_id, status, answered_by)
        .await;
    match ended {
        Ok(Some(a)) => {
            let text = approval_text(status, a.turn.or(turn), name.as_deref());
            match a.message_id {
                Some(message_id) => edit_approval_stub(state, s, room, message_id, text).await,
                None => post_approval_stub(state, s, sid, room, &approval_id, text).await,
            }
        }
        // Not open: ended already (a replayed frame) — or its opening never
        // arrived, and then it is recorded, and stubbed, as it ended.
        Ok(None) => match state.approvals.find(sid, &approval_id).await {
            Ok(Some(_)) => {}
            // Never recorded, in a session that is over: it opened after the
            // end, and was refused then — nothing to say now either.
            Ok(None) if s.status.is_terminal() => {}
            Ok(None) => {
                let record = AgentApproval {
                    id: None,
                    tenant_id: s.tenant_id,
                    session_id: sid,
                    device_id: s.location.device_id,
                    approval_id: approval_id.clone(),
                    turn,
                    status: status.as_str().to_string(),
                    message_id: None,
                    answered_by,
                    requested_at: DateTime::now(),
                    resolved_at: Some(DateTime::now()),
                };
                if let Ok(true) = state.approvals.insert(&record).await {
                    let text = approval_text(status, turn, name.as_deref());
                    post_approval_stub(state, s, sid, room, &approval_id, text).await;
                }
            }
            Err(e) => warn!(session = %sid, %e, "hive: an approval was not read"),
        },
        Err(e) => warn!(session = %sid, %e, "hive: an approval's end was not recorded"),
    }
}

async fn post_approval_stub(
    state: &HiveState,
    s: &AgentSession,
    sid: ObjectId,
    room: ObjectId,
    approval_id: &str,
    text: String,
) {
    let posted = state
        .chat
        .post_agent_message(
            s.tenant_id,
            room,
            sid,
            s.author_display(),
            Binding::new(MODULE, format!("{}!{approval_id}", sid.to_hex())),
            text,
        )
        .await;
    match posted {
        Ok(message_id) => {
            if let Err(e) = state
                .approvals
                .set_message(sid, approval_id, message_id)
                .await
            {
                warn!(session = %sid, %e, "hive: an approval's stub was not recorded");
            }
        }
        Err(e) => warn!(session = %sid, %e, "hive: an approval's stub was not posted"),
    }
}

async fn edit_approval_stub(
    state: &HiveState,
    s: &AgentSession,
    room: ObjectId,
    message_id: ObjectId,
    text: String,
) {
    match state
        .chat
        .update_agent_message(s.tenant_id, room, message_id, text)
        .await
    {
        Ok(true) => {}
        Ok(false) => debug!(message = %message_id, "hive: an approval's stub is gone"),
        Err(e) => warn!(message = %message_id, %e, "hive: an approval's stub was not updated"),
    }
}

/// The session is over: whatever it still had open is withdrawn, on the
/// record and in the room. A device that ends a session withdraws its own
/// first; this covers the ends it never heard of.
pub(crate) async fn withdraw_approvals(state: &HiveState, s: &AgentSession) {
    let (Some(sid), Some(room)) = (s.id, s.room_id) else {
        return;
    };
    match state.approvals.withdraw_open(sid).await {
        Ok(ended) => {
            for a in ended {
                if let Some(message_id) = a.message_id {
                    let text = approval_text(HiveApprovalStatus::Withdrawn, a.turn, None);
                    edit_approval_stub(state, s, room, message_id, text).await;
                }
            }
        }
        Err(e) => warn!(session = %sid, %e, "hive: a session's open approvals were not withdrawn"),
    }
}

/// FR-90 P3-4e — an approval card another module keeps in a session's room
/// (the vault's, for a policy that asks for a person's yes): authored by the
/// session, bound to that module's own `{module, ref}`, and pushed to the
/// session's drivers as hive's own approvals are. Its room and message, or
/// `None` when the session has no room or the post failed (logged).
pub async fn post_approval_card(
    core: &Core,
    s: &AgentSession,
    binding: Binding,
    text: String,
) -> Option<(ObjectId, ObjectId)> {
    let (Some(sid), Some(room)) = (s.id, s.room_id) else {
        return None;
    };
    let chat = BoundChat::new(core);
    match chat
        .post_agent_message(s.tenant_id, room, sid, s.author_display(), binding, text)
        .await
    {
        Ok(message_id) => {
            notify_approval_with(core, &chat, s, sid, room).await;
            Some((room, message_id))
        }
        Err(e) => {
            warn!(session = %sid, %e, "hive: another module's approval card was not posted");
            None
        }
    }
}

/// FR-90 P3-4e — the card [`post_approval_card`] posted, as it now stands.
/// Best-effort, like every stub.
pub async fn edit_approval_card(
    core: &Core,
    s: &AgentSession,
    room: ObjectId,
    message_id: ObjectId,
    text: String,
) {
    match BoundChat::new(core)
        .update_agent_message(s.tenant_id, room, message_id, text)
        .await
    {
        Ok(true) => {}
        Ok(false) => debug!(message = %message_id, "hive: another module's approval card is gone"),
        Err(e) => {
            warn!(message = %message_id, %e, "hive: another module's approval card was not updated")
        }
    }
}

/// Tell the session's drivers that it waits for them — each one still in its
/// room (P1c: one who left it answers nothing). By web push too, wherever
/// they are: a desk with the app open is not a phone in a pocket. It names
/// the session, never the call.
async fn notify_approval(state: &HiveState, s: &AgentSession, sid: ObjectId, room: ObjectId) {
    notify_approval_with(&state.core, &state.chat, s, sid, room).await;
}

async fn notify_approval_with(
    core: &Core,
    chat: &BoundChat,
    s: &AgentSession,
    sid: ObjectId,
    room: ObjectId,
) {
    let mut drivers = Vec::new();
    for d in s.all_drivers() {
        if matches!(chat.is_member(s.tenant_id, room, d).await, Ok(true)) {
            drivers.push(d);
        }
    }
    if drivers.is_empty() {
        return;
    }
    let params = NotifyParams {
        tenant_id: s.tenant_id,
        notification_type: NotificationType::ApprovalRequest,
        title: format!("{} needs approval", s.author_display()),
        body: format!("“{}” is waiting for a driver to answer.", s.title),
        link: format!("/tenant/{}/room/{}", s.tenant_id.to_hex(), room.to_hex()),
        source: NotificationSource {
            entity_type: "agent_session".to_string(),
            entity_id: sid,
            actor_id: None,
        },
        ws_type_label: "approval_request",
    };
    meshharbor_core::notify::notify_users(core, &params, &drivers, PushTo::Everyone).await;
}

/// The approval's stub as markdown: THAT the session waits for a driver, and
/// how it ended. Only a word, a number and an escaped display name go in.
pub(crate) fn approval_text(
    status: HiveApprovalStatus,
    turn: Option<u32>,
    by: Option<&str>,
) -> String {
    let at = turn.map(|t| format!(" · turn {t}")).unwrap_or_default();
    let by = by
        .filter(|n| !n.trim().is_empty())
        .map(|n| format!(" by **{}**", md_escape(n)))
        .unwrap_or_default();
    match status {
        HiveApprovalStatus::Open => {
            format!("🔐 **Approval needed**{at} — open the session to answer")
        }
        HiveApprovalStatus::Allowed => format!("🔐 **Approval**{at} — ✅ allowed{by}"),
        HiveApprovalStatus::Denied => format!("🔐 **Approval**{at} — ⛔ denied{by}"),
        HiveApprovalStatus::Expired => {
            format!("🔐 **Approval**{at} — ⌛ nobody answered in time")
        }
        HiveApprovalStatus::Withdrawn => format!("🔐 **Approval**{at} — ⏹ withdrawn"),
    }
}

/// The stub as markdown — what any chat client renders, whether or not it
/// knows Hive. Only numbers and an escaped display name go in.
pub(crate) fn stub_text(r: &TurnReport, asked_by: Option<&str>) -> String {
    let (mark, how) = match r.status {
        Some(HiveTurnStatus::Running) | None => ("⏳", "working…"),
        Some(HiveTurnStatus::Ok) => ("✅", "done"),
        Some(HiveTurnStatus::Error) => ("❌", "ended with an error"),
        Some(HiveTurnStatus::Interrupted) => ("⏹", "interrupted"),
    };
    let mut parts = vec![format!("{mark} **Turn {}** — {how}", r.turn)];
    if r.steps > 0 {
        parts.push(format!(
            "{} step{}",
            r.steps,
            if r.steps == 1 { "" } else { "s" }
        ));
    }
    if let Some(ms) = r.duration_ms {
        parts.push(format_duration(ms));
    }
    if let Some(usd) = r.cost_usd.filter(|c| c.is_finite() && *c >= 0.0) {
        parts.push(format!("${usd:.2}"));
    }
    if let Some(name) = asked_by.filter(|n| !n.trim().is_empty()) {
        parts.push(format!("asked by **{}**", md_escape(name)));
    }
    parts.join(" · ")
}

fn format_duration(ms: u64) -> String {
    let secs = ms / 1000;
    if secs < 60 {
        format!("{secs} s")
    } else if secs < 3600 {
        format!("{} min {} s", secs / 60, secs % 60)
    } else {
        format!("{} h {} min", secs / 3600, (secs % 3600) / 60)
    }
}

/// Escape what markdown would read as syntax, so a display name or a
/// device's words render as the text they are — never as a link, an image or
/// emphasis that changes what the note says. (The renderer's sanitiser is the
/// XSS boundary; this is about the note saying what it means.) Public for
/// the vault's cards (P3-4e), which say what a session asked for.
pub fn md_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            out.push(' ');
            continue;
        }
        if matches!(
            c,
            '\\' | '`'
                | '*'
                | '_'
                | '{'
                | '}'
                | '['
                | ']'
                | '('
                | ')'
                | '#'
                | '+'
                | '-'
                | '.'
                | '!'
                | '|'
                | '<'
                | '>'
                | '~'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-90 P2k-5 — the tail note says how many, in the device's name,
    /// escaped, one and many each in its own words.
    #[test]
    fn the_tail_note_says_how_many_events_did_not_carry_over() {
        assert_eq!(
            tail_note("p2k-u1", 4),
            "↩️ **p2k\\-u1** holds 4 events it wrote after the session moved on from it — they did not carry over, and stay set aside there"
        );
        assert!(
            tail_note("venus", 1).contains("holds 1 event it wrote")
                && tail_note("venus", 1).contains("it did not carry over, and stays"),
            "{}",
            tail_note("venus", 1)
        );
        assert!(tail_note("", 2).starts_with("↩️ the device holds 2 events"));
    }

    fn report(status: Option<HiveTurnStatus>) -> TurnReport {
        TurnReport {
            turn: 3,
            status,
            prompted_by: None,
            steps: 5,
            duration_ms: Some(42_000),
            cost_usd: Some(0.123),
        }
    }

    #[test]
    fn a_stub_says_how_the_turn_stands_and_nothing_it_said() {
        assert_eq!(
            stub_text(&report(Some(HiveTurnStatus::Ok)), Some("Alice")),
            "✅ **Turn 3** — done · 5 steps · 42 s · $0.12 · asked by **Alice**"
        );
        assert_eq!(
            stub_text(&report(Some(HiveTurnStatus::Running)), None),
            "⏳ **Turn 3** — working… · 5 steps · 42 s · $0.12"
        );
        let mut r = report(Some(HiveTurnStatus::Interrupted));
        r.steps = 1;
        r.duration_ms = Some(3_725_000);
        r.cost_usd = Some(f64::NAN);
        assert_eq!(
            stub_text(&r, None),
            "⏹ **Turn 3** — interrupted · 1 step · 1 h 2 min"
        );
    }

    /// A display name is text, not markdown: no link, image or emphasis
    /// survives into the note.
    #[test]
    fn a_name_cannot_inject_markdown() {
        let text = stub_text(
            &report(Some(HiveTurnStatus::Ok)),
            Some("x](javascript:alert(1)) ![img](http://e/x.png) **bold**\nnext"),
        );
        assert!(!text.contains("](java"), "{text}");
        assert!(!text.contains("![img]("), "{text}");
        assert!(!text.contains('\n'), "{text}");
        assert!(text.contains(r"\*\*bold\*\*"), "{text}");
    }

    /// An approval's stub says that the session waits and how it ended —
    /// nothing else can go in: its inputs are a word, a turn number and a
    /// display name, and the name is text, not markdown.
    #[test]
    fn an_approval_stub_says_that_it_waits_and_how_it_ended() {
        use HiveApprovalStatus::*;
        assert_eq!(
            approval_text(Open, Some(2), None),
            "🔐 **Approval needed** · turn 2 — open the session to answer"
        );
        assert_eq!(
            approval_text(Allowed, Some(2), Some("Alice")),
            "🔐 **Approval** · turn 2 — ✅ allowed by **Alice**"
        );
        assert_eq!(
            approval_text(Denied, None, Some("[x](javascript:1)")),
            r"🔐 **Approval** — ⛔ denied by **\[x\]\(javascript:1\)**"
        );
        assert_eq!(
            approval_text(Expired, None, Some("ignored")),
            "🔐 **Approval** — ⌛ nobody answered in time"
        );
        assert_eq!(
            approval_text(Withdrawn, Some(1), None),
            "🔐 **Approval** · turn 1 — ⏹ withdrawn"
        );
    }

    /// FR-90 P2e-3 — a promotion's notes name the devices and the person as
    /// text, never as markdown, and say where the session continues.
    #[test]
    fn a_promotions_notes_say_where_it_goes_and_cannot_inject_markdown() {
        use crate::model::{
            HarnessRef, PromotionState, SessionLocation, SessionOrigin, SessionStatus,
        };
        let now = DateTime::now();
        let from = SessionLocation {
            device_id: ObjectId::new(),
            device_name: "mars".into(),
            folder: "/srv/app".into(),
            account: None,
        };
        let p = Promotion {
            id: ObjectId::new(),
            to: ObjectId::new(),
            to_name: "[venus](javascript:1)".into(),
            to_role: "owner".into(),
            folder: "/home/a/app".into(),
            from: from.clone(),
            from_fence: 1,
            by: ObjectId::new(),
            state: PromotionState::Draining,
            started_at: now,
            deadline: now,
            drained: None,
            unreachable_from: false,
            prior: None,
            teleport: false,
            fork: None,
        };
        let moving = moving_note(&p, "Alice");
        assert_eq!(
            moving,
            r"🔀 **Alice** is moving the session to **\[venus\]\(javascript:1\)** — **mars** takes no new prompt meanwhile"
        );
        // P2e-6a — away from a primary that cannot be reached, the note says
        // what the session goes on from, the names escaped as everywhere.
        assert_eq!(
            moving_unreachable_note(&p, "Alice"),
            r"🔀 **Alice** is moving the session to **\[venus\]\(javascript:1\)** — **mars** cannot be reached, so the session goes on from the copy **\[venus\]\(javascript:1\)** holds; anything **mars** did after that copy ends is not in it"
        );
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
            location: SessionLocation {
                device_id: p.to,
                device_name: "venus".into(),
                folder: "/home/a/app".into(),
                account: Some("alice".into()),
            },
            status: SessionStatus::Idle,
            fence: 2,
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
            replicaset: None,
            promotion: None,
            fences: Vec::new(),
            moved: None,
            parent: None,
            from_terminal: None,
            path_map: Vec::new(),
            purged: None,
        };
        assert_eq!(
            moved_note(&s, &p, "Alice"),
            r"🔀 Moved from **mars** to **venus** by **Alice**, in /home/a/app as **alice**"
        );
        assert_eq!(
            move_failed_note(&p, "its copy did not catch up in time"),
            r"⛔ The move to **\[venus\]\(javascript:1\)** did not happen: its copy did not catch up in time. The session continues on **mars**"
        );
        let nameless = Promotion {
            to_name: String::new(),
            ..p
        };
        assert!(move_failed_note(&nameless, "x").starts_with("⛔ The move to the device"));
    }

    #[test]
    fn the_room_path_is_the_session() {
        let sid = ObjectId::new();
        assert_eq!(room_path(sid), format!("hive-{}", sid.to_hex()));
    }
}
