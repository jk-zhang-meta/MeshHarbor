// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-130 — how a resumable session ENDS at the edges the reviews of P1b
//! found, through real servers, real sockets and one MongoDB shared by the
//! pods (`TestApp::spawn_pair`):
//!
//! * a session its viewer was never told it may hold ends at its device's
//!   socket loss, though the device was told a window since (review 2, N3);
//! * a claim refused for a reason of no one's choosing leaves no open row
//!   behind: the gate could not be run, or the window closed between the
//!   claim's read and its commit (N4);
//! * a claim that lost its commit to an older connection's claim of the same
//!   device is tried once more, and the newest connection wins (M4); the
//!   older connection's claim leaves the winner's session and FR-115 slot
//!   alone (L1);
//! * the device's own end replaces an end inferred before this connection,
//!   by an earlier connection's registration or by the sweep, but never the
//!   one-time close's (N5);
//! * a hold nobody rejoins ends marked `hold_expired` (N17), and a rejoin that
//!   comes just after it is told a reason the page redials on (N9);
//! * an end someone asks for never overwrites an inferred one (N11), while at
//!   window 0 a session's end reads on its row as it always has.
//!
//! Two claims racing cannot be ordered through sockets, so those tests hand
//! the claim a row read before the other claim committed
//! (`resume::claim_as_read`), on a connection registered straight in the hub.

use std::time::Duration;

use bson::{DateTime, Document, doc, oid::ObjectId};
use meshharbor_core::cluster::session_slots::SlotScope;
use meshharbor_core::{AgentCtx, AgentResume};
use meshharbor_mod_fleet::hub::ResumeHello;
use meshharbor_mod_remote::RemoteState;
use meshharbor_remote_control::models::{EndReason, OsKind, RemoteSession};
use meshharbor_remote_control::signaling::ServerMsg;
use serde_json::json;
use tokio::sync::mpsc;

use crate::fixtures::test_app::TestApp;
use crate::rc_resume_claim_tests::{
    QUIET, RESUME, WINDOW, WITHIN, Ws, answer_for, attach_seq, detached, drop_socket, end_reason,
    ended, enroll, give_member, go_live, hello, insert, leftover, next_of, now_ms, oid, one, open,
    pair, row, scope, scope_all, tenant_of, wait_audit, wait_row,
};
use crate::rc_resume_rejoin_tests::{
    controller, live_session, rejoin, rejoin_answer, request, send, terminate_route,
};

/// The remote module's state on `app`.
pub(crate) fn remote(app: &TestApp) -> &RemoteState {
    app.state
        .modules
        .remote
        .as_ref()
        .expect("the remote module is mounted")
}

/// The session's row, as a claim reads it.
pub(crate) async fn as_read(app: &TestApp, tenant: ObjectId, sid: ObjectId) -> RemoteSession {
    remote(app)
        .remote_sessions
        .find_in_tenant(tenant, sid)
        .await
        .expect("the row reads")
}

/// A connection of `agent_id` registered straight in `app`'s hub, under the
/// window and claiming back `kept`: its context, as the socket builds it, and
/// what the hub sends the device on it.
pub(crate) fn claiming_connection(
    app: &TestApp,
    agent_id: ObjectId,
    tenant_id: ObjectId,
    owner_user_id: ObjectId,
    kept: Vec<ObjectId>,
) -> (AgentCtx, mpsc::Receiver<ServerMsg>) {
    let window = u32::try_from(WINDOW).unwrap();
    let reg = app.state.fleet().rc_hub.register_agent_resuming(
        agent_id,
        tenant_id,
        owner_user_id,
        OsKind::Linux,
        2,
        true,
        false,
        ResumeHello {
            advertised: true,
            window: Some(window),
            kept,
        },
    );
    let ctx = AgentCtx {
        conn_id: uuid::Uuid::new_v4().to_string(),
        agent_id,
        tenant_id,
        owner_user_id,
        agent_version: "0.4.208".into(),
        os: OsKind::Linux,
        dialed_tid: None,
        conn_established_ms: now_ms(),
        tx: reg.tx.clone(),
        resume: AgentResume {
            window_secs: window,
            claims: reg.claims.clone(),
            registered_at: Some(reg.registered_at),
            reaped: reg.reaped.clone(),
        },
    };
    (ctx, reg.rx)
}

/// The hub's answer to a claim on `sid`, sent on `rx`: the first
/// `rc:session.resumed` or `rc:terminate` naming it.
pub(crate) async fn hub_answer(
    rx: &mut mpsc::Receiver<ServerMsg>,
    sid: ObjectId,
) -> Option<ServerMsg> {
    let deadline = tokio::time::Instant::now() + WITHIN;
    while let Ok(Some(msg)) = tokio::time::timeout_at(deadline, rx.recv()).await {
        match &msg {
            ServerMsg::SessionResumed { session_id } | ServerMsg::Terminate { session_id, .. }
                if *session_id == sid =>
            {
                return Some(msg);
            }
            _ => {}
        }
    }
    None
}

/// The first frame of one of the types `ts` naming `sid` on `ws`.
async fn first_of(ws: &mut Ws, sid: ObjectId, ts: &[&str]) -> Option<serde_json::Value> {
    use futures::StreamExt;
    let deadline = tokio::time::Instant::now() + WITHIN;
    let hex = sid.to_hex();
    while tokio::time::Instant::now() < deadline {
        let Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text)))) =
            tokio::time::timeout(Duration::from_millis(200), ws.next()).await
        else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        if ts.iter().any(|t| v["t"] == *t) && v["session_id"] == hex.as_str() {
            return Some(v);
        }
    }
    None
}

/// The row as a claim that committed first leaves it: the next number, the
/// detach cleared (`RemoteSessionDao::commit_resume`).
async fn commit_elsewhere(app: &TestApp, sid: ObjectId, next: i64) {
    app.db
        .collection::<Document>("remote_sessions")
        .update_one(
            doc! { "_id": sid },
            doc! {
                "$set": { "attach_seq": next },
                "$unset": { "detached_at": "", "resume_by": "" },
            },
        )
        .await
        .unwrap();
}

/// Review 2, N3 — the device enters the scope while a session runs: its
/// connection is told the window by the re-announce on a scope change
/// (P1b-2), but the session's viewer was told no `resume_secs` when it began, so
/// it would ignore `rc:session.detached` and never rejoin, and a rebuilt
/// session would wait a whole window for nobody before it ended. At the
/// device's socket loss the session therefore ends as it always has:
/// `rc:terminate agent_disconnect` to the viewer, and the row ended, never
/// detached.
#[tokio::test]
async fn a_session_its_viewer_was_never_told_it_may_hold_ends_at_the_devices_socket_loss() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130nottold").await;
    // Outside the scope when the session starts.
    scope(&app, &[]).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-nottold").await;
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    assert!(
        next_of(&mut agent, "rc:agent.resume_window", QUIET)
            .await
            .is_none(),
        "no window outside the scope"
    );
    let (mut ctl, sid, created) =
        live_session(&app, &seeded.admin.access_token, agent_id, &mut agent).await;
    assert!(
        created.get("resume_secs").is_none(),
        "its viewer is told it may not hold it: {created}"
    );
    wait_row(&app, sid, "the session goes live", open).await;

    // The device enters the scope mid-session and is told its window by the
    // re-announce, which a scope change runs on every pod: the store read
    // again under the pod's own window (`resume_scope::reconcile`, what the
    // scope's event and the pod's own cadence both run). Not counted: the
    // cadence may be the reading that tells it.
    scope_all(&app).await;
    meshharbor_mod_fleet::resume_scope::reconcile(app.state.fleet()).await;
    let told = next_of(&mut agent, "rc:agent.resume_window", WITHIN)
        .await
        .expect("the device is told the window");
    assert_eq!(told["secs"], WINDOW, "{told}");

    drop_socket(agent).await;
    let first = first_of(&mut ctl, sid, &["rc:terminate", "rc:session.detached"])
        .await
        .expect("the viewer hears of the drop");
    assert_eq!(
        first["t"], "rc:terminate",
        "a session its viewer may not hold is not kept: {first}"
    );
    assert_eq!(first["reason"], "agent_disconnect", "{first}");
    let r = wait_row(&app, sid, "the row ends as today", ended).await;
    assert_eq!(end_reason(&r), Some("agent_disconnect"), "{r}");
    assert!(
        !r.contains_key("detached_at") && !r.contains_key("end_source"),
        "never detached, and an end that was seen: {r}"
    );
    assert!(app.state.fleet().rc_hub.session_snapshot(sid).is_none());
}

/// Review 2, N4 — the claim's gate cannot be run (the controller's member row
/// cannot be read), so the claim decides nothing and the device is told to
/// close the session. The session is over, so its row ends too, rather than
/// staying open while the device stays connected: `agent_disconnect` at its
/// own last clock (the detach), marked `end_source: registration`, as a claim
/// past its window ends.
#[tokio::test]
async fn a_claim_whose_gate_cannot_be_run_ends_the_row_it_refuses() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130gunk").await;
    scope_all(&app).await;
    give_member(
        &app,
        &seeded,
        "controller",
        crate::rc_resume_claim_tests::REMOTE_CONTROL,
    )
    .await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-gunk").await;
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app, &seeded.member.access_token, agent_id, &mut agent).await;
    wait_row(&app, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    let before = wait_row(&app, sid, "the row records the detach", detached).await;
    let detached_at = *before.get_datetime("detached_at").unwrap();

    // The member's row in the org cannot be read: the gate decides nothing.
    let members = app.db.collection::<Document>("tenant_members");
    let filter = doc! { "tenant_id": tenant_of(&seeded), "user_id": oid(&seeded.member.id) };
    members
        .update_one(filter, doc! { "$set": { "role_ids": "unreadable" } })
        .await
        .unwrap();

    let mut agent2 = hello(&app, &token, &[RESUME], &[sid]).await;
    let answer = answer_for(&mut agent2, sid, WITHIN)
        .await
        .expect("the claim is answered");
    assert_eq!(answer["t"], "rc:terminate", "{answer}");
    assert_eq!(answer["reason"], "agent_disconnect", "{answer}");
    let r = wait_row(&app, sid, "the refused claim ends the row", ended).await;
    assert_eq!(end_reason(&r), Some("agent_disconnect"), "{r}");
    assert_eq!(r.get_str("end_source"), Ok("registration"), "{r}");
    assert_eq!(
        r.get_datetime("ended_at").unwrap(),
        &detached_at,
        "dated by the row's own last clock: {r}"
    );
}

/// Review 2, N4 — the window closes between the claim's read and its commit,
/// so the commit matches nothing. The session cannot be resumed by anyone
/// now, and the device is told so: its row ends, `agent_disconnect` at the
/// detach, marked `end_source: registration`.
#[tokio::test]
async fn a_claim_whose_window_closes_before_its_commit_ends_the_row() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130late").await;
    scope_all(&app).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-late").await;
    let tenant = tenant_of(&seeded);
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app, &seeded.admin.access_token, agent_id, &mut agent).await;
    wait_row(&app, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    let before = wait_row(&app, sid, "the row records the detach", detached).await;
    let detached_at = *before.get_datetime("detached_at").unwrap();

    // The claim read the row while its window was open ...
    let read = as_read(&app, tenant, sid).await;
    assert!(read.resume_by.is_some_and(|by| by > DateTime::now()));
    // ... and the window closed before it committed.
    app.db
        .collection::<Document>("remote_sessions")
        .update_one(
            doc! { "_id": sid },
            doc! { "$set": { "resume_by": DateTime::from_millis(now_ms() - 1000) } },
        )
        .await
        .unwrap();

    let (ctx, mut rx) =
        claiming_connection(&app, agent_id, tenant, oid(&seeded.admin.id), vec![sid]);
    meshharbor_mod_remote::resume::claim_as_read(remote(&app), &ctx, sid, read).await;
    let answer = hub_answer(&mut rx, sid)
        .await
        .expect("the claim is answered");
    assert!(
        matches!(
            answer,
            ServerMsg::Terminate {
                reason: EndReason::AgentDisconnect,
                ..
            }
        ),
        "{answer:?}"
    );
    let r = wait_row(&app, sid, "the refused claim ends the row", ended).await;
    assert_eq!(end_reason(&r), Some("agent_disconnect"), "{r}");
    assert_eq!(r.get_str("end_source"), Ok("registration"), "{r}");
    assert_eq!(r.get_datetime("ended_at").unwrap(), &detached_at, "{r}");
}

/// P1b-1's review, M4 — this connection's claim read the row at number 0,
/// and before it committed, an older connection's claim of the same device
/// committed first (0 → 1) and found its connection gone. The commit at 0
/// matches nothing, yet the row is live, names this device and has no window
/// left to close: the claim tries once more at the number the other claim
/// left, and the device's newest connection wins (1 → 2). Before, it was
/// refused with `agent_disconnect` on the LIVE connection, and the device
/// closed a session nobody ended.
#[tokio::test]
async fn a_claim_that_lost_its_commit_to_an_older_connections_claim_is_tried_once_more() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130lost").await;
    scope_all(&app).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-lost").await;
    let tenant = tenant_of(&seeded);
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app, &seeded.admin.access_token, agent_id, &mut agent).await;
    wait_row(&app, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    wait_row(&app, sid, "the row records the detach", detached).await;

    let read = as_read(&app, tenant, sid).await;
    assert_eq!(read.attach_seq, 0);
    commit_elsewhere(&app, sid, 1).await;

    let (ctx, mut rx) =
        claiming_connection(&app, agent_id, tenant, oid(&seeded.admin.id), vec![sid]);
    meshharbor_mod_remote::resume::claim_as_read(remote(&app), &ctx, sid, read).await;
    let answer = hub_answer(&mut rx, sid)
        .await
        .expect("the claim is answered");
    assert!(
        matches!(answer, ServerMsg::SessionResumed { .. }),
        "the newest connection wins: {answer:?}"
    );
    let r = row(&app, sid).await;
    assert!(open(&r), "{r}");
    assert_eq!(
        attach_seq(&r),
        2,
        "committed once more, at the number the other claim left: {r}"
    );
    assert!(app.state.fleet().rc_hub.session_snapshot(sid).is_some());
}

/// P1b-1's review, L1 (and M4's other half) — the device's newest connection
/// claims the session on pod 1 and resumes it at number 1, its FR-115 lease
/// renewed. An older connection's claim of it, on pod 2, read the row at 0
/// and only now commits: it loses, and being an older connection's (the
/// device's presence names pod 1), it neither tries again nor writes, and it
/// leaves the winner's lease alone. Before, its failed commit gave the slot
/// back by the session's id: the winner's.
#[tokio::test]
async fn a_claim_from_an_older_connection_leaves_the_winners_session_and_slot() {
    let (app1, app2) = TestApp::spawn_pair(|s| {
        s.rc.session_resume_secs = WINDOW;
        s.rc.session_slots = true;
    })
    .await;
    let Some(slots) = app1.state.session_slots.clone() else {
        eprintln!("skipping: no Redis available");
        return;
    };
    let seeded = app1.seed_tenant("fr130winner").await;
    scope_all(&app1).await;
    let (agent_id, token) = enroll(&app1, &seeded, "fr130-winner").await;
    let tenant = tenant_of(&seeded);
    let org = SlotScope::Org(tenant);
    let mut agent = hello(&app1, &token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app1, &seeded.admin.access_token, agent_id, &mut agent).await;
    wait_row(&app1, sid, "the session goes live", open).await;
    assert_eq!(slots.held(org).await.unwrap(), 1, "the org's one slot");
    drop_socket(agent).await;
    wait_row(&app1, sid, "the row records the detach", detached).await;

    // The older connection's claim read the row here, at 0.
    let read = as_read(&app1, tenant, sid).await;
    // The newest connection claims it on pod 1, and wins.
    let mut agent2 = hello(&app1, &token, &[RESUME], &[sid]).await;
    let won = answer_for(&mut agent2, sid, WITHIN)
        .await
        .expect("the newest claim is answered");
    assert_eq!(won["t"], "rc:session.resumed", "{won}");
    assert_eq!(attach_seq(&row(&app1, sid).await), 1);
    assert_eq!(slots.held(org).await.unwrap(), 1);

    let (ctx, mut rx) =
        claiming_connection(&app2, agent_id, tenant, oid(&seeded.admin.id), vec![sid]);
    meshharbor_mod_remote::resume::claim_as_read(remote(&app2), &ctx, sid, read).await;
    let answer = hub_answer(&mut rx, sid)
        .await
        .expect("the older claim is answered");
    assert!(
        matches!(
            answer,
            ServerMsg::Terminate {
                reason: EndReason::AgentDisconnect,
                ..
            }
        ),
        "{answer:?}"
    );
    assert_eq!(
        slots.held(org).await.unwrap(),
        1,
        "the winner keeps the org's slot"
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    let r = row(&app1, sid).await;
    assert!(open(&r), "the winner's session goes on: {r}");
    assert_eq!(attach_seq(&r), 1, "at the winner's number: {r}");
    assert!(app1.state.fleet().rc_hub.session_snapshot(sid).is_some());
    assert!(app2.state.fleet().rc_hub.session_snapshot(sid).is_none());
}

/// Review 2, N5 — the person at the device ended two sessions during gaps
/// whose ends the server could only infer: one the sweep ended once the device
/// had been away past the window, one an earlier connection's registration
/// ended before the device could say how it ended. This connection's
/// registration ended neither. The device's own `rc:terminate` for each still
/// replaces the inferred `agent_disconnect`: its reason, `end_source`
/// cleared, `ended_at` the row's own last clock. A seen end, another device's
/// inferred end and the one-time close's `backfill` end are left as they are.
#[tokio::test]
async fn the_devices_own_end_replaces_an_end_inferred_before_this_connection() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130devend").await;
    scope_all(&app).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-devend").await;
    let (other_agent, _) = enroll(&app, &seeded, "fr130-devend-other").await;
    let tenant = tenant_of(&seeded);
    let ctl = oid(&seeded.admin.id);
    let base = now_ms() - 3600 * 1000;
    let at = DateTime::from_millis;
    let inferred = |source: &str, ended_ms: i64| {
        doc! {
            "phase": "closed",
            "ended_at": at(ended_ms),
            "end_reason": "agent_disconnect",
            "end_source": source,
            "detached_at": at(ended_ms),
            "resume_by": at(ended_ms + 60_000),
        }
    };
    let (swept, registered, seen, others, closed) = (
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
    );
    // The one-time close's end, as `close_dead` writes it: at the row's own
    // last clock, marked `backfill`.
    insert(
        &app,
        leftover(
            closed,
            agent_id,
            tenant,
            ctl,
            base,
            doc! {
                "phase": "closed",
                "stats_at": at(base + 120_000),
                "ended_at": at(base + 120_000),
                "end_reason": "agent_disconnect",
                "end_source": "backfill",
            },
        ),
    )
    .await;
    insert(
        &app,
        leftover(
            swept,
            agent_id,
            tenant,
            ctl,
            base,
            inferred("sweep", base + 600_000),
        ),
    )
    .await;
    insert(
        &app,
        leftover(
            registered,
            agent_id,
            tenant,
            ctl,
            base,
            inferred("registration", base + 900_000),
        ),
    )
    .await;
    insert(
        &app,
        leftover(
            seen,
            agent_id,
            tenant,
            ctl,
            base,
            doc! {
                "phase": "closed",
                "ended_at": at(base + 300_000),
                "end_reason": "agent_disconnect",
            },
        ),
    )
    .await;
    insert(
        &app,
        leftover(
            others,
            other_agent,
            tenant,
            ctl,
            base,
            inferred("sweep", base + 600_000),
        ),
    )
    .await;
    let untouched = [
        (seen, row(&app, seen).await),
        (others, row(&app, others).await),
        (closed, row(&app, closed).await),
    ];

    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    next_of(&mut agent, "rc:agent.resume_window", WITHIN)
        .await
        .expect("the window is announced");
    for (sid, reason, limit) in [
        (swept, "host_disconnect", None),
        (registered, "idle_timeout", Some("idle")),
        (seen, "host_disconnect", None),
        (others, "host_disconnect", None),
        (closed, "host_disconnect", None),
    ] {
        let mut msg = json!({ "t": "rc:terminate", "session_id": sid.to_hex(), "reason": reason });
        if let Some(l) = limit {
            msg["limit"] = json!(l);
        }
        send(&mut agent, msg).await;
    }

    for (sid, reason, ended_ms) in [
        (swept, "host_disconnect", base + 600_000),
        (registered, "idle_timeout", base + 900_000),
    ] {
        let r = wait_row(&app, sid, reason, |r| end_reason(r) == Some(reason)).await;
        assert_eq!(r.get_str("phase"), Ok("closed"), "{r}");
        assert!(
            !r.contains_key("end_source"),
            "the device saw the end, so it is no longer inferred: {r}"
        );
        assert_eq!(
            r.get_datetime("ended_at").unwrap().timestamp_millis(),
            ended_ms,
            "the row's own last clock stands: {r}"
        );
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    for (sid, before) in untouched {
        assert_eq!(row(&app, sid).await, before, "left alone: {sid}");
    }
}

/// Review 2, N17 — the device claims its session back and the claim rebuilds
/// it, but its viewer never rejoins. At the window the session ends
/// `controller_hangup`, as the viewer's socket loss ended it before FR-130, and
/// the end is MARKED `limit: hold_expired`, on the device's `rc:terminate` and
/// in the audit: AC7's read counts a resume lost this way with the ones lost
/// to `agent_disconnect`. It is no inferred end: the session's time is real,
/// so the row carries no `end_source`.
#[tokio::test]
async fn a_resume_its_viewer_never_rejoins_ends_marked_hold_expired() {
    // Long enough for the claim to land inside the window the detach wrote.
    const HOLD: u64 = 5;
    let app = one(HOLD).await;
    let seeded = app.seed_tenant("fr130marked").await;
    scope_all(&app).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-marked").await;
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app, &seeded.admin.access_token, agent_id, &mut agent).await;
    wait_row(&app, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    wait_row(&app, sid, "the row records the detach", detached).await;

    let mut agent2 = hello(&app, &token, &[RESUME], &[sid]).await;
    let claim = answer_for(&mut agent2, sid, WITHIN)
        .await
        .expect("the claim is answered");
    assert_eq!(claim["t"], "rc:session.resumed", "{claim}");
    let end = next_of(&mut agent2, "rc:terminate", Duration::from_secs(HOLD + 3))
        .await
        .expect("the resumed session ends at the window");
    assert_eq!(end["reason"], "controller_hangup", "{end}");
    assert_eq!(
        end["limit"], "hold_expired",
        "marked: its viewer never rejoined: {end}"
    );
    let events = wait_audit(&app, sid, "session_ended").await;
    let last = events
        .iter()
        .rev()
        .find(|e| e.get_str("kind") == Ok("session_ended"))
        .unwrap();
    assert_eq!(last.get_str("limit"), Ok("hold_expired"), "{last}");
    let r = wait_row(&app, sid, "the row ends", ended).await;
    assert_eq!(end_reason(&r), Some("controller_hangup"), "{r}");
    assert!(
        !r.contains_key("end_source"),
        "the session's time is real, not inferred: {r}"
    );
}

/// Review 2, N9 — the viewer's socket comes back just after its hold ended:
/// its rejoin finds the row ended `controller_hangup`, which the page reads as
/// its own hangup and never redials. A page that rejoins never hung up, so the
/// answer is a reason it redials on, `agent_disconnect`, as a page before
/// FR-130 redialed after every drop.
#[tokio::test]
async fn a_rejoin_just_after_the_hold_ended_is_told_to_redial() {
    const HOLD: u64 = 3;
    let app = one(HOLD).await;
    let seeded = app.seed_tenant("fr130late-rejoin").await;
    scope_all(&app).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-late-rejoin").await;
    let admin = seeded.admin.access_token.clone();
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let (ctl, sid, created) = live_session(&app, &admin, agent_id, &mut agent).await;
    assert_eq!(created["resume_secs"], HOLD, "{created}");
    drop_socket(ctl).await;

    let end = next_of(&mut agent, "rc:terminate", Duration::from_secs(HOLD + 3))
        .await
        .expect("the hold ends at the window");
    assert_eq!(end["reason"], "controller_hangup", "{end}");
    wait_row(&app, sid, "the row ends", ended).await;

    let mut ctl2 = controller(&app, &admin).await;
    rejoin(&mut ctl2, sid).await;
    let answer = rejoin_answer(&mut ctl2, sid, WITHIN)
        .await
        .expect("the late rejoin is answered");
    assert_eq!(answer["t"], "rc:terminate", "{answer}");
    assert_eq!(
        answer["reason"], "agent_disconnect",
        "a reason the page redials on: {answer}"
    );
}

/// Review 2, N11 — the device came back on pod 2 without the session, while
/// its socket to pod 1 lingers half-open: pod 2's registration read ends the
/// row as inferred. An admin then ends the stale copy pod 1 still holds. An
/// end someone asks for never overwrites an inferred end: the row keeps the
/// end it has, reason, time and mark, rather than a reason and a time from a
/// copy of a session that had already ended.
#[tokio::test]
async fn an_end_someone_asks_for_never_overwrites_an_inferred_one() {
    let (app1, app2) = pair(WINDOW).await;
    let seeded = app1.seed_tenant("fr130firstend").await;
    scope_all(&app1).await;
    let (agent_id, token) = enroll(&app1, &seeded, "fr130-firstend").await;
    let admin = seeded.admin.access_token.clone();
    let mut half_open = hello(&app1, &token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app1, &admin, agent_id, &mut half_open).await;
    wait_row(&app1, sid, "the session goes live", open).await;

    let mut agent2 = hello(&app2, &token, &[RESUME], &[]).await;
    next_of(&mut agent2, "rc:agent.resume_window", WITHIN)
        .await
        .expect("pod 2 announces the window");
    let inferred = wait_row(&app2, sid, "the registration read ends the row", |r| {
        ended(r) && r.get_str("end_source") == Ok("registration")
    })
    .await;
    assert!(
        app1.state.fleet().rc_hub.session_snapshot(sid).is_some(),
        "pod 1 still holds a stale copy"
    );

    let body = terminate_route(&app1, &seeded.tenant_id, sid, &admin).await;
    assert_eq!(body["terminated"], true, "pod 1 ended its copy: {body}");
    tokio::time::sleep(Duration::from_millis(600)).await;
    let r = row(&app1, sid).await;
    for field in ["phase", "ended_at", "end_reason", "end_source"] {
        assert_eq!(
            r.get(field),
            inferred.get(field),
            "{field}: the inferred end stands: {r}"
        );
    }
    drop_socket(half_open).await;
}

/// N11's guard at window 0 — FR-27 audits a device that could raise no prompt
/// as a consent timeout, then ends the session `no_prompt_surface`: two ends
/// of one row, the second the more precise. The row reads `no_prompt_surface`
/// as it always has: an end someone asks for still replaces a SEEN end, and
/// only an inferred one stands against it.
#[tokio::test]
async fn at_window_zero_a_no_prompt_surface_end_reads_so_on_its_row() {
    let app = one(0).await;
    let seeded = app.seed_tenant("fr130nps").await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-nps").await;
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let mut ctl = controller(&app, &seeded.admin.access_token).await;
    let created = request(&mut ctl, agent_id, None).await;
    assert_eq!(created["t"], "rc:session.created", "{created}");
    let sid = oid(created["session_id"].as_str().expect("a session id"));
    next_of(&mut agent, "rc:request", WITHIN)
        .await
        .expect("the device is asked");
    send(
        &mut agent,
        json!({
            "t": "rc:consent",
            "session_id": sid.to_hex(),
            "granted": false,
            "reason": "no_prompt_surface",
        }),
    )
    .await;
    let end = next_of(&mut ctl, "rc:terminate", WITHIN)
        .await
        .expect("the viewer is told");
    assert_eq!(end["reason"], "no_prompt_surface", "{end}");
    wait_row(&app, sid, "the row ends", ended).await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    let r = row(&app, sid).await;
    assert_eq!(
        end_reason(&r),
        Some("no_prompt_surface"),
        "the more precise end stands, as it always has: {r}"
    );
}
