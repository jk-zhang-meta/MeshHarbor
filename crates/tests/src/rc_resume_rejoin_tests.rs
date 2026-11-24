// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-130 P1b-2 — the viewer's half of the server's resume, through real
//! servers, real sockets and one MongoDB shared by two pods
//! (`TestApp::spawn_pair`):
//!
//! * **the hold**: a viewer told `resume_secs` keeps its session through the
//!   loss of its own socket. The pod that holds the session keeps it with no
//!   controller, tells the device nothing, and writes nothing to the row;
//! * **the rejoin**: `rc:session.rejoin` binds the viewer's new socket to the
//!   session on whichever pod holds it (across pods through the relay), after
//!   the row names this person and the gate a request runs passes again. A
//!   rejoin before the device's claim is answered `rc:session.detached`;
//! * **the slot**: a held session never costs its own viewer the slot. A
//!   redial that names it in `replaces` ends it before the capacity gate, and
//!   so does the same person's request without it; another person's request
//!   is refused busy;
//! * **ends while no pod holds the session**: the controller's own
//!   `rc:terminate` and an admin's end are written to the row, and the
//!   device's claim then enforces them. A device's own end, reported after
//!   its hello, replaces the end the registration read inferred;
//! * **off is today**: with the window at 0 the viewer's side behaves as it
//!   always has, and nothing new is read or written.

use std::time::{Duration, Instant};

use bson::{DateTime, oid::ObjectId};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::fixtures::test_app::TestApp;
use crate::rc_resume_claim_tests::{
    QUIET, REMOTE_CONTROL, RESUME, WINDOW, WITHIN, Ws, answer_for, attach_seq, detached,
    drop_socket, end_reason, ended, enroll, give_member, hello, hello_with, insert, leftover,
    next_of, now_ms, oid, one, open, pair, row, scope_all, tenant_of, urlencode, wait_row,
};

pub(crate) async fn send(ws: &mut Ws, v: Value) {
    ws.send(Message::Text(v.to_string().into()))
        .await
        .expect("a frame is sent");
}

/// One pod with the window `window`, and no org cap: the harness's orgs run
/// one session at a time (FR-115), and these tests are about the DEVICE's
/// capacity, or need more than one session in one org.
async fn one_uncapped(window: u64) -> TestApp {
    TestApp::spawn_with_settings(move |s| {
        s.rc.session_resume_secs = window;
        s.rc.org_session_cap = false;
    })
    .await
}

/// [`one_uncapped`], two pods over one database.
async fn pair_uncapped(window: u64) -> (TestApp, TestApp) {
    TestApp::spawn_pair(move |s| {
        s.rc.session_resume_secs = window;
        s.rc.org_session_cap = false;
    })
    .await
}

/// One pod with the window `window`, the org cap kept (one session at a time
/// for the harness's orgs) and counted in cluster-wide slots (FR-115 P3b),
/// claimed BEFORE the hub's own dispatch. Without Redis the hub counts them.
async fn one_slotted(window: u64) -> TestApp {
    TestApp::spawn_with_settings(move |s| {
        s.rc.session_resume_secs = window;
        s.rc.session_slots = true;
    })
    .await
}

/// A viewer's socket on `app`, past its `connected` greeting.
pub(crate) async fn controller(app: &TestApp, token: &str) -> Ws {
    let url = format!("ws://{}/ws?token={}", app.addr, urlencode(token));
    let (mut ws, _) = connect_async(&url).await.expect("controller ws");
    let _ = tokio::time::timeout(Duration::from_millis(200), ws.next()).await;
    ws
}

/// Ask for a session to `agent_id`, naming `replaces` when it is set: the
/// first `rc:session.created` or `rc:error` the viewer is sent.
pub(crate) async fn request(ctl: &mut Ws, agent_id: ObjectId, replaces: Option<ObjectId>) -> Value {
    let mut msg = json!({
        "t": "rc:session.request",
        "agent_id": agent_id.to_hex(),
        "permissions": "VIEW | INPUT",
    });
    if let Some(old) = replaces {
        msg["replaces"] = json!(old.to_hex());
    }
    send(ctl, msg).await;
    let deadline = tokio::time::Instant::now() + WITHIN;
    while tokio::time::Instant::now() < deadline {
        let Ok(Some(Ok(Message::Text(text)))) =
            tokio::time::timeout(Duration::from_millis(200), ctl.next()).await
        else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if v["t"] == "rc:session.created" || v["t"] == "rc:error" {
            return v;
        }
    }
    panic!("the request was not answered");
}

/// Drive `sid` live the way the two ends do: the device consents (the hub
/// takes it whether or not the device has read its `rc:request` yet), the
/// viewer offers, the device answers.
async fn drive_live(ctl: &mut Ws, agent: &mut Ws, sid: ObjectId) {
    let hex = sid.to_hex();
    send(
        agent,
        json!({ "t": "rc:consent", "session_id": hex, "granted": true }),
    )
    .await;
    next_of(ctl, "rc:ready", WITHIN).await.expect("rc:ready");
    send(
        ctl,
        json!({ "t": "rc:sdp.offer", "session_id": hex, "sdp": "v=0" }),
    )
    .await;
    next_of(agent, "rc:sdp.offer", WITHIN)
        .await
        .expect("the device's offer");
    send(
        agent,
        json!({ "t": "rc:sdp.answer", "session_id": hex, "sdp": "v=0" }),
    )
    .await;
    next_of(ctl, "rc:sdp.answer", WITHIN)
        .await
        .expect("the viewer's answer: the session is live");
}

/// A live session from a new viewer socket of `token`: the socket, the
/// session id and the `rc:session.created` the viewer was sent.
pub(crate) async fn live_session(
    app: &TestApp,
    token: &str,
    agent_id: ObjectId,
    agent: &mut Ws,
) -> (Ws, ObjectId, Value) {
    let mut ctl = controller(app, token).await;
    let created = request(&mut ctl, agent_id, None).await;
    assert_eq!(created["t"], "rc:session.created", "{created}");
    let sid = oid(created["session_id"].as_str().expect("a session id"));
    drive_live(&mut ctl, agent, sid).await;
    (ctl, sid, created)
}

pub(crate) async fn rejoin(ws: &mut Ws, sid: ObjectId) {
    send(
        ws,
        json!({ "t": "rc:session.rejoin", "session_id": sid.to_hex() }),
    )
    .await;
}

/// The answer to a rejoin of `sid`: the first `rc:session.resumed`,
/// `rc:session.detached` or `rc:terminate` naming it, within `within`.
pub(crate) async fn rejoin_answer(ws: &mut Ws, sid: ObjectId, within: Duration) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + within;
    let hex = sid.to_hex();
    while tokio::time::Instant::now() < deadline {
        let Ok(Some(Ok(Message::Text(text)))) =
            tokio::time::timeout(Duration::from_millis(200), ws.next()).await
        else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let t = v["t"].as_str().unwrap_or_default();
        if matches!(
            t,
            "rc:session.resumed" | "rc:session.detached" | "rc:terminate"
        ) && v["session_id"] == hex.as_str()
        {
            return Some(v);
        }
    }
    None
}

/// An ICE candidate from the device for `sid`: it reaches the session's
/// viewer, wherever that viewer's socket is.
async fn device_ice(agent: &mut Ws, sid: ObjectId) {
    send(
        agent,
        json!({
            "t": "rc:ice",
            "session_id": sid.to_hex(),
            "candidate": { "candidate": "candidate:1 1 udp 1 192.0.2.1 9 typ host", "sdpMid": "0" },
        }),
    )
    .await;
}

/// The cross-pod relay needs both pods' bus subscribers up. `false` when the
/// harness has no Redis (the cluster tests skip then too).
pub(crate) async fn wait_bus(a: &TestApp, b: &TestApp) -> bool {
    let (Some(x), Some(y)) = (a.state.cluster_bus.as_ref(), b.state.cluster_bus.as_ref()) else {
        return false;
    };
    for _ in 0..40 {
        if x.sub_alive.load(std::sync::atomic::Ordering::Relaxed)
            && y.sub_alive.load(std::sync::atomic::Ordering::Relaxed)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    true
}

pub(crate) async fn terminate_route(
    app: &TestApp,
    tenant: &str,
    sid: ObjectId,
    token: &str,
) -> Value {
    let resp = app
        .auth_post(
            &format!("/api/tenant/{tenant}/session/{sid}/terminate"),
            token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "the end is taken");
    resp.json().await.unwrap()
}

/// The hold and the rejoin, across pods. A viewer told `resume_secs` loses its
/// own socket while the device's stays up: pod 1 keeps the session with no
/// controller, tells the device nothing and writes nothing. Another person's
/// rejoin of it is answered as for no session of theirs and changes nothing.
/// The viewer comes back on pod 2 and rejoins: the row names it, the gate
/// passes, pod 2 relays the claim to pod 1, and pod 1 binds the new socket
/// and answers `rc:session.resumed`. The device's frames then reach the
/// viewer through pod 2, on the same session at the same number.
#[tokio::test]
async fn a_viewer_whose_socket_drops_rejoins_through_the_other_pod() {
    let (app1, app2) = pair(WINDOW).await;
    if !wait_bus(&app1, &app2).await {
        eprintln!("skipping: no Redis available");
        return;
    }
    let seeded = app1.seed_tenant("fr130rejoin").await;
    scope_all(&app1).await;
    let (agent_id, token) = enroll(&app1, &seeded, "fr130-rejoin").await;
    let mut agent = hello(&app1, &token, &[RESUME], &[]).await;
    next_of(&mut agent, "rc:agent.resume_window", WITHIN)
        .await
        .expect("pod 1 announces the window");
    let (ctl, sid, created) =
        live_session(&app1, &seeded.admin.access_token, agent_id, &mut agent).await;
    assert_eq!(
        created["resume_secs"], WINDOW,
        "the viewer is told the session may be held: {created}"
    );
    wait_row(&app1, sid, "the session goes live", open).await;

    // The viewer's socket drops; the device's stays up.
    drop_socket(ctl).await;
    tokio::time::sleep(QUIET).await;
    assert!(
        app1.state.fleet().rc_hub.session_snapshot(sid).is_some(),
        "pod 1 keeps the session with no controller"
    );
    assert!(
        next_of(&mut agent, "rc:terminate", QUIET).await.is_none(),
        "the device is not told to end it"
    );
    let r = row(&app1, sid).await;
    assert!(
        open(&r) && !r.contains_key("detached_at"),
        "the row is untouched: {r}"
    );

    // Another person's rejoin: answered as for no session of theirs.
    let mut stranger = controller(&app2, &seeded.member.access_token).await;
    rejoin(&mut stranger, sid).await;
    let answer = rejoin_answer(&mut stranger, sid, WITHIN)
        .await
        .expect("another person's rejoin is answered");
    assert_eq!(answer["t"], "rc:terminate", "{answer}");
    assert_eq!(answer["reason"], "agent_disconnect", "{answer}");
    assert!(app1.state.fleet().rc_hub.session_snapshot(sid).is_some());
    assert!(open(&row(&app1, sid).await), "and changes nothing");

    // The viewer comes back on pod 2 and rejoins.
    let mut ctl2 = controller(&app2, &seeded.admin.access_token).await;
    rejoin(&mut ctl2, sid).await;
    let answer = rejoin_answer(&mut ctl2, sid, WITHIN)
        .await
        .expect("the rejoin is answered");
    assert_eq!(answer["t"], "rc:session.resumed", "{answer}");

    // The session is the viewer's again, through pod 2.
    device_ice(&mut agent, sid).await;
    let ice = next_of(&mut ctl2, "rc:ice", WITHIN)
        .await
        .expect("the device's ICE reaches the rejoined viewer");
    assert_eq!(ice["session_id"], sid.to_hex().as_str(), "{ice}");
    let r = row(&app1, sid).await;
    assert!(open(&r), "the same session, still open: {r}");
    assert_eq!(
        attach_seq(&r),
        0,
        "a viewer's rejoin commits no number: {r}"
    );
}

/// A roll takes both sockets. The device's goes first: pod 1 detaches the
/// session and tells the viewer. Then the viewer's goes. The viewer is back
/// first, on pod 2, before the device: its rejoin is answered
/// `rc:session.detached` with the row's `resume_by`. The device then claims
/// the session on pod 2, which rebuilds it with no controller, and the
/// viewer's next rejoin is answered `rc:session.resumed` there. The device's
/// frames reach the viewer, and the row is the same one, resumed once.
#[tokio::test]
async fn a_roll_takes_both_sockets_and_the_viewer_rejoins_once_the_device_has_claimed() {
    let (app1, app2) = pair(WINDOW).await;
    let seeded = app1.seed_tenant("fr130roll").await;
    scope_all(&app1).await;
    let (agent_id, token) = enroll(&app1, &seeded, "fr130-roll").await;
    let mut agent = hello(&app1, &token, &[RESUME], &[]).await;
    let (mut ctl, sid, created) =
        live_session(&app1, &seeded.admin.access_token, agent_id, &mut agent).await;
    assert_eq!(created["resume_secs"], WINDOW, "{created}");
    wait_row(&app1, sid, "the session goes live", open).await;

    drop_socket(agent).await;
    let told = next_of(&mut ctl, "rc:session.detached", WITHIN)
        .await
        .expect("the viewer is told the session is kept");
    let resume_by = told["resume_by"].as_i64().expect("resume_by, unix ms");
    drop_socket(ctl).await;
    wait_row(&app1, sid, "the row records the detach", detached).await;

    // The viewer is back first.
    let mut ctl2 = controller(&app2, &seeded.admin.access_token).await;
    rejoin(&mut ctl2, sid).await;
    let answer = rejoin_answer(&mut ctl2, sid, WITHIN)
        .await
        .expect("a rejoin before the device's claim is answered");
    assert_eq!(answer["t"], "rc:session.detached", "{answer}");
    assert_eq!(
        answer["resume_by"].as_i64(),
        Some(resume_by),
        "the row's resume_by: {answer}"
    );

    // The device claims it on pod 2.
    let mut agent2 = hello(&app2, &token, &[RESUME], &[sid]).await;
    let claim = answer_for(&mut agent2, sid, WITHIN)
        .await
        .expect("the claim is answered");
    assert_eq!(claim["t"], "rc:session.resumed", "{claim}");

    // The viewer asks again: the session is its own once more.
    rejoin(&mut ctl2, sid).await;
    let answer = rejoin_answer(&mut ctl2, sid, WITHIN)
        .await
        .expect("the second rejoin is answered");
    assert_eq!(answer["t"], "rc:session.resumed", "{answer}");
    device_ice(&mut agent2, sid).await;
    next_of(&mut ctl2, "rc:ice", WITHIN)
        .await
        .expect("the device's ICE reaches the viewer");
    let r = row(&app2, sid).await;
    assert!(open(&r), "{r}");
    assert_eq!(attach_seq(&r), 1, "resumed once, by the device: {r}");
}

/// AC9 — a held session never costs its own viewer the slot, on a device that
/// allows one session. Its viewer's socket drops and the session is held:
/// another person's request is refused busy, and the held session stands. The
/// same person's redial, naming the session in `replaces`, ends it as
/// `controller_hangup` before the capacity gate and gets the device. Then
/// the new session is held the same way, and the same person's request
/// WITHOUT `replaces` (a page too old to send it, or the person's other tab)
/// reaps it as today and gets the device too.
#[tokio::test]
async fn a_held_session_never_costs_its_own_viewer_the_slot() {
    let app = one_uncapped(WINDOW).await;
    let seeded = app.seed_tenant("fr130slot").await;
    scope_all(&app).await;
    give_member(&app, &seeded, "controller", REMOTE_CONTROL).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-slot").await;
    let admin = seeded.admin.access_token.clone();
    let mut agent = hello_with(&app, &token, &[RESUME], &[], 1).await;
    next_of(&mut agent, "rc:agent.resume_window", WITHIN)
        .await
        .expect("the window is announced");

    // With `replaces`.
    let (ctl, held, _) = live_session(&app, &admin, agent_id, &mut agent).await;
    drop_socket(ctl).await;
    tokio::time::sleep(QUIET).await;
    let mut other = controller(&app, &seeded.member.access_token).await;
    let refused = request(&mut other, agent_id, None).await;
    assert_eq!(refused["t"], "rc:error", "{refused}");
    assert_eq!(refused["code"], "agent_busy", "{refused}");
    assert!(
        app.state.fleet().rc_hub.session_snapshot(held).is_some(),
        "another person's request spares the held session"
    );
    let mut ctl = controller(&app, &admin).await;
    let created = request(&mut ctl, agent_id, Some(held)).await;
    assert_eq!(
        created["t"], "rc:session.created",
        "its own redial gets the device, no agent_busy: {created}"
    );
    let next = oid(created["session_id"].as_str().unwrap());
    assert_ne!(next, held);
    let end = next_of(&mut agent, "rc:terminate", WITHIN)
        .await
        .expect("the device is told the replaced session ended");
    assert_eq!(end["session_id"], held.to_hex().as_str(), "{end}");
    assert_eq!(end["reason"], "controller_hangup", "{end}");
    let r = wait_row(&app, held, "the replaced session ends", ended).await;
    assert_eq!(end_reason(&r), Some("controller_hangup"), "{r}");
    assert!(
        !r.contains_key("end_source"),
        "an end someone asked for: {r}"
    );

    // Without `replaces`.
    drive_live(&mut ctl, &mut agent, next).await;
    drop_socket(ctl).await;
    tokio::time::sleep(QUIET).await;
    assert!(
        app.state.fleet().rc_hub.session_snapshot(next).is_some(),
        "held"
    );
    let mut ctl = controller(&app, &admin).await;
    let created = request(&mut ctl, agent_id, None).await;
    assert_eq!(
        created["t"], "rc:session.created",
        "the same person's request gets the device: {created}"
    );
    let r = wait_row(&app, next, "the held session is reaped", ended).await;
    assert_eq!(end_reason(&r), Some("controller_hangup"), "{r}");
}

/// AC9 — and never the org's slot either. The harness's orgs run one session
/// at a time (FR-115), counted in cluster-wide slots that the request claims
/// BEFORE the hub's own dispatch. A held session keeps the org's slot against
/// another person, whose request is refused `org_session_limit`. Its own
/// person's redial gets the device both with `replaces` and without it: the
/// held session ends, and its slot is given back, before the slot is claimed.
#[tokio::test]
async fn a_held_session_never_costs_its_own_viewer_the_orgs_slot() {
    let app = one_slotted(WINDOW).await;
    let seeded = app.seed_tenant("fr130orgslot").await;
    scope_all(&app).await;
    give_member(&app, &seeded, "controller", REMOTE_CONTROL).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-orgslot").await;
    let admin = seeded.admin.access_token.clone();
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    next_of(&mut agent, "rc:agent.resume_window", WITHIN)
        .await
        .expect("the window is announced");

    let (ctl, held, _) = live_session(&app, &admin, agent_id, &mut agent).await;
    drop_socket(ctl).await;
    tokio::time::sleep(QUIET).await;
    let mut other = controller(&app, &seeded.member.access_token).await;
    let refused = request(&mut other, agent_id, None).await;
    assert_eq!(refused["t"], "rc:error", "{refused}");
    assert_eq!(refused["code"], "org_session_limit", "{refused}");
    assert!(app.state.fleet().rc_hub.session_snapshot(held).is_some());

    // With `replaces`.
    let mut ctl = controller(&app, &admin).await;
    let created = request(&mut ctl, agent_id, Some(held)).await;
    assert_eq!(
        created["t"], "rc:session.created",
        "its own redial gets the org's slot: {created}"
    );
    let next = oid(created["session_id"].as_str().unwrap());
    let r = wait_row(&app, held, "the replaced session ends", ended).await;
    assert_eq!(end_reason(&r), Some("controller_hangup"), "{r}");

    // Without `replaces`.
    drive_live(&mut ctl, &mut agent, next).await;
    drop_socket(ctl).await;
    tokio::time::sleep(QUIET).await;
    let mut ctl = controller(&app, &admin).await;
    let created = request(&mut ctl, agent_id, None).await;
    assert_eq!(
        created["t"], "rc:session.created",
        "the same person's request gets the org's slot: {created}"
    );
    let r = wait_row(&app, next, "the held session is reaped", ended).await;
    assert_eq!(end_reason(&r), Some("controller_hangup"), "{r}");
}

/// P1b-1's review, C1 — a session a device's claim rebuilt waits for its
/// viewer with NO controller, and another person's request to the device
/// spares it: on a device that allows two sessions the request gets the
/// second place, and on one that allows one it is refused busy. Before
/// P1b-2 the orphan reap read a missing controller as a dead one and ended
/// the resumed session at the next request to its device.
#[tokio::test]
async fn a_resumed_session_is_spared_against_another_persons_request() {
    let (app1, app2) = pair_uncapped(WINDOW).await;
    let seeded = app1.seed_tenant("fr130spare").await;
    scope_all(&app1).await;
    give_member(&app1, &seeded, "controller", REMOTE_CONTROL).await;
    for max in [2u8, 1] {
        let (agent_id, token) = enroll(&app1, &seeded, &format!("fr130-spare-{max}")).await;
        let mut agent = hello_with(&app1, &token, &[RESUME], &[], max).await;
        let (_ctl, sid, _) =
            live_session(&app1, &seeded.admin.access_token, agent_id, &mut agent).await;
        wait_row(&app1, sid, "the session goes live", open).await;
        drop_socket(agent).await;
        wait_row(&app1, sid, "the row records the detach", detached).await;
        let mut agent2 = hello_with(&app2, &token, &[RESUME], &[sid], max).await;
        let claim = answer_for(&mut agent2, sid, WITHIN)
            .await
            .expect("the claim is answered");
        assert_eq!(claim["t"], "rc:session.resumed", "{max}: {claim}");

        let mut other = controller(&app2, &seeded.member.access_token).await;
        let answer = request(&mut other, agent_id, None).await;
        if max == 1 {
            assert_eq!(answer["code"], "agent_busy", "{max}: {answer}");
        } else {
            assert_eq!(answer["t"], "rc:session.created", "{max}: {answer}");
        }
        assert!(
            answer_for(&mut agent2, sid, QUIET).await.is_none(),
            "{max}: the device is not told to end the resumed session"
        );
        assert!(
            app2.state.fleet().rc_hub.session_snapshot(sid).is_some(),
            "{max}: the resumed session stands"
        );
        assert!(open(&row(&app2, sid).await), "{max}: its row stays open");
    }
}

/// AC4 — the controller's own end, issued while no pod holds the session, is
/// written to the row (conditional on the row naming that person: another
/// person's end of it writes nothing), and the device's claim on the other
/// pod then refuses the session with that reason within 5 s.
#[tokio::test]
async fn a_controllers_end_during_the_gap_is_enforced_at_the_claim() {
    let (app1, app2) = pair(WINDOW).await;
    let seeded = app1.seed_tenant("fr130ctlend").await;
    scope_all(&app1).await;
    let (agent_id, token) = enroll(&app1, &seeded, "fr130-ctlend").await;
    let mut agent = hello(&app1, &token, &[RESUME], &[]).await;
    let (mut ctl, sid, _) =
        live_session(&app1, &seeded.admin.access_token, agent_id, &mut agent).await;
    wait_row(&app1, sid, "the session goes live", open).await;

    drop_socket(agent).await;
    next_of(&mut ctl, "rc:session.detached", WITHIN)
        .await
        .expect("the viewer is told the session is kept");
    let before = wait_row(&app1, sid, "the row records the detach", detached).await;

    // Another person's end of it writes nothing.
    let mut stranger = controller(&app2, &seeded.member.access_token).await;
    send(
        &mut stranger,
        json!({ "t": "rc:terminate", "session_id": sid.to_hex(), "reason": "controller_hangup" }),
    )
    .await;
    tokio::time::sleep(QUIET).await;
    assert_eq!(row(&app1, sid).await, before, "the row names someone else");

    // The controller's own end, on pod 1, which no longer holds the session.
    send(
        &mut ctl,
        json!({ "t": "rc:terminate", "session_id": sid.to_hex(), "reason": "controller_hangup" }),
    )
    .await;
    let r = wait_row(
        &app1,
        sid,
        "the controller's end is written to the row",
        ended,
    )
    .await;
    assert_eq!(end_reason(&r), Some("controller_hangup"), "{r}");
    assert!(
        !r.contains_key("end_source"),
        "an end someone asked for: {r}"
    );

    let claimed_at = Instant::now();
    let mut agent2 = hello(&app2, &token, &[RESUME], &[sid]).await;
    let answer = answer_for(&mut agent2, sid, WITHIN)
        .await
        .expect("the claim is answered");
    assert!(claimed_at.elapsed() < WITHIN, "AC4: within 5 s");
    assert_eq!(answer["t"], "rc:terminate", "{answer}");
    assert_eq!(answer["reason"], "controller_hangup", "{answer}");
    assert!(app2.state.fleet().rc_hub.session_snapshot(sid).is_none());
}

/// AC4 — the person at the device ends a session during the gap, and another
/// reaches its idle limit there. The device comes back on pod 2 claiming
/// neither, so the registration read ends both as an inferred
/// `agent_disconnect`. The device's own `rc:terminate` for each, sent after
/// its hello, then REPLACES the inferred reason: `host_disconnect` and
/// `idle_timeout`. Each is now an end that was seen, so its `end_source` is
/// cleared, and it keeps its `ended_at` at the row's own last clock, the
/// detach: the frame carries no time. A third session an admin ended during
/// the gap keeps the admin's end, whatever the device then says.
#[tokio::test]
async fn a_device_reported_end_after_its_hello_replaces_the_inferred_one() {
    // Three sessions of one org: no org cap.
    let (app1, app2) = pair_uncapped(WINDOW).await;
    let seeded = app1.seed_tenant("fr130hostend").await;
    scope_all(&app1).await;
    let (agent_id, token) = enroll(&app1, &seeded, "fr130-hostend").await;
    let admin = seeded.admin.access_token.clone();
    let mut agent = hello_with(&app1, &token, &[RESUME], &[], 3).await;
    let (_c1, by_host, _) = live_session(&app1, &admin, agent_id, &mut agent).await;
    let (_c2, by_idle, _) = live_session(&app1, &admin, agent_id, &mut agent).await;
    let (_c3, by_admin, _) = live_session(&app1, &admin, agent_id, &mut agent).await;
    for sid in [by_host, by_idle, by_admin] {
        wait_row(&app1, sid, "the session goes live", open).await;
    }

    drop_socket(agent).await;
    let mut detached_at = Vec::new();
    for sid in [by_host, by_idle, by_admin] {
        let r = wait_row(&app1, sid, "the row records the detach", detached).await;
        detached_at.push(*r.get_datetime("detached_at").unwrap());
    }

    // An admin ends the third during the gap, on pod 2.
    terminate_route(&app2, &seeded.tenant_id, by_admin, &admin).await;
    let admins = wait_row(&app2, by_admin, "the admin's end", ended).await;
    assert_eq!(end_reason(&admins), Some("admin_terminated"), "{admins}");

    // Back on pod 2, claiming none of them, and reporting its own ends.
    let mut agent2 = hello_with(&app2, &token, &[RESUME], &[], 3).await;
    next_of(&mut agent2, "rc:agent.resume_window", WITHIN)
        .await
        .expect("the window is announced");
    for (sid, reason, limit) in [
        (by_host, "host_disconnect", None),
        (by_idle, "idle_timeout", Some("idle")),
        (by_admin, "host_disconnect", None),
    ] {
        let mut msg = json!({ "t": "rc:terminate", "session_id": sid.to_hex(), "reason": reason });
        if let Some(l) = limit {
            msg["limit"] = json!(l);
        }
        send(&mut agent2, msg).await;
    }

    for (sid, reason, at) in [
        (by_host, "host_disconnect", detached_at[0]),
        (by_idle, "idle_timeout", detached_at[1]),
    ] {
        let r = wait_row(&app2, sid, reason, |r| {
            ended(r) && end_reason(r) == Some(reason)
        })
        .await;
        assert_eq!(r.get_str("phase"), Ok("closed"), "{r}");
        assert!(
            !r.contains_key("end_source"),
            "the device saw the end, so it is no longer inferred: {r}"
        );
        assert_eq!(
            r.get_datetime("ended_at").unwrap(),
            &at,
            "dated by the row's own last clock, the detach: {r}"
        );
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    let r = row(&app2, by_admin).await;
    assert_eq!(r, admins, "the admin's end stands whatever the device says");
}

/// AC4 — the rejoin re-runs the gate a request runs. A member controls the
/// device, their socket drops and the session is held. The member is removed
/// from the org meanwhile. Their rejoin is refused `admin_terminated`, the
/// session ends with that reason, and the device is told.
#[tokio::test]
async fn a_viewer_removed_from_the_org_is_refused_at_its_rejoin() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130vgate").await;
    scope_all(&app).await;
    give_member(&app, &seeded, "controller", REMOTE_CONTROL).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-vgate").await;
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let (ctl, sid, _) = live_session(&app, &seeded.member.access_token, agent_id, &mut agent).await;
    drop_socket(ctl).await;
    tokio::time::sleep(QUIET).await;
    assert!(
        app.state.fleet().rc_hub.session_snapshot(sid).is_some(),
        "held"
    );

    let resp = app
        .auth_delete(
            &format!(
                "/api/tenant/{}/member/{}",
                seeded.tenant_id, seeded.member.id
            ),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "the member is removed");

    let mut ctl = controller(&app, &seeded.member.access_token).await;
    rejoin(&mut ctl, sid).await;
    let answer = rejoin_answer(&mut ctl, sid, WITHIN)
        .await
        .expect("the rejoin is answered");
    assert_eq!(answer["t"], "rc:terminate", "{answer}");
    assert_eq!(answer["reason"], "admin_terminated", "{answer}");
    let end = next_of(&mut agent, "rc:terminate", WITHIN)
        .await
        .expect("the device is told");
    assert_eq!(end["reason"], "admin_terminated", "{end}");
    assert!(app.state.fleet().rc_hub.session_snapshot(sid).is_none());
    let r = wait_row(&app, sid, "the session ends", ended).await;
    assert_eq!(end_reason(&r), Some("admin_terminated"), "{r}");
}

/// Each rejoin gets one answer that names its session, even when the gate
/// cannot be run: the page asks again only after `rc:session.detached`. The
/// member's row in the org cannot be read (a document the server cannot
/// decode), so the rejoin of the held session is answered
/// `rc:session.detached` with when the hold ends, the same deadline at every
/// ask; nothing is bound or ended, and the device is told nothing. Once the
/// row reads again, the next rejoin resumes the session.
#[tokio::test]
async fn a_rejoin_the_gate_cannot_decide_is_told_to_ask_again() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130vunk").await;
    scope_all(&app).await;
    give_member(&app, &seeded, "controller", REMOTE_CONTROL).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-vunk").await;
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let member = seeded.member.access_token.clone();
    let (ctl, sid, _) = live_session(&app, &member, agent_id, &mut agent).await;
    let dropped_at = now_ms();
    drop_socket(ctl).await;
    tokio::time::sleep(QUIET).await;
    assert!(
        app.state.fleet().rc_hub.session_snapshot(sid).is_some(),
        "held"
    );

    let mut ctl = controller(&app, &member).await;
    let members = app.db.collection::<bson::Document>("tenant_members");
    let filter = bson::doc! { "tenant_id": tenant_of(&seeded), "user_id": oid(&seeded.member.id) };
    let kept = members
        .find_one(filter.clone())
        .await
        .unwrap()
        .expect("the member's row");
    members
        .update_one(
            filter.clone(),
            bson::doc! { "$set": { "role_ids": "unreadable" } },
        )
        .await
        .unwrap();

    let mut told = Vec::new();
    for _ in 0..2 {
        rejoin(&mut ctl, sid).await;
        let answer = rejoin_answer(&mut ctl, sid, WITHIN)
            .await
            .expect("the rejoin is answered");
        assert_eq!(answer["t"], "rc:session.detached", "{answer}");
        told.push(answer["resume_by"].as_i64().expect("a resume_by"));
    }
    assert_eq!(told[0], told[1], "the same deadline at every ask");
    let window_ms = i64::try_from(WINDOW).unwrap() * 1000;
    assert!(
        (dropped_at + window_ms - 1000..=now_ms() + window_ms).contains(&told[0]),
        "the hold's own deadline: {told:?}"
    );
    assert!(
        app.state.fleet().rc_hub.session_snapshot(sid).is_some(),
        "nothing ends it"
    );
    assert!(
        next_of(&mut agent, "rc:terminate", QUIET).await.is_none(),
        "the device is told nothing"
    );

    members.replace_one(filter, kept).await.unwrap();
    rejoin(&mut ctl, sid).await;
    let answer = rejoin_answer(&mut ctl, sid, WITHIN)
        .await
        .expect("the rejoin is answered");
    assert_eq!(answer["t"], "rc:session.resumed", "{answer}");
    device_ice(&mut agent, sid).await;
    assert!(
        next_of(&mut ctl, "rc:ice", WITHIN).await.is_some(),
        "the device's frames reach the rejoined socket"
    );
}

/// Off is today. With the window at 0, the default, a session is never
/// called resumable (`rc:session.created` carries no `resume_secs`), the
/// viewer's socket loss ends it as `controller_hangup` at once with the device
/// told, a rejoin is dropped unanswered as a server before FR-130 drops it,
/// and none of the new ends touches a row no hub holds: the controller's own
/// `rc:terminate`, a redial's `replaces` and an admin's end all leave a row a
/// dead pod left open exactly as it was.
#[tokio::test]
async fn with_the_window_at_zero_the_viewers_side_is_as_today() {
    let app = one(0).await;
    let seeded = app.seed_tenant("fr130vzero").await;
    scope_all(&app).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-vzero").await;
    let admin = seeded.admin.access_token.clone();
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let (ctl, sid, created) = live_session(&app, &admin, agent_id, &mut agent).await;
    assert!(
        created.get("resume_secs").is_none(),
        "never held at 0: {created}"
    );

    drop_socket(ctl).await;
    let end = next_of(&mut agent, "rc:terminate", WITHIN)
        .await
        .expect("the device is told, as today");
    assert_eq!(end["reason"], "controller_hangup", "{end}");
    let r = wait_row(&app, sid, "the session ends as today", ended).await;
    assert_eq!(end_reason(&r), Some("controller_hangup"), "{r}");

    let mut ctl = controller(&app, &admin).await;
    rejoin(&mut ctl, sid).await;
    assert!(
        rejoin_answer(&mut ctl, sid, QUIET).await.is_none(),
        "a rejoin is dropped unanswered at 0"
    );

    // A row a dead pod left open, two hours old, naming this viewer.
    let dead = ObjectId::new();
    let started = now_ms() - 2 * 3600 * 1000;
    insert(
        &app,
        leftover(
            dead,
            agent_id,
            tenant_of(&seeded),
            oid(&seeded.admin.id),
            started,
            bson::doc! { "stats_at": DateTime::from_millis(started + 600_000) },
        ),
    )
    .await;
    let before = row(&app, dead).await;
    send(
        &mut ctl,
        json!({ "t": "rc:terminate", "session_id": dead.to_hex(), "reason": "controller_hangup" }),
    )
    .await;
    let created = request(&mut ctl, agent_id, Some(dead)).await;
    assert_eq!(created["t"], "rc:session.created", "{created}");
    let body = terminate_route(&app, &seeded.tenant_id, dead, &admin).await;
    assert_ne!(body["row_ended"], json!(true), "{body}");
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        row(&app, dead).await,
        before,
        "nothing new writes a row at 0"
    );
}
