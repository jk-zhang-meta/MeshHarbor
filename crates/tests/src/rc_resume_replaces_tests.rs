// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-130 (D5 = A, the operator, 2026-11-11) — what a redial's `replaces`
//! writes to the row of a session that no hub on the redial's pod holds,
//! through real servers and real sockets:
//!
//! * **detached**: the device's socket went, and no pod holds the session. A
//!   viewer the server told so redials only once its peer is gone (the
//!   device's own deadline closed it, or the peer failed during the gap), and
//!   names the session in `replaces`. So the session ended on the device's
//!   side: its row ends `agent_disconnect`, marked inferred
//!   (`end_source: redial`) and dated by the row's own last clock. The
//!   device's claim then hears that reason, and the slot is the person's
//!   again;
//! * **the device's own end replaces it**: a device that ended the session
//!   during the gap (its `rc:ended` lost on the way to the viewer) says so
//!   after its hello, and its reason replaces the inference;
//! * **attached**: the session is held on the device's pod for a viewer whose
//!   own socket dropped. Its redial, on the other pod, ends it
//!   `controller_hangup` as before, and the pod that holds it is told.
//!
//! The controller's own `rc:terminate` of a detached session stays
//! `controller_hangup`
//! (`rc_resume_rejoin_tests::a_controllers_end_during_the_gap_is_enforced_at_the_claim`).

use bson::{Document, oid::ObjectId};
use serde_json::json;

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use crate::rc_resume_claim_tests::{
    QUIET, REMOTE_CONTROL, RESUME, WINDOW, WITHIN, Ws, answer_for, detached, drop_socket,
    end_reason, ended, enroll, give_member, hello, hello_with, next_of, one, open, row, scope_all,
    wait_audit, wait_row,
};
use crate::rc_resume_rejoin_tests::{controller, live_session, request, send, wait_bus};

/// One pod with the window `window`, the org cap kept (one session at a time
/// for the harness's orgs) and counted in cluster-wide slots (FR-115 P3b).
async fn one_slotted(window: u64) -> TestApp {
    TestApp::spawn_with_settings(move |s| {
        s.rc.session_resume_secs = window;
        s.rc.session_slots = true;
    })
    .await
}

/// Two pods over one database with the window `window`, and no org cap: the
/// redial below gets the device's second place, whatever the org's count.
async fn pair_uncapped(window: u64) -> (TestApp, TestApp) {
    TestApp::spawn_pair(move |s| {
        s.rc.session_resume_secs = window;
        s.rc.org_session_cap = false;
    })
    .await
}

/// A live session the device's socket then dropped.
struct Detached {
    /// The viewer's socket, still up.
    ctl: Ws,
    agent_id: ObjectId,
    /// The device's token, for its next hello.
    token: String,
    sid: ObjectId,
    /// The row as the detach left it.
    row: Document,
}

/// Enroll a device that allows one session, take a session to it live as the
/// org's admin, and drop the device's socket: the viewer is told the session
/// is kept, and the row records the detach.
async fn detached_session(app: &TestApp, seeded: &SeededTenant, machine: &str) -> Detached {
    scope_all(app).await;
    let (agent_id, token) = enroll(app, seeded, machine).await;
    let mut agent = hello_with(app, &token, &[RESUME], &[], 1).await;
    next_of(&mut agent, "rc:agent.resume_window", WITHIN)
        .await
        .expect("the window is announced");
    let (mut ctl, sid, created) =
        live_session(app, &seeded.admin.access_token, agent_id, &mut agent).await;
    assert_eq!(created["resume_secs"], WINDOW, "{created}");
    wait_row(app, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    next_of(&mut ctl, "rc:session.detached", WITHIN)
        .await
        .expect("the viewer is told the session is kept");
    let row = wait_row(app, sid, "the row records the detach", detached).await;
    Detached {
        ctl,
        agent_id,
        token,
        sid,
        row,
    }
}

/// AC4, cell (d): nobody claims the session. Its device's socket dropped, and
/// the viewer, told the session is detached, redials once its peer goes (the
/// device's own deadline closed it), naming the session in `replaces`. No pod
/// holds the session, so its row ends `agent_disconnect`, marked
/// `end_source: redial` and dated by its own last clock (the detach, never
/// the redial), and the audit's trail says the same. A `replaces` that names
/// it from another person, or on a request to another device, writes nothing.
/// The device's claim, once it is back, is refused with the row's reason, and
/// the person's next request gets the device and the org's slot.
#[tokio::test]
async fn a_redial_of_a_detached_session_ends_it_as_agent_disconnect_inferred() {
    let app = one_slotted(WINDOW).await;
    let seeded = app.seed_tenant("fr130redial").await;
    let Detached {
        mut ctl,
        agent_id,
        token,
        sid,
        row: before,
    } = detached_session(&app, &seeded, "fr130-redial").await;
    let detached_at = *before.get_datetime("detached_at").unwrap();

    // Another person naming it, and the person naming it on a request to
    // another device: neither is this session's redial.
    give_member(&app, &seeded, "controller", REMOTE_CONTROL).await;
    let mut other = controller(&app, &seeded.member.access_token).await;
    let answer = request(&mut other, agent_id, Some(sid)).await;
    assert_eq!(answer["t"], "rc:error", "{answer}");
    let (other_device, _) = enroll(&app, &seeded, "fr130-redial-other").await;
    let answer = request(&mut ctl, other_device, Some(sid)).await;
    assert_eq!(answer["t"], "rc:error", "{answer}");
    tokio::time::sleep(QUIET).await;
    assert_eq!(
        row(&app, sid).await,
        before,
        "neither names this person and this device"
    );

    // The viewer's redial, its device still away.
    let answer = request(&mut ctl, agent_id, Some(sid)).await;
    assert_eq!(answer["t"], "rc:error", "{answer}");
    assert_eq!(answer["code"], "agent_offline", "{answer}");
    let r = wait_row(&app, sid, "the redial ends the detached session", ended).await;
    assert_eq!(
        end_reason(&r),
        Some("agent_disconnect"),
        "the session ended on its device's side, and nobody hung up: {r}"
    );
    assert_eq!(
        r.get_str("end_source"),
        Ok("redial"),
        "an end nobody saw: {r}"
    );
    assert_eq!(r.get_str("phase"), Ok("closed"), "{r}");
    assert_eq!(
        r.get_datetime("ended_at").unwrap(),
        &detached_at,
        "dated by the row's own last clock, the detach: {r}"
    );
    let events = wait_audit(&app, sid, "session_ended").await;
    let trail = events
        .iter()
        .rev()
        .find(|e| e.get_str("kind") == Ok("session_ended"))
        .unwrap();
    assert_eq!(trail.get_str("reason"), Ok("agent_disconnect"), "{trail}");
    assert_eq!(trail.get_str("end_source"), Ok("redial"), "{trail}");

    // The device comes back claiming it: refused with the row's reason.
    let mut agent = hello_with(&app, &token, &[RESUME], &[sid], 1).await;
    let claim = answer_for(&mut agent, sid, WITHIN)
        .await
        .expect("the claim is answered");
    assert_eq!(claim["t"], "rc:terminate", "{claim}");
    assert_eq!(claim["reason"], "agent_disconnect", "{claim}");

    // The device's place and the org's slot are the person's again.
    let created = request(&mut ctl, agent_id, None).await;
    assert_eq!(
        created["t"], "rc:session.created",
        "no agent_busy and no org_session_limit: {created}"
    );
}

/// AC4, cell (e), with the device's `rc:ended` lost: the person at the device
/// ended the session during the gap, but the frame that says so never
/// reached the viewer, which saw its peer go and redialed, naming the session
/// in `replaces`. The row reads the redial's inference. The device comes back
/// claiming nothing and reports its own end after its hello: its reason
/// replaces the inference, the end is one that was seen (`end_source`
/// cleared), and it keeps its `ended_at`, the detach.
#[tokio::test]
async fn the_devices_own_end_after_its_hello_replaces_a_redials_inferred_end() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130redialhost").await;
    let Detached {
        mut ctl,
        agent_id,
        token,
        sid,
        row: before,
    } = detached_session(&app, &seeded, "fr130-redial-host").await;
    let detached_at = *before.get_datetime("detached_at").unwrap();

    let answer = request(&mut ctl, agent_id, Some(sid)).await;
    assert_eq!(answer["t"], "rc:error", "{answer}");
    wait_row(&app, sid, "the redial ends the detached session", ended).await;

    // Back, claiming nothing: it ended the session itself, and says so.
    let mut agent = hello_with(&app, &token, &[RESUME], &[], 1).await;
    next_of(&mut agent, "rc:agent.resume_window", WITHIN)
        .await
        .expect("the window is announced");
    send(
        &mut agent,
        json!({ "t": "rc:terminate", "session_id": sid.to_hex(), "reason": "host_disconnect" }),
    )
    .await;
    let r = wait_row(
        &app,
        sid,
        "the device's own end replaces the redial's inference",
        |r| end_reason(r) == Some("host_disconnect"),
    )
    .await;
    assert_eq!(r.get_str("phase"), Ok("closed"), "{r}");
    assert!(
        !r.contains_key("end_source"),
        "the device saw the end, so it is no longer inferred: {r}"
    );
    assert_eq!(
        r.get_datetime("ended_at").unwrap(),
        &detached_at,
        "dated by the row's own last clock, the detach: {r}"
    );
}

/// AC9: a session held for a viewer whose own socket dropped is ATTACHED, its
/// device still connected to pod 1. The same person's redial reaches pod 2,
/// where no hub holds the session, and names it in `replaces`: the row ends
/// `controller_hangup`, an end someone asked for (no `end_source`), as before
/// D5, and pod 1, which holds it, ends it there and tells the device.
#[tokio::test]
async fn a_redial_of_an_attached_session_held_on_another_pod_stays_controller_hangup() {
    let (app1, app2) = pair_uncapped(WINDOW).await;
    if !wait_bus(&app1, &app2).await {
        eprintln!("skipping: no Redis available");
        return;
    }
    let seeded = app1.seed_tenant("fr130attached").await;
    scope_all(&app1).await;
    let (agent_id, token) = enroll(&app1, &seeded, "fr130-attached").await;
    let admin = seeded.admin.access_token.clone();
    let mut agent = hello(&app1, &token, &[RESUME], &[]).await;
    next_of(&mut agent, "rc:agent.resume_window", WITHIN)
        .await
        .expect("pod 1 announces the window");
    let (ctl, sid, _) = live_session(&app1, &admin, agent_id, &mut agent).await;
    wait_row(&app1, sid, "the session goes live", open).await;

    // The viewer's socket drops, and pod 1 holds the session for it.
    drop_socket(ctl).await;
    tokio::time::sleep(QUIET).await;
    assert!(
        app1.state.fleet().rc_hub.session_snapshot(sid).is_some(),
        "pod 1 holds the session"
    );
    let r = row(&app1, sid).await;
    assert!(
        open(&r) && !r.contains_key("detached_at"),
        "attached: its device is connected: {r}"
    );

    // Its redial, on pod 2.
    let mut ctl2 = controller(&app2, &admin).await;
    let created = request(&mut ctl2, agent_id, Some(sid)).await;
    assert_eq!(created["t"], "rc:session.created", "{created}");
    let r = wait_row(&app1, sid, "the replaced session ends", ended).await;
    assert_eq!(end_reason(&r), Some("controller_hangup"), "{r}");
    assert!(
        !r.contains_key("end_source"),
        "an end someone asked for: {r}"
    );
    let end = answer_for(&mut agent, sid, WITHIN)
        .await
        .expect("pod 1 ends the session there and tells the device");
    assert_eq!(end["t"], "rc:terminate", "{end}");
    assert_eq!(end["reason"], "controller_hangup", "{end}");
}
