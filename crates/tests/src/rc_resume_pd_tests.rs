// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-130 — the server's resume at the edges the P1b reviews deferred to
//! "PR D", through real servers, real sockets and one MongoDB shared by the
//! pods (`TestApp::spawn_pair`):
//!
//! * a detached session keeps its FR-115 slot against a request on its own
//!   pod, whose stale-lease check reads the row first (M5), and at window 0
//!   that check is what it always was;
//! * a claim that loses its commit never renews or retags the winner's lease
//!   (`refuse_claim`'s race);
//! * a claim whose connection was displaced after its commit writes the
//!   detach back, so the row is not left open with no pod and no deadline
//!   (L2);
//! * a detached session's lease lives until `resume_by` plus 10 s, and no
//!   longer (L5);
//! * an external session is marked on its row while its device holds a
//!   window, and a claim of a marked row is refused (L6, D3);
//! * an admin's end during the gap that cannot be written answers 503, not
//!   200 (N10);
//! * the rejoin of a detached session runs the gate at most once per 5 s for
//!   its viewer (N14).
//!
//! And the edges PR D's own review found:
//!
//! * a lease this pod holds for a session no hub holds is kept only while
//!   the row can still be resumed: past `resume_by` plus the 10 s grace, or
//!   live with no `resume_by` on a device outside the resume scope, it is
//!   dropped as before FR-130 (MEDIUM 1, LOW 4);
//! * the lease's expiry only grows: a renewal, a claim, a restore and a keep
//!   never shorten a kept lease, and a keep never revives a lapsed one
//!   (LOW 5, LOW 7, and the renewal's test gap);
//! * a resumed session whose slot another session took during the gap ends,
//!   fenced at the number its claim committed (a test gap);
//! * a viewer removed from the org during the gap is refused within about
//!   5 s on a detached row, and the rate's entry goes once the session is
//!   bound (a test gap, LOW 8).

use std::sync::atomic::Ordering;
use std::time::Duration;

use bson::{DateTime, Document, doc, oid::ObjectId};
use meshharbor_core::cluster::session_slots::{Lease, SlotClaim, SlotScope};
use meshharbor_mod_fleet::hub::{OrgPolicy, ResumeHello};
use meshharbor_remote_control::models::{ConsentMode, OsKind};
use meshharbor_remote_control::permissions::Permissions;
use meshharbor_remote_control::signaling::{ExternalGrant, ServerMsg};
use meshharbor_services::dao::rc_resume_scope::ResumeScopeKind;
use redis::aio::ConnectionManager;
use tokio::sync::mpsc;

use crate::fixtures::test_app::TestApp;
use crate::rc_resume_claim_tests::{
    REMOTE_CONTROL, RESUME, WINDOW, WITHIN, answer_for, attach_seq, detached, drop_socket,
    end_reason, ended, enroll, give_member, go_live, hello, insert, leftover, now_ms, oid, one,
    open, row, scope, scope_all, tenant_of, wait_row,
};
use crate::rc_resume_ends_tests::{as_read, claiming_connection, hub_answer, remote};
use crate::rc_resume_rejoin_tests::{controller, live_session, rejoin, rejoin_answer, request};

/// One pod with the window `window` and the org's sessions counted in
/// cluster-wide slots (FR-115 P3b): the harness's orgs run one at a time.
async fn one_slotted(window: u64) -> TestApp {
    TestApp::spawn_with_settings(move |s| {
        s.rc.session_resume_secs = window;
        s.rc.session_slots = true;
    })
    .await
}

/// The row's `resume_by`, in ms.
fn resume_by_ms(r: &Document) -> i64 {
    r.get_datetime("resume_by")
        .expect("a resume_by")
        .timestamp_millis()
}

/// `sid`'s score in the payer's set `set` (its lease's expiry, ms), when the
/// set holds it.
async fn score(conn: &mut ConnectionManager, set: &str, sid: ObjectId) -> Option<i64> {
    let s: Option<String> = redis::cmd("ZSCORE")
        .arg(set)
        .arg(sid.to_hex())
        .query_async(conn)
        .await
        .unwrap();
    s.and_then(|s| s.parse::<f64>().ok()).map(|f| f as i64)
}

/// A key's time to live, in ms (-2: no key, -1: no expiry).
async fn pttl(conn: &mut ConnectionManager, key: &str) -> i64 {
    redis::cmd("PTTL").arg(key).query_async(conn).await.unwrap()
}

/// The holder hash of `sid`'s lease.
fn holder_key(app: &TestApp, sid: ObjectId) -> String {
    format!("meshharbor:rc:slot:{}:{}", app.db.name(), sid.to_hex())
}

/// Review 1, M5 — the org runs one session at a time. Its session on device
/// A is detached when A's socket drops, and the same pod is then asked for a
/// session to device B. The pod claimed A's lease and its hub no longer holds
/// the session, so FR-115's stale-lease check called it stale, dropped it and
/// gave the slot to B, and A's claim then found the org full and ended the
/// session. The row says the session may still be resumed: B is refused
/// `org_session_limit`, and A's claim resumes it on the slot it kept.
#[tokio::test]
async fn a_detached_sessions_slot_is_kept_against_a_request_on_its_own_pod() {
    let app = one_slotted(WINDOW).await;
    let Some(slots) = app.state.session_slots.clone() else {
        eprintln!("skipping: no Redis available");
        return;
    };
    let seeded = app.seed_tenant("fr130pdm5").await;
    scope_all(&app).await;
    let org = SlotScope::Org(tenant_of(&seeded));
    let (a_id, a_token) = enroll(&app, &seeded, "fr130-pd-m5a").await;
    let (b_id, b_token) = enroll(&app, &seeded, "fr130-pd-m5b").await;
    let admin = seeded.admin.access_token.clone();
    let mut a = hello(&app, &a_token, &[RESUME], &[]).await;
    let _b = hello(&app, &b_token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app, &admin, a_id, &mut a).await;
    wait_row(&app, sid, "the session goes live", open).await;
    assert_eq!(slots.held(org).await.unwrap(), 1, "the org's one slot");
    drop_socket(a).await;
    wait_row(&app, sid, "the row records the detach", detached).await;

    let mut ctl = controller(&app, &admin).await;
    let refused = request(&mut ctl, b_id, None).await;
    assert_eq!(
        refused["t"], "rc:error",
        "the detached session keeps the org's slot: {refused}"
    );
    assert_eq!(refused["code"], "org_session_limit", "{refused}");

    let mut a2 = hello(&app, &a_token, &[RESUME], &[sid]).await;
    let answer = answer_for(&mut a2, sid, WITHIN)
        .await
        .expect("the claim is answered");
    assert_eq!(
        answer["t"], "rc:session.resumed",
        "resumed on its own slot: {answer}"
    );
    assert_eq!(slots.held(org).await.unwrap(), 1);
}

/// Review 1, M5's guard — at window 0 the stale-lease check is FR-115's,
/// with no read: a lease this pod claimed for a session its hub does not
/// hold is dropped, even when that session's row reads detached (above 0,
/// the M5 test keeps exactly that lease).
#[tokio::test]
async fn at_window_zero_the_stale_lease_check_reads_no_row() {
    let app = one_slotted(0).await;
    let Some(slots) = app.state.session_slots.clone() else {
        eprintln!("skipping: no Redis available");
        return;
    };
    let seeded = app.seed_tenant("fr130pdm5z").await;
    let tenant = tenant_of(&seeded);
    let org = SlotScope::Org(tenant);
    let (agent_id, token) = enroll(&app, &seeded, "fr130-pd-m5z").await;
    let _agent = hello(&app, &token, &[RESUME], &[]).await;
    let admin_id = oid(&seeded.admin.id);

    let stale = ObjectId::new();
    let claimed = slots
        .claim(org, stale, admin_id, agent_id, 1, &app.state.pod.pod_id)
        .await
        .unwrap();
    assert_eq!(claimed, SlotClaim::Claimed, "the org's one slot");
    let now = now_ms();
    insert(
        &app,
        leftover(
            stale,
            agent_id,
            tenant,
            admin_id,
            now - 60_000,
            doc! {
                "detached_at": DateTime::from_millis(now - 1_000),
                "resume_by": DateTime::from_millis(now + 59_000),
            },
        ),
    )
    .await;

    let mut ctl = controller(&app, &seeded.admin.access_token).await;
    let created = request(&mut ctl, agent_id, None).await;
    assert_eq!(
        created["t"], "rc:session.created",
        "the stale lease is dropped as it always was: {created}"
    );
}

/// `refuse_claim`'s race (PR C, deferred) — the device's newest connection
/// claims the session on pod 1 and resumes it there. An older connection's
/// claim of it, on pod 2, read the row before that commit and loses its own.
/// It must leave the winner's lease as the winner left it: before, it took
/// the slot BEFORE its commit, which renewed the lease and wrote pod 2 into
/// it, so pod 2 could later read the winner's live lease as its own stale one.
#[tokio::test]
async fn a_claim_that_loses_its_commit_never_retags_the_winners_lease() {
    let (app1, app2) = TestApp::spawn_pair(|s| {
        s.rc.session_resume_secs = WINDOW;
        s.rc.session_slots = true;
    })
    .await;
    let Some(slots) = app1.state.session_slots.clone() else {
        eprintln!("skipping: no Redis available");
        return;
    };
    let seeded = app1.seed_tenant("fr130pdrace").await;
    scope_all(&app1).await;
    let (agent_id, token) = enroll(&app1, &seeded, "fr130-pd-race").await;
    let tenant = tenant_of(&seeded);
    let org = SlotScope::Org(tenant);
    let mut agent = hello(&app1, &token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app1, &seeded.admin.access_token, agent_id, &mut agent).await;
    wait_row(&app1, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    wait_row(&app1, sid, "the row records the detach", detached).await;

    // The older connection's claim read the row here, at 0.
    let read = as_read(&app1, tenant, sid).await;
    let mut agent2 = hello(&app1, &token, &[RESUME], &[sid]).await;
    let won = answer_for(&mut agent2, sid, WITHIN)
        .await
        .expect("the newest claim is answered");
    assert_eq!(won["t"], "rc:session.resumed", "{won}");

    let (ctx, mut rx) =
        claiming_connection(&app2, agent_id, tenant, oid(&seeded.admin.id), vec![sid]);
    meshharbor_mod_remote::resume::claim_as_read(remote(&app2), &ctx, sid, read).await;
    let lost = hub_answer(&mut rx, sid)
        .await
        .expect("the older claim is answered");
    assert!(matches!(lost, ServerMsg::Terminate { .. }), "{lost:?}");

    match slots
        .claim(
            org,
            ObjectId::new(),
            ObjectId::new(),
            ObjectId::new(),
            1,
            "fr130-pd-probe",
        )
        .await
        .unwrap()
    {
        SlotClaim::Full(holders) => {
            assert_eq!(holders.len(), 1, "{holders:?}");
            assert_eq!(holders[0].session, sid.to_hex(), "{holders:?}");
            assert_eq!(
                holders[0].pod, app1.state.pod.pod_id,
                "the lease names the pod that holds the session: {holders:?}"
            );
        }
        other => panic!("the org's one slot is the winner's: {other:?}"),
    }
}

/// Review 1, L2 — a claim commits, and its connection is displaced before
/// the hub rebuilds the session: the claim is no longer its to answer. The
/// commit cleared the row's deadline, so the row was left open at the new
/// number with no pod holding it and no `resume_by` for the sweep. The claim
/// now writes the detach back, fenced at the number it committed: the row
/// reads detached again, and the newer connection's claim resumes it.
#[tokio::test]
async fn a_claim_whose_connection_is_gone_after_its_commit_writes_the_detach_back() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130pdl2").await;
    scope_all(&app).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-pd-l2").await;
    let tenant = tenant_of(&seeded);
    let owner = oid(&seeded.admin.id);
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app, &seeded.admin.access_token, agent_id, &mut agent).await;
    wait_row(&app, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    wait_row(&app, sid, "the row records the detach", detached).await;

    let (ctx1, _rx1) = claiming_connection(&app, agent_id, tenant, owner, vec![sid]);
    // A newer connection of the device displaces the first one.
    let (ctx2, mut rx2) = claiming_connection(&app, agent_id, tenant, owner, vec![sid]);
    let before = now_ms();
    let read = as_read(&app, tenant, sid).await;
    meshharbor_mod_remote::resume::claim_as_read(remote(&app), &ctx1, sid, read).await;
    let r = wait_row(&app, sid, "the lost claim writes the detach back", detached).await;
    assert_eq!(attach_seq(&r), 1, "fenced at the number it committed: {r}");
    assert!(resume_by_ms(&r) > before, "a deadline ahead: {r}");
    assert!(app.state.fleet().rc_hub.session_snapshot(sid).is_none());

    let read = as_read(&app, tenant, sid).await;
    meshharbor_mod_remote::resume::claim_as_read(remote(&app), &ctx2, sid, read).await;
    let answer = hub_answer(&mut rx2, sid)
        .await
        .expect("the newer claim is answered");
    assert!(
        matches!(answer, ServerMsg::SessionResumed { .. }),
        "{answer:?}"
    );
    let r = wait_row(&app, sid, "resumed at the next number", |r| {
        open(r) && attach_seq(r) == 2
    })
    .await;
    assert!(r.get("resume_by").is_none(), "{r}");
}

/// Review 1, L5 — the lease a session holds lives 90 s and is renewed every
/// 30 s by the pod that holds the session, so at a detach it has 60 to 90 s
/// left: less than a 120 s window. The detach now keeps it until `resume_by`
/// plus 10 s, in Redis, where no pod has to renew it (the pod that detached it
/// may be the one a roll takes down), and no longer: a session nobody claims
/// gives its slot back 10 s after its deadline.
#[tokio::test]
async fn a_detached_sessions_lease_lives_until_its_deadline_and_no_longer() {
    let app = one_slotted(120).await;
    let (Some(slots), Some(redis)) = (
        app.state.session_slots.clone(),
        app.state.redis_pubsub.clone(),
    ) else {
        eprintln!("skipping: no Redis available");
        return;
    };
    let seeded = app.seed_tenant("fr130pdl5").await;
    scope_all(&app).await;
    let org = SlotScope::Org(tenant_of(&seeded));
    let (agent_id, token) = enroll(&app, &seeded, "fr130-pd-l5").await;
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app, &seeded.admin.access_token, agent_id, &mut agent).await;
    wait_row(&app, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    let r = wait_row(&app, sid, "the row records the detach", detached).await;
    let keep_until = resume_by_ms(&r) + 10_000;

    let set = slots.slots_key(org);
    let holder = format!("meshharbor:rc:slot:{}:{}", app.db.name(), sid.to_hex());
    let mut conn = redis.connection();
    let deadline = tokio::time::Instant::now() + WITHIN;
    let score = loop {
        let score: Option<String> = redis::cmd("ZSCORE")
            .arg(&set)
            .arg(sid.to_hex())
            .query_async(&mut conn)
            .await
            .unwrap();
        let score = score.and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0) as i64;
        if score >= keep_until - 1_000 || tokio::time::Instant::now() >= deadline {
            break score;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(
        (keep_until - 1_000..=keep_until + 1_000).contains(&score),
        "the lease is kept until resume_by + 10 s ({keep_until}), not {score}"
    );
    let left = keep_until - now_ms();
    for key in [&set, &holder] {
        let pttl: i64 = redis::cmd("PTTL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(
            (left - 2_000..=left + 1_000).contains(&pttl),
            "{key} expires with the lease ({left} ms), not in {pttl} ms"
        );
    }
}

/// Review 1, L6 (D3) — a device never keeps an external session, so a claim
/// of a row marked external is refused `agent_disconnect` and the row ended,
/// whatever the gate says. Before, the row carried no marker, the claim made
/// no D3 check, and the session came back as an ordinary one that an FR-52
/// revocation would miss.
#[tokio::test]
async fn a_claim_of_an_external_session_is_refused() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130pdl6").await;
    scope_all(&app).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-pd-l6").await;
    let sid = ObjectId::new();
    let now = now_ms();
    insert(
        &app,
        leftover(
            sid,
            agent_id,
            tenant_of(&seeded),
            oid(&seeded.admin.id),
            now - 60_000,
            doc! {
                "external": true,
                "detached_at": DateTime::from_millis(now - 1_000),
                "resume_by": DateTime::from_millis(now + 59_000),
            },
        ),
    )
    .await;

    let mut agent = hello(&app, &token, &[RESUME], &[sid]).await;
    let answer = answer_for(&mut agent, sid, WITHIN)
        .await
        .expect("the claim is answered");
    assert_eq!(answer["t"], "rc:terminate", "{answer}");
    assert_eq!(answer["reason"], "agent_disconnect", "{answer}");
    let r = wait_row(&app, sid, "the row ends", ended).await;
    assert_eq!(end_reason(&r), Some("agent_disconnect"), "{r}");
    assert!(app.state.fleet().rc_hub.session_snapshot(sid).is_none());
}

/// Review 1, L6 — what marks the row: an external session (FR-52's door)
/// created while its device's connection holds a window is marked
/// `external: true` on its row; one created while it holds none writes the
/// row it always wrote, with no marker.
#[tokio::test]
async fn an_external_session_is_marked_on_its_row_only_under_a_window() {
    let app = one(WINDOW).await;
    let hub = &app.state.fleet().rc_hub;
    let mut kept = Vec::new();
    for (window, marked) in [(Some(60), true), (None, false)] {
        let (agent_id, tenant_id) = (ObjectId::new(), ObjectId::new());
        let reg = hub.register_agent_resuming(
            agent_id,
            tenant_id,
            ObjectId::new(),
            OsKind::Linux,
            2,
            true,
            false,
            ResumeHello {
                advertised: true,
                window,
                kept: Vec::new(),
            },
        );
        let (tx, rx) = mpsc::channel(32);
        let sid = hub
            .create_session_full(
                agent_id,
                ObjectId::new(),
                "An Outsider".into(),
                tx,
                Permissions::VIEW,
                Vec::new(),
                None,
                None,
                None,
                false,
                ConsentMode::Prompt,
                None,
                None,
                false,
                None,
                None,
                false,
                OrgPolicy::Unavailable,
                None,
                None,
                None,
                Some(ExternalGrant {
                    attempt_id: "fr130-pd-attempt".into(),
                }),
                None,
                None,
            )
            .expect("the external session is created");
        let r = wait_row(&app, sid, "the row is written", |r| !r.is_empty()).await;
        if marked {
            assert_eq!(
                r.get_bool("external"),
                Ok(true),
                "marked under a window: {r}"
            );
        } else {
            assert!(r.get("external").is_none(), "no marker without one: {r}");
        }
        kept.push((reg, rx));
    }
}

/// Review 2, N10 — an admin ends a detached session, and the write to its row
/// fails (a validator stands in for the database refusing it). The device's
/// claim would then resume a session the admin was told was ended: the route
/// answers 503, never 200.
#[tokio::test]
async fn an_admins_end_that_cannot_be_written_answers_503() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130pdn10").await;
    scope_all(&app).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-pd-n10").await;
    let admin = seeded.admin.access_token.clone();
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app, &admin, agent_id, &mut agent).await;
    wait_row(&app, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    wait_row(&app, sid, "the row records the detach", detached).await;

    app.db
        .run_command(doc! {
            "collMod": "remote_sessions",
            "validator": { "end_reason": { "$ne": "admin_terminated" } },
        })
        .await
        .expect("the fault is in place");
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/session/{sid}/terminate", seeded.tenant_id),
            &admin,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        503,
        "an end that was not written is not taken"
    );
    assert!(open(&row(&app, sid).await), "the row is as it was");
}

/// Review 2, N14 — the viewer of a detached session asks again every second
/// until the device claims it, and each ask ran the whole gate (about five
/// reads). Nothing is bound or relayed while the row is detached, so the
/// gate now runs at most once per 5 s for the viewer: five asks inside that
/// run it once, and every ask is still answered with the session's deadline.
#[tokio::test]
async fn a_detached_sessions_rejoins_run_the_gate_once_per_five_seconds() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130pdn14").await;
    scope_all(&app).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-pd-n14").await;
    let admin = seeded.admin.access_token.clone();
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app, &admin, agent_id, &mut agent).await;
    wait_row(&app, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    let r = wait_row(&app, sid, "the row records the detach", detached).await;

    let runs = &remote(&app).resume_gate_runs;
    let before = runs.load(Ordering::Relaxed);
    let mut ctl = controller(&app, &admin).await;
    for _ in 0..5 {
        rejoin(&mut ctl, sid).await;
        let answer = rejoin_answer(&mut ctl, sid, WITHIN)
            .await
            .expect("the rejoin is answered");
        assert_eq!(answer["t"], "rc:session.detached", "{answer}");
        assert_eq!(
            answer["resume_by"].as_i64(),
            Some(resume_by_ms(&r)),
            "{answer}"
        );
    }
    assert_eq!(
        runs.load(Ordering::Relaxed) - before,
        1,
        "five asks inside 5 s run the gate once"
    );
}

/// PR D's review, MEDIUM 1 — a pod that dies writes none of
/// its ends, and the pod that replaces it on the node has its pod id. The
/// lease of a session its hub held is then this pod's, its hub holds nothing,
/// and the row reads live with no `resume_by`. On a device outside the resume
/// scope nothing will ever resume that session, so the lease is dropped as
/// stale and the org's request is created at once, as before FR-130. On a
/// device inside the scope a detach may still be on its way to the row, so
/// the same lease is kept, and lapses on its own.
#[tokio::test]
async fn a_dead_pods_lease_is_dropped_outside_the_resume_scope_and_kept_inside() {
    let app = one_slotted(WINDOW).await;
    let Some(slots) = app.state.session_slots.clone() else {
        eprintln!("skipping: no Redis available");
        return;
    };
    let pod = app.state.pod.pod_id.clone();
    let outside = app.seed_tenant("fr130pd11o").await;
    let inside = app.seed_tenant("fr130pd11i").await;
    scope(&app, &[(ResumeScopeKind::Org, Some(tenant_of(&inside)))]).await;
    for (seeded, machine, in_scope) in [
        (&outside, "fr130-pd-11o", false),
        (&inside, "fr130-pd-11i", true),
    ] {
        let tenant = tenant_of(seeded);
        let (agent_id, token) = enroll(&app, seeded, machine).await;
        // No `rc-resume`: no window, so no registration read races the row
        // below. The scope list alone decides.
        let _agent = hello(&app, &token, &[], &[]).await;
        let admin_id = oid(&seeded.admin.id);
        let ghost = ObjectId::new();
        assert_eq!(
            slots
                .claim(SlotScope::Org(tenant), ghost, admin_id, agent_id, 1, &pod)
                .await
                .unwrap(),
            SlotClaim::Claimed,
            "the org's one slot, held for a session of the pod that died"
        );
        insert(
            &app,
            leftover(
                ghost,
                agent_id,
                tenant,
                admin_id,
                now_ms() - 60_000,
                doc! {},
            ),
        )
        .await;

        let mut ctl = controller(&app, &seeded.admin.access_token).await;
        let answer = request(&mut ctl, agent_id, None).await;
        if in_scope {
            assert_eq!(
                answer["t"], "rc:error",
                "inside the scope a detach may be in flight: {answer}"
            );
            assert_eq!(answer["code"], "org_session_limit", "{answer}");
        } else {
            assert_eq!(
                answer["t"], "rc:session.created",
                "outside the scope the stale lease is dropped, as before FR-130: {answer}"
            );
        }
    }
}

/// PR D's review, LOW 4 — a claim that began before its row's `resume_by`
/// may commit just after it, and finds its slot only because the detach kept
/// the lease 10 s past the deadline. The stale-lease check honours the same
/// grace: inside it the lease is kept and the org's request refused; past it
/// the lease is over, dropped, and the request created.
#[tokio::test]
async fn a_lease_past_its_deadline_is_kept_through_the_grace_and_no_longer() {
    let app = one_slotted(WINDOW).await;
    let Some(slots) = app.state.session_slots.clone() else {
        eprintln!("skipping: no Redis available");
        return;
    };
    let seeded = app.seed_tenant("fr130pdl4").await;
    let tenant = tenant_of(&seeded);
    let (agent_id, token) = enroll(&app, &seeded, "fr130-pd-l4").await;
    let _agent = hello(&app, &token, &[], &[]).await;
    let admin_id = oid(&seeded.admin.id);
    let ghost = ObjectId::new();
    assert_eq!(
        slots
            .claim(
                SlotScope::Org(tenant),
                ghost,
                admin_id,
                agent_id,
                1,
                &app.state.pod.pod_id,
            )
            .await
            .unwrap(),
        SlotClaim::Claimed
    );
    let now = now_ms();
    insert(
        &app,
        leftover(
            ghost,
            agent_id,
            tenant,
            admin_id,
            now - 120_000,
            doc! {
                "detached_at": DateTime::from_millis(now - 63_000),
                "resume_by": DateTime::from_millis(now - 3_000),
            },
        ),
    )
    .await;

    let mut ctl = controller(&app, &seeded.admin.access_token).await;
    let refused = request(&mut ctl, agent_id, None).await;
    assert_eq!(
        refused["t"], "rc:error",
        "3 s past resume_by a late claim may still commit: {refused}"
    );
    assert_eq!(refused["code"], "org_session_limit", "{refused}");

    app.db
        .collection::<Document>("remote_sessions")
        .update_one(
            doc! { "_id": ghost },
            doc! { "$set": { "resume_by": DateTime::from_millis(now - 11_000) } },
        )
        .await
        .unwrap();
    let mut ctl = controller(&app, &seeded.admin.access_token).await;
    let created = request(&mut ctl, agent_id, None).await;
    assert_eq!(
        created["t"], "rc:session.created",
        "11 s past resume_by the lease is over: {created}"
    );
}

/// PR D's review, LOW 7 — a lease whose pod stopped renewing it has lapsed,
/// and no claim has purged it yet. A keep must not bring it back: it would
/// take the org's slot again until the deadline it was kept to.
#[tokio::test]
async fn a_lapsed_lease_is_never_kept_again() {
    let app = one_slotted(WINDOW).await;
    let (Some(slots), Some(redis)) = (
        app.state.session_slots.clone(),
        app.state.redis_pubsub.clone(),
    ) else {
        eprintln!("skipping: no Redis available");
        return;
    };
    let org = SlotScope::Org(ObjectId::new());
    let sid = ObjectId::new();
    assert_eq!(
        slots
            .claim(org, sid, ObjectId::new(), ObjectId::new(), 1, "fr130-pd-l7")
            .await
            .unwrap(),
        SlotClaim::Claimed
    );
    let set = slots.slots_key(org);
    let mut conn = redis.connection();
    redis::cmd("ZADD")
        .arg(&set)
        .arg(1)
        .arg(sid.to_hex())
        .query_async::<()>(&mut conn)
        .await
        .unwrap();

    let kept = slots.keep(org, sid, now_ms() + 60_000).await.unwrap();
    assert!(!kept, "a lapsed lease stays lapsed");
    assert_eq!(slots.held(org).await.unwrap(), 0, "no slot is taken");
    assert_eq!(score(&mut conn, &set, sid).await, Some(1), "left as it was");
}

/// PR D's review, LOW 5 — a detached session's lease is kept past a lease's
/// 90 s when its window is longer. Another session's claim in the org, and a
/// renewal round that puts back the leases Redis lost, wrote the set's expiry
/// as 90 s from then, which could take the kept lease with the set before its
/// deadline. Both only lengthen an expiry now, and a restore never lowers a
/// kept lease's score.
#[tokio::test]
async fn a_claim_or_a_restore_never_shortens_a_kept_lease() {
    let app = one_slotted(WINDOW).await;
    let (Some(slots), Some(redis)) = (
        app.state.session_slots.clone(),
        app.state.redis_pubsub.clone(),
    ) else {
        eprintln!("skipping: no Redis available");
        return;
    };
    let org = SlotScope::Org(ObjectId::new());
    let pod = "fr130-pd-l5b";
    let (user, device) = (ObjectId::new(), ObjectId::new());
    let (kept, other) = (ObjectId::new(), ObjectId::new());
    let lease = |session| Lease {
        scope: org,
        session,
        user,
        device,
    };
    assert_eq!(
        slots.claim(org, kept, user, device, 2, pod).await.unwrap(),
        SlotClaim::Claimed
    );
    let until = now_ms() + 130_000;
    assert!(slots.keep(org, kept, until).await.unwrap(), "kept");
    let set = slots.slots_key(org);
    let holder = holder_key(&app, kept);
    let mut conn = redis.connection();

    assert_eq!(
        slots.claim(org, other, user, device, 2, pod).await.unwrap(),
        SlotClaim::Claimed
    );
    let left = pttl(&mut conn, &set).await;
    assert!(
        left > 120_000,
        "a claim leaves the set's longer expiry alone, not {left} ms"
    );

    slots
        .restore(&[lease(other), lease(kept)], pod)
        .await
        .unwrap();
    for key in [&set, &holder] {
        let left = pttl(&mut conn, key).await;
        assert!(
            left > 120_000,
            "a restore leaves {key}'s longer expiry alone, not {left} ms"
        );
    }
    assert_eq!(
        score(&mut conn, &set, kept).await,
        Some(until),
        "a restore never lowers a kept lease"
    );
}

/// PR D's review, a test gap (review 1, L5's renewal race) — a renewal
/// round can be in flight when a session detaches, and its lease is kept to
/// `resume_by` plus 10 s, past the 90 s the round writes. The round only
/// raises a lease (`GT` on the score and on both expiries): the kept lease
/// stands, and is answered as missing, so the hub, which no longer holds the
/// session, does not put it back. Without `GT` the round cut it to 90 s.
#[tokio::test]
async fn a_renewal_never_shortens_a_kept_lease() {
    let app = one_slotted(WINDOW).await;
    let (Some(slots), Some(redis)) = (
        app.state.session_slots.clone(),
        app.state.redis_pubsub.clone(),
    ) else {
        eprintln!("skipping: no Redis available");
        return;
    };
    let org = SlotScope::Org(ObjectId::new());
    let (sid, user, device) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
    assert_eq!(
        slots
            .claim(org, sid, user, device, 1, "fr130-pd-gt")
            .await
            .unwrap(),
        SlotClaim::Claimed
    );
    let until = now_ms() + 130_000;
    assert!(slots.keep(org, sid, until).await.unwrap(), "kept");

    let lease = Lease {
        scope: org,
        session: sid,
        user,
        device,
    };
    let missing = slots.renew(std::slice::from_ref(&lease)).await.unwrap();
    assert_eq!(
        missing,
        vec![lease],
        "a lease the round did not raise is answered missing"
    );
    let set = slots.slots_key(org);
    let mut conn = redis.connection();
    assert_eq!(
        score(&mut conn, &set, sid).await,
        Some(until),
        "the kept score stands"
    );
    for key in [set.clone(), holder_key(&app, sid)] {
        let left = pttl(&mut conn, &key).await;
        assert!(left > 120_000, "{key} keeps the kept expiry, not {left} ms");
    }
}

/// PR D's review, a test gap — another session took the org's one slot
/// during the gap, on another pod. The device's claim wins its commit and
/// then finds the org full: the session ends, the device is told
/// `agent_disconnect`, the row ends with that reason at the number the claim
/// committed, and no lease of the session is left.
#[tokio::test]
async fn a_resumed_session_whose_slot_another_took_during_the_gap_ends() {
    let app = one_slotted(WINDOW).await;
    let Some(slots) = app.state.session_slots.clone() else {
        eprintln!("skipping: no Redis available");
        return;
    };
    let seeded = app.seed_tenant("fr130pdfull").await;
    scope_all(&app).await;
    let org = SlotScope::Org(tenant_of(&seeded));
    let (agent_id, token) = enroll(&app, &seeded, "fr130-pd-full").await;
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app, &seeded.admin.access_token, agent_id, &mut agent).await;
    wait_row(&app, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    let r = wait_row(&app, sid, "the row records the detach", detached).await;
    let read_at = attach_seq(&r);

    // The slot goes to another session, held by another pod.
    slots.release(org, sid).await.unwrap();
    assert_eq!(
        slots
            .claim(
                org,
                ObjectId::new(),
                ObjectId::new(),
                ObjectId::new(),
                1,
                "fr130-pd-other",
            )
            .await
            .unwrap(),
        SlotClaim::Claimed
    );

    let mut agent2 = hello(&app, &token, &[RESUME], &[sid]).await;
    let answer = answer_for(&mut agent2, sid, WITHIN)
        .await
        .expect("the claim is answered");
    assert_eq!(answer["t"], "rc:terminate", "{answer}");
    assert_eq!(answer["reason"], "agent_disconnect", "{answer}");
    let r = wait_row(&app, sid, "the row ends", ended).await;
    assert_eq!(end_reason(&r), Some("agent_disconnect"), "{r}");
    assert_eq!(
        attach_seq(&r),
        read_at + 1,
        "fenced at the number committed: {r}"
    );
    assert!(app.state.fleet().rc_hub.session_snapshot(sid).is_none());
    assert_eq!(
        slots.held(org).await.unwrap(),
        1,
        "only the other session's lease"
    );
}

/// PR D's review, a test gap (review 2, N14) — the viewer of a DETACHED row
/// asks every second, and the gate runs at most once per 5 s for it. A
/// viewer removed from the org during the gap is still told `detached` inside
/// those 5 s, and is refused `admin_terminated` at its first ask after them,
/// the row ended with that reason. (The held-here path, whose gate always
/// runs, is `a_viewer_removed_from_the_org_is_refused_at_its_rejoin`.)
#[tokio::test]
async fn a_viewer_removed_from_the_org_during_the_gap_is_refused_within_five_seconds() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130pdgap").await;
    scope_all(&app).await;
    give_member(&app, &seeded, "controller", REMOTE_CONTROL).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-pd-gap").await;
    let member = seeded.member.access_token.clone();
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let (_ctl, sid, _) = live_session(&app, &member, agent_id, &mut agent).await;
    drop_socket(agent).await;
    wait_row(&app, sid, "the row records the detach", detached).await;

    let mut ctl = controller(&app, &member).await;
    rejoin(&mut ctl, sid).await;
    let first = rejoin_answer(&mut ctl, sid, WITHIN)
        .await
        .expect("the rejoin is answered");
    let gated_at = tokio::time::Instant::now();
    assert_eq!(first["t"], "rc:session.detached", "{first}");

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

    rejoin(&mut ctl, sid).await;
    let soon = rejoin_answer(&mut ctl, sid, WITHIN)
        .await
        .expect("the rejoin is answered");
    if gated_at.elapsed() < Duration::from_secs(4) {
        assert_eq!(
            soon["t"], "rc:session.detached",
            "inside the 5 s the gate does not run again: {soon}"
        );
    }

    tokio::time::sleep_until(gated_at + Duration::from_millis(5_300)).await;
    rejoin(&mut ctl, sid).await;
    let refused = rejoin_answer(&mut ctl, sid, WITHIN)
        .await
        .expect("the rejoin is answered");
    assert_eq!(refused["t"], "rc:terminate", "{refused}");
    assert_eq!(refused["reason"], "admin_terminated", "{refused}");
    let r = wait_row(&app, sid, "the session ends", ended).await;
    assert_eq!(end_reason(&r), Some("admin_terminated"), "{r}");
}

/// PR D's review, LOW 8 — the rate's entry for a viewer goes once its
/// session is bound: the viewer's asks while the row is detached are timed,
/// and once the device has claimed the session back, the ask that binds it
/// takes the entry with it. Before, an entry left only when the map held
/// more than 1024, and then every ask walked the whole map.
#[tokio::test]
async fn a_rejoins_rate_entry_goes_once_its_session_is_bound() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130pdl8").await;
    scope_all(&app).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-pd-l8").await;
    let admin = seeded.admin.access_token.clone();
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app, &admin, agent_id, &mut agent).await;
    wait_row(&app, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    wait_row(&app, sid, "the row records the detach", detached).await;

    let mut ctl = controller(&app, &admin).await;
    rejoin(&mut ctl, sid).await;
    let waiting = rejoin_answer(&mut ctl, sid, WITHIN)
        .await
        .expect("the rejoin is answered");
    assert_eq!(waiting["t"], "rc:session.detached", "{waiting}");
    let gates = &remote(&app).rejoin_gates;
    assert_eq!(gates.len(), 1, "the viewer's ask is timed");

    let mut agent2 = hello(&app, &token, &[RESUME], &[sid]).await;
    let claimed = answer_for(&mut agent2, sid, WITHIN)
        .await
        .expect("the claim is answered");
    assert_eq!(claimed["t"], "rc:session.resumed", "{claimed}");
    rejoin(&mut ctl, sid).await;
    let bound = rejoin_answer(&mut ctl, sid, WITHIN)
        .await
        .expect("the rejoin is answered");
    assert_eq!(bound["t"], "rc:session.resumed", "{bound}");
    assert_eq!(gates.len(), 0, "a bound session's entry goes with the bind");
}
