// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-130 P1b-2, part two — the rest of the server's resume, through real
//! servers and one MongoDB:
//!
//! * **the sweep** (cluster-singleton, on the presence sweep's cadence) ends
//!   a detached row past its `resume_by`, and a row a pod that died without
//!   a word left open on a device the scope covers that has been offline for
//!   longer than the window. Each ends at its own last clock with
//!   `end_source: sweep`. It leaves alone a row still inside its window, a
//!   resumed one, one on a device outside the scope and, at window 0, any row
//!   no detach marked;
//! * **the re-announce**: a change to the resume scope reaches a connected
//!   device on the other pod at once, and taking it out withdraws its window;
//! * **the dead-row close** (`POST /api/admin/rc-sessions/close-dead`), a
//!   platform admin's: its dry run lists without writing, and a real run
//!   closes at the row's own last clock with `end_source: backfill`.
//!
//! The second review of part two added a test per finding in part two's own
//! code, each written before its fix: the close never ends a session another
//! pod holds, is refused while stats are off, shows its evidence and pages
//! (N1, N7); a scope change is a nudge that every pod reads under its own
//! window, and reaches a device whose event was lost (N2); the sweep ends a
//! row whose device was removed (N6) and is not starved by rows it will never
//! end (N7); a stranger gets the admin 404 whatever the body (N13).

use std::time::{Duration, Instant};

use bson::{DateTime, Document, doc, oid::ObjectId};
use meshharbor_services::dao::rc_resume_scope::ResumeScopeKind;
use serde_json::{Value, json};

use crate::fixtures::test_app::TestApp;
use crate::rc_resume_claim_tests::operator_token;
use crate::rc_resume_claim_tests::{
    QUIET, RESUME, WINDOW, WITHIN, ended, enroll, go_live, hello, hello_with, insert, leftover,
    next_of, now_ms, oid, one, open, row, scope, scope_all, tenant_of, wait_row,
};

/// The presence sweep's cadence, the shortest it takes: the resume sweep runs
/// on it.
const SWEEP_SECS: u64 = 5;
/// How long a sweep may take to land: two cycles and the batched writes.
const SWEPT_WITHIN: Duration = Duration::from_secs(2 * SWEEP_SECS + 4);

/// One pod with the window `window`, sweeping every [`SWEEP_SECS`].
async fn sweeping(window: u64) -> TestApp {
    TestApp::spawn_with_settings(move |s| {
        s.rc.session_resume_secs = window;
        s.rc.presence_sweep_secs = SWEEP_SECS;
    })
    .await
}

/// A device the presence sweep found offline `hours` ago.
async fn offline_since(app: &TestApp, agent: ObjectId, hours: i64) {
    app.db
        .collection::<Document>("agents")
        .update_one(
            doc! { "_id": agent },
            doc! { "$set": {
                "status": "offline",
                "last_presence": "offline",
                "last_seen_at": DateTime::from_millis(now_ms() - hours * 3_600_000),
            }},
        )
        .await
        .unwrap();
}

/// The row once `pred` holds, within `within`; panics with `what` otherwise.
async fn wait_for(
    app: &TestApp,
    sid: ObjectId,
    within: Duration,
    what: &str,
    pred: impl Fn(&Document) -> bool,
) -> Document {
    let deadline = Instant::now() + within;
    loop {
        let r = row(app, sid).await;
        if pred(&r) {
            return r;
        }
        assert!(Instant::now() < deadline, "{what}: {r}");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn swept(r: &Document) -> bool {
    ended(r) && r.get_str("end_source") == Ok("sweep")
}

/// AC4, AC9 — the sweep, window on. The device the scope covers has been
/// offline for two hours, the other device is outside the scope. Over two
/// cycles the sweep ends the detached row past its `resume_by` at its
/// `detached_at`, and the row a dead pod left open on the covered device at
/// its `stats_at`, each `agent_disconnect` with `end_source: sweep`. It leaves
/// the detached row still inside its window, the resumed row whose stats are
/// fresh, and the dead pod's row on the device outside the scope.
#[tokio::test]
async fn the_sweep_ends_what_nobody_will_claim_and_leaves_the_rest() {
    let app = sweeping(WINDOW).await;
    let seeded = app.seed_tenant("fr130sweep").await;
    let (covered, _) = enroll(&app, &seeded, "fr130-sweep-in").await;
    let (outside, _) = enroll(&app, &seeded, "fr130-sweep-out").await;
    scope(&app, &[(ResumeScopeKind::Device, Some(covered))]).await;
    offline_since(&app, covered, 2).await;
    offline_since(&app, outside, 2).await;
    let (tenant, ctl) = (tenant_of(&seeded), oid(&seeded.admin.id));
    let base = now_ms() - 3 * 3_600_000;
    let at = DateTime::from_millis;
    let ids: Vec<ObjectId> = (0..5).map(|_| ObjectId::new()).collect();
    let (expired, inside, abandoned, foreign, resumed) = (ids[0], ids[1], ids[2], ids[3], ids[4]);

    let detached_at = now_ms() - 120_000;
    insert(
        &app,
        leftover(
            expired,
            covered,
            tenant,
            ctl,
            base,
            doc! { "detached_at": at(detached_at), "resume_by": at(detached_at + 60_000) },
        ),
    )
    .await;
    insert(
        &app,
        leftover(
            inside,
            covered,
            tenant,
            ctl,
            base,
            doc! { "detached_at": at(now_ms()), "resume_by": at(now_ms() + 600_000) },
        ),
    )
    .await;
    let stats_at = now_ms() - 3_600_000;
    insert(
        &app,
        leftover(
            abandoned,
            covered,
            tenant,
            ctl,
            base,
            doc! { "stats_at": at(stats_at) },
        ),
    )
    .await;
    insert(
        &app,
        leftover(
            foreign,
            outside,
            tenant,
            ctl,
            base,
            doc! { "stats_at": at(stats_at) },
        ),
    )
    .await;
    insert(
        &app,
        leftover(
            resumed,
            covered,
            tenant,
            ctl,
            base,
            doc! { "attach_seq": 1_i64, "stats_at": at(now_ms() + 600_000) },
        ),
    )
    .await;
    let untouched = [
        (inside, row(&app, inside).await),
        (foreign, row(&app, foreign).await),
        (resumed, row(&app, resumed).await),
    ];

    for (sid, last_clock, what) in [
        (expired, at(detached_at), "the detached row past resume_by"),
        (
            abandoned,
            at(stats_at),
            "the dead pod's row on the covered device",
        ),
    ] {
        let r = wait_for(&app, sid, SWEPT_WITHIN, what, swept).await;
        assert_eq!(
            r.get_str("end_reason"),
            Ok("agent_disconnect"),
            "{what}: {r}"
        );
        assert_eq!(r.get_str("phase"), Ok("closed"), "{what}: {r}");
        assert_eq!(
            r.get_datetime("ended_at").unwrap(),
            &last_clock,
            "{what}: dated by its own last clock: {r}"
        );
    }
    for (sid, before) in untouched {
        assert_eq!(row(&app, sid).await, before, "left alone: {sid}");
    }
}

/// Off is today: at window 0 the sweep ends nothing no detach marked. A row a
/// dead pod left open stays as it is whatever its device and the scope say,
/// while a row a detach marked before the window was turned back to 0 still
/// ends at its `resume_by`.
#[tokio::test]
async fn at_window_zero_the_sweep_ends_only_what_a_detach_marked() {
    let app = sweeping(0).await;
    let seeded = app.seed_tenant("fr130sweepzero").await;
    scope_all(&app).await;
    let (device, _) = enroll(&app, &seeded, "fr130-sweep-zero").await;
    offline_since(&app, device, 2).await;
    let (tenant, ctl) = (tenant_of(&seeded), oid(&seeded.admin.id));
    let base = now_ms() - 3 * 3_600_000;
    let at = DateTime::from_millis;
    let (marked, dead) = (ObjectId::new(), ObjectId::new());
    let detached_at = now_ms() - 120_000;
    insert(
        &app,
        leftover(
            marked,
            device,
            tenant,
            ctl,
            base,
            doc! { "detached_at": at(detached_at), "resume_by": at(detached_at + 60_000) },
        ),
    )
    .await;
    insert(
        &app,
        leftover(
            dead,
            device,
            tenant,
            ctl,
            base,
            doc! { "stats_at": at(now_ms() - 3_600_000) },
        ),
    )
    .await;
    let before = row(&app, dead).await;

    let r = wait_for(&app, marked, SWEPT_WITHIN, "the marked row", swept).await;
    assert_eq!(r.get_datetime("ended_at").unwrap(), &at(detached_at), "{r}");
    assert_eq!(
        row(&app, dead).await,
        before,
        "a row no detach marked stays"
    );
}

/// Platform operators only.
async fn pair_with_operator(window: u64, operator: ObjectId) -> (TestApp, TestApp) {
    TestApp::spawn_pair(move |s| {
        s.rc.session_resume_secs = window;
        s.stats.platform_admins = Some(operator.to_hex());
    })
    .await
}

/// A client with no cookie jar, so the bearer token is the only identity:
/// `app.client` keeps the cookie the last sign-up set.
fn bare_client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(false)
        .build()
        .unwrap()
}

async fn put_scope(app: &TestApp, token: &str, entries: Value) {
    let resp = bare_client()
        .put(app.url("/api/admin/rc-resume-scope"))
        .bearer_auth(token)
        .json(&json!({ "entries": entries }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "the scope saves");
}

/// The re-announce (spec §4.1): a device on pod 2 that advertises the verb
/// and is outside the scope holds no window. A platform admin puts it in the
/// scope on pod 1, and the device is told its window at once, across pods.
/// Taken out again, it is told 0, which withdraws it. A device on pod 1 hears
/// the same through pod 1's own apply.
#[tokio::test]
async fn a_scope_change_reaches_a_device_on_the_other_pod() {
    let operator = ObjectId::new();
    let (app1, app2) = pair_with_operator(WINDOW, operator).await;
    if app1.state.cluster_bus.is_none() {
        eprintln!("skipping: no Redis available");
        return;
    }
    let seeded = app1.seed_tenant("fr130announce").await;
    let token = operator_token(&app1, operator).await;
    put_scope(&app1, &token, json!([])).await;
    let (far, far_token) = enroll(&app1, &seeded, "fr130-announce-far").await;
    let (near, near_token) = enroll(&app1, &seeded, "fr130-announce-near").await;
    let mut far_ws = hello(&app2, &far_token, &[RESUME], &[]).await;
    let mut near_ws = hello(&app1, &near_token, &[RESUME], &[]).await;
    for ws in [&mut far_ws, &mut near_ws] {
        assert!(
            next_of(ws, "rc:agent.resume_window", QUIET).await.is_none(),
            "no window outside the scope"
        );
    }

    put_scope(
        &app1,
        &token,
        json!([
            { "kind": "device", "id": far.to_hex() },
            { "kind": "device", "id": near.to_hex() },
        ]),
    )
    .await;
    for (ws, who) in [
        (&mut far_ws, "pod 2's device"),
        (&mut near_ws, "pod 1's device"),
    ] {
        let told = next_of(ws, "rc:agent.resume_window", WITHIN)
            .await
            .unwrap_or_else(|| panic!("{who} is told its window"));
        assert_eq!(told["secs"], WINDOW, "{who}: {told}");
    }
    assert_eq!(
        app2.state.fleet().rc_hub.agent_resume_window(far),
        Some(WINDOW as u32)
    );

    put_scope(&app1, &token, json!([])).await;
    for (ws, who) in [
        (&mut far_ws, "pod 2's device"),
        (&mut near_ws, "pod 1's device"),
    ] {
        let told = next_of(ws, "rc:agent.resume_window", WITHIN)
            .await
            .unwrap_or_else(|| panic!("{who} is told its window is withdrawn"));
        assert_eq!(told["secs"], 0, "{who}: {told}");
    }
    assert_eq!(app2.state.fleet().rc_hub.agent_resume_window(far), None);
}

async fn close_dead(app: &TestApp, token: &str, body: Value) -> (u16, Value) {
    let resp = bare_client()
        .post(app.url("/api/admin/rc-sessions/close-dead"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

fn listed(body: &Value) -> Vec<String> {
    body["rows"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r["session_id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The dead-row close (P0's 11 rows): a platform admin's. Its dry run lists
/// the live row a dead pod left open days ago on a device that has had a
/// session since, and writes nothing. It does not list a row on a device with
/// no later session, nor a row younger than a day. A real run then closes
/// the listed row as `agent_disconnect`, at its own last clock, marked
/// `end_source: backfill`, and a second run finds nothing left.
#[tokio::test]
async fn the_dead_row_close_lists_in_its_dry_run_and_closes_on_a_real_one() {
    let operator = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(operator.to_hex());
    })
    .await;
    let seeded = app.seed_tenant("fr130deadrows").await;
    let token = operator_token(&app, operator).await;
    let (used, _) = enroll(&app, &seeded, "fr130-dead-used").await;
    let (idle, _) = enroll(&app, &seeded, "fr130-dead-idle").await;
    let (tenant, ctl) = (tenant_of(&seeded), oid(&seeded.admin.id));
    let day = 24 * 3_600_000;
    let at = DateTime::from_millis;
    let (dead, later, lonely, young) = (
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
    );
    let started = now_ms() - 5 * day;
    insert(&app, leftover(dead, used, tenant, ctl, started, doc! {})).await;
    insert(
        &app,
        leftover(
            later,
            used,
            tenant,
            ctl,
            now_ms() - day,
            doc! { "phase": "closed", "ended_at": at(now_ms() - day + 60_000), "end_reason": "controller_hangup" },
        ),
    )
    .await;
    insert(&app, leftover(lonely, idle, tenant, ctl, started, doc! {})).await;
    insert(
        &app,
        leftover(young, used, tenant, ctl, now_ms() - 3_600_000, doc! {}),
    )
    .await;
    let before: Vec<(ObjectId, Document)> = {
        let mut v = Vec::new();
        for sid in [dead, lonely, young] {
            v.push((sid, row(&app, sid).await));
        }
        v
    };

    let stranger = seeded.admin.access_token.clone();
    let (status, _) = close_dead(&app, &stranger, json!({})).await;
    assert_eq!(status, 404, "a platform admin's route");

    let (status, body) = close_dead(&app, &token, json!({})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["dry_run"], true, "a dry run by default: {body}");
    assert_eq!(listed(&body), vec![dead.to_hex()], "{body}");
    assert_eq!(body["closed"], 0, "{body}");
    for (sid, b) in &before {
        assert_eq!(&row(&app, *sid).await, b, "the dry run writes nothing");
    }

    let (status, body) = close_dead(&app, &token, json!({ "dry_run": false })).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["closed"], 1, "{body}");
    let r = row(&app, dead).await;
    assert!(ended(&r), "{r}");
    assert_eq!(r.get_str("end_reason"), Ok("agent_disconnect"), "{r}");
    assert_eq!(r.get_str("end_source"), Ok("backfill"), "{r}");
    assert_eq!(
        r.get_datetime("ended_at").unwrap(),
        &at(started),
        "at its own last clock, never the operator's: {r}"
    );
    for sid in [lonely, young] {
        assert!(open(&row(&app, sid).await), "{sid} is not dead");
    }

    let (_, body) = close_dead(&app, &token, json!({ "dry_run": false })).await;
    assert!(listed(&body).is_empty(), "nothing left: {body}");
}

// ── Review 2: a test per finding in part two's own code, each written before
// its fix. ──

/// One pod with the platform admin `operator`, and `tweak` on top.
async fn with_operator(
    operator: ObjectId,
    tweak: impl FnOnce(&mut meshharbor_config::Settings),
) -> TestApp {
    TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(operator.to_hex());
        tweak(s);
    })
    .await
}

/// Once `agent` is registered on `app`'s hub (a hello with no window has no
/// frame to wait for).
async fn registered(app: &TestApp, agent: ObjectId) {
    let deadline = Instant::now() + WITHIN;
    while !app.state.fleet().rc_hub.is_agent_online(agent) {
        assert!(Instant::now() < deadline, "the device never registered");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The `kept` rows of a close's answer: `(session_id, why)`.
fn kept(body: &Value) -> Vec<(String, String)> {
    body["kept"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|r| {
                    Some((
                        r["session_id"].as_str()?.to_string(),
                        r["why"].as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// N13 — the close is a platform admin's before anything else is read: a
/// stranger gets the 404 every `/api/admin/*` route gives whatever the body,
/// never a 422 that says the route exists. The operator's own bad body is a
/// 400.
#[tokio::test]
async fn a_stranger_gets_the_admin_404_whatever_the_body() {
    let operator = ObjectId::new();
    let app = with_operator(operator, |_| {}).await;
    let seeded = app.seed_tenant("fr130deadbody").await;
    let stranger = seeded.admin.access_token.clone();
    for body in [
        json!({ "dry_run": "no" }),
        json!({ "limit": -1 }),
        json!([1, 2]),
    ] {
        let (status, answer) = close_dead(&app, &stranger, body.clone()).await;
        assert_eq!(status, 404, "{body} -> {answer}");
    }
    let token = operator_token(&app, operator).await;
    let (status, answer) = close_dead(&app, &token, json!({ "dry_run": "no" })).await;
    assert_eq!(status, 400, "the operator's bad body: {answer}");
}

/// N1 — the close never ends a session another pod holds. A device with two
/// places is online on pod 2 with two live sessions, and S1 is made to look
/// like a dead pod's leftover: two hours old, with no clock of its own. Pod 2
/// holds S1, so the close on pod 1 keeps it, live. S0, a leftover on the same
/// device that pod 2 does not hold, is dead although its device is online,
/// and closes.
#[tokio::test]
async fn the_dead_row_close_keeps_a_session_another_pod_holds() {
    let operator = ObjectId::new();
    // Window 0, and no org cap: the harness's orgs run one session at a time,
    // and this device runs two.
    let (app1, app2) = TestApp::spawn_pair(move |s| {
        s.stats.platform_admins = Some(operator.to_hex());
        s.rc.org_session_cap = false;
    })
    .await;
    if app1.state.cluster_bus.is_none() {
        eprintln!("skipping: no Redis available");
        return;
    }
    let seeded = app1.seed_tenant("fr130deadheld").await;
    let token = operator_token(&app1, operator).await;
    let (device, device_token) = enroll(&app1, &seeded, "fr130-dead-held").await;
    let mut agent = hello_with(&app2, &device_token, &[], &[], 2).await;
    registered(&app2, device).await;
    let viewer = seeded.admin.access_token.clone();
    let (_c1, s1) = go_live(&app2, &viewer, device, &mut agent).await;
    let (_c2, s2) = go_live(&app2, &viewer, device, &mut agent).await;
    for sid in [s1, s2] {
        wait_row(&app1, sid, "the session's row is live", open).await;
    }
    let two_hours_ago = DateTime::from_millis(now_ms() - 2 * 3_600_000);
    app1.db
        .collection::<Document>("remote_sessions")
        .update_one(
            doc! { "_id": s1 },
            doc! {
                "$set": { "created_at": two_hours_ago, "started_at": two_hours_ago },
                "$unset": { "stats_at": "" },
            },
        )
        .await
        .unwrap();
    let (tenant, ctl) = (tenant_of(&seeded), oid(&seeded.admin.id));
    let s0 = ObjectId::new();
    insert(
        &app1,
        leftover(
            s0,
            device,
            tenant,
            ctl,
            now_ms() - 3 * 24 * 3_600_000,
            doc! {},
        ),
    )
    .await;

    let (status, body) = close_dead(
        &app1,
        &token,
        json!({ "dry_run": false, "min_age_hours": 1 }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        !listed(&body).contains(&s1.to_hex()),
        "S1 is pod 2's: {body}"
    );
    assert!(open(&row(&app1, s1).await), "S1 stays live");
    assert!(
        app2.state.fleet().rc_hub.session_snapshot(s1).is_some(),
        "and pod 2 still runs it"
    );
    assert!(
        kept(&body).contains(&(s1.to_hex(), "held_by_owner".to_string())),
        "{body}"
    );
    assert_eq!(listed(&body), vec![s0.to_hex()], "{body}");
    assert!(ended(&row(&app1, s0).await), "S0 was nobody's: closed");
}

/// N1 — with `stats.enabled` off no row's own clock moves, so a live session
/// looks as quiet as a dead pod's leftover. A real run is refused (409) and
/// writes nothing; the dry run still answers, and says stats are off.
#[tokio::test]
async fn a_real_close_is_refused_while_stats_are_off() {
    let operator = ObjectId::new();
    let app = with_operator(operator, |s| s.stats.enabled = false).await;
    let seeded = app.seed_tenant("fr130deadnostats").await;
    let token = operator_token(&app, operator).await;
    let (used, _) = enroll(&app, &seeded, "fr130-dead-nostats").await;
    let (tenant, ctl) = (tenant_of(&seeded), oid(&seeded.admin.id));
    let day = 24 * 3_600_000;
    let (dead, later) = (ObjectId::new(), ObjectId::new());
    insert(
        &app,
        leftover(dead, used, tenant, ctl, now_ms() - 5 * day, doc! {}),
    )
    .await;
    insert(
        &app,
        leftover(
            later,
            used,
            tenant,
            ctl,
            now_ms() - day,
            doc! { "phase": "closed", "ended_at": DateTime::from_millis(now_ms() - day + 60_000), "end_reason": "controller_hangup" },
        ),
    )
    .await;
    let before = row(&app, dead).await;

    let (status, body) = close_dead(&app, &token, json!({})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["stats_enabled"], false, "the dry run says why: {body}");
    let (status, body) = close_dead(&app, &token, json!({ "dry_run": false })).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(row(&app, dead).await, before, "nothing is written");
}

/// N1 — every row the close reads carries its evidence, dead or kept: its own
/// clock and that clock's age, whether this pod holds it, where its device is
/// now, and whether the device has had a session since. A kept row says why.
#[tokio::test]
async fn the_dry_run_shows_each_rows_evidence() {
    let operator = ObjectId::new();
    let app = with_operator(operator, |_| {}).await;
    let seeded = app.seed_tenant("fr130deadevidence").await;
    let token = operator_token(&app, operator).await;
    let (used, _) = enroll(&app, &seeded, "fr130-dead-ev-used").await;
    let (idle, _) = enroll(&app, &seeded, "fr130-dead-ev-idle").await;
    let (tenant, ctl) = (tenant_of(&seeded), oid(&seeded.admin.id));
    let day = 24 * 3_600_000;
    let at = DateTime::from_millis;
    let (dead, later, lonely) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
    insert(
        &app,
        leftover(
            dead,
            used,
            tenant,
            ctl,
            now_ms() - 5 * day,
            doc! { "stats_at": at(now_ms() - 4 * day) },
        ),
    )
    .await;
    insert(
        &app,
        leftover(
            later,
            used,
            tenant,
            ctl,
            now_ms() - day,
            doc! { "phase": "closed", "ended_at": at(now_ms() - day + 60_000), "end_reason": "controller_hangup" },
        ),
    )
    .await;
    insert(
        &app,
        leftover(lonely, idle, tenant, ctl, now_ms() - 5 * day, doc! {}),
    )
    .await;

    let (status, body) = close_dead(&app, &token, json!({})).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["stats_enabled"], true, "{body}");
    assert_eq!(listed(&body), vec![dead.to_hex()], "{body}");
    let ev = &body["rows"][0]["evidence"];
    assert!(ev["stats_at"].is_string(), "{ev}");
    let age = ev["stats_age_hours"].as_f64().expect("the clock's age");
    assert!((95.0..=97.0).contains(&age), "{age}");
    assert_eq!(ev["held_here"], false, "{ev}");
    assert_eq!(ev["device"], "offline", "{ev}");
    assert_eq!(ev["later_row"], true, "{ev}");
    assert_eq!(
        kept(&body),
        vec![(lonely.to_hex(), "no_later_row".to_string())],
        "{body}"
    );
    let lonely_ev = &body["kept"][0]["evidence"];
    assert!(lonely_ev["stats_at"].is_null(), "{lonely_ev}");
    assert_eq!(lonely_ev["later_row"], false, "{lonely_ev}");
}

/// N7 — the close pages: rows it reads and keeps (two on a device with no
/// later session) never hide a newer dead row. The answer says where to go on
/// (`next`), and a call given it starts there.
#[tokio::test]
async fn the_dead_row_close_pages_past_the_rows_it_keeps() {
    let operator = ObjectId::new();
    let app = with_operator(operator, |_| {}).await;
    let seeded = app.seed_tenant("fr130deadpage").await;
    let token = operator_token(&app, operator).await;
    let (used, _) = enroll(&app, &seeded, "fr130-dead-page-used").await;
    // Two devices with one row each and no session since: kept.
    let (idle1, _) = enroll(&app, &seeded, "fr130-dead-page-idle1").await;
    let (idle2, _) = enroll(&app, &seeded, "fr130-dead-page-idle2").await;
    let (tenant, ctl) = (tenant_of(&seeded), oid(&seeded.admin.id));
    let day = 24 * 3_600_000;
    let (lonely1, lonely2, dead, later) = (
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
    );
    insert(
        &app,
        leftover(lonely1, idle1, tenant, ctl, now_ms() - 5 * day, doc! {}),
    )
    .await;
    insert(
        &app,
        leftover(lonely2, idle2, tenant, ctl, now_ms() - 4 * day, doc! {}),
    )
    .await;
    insert(
        &app,
        leftover(dead, used, tenant, ctl, now_ms() - 3 * day, doc! {}),
    )
    .await;
    insert(
        &app,
        leftover(
            later,
            used,
            tenant,
            ctl,
            now_ms() - day,
            doc! { "phase": "closed", "ended_at": DateTime::from_millis(now_ms() - day + 60_000), "end_reason": "controller_hangup" },
        ),
    )
    .await;

    let (status, first) = close_dead(&app, &token, json!({ "limit": 2 })).await;
    assert_eq!(status, 200, "{first}");
    assert!(listed(&first).is_empty(), "{first}");
    assert_eq!(first["more"], true, "{first}");
    let next = first["next"]
        .as_str()
        .unwrap_or_else(|| panic!("a cursor to go on from: {first}"))
        .to_string();
    let (status, second) = close_dead(&app, &token, json!({ "limit": 2, "after": next })).await;
    assert_eq!(status, 200, "{second}");
    assert_eq!(listed(&second), vec![dead.to_hex()], "{second}");
    let (status, real) = close_dead(
        &app,
        &token,
        json!({ "limit": 2, "after": next, "dry_run": false }),
    )
    .await;
    assert_eq!(status, 200, "{real}");
    assert_eq!(real["closed"], 1, "{real}");
    assert!(ended(&row(&app, dead).await));
}

/// N2 — a pod at window 0 never announces a window, whatever a scope event
/// from another pod carries: the event is only a nudge, and each pod reads
/// the store under its OWN window.
#[tokio::test]
async fn a_scope_event_tells_a_pod_at_window_zero_nothing() {
    let app = one(0).await;
    let seeded = app.seed_tenant("fr130scopezero").await;
    scope_all(&app).await;
    let (_device, token) = enroll(&app, &seeded, "fr130-scope-zero").await;
    let mut ws = hello(&app, &token, &[RESUME], &[]).await;
    assert!(
        next_of(&mut ws, "rc:agent.resume_window", QUIET)
            .await
            .is_none(),
        "no window at 0"
    );
    app.state.modules.apply_rc_ctrl(&json!({
        "class": "rc", "evt": "resume_scope", "window_secs": WINDOW,
        "entries": [{ "kind": "all", "id": null }],
    }));
    assert!(
        next_of(&mut ws, "rc:agent.resume_window", QUIET)
            .await
            .is_none(),
        "a pod at 0 announces nothing"
    );
}

/// N2 — an event that arrives late, or twice, never undoes a newer scope: a
/// device withdrawn from the scope stays withdrawn on pod 2 when the older
/// event that covered it reaches pod 2 again.
#[tokio::test]
async fn a_replayed_scope_event_never_undoes_a_withdrawal() {
    let operator = ObjectId::new();
    let (app1, app2) = pair_with_operator(WINDOW, operator).await;
    if app1.state.cluster_bus.is_none() {
        eprintln!("skipping: no Redis available");
        return;
    }
    let seeded = app1.seed_tenant("fr130scopereplay").await;
    let token = operator_token(&app1, operator).await;
    put_scope(&app1, &token, json!([])).await;
    let (device, device_token) = enroll(&app1, &seeded, "fr130-scope-replay").await;
    let mut ws = hello(&app2, &device_token, &[RESUME], &[]).await;
    let covered = json!([{ "kind": "device", "id": device.to_hex() }]);
    put_scope(&app1, &token, covered.clone()).await;
    let told = next_of(&mut ws, "rc:agent.resume_window", WITHIN)
        .await
        .expect("told its window");
    assert_eq!(told["secs"], WINDOW, "{told}");
    put_scope(&app1, &token, json!([])).await;
    let told = next_of(&mut ws, "rc:agent.resume_window", WITHIN)
        .await
        .expect("told it is withdrawn");
    assert_eq!(told["secs"], 0, "{told}");

    // The older event, as a pod published it, reaches pod 2 again.
    app2.state.modules.apply_rc_ctrl(&json!({
        "class": "rc", "evt": "resume_scope", "window_secs": WINDOW, "entries": covered,
    }));
    assert!(
        next_of(&mut ws, "rc:agent.resume_window", QUIET)
            .await
            .is_none(),
        "the withdrawal stands"
    );
    assert_eq!(app2.state.fleet().rc_hub.agent_resume_window(device), None);
}

/// N2 — a scope change whose event is lost still reaches a connected device:
/// while the window is on, each pod reads the store again on the sweep's
/// cadence and tells every connection whose window changed.
#[tokio::test]
async fn a_scope_change_reaches_a_device_whose_event_was_lost() {
    let app = sweeping(WINDOW).await;
    let seeded = app.seed_tenant("fr130scopelost").await;
    let (device, token) = enroll(&app, &seeded, "fr130-scope-lost").await;
    let mut ws = hello(&app, &token, &[RESUME], &[]).await;
    assert!(
        next_of(&mut ws, "rc:agent.resume_window", QUIET)
            .await
            .is_none(),
        "outside the scope"
    );
    // Written to the store with no event, as a lost event leaves it.
    scope(&app, &[(ResumeScopeKind::Device, Some(device))]).await;
    let told = next_of(&mut ws, "rc:agent.resume_window", SWEPT_WITHIN)
        .await
        .expect("told its window by the pod's own reading");
    assert_eq!(told["secs"], WINDOW, "{told}");
}

/// N6 — a row a dead pod left open on a device removed since is nobody's:
/// the sweep ends it, as it ends one on a device gone offline. A removed
/// device is not "unreadable, try later".
#[tokio::test]
async fn the_sweep_ends_a_row_whose_device_was_removed() {
    let app = sweeping(WINDOW).await;
    let seeded = app.seed_tenant("fr130sweepgone").await;
    scope_all(&app).await;
    let (device, _) = enroll(&app, &seeded, "fr130-sweep-gone").await;
    let (tenant, ctl) = (tenant_of(&seeded), oid(&seeded.admin.id));
    let at = DateTime::from_millis;
    let stats_at = now_ms() - 3_600_000;
    let sid = ObjectId::new();
    insert(
        &app,
        leftover(
            sid,
            device,
            tenant,
            ctl,
            now_ms() - 3 * 3_600_000,
            doc! { "stats_at": at(stats_at) },
        ),
    )
    .await;
    app.db
        .collection::<Document>("agents")
        .update_one(
            doc! { "_id": device },
            doc! { "$set": { "deleted_at": DateTime::now(), "last_presence": "offline", "status": "offline" } },
        )
        .await
        .unwrap();

    let r = wait_for(&app, sid, SWEPT_WITHIN, "the removed device's row", swept).await;
    assert_eq!(r.get_datetime("ended_at").unwrap(), &at(stats_at), "{r}");
}

/// N7 — rows the sweep will never end (200 on a device outside the scope, all
/// older) do not starve a newer row it must end.
#[tokio::test]
async fn the_sweep_is_not_starved_by_rows_it_will_never_end() {
    let app = sweeping(WINDOW).await;
    let seeded = app.seed_tenant("fr130sweeppage").await;
    let (outside, _) = enroll(&app, &seeded, "fr130-sweep-page-out").await;
    let (covered, _) = enroll(&app, &seeded, "fr130-sweep-page-in").await;
    scope(&app, &[(ResumeScopeKind::Device, Some(covered))]).await;
    offline_since(&app, outside, 2).await;
    offline_since(&app, covered, 2).await;
    let (tenant, ctl) = (tenant_of(&seeded), oid(&seeded.admin.id));
    let at = DateTime::from_millis;
    let stats_at = now_ms() - 3_600_000;
    let base = now_ms() - 4 * 3_600_000;
    let crowd: Vec<Document> = (0..200)
        .map(|i| {
            leftover(
                ObjectId::new(),
                outside,
                tenant,
                ctl,
                base + i,
                doc! { "stats_at": at(stats_at) },
            )
        })
        .collect();
    app.db
        .collection::<Document>("remote_sessions")
        .insert_many(crowd)
        .await
        .unwrap();
    let sid = ObjectId::new();
    insert(
        &app,
        leftover(
            sid,
            covered,
            tenant,
            ctl,
            now_ms() - 3 * 3_600_000,
            doc! { "stats_at": at(stats_at) },
        ),
    )
    .await;

    wait_for(&app, sid, SWEPT_WITHIN, "the covered device's row", swept).await;
}
