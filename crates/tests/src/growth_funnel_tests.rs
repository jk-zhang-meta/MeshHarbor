// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P2 — the account funnel, `growth_org_daily` and the org views,
//! against a real server (spec §3d; AC6, AC8).
//!
//! * **AC6** — on a seeded database the funnel returns the exact count per
//!   step with correct `pending`/`settled` (dates chosen so one cohort is
//!   settled and one is still open), and a step reads `null` when its
//!   module is unmounted (`fleet` off).
//! * **AC8** — a `growth_org_daily` row folded from a day's tunnel and SSH
//!   audit still reports that use after the audit rows are deleted (the
//!   90-day TTL), and deleting the org removes its rows.
//! * Cohorts: a small fixture with known W1/W4 activity.
//! * The routes 404 for a non-admin.
//!
//! Dates are relative to `DateTime::now()` so the handler's real `now`
//! settles the windows the test expects; the pure window logic is unit
//! tested with an injected `now` in `crates/api/src/growth/funnel.rs`.

use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use meshharbor_api::growth::org_daily;
use meshharbor_core::growth::ExclusionSet;
use meshharbor_services::dao::growth::{GrowthDao, OrgDay};
use serde_json::{Value, json};

use crate::fixtures::test_app::TestApp;

/// Hour `h` (UTC) of the day `days_ago` days before today — anchored to the
/// UTC calendar, so every seeded event lands on a KNOWN day whatever the wall
/// clock is when the test runs. (A "+h hours from now − N days" helper put
/// every event on the next UTC day once CI ran past 14:00Z, and a single-day
/// fold found nothing.)
fn at(days_ago: i64, h: u32) -> DateTime {
    let day = org_daily::parse_day_of(DateTime::now()) - chrono::Duration::days(days_ago);
    DateTime::from_millis(
        day.and_hms_opt(h, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp_millis(),
    )
}

/// Noon of that day: "some time that day" where the hour does not matter.
fn ago(days: i64) -> DateTime {
    at(days, 12)
}

async fn insert(app: &TestApp, coll: &str, mut d: Document) -> ObjectId {
    let id = d
        .get_object_id("_id")
        .map(|x| x.to_owned())
        .unwrap_or_else(|_| ObjectId::new());
    d.insert("_id", id);
    app.db
        .collection::<Document>(coll)
        .insert_one(d)
        .await
        .unwrap_or_else(|e| panic!("insert into {coll}: {e}"));
    id
}

async fn user(app: &TestApp, id: ObjectId, email: &str, created: DateTime, attr: Option<Document>) {
    let mut d = doc! {
        "_id": id, "email": email, "username": email.split('@').next().unwrap(),
        "display_name": "A Person", "avatar": Bson::Null, "bio": Bson::Null,
        "is_verified": true, "is_mfa_enabled": false, "last_active_at": Bson::Null,
        "oauth_providers": [], "created_at": created, "updated_at": created,
        "deleted_at": Bson::Null,
    };
    if let Some(a) = attr {
        d.insert("signup_attribution", a);
    }
    insert(app, "users", d).await;
}

async fn org(app: &TestApp, owner: ObjectId, slug: &str, created: DateTime) -> ObjectId {
    let id = insert(
        app,
        "tenants",
        doc! {
            "name": format!("{slug} <org>"), "slug": slug, "description": Bson::Null,
            "icon": Bson::Null, "owner_id": owner, "plan": "free", "features": [],
            "settings": { "default_locale": "en-US" }, "billing": Bson::Null,
            "integrations": Bson::Null, "is_archived": false,
            "created_at": created, "updated_at": created, "deleted_at": Bson::Null,
        },
    )
    .await;
    insert(
        app,
        "tenant_members",
        doc! {
            "tenant_id": id, "user_id": owner, "nickname": Bson::Null, "role_ids": [],
            "joined_at": created, "is_pending": false, "is_muted": false,
            "notification_override": Bson::Null, "invited_by": Bson::Null,
            "last_seen_at": Bson::Null, "created_at": created, "updated_at": created,
        },
    )
    .await;
    id
}

async fn device(app: &TestApp, tenant: ObjectId, created: DateTime, tombstoned: bool) {
    insert(
        app,
        "agents",
        doc! {
            "tenant_id": tenant, "owner_user_id": ObjectId::new(), "name": "box",
            "machine_id": format!("m-{}", ObjectId::new()), "os": "linux",
            "agent_version": "0.4.130", "status": "offline",
            "created_at": created, "updated_at": created,
            "deleted_at": if tombstoned { Bson::DateTime(created) } else { Bson::Null },
        },
    )
    .await;
}

async fn rc_session(app: &TestApp, tenant: ObjectId, started: DateTime, ended: DateTime) {
    insert(
        app,
        "remote_sessions",
        doc! {
            "agent_id": ObjectId::new(), "tenant_id": tenant, "controller_user_id": ObjectId::new(),
            "watchers": [], "permissions": 0_i32, "phase": "closed",
            "created_at": started, "started_at": started, "ended_at": ended,
            "end_reason": "controller_hangup", "recording_url": Bson::Null,
        },
    )
    .await;
}

async fn call(app: &TestApp, tenant: ObjectId, started: DateTime, peak: i32) {
    insert(
        app,
        "call_sessions",
        doc! {
            "tenant_id": tenant, "room_id": ObjectId::new(), "started_by": ObjectId::new(),
            "started_at": started,
            "ended_at": DateTime::from_millis(started.timestamp_millis() + 600_000),
            "peak_participants": peak, "participant_seconds": 600_i64,
        },
    )
    .await;
}

async fn tunnel_flow(app: &TestApp, tenant: ObjectId, at: DateTime) {
    insert(
        app,
        "tunnel_audit",
        doc! {
            "tenant_id": tenant, "tunnel_session_id": ObjectId::new(), "agent_id": ObjectId::new(),
            "user_id": ObjectId::new(), "at": at, "kind": "tcp_accept", "relay": "direct",
            "client_version": "0.4.130", "client_os": "linux",
        },
    )
    .await;
}

async fn ssh_grant(app: &TestApp, tenant: ObjectId, at: DateTime) {
    insert(
        app,
        "ssh_audit",
        doc! {
            "tenant_id": tenant, "agent_id": ObjectId::new(), "user_id": ObjectId::new(),
            "grant_id": format!("g-{}", ObjectId::new()), "source": "api", "caller": "op", "at": at,
        },
    )
    .await;
}

/// A platform-admin TestApp, with the admin's own org excluded implicitly.
async fn admin_app(fleet: bool) -> (TestApp, ObjectId, String) {
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
        s.modules.fleet = fleet;
    })
    .await;
    let token = app
        .state
        .auth
        .generate_tokens(admin_id, "padmin@test.io", "padmin")
        .unwrap()
        .access_token;
    user(&app, admin_id, "padmin@test.io", at(1, 10), None).await;
    org(&app, admin_id, "admin-org", at(1, 11)).await;
    (app, admin_id, token)
}

/// AC6 — the funnel's exact counts, pending/settled per window, and the
/// breakdown by source. One cohort is fully settled (40 days ago), one is
/// still inside its first window (2 days ago).
#[tokio::test]
async fn the_funnel_counts_each_step_with_pending_and_settled() {
    let (app, _admin, token) = admin_app(true).await;

    // A: org +1h, device +1d (tombstoned — still counts), value (a 10-min
    // RC session) +2d. Reaches first value. Settled.
    let a = ObjectId::new();
    user(
        &app,
        a,
        "a@test.io",
        at(40, 10),
        Some(doc! { "source": "YouTub", "medium": "video" }),
    )
    .await;
    let org_a = org(&app, a, "org-a", at(40, 11)).await;
    device(&app, org_a, at(39, 10), true).await;
    rc_session(&app, org_a, at(38, 10), at(38, 10).checked_add_min(10)).await;
    // A short session the same day is not value; a call with 2 is.
    rc_session(&app, org_a, at(38, 12), at(38, 12).checked_add_min(0)).await;
    call(&app, org_a, at(38, 13), 2).await;
    tunnel_flow(&app, org_a, at(38, 14)).await;
    ssh_grant(&app, org_a, at(38, 15)).await;

    // B: org, no device. Activated cold, value cold. Settled.
    let b = ObjectId::new();
    user(&app, b, "b@test.io", at(40, 10), None).await;
    org(&app, b, "org-b", at(39, 10)).await;

    // C: org, device, NO value event. Activated reached, value cold. Settled.
    let c = ObjectId::new();
    user(
        &app,
        c,
        "c@test.io",
        at(40, 10),
        Some(doc! { "source": "linkedin" }),
    )
    .await;
    let org_c = org(&app, c, "org-c", at(39, 10)).await;
    device(&app, org_c, at(38, 10), false).await;

    // D: signed up 2 days ago, no org yet. Org pending.
    let d = ObjectId::new();
    user(
        &app,
        d,
        "d@test.io",
        at(2, 10),
        Some(doc! { "source": "youtube" }),
    )
    .await;

    // An excluded user (explicit) with an org and a device: absent.
    let x = ObjectId::new();
    user(
        &app,
        x,
        "x@test.io",
        at(40, 10),
        Some(doc! { "source": "youtube" }),
    )
    .await;
    let org_x = org(&app, x, "org-x", at(39, 10)).await;
    device(&app, org_x, at(38, 10), false).await;
    rc_session(&app, org_x, at(37, 10), at(37, 10).checked_add_min(10)).await;
    let r = app
        .auth_put("/api/admin/growth/exclusions", &token)
        .json(&json!({ "exclusions": [ { "kind": "user", "id": x.to_hex(), "reason": "field tester" } ] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

    // Fold the sources into growth_org_daily (the funnel reads first value
    // from it). Over the whole seeded span.
    let rep = org_daily::recompute_range(
        &app.state,
        org_daily::parse_day_of(at(41, 0)),
        org_daily::parse_day_of(at(1, 0)),
        DateTime::now(),
    )
    .await
    .unwrap();
    assert!(rep.rows >= 2, "A and X have value days: {rep:?}");

    let j: Value = app
        .auth_get(
            &format!(
                "/api/admin/growth/funnel?since={}&by=source",
                at(60, 0).timestamp_millis() / 1000
            ),
            &token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    println!("FUNNEL {}", serde_json::to_string_pretty(&j).unwrap());

    assert_eq!(j["enabled"], true);
    assert_eq!(
        j["excluded"],
        json!({ "users": 2, "tenants": 2 }),
        "x + admin, their orgs"
    );
    assert_eq!(j["value_basis"], json!(["remote", "conference", "network"]));
    // signups: a, b, c, d (x and admin excluded).
    assert_eq!(j["steps"]["signup"], 4);
    // org_created: a, b, c reached; d pending. settled = 4 − 1.
    assert_eq!(step(&j, "org_created"), (3, 1, 3));
    // activated: a, c reached; b cold; d pending (its org window is open, so
    // the later steps are pending too).
    assert_eq!(step(&j, "activated"), (2, 1, 3));
    // first value: a only; b, c cold; d pending.
    assert_eq!(step(&j, "first_value"), (1, 1, 3));
    // P4 — paid is measured (saas is mounted) and nobody paid: a measured
    // zero; d is still pending at the org step.
    assert_eq!(step(&j, "paid"), (0, 1, 3));
    // Time to value has its n.
    assert_eq!(j["time_to_value"]["first_device"]["n"], 2);
    assert_eq!(j["time_to_value"]["first_value"]["n"], 1);

    // By source: youtube (a + d), linkedin (c), none (b).
    let bucket = |key: &str| {
        j["buckets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["key"] == json!(key))
            .cloned()
            .unwrap_or_else(|| panic!("no bucket {key}"))
    };
    let yt = bucket("youtube");
    assert_eq!(yt["signups"], 2, "a normalised from YouTub, plus d");
    assert_eq!(yt["org_created"]["count"], 1);
    assert_eq!(yt["org_created"]["pending"], 1, "d's org window is open");
    assert_eq!(yt["first_value"]["count"], 1);
    assert_eq!(bucket("linkedin")["signups"], 1);

    // Nothing about a person anywhere in the payload.
    let text = j.to_string();
    assert!(!text.contains('@'), "an address leaked: {text}");
    assert!(!text.contains("A Person"), "a name leaked");
}

/// AC6 — without `fleet`, `activated` and `first_value` are `null` with the
/// module named, never 0; `org_created` is still measured.
#[tokio::test]
async fn unmounted_steps_are_null_with_the_module_named() {
    let (app, _admin, token) = admin_app(false).await;
    let a = ObjectId::new();
    user(
        &app,
        a,
        "a@test.io",
        at(40, 10),
        Some(doc! { "source": "youtube" }),
    )
    .await;
    org(&app, a, "org-a", at(39, 10)).await;

    let j: Value = app
        .auth_get(
            &format!(
                "/api/admin/growth/funnel?since={}",
                at(60, 0).timestamp_millis() / 1000
            ),
            &token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(j["steps"]["signup"], 1);
    assert_eq!(j["steps"]["org_created"]["count"], 1);
    assert!(j["steps"]["activated"].is_null(), "{}", j["steps"]);
    assert!(j["steps"]["first_value"].is_null());
    assert!(j["time_to_value"]["first_device"].is_null());
    assert_eq!(
        j["not_measured"]["activated"], "fleet module not mounted",
        "{}",
        j["not_measured"]
    );
    assert!(
        j["not_measured"]["first_value"]
            .as_str()
            .unwrap()
            .contains("fleet")
    );
    // `conference` does not depend on `fleet`, so calls stay a value module
    // without it and the basis says so; `first_value` is still null above
    // because activation (a device) precedes value and devices are unseen.
    assert_eq!(j["value_basis"], json!(["conference"]));
}

/// AC7's follow-up — a bare-day `until` is the WHOLE day, as on every other
/// growth route, so `since=D&until=D` counts a sign-up made at noon on D (it
/// was a 400 "since must be before until"). An instant `until` keeps its
/// exclusive meaning: the same day spelled as its midnight is an empty window.
#[tokio::test]
async fn a_bare_day_until_is_the_whole_day() {
    let (app, _admin, token) = admin_app(true).await;
    let a = ObjectId::new();
    user(
        &app,
        a,
        "a@test.io",
        ago(3),
        Some(doc! { "source": "youtube" }),
    )
    .await;
    let day = |days_ago: i64| {
        (org_daily::parse_day_of(DateTime::now()) - chrono::Duration::days(days_ago))
            .format("%Y-%m-%d")
            .to_string()
    };
    let (d, next) = (day(3), day(2));

    let r = app
        .auth_get(
            &format!("/api/admin/growth/funnel?since={d}&until={d}"),
            &token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let j: Value = r.json().await.unwrap();
    assert_eq!(j["steps"]["signup"], 1, "{}", j["steps"]);

    // The window is exactly that day: the next one holds no sign-up.
    let j: Value = app
        .auth_get(
            &format!("/api/admin/growth/funnel?since={next}&until={next}"),
            &token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(j["steps"]["signup"], 0, "{}", j["steps"]);

    // An instant is exact: D's midnight as `until` ends the window where it
    // starts.
    let r = app
        .auth_get(
            &format!("/api/admin/growth/funnel?since={d}&until={d}T00:00:00Z"),
            &token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
}

/// AC8 — a day's tunnel and SSH use is folded into `growth_org_daily`, and
/// the row still reports it after the audit rows are deleted (the 90-day
/// TTL). Deleting the org removes its rows (and its frozen daily rows).
#[tokio::test]
async fn org_daily_outlives_the_audit_rows_and_dies_with_the_org() {
    let (app, _admin, _token) = admin_app(true).await;
    let a = ObjectId::new();
    user(&app, a, "a@test.io", at(100, 9), None).await;
    let org_a = org(&app, a, "org-a", at(100, 9)).await;
    // A day 100 days ago — past every audit TTL — with a tunnel flow and an
    // SSH grant, and nothing else. All three on that one UTC day.
    tunnel_flow(&app, org_a, at(100, 10)).await;
    tunnel_flow(&app, org_a, at(100, 11)).await;
    ssh_grant(&app, org_a, at(100, 12)).await;

    let day = org_daily::parse_day_of(at(100, 0));
    org_daily::recompute_range(&app.state, day, day, DateTime::now())
        .await
        .unwrap();

    let dao = GrowthDao::new(&app.db);
    let read = |value_only: bool| {
        let dao = GrowthDao::new(&app.db);
        let d = org_daily::day_str_of(day);
        async move {
            dao.org_days_between(Some(&[org_a]), &[], &d, &d, value_only)
                .await
                .unwrap()
        }
    };
    let rows = read(false).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let row: &OrgDay = &rows[0];
    assert_eq!(row.tunnel_flows, 2);
    assert_eq!(row.ssh_sessions, 1);
    assert!(row.value);
    assert_eq!(
        row.value_kinds,
        vec!["tunnel".to_string(), "ssh".to_string()]
    );

    // Simulate the 90-day TTL: the audit rows are gone.
    for coll in ["tunnel_audit", "ssh_audit"] {
        app.db
            .collection::<Document>(coll)
            .delete_many(doc! { "tenant_id": org_a })
            .await
            .unwrap();
    }
    // The frozen row still reports the use — the whole reason it exists.
    let after = read(true).await;
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].tunnel_flows, 2);
    assert_eq!(after[0].ssh_sessions, 1);

    // A frozen daily row keyed by this tenant, to prove the purge takes it.
    insert(
        &app,
        "growth_daily",
        doc! { "day": "2026-01-01", "source": "quota", "metric": "collision",
        "dims": { "tenant": org_a.to_hex() }, "value": 1_i64 },
    )
    .await;

    // Deleting the org removes its rows.
    let purged = dao.purge_tenant(org_a).await.unwrap();
    assert_eq!(purged.org_days, 1);
    assert_eq!(purged.daily, 1);
    assert!(read(false).await.is_empty(), "the org's rows are gone");
    // Idempotent.
    let again = dao.purge_tenant(org_a).await.unwrap();
    assert_eq!((again.org_days, again.daily), (0, 0));
}

/// Cohorts: two creation weeks, known value days in known weeks, the
/// north-star WAO beside them. Seeded straight into `growth_org_daily`.
#[tokio::test]
async fn cohorts_count_active_orgs_by_week_since_creation() {
    let (app, _admin, token) = admin_app(true).await;
    // Two orgs created ~8 weeks ago (same cohort week), one ~4 weeks ago.
    let early = at(56, 12);
    let late = at(28, 12);
    let (o1, o2, o3) = (
        org(&app, ObjectId::new(), "o1", early).await,
        org(&app, ObjectId::new(), "o2", early).await,
        org(&app, ObjectId::new(), "o3", late).await,
    );
    // Value days land ON a creation day (W0) or exactly 28 days later (W4):
    // adding 28 days keeps the weekday, so the week offset is exact
    // whatever today's weekday is. Seeded by a direct insert (a serialised
    // struct, never a hand-built doc!) — grouping is not needed, and
    // `replace_day`'s real path is already exercised by the AC8 test.
    let value_day = |tenant: ObjectId, days: i64| {
        let d = ago(days);
        let day = org_daily::day_str_of(org_daily::parse_day_of(d));
        OrgDay {
            id: OrgDay::id_of(&tenant, &day),
            tenant_id: tenant,
            day,
            day_start: DateTime::from_millis(
                org_daily::parse_day_of(d)
                    .and_hms_opt(0, 0, 0)
                    .unwrap()
                    .and_utc()
                    .timestamp_millis(),
            ),
            rc_sessions: 1,
            rc_session_minutes: 5.0,
            rc_controllers: 1,
            calls: 0,
            call_participant_minutes: 0.0,
            tunnel_flows: 0,
            ssh_sessions: 0,
            exec_runs: 0,
            devices_online: 1,
            members_active: 1,
            value: true,
            value_kinds: vec!["rc".into()],
            computed_at: DateTime::now(),
        }
    };
    for row in [
        value_day(o1, 56), // o1 W0 (its creation day)
        value_day(o1, 28), // o1 W4 (exactly 4 weeks later)
        value_day(o2, 56), // o2 W0
        value_day(o3, 28), // o3 W0 (its own creation day)
    ] {
        app.db
            .collection::<Document>("growth_org_daily")
            .insert_one(bson::to_document(&row).unwrap())
            .await
            .unwrap();
    }

    let j: Value = app
        .auth_get("/api/admin/growth/cohorts?unit=week", &token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    println!("COHORTS {}", serde_json::to_string_pretty(&j).unwrap());
    assert_eq!(j["enabled"], true);
    let cohorts = j["cohorts"].as_array().unwrap();
    // The early cohort: 2 orgs, both active in W0, one in W4.
    let early_row = cohorts
        .iter()
        .find(|c| c["size"] == 2)
        .expect("the early cohort");
    assert_eq!(early_row["active"][0], 2);
    assert_eq!(early_row["active"][4], 1);
    // WAO: the current series spans 13 entries, last one partial.
    let wao = j["wao"].as_array().unwrap();
    assert_eq!(wao.len(), 13);
    assert_eq!(wao.last().unwrap()["partial"], true);
    assert!(wao.iter().any(|w| w["active_orgs"].as_i64().unwrap() >= 1));
}

/// The org list and one org's timeline: the owner's channel, devices, the
/// last value day, and the milestones — never a person.
#[tokio::test]
async fn the_org_views_carry_the_channel_and_milestones() {
    let (app, _admin, token) = admin_app(true).await;
    let a = ObjectId::new();
    user(
        &app,
        a,
        "a@test.io",
        at(40, 10),
        Some(doc! { "source": "linkedin", "medium": "post", "referrer_host": "linkedin.com" }),
    )
    .await;
    let org_a = org(&app, a, "org-a", at(39, 11)).await;
    device(&app, org_a, at(38, 10), false).await;
    rc_session(&app, org_a, at(37, 10), at(37, 10).checked_add_min(10)).await;
    let day = org_daily::parse_day_of(at(37, 0));
    org_daily::recompute_range(&app.state, day, day, DateTime::now())
        .await
        .unwrap();

    let list: Value = app
        .auth_get("/api/admin/growth/orgs", &token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = list["orgs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["tenant_id"] == json!(org_a.to_hex()))
        .expect("org-a in the list");
    assert_eq!(row["owner"]["channel"], "social");
    assert_eq!(row["owner"]["source"], "linkedin");
    assert_eq!(row["devices"]["enrolled"], 1);
    assert!(row["last_value_day"].is_string());
    assert_eq!(row["at_risk"], false, "active recently");

    let tl: Value = app
        .auth_get(
            &format!("/api/admin/growth/org/{}/timeline", org_a.to_hex()),
            &token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    println!("TIMELINE {}", serde_json::to_string_pretty(&tl).unwrap());
    let kinds: Vec<&str> = tl["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"signup"));
    assert!(kinds.contains(&"org_created"));
    assert!(kinds.contains(&"first_device"));
    assert!(kinds.contains(&"first_value"));
    assert_eq!(tl["totals"]["rc_sessions"], 1);
    assert_eq!(tl["members"], 1);
    // A missing org 404s.
    let r = app
        .auth_get(
            &format!(
                "/api/admin/growth/org/{}/timeline",
                ObjectId::new().to_hex()
            ),
            &token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
    let text = tl.to_string() + &list.to_string();
    assert!(!text.contains('@'), "an address leaked");
    assert!(!text.contains("A Person"), "a name leaked");
}

/// Every P2 route 404s a non-admin, and the backfill is bounded to closed
/// days.
#[tokio::test]
async fn the_routes_404_a_non_admin_and_the_backfill_is_bounded() {
    let (app, _admin, token) = admin_app(true).await;
    let plain = app
        .register_user(
            "plain@test.io",
            "plain",
            "Plain",
            "Password123!",
            None,
            None,
        )
        .await;
    for path in [
        "/api/admin/growth/funnel",
        "/api/admin/growth/cohorts",
        "/api/admin/growth/orgs",
        &format!(
            "/api/admin/growth/org/{}/timeline",
            ObjectId::new().to_hex()
        ),
    ] {
        let r = app
            .auth_get(path, &plain.access_token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 404, "{path}");
    }
    let r = app
        .auth_post(
            "/api/admin/growth/org-daily/backfill?since=2026-01-01",
            &plain.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);

    // The admin's backfill of a closed range runs; a bad `by` is a 400.
    let r = app
        .auth_post(
            &format!(
                "/api/admin/growth/org-daily/backfill?since={}",
                day_str_of_ago(10)
            ),
            &token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{}", r.text().await.unwrap());
    let r = app
        .auth_get("/api/admin/growth/funnel?by=nonsense", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    // And the exclusion set is the same object the digest uses.
    let set = ExclusionSet::load(&app.state.core).await.unwrap();
    assert_eq!(set.counts().0, 1, "the platform admin");
}

fn day_str_of_ago(days: i64) -> String {
    org_daily::day_str_of(org_daily::parse_day_of(ago(days)))
}

/// `(count, pending, settled)` of a funnel step.
fn step(j: &Value, name: &str) -> (i64, i64, i64) {
    let s = &j["steps"][name];
    (
        s["count"].as_i64().unwrap_or(-1),
        s["pending"].as_i64().unwrap_or(-1),
        s["settled"].as_i64().unwrap_or(-1),
    )
}

/// `DateTime` + minutes, for the session helpers.
trait AddMin {
    fn checked_add_min(self, m: i64) -> DateTime;
}
impl AddMin for DateTime {
    fn checked_add_min(self, m: i64) -> DateTime {
        DateTime::from_millis(self.timestamp_millis() + m * 60_000)
    }
}
