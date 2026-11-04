// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P6 — the purestat puller and the Campaigns table, against a real
//! server and a fake purestat (spec §3i).
//!
//! * **The puller** (`saas::purestat_pull::run_once`, an injected clock):
//!   the seven closed days of the horizon are pulled once per cycle into
//!   `growth_daily` with one `growth_pulls` row each; a second run of the
//!   same cycle asks nothing; the next cycle re-pulls the horizon and
//!   changes no row whose value held (idempotent, never doubled); a day
//!   past the horizon is frozen and never rewritten; a 401 is recorded as a
//!   failed pull — one request, every owed day — and never as a zero; a
//!   pulled day stays `ok` through a later failure; a site without goals
//!   still pulls its visitors.
//! * **The Campaigns table** (`GET /api/admin/growth/campaigns`): the web
//!   plane (live, for the exact range) and the account plane joined by the
//!   normalised key; a revoked key makes every web cell `not_measured`,
//!   never 0, with the account plane intact (AC16's control); an unmounted
//!   module is named; the route hides from everyone but a platform admin.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use chrono::NaiveDate;
use meshharbor_api::growth::org_daily;
use meshharbor_mod_saas::purestat_pull;
use meshharbor_services::{
    dao::growth::{GROWTH_DAILY, GROWTH_PULLS, GrowthDao, PURESTAT_SOURCE, PullStatus},
    purestat::PurestatClient,
};
use serde_json::{Map, Value, json};

use crate::fixtures::test_app::TestApp;

// ── A fake purestat ─────────────────────────────────────────────────────

pub(crate) type Seen = Arc<Mutex<Vec<(Option<String>, Value)>>>;

#[derive(Clone, Default)]
pub(crate) struct Fake {
    pub(crate) seen: Seen,
}

/// The fake's whole site, at the finest grain the contract allows: four
/// UTM dimensions per row. A coarser breakdown is the sum of these grouped
/// by the dimensions asked (good enough for a fake: real purestat counts
/// unique visitors per breakdown, which the views never sum).
fn campaign_base() -> Vec<(Value, Value, Value)> {
    vec![
        (
            json!({ "utm_source": "LinkedIn", "utm_medium": "post", "utm_campaign": "C1", "utm_content": null }),
            json!({ "visitors": 52, "visits": 60, "pageviews": 265, "reads": 30 }),
            json!({ "signup": 1 }),
        ),
        (
            json!({ "utm_source": "linkedin", "utm_medium": "Post", "utm_campaign": "c1", "utm_content": null }),
            json!({ "visitors": 3, "visits": 3, "pageviews": 3, "reads": 0 }),
            json!({}),
        ),
        (
            json!({ "utm_source": "youtub", "utm_medium": "video", "utm_campaign": "20261019-ssh", "utm_content": "desc-top" }),
            json!({ "visitors": 7, "visits": 7, "pageviews": 9, "reads": 2 }),
            json!({ "subscribe": 1 }),
        ),
        (
            json!({ "utm_source": null, "utm_medium": null, "utm_campaign": null, "utm_content": null }),
            json!({ "visitors": 20, "visits": 21, "pageviews": 40, "reads": 5 }),
            json!({ "signup": 1 }),
        ),
    ]
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Keep the asked metrics / goals of a row, summing into `into`.
fn add_into(into: &mut Map<String, Value>, from: &Value, asked: &[String]) {
    for k in asked {
        let add = from.get(k).and_then(Value::as_f64).unwrap_or(0.0);
        let cur = into.get(k).and_then(Value::as_f64).unwrap_or(0.0);
        into.insert(k.clone(), json!(cur + add));
    }
}

fn answer(body: &Value, goals_defined: bool) -> Result<Value, (StatusCode, Value)> {
    let dims = strs(&body["dimensions"]);
    let metrics = strs(&body["metrics"]);
    let goals = strs(&body["goals"]);
    if !goals.is_empty() && !goals_defined {
        return Err((
            StatusCode::BAD_REQUEST,
            json!({ "error": "unknown goal: \"signup\"" }),
        ));
    }
    let mut rows: Vec<Value> = Vec::new();
    if dims.is_empty() {
        let (mut m, mut g) = (Map::new(), Map::new());
        add_into(
            &mut m,
            &json!({ "visitors": 44, "visits": 77, "pageviews": 241, "reads": 12 }),
            &metrics,
        );
        add_into(&mut g, &json!({ "signup": 2, "subscribe": 1 }), &goals);
        rows.push(json!({ "dimensions": {}, "metrics": m, "goals": g }));
    } else if dims == ["path"] {
        for (path, v, pv, reads) in [("/blog/a/", 10, 12, 4), ("/pricing", 5, 5, 0)] {
            let all = json!({ "visitors": v, "pageviews": pv, "reads": reads, "visits": null });
            let mut m = Map::new();
            add_into(&mut m, &all, &metrics);
            rows.push(json!({ "dimensions": { "path": path }, "metrics": m, "goals": {} }));
        }
    } else {
        /// One breakdown row: its dimensions, metrics and goals.
        type Group = (Map<String, Value>, Map<String, Value>, Map<String, Value>);
        let mut grouped: BTreeMap<String, Group> = BTreeMap::new();
        for (d, m, g) in campaign_base() {
            let key: Map<String, Value> = dims
                .iter()
                .map(|k| (k.clone(), d.get(k).cloned().unwrap_or(Value::Null)))
                .collect();
            let slot = grouped
                .entry(Value::Object(key.clone()).to_string())
                .or_insert_with(|| (key, Map::new(), Map::new()));
            add_into(&mut slot.1, &m, &metrics);
            add_into(&mut slot.2, &g, &goals);
        }
        for (_, (d, m, g)) in grouped {
            rows.push(json!({ "dimensions": d, "metrics": m, "goals": g }));
        }
    }
    Ok(json!({ "rows": rows, "meta": {
        "site_domain": "meshharbor.itachi.fans", "hostnames": ["meshharbor.itachi.fans"],
        "date_from": body["date_from"], "date_to": body["date_to"],
        "limit": 100, "offset": 0, "has_more": false,
    } }))
}

async fn fake_query(
    State(f): State<Fake>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    f.seen.lock().unwrap().push((key.clone(), body.clone()));
    let goals_defined = match key.as_deref() {
        Some("good") => true,
        Some("nogoals") => false,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "unauthorized" })),
            );
        }
    };
    match answer(&body, goals_defined) {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err((s, v)) => (s, Json(v)),
    }
}

pub(crate) async fn fake_purestat() -> (String, Fake) {
    let fake = Fake::default();
    let router = Router::new()
        .route("/api/v1/query", post(fake_query))
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), fake)
}

// ── Days and seeds ──────────────────────────────────────────────────────

pub(crate) fn today() -> NaiveDate {
    org_daily::parse_day_of(DateTime::now())
}

pub(crate) fn ds(day: NaiveDate) -> String {
    org_daily::day_str_of(day)
}

/// `day` at `h:00` UTC.
pub(crate) fn at_day(day: NaiveDate, h: u32) -> DateTime {
    DateTime::from_millis(
        day.and_hms_opt(h, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp_millis(),
    )
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
    insert(
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
    .await
}

async fn device(app: &TestApp, tenant: ObjectId, created: DateTime) {
    insert(
        app,
        "agents",
        doc! {
            "tenant_id": tenant, "owner_user_id": ObjectId::new(), "name": "box",
            "machine_id": format!("m-{}", ObjectId::new()), "os": "linux",
            "agent_version": "0.4.135", "status": "offline",
            "created_at": created, "updated_at": created, "deleted_at": Bson::Null,
        },
    )
    .await;
}

/// A platform-admin app pointed at `purestat` with `key`; `tweak` adjusts
/// the rest. The admin and their org exist (and are excluded implicitly).
pub(crate) async fn admin_app(
    purestat: &str,
    key: &str,
    tweak: impl FnOnce(&mut meshharbor_config::Settings),
) -> (TestApp, String) {
    let admin_id = ObjectId::new();
    let (base, key) = (purestat.to_string(), key.to_string());
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
        s.growth.purestat_url = base;
        s.growth.purestat_api_key = key;
        tweak(s);
    })
    .await;
    let token = app
        .state
        .auth
        .generate_tokens(admin_id, "padmin@test.io", "padmin")
        .unwrap()
        .access_token;
    let y = today() - chrono::Duration::days(1);
    user(&app, admin_id, "padmin@test.io", at_day(y, 8), None).await;
    org(&app, admin_id, "admin-org", at_day(y, 8)).await;
    (app, token)
}

/// Yesterday's sign-ups: LinkedIn/post/C1 (an org and a device: activated),
/// x/post/c9 (no web row), youtube/video/20261019-SSH/Desc-Top, and one
/// organic. Stored as ingress stores them: source and medium normalised,
/// campaign and content as sent.
pub(crate) async fn seed_signups(app: &TestApp) -> NaiveDate {
    let y = today() - chrono::Duration::days(1);
    let li = ObjectId::new();
    user(
        app,
        li,
        "li@test.io",
        at_day(y, 10),
        Some(doc! { "source": "linkedin", "medium": "post", "campaign": "C1" }),
    )
    .await;
    let t = org(app, li, "li-org", at_day(y, 11)).await;
    device(app, t, at_day(y, 12)).await;
    user(
        app,
        ObjectId::new(),
        "x@test.io",
        at_day(y, 13),
        Some(doc! { "source": "x", "medium": "post", "campaign": "c9" }),
    )
    .await;
    user(
        app,
        ObjectId::new(),
        "yt@test.io",
        at_day(y, 14),
        Some(doc! { "source": "youtube", "medium": "video", "campaign": "20261019-SSH", "content": "Desc-Top" }),
    )
    .await;
    user(app, ObjectId::new(), "organic@test.io", at_day(y, 15), None).await;
    y
}

pub(crate) async fn get_json(app: &TestApp, path: &str, token: &str) -> (u16, Value) {
    let r = app.auth_get(path, token).send().await.unwrap();
    let status = r.status().as_u16();
    let text = r.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

pub(crate) fn row<'a>(j: &'a Value, source: &str, campaign: Option<&str>) -> &'a Value {
    j["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["key"]["source"] == source
                && match campaign {
                    Some(c) => r["key"]["campaign"] == c,
                    None => true,
                }
        })
        .unwrap_or_else(|| panic!("no {source}/{campaign:?} row in {}", j["rows"]))
}

async fn daily_value(app: &TestApp, day: &str, metric: &str, dims: Document) -> Option<i64> {
    let mut filter = doc! { "source": PURESTAT_SOURCE, "day": day, "metric": metric };
    for (k, v) in dims {
        filter.insert(format!("dims.{k}"), v);
    }
    app.db
        .collection::<Document>(GROWTH_DAILY)
        .find_one(filter)
        .await
        .unwrap()
        .and_then(|d| d.get_i64("value").ok())
}

pub(crate) async fn count(app: &TestApp, coll: &str, filter: Document) -> u64 {
    app.db
        .collection::<Document>(coll)
        .count_documents(filter)
        .await
        .unwrap()
}

// ── The puller ──────────────────────────────────────────────────────────

/// The horizon pulled once per cycle, the next cycle idempotent, and a
/// frozen day never rewritten.
#[tokio::test]
async fn the_puller_freezes_seven_closed_days_once_and_never_rewrites_a_frozen_one() {
    let (base, fake) = fake_purestat().await;
    let app = TestApp::spawn().await;
    let client = PurestatClient::new(&base, "good").unwrap();
    let t = today();
    let now = at_day(t, 12);

    let r1 = purestat_pull::run_once(&app.state.core, &client, now)
        .await
        .unwrap();
    assert_eq!((r1.pulled, r1.failed), (7, 0), "{r1:?}");
    assert_eq!(r1.due.first(), Some(&ds(t - chrono::Duration::days(7))));
    assert_eq!(r1.due.last(), Some(&ds(t - chrono::Duration::days(1))));
    assert!(!r1.due.contains(&ds(t)), "today is never pulled");
    // Three breakdowns a day, nothing else.
    assert_eq!(fake.seen.lock().unwrap().len(), 21);

    let y = ds(t - chrono::Duration::days(1));
    // The site row, the campaign key folded from two spellings, the paths.
    assert_eq!(
        daily_value(&app, &y, "visitors", doc! { "by": "site" }).await,
        Some(44)
    );
    assert_eq!(
        daily_value(&app, &y, "goal.signup", doc! { "by": "site" }).await,
        Some(2)
    );
    let li = doc! { "by": "campaign", "source": "linkedin", "medium": "post", "campaign": "c1" };
    assert_eq!(
        daily_value(&app, &y, "visitors", li.clone()).await,
        Some(55)
    );
    assert_eq!(daily_value(&app, &y, "visits", li.clone()).await, Some(63));
    assert_eq!(
        daily_value(&app, &y, "goal.signup", li.clone()).await,
        Some(1)
    );
    assert_eq!(
        daily_value(
            &app,
            &y,
            "visitors",
            doc! { "by": "campaign", "source": "youtube", "content": "desc-top" }
        )
        .await,
        Some(7)
    );
    assert_eq!(
        daily_value(
            &app,
            &y,
            "pageviews",
            doc! { "by": "path", "path": "/blog/a/" }
        )
        .await,
        Some(12)
    );
    // Organic traffic has no campaign row; a zero is not stored.
    assert_eq!(
        count(
            &app,
            GROWTH_DAILY,
            doc! { "dims.by": "campaign", "day": y.as_str(), "dims.source": { "$exists": false } }
        )
        .await,
        0
    );
    assert_eq!(
        daily_value(&app, &y, "reads", doc! { "by": "path", "path": "/pricing" }).await,
        None
    );

    let per_day = count(&app, GROWTH_DAILY, doc! { "day": y.as_str() }).await;
    assert!(per_day > 10, "{per_day}");
    assert_eq!(
        count(&app, GROWTH_DAILY, doc! { "source": PURESTAT_SOURCE }).await,
        7 * per_day
    );
    let pulls = GrowthDao::new(&app.db)
        .pulls_between(PURESTAT_SOURCE, &ds(t - chrono::Duration::days(30)), &ds(t))
        .await
        .unwrap();
    assert_eq!(pulls.len(), 7);
    assert!(pulls.iter().all(|p| p.status == PullStatus::Ok
        && p.attempts == 1
        && p.rows as u64 == per_day
        && p.error.is_none()
        && p.missing_goal.is_none()));

    // The same cycle again: nothing owed, nothing asked.
    let r2 = purestat_pull::run_once(&app.state.core, &client, at_day(t, 18))
        .await
        .unwrap();
    assert!(r2.due.is_empty(), "{r2:?}");
    assert_eq!(fake.seen.lock().unwrap().len(), 21);

    // The next cycle re-pulls the horizon: one new day written, the six it
    // shares unchanged — nothing doubled.
    let r3 = purestat_pull::run_once(
        &app.state.core,
        &client,
        at_day(t + chrono::Duration::days(1), 2),
    )
    .await
    .unwrap();
    assert_eq!(r3.pulled, 7);
    assert_eq!(r3.rows_written, per_day, "only the new day is written");
    assert_eq!(r3.rows_unchanged, 6 * per_day);
    assert_eq!(
        count(&app, GROWTH_DAILY, doc! { "source": PURESTAT_SOURCE }).await,
        8 * per_day
    );
    assert_eq!(
        daily_value(&app, &y, "visitors", li.clone()).await,
        Some(55),
        "never doubled"
    );

    // Frozen: the oldest day (age 9 two cycles on) is never rewritten, a
    // day inside the horizon is.
    let oldest = ds(t - chrono::Duration::days(7));
    for day in [oldest.as_str(), y.as_str()] {
        app.db
            .collection::<Document>(GROWTH_DAILY)
            .update_one(
                doc! { "source": PURESTAT_SOURCE, "day": day, "metric": "visitors", "dims.by": "site" },
                doc! { "$set": { "value": 999_i64 } },
            )
            .await
            .unwrap();
    }
    let r4 = purestat_pull::run_once(
        &app.state.core,
        &client,
        at_day(t + chrono::Duration::days(2), 3),
    )
    .await
    .unwrap();
    assert!(!r4.due.contains(&oldest));
    assert_eq!(
        daily_value(&app, &oldest, "visitors", doc! { "by": "site" }).await,
        Some(999),
        "a frozen day is never rewritten"
    );
    assert_eq!(
        daily_value(&app, &y, "visitors", doc! { "by": "site" }).await,
        Some(44),
        "a day inside the horizon is re-pulled"
    );
}

/// A revoked key: one request, every owed day recorded `failed` with the
/// reason, and not a single row — "not pulled" is never a 0. The next
/// good tick of the same cycle catches up; a later failure leaves a pulled
/// day `ok`. A site without goals still pulls its visitors.
#[tokio::test]
async fn a_failed_pull_is_recorded_never_a_zero_and_a_pulled_day_stays_ok() {
    let (base, fake) = fake_purestat().await;
    let app = TestApp::spawn().await;
    let t = today();
    let bad = PurestatClient::new(&base, "revoked").unwrap();
    let r = purestat_pull::run_once(&app.state.core, &bad, at_day(t, 2))
        .await
        .unwrap();
    assert_eq!((r.pulled, r.failed), (0, 7));
    assert!(
        r.error.as_deref().unwrap().contains("unauthorized"),
        "{r:?}"
    );
    assert_eq!(
        fake.seen.lock().unwrap().len(),
        1,
        "a fatal error stops the asking"
    );
    assert_eq!(
        count(&app, GROWTH_DAILY, doc! { "source": PURESTAT_SOURCE }).await,
        0
    );
    let pulls = GrowthDao::new(&app.db)
        .pulls_between(PURESTAT_SOURCE, &ds(t - chrono::Duration::days(30)), &ds(t))
        .await
        .unwrap();
    assert_eq!(pulls.len(), 7);
    assert!(pulls.iter().all(|p| {
        p.status == PullStatus::Failed
            && p.pulled_at.is_none()
            && p.error
                .as_deref()
                .is_some_and(|e| e.contains("unauthorized"))
    }));

    // The key fixed, the same cycle: the failed days are due again.
    let good = PurestatClient::new(&base, "good").unwrap();
    let r = purestat_pull::run_once(&app.state.core, &good, at_day(t, 3))
        .await
        .unwrap();
    assert_eq!((r.pulled, r.failed), (7, 0));

    // Revoked again next cycle: the six days already pulled stay `ok` (their
    // rows are the last good pull's), the new day is `failed`.
    let r = purestat_pull::run_once(
        &app.state.core,
        &bad,
        at_day(t + chrono::Duration::days(1), 2),
    )
    .await
    .unwrap();
    assert_eq!(r.failed, 7);
    let pulls = GrowthDao::new(&app.db)
        .pulls_between(PURESTAT_SOURCE, &ds(t - chrono::Duration::days(30)), &ds(t))
        .await
        .unwrap();
    let ok: Vec<_> = pulls
        .iter()
        .filter(|p| p.status == PullStatus::Ok)
        .collect();
    assert_eq!(ok.len(), 7, "pulled days stay ok through a failure");
    let oldest = ds(t - chrono::Duration::days(7));
    for p in &ok {
        if p.day == oldest {
            // Frozen by the third run's clock: not attempted again.
            assert!(p.error.is_none() && p.attempts == 2, "{p:?}");
        } else {
            assert!(p.error.is_some() && p.attempts == 3, "{p:?}");
            assert!(p.pulled_at.is_some());
        }
    }
    let today_pull = pulls.iter().find(|p| p.day == ds(t)).unwrap();
    assert_eq!(today_pull.status, PullStatus::Failed);
    assert_eq!(count(&app, GROWTH_PULLS, doc! {}).await, 8);

    // A site that defines no goals: visitors pulled, conversions named.
    let app2 = TestApp::spawn().await;
    let nogoals = PurestatClient::new(&base, "nogoals").unwrap();
    let r = purestat_pull::run_once(&app2.state.core, &nogoals, at_day(t, 2))
        .await
        .unwrap();
    assert_eq!((r.pulled, r.failed), (7, 0));
    let y = ds(t - chrono::Duration::days(1));
    assert_eq!(
        daily_value(&app2, &y, "visitors", doc! { "by": "site" }).await,
        Some(44)
    );
    assert_eq!(
        count(
            &app2,
            GROWTH_DAILY,
            doc! { "metric": { "$regex": "^goal\\." } }
        )
        .await,
        0
    );
    let p = GrowthDao::new(&app2.db)
        .pulls_between(PURESTAT_SOURCE, &y, &y)
        .await
        .unwrap();
    assert_eq!(p[0].missing_goal.as_deref(), Some("signup"));
}

// ── The Campaigns table ─────────────────────────────────────────────────

/// Both planes, joined by the normalised key: purestat's two spellings of
/// LinkedIn/post/C1 are one row beside the sign-up stored as `C1`; a key
/// purestat never saw is a measured zero; a depth cuts the key.
#[tokio::test]
async fn the_campaigns_view_joins_both_planes_by_the_normalised_key() {
    let (base, fake) = fake_purestat().await;
    let (app, token) = admin_app(&base, "good", |_| {}).await;
    let y = seed_signups(&app).await;
    let day = ds(y);

    let (status, j) = get_json(
        &app,
        &format!("/api/admin/growth/campaigns?since={day}&until={day}"),
        &token,
    )
    .await;
    assert_eq!(status, 200, "{j}");
    assert_eq!(
        (j["since"].as_str(), j["until"].as_str()),
        (Some(day.as_str()), Some(day.as_str()))
    );
    assert_eq!(j["by"], "campaign", "the default depth");
    assert!(j.get("web_not_measured").is_none(), "{j}");
    // The live query asked for exactly the range and the breakdown.
    {
        let seen = fake.seen.lock().unwrap();
        assert!(seen.iter().any(|(_, b)| b["date_from"] == day.as_str()
            && b["date_to"] == day.as_str()
            && b["dimensions"] == json!(["utm_source", "utm_medium", "utm_campaign"])));
    }

    let li = row(&j, "linkedin", Some("c1"));
    assert_eq!(li["key"]["medium"], "post");
    assert_eq!(li["web"]["visitors"], 55, "LinkedIn/C1 + linkedin/c1");
    assert_eq!(li["web"]["visits"], 63);
    assert_eq!(li["web"]["spellings"], 2);
    assert_eq!(li["web"]["goals"]["signup"], 1);
    assert_eq!(li["signups"], 1, "the sign-up stored as C1 joins c1");
    assert_eq!(li["org_created"]["count"], 1);
    assert_eq!(li["activated"]["count"], 1);
    assert_eq!(li["coverage"]["purestat_signup_goals"], 1);
    assert_eq!(li["coverage"]["server_signups"], 1);
    assert!(
        li["coverage"].get("ratio").is_none(),
        "no ratio below n = 30"
    );
    assert_eq!(li["rates"]["signup_per_visitor"]["n"], 55);
    // P4 — measured (saas is mounted), nobody paid: a zero, never "P4".
    assert_eq!(li["paid"]["count"], 0);
    assert_eq!(li["paid"]["settled"], 1);
    // P8 — no post was pushed with this key: reach not measured, never 0.
    assert_eq!(
        li["reach"]["not_measured"],
        "no post pushed with this key in the range"
    );
    assert_eq!(li["group"], "linkedin");
    // A key purestat never saw: a measured zero, not "not measured".
    let x = row(&j, "x", Some("c9"));
    assert_eq!(x["web"]["visitors"], 0);
    assert_eq!(x["web"]["spellings"], 0);
    assert_eq!(x["signups"], 1);
    assert_eq!(x["org_created"]["pending"], 1);
    // youtub → youtube; the content cut at this depth.
    let yt = row(&j, "youtube", Some("20261019-ssh"));
    assert_eq!(yt["web"]["visitors"], 7);
    assert_eq!(yt["signups"], 1);
    assert!(yt["key"]["content"].is_null());
    // No organic row; the totals carry it.
    assert_eq!(j["rows"].as_array().unwrap().len(), 3);
    assert_eq!(j["totals"]["web"]["visitors"], 44);
    assert_eq!(
        j["totals"]["signups"], 4,
        "the admin excluded, the organic one counted"
    );
    assert_eq!(j["totals"]["keyed_signups"], 3);
    assert_eq!(j["totals"]["coverage"]["purestat_signup_goals"], 2);
    assert_eq!(j["excluded"]["users"], 1);
    // The daily pull's state for the range: not pulled in this test.
    assert_eq!(j["pulls"]["days"], 1);
    assert_eq!(j["pulls"]["not_pulled"], 1);
    assert!(j["pulls"].get("not_measured").is_none());
    // No person in the answer.
    assert!(!j.to_string().contains("@test.io"), "{j}");

    // Deeper and shallower.
    let (_, j) = get_json(
        &app,
        &format!("/api/admin/growth/campaigns?since={day}&until={day}&by=content"),
        &token,
    )
    .await;
    assert_eq!(row(&j, "youtube", None)["key"]["content"], "desc-top");
    let (_, j) = get_json(
        &app,
        &format!("/api/admin/growth/campaigns?since={day}&until={day}&by=source"),
        &token,
    )
    .await;
    let li = row(&j, "linkedin", None);
    assert!(li["key"]["medium"].is_null() && li["key"]["campaign"].is_null());
    assert_eq!(li["web"]["visitors"], 55);
    // include_internal: the admin's own sign-up counts too.
    let (_, j) = get_json(
        &app,
        &format!("/api/admin/growth/campaigns?since={day}&until={day}&include_internal=true"),
        &token,
    )
    .await;
    assert_eq!(j["totals"]["signups"], 5);
    assert_eq!(j["excluded"]["users"], 0);
}

/// AC16's control: with the key revoked every web cell reads
/// `not_measured` with the reason — never 0 — and the account plane still
/// answers. Without a key, the reason says so and nothing is asked.
#[tokio::test]
async fn a_revoked_purestat_key_reads_not_measured_never_zero() {
    let (base, fake) = fake_purestat().await;
    let (app, token) = admin_app(&base, "revoked", |_| {}).await;
    let y = seed_signups(&app).await;
    let day = ds(y);
    let (status, j) = get_json(
        &app,
        &format!("/api/admin/growth/campaigns?since={day}&until={day}"),
        &token,
    )
    .await;
    assert_eq!(status, 200, "{j}");
    assert!(
        j["web_not_measured"]["not_measured"]
            .as_str()
            .unwrap()
            .contains("unauthorized"),
        "{j}"
    );
    let rows = j["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "the account plane's keys still list");
    for r in rows {
        assert!(
            r["web"]["not_measured"]
                .as_str()
                .unwrap()
                .contains("unauthorized"),
            "{r}"
        );
        assert!(r["web"].get("visitors").is_none(), "never a 0: {r}");
        assert!(r["coverage"]["not_measured"].is_string());
        assert!(r["rates"]["signup_per_visitor"].is_null());
    }
    assert_eq!(row(&j, "linkedin", Some("c1"))["signups"], 1);
    assert!(j["totals"]["web"]["not_measured"].is_string());
    assert!(j["totals"]["coverage"]["not_measured"].is_string());
    assert_eq!(j["totals"]["signups"], 4);
    assert!(!fake.seen.lock().unwrap().is_empty());

    // No key at all: not measured, and purestat is never asked.
    let (app, token) = admin_app(&base, "", |_| {}).await;
    let before = fake.seen.lock().unwrap().len();
    seed_signups(&app).await;
    let (_, j) = get_json(
        &app,
        &format!("/api/admin/growth/campaigns?since={day}&until={day}"),
        &token,
    )
    .await;
    assert_eq!(
        j["web_not_measured"]["not_measured"],
        "purestat key not configured"
    );
    assert_eq!(
        fake.seen.lock().unwrap().len(),
        before,
        "no request without a key"
    );
}

/// A step whose module is unmounted is `null` with the module named; the
/// puller's summary names `saas` when it is not mounted.
#[tokio::test]
async fn unmounted_modules_read_null_with_the_module_named() {
    let (base, _fake) = fake_purestat().await;
    let (app, token) = admin_app(&base, "good", |s| {
        s.modules.fleet = false;
        s.modules.saas = false;
    })
    .await;
    let y = seed_signups(&app).await;
    let day = ds(y);
    let (status, j) = get_json(
        &app,
        &format!("/api/admin/growth/campaigns?since={day}&until={day}"),
        &token,
    )
    .await;
    assert_eq!(status, 200, "{j}");
    assert_eq!(j["not_measured"]["activated"], "fleet module not mounted");
    let li = row(&j, "linkedin", Some("c1"));
    assert!(
        li["activated"].is_null() && li["first_value"].is_null(),
        "{li}"
    );
    assert!(li["rates"]["activation"].is_null());
    // P4 — paid needs `saas` (billing_events): null with the module named.
    assert!(li["paid"].is_null(), "{li}");
    assert!(li["rates"]["paid"].is_null());
    assert_eq!(j["not_measured"]["paid"], "saas module not mounted");
    assert_eq!(li["signups"], 1);
    assert_eq!(
        li["web"]["visitors"], 55,
        "the web plane does not need fleet"
    );
    assert!(
        j["pulls"]["not_measured"]
            .as_str()
            .unwrap()
            .contains("saas module not mounted"),
        "{j}"
    );
}

/// 404 to everyone but a platform admin, and to the admin when the growth
/// surface is off; a bad depth or range is a 400.
#[tokio::test]
async fn the_campaigns_route_hides_from_non_admins_and_refuses_bad_input() {
    let (base, _fake) = fake_purestat().await;
    let (app, token) = admin_app(&base, "good", |_| {}).await;
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
    let (status, _) = get_json(&app, "/api/admin/growth/campaigns", &plain.access_token).await;
    assert_eq!(status, 404);
    // A fresh client: `app.client` keeps the plain user's session cookie.
    let r = reqwest::Client::new()
        .get(app.url("/api/admin/growth/campaigns"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "no credential at all is the extractor's 401"
    );
    for bad in [
        "/api/admin/growth/campaigns?by=channel",
        "/api/admin/growth/campaigns?since=2026-10-10&until=2026-10-01",
        "/api/admin/growth/campaigns?until=2999-01-01",
        "/api/admin/growth/campaigns?since=2020-01-01&until=2026-10-01",
        "/api/admin/growth/campaigns?since=yesterday",
    ] {
        let (status, j) = get_json(&app, bad, &token).await;
        assert_eq!(status, 400, "{bad}: {j}");
    }
    let (status, _) = get_json(&app, "/api/admin/growth/campaigns", &token).await;
    assert_eq!(
        status, 200,
        "the defaults: the 28 closed days ending yesterday"
    );

    let (off, token) = admin_app(&base, "good", |s| s.growth.enabled = false).await;
    let (status, _) = get_json(&off, "/api/admin/growth/campaigns", &token).await;
    assert_eq!(status, 404, "the kill switch hides it from the admin too");
}
