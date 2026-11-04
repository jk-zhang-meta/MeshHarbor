// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P10 — the read key, the weekly roll-up and the alerts, against a
//! real server and a fake purestat (spec §3l, D12).
//!
//! * **AC20**, exactly: a read key gets the same JSON as a platform
//!   admin's session for the same range on every GET view; every write
//!   route — the exclusions PUT, the digest and weekly runs, the backfill,
//!   the keys, the alert evaluation, the ingest routes — answers it the
//!   empty 404 of an absent path, as do the admin surface's GETs, an
//!   ingest key on a view, a malformed, unknown or revoked read key, and
//!   `growth.enabled = false`.
//! * **The weekly roll-up's claim**, mirroring the digest's matrix: two
//!   concurrent scheduled runs store once and mail once; a re-run after
//!   `sent` does nothing; a manual preview never cancels the scheduled
//!   mail; a manual send racing the scheduler mails once; the routes.
//! * **The alerts**: each evaluable rule fires once (one row, one mail),
//!   a second evaluation the same day adds neither, the row clears when
//!   the condition goes away, a re-fire the same day does not mail again,
//!   and the digest's `alerts` section reports the open rows.

use std::{future::Future, pin::Pin, sync::Mutex};

use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use chrono::{Duration, NaiveDate};
use meshharbor_api::growth::{alerts, cohorts::week_start, digest, digest::DigestMailer, weekly};
use meshharbor_services::dao::{
    growth::{BING_SOURCE, GROWTH_PULLS, PURESTAT_SOURCE, SEARCH_CONSOLE_SOURCE},
    growth_alert::GROWTH_ALERTS,
    growth_digest::{DigestStatus, DigestStore, GROWTH_DIGESTS, GROWTH_WEEKLY},
    growth_key::{GrowthKeyDao, GrowthKeyKind},
};
use serde_json::{Value, json};

use crate::{
    fixtures::test_app::TestApp,
    growth_campaigns_tests::{admin_app, at_day, ds, fake_purestat, get_json, seed_signups, today},
};

// ── Helpers ──────────────────────────────────────────────────────────────

/// A mailer that records every attempt and never fails.
#[derive(Default)]
struct Recording {
    sends: Mutex<Vec<(String, String, String, String)>>,
}

impl Recording {
    fn count(&self) -> usize {
        self.sends.lock().unwrap().len()
    }

    fn last(&self) -> (String, String, String, String) {
        self.sends.lock().unwrap().last().cloned().unwrap()
    }
}

impl DigestMailer for Recording {
    fn send<'a>(
        &'a self,
        to: &'a str,
        subject: &'a str,
        html: &'a str,
        text: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        self.sends.lock().unwrap().push((
            to.to_string(),
            subject.to_string(),
            html.to_string(),
            text.to_string(),
        ));
        Box::pin(async { Ok(()) })
    }
}

async fn insert(app: &TestApp, coll: &str, mut d: Document) -> ObjectId {
    let id = ObjectId::new();
    d.insert("_id", id);
    app.db
        .collection::<Document>(coll)
        .insert_one(d)
        .await
        .unwrap_or_else(|e| panic!("insert into {coll}: {e}"));
    id
}

async fn user(app: &TestApp, created: DateTime) -> ObjectId {
    let id = ObjectId::new();
    let email = format!("{}@test.io", id.to_hex());
    app.db
        .collection::<Document>("users")
        .insert_one(doc! {
            "_id": id, "email": &email, "username": id.to_hex(),
            "display_name": "A Person", "avatar": Bson::Null, "bio": Bson::Null,
            "is_verified": true, "is_mfa_enabled": false, "last_active_at": Bson::Null,
            "oauth_providers": [], "created_at": created, "updated_at": created,
            "deleted_at": Bson::Null,
        })
        .await
        .unwrap();
    id
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
            "agent_version": "0.4.136", "status": "offline",
            "created_at": created, "updated_at": created, "deleted_at": Bson::Null,
        },
    )
    .await;
}

/// Mint a key of `kind` as the admin; `(key, id)`.
async fn mint(app: &TestApp, token: &str, kind: &str) -> (String, String) {
    let r = app
        .auth_post("/api/admin/growth/keys", token)
        .json(&json!({ "kind": kind, "label": format!("pipeline ({kind})") }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 201);
    let j: Value = r.json().await.unwrap();
    assert!(
        j["key"]
            .as_str()
            .unwrap()
            .starts_with(if kind == "read" { "rgr_" } else { "rgi_" })
    );
    (
        j["key"].as_str().unwrap().to_string(),
        j["id"].as_str().unwrap().to_string(),
    )
}

/// A request from a client with no cookie jar, with `key` as the bearer
/// (none when `None`): `(status, body text)`.
async fn with_key(
    app: &TestApp,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: Option<&str>,
) -> (u16, String) {
    let client = reqwest::Client::new();
    let url = app.url(path);
    let mut req = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        other => panic!("{other}"),
    };
    if let Some(k) = key {
        req = req.header("authorization", format!("Bearer {k}"));
    }
    if let Some(b) = body {
        req = req
            .header("content-type", "application/json")
            .body(b.to_string());
    }
    let r = req.send().await.unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

fn last_closed_monday() -> NaiveDate {
    week_start(today()) - Duration::weeks(1)
}

fn monday_label(monday: NaiveDate) -> String {
    meshharbor_api::growth::cohorts::week_label(monday)
}

async fn count(app: &TestApp, coll: &str, filter: Document) -> u64 {
    app.db
        .collection::<Document>(coll)
        .count_documents(filter)
        .await
        .unwrap()
}

// ── AC20: the read key ──────────────────────────────────────────────────

#[tokio::test]
async fn ac20_a_read_key_reads_what_the_admin_reads_and_never_writes() {
    let (base, _fake) = fake_purestat().await;
    let (app, token) = admin_app(&base, "good", |_| {}).await;
    let yesterday = seed_signups(&app).await;
    let monday = last_closed_monday();
    // A stored day and a stored week, so the stored views have rows.
    digest::run_manual(&app.state, yesterday, false, None, DateTime::now())
        .await
        .unwrap();
    weekly::run_manual(&app.state, monday, false, None, DateTime::now())
        .await
        .unwrap();
    let tenant = app
        .db
        .collection::<Document>("tenants")
        .find_one(doc! { "slug": "li-org" })
        .await
        .unwrap()
        .unwrap()
        .get_object_id("_id")
        .unwrap()
        .to_hex();
    let (read_key, read_id) = mint(&app, &token, "read").await;
    let (ingest_key, _) = mint(&app, &token, "ingest").await;

    // Every GET view, with a fixed range where the default would be "now":
    // the same JSON for the session and for the key.
    let since = ds(yesterday - Duration::days(1));
    let until = ds(yesterday);
    let views = [
        format!("/api/admin/growth/digest?day={until}"),
        "/api/admin/growth/digests?limit=5".to_string(),
        format!("/api/admin/growth/digest/preview?day={until}"),
        format!(
            "/api/admin/growth/funnel?since={since}&until={}",
            ds(today() + Duration::days(1))
        ),
        format!(
            "/api/admin/growth/funnel?since={since}&until={}&by=source",
            ds(today() + Duration::days(1))
        ),
        format!(
            "/api/admin/growth/cohorts?since={}",
            ds(monday - Duration::weeks(4))
        ),
        "/api/admin/growth/orgs?limit=50".to_string(),
        format!("/api/admin/growth/org/{tenant}/timeline"),
        format!("/api/admin/growth/campaigns?since={since}&until={until}&by=source"),
        format!("/api/admin/growth/channels?since={since}&until={until}"),
        format!("/api/admin/growth/newsletter?since={since}&until={until}"),
        format!("/api/admin/growth/weekly?week={}", monday_label(monday)),
        "/api/admin/growth/weeklies?limit=5".to_string(),
        "/api/admin/growth/alerts".to_string(),
        // P4's view, a closed range (nothing on record: not measured, and
        // the same not-measured for both credentials).
        "/api/admin/growth/revenue?since=2026-01&until=2026-03".to_string(),
        // P9a's view, a closed range (nothing frozen: not measured).
        format!("/api/admin/growth/quality?since={since}&until={until}"),
    ];
    for path in &views {
        let (s_admin, mut admin) = get_json(&app, path, &token).await;
        assert_eq!(s_admin, 200, "admin on {path}: {admin}");
        let (s_key, key_text) = with_key(&app, "GET", path, Some(&read_key), None).await;
        assert_eq!(s_key, 200, "read key on {path}: {key_text}");
        let mut key_json: Value = serde_json::from_str(&key_text).unwrap();
        // P4's revenue report stamps the instant it was computed (`as_of`,
        // "now" for the MRR): two calls a few ms apart differ there and
        // nowhere else — the numbers are compared with the stamp set aside.
        if path.contains("/revenue") {
            for v in [&mut admin, &mut key_json] {
                let stamp = v.as_object_mut().unwrap().remove("as_of");
                assert!(stamp.is_some_and(|s| s.is_string()), "{path}: no as_of");
            }
        }
        assert_eq!(admin, key_json, "the same numbers on {path}");
    }
    // The digest it read is a real one, not an empty answer.
    let (_, d) = get_json(&app, &views[0], &token).await;
    assert_eq!(d["day"], until);
    assert!(
        d["sections"]["headline"]["signups"]["day"]
            .as_i64()
            .unwrap()
            >= 1
    );

    // The use is recorded on the key, and the key stays a hash at rest.
    let (_, list) = get_json(&app, "/api/admin/growth/keys", &token).await;
    let row = list["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["id"] == read_id)
        .unwrap();
    assert_eq!(row["kind"], "read");
    assert!(row["last_used_at"].is_string(), "{row}");
    assert!(!list.to_string().contains(&read_key[12..]));

    // Every write, the admin surface's GETs, and a path that does not
    // exist: the SAME empty 404, body for body.
    let (absent_status, absent_body) = with_key(
        &app,
        "GET",
        "/api/admin/growth/nothing-here",
        Some(&read_key),
        None,
    )
    .await;
    assert_eq!(absent_status, 404);
    let writes = [
        (
            "PUT",
            "/api/admin/growth/exclusions",
            Some(r#"{"exclusions":[]}"#),
        ),
        ("POST", "/api/admin/growth/digest/run?day=2026-01-01", None),
        (
            "POST",
            "/api/admin/growth/org-daily/backfill?since=2026-01-01&until=2026-01-02",
            None,
        ),
        (
            "POST",
            "/api/admin/growth/keys",
            Some(r#"{"kind":"read","label":"x"}"#),
        ),
        (
            "DELETE",
            "/api/admin/growth/keys/0123456789abcdef01234567",
            None,
        ),
        ("POST", "/api/admin/growth/weekly/run?week=2026-W01", None),
        ("POST", "/api/admin/growth/alerts/evaluate", None),
        (
            "POST",
            "/api/admin/growth/quality/backfill?since=2026-01-01",
            None,
        ),
        ("POST", "/api/admin/growth/ingest/posts", Some("{}")),
        ("POST", "/api/admin/growth/ingest/snapshots", Some("{}")),
        ("GET", "/api/admin/growth/keys", None),
        ("GET", "/api/admin/growth/exclusions", None),
    ];
    for (method, path, body) in writes {
        let (s, text) = with_key(&app, method, path, Some(&read_key), body).await;
        assert_eq!(
            (s, text.as_str()),
            (404, absent_body.as_str()),
            "{method} {path}"
        );
    }
    assert_eq!(
        count(&app, "growth_exclusions", doc! {}).await,
        0,
        "nothing was written"
    );
    // The kinds do not cross: an ingest key opens no view.
    let (s, text) = with_key(&app, "GET", &views[3], Some(&ingest_key), None).await;
    assert_eq!(
        (s, text.as_str()),
        (404, absent_body.as_str()),
        "ingest key on a view"
    );
    // Malformed and unknown read keys.
    let unknown = format!("rgr_{}", "A".repeat(32));
    for bad in ["rgr_short", unknown.as_str(), "rgr_"] {
        let (s, text) = with_key(&app, "GET", &views[3], Some(bad), None).await;
        assert_eq!((s, text.as_str()), (404, absent_body.as_str()), "{bad}");
    }
    // The session flow is untouched: no credential is still 401, a
    // non-admin's session still 404.
    let (s, _) = with_key(&app, "GET", &views[3], None, None).await;
    assert_eq!(s, 401);
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
    let (s, _) = get_json(&app, &views[3], &plain.access_token).await;
    assert_eq!(s, 404);

    // Revoked: the same 404.
    let r = app
        .client
        .delete(app.url(&format!("/api/admin/growth/keys/{read_id}")))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 204);
    for path in views.iter().take(4) {
        let (s, text) = with_key(&app, "GET", path, Some(&read_key), None).await;
        assert_eq!(
            (s, text.as_str()),
            (404, absent_body.as_str()),
            "revoked on {path}"
        );
    }

    // The kill switch: a live read key on a server whose surface is off.
    let (off, _) = admin_app(&base, "good", |s| s.growth.enabled = false).await;
    let (_, raw) = GrowthKeyDao::new(&off.db)
        .mint(
            GrowthKeyKind::Read,
            "test",
            ObjectId::new(),
            DateTime::now(),
        )
        .await
        .unwrap();
    let (s, _) = with_key(&off, "GET", "/api/admin/growth/funnel", Some(&raw), None).await;
    assert_eq!(s, 404, "growth.enabled = false");
}

// ── The weekly roll-up ──────────────────────────────────────────────────

/// Two concurrent scheduled runs: one claim, one row, one mail; a sent
/// week is never sent again; a failed week is retried.
#[tokio::test]
async fn the_weekly_roll_up_is_stored_once_and_mailed_once() {
    let (base, _fake) = fake_purestat().await;
    let (app, _token) = admin_app(&base, "good", |_| {}).await;
    let monday = last_closed_monday();
    // The week: three sign-ups, one org with a device; the week before:
    // one sign-up.
    let a = user(&app, at_day(monday, 9)).await;
    user(&app, at_day(monday + Duration::days(3), 9)).await;
    user(&app, at_day(monday + Duration::days(6), 23)).await;
    let t = org(&app, a, "week-org", at_day(monday, 10)).await;
    device(&app, t, at_day(monday + Duration::days(1), 10)).await;
    user(&app, at_day(monday - Duration::days(2), 9)).await;

    let mailer = Recording::default();
    let now = DateTime::now();
    let (r1, r2) = tokio::join!(
        weekly::run_scheduled(&app.state, monday, Some(&mailer), now),
        weekly::run_scheduled(&app.state, monday, Some(&mailer), now),
    );
    let (r1, r2) = (r1.unwrap(), r2.unwrap());
    assert_eq!(
        [r1.claimed, r2.claimed].iter().filter(|c| **c).count(),
        1,
        "exactly one claim: {r1:?} {r2:?}"
    );
    let winner = if r1.claimed { &r1 } else { &r2 };
    assert_eq!(winner.day, monday_label(monday));
    assert_eq!(winner.status, DigestStatus::Sent);
    assert_eq!(winner.recipients, 1, "the platform admin's proven address");
    assert_eq!(winner.sent, 1);
    assert_eq!(mailer.count(), 1, "one send across both runs");

    let store = DigestStore::weekly(&app.db);
    let stored = store.get(&monday_label(monday)).await.unwrap().unwrap();
    assert_eq!(stored.status, DigestStatus::Sent);
    assert_eq!(stored.attempts, 1);
    assert!(stored.sent_at.is_some() && stored.computed_at.is_some());
    assert_eq!(count(&app, GROWTH_WEEKLY, doc! {}).await, 1);
    assert_eq!(
        count(&app, GROWTH_DIGESTS, doc! {}).await,
        0,
        "a week never lands among the days"
    );
    let sections = stored.sections.unwrap();
    let head = sections.get_document("headline").unwrap();
    assert_eq!(head.get_str("week").unwrap(), monday_label(monday));
    let signups = head.get_document("signups").unwrap();
    assert_eq!(signups.get_i64("week").unwrap(), 3);
    assert_eq!(signups.get_i64("prev_week").unwrap(), 1);
    assert_eq!(
        signups.get_f64("w4_avg").unwrap(),
        0.3,
        "1 over the four weeks before"
    );
    let devices = head.get_document("devices_enrolled").unwrap();
    assert_eq!(devices.get_i64("week").unwrap(), 1);
    assert_eq!(
        sections
            .get_document("funnel")
            .unwrap()
            .get_document("steps")
            .unwrap()
            .get_i64("signup")
            .unwrap(),
        3
    );
    assert!(sections.get_document("campaigns").is_ok());
    assert!(sections.get_document("cohorts").is_ok());
    assert!(sections.get_document("channels").is_ok());
    assert!(sections.get_document("newsletter").is_ok());
    assert!(
        sections
            .get_document("alerts")
            .unwrap()
            .get_str("not_measured")
            .is_ok(),
        "alerts are off here: a reason, never a count"
    );

    // The mail.
    {
        let (to, subject, html, text) = mailer.last();
        assert_eq!(to, "padmin@test.io");
        assert!(
            subject.starts_with(&format!(
                "MeshHarbor weekly roll-up — {}",
                monday_label(monday)
            )),
            "{subject}"
        );
        assert!(text.contains("Sign-ups: 3 (prev 1 · 4w avg 0.3)"), "{text}");
        assert!(
            text.contains("Devices enrolled: 1 (prev 0 · 4w avg 0.0)"),
            "{text}"
        );
        assert!(text.contains("== The account funnel — the week's sign-ups =="));
        assert!(text.contains("Sign-ups: 3\n"));
        assert!(
            text.contains("n < 30"),
            "every rate below the floor stays a count"
        );
        assert!(
            !html.contains('@') && !text.contains('@'),
            "an address in the mail"
        );
        assert!(
            html.contains("week-org &lt;org&gt;") || !html.contains("<org>"),
            "org names escaped"
        );
    }

    // A sent week is never sent again.
    let again = weekly::run_scheduled(&app.state, monday, Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(!again.claimed);
    assert_eq!(again.status, DigestStatus::Sent);
    assert_eq!(mailer.count(), 1);

    // A failed week is retried.
    app.db
        .collection::<Document>(GROWTH_WEEKLY)
        .update_one(
            doc! { "_id": monday_label(monday) },
            doc! { "$set": { "status": "failed", "error": "simulated" } },
        )
        .await
        .unwrap();
    let retried = weekly::run_scheduled(&app.state, monday, Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(retried.claimed);
    assert_eq!(retried.attempts, 2);
    assert_eq!(retried.status, DigestStatus::Sent);
    assert_eq!(mailer.count(), 2);
}

/// A manual preview never cancels the scheduled mail; a manual send racing
/// the scheduler mails once; a re-run after `sent` does nothing; the
/// routes.
#[tokio::test]
async fn a_weekly_preview_never_cancels_the_scheduled_mail_and_the_routes_answer() {
    let (base, _fake) = fake_purestat().await;
    let (app, token) = admin_app(&base, "good", |_| {}).await;
    let mailer = Recording::default();
    let store = DigestStore::weekly(&app.db);
    let w2 = last_closed_monday() - Duration::weeks(1);
    let w3 = w2 - Duration::weeks(1);
    let w4 = w3 - Duration::weeks(1);

    // (a) preview, then the scheduler: exactly one mail.
    let r = weekly::run_manual(&app.state, w2, false, Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(r.claimed);
    assert_eq!(r.status, DigestStatus::Preview);
    assert_eq!(mailer.count(), 0);
    let r = weekly::run_scheduled(&app.state, w2, Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(r.claimed, "the scheduler claims a previewed week");
    assert_eq!(r.attempts, 2);
    assert_eq!(r.status, DigestStatus::Sent);
    assert_eq!(mailer.count(), 1);
    // … and a manual send after that refreshes in place, never re-sends.
    let r = weekly::run_manual(&app.state, w2, true, Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(!r.claimed);
    assert_eq!(r.status, DigestStatus::Sent);
    assert_eq!(mailer.count(), 1);
    assert_eq!(
        store.get(&monday_label(w2)).await.unwrap().unwrap().status,
        DigestStatus::Sent
    );

    // (b) a manual send racing the scheduler.
    let now = DateTime::now();
    let (manual, scheduled) = tokio::join!(
        weekly::run_manual(&app.state, w3, true, Some(&mailer), now),
        weekly::run_scheduled(&app.state, w3, Some(&mailer), now),
    );
    let manual_claimed = match &manual {
        Ok(r) => r.claimed,
        Err(digest::RunError::Busy) => false,
        Err(e) => panic!("manual run failed: {e}"),
    };
    let scheduled = scheduled.unwrap();
    assert_ne!(
        manual_claimed, scheduled.claimed,
        "exactly one held the week"
    );
    assert_eq!(mailer.count(), 2, "one send across both runs");

    // (c) the routes: list, get, run (preview), bad weeks, non-admin.
    let (s, j) = get_json(&app, "/api/admin/growth/weeklies", &token).await;
    assert_eq!(s, 200);
    let weeks = j["weeks"].as_array().unwrap();
    assert_eq!(weeks.len(), 2);
    assert_eq!(weeks[0]["week"], monday_label(w2), "newest first");
    assert_eq!(weeks[0]["status"], "sent");
    assert!(weeks[0]["headline"]["signups"]["week"].is_number());
    assert!(weeks[0].get("sections").is_none());
    assert_eq!(j["scheduled"], false, "the scheduler is off in this app");
    let (s, latest) = get_json(&app, "/api/admin/growth/weekly", &token).await;
    assert_eq!(s, 200);
    assert_eq!(latest["week"], monday_label(w2));
    assert_eq!(latest["sections"]["headline"]["week"], monday_label(w2));
    assert!(latest["sent_at"].as_str().unwrap().ends_with('Z'));
    let text = latest.to_string();
    assert!(!text.contains("$date") && !text.contains("$oid"), "{text}");
    assert!(!text.contains('@'), "an address in the stored JSON");
    let (s, by_week) = get_json(
        &app,
        &format!("/api/admin/growth/weekly?week={}", monday_label(w3)),
        &token,
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(by_week["week"], monday_label(w3));
    let (s, _) = get_json(&app, "/api/admin/growth/weekly?week=2020-W01", &token).await;
    assert_eq!(s, 404, "no roll-up for that week");
    let (s, _) = get_json(&app, "/api/admin/growth/weekly?week=2026-10-05", &token).await;
    assert_eq!(s, 400, "a day is not a week");

    let r = app
        .auth_post(
            &format!(
                "/api/admin/growth/weekly/run?week={}&send=false",
                monday_label(w4)
            ),
            &token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["week"], monday_label(w4));
    assert_eq!(body["status"], "preview", "send=false ends preview");
    assert_eq!(mailer.count(), 2, "the route did not mail");
    for bad in [
        monday_label(week_start(today())),
        "2030-W01".to_string(),
        "x".to_string(),
    ] {
        let r = app
            .auth_post(&format!("/api/admin/growth/weekly/run?week={bad}"), &token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 400, "{bad}");
    }
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
    for path in ["/api/admin/growth/weekly", "/api/admin/growth/weeklies"] {
        let (s, _) = get_json(&app, path, &plain.access_token).await;
        assert_eq!(s, 404, "{path}");
    }
    let r = app
        .auth_post("/api/admin/growth/weekly/run", &plain.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
}

// ── Alerts ──────────────────────────────────────────────────────────────

fn open_rows(ev: &alerts::Evaluation) -> Vec<(String, String)> {
    ev.fired
        .iter()
        .map(|a| (a.rule.clone(), a.key.clone()))
        .collect()
}

/// Each evaluable rule fires once and mails once; a second evaluation
/// adds nothing; the row clears when the condition goes; a re-fire the
/// same day does not mail; the routes and the digest's section.
#[tokio::test]
async fn alerts_fire_once_clear_and_mail_at_most_once_a_day() {
    let (base, _fake) = fake_purestat().await;
    let (app, token) = admin_app(&base, "good", |s| {
        s.growth.alerts = true;
        s.growth.digest_enabled = true;
    })
    .await;
    // The rules are evaluated on a clock three days back, and every day
    // seeded or asserted on derives from it: with `digest_enabled` on, the
    // host's digest scheduler runs inside this app, and on a slow box its
    // first tick (two minutes in) could compute REAL yesterday before the
    // first evaluation — a day this test never touches on the shifted
    // clock, so the scheduler can neither pre-empt `digest_missing` nor
    // own the day whose digest is read below.
    let now = DateTime::from_millis(DateTime::now().timestamp_millis() - 3 * 86_400_000);
    let yesterday = meshharbor_api::growth::org_daily::parse_day_of(now) - Duration::days(1);
    // A spike: 40 sign-ups over the 28 days before yesterday (mean 1.43,
    // the band's edge 5.0), and 6 yesterday.
    for age in 1..=20 {
        let d = yesterday - Duration::days(age);
        user(&app, at_day(d, 9)).await;
        user(&app, at_day(d, 15)).await;
    }
    for h in [1, 5, 9, 13, 17, 21] {
        user(&app, at_day(yesterday, h)).await;
    }
    // The puller failed on its two latest cycled days (and pulled before).
    let pull_day = alerts::latest_due_day(
        now,
        alerts::PULL_CYCLE_HOUR_UTC as u8,
        alerts::PULL_GRACE_HOURS,
    );
    let pull_days = [pull_day - Duration::days(1), pull_day];
    for d in pull_days {
        app.db
            .collection::<Document>(GROWTH_PULLS)
            .insert_one(doc! {
                "_id": format!("{PURESTAT_SOURCE}:{}", ds(d)), "source": PURESTAT_SOURCE,
                "day": ds(d), "status": "failed", "attempted_at": now, "attempts": 2_i64,
                "rows": 0_i64, "error": "HTTP 401", "truncated": false,
            })
            .await
            .unwrap();
    }
    let older = pull_day - Duration::days(5);
    app.db
        .collection::<Document>(GROWTH_PULLS)
        .insert_one(doc! {
            "_id": format!("{PURESTAT_SOURCE}:{}", ds(older)), "source": PURESTAT_SOURCE,
            "day": ds(older), "status": "ok", "pulled_at": now, "attempted_at": now,
            "attempts": 1_i64, "rows": 3_i64, "truncated": false,
        })
        .await
        .unwrap();

    let mailer = Recording::default();
    let ev = alerts::evaluate(&app.state, Some(&mailer), false, now)
        .await
        .unwrap();
    let fired = open_rows(&ev);
    assert!(
        fired.contains(&("digest_missing".into(), "daily".into())),
        "no digest for the due day: {fired:?}"
    );
    assert!(
        fired.contains(&("spike".into(), "signups".into())),
        "{fired:?}"
    );
    assert!(
        fired.contains(&("source_not_measured".into(), "purestat_pull".into())),
        "{fired:?}"
    );
    assert_eq!(fired.len(), 3, "{fired:?}");
    let spike = ev.fired.iter().find(|a| a.rule == "spike").unwrap();
    assert_eq!(spike.detail.get_str("day").unwrap(), ds(yesterday));
    assert_eq!(spike.detail.get_i64("value").unwrap(), 6);
    assert_eq!(spike.detail.get_i64("baseline_n").unwrap(), 40);
    assert_eq!(ev.mailed, 3, "one mail per fired alert, one recipient");
    assert_eq!(mailer.count(), 3);
    {
        let sends = mailer.sends.lock().unwrap();
        let subjects: Vec<&str> = sends.iter().map(|s| s.1.as_str()).collect();
        assert!(
            subjects.contains(&"MeshHarbor growth alert — spike: signups"),
            "{subjects:?}"
        );
        assert!(subjects.contains(&"MeshHarbor growth alert — digest_missing: daily"));
        assert!(sends.iter().all(|s| s.0 == "padmin@test.io"));
        assert!(
            sends
                .iter()
                .all(|s| !s.2.contains('@') && !s.3.contains('@'))
        );
    }
    // What could not be evaluated held nothing: the webhook key is not
    // configured, nothing was pulled for visitors.
    for v in &ev.verdicts {
        if (v.key == "sendgrid") || (v.key == "visitors") || v.rule == alerts::Rule::Drop {
            assert!(!v.holds, "{v:?}");
        }
    }
    assert_eq!(count(&app, GROWTH_ALERTS, doc! {}).await, 3);

    // The same hour again: the same three open rows, nothing new, no mail.
    let ev2 = alerts::evaluate(&app.state, Some(&mailer), false, now)
        .await
        .unwrap();
    assert!(ev2.fired.is_empty() && ev2.cleared.is_empty(), "{ev2:?}");
    assert_eq!(ev2.mailed, 0);
    assert_eq!(count(&app, GROWTH_ALERTS, doc! {}).await, 3);
    assert_eq!(mailer.count(), 3);

    // The route: open rows, the rule table, a dry run.
    let (s, j) = get_json(&app, "/api/admin/growth/alerts", &token).await;
    assert_eq!(s, 200);
    assert_eq!(j["enabled"], true);
    assert_eq!(j["open"].as_array().unwrap().len(), 3);
    assert_eq!(j["recent"].as_array().unwrap().len(), 0);
    assert_eq!(j["rules"].as_array().unwrap().len(), 4);
    let text = j.to_string();
    assert!(!text.contains("$date") && !text.contains('@'), "{text}");
    assert!(
        j["open"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["mailed_on"].is_string())
    );
    let r = app
        .auth_post("/api/admin/growth/alerts/evaluate?dry_run=true", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let dry: Value = r.json().await.unwrap();
    assert_eq!(dry["dry_run"], true);
    // One verdict per (rule, key) the rules evaluate.
    let pairs: usize = alerts::Rule::ALL.iter().map(|r| r.keys().len()).sum();
    assert_eq!(pairs, 14);
    assert_eq!(dry["verdicts"].as_array().unwrap().len(), pairs);
    assert_eq!(
        count(&app, GROWTH_ALERTS, doc! {}).await,
        3,
        "a dry run writes nothing"
    );

    // The conditions go away: the digest runs (a preview counts as a run),
    // the puller succeeds.
    let due = alerts::latest_due_day(now, 6, alerts::DIGEST_GRACE_HOURS);
    digest::run_manual(&app.state, due, false, None, DateTime::now())
        .await
        .unwrap();
    app.db
        .collection::<Document>(GROWTH_PULLS)
        .update_many(
            doc! { "source": PURESTAT_SOURCE, "day": { "$in": [ds(pull_days[0]), ds(pull_days[1])] } },
            doc! { "$set": { "status": "ok", "pulled_at": DateTime::now() }, "$unset": { "error": "" } },
        )
        .await
        .unwrap();
    let ev3 = alerts::evaluate(&app.state, Some(&mailer), false, now)
        .await
        .unwrap();
    let cleared: Vec<(String, String)> = ev3
        .cleared
        .iter()
        .map(|a| (a.rule.clone(), a.key.clone()))
        .collect();
    assert!(
        cleared.contains(&("digest_missing".into(), "daily".into())),
        "{cleared:?}"
    );
    assert!(
        cleared.contains(&("source_not_measured".into(), "purestat_pull".into())),
        "{cleared:?}"
    );
    assert_eq!(cleared.len(), 2, "the spike still holds: {cleared:?}");
    assert_eq!(mailer.count(), 3, "a clear mails nothing");
    assert_eq!(
        count(&app, GROWTH_ALERTS, doc! { "cleared_at": Bson::Null }).await,
        1
    );
    let (_, j) = get_json(&app, "/api/admin/growth/alerts", &token).await;
    assert_eq!(j["open"].as_array().unwrap().len(), 1);
    assert_eq!(
        j["recent"].as_array().unwrap().len(),
        2,
        "cleared rows stay listed"
    );

    // A re-fire the same day: a new row, and NO second mail for the pair.
    app.db
        .collection::<Document>(GROWTH_PULLS)
        .update_many(
            doc! { "source": PURESTAT_SOURCE, "day": { "$in": [ds(pull_days[0]), ds(pull_days[1])] } },
            doc! { "$set": { "status": "failed", "error": "HTTP 401 again" } },
        )
        .await
        .unwrap();
    let ev4 = alerts::evaluate(&app.state, Some(&mailer), false, now)
        .await
        .unwrap();
    assert_eq!(
        open_rows(&ev4),
        vec![(
            "source_not_measured".to_string(),
            "purestat_pull".to_string()
        )]
    );
    assert_eq!(ev4.mailed, 0, "mailed earlier today for this rule and key");
    assert_eq!(mailer.count(), 3);
    assert_eq!(
        count(
            &app,
            GROWTH_ALERTS,
            doc! { "rule": "source_not_measured", "key": "purestat_pull" }
        )
        .await,
        2
    );

    // The digest's alerts section: the open rows at the compute (the three
    // still open, fired after the due day closed), and the rows fired or
    // cleared inside the due day itself (none: everything fired at `now`).
    let d = DigestStore::new(&app.db)
        .get(&ds(due))
        .await
        .unwrap()
        .unwrap();
    let a = d.sections.unwrap().get_document("alerts").unwrap().clone();
    assert!(
        !a.get_array("open").unwrap().is_empty(),
        "open at the compute: {a}"
    );
    assert_eq!(a.get_array("fired").unwrap().len(), 0, "{a}");

    // Alerts off: the hourly job's route refuses to fire, a dry run still
    // decides, and the stored digest says so.
    let (off, off_token) = admin_app(&base, "good", |_| {}).await;
    let r = off
        .auth_post("/api/admin/growth/alerts/evaluate", &off_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409);
    let r = off
        .auth_post("/api/admin/growth/alerts/evaluate?dry_run=true", &off_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let (_, j) = get_json(&off, "/api/admin/growth/alerts", &off_token).await;
    assert_eq!(j["enabled"], false);
    assert_eq!(count(&off, GROWTH_ALERTS, doc! {}).await, 0);
}

/// §3l — a configured puller failing two days running opens ONE
/// `source_not_measured` row keyed by the puller, carrying its last success
/// and its newest error, and the row closes once a pull succeeds. A puller
/// that is not configured says nothing over the same failing rows.
#[tokio::test]
async fn a_puller_failing_two_days_running_alerts_and_clears() {
    let (base, _fake) = fake_purestat().await;
    let (app, _token) = admin_app(&base, "good", |s| {
        s.growth.alerts = true;
        // A key that does not parse: the puller never starts (whether a key
        // PARSES is the puller's to say), and the rule still watches.
        s.growth.search_console_key = "{}".into();
        s.growth.search_console_site = "sc-domain:example.test".into();
        s.growth.bing_api_key = String::new();
    })
    .await;
    let now = DateTime::now();
    let ago = |h: i64| DateTime::from_millis(now.timestamp_millis() - h * 3_600_000);
    let t = today();
    let pulls = app.db.collection::<Document>(GROWTH_PULLS);
    // Search Console: the last good pull 72 h ago, failing since; Bing (no
    // key here) carries the same failing shape.
    for (source, back, ok_hours, attempt_hours, error) in [
        (SEARCH_CONSOLE_SOURCE, 5, Some(72), 72, None),
        (SEARCH_CONSOLE_SOURCE, 4, None, 30, Some("HTTP 403")),
        (SEARCH_CONSOLE_SOURCE, 3, None, 1, Some("HTTP 403")),
        (BING_SOURCE, 4, Some(80), 80, None),
        (BING_SOURCE, 1, None, 1, Some("HTTP 401")),
    ] {
        let day = ds(t - Duration::days(back));
        let mut d = doc! {
            "_id": format!("{source}:{day}"), "source": source, "day": &day,
            "status": if ok_hours.is_some() { "ok" } else { "failed" },
            "attempted_at": ago(attempt_hours), "attempts": 2_i64, "rows": 0_i64,
            "truncated": false,
        };
        if let Some(h) = ok_hours {
            d.insert("pulled_at", ago(h));
        }
        if let Some(e) = error {
            d.insert("error", e);
        }
        pulls.insert_one(d).await.unwrap();
    }

    let mailer = Recording::default();
    let ev = alerts::evaluate(&app.state, Some(&mailer), false, now)
        .await
        .unwrap();
    let failing: Vec<&str> = ev
        .fired
        .iter()
        .filter(|a| a.rule == "source_not_measured" && a.key.ends_with("_pull"))
        .map(|a| a.key.as_str())
        .collect();
    assert_eq!(failing, ["search_console_pull"], "{:?}", open_rows(&ev));
    let row = ev
        .fired
        .iter()
        .find(|a| a.key == "search_console_pull")
        .unwrap();
    assert_eq!(row.detail.get_str("last_error").unwrap(), "HTTP 403");
    assert_eq!(row.detail.get_i64("hours_failing").unwrap(), 72);
    assert!(row.detail.get_str("last_ok").is_ok(), "{:?}", row.detail);

    // A second evaluation opens nothing new.
    let again = alerts::evaluate(&app.state, Some(&mailer), false, now)
        .await
        .unwrap();
    assert!(
        !open_rows(&again).contains(&("source_not_measured".into(), "search_console_pull".into())),
        "{:?}",
        open_rows(&again)
    );

    // A pull succeeds: the row closes.
    pulls
        .update_one(
            doc! { "_id": format!("{SEARCH_CONSOLE_SOURCE}:{}", ds(t - Duration::days(3))) },
            doc! {
                "$set": { "status": "ok", "pulled_at": now, "attempted_at": now },
                "$unset": { "error": "" },
            },
        )
        .await
        .unwrap();
    let ev = alerts::evaluate(&app.state, Some(&mailer), false, now)
        .await
        .unwrap();
    let cleared: Vec<(String, String)> = ev
        .cleared
        .iter()
        .map(|a| (a.rule.clone(), a.key.clone()))
        .collect();
    assert!(
        cleared.contains(&("source_not_measured".into(), "search_console_pull".into())),
        "{cleared:?}"
    );
    assert_eq!(
        count(
            &app,
            GROWTH_ALERTS,
            doc! { "key": "search_console_pull", "cleared_at": Bson::Null }
        )
        .await,
        0
    );
}
