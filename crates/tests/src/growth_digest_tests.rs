// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P1d — the daily digest, against a real server (spec §3l, AC23).
//!
//! * a seeded, fixed past day: every section's exact numbers, the
//!   `not_measured` sections without a purestat key, the exclusion set
//!   applied and `include_internal=true` showing the raw totals (AC4);
//! * once-only: two concurrent scheduled runs ⇒ one claim, one send; a
//!   `sent` day is never sent again; a `failed` day and a stale `computing`
//!   one are retried; a fresh `computing` claim is honoured;
//! * the manual run never mails with `send=false`, and never a `sent` day;
//! * the routes 404 a non-admin, and the stored JSON and the rendered mail
//!   carry no address;
//! * the purestat client against a fake server: the contract's body and
//!   header, paging, a 401 and a timeout as `not_measured`.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use chrono::NaiveDate;
use meshharbor_api::growth::{
    digest::{self, DigestMailer, Measured, Sections},
    purestat::{Filter, PurestatClient, PurestatError, Query},
};
use meshharbor_services::dao::growth_digest::{DigestStatus, DigestStore};
use meshharbor_core::growth::ExclusionSet;
use serde_json::{Value, json};

use crate::fixtures::test_app::TestApp;

/// The closed day every number below is counted for.
const DAY: &str = "2026-10-01";

fn day() -> NaiveDate {
    digest::parse_day(DAY).unwrap()
}

/// `DAY + days` at `h:m:s` UTC.
fn at(days: i64, h: u32, m: u32, s: u32) -> DateTime {
    let d = day() + chrono::Duration::days(days);
    DateTime::from_millis(d.and_hms_opt(h, m, s).unwrap().and_utc().timestamp_millis())
}

async fn insert(app: &TestApp, coll: &str, d: Document) -> ObjectId {
    let id = d
        .get_object_id("_id")
        .map(|x| x.to_owned())
        .unwrap_or_else(|_| ObjectId::new());
    let mut d = d;
    d.insert("_id", id);
    app.db
        .collection::<Document>(coll)
        .insert_one(d)
        .await
        .unwrap_or_else(|e| panic!("insert into {coll}: {e}"));
    id
}

async fn insert_user(
    app: &TestApp,
    id: ObjectId,
    email: &str,
    created: DateTime,
    attribution: Option<Document>,
    provider: Option<&str>,
) {
    let mut d = doc! {
        "_id": id,
        "email": email,
        "username": email.split('@').next().unwrap(),
        "display_name": "A Person",
        "avatar": Bson::Null,
        "bio": Bson::Null,
        "is_verified": true,
        "is_mfa_enabled": false,
        "last_active_at": Bson::Null,
        "oauth_providers": provider
            .map(|p| vec![doc! { "provider": p, "provider_id": "x", "access_token": Bson::Null, "refresh_token": Bson::Null }])
            .unwrap_or_default(),
        "created_at": created,
        "updated_at": created,
        "deleted_at": Bson::Null,
    };
    if let Some(a) = attribution {
        d.insert("signup_attribution", a);
    }
    insert(app, "users", d).await;
}

async fn insert_tenant(
    app: &TestApp,
    owner: ObjectId,
    slug: &str,
    created: DateTime,
    plan: &str,
    billing_status: Option<&str>,
) -> ObjectId {
    let billing = match billing_status {
        Some(s) => Bson::Document(doc! {
            "customer_id": Bson::Null, "subscription_id": Bson::Null,
            "current_period_end": Bson::Null, "status": s, "cancel_at_period_end": false,
        }),
        None => Bson::Null,
    };
    insert(
        app,
        "tenants",
        doc! {
            "name": format!("{slug} <org>"),
            "slug": slug,
            "description": Bson::Null,
            "icon": Bson::Null,
            "owner_id": owner,
            "plan": plan,
            "features": [],
            "settings": { "default_locale": "en-US" },
            "billing": billing,
            "integrations": Bson::Null,
            "is_archived": false,
            "created_at": created,
            "updated_at": created,
            "deleted_at": Bson::Null,
        },
    )
    .await
}

async fn insert_member(app: &TestApp, tenant: ObjectId, user: ObjectId) {
    let now = DateTime::now();
    insert(
        app,
        "tenant_members",
        doc! {
            "tenant_id": tenant, "user_id": user, "nickname": Bson::Null, "role_ids": [],
            "joined_at": now, "is_pending": false, "is_muted": false,
            "notification_override": Bson::Null, "invited_by": Bson::Null,
            "last_seen_at": Bson::Null, "created_at": now, "updated_at": now,
        },
    )
    .await;
}

/// `install_method`: `Some` writes a P3 `install` block; `None` is a row
/// from before the install trace (no block at all), which must read as
/// `unknown`.
async fn insert_agent(
    app: &TestApp,
    tenant: ObjectId,
    os: &str,
    created: DateTime,
    install_method: Option<&str>,
) {
    let mut d = doc! {
        "tenant_id": tenant, "owner_user_id": ObjectId::new(), "name": "box",
        "machine_id": format!("m-{}", ObjectId::new()), "os": os,
        "agent_version": "0.4.130", "status": "offline",
        "created_at": created, "updated_at": created, "deleted_at": Bson::Null,
    };
    if let Some(m) = install_method {
        d.insert("install", doc! { "method": m, "scope": "system" });
    }
    insert(app, "agents", d).await;
}

/// A row whose `_id` is a STRING (the jti, the daily counter's fact) —
/// `insert` above would replace it with a fresh ObjectId.
async fn insert_string_id(app: &TestApp, coll: &str, d: Document) {
    app.db
        .collection::<Document>(coll)
        .insert_one(d)
        .await
        .unwrap_or_else(|e| panic!("insert into {coll}: {e}"));
}

/// P3 — an `enroll_token_issued` row: minted at `issued`, redeemed or not.
async fn insert_token(app: &TestApp, tenant: ObjectId, issued: DateTime, redeemed: bool) {
    insert_string_id(
        app,
        "enroll_token_issued",
        doc! {
            "_id": format!("jti-{}", ObjectId::new()),
            "tenant_id": tenant, "issued_by": ObjectId::new(), "issued_at": issued,
            "kind": "standard",
            "redeemed_at": if redeemed { Bson::DateTime(issued) } else { Bson::Null },
            "agent_id": if redeemed { Bson::ObjectId(ObjectId::new()) } else { Bson::Null },
        },
    )
    .await;
}

/// P3 — a `growth_daily` counter row, as the fleet module writes them.
async fn insert_fetch(app: &TestApp, day: &str, asset: &str, client: &str, os: &str, value: i64) {
    let dims = doc! { "asset": asset, "client": client, "os": os };
    let id = format!("install:fetch:asset={asset},client={client},os={os}:{day}");
    insert_string_id(
        app,
        "growth_daily",
        doc! {
            "_id": id, "day": day, "source": "install", "metric": "fetch",
            "dims": dims, "value": value,
        },
    )
    .await;
}

async fn insert_session(
    app: &TestApp,
    tenant: ObjectId,
    started: Option<DateTime>,
    ended: Option<DateTime>,
    reason: Option<&str>,
) {
    insert(
        app,
        "remote_sessions",
        doc! {
            "agent_id": ObjectId::new(), "tenant_id": tenant, "controller_user_id": ObjectId::new(),
            "watchers": [], "permissions": 0_i32,
            "phase": if ended.is_some() { "closed" } else { "active" },
            "created_at": started.unwrap_or_else(|| ended.unwrap()),
            "started_at": started.map(Bson::DateTime).unwrap_or(Bson::Null),
            "ended_at": ended.map(Bson::DateTime).unwrap_or(Bson::Null),
            "end_reason": reason.map(|r| Bson::String(r.into())).unwrap_or(Bson::Null),
            "recording_url": Bson::Null,
        },
    )
    .await;
}

async fn insert_call(app: &TestApp, tenant: ObjectId, started: DateTime, peak: i32, secs: i64) {
    insert(
        app,
        "call_sessions",
        doc! {
            "tenant_id": tenant, "room_id": ObjectId::new(), "started_by": ObjectId::new(),
            "started_at": started, "ended_at": DateTime::from_millis(started.timestamp_millis() + secs * 1000),
            "peak_participants": peak, "participant_seconds": secs,
        },
    )
    .await;
}

async fn insert_subscriber(
    app: &TestApp,
    email: &str,
    source: &str,
    created: DateTime,
    confirmed: Option<DateTime>,
    unsubscribed: Option<DateTime>,
) {
    let mut d = doc! {
        "email": email, "source": source, "confirmed": confirmed.is_some(),
        "unsubscribe_token": format!("tok-{email}"), "created_at": created,
    };
    if let Some(c) = confirmed {
        d.insert("confirmed_at", c);
    }
    if let Some(u) = unsubscribed {
        d.insert("unsubscribed_at", u);
    }
    insert(app, "subscribers", d).await;
}

/// An `agent_crashes` row as `AgentCrashDao::record` writes it: the record's
/// own fields snake_case, the payload flattened **camelCase**
/// (`AgentCrashPayload` is `rename_all = "camelCase"`). ⚠️ A seed in
/// `agent_version` would pass a reader of that spelling while every
/// production row says `agentVersion` — which is how P1d's "crashes by
/// version" read `unknown` for every crash until P9a.
async fn insert_crash(app: &TestApp, tenant: ObjectId, reported: DateTime, version: &str) {
    insert(
        app,
        "agent_crashes",
        doc! {
            "tenant_id": tenant, "agent_id": ObjectId::new(), "reported_at": reported,
            "crashedAtUnix": reported.timestamp_millis() / 1000, "reason": "panic",
            "summary": "boom", "logTail": "", "agentVersion": version, "os": "linux",
            "hostname": "box", "pid": 1_i64, "suppressedSinceLast": 0_i64,
        },
    )
    .await;
}

/// A mailer that records every attempt and never fails.
#[derive(Default)]
struct Recording {
    sends: Mutex<Vec<(String, String, String, String)>>,
}

impl Recording {
    fn count(&self) -> usize {
        self.sends.lock().unwrap().len()
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

struct Seeded {
    app: TestApp,
    admin_id: ObjectId,
    admin_token: String,
    org_a: ObjectId,
}

/// The fixed day, seeded end to end. Every email here is a `.test.io`
/// address with an `@`; the no-address checks look for exactly that.
async fn seed() -> Seeded {
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
    })
    .await;
    let admin_token = app
        .state
        .auth
        .generate_tokens(admin_id, "padmin@test.io", "padmin")
        .unwrap()
        .access_token;

    // People.
    let (a, b, c, d, e, x) = (
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
    );
    insert_user(
        &app,
        a,
        "a@test.io",
        at(0, 10, 0, 0),
        Some(doc! { "source": "youtube", "medium": "video", "campaign": "c1" }),
        None,
    )
    .await;
    insert_user(&app, b, "b@test.io", at(0, 11, 0, 0), None, Some("google")).await;
    insert_user(&app, c, "c@test.io", at(-1, 12, 0, 0), None, None).await;
    insert_user(&app, d, "d@test.io", at(-20, 12, 0, 0), None, None).await;
    insert_user(&app, e, "e@test.io", at(-40, 12, 0, 0), None, None).await;
    insert_user(&app, admin_id, "padmin@test.io", at(0, 9, 0, 0), None, None).await;
    insert_user(&app, x, "x@test.io", at(0, 13, 0, 0), None, None).await;

    // Orgs: A (a's, pro, active), C (c's, free), the admin's, X (x's).
    let org_a = insert_tenant(&app, a, "org-a", at(0, 10, 5, 0), "pro", Some("active")).await;
    let org_c = insert_tenant(&app, c, "org-c", at(-1, 12, 5, 0), "free", None).await;
    insert_tenant(&app, admin_id, "org-adm", at(0, 9, 5, 0), "free", None).await;
    let org_x = insert_tenant(&app, x, "org-x", at(0, 13, 5, 0), "pro", Some("active")).await;
    insert_member(&app, org_a, a).await;
    insert_member(&app, org_a, b).await;
    insert_member(&app, org_x, x).await;

    // Devices (tombstones count as enrolled; X is excluded). P3: two say how
    // they were installed, C's row predates the install trace.
    insert_agent(&app, org_a, "linux", at(0, 11, 0, 0), Some("script-sh")).await;
    insert_agent(&app, org_a, "windows", at(0, 12, 0, 0), Some("wizard")).await;
    insert_agent(&app, org_c, "macos", at(-1, 13, 0, 0), None).await;
    insert_agent(&app, org_x, "linux", at(0, 14, 0, 0), Some("wizard")).await;

    // P3 — enrollment tokens: three minted in A that day (two redeemed), one
    // the day before (unredeemed), one in the excluded X, one out of window.
    insert_token(&app, org_a, at(0, 10, 0, 0), true).await;
    insert_token(&app, org_a, at(0, 10, 30, 0), true).await;
    insert_token(&app, org_a, at(0, 11, 0, 0), false).await;
    insert_token(&app, org_a, at(-1, 9, 0, 0), false).await;
    insert_token(&app, org_x, at(0, 9, 0, 0), true).await;
    insert_token(&app, org_a, at(-40, 9, 0, 0), true).await;

    // P3 — fetch counters: install.sh by curl that day, 3 days before and 20
    // days before; the wizard's MSI that day; and a row of another source
    // that the install section must not read.
    insert_fetch(&app, DAY, "install.sh", "script-sh", "unknown", 5).await;
    insert_fetch(&app, "2026-09-28", "install.sh", "script-sh", "unknown", 2).await;
    insert_fetch(&app, "2026-09-11", "install.sh", "script-sh", "unknown", 1).await;
    insert_fetch(&app, DAY, "installer-permachine", "wizard", "windows", 1).await;
    // P3c — the lab's own fetches (`client: internal`), counted while a
    // network was configured: never in the table, summed on their own line
    // whatever the asset — and still a measurement on a server that names
    // no network today (this one).
    insert_fetch(&app, DAY, "install.sh", "internal", "unknown", 4).await;
    insert_fetch(
        &app,
        "2026-09-28",
        "installer-permachine",
        "internal",
        "windows",
        2,
    )
    .await;
    insert_string_id(
        &app,
        "growth_daily",
        doc! {
            "_id": "web:pageview::2026-10-01", "day": DAY, "source": "web",
            "metric": "pageview", "dims": {}, "value": 999_i64,
        },
    )
    .await;
    // And a malformed install row (an ObjectId `_id`, no `dims`): it must
    // cost its own count and nothing else — never the whole digest.
    insert(
        &app,
        "growth_daily",
        doc! { "day": DAY, "source": "install", "metric": "fetch", "value": 7_i64 },
    )
    .await;

    // Remote sessions: s1 30 min; s2 spans midnight; s3 12 s; s4 excluded;
    // s5 never started (consent timed out) and ended that day.
    insert_session(
        &app,
        org_a,
        Some(at(0, 10, 0, 0)),
        Some(at(0, 10, 30, 0)),
        Some("controller_hangup"),
    )
    .await;
    insert_session(
        &app,
        org_a,
        Some(at(-1, 23, 30, 0)),
        Some(at(0, 0, 30, 0)),
        Some("agent_disconnect"),
    )
    .await;
    insert_session(
        &app,
        org_a,
        Some(at(0, 15, 0, 0)),
        Some(at(0, 15, 0, 12)),
        Some("error"),
    )
    .await;
    insert_session(
        &app,
        org_x,
        Some(at(0, 16, 0, 0)),
        Some(at(0, 16, 10, 0)),
        Some("controller_hangup"),
    )
    .await;
    insert_session(
        &app,
        org_a,
        None,
        Some(at(0, 17, 0, 0)),
        Some("consent_timeout"),
    )
    .await;

    // Calls in C: one with two participants (a value event), one alone.
    insert_call(&app, org_c, at(0, 9, 0, 0), 2, 600).await;
    insert_call(&app, org_c, at(0, 10, 0, 0), 1, 120).await;

    // The newsletter list and one issue sent that day.
    insert_subscriber(&app, "sa@test.io", "landing", at(0, 8, 0, 0), None, None).await;
    insert_subscriber(
        &app,
        "sb@test.io",
        "docs",
        at(-2, 8, 0, 0),
        Some(at(0, 9, 0, 0)),
        None,
    )
    .await;
    insert_subscriber(
        &app,
        "sc@test.io",
        "landing",
        at(-10, 8, 0, 0),
        None,
        Some(at(0, 9, 30, 0)),
    )
    .await;
    insert(
        &app,
        "newsletter_issues",
        doc! {
            "slug": "oct", "subject": "October", "preheader": "", "body_md": "", "status": "completed",
            "counts": { "total": 10_i64, "sent": 9_i64, "failed": 1_i64, "suppressed": 0_i64, "stale": 0_i64 },
            "created_at": at(0, 7, 0, 0), "updated_at": at(0, 8, 0, 0), "sent_at": at(0, 8, 0, 0),
        },
    )
    .await;

    // Crashes: one in A, one in the excluded X.
    insert_crash(&app, org_a, at(0, 12, 0, 0), "0.4.130").await;
    insert_crash(&app, org_x, at(0, 12, 0, 0), "0.4.130").await;

    // x is an explicit exclusion; the admin and their org are implicit.
    let r = app
        .auth_put("/api/admin/growth/exclusions", &admin_token)
        .json(&json!({ "exclusions": [ { "kind": "user", "id": x.to_hex(), "reason": "field tester" } ] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

    Seeded {
        app,
        admin_id,
        admin_token,
        org_a,
    }
}

fn fig(v: &Value) -> (i64, i64, i64) {
    (
        v["day"].as_i64().unwrap_or(-1),
        v["d7"].as_i64().unwrap_or(-1),
        v["d28"].as_i64().unwrap_or(-1),
    )
}

fn figf(v: &Value) -> (f64, f64, f64) {
    (
        v["day"].as_f64().unwrap_or(-1.0),
        v["d7"].as_f64().unwrap_or(-1.0),
        v["d28"].as_f64().unwrap_or(-1.0),
    )
}

fn not_measured(v: &Value) -> Option<(&str, Option<&str>)> {
    v.get("not_measured")
        .and_then(|n| n.as_str())
        .map(|n| (n, v.get("arrives_with").and_then(|p| p.as_str())))
}

/// Every section's numbers, on the seeded day, without a purestat key.
#[tokio::test]
async fn every_section_counts_the_seeded_day_exactly() {
    let s = seed().await;
    let set = ExclusionSet::load(&s.app.state.core).await.unwrap();
    assert_eq!(set.counts(), (2, 2), "admin + x; the admin's org + X");
    let sections = digest::compute(&s.app.state, day(), &set, DateTime::now())
        .await
        .unwrap();
    let j = serde_json::to_value(&sections).unwrap();
    println!(
        "DIGEST SECTIONS {}",
        serde_json::to_string_pretty(&j).unwrap()
    );

    // Headline.
    assert_eq!(
        fig(&j["headline"]["signups"]),
        (2, 3, 4),
        "{}",
        j["headline"]
    );
    assert_eq!(fig(&j["headline"]["orgs_created"]), (1, 2, 2));
    assert_eq!(fig(&j["headline"]["devices_enrolled"]), (2, 3, 3));
    assert_eq!(fig(&j["headline"]["active_orgs"]), (2, 2, 2));
    assert_eq!(
        j["headline"]["active_orgs"]["basis"],
        json!(["remote", "conference", "network"]),
        "P2 — network's tunnel/SSH flows are value events too"
    );
    assert_eq!(
        not_measured(&j["headline"]["coverage"]),
        Some(("purestat key not configured", None))
    );

    // Sign-ups: provider and campaign key, never a person.
    assert_eq!(fig(&j["signups"]["total"]), (2, 3, 4));
    assert_eq!(fig(&j["signups"]["attributed"]), (1, 1, 1));
    assert_eq!(
        j["signups"]["by_provider"],
        json!([{ "key": "email", "count": 1 }, { "key": "google", "count": 1 }])
    );
    assert_eq!(
        j["signups"]["by_source"],
        json!([{ "key": "(none)", "count": 1 }, { "key": "youtube", "count": 1 }])
    );
    let rows = j["signups"]["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|r| r["provider"] == "email"
        && r["source"] == "youtube"
        && r["medium"] == "video"
        && r["campaign"] == "c1"));
    assert!(
        rows.iter()
            .any(|r| r["provider"] == "google" && r.get("source").is_none())
    );

    // Orgs and devices.
    assert_eq!(fig(&j["orgs_devices"]["orgs_created"]), (1, 2, 2));
    assert_eq!(fig(&j["orgs_devices"]["devices_enrolled"]), (2, 3, 3));
    assert_eq!(
        j["orgs_devices"]["devices_by_os"],
        json!([{ "key": "linux", "count": 1 }, { "key": "windows", "count": 1 }])
    );
    assert_eq!(fig(&j["orgs_devices"]["orgs_first_device"]), (1, 2, 2));
    // P3 — the day's devices by install method (X's wizard row is excluded).
    assert_eq!(
        j["orgs_devices"]["by_install_method"],
        json!([{ "key": "script-sh", "count": 1 }, { "key": "wizard", "count": 1 }])
    );

    // Usage: a session spanning midnight counts only its overlap.
    assert_eq!(fig(&j["usage"]["remote"]["sessions_started"]), (2, 3, 3));
    assert_eq!(
        figf(&j["usage"]["remote"]["session_minutes"]),
        (60.2, 90.2, 90.2),
        "{}",
        j["usage"]
    );
    assert_eq!(fig(&j["usage"]["calls"]["calls"]), (2, 2, 2));
    assert_eq!(
        figf(&j["usage"]["calls"]["participant_minutes"]),
        (12.0, 12.0, 12.0)
    );
    assert_eq!(fig(&j["usage"]["active_orgs"]), (2, 2, 2));
    let top = j["usage"]["top_orgs"].as_array().unwrap();
    assert_eq!(top.len(), 1, "{top:?}");
    assert_eq!(top[0]["tenant_id"], s.org_a.to_hex());
    assert_eq!(top[0]["name"], "org-a <org>");
    assert_eq!(top[0]["minutes"], 60.2);
    assert_eq!(top[0]["sessions"], 2);

    // The web plane, without a key: not measured, never 0.
    for k in ["website", "blog", "campaigns"] {
        assert_eq!(
            not_measured(&j[k]),
            Some(("purestat key not configured", None)),
            "{k}: {}",
            j[k]
        );
    }

    // Newsletter.
    assert_eq!(fig(&j["newsletter"]["new"]), (1, 2, 3));
    assert_eq!(fig(&j["newsletter"]["confirmed"]), (1, 1, 1));
    assert_eq!(fig(&j["newsletter"]["unsubscribed"]), (1, 1, 1));
    assert_eq!(
        j["newsletter"]["by_source"],
        json!([
            { "source": "landing", "new": 1, "confirmed": 0, "unsubscribed": 1 },
            { "source": "docs", "new": 0, "confirmed": 1, "unsubscribed": 0 },
        ])
    );
    let issues = j["newsletter"]["issues"].as_array().unwrap();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0]["slug"], "oct");
    assert_eq!(issues[0]["counts"]["sent"], 9);
    assert_eq!(issues[0]["sent_at"], "2026-10-01T08:00:00Z");
    // P5 — this server verifies no SendGrid webhook: delivery is not
    // measured (never 0), and says why rather than which phase brings it.
    let (reason, phase) = not_measured(&j["newsletter"]["delivery"]).expect("not measured");
    assert!(reason.contains("EVENT_WEBHOOK_PUBLIC_KEY"), "{reason}");
    assert_eq!(phase, None);
    assert!(
        not_measured(&issues[0]["delivery"]).is_some(),
        "{}",
        issues[0]
    );
    assert_eq!(fig(&j["newsletter"]["unsubscribed_via_issue"]), (0, 0, 0));

    // Revenue: the excluded orgs are not counted; MRR is a labelled estimate.
    assert_eq!(
        j["revenue"]["orgs_by_plan_status"],
        json!([
            { "plan": "free", "status": "none", "orgs": 1 },
            { "plan": "pro", "status": "active", "orgs": 1 },
        ])
    );
    assert_eq!(j["revenue"]["mrr"]["cents"], 1600.0);
    assert_eq!(j["revenue"]["mrr"]["estimate"], true);
    // P4 — nothing on record: billed is not measured (never "0 MRR"), and
    // says why rather than which phase brings it; no collision was counted.
    let (reason, phase) = not_measured(&j["revenue"]["billed"]).expect("not measured");
    assert!(reason.contains("no billing event on record"), "{reason}");
    assert_eq!(phase, None);
    assert_eq!(
        fig(&j["revenue"]["upgrade_intent"]["collisions"]),
        (0, 0, 0)
    );

    // Quality: failures apart from hang-ups and refusals; crashes by version.
    assert_eq!(fig(&j["quality"]["remote"]["ended"]), (4, 4, 4));
    assert_eq!(fig(&j["quality"]["remote"]["hangups"]), (1, 1, 1));
    assert_eq!(fig(&j["quality"]["remote"]["refusals"]), (1, 1, 1));
    assert_eq!(fig(&j["quality"]["remote"]["failures"]), (2, 2, 2));
    let reasons = j["quality"]["remote"]["by_end_reason"].as_array().unwrap();
    assert_eq!(reasons.len(), 4);
    assert!(
        reasons
            .iter()
            .any(|r| r["reason"] == "consent_timeout" && r["class"] == "refusal")
    );
    assert!(
        reasons
            .iter()
            .any(|r| r["reason"] == "error" && r["class"] == "failure")
    );
    assert_eq!(fig(&j["quality"]["crashes"]["total"]), (1, 1, 1));
    assert_eq!(
        j["quality"]["crashes"]["by_agent_version"],
        json!([{ "key": "0.4.130", "count": 1 }])
    );
    // P9a — the sessions requested (s1, s3, s5 that day; s2 the day
    // before), the live distributions, and the frozen parts saying why
    // they are not there (no freeze ran here).
    assert_eq!(fig(&j["quality"]["remote"]["requested"]), (3, 4, 4));
    assert_eq!(fig(&j["quality"]["remote"]["reached_active"]), (2, 3, 3));
    assert_eq!(fig(&j["quality"]["remote"]["not_reached"]), (1, 1, 1));
    assert_eq!(j["quality"]["remote"]["duration_ms"]["day"]["n"], 2);
    assert_eq!(fig(&j["quality"]["crashes"]["device_days"]), (0, 0, 0));
    assert!(
        not_measured(&j["quality"]["ttff"]).is_some_and(|(r, _)| r.contains("not frozen yet")),
        "{}",
        j["quality"]["ttff"]
    );

    // P3 — the install trace. Tokens: issued in the window, minus X's; of
    // those, the redeemed ones. Fetches summed into the windows from the
    // daily rows, the other source untouched. Enrollments by (method, OS),
    // C's pre-P3 row reading as `unknown`.
    assert_eq!(fig(&j["install"]["tokens"]["issued"]), (3, 4, 4));
    assert_eq!(fig(&j["install"]["tokens"]["redeemed"]), (2, 2, 2));
    assert_eq!(
        j["install"]["fetches"],
        json!([
            { "asset": "install.sh", "client": "script-sh", "os": "unknown",
              "fetches": { "day": 5, "d7": 7, "d28": 8 } },
            { "asset": "installer-permachine", "client": "wizard", "os": "windows",
              "fetches": { "day": 1, "d7": 1, "d28": 1 } },
        ])
    );
    assert_eq!(fig(&j["install"]["internal_fetches"]), (4, 6, 6));
    assert_eq!(
        j["install"]["enrollments_by_method"],
        json!([
            { "method": "script-sh", "os": "linux", "enrolled": { "day": 1, "d7": 1, "d28": 1 } },
            { "method": "unknown", "os": "macos", "enrolled": { "day": 0, "d7": 1, "d28": 1 } },
            { "method": "wizard", "os": "windows", "enrolled": { "day": 1, "d7": 1, "d28": 1 } },
        ])
    );
    // P3b — the switch is on and no run opted in: a measured zero with its
    // n, never "not measured" (that is the switch-off answer, asserted in
    // `growth_setup_diagnostics_tests`).
    assert_eq!(
        j["install"]["wizard_steps"],
        json!({
            "runs": { "day": 0, "d7": 0, "d28": 0 },
            "n_floor": 30,
            "steps": [],
            "errors": [],
        })
    );

    // P8 — built, but nothing was pushed: not measured, never 0.
    assert_eq!(
        not_measured(&j["social"]),
        Some(("no posts pushed in the last 28 days", None))
    );
    // P7 — built, but this server holds no search credential: each engine
    // says so, never a 0.
    assert_eq!(
        not_measured(&j["search"]["google"]),
        Some((
            "no Search Console key configured (MESHHARBOR__GROWTH__SEARCH_CONSOLE_KEY)",
            None
        ))
    );
    assert_eq!(
        not_measured(&j["search"]["bing"]),
        Some((
            "no Bing Webmaster API key configured (MESHHARBOR__GROWTH__BING_API_KEY)",
            None
        ))
    );

    // Nothing about a person.
    let text = j.to_string();
    assert!(!text.contains('@'), "an address leaked: {text}");
    assert!(!text.contains("A Person"), "a name leaked");
    assert!(!text.contains("padmin"), "the admin leaked");

    // The typed sections round-trip through BSON exactly as the store
    // writes and the GET reads them.
    let back: Sections = bson::from_document(bson::to_document(&sections).unwrap()).unwrap();
    assert_eq!(back, sections);
    assert!(matches!(back.website, Measured::NotMeasured(_)));
}

/// AC4 — an excluded org or user is absent from every number, and present
/// with `include_internal=true`; the preview stores and mails nothing.
#[tokio::test]
async fn include_internal_shows_the_raw_totals_and_stores_nothing() {
    let s = seed().await;
    let get = |internal: bool| {
        s.app.auth_get(
            &format!("/api/admin/growth/digest/preview?day={DAY}&include_internal={internal}"),
            &s.admin_token,
        )
    };
    let excl: Value = get(false).send().await.unwrap().json().await.unwrap();
    let raw: Value = get(true).send().await.unwrap().json().await.unwrap();
    assert_eq!(excl["include_internal"], false);
    assert_eq!(excl["excluded"], json!({ "users": 2, "tenants": 2 }));
    assert_eq!(raw["include_internal"], true);
    assert_eq!(raw["excluded"], json!({ "users": 0, "tenants": 0 }));
    // a, b (+ admin, x)
    assert_eq!(fig(&excl["sections"]["signups"]["total"]), (2, 3, 4));
    assert_eq!(fig(&raw["sections"]["signups"]["total"]), (4, 5, 6));
    // A (+ the admin's, X)
    assert_eq!(fig(&excl["sections"]["orgs_created"]).0, -1, "no such key");
    assert_eq!(
        fig(&excl["sections"]["headline"]["orgs_created"]),
        (1, 2, 2)
    );
    assert_eq!(fig(&raw["sections"]["headline"]["orgs_created"]), (3, 4, 4));
    assert_eq!(
        fig(&excl["sections"]["headline"]["devices_enrolled"]),
        (2, 3, 3)
    );
    assert_eq!(
        fig(&raw["sections"]["headline"]["devices_enrolled"]),
        (3, 4, 4)
    );
    assert_eq!(
        fig(&excl["sections"]["quality"]["crashes"]["total"]),
        (1, 1, 1)
    );
    assert_eq!(
        fig(&raw["sections"]["quality"]["crashes"]["total"]),
        (2, 2, 2)
    );
    // Nothing was stored by a preview.
    assert!(
        DigestStore::new(&s.app.db)
            .get(DAY)
            .await
            .unwrap()
            .is_none()
    );
}

/// AC23 — two pods racing: one insert, one send; then the retry rules.
#[tokio::test]
async fn two_concurrent_runs_store_once_and_send_once() {
    let s = seed().await;
    let mailer = Recording::default();
    let now = DateTime::now();
    let (r1, r2) = tokio::join!(
        digest::run_scheduled(&s.app.state, day(), Some(&mailer), now),
        digest::run_scheduled(&s.app.state, day(), Some(&mailer), now),
    );
    let (r1, r2) = (r1.unwrap(), r2.unwrap());
    assert_eq!(
        [r1.claimed, r2.claimed].iter().filter(|c| **c).count(),
        1,
        "exactly one claim: {r1:?} {r2:?}"
    );
    let winner = if r1.claimed { &r1 } else { &r2 };
    assert_eq!(winner.status, DigestStatus::Sent);
    assert_eq!(winner.recipients, 1, "the platform admin's proven address");
    assert_eq!(winner.send_attempts, 1);
    assert_eq!(winner.sent, 1);
    assert_eq!(mailer.count(), 1, "one send across both runs");

    let store = DigestStore::new(&s.app.db);
    let stored = store.get(DAY).await.unwrap().expect("stored once");
    assert_eq!(stored.status, DigestStatus::Sent);
    assert_eq!(stored.attempts, 1);
    assert_eq!(stored.recipients, 1);
    assert!(stored.sent_at.is_some() && stored.computed_at.is_some());
    assert_eq!(
        s.app
            .db
            .collection::<Document>("growth_digests")
            .count_documents(doc! {})
            .await
            .unwrap(),
        1
    );

    // The mail: the subject, both bodies, and no address in either.
    {
        let sends = mailer.sends.lock().unwrap();
        let (to, subject, html, text) = &sends[0];
        assert_eq!(to, "padmin@test.io");
        assert_eq!(subject, &format!("Roomler daily digest — {DAY}"));
        assert!(
            html.contains("Sign-ups</strong>: 2 (7d 3 · 28d 31)")
                || html.contains("2 (7d 3 · 28d 4)"),
            "{html}"
        );
        assert!(text.contains("Sign-ups: 2 (7d 3 · 28d 4)"), "{text}");
        assert!(text.contains("not measured — purestat key not configured"));
        assert!(text.contains("Excluded from every number above: 2 users and 2 orgs"));
        assert!(
            !html.contains('@') && !text.contains('@'),
            "an address in the mail"
        );
        assert!(
            html.contains("org-a &lt;org&gt;"),
            "org names are escaped: {html}"
        );
    }

    // A sent day is never sent again.
    let again = digest::run_scheduled(&s.app.state, day(), Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(!again.claimed);
    assert_eq!(again.status, DigestStatus::Sent);
    assert_eq!(mailer.count(), 1);

    // A failed day is retried (attempts 2, one more send).
    s.app
        .db
        .collection::<Document>("growth_digests")
        .update_one(
            doc! { "_id": DAY },
            doc! { "$set": { "status": "failed", "error": "simulated" } },
        )
        .await
        .unwrap();
    let retried = digest::run_scheduled(&s.app.state, day(), Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(retried.claimed);
    assert_eq!(retried.attempts, 2);
    assert_eq!(retried.status, DigestStatus::Sent);
    assert_eq!(mailer.count(), 2);
    let stored = store.get(DAY).await.unwrap().unwrap();
    assert_eq!(stored.status, DigestStatus::Sent);
    assert!(stored.error.is_none(), "the retry cleared the error");

    // A fresh `computing` claim is another pod's: honoured.
    let fresh = DateTime::now();
    s.app
        .db
        .collection::<Document>("growth_digests")
        .update_one(
            doc! { "_id": DAY },
            doc! { "$set": { "status": "computing", "claimed_at": fresh } },
        )
        .await
        .unwrap();
    let busy = digest::run_scheduled(&s.app.state, day(), Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(!busy.claimed);
    assert_eq!(mailer.count(), 2);

    // A stale `computing` claim (a pod that died) is re-claimed.
    let stale = DateTime::from_millis(DateTime::now().timestamp_millis() - 31 * 60 * 1000);
    s.app
        .db
        .collection::<Document>("growth_digests")
        .update_one(
            doc! { "_id": DAY },
            doc! { "$set": { "claimed_at": stale } },
        )
        .await
        .unwrap();
    let reclaimed = digest::run_scheduled(&s.app.state, day(), Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(reclaimed.claimed);
    assert_eq!(reclaimed.attempts, 3);
    assert_eq!(mailer.count(), 3);
}

/// The manual run never mails with `send=false` (the day ends `preview`,
/// not a status the scheduler respects), mails once with `send=true`, and
/// never a day already `sent` — which it refreshes in place, with or
/// without a mailer, `send` or not.
#[tokio::test]
async fn the_manual_run_mails_only_when_asked_and_never_a_sent_day() {
    let s = seed().await;
    let mailer = Recording::default();
    let store = DigestStore::new(&s.app.db);
    let d2 = day().pred_opt().unwrap();
    let k2 = digest::day_str(d2);
    let r = digest::run_manual(&s.app.state, d2, false, Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(r.claimed);
    assert_eq!(r.status, DigestStatus::Preview);
    assert_eq!(r.send_attempts, 0);
    assert_eq!(mailer.count(), 0);
    assert_eq!(
        store.get(&k2).await.unwrap().unwrap().status,
        DigestStatus::Preview
    );
    let r = digest::run_manual(&s.app.state, d2, true, Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(r.claimed, "a preview is re-claimed by a delivering run");
    assert_eq!(r.status, DigestStatus::Sent);
    assert_eq!(mailer.count(), 1);
    let r = digest::run_manual(&s.app.state, d2, true, Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(!r.claimed, "a sent day is refreshed in place");
    assert_eq!(r.status, DigestStatus::Sent, "a sent day stays sent");
    assert_eq!(mailer.count(), 1, "and is not sent again");
    // (c) `send=false` on a sent day: in place, still sent, nothing mailed.
    let before = store.get(&k2).await.unwrap().unwrap();
    let r = digest::run_manual(&s.app.state, d2, false, Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(!r.claimed);
    assert_eq!(r.status, DigestStatus::Sent);
    assert_eq!(mailer.count(), 1);
    let after = store.get(&k2).await.unwrap().unwrap();
    assert_eq!(after.status, DigestStatus::Sent);
    assert_eq!(
        after.sent_at, before.sent_at,
        "the send record is untouched"
    );
    assert!(
        after.computed_at >= before.computed_at,
        "the sections were refreshed"
    );
    // No mailer at all: a sent day still stays sent; a fresh day with
    // nobody to mail ends `stored`, and a preview of a stored day keeps it.
    let r = digest::run_manual(&s.app.state, d2, true, None, DateTime::now())
        .await
        .unwrap();
    assert_eq!(r.status, DigestStatus::Sent);
    let d3 = d2.pred_opt().unwrap();
    let k3 = digest::day_str(d3);
    let r = digest::run_manual(&s.app.state, d3, true, None, DateTime::now())
        .await
        .unwrap();
    assert!(r.claimed);
    assert_eq!(r.status, DigestStatus::Stored);
    let r = digest::run_manual(&s.app.state, d3, false, Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(
        !r.claimed,
        "a stored day is refreshed in place by a preview"
    );
    assert_eq!(r.status, DigestStatus::Stored);
    assert_eq!(mailer.count(), 1);
    // ...but a delivering run re-claims it: it was never mailed.
    let r = digest::run_manual(&s.app.state, d3, true, Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(r.claimed);
    assert_eq!(r.status, DigestStatus::Sent);
    assert_eq!(mailer.count(), 2);
    // A fresh `computing` claim refuses a manual run, either way.
    s.app
        .db
        .collection::<Document>("growth_digests")
        .update_one(
            doc! { "_id": &k3 },
            doc! { "$set": { "status": "computing", "claimed_at": DateTime::now() } },
        )
        .await
        .unwrap();
    for send in [false, true] {
        let e = digest::run_manual(&s.app.state, d3, send, Some(&mailer), DateTime::now())
            .await
            .unwrap_err();
        assert_eq!(e, digest::RunError::Busy, "send={send}");
    }
    assert_eq!(mailer.count(), 2);
    assert_eq!(
        store.get(&k3).await.unwrap().unwrap().status,
        DigestStatus::Computing
    );
}

/// (a) A preview before the scheduled run never cancels the email: the
/// scheduler re-claims the `preview` day and sends exactly once.
#[tokio::test]
async fn a_preview_never_cancels_the_scheduled_email() {
    let s = seed().await;
    let mailer = Recording::default();
    let store = DigestStore::new(&s.app.db);
    let r = digest::run_manual(&s.app.state, day(), false, Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert_eq!(r.status, DigestStatus::Preview);
    assert_eq!(mailer.count(), 0);
    assert_eq!(
        store.get(DAY).await.unwrap().unwrap().status,
        DigestStatus::Preview
    );

    let r = digest::run_scheduled(&s.app.state, day(), Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(r.claimed, "the scheduler claims a previewed day");
    assert_eq!(r.attempts, 2);
    assert_eq!(r.status, DigestStatus::Sent);
    assert_eq!(r.sent, 1);
    assert_eq!(mailer.count(), 1);
    let stored = store.get(DAY).await.unwrap().unwrap();
    assert_eq!(stored.status, DigestStatus::Sent);
    assert!(stored.sent_at.is_some());

    let again = digest::run_scheduled(&s.app.state, day(), Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(!again.claimed);
    assert_eq!(again.status, DigestStatus::Sent);
    assert_eq!(mailer.count(), 1, "exactly once");
}

/// (b) A manual `send=true` racing the scheduled run of the same day: the
/// two go through one claim, so exactly one of them mails.
#[tokio::test]
async fn a_manual_send_racing_the_scheduler_mails_once() {
    let s = seed().await;
    let mailer = Recording::default();
    let store = DigestStore::new(&s.app.db);
    let now = DateTime::now();
    let (manual, scheduled) = tokio::join!(
        digest::run_manual(&s.app.state, day(), true, Some(&mailer), now),
        digest::run_scheduled(&s.app.state, day(), Some(&mailer), now),
    );
    let manual_claimed = match &manual {
        Ok(r) => r.claimed,
        Err(digest::RunError::Busy) => false,
        Err(e) => panic!("manual run failed: {e}"),
    };
    let scheduled = scheduled.unwrap();
    assert_ne!(
        manual_claimed, scheduled.claimed,
        "exactly one of the two held the day: {manual:?} {scheduled:?}"
    );
    assert_eq!(mailer.count(), 1, "one send across both runs");
    let stored = store.get(DAY).await.unwrap().unwrap();
    assert_eq!(stored.status, DigestStatus::Sent);
    assert_eq!(stored.attempts, 1);

    // After the race, both paths leave a sent day alone.
    let r = digest::run_manual(&s.app.state, day(), true, Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(!r.claimed);
    let r = digest::run_scheduled(&s.app.state, day(), Some(&mailer), DateTime::now())
        .await
        .unwrap();
    assert!(!r.claimed);
    assert_eq!(mailer.count(), 1);
}

/// The routes: 404 for a non-admin, the JSON shape with RFC 3339 dates and
/// no BSON, the list, and the run route storing without sending.
#[tokio::test]
async fn the_routes_answer_the_admin_and_hide_from_everyone_else() {
    let s = seed().await;
    let plain = s
        .app
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
        format!("/api/admin/growth/digest?day={DAY}"),
        "/api/admin/growth/digests".to_string(),
        format!("/api/admin/growth/digest/preview?day={DAY}"),
    ] {
        let r = s
            .app
            .auth_get(&path, &plain.access_token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 404, "{path}");
    }
    let r = s
        .app
        .auth_post(
            &format!("/api/admin/growth/digest/run?day={DAY}"),
            &plain.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);

    // Nothing stored yet: 404 for the admin too, and an empty list.
    let r = s
        .app
        .auth_get(
            &format!("/api/admin/growth/digest?day={DAY}"),
            &s.admin_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
    let list: Value = s
        .app
        .auth_get("/api/admin/growth/digests", &s.admin_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["digests"], json!([]));

    // An open day is refused.
    let r = s
        .app
        .auth_post(
            "/api/admin/growth/digest/run?day=2999-01-01",
            &s.admin_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);

    // The run route (send=false): stored, never mailed.
    let r = s
        .app
        .auth_post(
            &format!("/api/admin/growth/digest/run?day={DAY}&send=false"),
            &s.admin_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["day"], DAY);
    assert_eq!(
        body["status"], "preview",
        "send=false ends preview, never stored"
    );
    assert_eq!(body["recipients"], 1);
    assert_eq!(body["excluded"], json!({ "users": 2, "tenants": 2 }));
    assert!(body["claimed_at"].as_str().unwrap().ends_with('Z'));
    assert!(body["computed_at"].as_str().unwrap().ends_with('Z'));
    assert!(body.get("sent_at").is_none());
    assert_eq!(fig(&body["sections"]["headline"]["signups"]), (2, 3, 4));
    let text = body.to_string();
    assert!(
        !text.contains("$date") && !text.contains("$oid") && !text.contains("$numberLong"),
        "{text}"
    );
    assert!(!text.contains('@'), "an address in the stored JSON");

    // GET by day and the latest; the list carries the headline.
    let by_day: Value = s
        .app
        .auth_get(
            &format!("/api/admin/growth/digest?day={DAY}"),
            &s.admin_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(by_day["sections"]["headline"], body["sections"]["headline"]);
    let latest: Value = s
        .app
        .auth_get("/api/admin/growth/digest", &s.admin_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(latest["day"], DAY);
    let list: Value = s
        .app
        .auth_get(
            "/api/admin/growth/digests?since=2026-09-01&limit=5",
            &s.admin_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = list["digests"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["day"], DAY);
    assert_eq!(rows[0]["status"], "preview");
    assert_eq!(fig(&rows[0]["headline"]["signups"]), (2, 3, 4));
    assert!(rows[0].get("sections").is_none());

    // A run in progress on some pod: the route answers 409, and touches
    // nothing.
    s.app
        .db
        .collection::<Document>("growth_digests")
        .update_one(
            doc! { "_id": DAY },
            doc! { "$set": { "status": "computing", "claimed_at": DateTime::now() } },
        )
        .await
        .unwrap();
    let r = s
        .app
        .auth_post(
            &format!("/api/admin/growth/digest/run?day={DAY}&send=true"),
            &s.admin_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409);
    assert_eq!(
        DigestStore::new(&s.app.db)
            .get(DAY)
            .await
            .unwrap()
            .unwrap()
            .status,
        DigestStatus::Computing
    );

    let _ = s.admin_id;
}

// ── The purestat client against a fake server ───────────────────────────

/// Every request the fake saw: the `X-API-Key` header and the body.
type Seen = Arc<Mutex<Vec<(Option<String>, Value)>>>;

#[derive(Clone, Default)]
struct Fake {
    seen: Seen,
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
    let meta = |has_more: bool, offset: u64| {
        json!({ "site_domain": "roomler.ai", "hostnames": ["roomler.ai"], "date_from": body["date_from"],
                "date_to": body["date_to"], "limit": 100, "offset": offset, "has_more": has_more })
    };
    match key.as_deref() {
        Some("good") => {
            let offset = body["offset"].as_u64().unwrap_or(0);
            if offset == 0 {
                (
                    StatusCode::OK,
                    Json(json!({ "rows": [
                        { "dimensions": { "utm_source": "LinkedIn", "utm_medium": "post", "utm_campaign": "c1" },
                          "metrics": { "visitors": 52, "visits": 60, "pageviews": 265, "median_read_s": null },
                          "goals": { "signup": 1 } },
                        { "dimensions": { "utm_source": "youtub", "utm_medium": null, "utm_campaign": null },
                          "metrics": { "visitors": 7, "pageviews": 9 }, "goals": {} },
                    ], "meta": meta(true, 0) })),
                )
            } else {
                (
                    StatusCode::OK,
                    Json(json!({ "rows": [
                        { "dimensions": { "utm_source": "x" }, "metrics": { "visitors": 3, "pageviews": 3 } },
                    ], "meta": meta(false, offset) })),
                )
            }
        }
        Some("slow") => {
            tokio::time::sleep(Duration::from_secs(3)).await;
            (
                StatusCode::OK,
                Json(json!({ "rows": [], "meta": meta(false, 0) })),
            )
        }
        Some("broken") => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "unknown dimension" })),
        ),
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        ),
    }
}

async fn fake_purestat() -> (String, Fake) {
    let fake = Fake::default();
    let router = Router::new()
        .route("/api/v1/query", post(fake_query))
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), fake)
}

#[tokio::test]
async fn the_purestat_client_speaks_the_contract_pages_and_fails_honestly() {
    let (base, fake) = fake_purestat().await;
    let client = PurestatClient::with_timeout(&base, "good", Duration::from_millis(500)).unwrap();
    let q = Query::day(
        "2026-10-01",
        &["utm_source", "utm_medium", "utm_campaign"],
        &["visitors", "pageviews"],
        &["signup", "subscribe"],
    )
    .filter(Filter::starts_with("path", "/blog/"));
    let rows = client.query(&q).await.unwrap();
    assert_eq!(rows.len(), 3, "two pages followed");
    assert_eq!(rows[0].dim("utm_source"), Some("LinkedIn"));
    assert_eq!(rows[0].count("visitors"), 52);
    assert_eq!(rows[0].goal("signup"), 1);
    assert_eq!(rows[1].dim("utm_medium"), None);
    assert_eq!(rows[2].count("visitors"), 3);
    {
        let seen = fake.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[0].0.as_deref(),
            Some("good"),
            "the key travels as X-API-Key"
        );
        assert_eq!(
            seen[0].1,
            json!({
                "date_from": "2026-10-01", "date_to": "2026-10-01",
                "dimensions": ["utm_source", "utm_medium", "utm_campaign"],
                "metrics": ["visitors", "pageviews"], "goals": ["signup", "subscribe"],
                "filters": [{ "dimension": "path", "operator": "starts_with", "value": "/blog/" }],
                "limit": 100, "offset": 0,
            })
        );
        assert_eq!(
            seen[1].1["offset"], 2,
            "the second page starts past the first"
        );
    }

    let bad = PurestatClient::with_timeout(&base, "bad", Duration::from_millis(500)).unwrap();
    assert_eq!(
        bad.query(&q).await.unwrap_err(),
        PurestatError::Unauthorized
    );
    let broken = PurestatClient::with_timeout(&base, "broken", Duration::from_millis(500)).unwrap();
    assert_eq!(
        broken.query(&q).await.unwrap_err(),
        PurestatError::Status(400, "unknown dimension".into())
    );
    let slow = PurestatClient::with_timeout(&base, "slow", Duration::from_millis(300)).unwrap();
    let t0 = std::time::Instant::now();
    assert_eq!(slow.query(&q).await.unwrap_err(), PurestatError::Timeout);
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "gave up at the timeout"
    );
    // A port nothing listens on: bound, read, released.
    let closed = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };
    let unreachable = PurestatClient::with_timeout(
        &format!("http://127.0.0.1:{closed}"),
        "k",
        Duration::from_millis(500),
    )
    .unwrap();
    let e = unreachable.query(&q).await.unwrap_err();
    assert!(matches!(e, PurestatError::Transport(_)), "{e:?}");
    assert!(e.is_fatal());
}

/// With a key: the web sections are measured from purestat's rows and the
/// campaign table joins the server's sign-ups by the normalised key; with
/// a revoked key every web section reads unauthorized, and the rest of the
/// digest still completes.
#[tokio::test]
async fn the_web_sections_read_purestat_and_fail_to_not_measured() {
    let (base, _fake) = fake_purestat().await;
    for (key, expect_measured) in [("good", true), ("bad", false)] {
        let admin_id = ObjectId::new();
        let b = base.clone();
        let app = TestApp::spawn_with_settings(move |s| {
            s.stats.platform_admins = Some(admin_id.to_hex());
            s.growth.purestat_url = b;
            s.growth.purestat_api_key = key.to_string();
        })
        .await;
        // One sign-up with the key linkedin/post/c1, to join.
        insert_user(
            &app,
            ObjectId::new(),
            "j@test.io",
            at(0, 10, 0, 0),
            Some(doc! { "source": "linkedin", "medium": "post", "campaign": "C1" }),
            None,
        )
        .await;
        let sections = digest::compute(&app.state, day(), &ExclusionSet::none(), DateTime::now())
            .await
            .unwrap();
        let j = serde_json::to_value(&sections).unwrap();
        if expect_measured {
            assert_eq!(
                fig(&j["website"]["visitors"]),
                (52, 52, 52),
                "{}",
                j["website"]
            );
            assert_eq!(fig(&j["website"]["pageviews"]), (265, 265, 265));
            let rows = j["campaigns"]["rows"].as_array().unwrap();
            let li = rows
                .iter()
                .find(|r| r["source"] == "linkedin" && r["campaign"] == "c1")
                .expect("the linkedin row");
            assert_eq!(li["medium"], "post");
            assert_eq!(li["visitors"], 52);
            assert_eq!(li["goals"]["signup"], 1);
            assert_eq!(li["signups"], 1, "joined by the normalised key");
            assert!(
                rows.iter().any(|r| r["source"] == "youtube"),
                "youtub normalised: {rows:?}"
            );
            assert_eq!(j["headline"]["coverage"]["purestat_signup_goals"], 1);
            assert_eq!(j["headline"]["coverage"]["server_signups"], 1);
            assert!(
                j["headline"]["coverage"].get("ratio").is_none(),
                "no ratio below n = 30"
            );
        } else {
            for k in ["website", "blog", "campaigns"] {
                let (reason, _) = not_measured(&j[k]).unwrap_or_else(|| panic!("{k}: {}", j[k]));
                assert!(reason.contains("unauthorized"), "{k}: {reason}");
            }
            assert!(not_measured(&j["headline"]["coverage"]).is_some());
        }
        // Either way the rest completed.
        assert_eq!(fig(&j["signups"]["total"]), (1, 1, 1));
    }
}
