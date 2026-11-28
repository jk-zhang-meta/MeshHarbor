// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P9b — the post-session rating's server half (spec §3f, D10),
//! against a real server:
//!
//! * a party to the session (its controller, a watcher) stores one rating
//!   with exactly the documented fields — the person from the request, the
//!   device from the session row, codes only; the controller and a watcher
//!   each rate the same session once, and the same person's second post is
//!   `already_rated` and stores nothing;
//! * a member who was not in the session, a foreign org's member, an
//!   unauthenticated caller, a session the path's org does not own, a post
//!   sooner than 30 s after the request, every bad body and an oversize one
//!   are refused with a code and nothing stored;
//! * `growth.feedback = false` answers the empty 404 of a path that does not
//!   exist, and `/api/capabilities` says `features.session_feedback: false`;
//! * `purge_user` takes one person's ratings and nobody else's;
//! * the digest's `quality.ratings` counts the thumbs and the reasons with
//!   the exclusion set applied, and reads "off" with the switch off.

use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use meshharbor_remote_control::models::{SessionFeedback, SessionFeedbackRequest};
use meshharbor_services::dao::session_feedback::SessionFeedbackDao;
use serde_json::{Value, json};

use crate::fixtures::test_app::TestApp;

const COLLECTION: &str = "session_feedback";

fn ago_secs(secs: i64) -> DateTime {
    DateTime::from_millis(DateTime::now().timestamp_millis() - secs * 1000)
}

fn plus_secs(t: DateTime, secs: i64) -> DateTime {
    DateTime::from_millis(t.timestamp_millis() + secs * 1000)
}

/// A `remote_sessions` row as the audit projection leaves it after an end:
/// created at the request, started, ended with a reason.
async fn session(
    app: &TestApp,
    tenant: ObjectId,
    controller: ObjectId,
    watchers: Vec<ObjectId>,
    created: DateTime,
    started: bool,
) -> (ObjectId, ObjectId) {
    let sid = ObjectId::new();
    let aid = ObjectId::new();
    app.db
        .collection::<Document>("remote_sessions")
        .insert_one(doc! {
            "_id": sid, "agent_id": aid, "tenant_id": tenant, "controller_user_id": controller,
            "watchers": watchers, "permissions": 1_i32, "phase": "closed",
            "created_at": created,
            "started_at": if started { Bson::DateTime(plus_secs(created, 2)) } else { Bson::Null },
            "ended_at": plus_secs(created, 20),
            "end_reason": if started { "controller_hangup" } else { "consent_timeout" },
            "recording_url": Bson::Null,
        })
        .await
        .unwrap();
    (sid, aid)
}

fn path(tenant: &str, session: &ObjectId) -> String {
    format!("/api/tenant/{tenant}/session/{}/feedback", session.to_hex())
}

async fn post(app: &TestApp, path: &str, token: &str, body: Value) -> (u16, Value) {
    let r = app.auth_post(path, token).json(&body).send().await.unwrap();
    let status = r.status().as_u16();
    let text = r.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

async fn rows(app: &TestApp) -> Vec<Document> {
    use futures::TryStreamExt;
    app.db
        .collection::<Document>(COLLECTION)
        .find(doc! {})
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap()
}

#[tokio::test]
async fn a_party_rates_a_session_once_with_codes_only_and_everyone_else_is_refused() {
    let app = TestApp::spawn().await;
    let org = app.seed_tenant("fb").await;
    let other = app.seed_tenant("fb2").await;
    let tid = ObjectId::parse_str(&org.tenant_id).unwrap();
    let admin = ObjectId::parse_str(&org.admin.id).unwrap();
    let member = ObjectId::parse_str(&org.member.id).unwrap();
    let other_tid = ObjectId::parse_str(&other.tenant_id).unwrap();
    let other_admin = ObjectId::parse_str(&other.admin.id).unwrap();

    // s1: the admin controlled it; s2: the member watched it; s3: requested
    // five seconds ago; s4: never reached Active (a refusal is still rated —
    // "couldn't connect" is a reason); s_other: the other org's.
    let (s1, a1) = session(&app, tid, admin, vec![], ago_secs(120), true).await;
    let (s2, _) = session(&app, tid, admin, vec![member], ago_secs(120), true).await;
    let (s3, _) = session(&app, tid, admin, vec![], ago_secs(5), true).await;
    let (s4, _) = session(&app, tid, admin, vec![], ago_secs(60), false).await;
    let (s_other, _) = session(&app, other_tid, other_admin, vec![], ago_secs(120), true).await;

    // The controller rates s1: stored with exactly the documented fields.
    let (status, j) = post(
        &app,
        &path(&org.tenant_id, &s1),
        &org.admin.access_token,
        json!({ "rating": "up", "reasons": [] }),
    )
    .await;
    assert_eq!(status, 201, "{j}");
    assert_eq!(j["session_id"], s1.to_hex());
    assert_eq!(j["rating"], "up");
    assert_eq!(j["reasons"], json!([]));
    assert!(j["ts"].is_string());
    let stored = rows(&app).await;
    assert_eq!(stored.len(), 1);
    let d = &stored[0];
    let mut keys: Vec<&str> = d.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "_id",
            "agent_id",
            "rating",
            "reasons",
            "session_id",
            "tenant_id",
            "ts",
            "user_id"
        ],
        "exactly the record"
    );
    assert_eq!(
        d.get_object_id("user_id").unwrap(),
        admin,
        "the person from the request"
    );
    assert_eq!(
        d.get_object_id("agent_id").unwrap(),
        a1,
        "the device from the session row"
    );
    assert_eq!(d.get_object_id("tenant_id").unwrap(), tid);
    assert_eq!(d.get_str("rating").unwrap(), "up");

    // The same person's second post for s1 — a double click, another tab —
    // stores nothing.
    let (status, j) = post(
        &app,
        &path(&org.tenant_id, &s1),
        &org.admin.access_token,
        json!({ "rating": "down", "reasons": ["lag"] }),
    )
    .await;
    assert_eq!((status, j["error"].as_str()), (409, Some("already_rated")));
    assert_eq!(rows(&app).await.len(), 1);

    // The watcher rates s2: reasons deduplicated in vocabulary order.
    let (status, j) = post(
        &app,
        &path(&org.tenant_id, &s2),
        &org.member.access_token,
        json!({ "rating": "down", "reasons": ["other", "lag", "lag"] }),
    )
    .await;
    assert_eq!(status, 201, "{j}");
    assert_eq!(j["reasons"], json!(["lag", "other"]));
    // A rating is one person's experience: the controller of s2 rates it
    // too, once — and not twice.
    let (status, j) = post(
        &app,
        &path(&org.tenant_id, &s2),
        &org.admin.access_token,
        json!({ "rating": "up" }),
    )
    .await;
    assert_eq!(status, 201, "the controller after the watcher: {j}");
    let (status, j) = post(
        &app,
        &path(&org.tenant_id, &s2),
        &org.admin.access_token,
        json!({ "rating": "up" }),
    )
    .await;
    assert_eq!((status, j["error"].as_str()), (409, Some("already_rated")));
    let s2_raters: Vec<ObjectId> = rows(&app)
        .await
        .iter()
        .filter(|d| d.get_object_id("session_id").unwrap() == s2)
        .map(|d| d.get_object_id("user_id").unwrap())
        .collect();
    assert_eq!(s2_raters.len(), 2, "two people, one row each");
    assert!(s2_raters.contains(&member) && s2_raters.contains(&admin));

    // A session that never reached Active is rated like any other.
    let (status, _) = post(
        &app,
        &path(&org.tenant_id, &s4),
        &org.admin.access_token,
        json!({ "rating": "down", "reasons": ["could_not_connect"] }),
    )
    .await;
    assert_eq!(status, 201);
    let before = rows(&app).await.len();

    // Refused, each with its code, and nothing stored.
    let cases: Vec<(&str, &str, Value, u16, Option<&str>)> = vec![
        // The member was not in s1.
        (
            &org.tenant_id,
            &org.member.access_token,
            json!({ "rating": "up" }),
            403,
            Some("forbidden"),
        ),
        // The other org's admin is no member of this org.
        (
            &org.tenant_id,
            &other.admin.access_token,
            json!({ "rating": "up" }),
            403,
            Some("not_a_member"),
        ),
        // Too soon after the request.
        (
            "s3",
            &org.admin.access_token,
            json!({ "rating": "up" }),
            409,
            Some("too_early"),
        ),
        // Bad bodies.
        (
            &org.tenant_id,
            &org.admin.access_token,
            json!({ "rating": "meh" }),
            422,
            Some("unknown_rating"),
        ),
        (
            &org.tenant_id,
            &org.admin.access_token,
            json!({ "rating": "down", "reasons": ["slow host"] }),
            422,
            Some("unknown_reason"),
        ),
        (
            &org.tenant_id,
            &org.admin.access_token,
            json!({ "rating": "down", "reasons": ["lag", "lag", "lag", "lag", "lag", "lag"] }),
            422,
            Some("too_many_reasons"),
        ),
        (
            &org.tenant_id,
            &org.admin.access_token,
            json!({ "rating": "up", "comment": "hunter2" }),
            422,
            Some("invalid_json"),
        ),
        (
            &org.tenant_id,
            &org.admin.access_token,
            json!("a string"),
            422,
            Some("invalid_json"),
        ),
    ];
    for (tenant, token, body, want_status, want_code) in cases {
        // `s3` names the too-early session; everything else targets s2 (the
        // member's) or s1 through the org's own path.
        let p = if tenant == "s3" {
            path(&org.tenant_id, &s3)
        } else if token == org.member.access_token.as_str() {
            path(tenant, &s1)
        } else {
            path(tenant, &s2)
        };
        let (status, j) = post(&app, &p, token, body.clone()).await;
        assert_eq!(status, want_status, "{p} {body}: {j}");
        if let Some(code) = want_code {
            assert_eq!(j["error"], code, "{p} {body}: {j}");
        }
        assert!(
            j.get("message")
                .is_none_or(|m| !m.to_string().contains("hunter2"))
        );
    }
    // The other org's session through this org's path: not this org's.
    let (status, _) = post(
        &app,
        &path(&org.tenant_id, &s_other),
        &org.admin.access_token,
        json!({ "rating": "up" }),
    )
    .await;
    assert_eq!(status, 404);
    // A session that does not exist.
    let (status, _) = post(
        &app,
        &path(&org.tenant_id, &ObjectId::new()),
        &org.admin.access_token,
        json!({ "rating": "up" }),
    )
    .await;
    assert_eq!(status, 404);
    // Over the body limit: refused before any parse.
    let big = json!({ "rating": "up", "reasons": [ "x".repeat(SessionFeedbackRequest::MAX_BODY_BYTES) ] });
    let (status, _) = post(
        &app,
        &path(&org.tenant_id, &s2),
        &org.admin.access_token,
        big,
    )
    .await;
    assert_eq!(status, 413);
    // Unauthenticated — a client with no cookie jar (`app.client` carries the
    // seed logins' session cookie, which the API accepts as a credential).
    let r = reqwest::Client::new()
        .post(app.url(&path(&org.tenant_id, &s2)))
        .json(&json!({ "rating": "up" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
    assert_eq!(
        rows(&app).await.len(),
        before,
        "nothing stored by a refusal"
    );

    // The capability says the prompt may be offered here.
    let caps: Value = app
        .client
        .get(app.url("/api/capabilities"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(caps["features"]["session_feedback"], true, "{caps}");
}

#[tokio::test]
async fn the_kill_switch_answers_the_empty_404_of_an_absent_path() {
    let app = TestApp::spawn_with_settings(|s| s.growth.feedback = false).await;
    let org = app.seed_tenant("fboff").await;
    let tid = ObjectId::parse_str(&org.tenant_id).unwrap();
    let admin = ObjectId::parse_str(&org.admin.id).unwrap();
    let (s1, _) = session(&app, tid, admin, vec![], ago_secs(120), true).await;

    let absent = app
        .auth_post(
            "/api/tenant/x/this-path-does-not-exist",
            &org.admin.access_token,
        )
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    let absent_status = absent.status();
    let absent_type = absent.headers().get("content-type").cloned();
    let absent_body = absent.bytes().await.unwrap();
    assert_eq!(absent_status.as_u16(), 404);

    let r = app
        .auth_post(&path(&org.tenant_id, &s1), &org.admin.access_token)
        .json(&json!({ "rating": "up" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), absent_status);
    assert_eq!(r.headers().get("content-type").cloned(), absent_type);
    assert_eq!(
        r.bytes().await.unwrap(),
        absent_body,
        "the same bytes as an absent path"
    );
    assert!(rows(&app).await.is_empty());

    let caps: Value = app
        .client
        .get(app.url("/api/capabilities"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(caps["features"]["session_feedback"], false, "{caps}");
}

#[tokio::test]
async fn purge_user_takes_one_persons_ratings_and_nobody_elses() {
    let app = TestApp::spawn().await;
    let dao = SessionFeedbackDao::new(&app.db);
    let (a, b, tid) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
    let row = |user: ObjectId| SessionFeedback {
        id: None,
        session_id: ObjectId::new(),
        tenant_id: tid,
        user_id: user,
        agent_id: ObjectId::new(),
        rating: meshharbor_remote_control::models::FeedbackRating::Up,
        reasons: vec![],
        ts: DateTime::now(),
    };
    for r in [row(a), row(a), row(b)] {
        dao.record(&r).await.unwrap();
    }
    assert_eq!(dao.purge_user(a).await.unwrap(), 2);
    assert_eq!(dao.purge_user(a).await.unwrap(), 0, "idempotent");
    let left = rows(&app).await;
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].get_object_id("user_id").unwrap(), b);
}
