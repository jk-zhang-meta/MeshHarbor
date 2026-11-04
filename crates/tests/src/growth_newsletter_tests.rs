// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P5 — the newsletter's delivery side, against a real server and
//! signed requests (spec §3h, D5, D6):
//!
//! * **AC14 (the test half)**: SendGrid's Event Webhook refuses a missing
//!   or bad signature — before the body is parsed — and records `delivered`
//!   and a hard `bounce` on the issue's ledger rows; the bounced address is
//!   suppressed at the next send; opens and clicks are never recorded.
//! * The per-issue unsubscribe (`i=<slug>` → `subscribers.unsubscribed_via`).
//! * The per-issue table (`GET /api/admin/growth/newsletter`) and the
//!   digest's newsletter section: delivery is `not_measured` unless this
//!   server verifies the webhook, never 0.
//!
//! (AC15 — every link but the unsubscribe link byte-identical for two
//! recipients — is the `saas` crate's unit test on the exact functions the
//! fan-out composes a message with: `newsletter_send::tests`.)

use base64::Engine;
use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::{Value, json};

use crate::{
    fixtures::test_app::TestApp,
    growth_campaigns_tests::{at_day, count, ds, get_json, today},
};

const WEBHOOK: &str = "/api/sendgrid/webhook";
const SIG: &str = "x-twilio-email-event-webhook-signature";
const TS: &str = "x-twilio-email-event-webhook-timestamp";

/// A P-256 key pair, and its public half as SendGrid shows it.
fn keypair() -> (EcdsaKeyPair, String) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let mut spki = meshharbor_services::sendgrid::P256_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(pair.public_key().as_ref());
    (pair, base64::engine::general_purpose::STANDARD.encode(spki))
}

fn sign(pair: &EcdsaKeyPair, ts: &str, body: &[u8]) -> String {
    let mut msg = ts.as_bytes().to_vec();
    msg.extend_from_slice(body);
    let sig = pair.sign(&SystemRandom::new(), &msg).unwrap();
    base64::engine::general_purpose::STANDARD.encode(sig.as_ref())
}

fn now_secs() -> i64 {
    DateTime::now().timestamp_millis() / 1000
}

/// POST `body` to the webhook with the given headers, from a client with
/// no cookies. `(status, body text)`.
async fn post_raw(
    app: &TestApp,
    body: &[u8],
    sig: Option<&str>,
    ts: Option<&str>,
) -> (u16, String) {
    let mut req = reqwest::Client::new()
        .post(app.url(WEBHOOK))
        .header("content-type", "application/json")
        .body(body.to_vec());
    if let Some(s) = sig {
        req = req.header(SIG, s);
    }
    if let Some(t) = ts {
        req = req.header(TS, t);
    }
    let r = req.send().await.unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

/// POST `events`, signed now by `pair`. `(status, answer)`.
async fn post_signed(app: &TestApp, pair: &EcdsaKeyPair, events: &Value) -> (u16, Value) {
    let body = events.to_string().into_bytes();
    let ts = now_secs().to_string();
    let (status, text) = post_raw(app, &body, Some(&sign(pair, &ts, &body)), Some(&ts)).await;
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

/// An app with the webhook key, a platform admin, and a mail host that does
/// not resolve (every send fails; the fan-out still ledgers each recipient).
async fn app_with_webhook(key: Option<String>) -> (TestApp, String) {
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
        s.email.smtp_host = Some("mailer.does-not-exist.invalid".into());
        s.email.smtp_port = Some(1025);
        if let Some(k) = key {
            s.newsletter.event_webhook_public_key = k;
        }
    })
    .await;
    let token = app
        .state
        .auth
        .generate_tokens(admin_id, "padmin@test.io", "padmin")
        .unwrap()
        .access_token;
    (app, token)
}

async fn subscriber(app: &TestApp, email: &str) -> ObjectId {
    let id = ObjectId::new();
    app.db
        .collection::<Document>("subscribers")
        .insert_one(doc! {
            "_id": id, "email": email, "source": "landing", "confirmed": true,
            "unsubscribe_token": format!("tok-{id}"),
            "created_at": DateTime::now(), "confirmed_at": DateTime::now(),
        })
        .await
        .unwrap();
    id
}

/// A completed issue with one `sent` ledger row per subscriber, stamped as
/// a P5 fan-out stamps it.
async fn sent_issue(
    app: &TestApp,
    slug: &str,
    subs: &[(ObjectId, &str)],
    sent_at: DateTime,
) -> ObjectId {
    let id = ObjectId::new();
    let n = subs.len() as i64;
    app.db
        .collection::<Document>("newsletter_issues")
        .insert_one(doc! {
            "_id": id, "slug": slug, "subject": format!("Issue {slug}"), "preheader": "p",
            "body_md": "b", "status": "completed",
            "counts": { "total": n, "sent": n, "failed": 0_i64, "suppressed": 0_i64, "stale": 0_i64 },
            "created_at": sent_at, "updated_at": sent_at, "sent_at": sent_at,
            "campaign": format!("nl-{slug}"), "delivery_events": true,
        })
        .await
        .unwrap();
    for (sub, email) in subs {
        app.db
            .collection::<Document>("newsletter_sends")
            .insert_one(doc! {
                "issue_id": id, "subscriber_id": sub, "email": *email, "status": "sent",
                "claimed_at": sent_at, "updated_at": sent_at, "sent_at": sent_at,
            })
            .await
            .unwrap();
    }
    id
}

async fn send_row(app: &TestApp, issue: ObjectId, sub: ObjectId) -> Document {
    app.db
        .collection::<Document>("newsletter_sends")
        .find_one(doc! { "issue_id": issue, "subscriber_id": sub })
        .await
        .unwrap()
        .expect("the ledger row")
}

async fn sub_row(app: &TestApp, id: ObjectId) -> Document {
    app.db
        .collection::<Document>("subscribers")
        .find_one(doc! { "_id": id })
        .await
        .unwrap()
        .expect("the subscriber")
}

fn event(kind: &str, email: &str, issue: Option<&str>) -> Value {
    let mut e = json!({
        "event": kind, "email": email, "timestamp": now_secs() - 60,
        "sg_event_id": format!("ev-{kind}-{email}"), "sg_message_id": "m.filter0001",
    });
    if let Some(i) = issue {
        e["nl_issue"] = json!(i);
    }
    e
}

/// Without a key the webhook does not exist — the empty 404 of an absent
/// path, whatever is posted.
#[tokio::test]
async fn without_a_key_the_webhook_is_an_absent_path() {
    let (app, _) = app_with_webhook(None).await;
    let (pair, _) = keypair();
    let (status, body) = post_raw(&app, b"[]", None, None).await;
    assert_eq!(status, 404);
    assert!(body.is_empty(), "the empty 404: {body:?}");
    let (status, _) = post_signed(&app, &pair, &json!([])).await;
    assert_eq!(
        status, 404,
        "a signed post with no key to verify it: still absent"
    );
}

/// AC14 control — a missing, stale or wrong signature is refused with 401
/// BEFORE the body is parsed (a non-JSON body still gets 401, not 400), and
/// writes nothing; only a verified body is parsed (then non-JSON is 400).
#[tokio::test]
async fn a_missing_stale_or_bad_signature_is_refused_before_parsing() {
    let (pair, key) = keypair();
    let (app, _) = app_with_webhook(Some(key)).await;
    let a = subscriber(&app, "a@test.io").await;
    let issue = sent_issue(&app, "oct", &[(a, "a@test.io")], DateTime::now()).await;
    let events = json!([event("delivered", "a@test.io", Some("oct"))]).to_string();
    let body = events.as_bytes();
    let ts = now_secs().to_string();

    // No headers at all; one header only.
    assert_eq!(post_raw(&app, body, None, None).await.0, 401);
    assert_eq!(
        post_raw(&app, body, Some(&sign(&pair, &ts, body)), None)
            .await
            .0,
        401
    );
    assert_eq!(post_raw(&app, body, None, Some(&ts)).await.0, 401);
    // Signed by another key.
    let (other, _) = keypair();
    assert_eq!(
        post_raw(&app, body, Some(&sign(&other, &ts, body)), Some(&ts))
            .await
            .0,
        401
    );
    // A signature over a different body, or a different timestamp.
    let tampered = events.replace("delivered", "bounce").into_bytes();
    assert_eq!(
        post_raw(&app, &tampered, Some(&sign(&pair, &ts, body)), Some(&ts))
            .await
            .0,
        401
    );
    let later = (now_secs() + 1).to_string();
    assert_eq!(
        post_raw(&app, body, Some(&sign(&pair, &ts, body)), Some(&later))
            .await
            .0,
        401
    );
    // A genuine signature from outside the window (a replay of a 2-day-old
    // batch).
    let old = (now_secs() - 2 * 86_400).to_string();
    assert_eq!(
        post_raw(&app, body, Some(&sign(&pair, &old, body)), Some(&old))
            .await
            .0,
        401
    );
    // Refused BEFORE parsing: garbage that would be a 400 if it were parsed
    // first is a 401 when its signature is wrong…
    let junk = b"this is not json {";
    assert_eq!(
        post_raw(&app, junk, Some("bm90IGEgc2lnbmF0dXJl"), Some(&ts))
            .await
            .0,
        401
    );
    // …and only a VERIFIED body reaches the parser.
    assert_eq!(
        post_raw(&app, junk, Some(&sign(&pair, &ts, junk)), Some(&ts))
            .await
            .0,
        400
    );
    assert!(
        send_row(&app, issue, a).await.get("delivery").is_none(),
        "no refused request wrote anything"
    );
}

/// AC14 (the test half) — `delivered` and a hard `bounce` land on the
/// issue's ledger rows; the bounce suppresses its address, a block does
/// not; opens and clicks — and every other kind, and every message that is
/// not a newsletter's — are recorded as nothing; a replay changes nothing;
/// and at the NEXT send the bounced address is `suppressed`, never mailed.
#[tokio::test]
async fn delivered_and_a_hard_bounce_are_recorded_and_the_bounce_is_suppressed_at_the_next_send() {
    let (pair, key) = keypair();
    let (app, token) = app_with_webhook(Some(key)).await;
    let a = subscriber(&app, "a@test.io").await;
    let b = subscriber(&app, "b@test.io").await;
    let c = subscriber(&app, "c@test.io").await;
    let issue = sent_issue(
        &app,
        "oct",
        &[(a, "a@test.io"), (b, "b@test.io"), (c, "c@test.io")],
        DateTime::now(),
    )
    .await;

    let mut hard = event("bounce", "B@Test.io", Some("oct"));
    hard["type"] = json!("bounce");
    hard["reason"] = json!("550 5.1.1 no such user");
    let mut blocked = event("bounce", "c@test.io", Some("oct"));
    blocked["type"] = json!("blocked");
    let mut transactional = event("bounce", "a@test.io", None);
    transactional["type"] = json!("bounce");
    let batch = json!([
        event("processed", "a@test.io", Some("oct")),
        event("delivered", "a@test.io", Some("oct")),
        event("open", "a@test.io", Some("oct")),
        event("click", "a@test.io", Some("oct")),
        hard,
        blocked,
        transactional,
        event("delivered", "stranger@test.io", Some("oct")),
        event("delivered", "a@test.io", Some("no-such-issue")),
    ]);
    let (status, r) = post_signed(&app, &pair, &batch).await;
    assert_eq!(status, 200, "{r}");
    assert_eq!(r["events"], 9);
    assert_eq!(r["recorded"], 3, "delivered a, the hard bounce, the block");
    assert_eq!(
        r["ignored"], 4,
        "processed, open, click and the transactional bounce"
    );
    assert_eq!(r["unmatched"], 2, "an unknown address, an unknown issue");
    assert_eq!(r["suppressed"], 1);

    let row_a = send_row(&app, issue, a).await;
    let d = row_a.get_document("delivery").unwrap();
    assert!(d.get_datetime("delivered_at").is_ok());
    let keys: Vec<&str> = d.keys().map(String::as_str).collect();
    assert_eq!(keys, ["delivered_at"], "nothing but the delivery: {d}");
    assert_eq!(
        row_a.get_str("status").unwrap(),
        "sent",
        "our disposition is untouched"
    );
    // Nothing anywhere names an open or a click.
    let all: Vec<Document> = {
        use futures::TryStreamExt;
        app.db
            .collection::<Document>("newsletter_sends")
            .find(doc! {})
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap()
    };
    for row in &all {
        let text = row.to_string();
        assert!(!text.contains("open") && !text.contains("click"), "{text}");
    }

    let row_b = send_row(&app, issue, b).await;
    let d = row_b.get_document("delivery").unwrap();
    assert!(d.get_datetime("bounced_at").is_ok());
    assert_eq!(d.get_str("bounce_type").unwrap(), "bounce");
    assert_eq!(d.get_str("reason").unwrap(), "550 5.1.1 no such user");
    let sub_b = sub_row(&app, b).await;
    assert!(sub_b.get_datetime("suppressed_at").is_ok());
    assert_eq!(sub_b.get_str("suppressed_reason").unwrap(), "bounce");
    assert!(
        sub_b.get_bool("confirmed").unwrap(),
        "suppressed, not unsubscribed"
    );

    let row_c = send_row(&app, issue, c).await;
    assert_eq!(
        row_c
            .get_document("delivery")
            .unwrap()
            .get_str("bounce_type")
            .unwrap(),
        "blocked"
    );
    assert!(
        sub_row(&app, c).await.get("suppressed_at").is_none(),
        "a block never costs the address its subscription"
    );

    // A replay of the same signed batch changes nothing.
    let before = send_row(&app, issue, a).await;
    let (status, _) = post_signed(&app, &pair, &batch).await;
    assert_eq!(status, 200);
    assert_eq!(
        send_row(&app, issue, a)
            .await
            .get_document("delivery")
            .unwrap(),
        before.get_document("delivery").unwrap()
    );

    // The NEXT send: b is suppressed — claimed and never mailed — while a
    // and c are attempted (and fail: the mail host does not resolve).
    let r = app
        .auth_post("/api/admin/newsletter/issues", &token)
        .json(&json!({
            "slug": "nov", "subject": "November", "preheader": "p",
            "body_md": "Read [the docs](https://roomler.ai/docs).",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 201);
    let r = app
        .auth_post("/api/admin/newsletter/issues/nov/send", &token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 202);
    let nov = wait_completed(&app, "nov").await;
    assert_eq!(
        nov.get_str("campaign").unwrap(),
        "nl-nov",
        "the fan-out stamps the campaign its links carried"
    );
    assert!(nov.get_bool("delivery_events").unwrap());
    let nov_id = nov.get_object_id("_id").unwrap();
    assert_eq!(
        send_row(&app, nov_id, b).await.get_str("status").unwrap(),
        "suppressed"
    );
    assert_eq!(
        send_row(&app, nov_id, a).await.get_str("status").unwrap(),
        "failed"
    );
    assert_eq!(
        send_row(&app, nov_id, c).await.get_str("status").unwrap(),
        "failed"
    );

    // Fresh consent lifts the suppression: the address subscribes again,
    // and the row is revived UNCONFIRMED — the confirmation click is the
    // proof the mailbox works.
    let r = reqwest::Client::new()
        .post(app.url("/api/subscribe"))
        .json(&json!({ "email": "b@test.io", "source": "landing" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 202);
    let sub_b = sub_row(&app, b).await;
    assert!(sub_b.get("suppressed_at").is_none());
    assert!(!sub_b.get_bool("confirmed").unwrap());
}

/// A TEST issue (the field run AC14 needs on production) goes only to the
/// confirmed subscribers among its audience — never to the list — and the
/// per-issue table shows the audience's size, never its addresses.
#[tokio::test]
async fn a_test_issue_goes_only_to_its_audience() {
    let (app, token) = app_with_webhook(None).await;
    let a = subscriber(&app, "a@test.io").await;
    let b = subscriber(&app, "b@test.io").await;
    let c = subscriber(&app, "c@test.io").await;

    // An audience must name 1–20 plausible addresses.
    for bad in [json!([]), json!(["nope"])] {
        let r = app
            .auth_post("/api/admin/newsletter/issues", &token)
            .json(&json!({
                "slug": "bad-audience", "subject": "s", "preheader": "p",
                "body_md": "b", "audience": bad,
            }))
            .send()
            .await
            .unwrap();
        assert!(r.status().is_client_error(), "{bad}: {}", r.status());
    }

    let r = app
        .auth_post("/api/admin/newsletter/issues", &token)
        .json(&json!({
            "slug": "field-test", "subject": "Field test", "preheader": "p",
            "body_md": "Read [the docs](https://roomler.ai/docs).",
            "audience": ["A@Test.io", "c@test.io", "nobody@test.io"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 201);
    let created: Value = r.json().await.unwrap();
    assert_eq!(
        created["audience"],
        json!(["a@test.io", "c@test.io", "nobody@test.io"]),
        "normalised to the store's spelling"
    );
    let r = app
        .auth_post("/api/admin/newsletter/issues/field-test/send", &token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 202);
    let issue = wait_completed(&app, "field-test").await;
    let id = issue.get_object_id("_id").unwrap();
    assert_eq!(
        count(&app, "newsletter_sends", doc! { "issue_id": id }).await,
        2,
        "a and c — never b, and an address on no list is no recipient"
    );
    assert_eq!(
        count(
            &app,
            "newsletter_sends",
            doc! { "issue_id": id, "subscriber_id": b }
        )
        .await,
        0
    );
    for sub in [a, c] {
        assert_eq!(
            count(
                &app,
                "newsletter_sends",
                doc! { "issue_id": id, "subscriber_id": sub }
            )
            .await,
            1
        );
    }

    let path = format!("/api/admin/growth/newsletter?until={}", ds(today()));
    let (status, j) = get_json(&app, &path, &token).await;
    assert_eq!(status, 200, "{j}");
    let row = j["issues"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["slug"] == "field-test")
        .expect("the test issue");
    assert_eq!(row["test_audience"], 3);
    assert_eq!(row["ledger"]["recipients"], 2);
    assert!(
        !j.to_string().contains("@test.io"),
        "the size, never the addresses"
    );
}

/// A spam report suppresses too; a `dropped` is recorded with its reason
/// and suppresses nothing.
#[tokio::test]
async fn a_spam_report_suppresses_and_a_drop_does_not() {
    let (pair, key) = keypair();
    let (app, _) = app_with_webhook(Some(key)).await;
    let a = subscriber(&app, "a@test.io").await;
    let b = subscriber(&app, "b@test.io").await;
    let issue = sent_issue(
        &app,
        "oct",
        &[(a, "a@test.io"), (b, "b@test.io")],
        DateTime::now(),
    )
    .await;
    let mut dropped = event("dropped", "b@test.io", Some("oct"));
    dropped["reason"] = json!("Bounced Address");
    let (status, r) = post_signed(
        &app,
        &pair,
        &json!([
            event("delivered", "a@test.io", Some("oct")),
            event("spamreport", "a@test.io", Some("oct")),
            dropped
        ]),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        (r["recorded"].as_i64(), r["suppressed"].as_i64()),
        (Some(3), Some(1))
    );
    let d = send_row(&app, issue, a).await;
    let d = d.get_document("delivery").unwrap();
    assert!(d.get_datetime("delivered_at").is_ok() && d.get_datetime("spam_reported_at").is_ok());
    assert_eq!(
        sub_row(&app, a).await.get_str("suppressed_reason").unwrap(),
        "spamreport"
    );
    let d = send_row(&app, issue, b).await;
    assert_eq!(
        d.get_document("delivery")
            .unwrap()
            .get_str("reason")
            .unwrap(),
        "Bounced Address"
    );
    assert!(sub_row(&app, b).await.get("suppressed_at").is_none());
}

/// Poll until the issue completes — the fan-out runs behind a 202.
async fn wait_completed(app: &TestApp, slug: &str) -> Document {
    for _ in 0..60 {
        let row = app
            .db
            .collection::<Document>("newsletter_issues")
            .find_one(doc! { "slug": slug })
            .await
            .unwrap()
            .expect("issue exists");
        if row.get_str("status").unwrap() == "completed" {
            return row;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    panic!("issue `{slug}` never completed");
}

/// D5 — the unsubscribe link of issue X carries `i=X` (the same for every
/// recipient); the click records it, once. A repeat click (a prefetcher)
/// changes nothing; a link naming no sent issue unsubscribes all the same
/// and records no issue; the RFC 8058 one-click POST records it too.
#[tokio::test]
async fn an_unsubscribe_through_an_issue_link_records_the_issue_once() {
    let (app, _) = app_with_webhook(None).await;
    let a = subscriber(&app, "a@test.io").await;
    let b = subscriber(&app, "b@test.io").await;
    let c = subscriber(&app, "c@test.io").await;
    sent_issue(&app, "oct", &[(a, "a@test.io")], DateTime::now()).await;
    app.db
        .collection::<Document>("newsletter_issues")
        .insert_one(doc! {
            "slug": "draft-one", "subject": "s", "preheader": "p", "body_md": "b",
            "status": "draft", "created_at": DateTime::now(), "updated_at": DateTime::now(),
        })
        .await
        .unwrap();
    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let visit = |token: String, query: &'static str| {
        let url = app.url(&format!("/api/subscribe/unsubscribe/{token}{query}"));
        let client = no_redirect.clone();
        async move { client.get(url).send().await.unwrap().status().as_u16() }
    };

    assert!((300..400).contains(&visit(format!("tok-{a}"), "?i=oct").await));
    let row = sub_row(&app, a).await;
    assert_eq!(row.get_str("unsubscribed_via").unwrap(), "oct");
    let first = row.get_datetime("unsubscribed_at").unwrap().to_owned();
    // A repeat click, even through another issue's link, changes nothing.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    visit(format!("tok-{a}"), "?i=draft-one").await;
    let row = sub_row(&app, a).await;
    assert_eq!(row.get_str("unsubscribed_via").unwrap(), "oct");
    assert_eq!(row.get_datetime("unsubscribed_at").unwrap(), &first);

    // Naming a draft, an unknown issue or garbage: unsubscribed, no issue.
    for (sub, q) in [(b, "?i=draft-one"), (c, "?i=%E2%80%AE../x&i=oct")] {
        assert!((300..400).contains(&visit(format!("tok-{sub}"), q).await));
        let row = sub_row(&app, sub).await;
        assert!(row.get_datetime("unsubscribed_at").is_ok(), "{q}");
        assert!(row.get("unsubscribed_via").is_none(), "{q}: {row}");
    }

    // The one-click POST (List-Unsubscribe) carries the same link.
    let d = subscriber(&app, "d@test.io").await;
    let r = reqwest::Client::new()
        .post(app.url(&format!("/api/subscribe/unsubscribe/tok-{d}?i=oct")))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("List-Unsubscribe=One-Click")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(
        sub_row(&app, d).await.get_str("unsubscribed_via").unwrap(),
        "oct"
    );
}

/// The per-issue table: recipients and accepted from the ledger, delivery
/// from the webhook's events, unsubscribes through the issue's link,
/// sign-ups by the issue's campaign key (exclusions applied); visits
/// `not_measured` without a purestat key — never 0; delivery `not_measured`
/// on a server that does not verify the webhook. Platform admins only.
#[tokio::test]
async fn the_per_issue_table_counts_each_issue_and_never_shows_an_unmeasured_zero() {
    let (pair, key) = keypair();
    let (app, token) = app_with_webhook(Some(key)).await;
    let y = today() - chrono::Duration::days(1);
    let subs: Vec<(ObjectId, String)> = {
        let mut v = Vec::new();
        for i in 0..4 {
            let email = format!("r{i}@test.io");
            v.push((subscriber(&app, &email).await, email));
        }
        v
    };
    let pairs: Vec<(ObjectId, &str)> = subs.iter().map(|(id, e)| (*id, e.as_str())).collect();
    sent_issue(&app, "oct", &pairs, at_day(y, 9)).await;
    let mut hard = event("bounce", "r3@test.io", Some("oct"));
    hard["type"] = json!("bounce");
    let (status, _) = post_signed(
        &app,
        &pair,
        &json!([
            event("delivered", "r0@test.io", Some("oct")),
            event("delivered", "r1@test.io", Some("oct")),
            event("delivered", "r2@test.io", Some("oct")),
            event("spamreport", "r2@test.io", Some("oct")),
            hard,
        ]),
    )
    .await;
    assert_eq!(status, 200);
    // r1 leaves through the issue's link.
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(app.url(&format!(
            "/api/subscribe/unsubscribe/tok-{}?i=oct",
            subs[1].0
        )))
        .send()
        .await
        .unwrap();
    // Two sign-ups through the issue's link (one with the link's own
    // spelling cased differently) and one through another campaign.
    for (email, campaign) in [
        ("s1@test.io", "nl-oct"),
        ("s2@test.io", "NL-Oct"),
        ("s3@test.io", "20261019-x"),
    ] {
        signup(&app, ObjectId::new(), email, at_day(y, 12), campaign).await;
    }

    // The range runs through today: the list's changes above happened now.
    let path = format!("/api/admin/growth/newsletter?until={}", ds(today()));
    let (status, j) = get_json(&app, &path, &token).await;
    assert_eq!(status, 200, "{j}");
    assert_eq!(j["webhook_configured"], true);
    let issue = &j["issues"][0];
    assert_eq!(issue["slug"], "oct");
    assert_eq!(issue["campaign"], "nl-oct");
    assert_eq!(issue["ledger"]["recipients"], 4);
    assert_eq!(issue["ledger"]["accepted"], 4);
    assert_eq!(issue["delivery"]["delivered"], 3);
    assert_eq!(issue["delivery"]["bounced"], 1);
    assert_eq!(issue["delivery"]["hard_bounced"], 1);
    assert_eq!(issue["delivery"]["complaints"], 1);
    assert_eq!(issue["unsubscribed_via"], 1);
    assert_eq!(
        issue["signups"], 2,
        "the issue's key, both spellings: {issue}"
    );
    assert!(
        issue["web"]["not_measured"].is_string(),
        "no purestat key: not measured, never 0 — {}",
        issue["web"]
    );
    assert_eq!(issue["rates"]["delivered"]["n"], 4);
    assert!(
        issue["rates"]["delivered"].get("value").is_none(),
        "n < 30: counts only"
    );
    // The list: four confirmed today, one unsubscribed (via the issue), two
    // suppressed (the hard bounce and the spam report).
    let list = &j["list"];
    assert_eq!(list["totals"]["unsubscribed_via_issue"], 1);
    assert_eq!(list["size"]["suppressed"], 2);
    assert_eq!(list["size"]["mailable"], 1, "r0 only");
    assert!(
        !j.to_string().contains("@test.io"),
        "no address in the view: {j}"
    );

    // Not a platform admin: the same 404 as any growth route.
    let outsider = app
        .state
        .auth
        .generate_tokens(ObjectId::new(), "x@test.io", "x")
        .unwrap()
        .access_token;
    assert_eq!(
        get_json(&app, "/api/admin/growth/newsletter", &outsider)
            .await
            .0,
        404
    );

    // A server that does not verify the webhook: delivery is not measured.
    let (app2, token2) = app_with_webhook(None).await;
    let r = subscriber(&app2, "z@test.io").await;
    sent_issue(&app2, "oct", &[(r, "z@test.io")], at_day(y, 9)).await;
    let (_, j) = get_json(&app2, "/api/admin/growth/newsletter", &token2).await;
    assert_eq!(j["webhook_configured"], false);
    assert!(
        j["issues"][0]["delivery"]["not_measured"]
            .as_str()
            .unwrap()
            .contains("EVENT_WEBHOOK_PUBLIC_KEY"),
        "{}",
        j["issues"][0]["delivery"]
    );
    assert_eq!(j["issues"][0]["ledger"]["accepted"], 1);
}

async fn signup(app: &TestApp, id: ObjectId, email: &str, created: DateTime, campaign: &str) {
    app.db
        .collection::<Document>("users")
        .insert_one(doc! {
            "_id": id, "email": email, "username": email.split('@').next().unwrap(),
            "display_name": "A Person", "avatar": Bson::Null, "bio": Bson::Null,
            "is_verified": true, "is_mfa_enabled": false, "last_active_at": Bson::Null,
            "oauth_providers": [], "created_at": created, "updated_at": created,
            "deleted_at": Bson::Null,
            "signup_attribution": { "source": "newsletter", "medium": "email", "campaign": campaign },
        })
        .await
        .unwrap();
}

/// The digest's newsletter section carries the day's delivery figures and
/// each issue's delivery — and, on a server without the webhook, says
/// "not measured", never 0. No address reaches it.
#[tokio::test]
async fn the_digest_reads_delivery_and_says_when_it_cannot() {
    let (pair, key) = keypair();
    let (app, token) = app_with_webhook(Some(key)).await;
    let y = today() - chrono::Duration::days(1);
    let a = subscriber(&app, "a@test.io").await;
    sent_issue(&app, "oct", &[(a, "a@test.io")], at_day(y, 9)).await;
    let mut delivered = event("delivered", "a@test.io", Some("oct"));
    delivered["timestamp"] = json!(at_day(y, 9).timestamp_millis() / 1000 + 120);
    assert_eq!(post_signed(&app, &pair, &json!([delivered])).await.0, 200);

    let (status, j) = get_json(
        &app,
        &format!("/api/admin/growth/digest/preview?day={}", ds(y)),
        &token,
    )
    .await;
    assert_eq!(status, 200, "{j}");
    let nl = &j["sections"]["newsletter"];
    assert_eq!(nl["delivery"]["delivered"]["day"], 1, "{nl}");
    assert_eq!(nl["issues"][0]["slug"], "oct");
    assert_eq!(nl["issues"][0]["delivery"]["delivered"], 1);
    assert_eq!(nl["issues"][0]["unsubscribed_via"], 0);
    assert!(!j.to_string().contains("a@test.io"));

    let (app2, token2) = app_with_webhook(None).await;
    let r = subscriber(&app2, "z@test.io").await;
    sent_issue(&app2, "oct", &[(r, "z@test.io")], at_day(y, 9)).await;
    let (_, j) = get_json(
        &app2,
        &format!("/api/admin/growth/digest/preview?day={}", ds(y)),
        &token2,
    )
    .await;
    let nl = &j["sections"]["newsletter"];
    assert!(nl["delivery"]["not_measured"].is_string(), "{nl}");
    assert!(nl["issues"][0]["delivery"]["not_measured"].is_string());
    assert_eq!(count(&app2, "newsletter_sends", doc! {}).await, 1);
}
