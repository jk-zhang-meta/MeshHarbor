// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-39 — the public subscribe / confirm / unsubscribe routes, against a real
//! server and a real MongoDB.
//!
//! The unit tests in `meshharbor_mod_saas::subscribe` pin the validators. These pin the
//! things a pure function cannot reach, and the first is the whole reason the
//! feature is shaped the way it is:
//!
//! **The response must not reveal whether an address is already on the list.**
//! `POST /api/subscribe` is unauthenticated and takes an address the caller may
//! not own, and those addresses are overwhelmingly also `users.email` values —
//! a unique index that is *also* the key OAuth account-linking resolves
//! against. If a fresh address and a known one produced different status codes,
//! bodies or headers, the endpoint would be a membership oracle for the user
//! table. A future "improvement" that returns 200-vs-409, or adds
//! `{"already_subscribed": true}` to be helpful, would reintroduce exactly that
//! — so it is asserted here rather than left to review.

use crate::fixtures::test_app::TestApp;
use bson::doc;

async fn post_subscribe(app: &TestApp, email: &str) -> reqwest::Response {
    app.client
        .post(app.url("/api/subscribe"))
        .json(&serde_json::json!({ "email": email, "source": "landing" }))
        .send()
        .await
        .expect("subscribe request failed")
}

/// Follow a confirm/unsubscribe link WITHOUT chasing the redirect, and return
/// where it pointed.
///
/// ⚠️ Both routes answer a redirect to `app.frontend_url`, which in a test is
/// the default `http://localhost:5000` — a port nothing is listening on. A
/// default `reqwest::Client` follows that hop and the test dies with
/// `ConnectionRefused` against port 5000 while the route under test behaved
/// perfectly. Stopping at the hop is also the better assertion: it pins *where*
/// the link sends a human, which following it silently discards.
async fn visit(app: &TestApp, path: &str) -> (reqwest::StatusCode, String) {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client build failed");
    let resp = client
        .get(app.url(path))
        .send()
        .await
        .expect("link request failed");
    let status = resp.status();
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    (status, location)
}

async fn row(app: &TestApp, email: &str) -> Option<bson::Document> {
    app.db
        .collection::<bson::Document>("subscribers")
        .find_one(doc! { "email": email })
        .await
        .expect("subscribers query failed")
}

#[tokio::test]
async fn a_fresh_address_is_stored_unconfirmed_with_both_tokens() {
    let app = TestApp::spawn().await;

    let resp = post_subscribe(&app, "fresh@example.com").await;
    assert_eq!(resp.status(), 202);

    let doc = row(&app, "fresh@example.com").await.expect("no row stored");
    assert!(!doc.get_bool("confirmed").unwrap());
    assert_eq!(doc.get_str("source").unwrap(), "landing");
    assert!(
        doc.get_str("confirm_token").is_ok(),
        "a confirm token must exist or the address can never be confirmed"
    );
    // The exit is built with the entrance, deliberately — see the model docs.
    assert!(
        doc.get_str("unsubscribe_token").is_ok(),
        "the unsubscribe token must be minted at subscribe time, not at send time"
    );
}

/// The load-bearing one. Same request twice; the second time the address is
/// known. Every observable part of the response must be identical.
#[tokio::test]
async fn a_known_address_is_indistinguishable_from_a_fresh_one() {
    let app = TestApp::spawn().await;

    let first = post_subscribe(&app, "known@example.com").await;
    let first_status = first.status();
    let first_body = first.text().await.unwrap();

    let second = post_subscribe(&app, "known@example.com").await;
    let second_status = second.status();
    let second_body = second.text().await.unwrap();

    assert_eq!(first_status, 202);
    assert_eq!(
        first_status, second_status,
        "a known address must not answer with a different status"
    );
    assert_eq!(
        first_body, second_body,
        "a known address must not answer with a different body"
    );

    // And it must not have produced a second row, or the first row's
    // unsubscribe link would not cover the address any more.
    let n = app
        .db
        .collection::<bson::Document>("subscribers")
        .count_documents(doc! { "email": "known@example.com" })
        .await
        .unwrap();
    assert_eq!(n, 1, "the email index must collapse repeats to one row");
}

/// Junk is accepted with the same 202 and simply not stored. A 400 here would
/// be a weaker oracle than membership, but still one.
#[tokio::test]
async fn a_malformed_address_answers_the_same_and_stores_nothing() {
    let app = TestApp::spawn().await;

    let good = post_subscribe(&app, "good@example.com").await;
    let good_status = good.status();
    let good_body = good.text().await.unwrap();

    let bad = post_subscribe(&app, "not-an-address").await;
    assert_eq!(bad.status(), good_status);
    assert_eq!(bad.text().await.unwrap(), good_body);

    assert!(
        row(&app, "not-an-address").await.is_none(),
        "junk must not reach the collection"
    );
}

/// Case and surrounding whitespace must collapse to one row, or the second
/// spelling is an address nobody can unsubscribe.
#[tokio::test]
async fn addresses_are_normalized_to_a_single_row() {
    let app = TestApp::spawn().await;

    post_subscribe(&app, "Casing@Example.COM").await;
    post_subscribe(&app, "  casing@example.com  ").await;

    let n = app
        .db
        .collection::<bson::Document>("subscribers")
        .count_documents(doc! { "email": "casing@example.com" })
        .await
        .unwrap();
    assert_eq!(n, 1, "casing and whitespace must not create a second row");
}

/// The FR-58 P6 field finding, pinned: Gmail's link scanner followed the old
/// confirming GET and burned the very first real subscriber's token before
/// any human clicked. The GET is therefore a PURE redirect to the confirm
/// page, and only the page button's POST — the deliberate click — confirms.
#[tokio::test]
async fn a_prefetched_get_confirms_nothing_and_the_post_is_the_click() {
    let app = TestApp::spawn().await;
    post_subscribe(&app, "confirm@example.com").await;

    let token = row(&app, "confirm@example.com")
        .await
        .unwrap()
        .get_str("confirm_token")
        .unwrap()
        .to_string();

    // The prefetcher's move: GET the link. It must redirect to the page and
    // change NOTHING — the row stays unconfirmed, the token stays alive.
    let (status, location) = visit(&app, &format!("/api/subscribe/confirm/{token}")).await;
    assert!(status.is_redirection(), "expected a redirect, got {status}");
    assert!(
        location.contains(&format!("/newsletter/confirm/{token}")),
        "the GET must hand the human to the confirm PAGE; got {location:?}"
    );
    let doc = row(&app, "confirm@example.com").await.unwrap();
    assert!(
        !doc.get_bool("confirmed").unwrap(),
        "a GET must never confirm — that is the prefetch hole, field-hit on day one"
    );
    assert!(
        doc.get_str("confirm_token").is_ok(),
        "the token must survive any number of prefetches"
    );

    // The human's move: the page button POSTs. That flips the row and burns
    // the token, single-use.
    let resp = app
        .client
        .post(app.url(&format!("/api/subscribe/confirm/{token}")))
        .send()
        .await
        .expect("confirm POST failed");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["confirmed"], true);

    let doc = row(&app, "confirm@example.com").await.unwrap();
    assert!(doc.get_bool("confirmed").unwrap());
    assert!(
        doc.get_str("confirm_token").is_err(),
        "the confirm token must be single-use"
    );

    // A second POST of the burned token says so, plainly, to the holder.
    let resp = app
        .client
        .post(app.url(&format!("/api/subscribe/confirm/{token}")))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["confirmed"], false, "burned means burned");
}

/// One click, no session, no account — and idempotent, because mail clients
/// prefetch links and would otherwise "use up" the unsubscribe on delivery.
#[tokio::test]
async fn unsubscribing_needs_no_session_and_is_idempotent() {
    let app = TestApp::spawn().await;
    post_subscribe(&app, "leaving@example.com").await;

    let token = row(&app, "leaving@example.com")
        .await
        .unwrap()
        .get_str("unsubscribe_token")
        .unwrap()
        .to_string();

    for attempt in 1..=2 {
        let (status, location) = visit(&app, &format!("/api/subscribe/unsubscribe/{token}")).await;
        assert!(
            status.is_redirection(),
            "attempt {attempt} expected a redirect, got {status}"
        );
        assert!(
            location.contains("/newsletter/unsubscribed?status=ok"),
            "attempt {attempt}: a prefetched link must still report success on the \
             public outcome page, got {location:?}"
        );
    }

    let doc = row(&app, "leaving@example.com").await.unwrap();
    assert!(!doc.get_bool("confirmed").unwrap());
    assert!(
        doc.get("unsubscribed_at").is_some(),
        "the row is kept and stamped, so the address cannot be silently re-added"
    );
}

/// Re-subscribing after a withdrawal must not silently restore the old consent.
#[tokio::test]
async fn resubscribing_after_a_withdrawal_requires_confirming_again() {
    let app = TestApp::spawn().await;
    post_subscribe(&app, "again@example.com").await;

    let doc = row(&app, "again@example.com").await.unwrap();
    let confirm = doc.get_str("confirm_token").unwrap().to_string();
    let unsub = doc.get_str("unsubscribe_token").unwrap().to_string();

    // Confirm is a deliberate POST now (the GET is a pure page redirect).
    app.client
        .post(app.url(&format!("/api/subscribe/confirm/{confirm}")))
        .send()
        .await
        .expect("confirm POST failed");
    visit(&app, &format!("/api/subscribe/unsubscribe/{unsub}")).await;

    post_subscribe(&app, "again@example.com").await;

    let doc = row(&app, "again@example.com").await.unwrap();
    assert!(
        !doc.get_bool("confirmed").unwrap(),
        "re-entry after opting out is a new decision and must be re-proved"
    );
    assert!(
        doc.get_str("confirm_token").is_ok(),
        "a fresh confirm token must be issued"
    );
}

/// An unknown token must change nothing at all — it is the only defence against
/// someone walking the token space.
#[tokio::test]
async fn an_unknown_token_changes_nothing() {
    let app = TestApp::spawn().await;
    post_subscribe(&app, "untouched@example.com").await;

    // Unknown confirm token: the GET redirects to the page regardless (it
    // reads nothing), and the POST — the only thing that could act — reports
    // false and changes nothing.
    let (status, location) = visit(
        &app,
        "/api/subscribe/confirm/0000000000000000000000000000000000000000000000",
    )
    .await;
    assert!(status.is_redirection());
    assert!(
        location.contains("/newsletter/confirm/"),
        "got {location:?}"
    );
    let resp = app
        .client
        .post(app.url("/api/subscribe/confirm/0000000000000000000000000000000000000000000000"))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["confirmed"], false);

    let (status, location) = visit(
        &app,
        "/api/subscribe/unsubscribe/0000000000000000000000000000000000000000000000",
    )
    .await;
    assert!(status.is_redirection(), "unsubscribe should still redirect");
    assert!(
        location.contains("status=invalid"),
        "an unknown token must say so rather than claim success; got {location:?}"
    );

    let doc = row(&app, "untouched@example.com").await.unwrap();
    assert!(!doc.get_bool("confirmed").unwrap());
    assert!(doc.get("unsubscribed_at").is_none());
}

/// The RFC 8058 one-click leg (FR-58): a mailbox provider POSTs the
/// unsubscribe URL with a urlencoded body and expects a plain 2xx. No
/// redirect (providers follow none), no oracle (hit, repeat and miss are
/// indistinguishable), body unread (the token in the path is the input).
#[tokio::test]
async fn one_click_post_unsubscribes_with_a_uniform_200() {
    let app = TestApp::spawn().await;
    post_subscribe(&app, "oneclick@example.com").await;

    let token = row(&app, "oneclick@example.com")
        .await
        .unwrap()
        .get_str("unsubscribe_token")
        .unwrap()
        .to_string();

    async fn one_click(app: &TestApp, path: &str) -> reqwest::Response {
        app.client
            .post(app.url(path))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("List-Unsubscribe=One-Click")
            .send()
            .await
            .expect("one-click request failed")
    }

    for attempt in 1..=2 {
        let resp = one_click(&app, &format!("/api/subscribe/unsubscribe/{token}")).await;
        assert_eq!(
            resp.status(),
            200,
            "attempt {attempt}: prefetch/repeat must answer the same plain 200"
        );
        assert!(
            resp.headers().get(reqwest::header::LOCATION).is_none(),
            "providers follow no redirects — the answer must be a plain 200"
        );
    }

    let miss = one_click(
        &app,
        "/api/subscribe/unsubscribe/0000000000000000000000000000000000000000000000",
    )
    .await;
    assert_eq!(
        miss.status(),
        200,
        "an unknown token must be indistinguishable from a hit"
    );

    let doc = row(&app, "oneclick@example.com").await.unwrap();
    assert!(
        doc.get("unsubscribed_at").is_some(),
        "the one-click POST must stamp the row"
    );
}
