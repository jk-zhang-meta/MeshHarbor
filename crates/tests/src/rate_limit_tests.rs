// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Tests for the per-IP `/api` limiter (`middleware::api_rate_limit`), which meters only
//! requests that carry no credential this server signed.
//!
//! ⚠️ Both tests here used to hit `/health`, which the governor **deliberately
//! does not cover**: `build_router` layers it onto `Router::new().nest("/api",
//! api)` alone, under the comment *"not health/ws which need unrestricted
//! access"*. So one test asserted rate limiting on the single endpoint
//! guaranteed never to be rate limited — it failed 3/3 in CI and was written
//! off as "timing-sensitive" and skipped — while the other passed VACUOUSLY,
//! asserting that an unlimited endpoint kept answering.
//!
//! Point them at a route the limiter actually covers and both mean something.

use crate::fixtures::test_app::TestApp;

/// A route that IS behind the governor, and is cheap to hit.
///
/// `/api/auth/refresh` is under `/api` and deliberately outside the stricter
/// per-(address, account) credential gate, so it exercises the general limiter
/// on its own. With no token it answers 401 without touching the database —
/// and the governor runs BEFORE the handler, so any non-429 status is proof
/// the request got past the limiter, whatever the handler then decides.
const LIMITED_ROUTE: &str = "/api/auth/refresh";

/// Fire `n` requests CONCURRENTLY and collect their status codes.
///
/// ⚠️ Concurrent, not sequential, and that part is load-bearing too: the
/// limiter refills one token per second, so a sequential loop of 65
/// round-trips races its own refill. On a slow runner such a loop outlasts the
/// burst it is trying to exhaust, nothing is ever limited, and the failure
/// reports the runner's speed rather than the limiter's behaviour. A burst
/// test has to actually burst.
async fn burst(app: &TestApp, n: usize) -> Vec<u16> {
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let client = app.client.clone();
        let url = app.url(LIMITED_ROUTE);
        handles.push(tokio::spawn(async move {
            client
                .post(url)
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }));
    }
    let mut out = Vec::with_capacity(n);
    for h in handles {
        out.push(h.await.unwrap());
    }
    out
}

#[tokio::test]
async fn rate_limit_returns_429_after_burst() {
    let app = TestApp::spawn().await;

    // Burst is 60, refill 1/s. 65 at once must overrun it.
    let statuses = burst(&app, 65).await;
    let limited = statuses.iter().filter(|&&s| s == 429).count();
    let passed = statuses.len() - limited;

    assert!(
        passed >= 60,
        "the burst is 60, so at least that many should reach the handler; only {passed} did"
    );
    assert!(
        limited >= 1,
        "65 concurrent requests against a burst of 60 must produce at least one 429; got none \
         (statuses: {statuses:?})"
    );
}

#[tokio::test]
async fn rate_limit_recovers_after_wait() {
    let app = TestApp::spawn().await;

    let statuses = burst(&app, 65).await;
    // ⚠️ Precondition, and the reason this test is no longer vacuous: if the
    // burst was never exhausted, "it works again afterwards" asserts nothing.
    assert!(
        statuses.contains(&429),
        "precondition: the burst must actually be exhausted before recovery means anything"
    );

    // One token per second; two is comfortable slack.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let after = app
        .client
        .post(app.url(LIMITED_ROUTE))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16();
    assert_ne!(
        after, 429,
        "after refill a request must pass the limiter again"
    );
}

/// Fire `n` concurrent `GET /api/auth/me` requests carrying only `header` as a credential.
///
/// ⚠️ A fresh client without a cookie store: `app.client` keeps the session cookie that
/// registration set, which would sign in every request here, the forged ones too.
async fn burst_signed(app: &TestApp, n: usize, header: (&'static str, String)) -> Vec<u16> {
    let bare = reqwest::Client::new();
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let client = bare.clone();
        let url = app.url("/api/auth/me");
        let (name, value) = header.clone();
        handles.push(tokio::spawn(async move {
            client
                .get(url)
                .header(name, value)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }));
    }
    let mut out = Vec::with_capacity(n);
    for h in handles {
        out.push(h.await.unwrap());
    }
    out
}

/// A signed-in caller is not metered: one address may carry a whole household's devices
/// and a browser, or every user of a front that injects the session. A token that does
/// not verify is still anonymous, and still limited.
#[tokio::test]
async fn a_signed_in_caller_is_not_rate_limited_and_a_forged_token_is() {
    let app = TestApp::spawn().await;
    let user = app
        .register_user(
            "rl@example.com",
            "rl",
            "RL",
            "correct-horse-battery-1",
            None,
            None,
        )
        .await;
    // Twice the burst of 60, at once, by header and by the session cookie.
    for header in [
        ("authorization", format!("Bearer {}", user.access_token)),
        ("cookie", format!("access_token={}", user.access_token)),
    ] {
        let statuses = burst_signed(&app, 120, header.clone()).await;
        assert!(
            statuses.iter().all(|&s| s == 200),
            "{}: every signed-in request reaches the handler (statuses: {statuses:?})",
            header.0
        );
    }
    let forged = burst_signed(&app, 65, ("authorization", "Bearer not.a.token".into())).await;
    assert!(
        forged.contains(&429),
        "a token that does not verify is metered like no token (statuses: {forged:?})"
    );
}
