// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P7 — the GitHub puller and its readers, against a fake GitHub
//! (spec §3k).
//!
//! * **The puller** (`saas::github_pull::run_once`, an injected clock): the
//!   closed day's snapshot read once inside its window, the releases paged,
//!   drafts and sidecars left out; a second tick in the window asks
//!   nothing; a tick past the window owes nothing; no token means no
//!   traffic request at all; a listing past the page bound stored and
//!   marked `truncated`; a spent rate limit stops the listing and the next
//!   tick retries.
//! * **Traffic** with a token: the per-day buckets inside the horizon, the
//!   referrer ranking under the latest closed day, the token on the traffic
//!   requests only; a refused token recorded as `failed` per traffic day,
//!   never a 0, and the counters' snapshot taken all the same.
//! * **The readers** (`growth::github::section`, the digest's `github`):
//!   consecutive snapshots differenced, a 7-day delta from its two ends, a
//!   delta across a missing day `null`, a day without a snapshot read at the
//!   latest one before it, and no snapshot at all "not measured".

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use bson::{Document, doc};
use chrono::Duration;
use meshharbor_api::growth::{digest, github};
use meshharbor_config::GrowthSettings;
use meshharbor_mod_saas::github_pull::{self, GithubClient};
use meshharbor_services::dao::growth::{
    GITHUB_SOURCE, GITHUB_TRAFFIC_SOURCE, GROWTH_DAILY, GROWTH_PULLS,
};
use serde_json::{Value, json};

use crate::{
    fixtures::test_app::TestApp,
    growth_campaigns_tests::{at_day, count, ds, today},
};

const REPO: &str = "acme/site";

/// One release as the fake serves it: `(tag, draft, [(asset, downloads)])`.
type FakeRelease = (String, bool, Vec<(String, i64)>);
/// One request the fake saw: `(path, authorization)`.
type SeenRequest = (String, Option<String>);

/// What the fake serves, and every request it saw.
#[derive(Clone, Default)]
struct Fake {
    stars: Arc<Mutex<i64>>,
    /// In GitHub's order.
    releases: Arc<Mutex<Vec<FakeRelease>>>,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
    /// `X-RateLimit-Remaining` on every answer, when set.
    remaining: Arc<Mutex<Option<u32>>>,
}

impl Fake {
    fn seen(&self) -> Vec<SeenRequest> {
        self.seen.lock().unwrap().clone()
    }

    /// An answer, with the rate-limit header GitHub sends when one is set.
    fn reply(&self, status: StatusCode, body: Value) -> Response {
        let mut r = (status, Json(body)).into_response();
        if let Some(n) = *self.remaining.lock().unwrap() {
            r.headers_mut()
                .insert("x-ratelimit-remaining", n.to_string().parse().unwrap());
        }
        r
    }

    /// A token other than `good` is refused everywhere, as GitHub refuses a
    /// bad token even on a public endpoint.
    fn check(&self, path: String, headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        self.seen.lock().unwrap().push((path, auth.clone()));
        match auth.as_deref() {
            None | Some("Bearer good") => Ok(()),
            Some(_) => Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "message": "Bad credentials" })),
            )),
        }
    }
}

async fn repo(
    State(f): State<Fake>,
    Path((o, r)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = f.check(format!("/repos/{o}/{r}"), &headers) {
        return e.into_response();
    }
    let stars = *f.stars.lock().unwrap();
    f.reply(
        StatusCode::OK,
        json!({
            "full_name": format!("{o}/{r}"),
            "stargazers_count": stars, "watchers_count": stars,
            "forks_count": 7, "subscribers_count": 3,
        }),
    )
}

async fn releases(
    State(f): State<Fake>,
    Path((o, r)): Path<(String, String)>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let page: usize = q.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
    let per: usize = q.get("per_page").and_then(|p| p.parse().ok()).unwrap_or(30);
    if let Err(e) = f.check(format!("/repos/{o}/{r}/releases?page={page}"), &headers) {
        return e.into_response();
    }
    let all = f.releases.lock().unwrap().clone();
    let slice: Vec<Value> = all
        .iter()
        .skip((page - 1) * per)
        .take(per)
        .map(|(tag, draft, assets)| {
            json!({
                "tag_name": tag, "draft": draft, "prerelease": false,
                "assets": assets.iter().map(|(n, c)| json!({
                    "name": n, "download_count": c, "size": 1,
                    "browser_download_url": "https://example.invalid/x",
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    f.reply(StatusCode::OK, Value::Array(slice))
}

async fn traffic(
    State(f): State<Fake>,
    Path((o, r, kind)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    if let Err(e) = f.check(format!("/repos/{o}/{r}/traffic/{kind}"), &headers) {
        return e;
    }
    if headers.get("authorization").is_none() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "message": "Must have push access to repository" })),
        );
    }
    let t = today();
    let bucket = |age: i64, count: i64, uniques: i64| json!({ "timestamp": format!("{}T00:00:00Z", ds(t - Duration::days(age))), "count": count, "uniques": uniques });
    let body = match kind.as_str() {
        // Today's partial bucket, yesterday, and a day 20 days back that
        // GitHub would not even have: neither of the outer two is stored.
        "views" => json!({ "count": 0, "uniques": 0, "views": [
            bucket(0, 99, 9), bucket(1, 12, 4), bucket(3, 5, 2), bucket(20, 7, 7)] }),
        "clones" => json!({ "count": 0, "uniques": 0, "clones": [bucket(1, 2, 1)] }),
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "message": "Not Found" })),
            );
        }
    };
    (StatusCode::OK, Json(body))
}

async fn referrers(
    State(f): State<Fake>,
    Path((o, r)): Path<(String, String)>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    if let Err(e) = f.check(
        format!("/repos/{o}/{r}/traffic/popular/referrers"),
        &headers,
    ) {
        return e;
    }
    (
        StatusCode::OK,
        Json(json!([
            { "referrer": "Google", "count": 4, "uniques": 3 },
            { "referrer": "news.ycombinator.com", "count": 10, "uniques": 8 },
        ])),
    )
}

/// 151 releases: page 1 and half of page 2. The newest is a draft, the last
/// a helper (a vendored build); every product release carries a signature
/// sidecar the updater fetched, which is never a download.
fn seed_releases(f: &Fake) {
    let mut v = vec![(
        "agent-v0.4.999".to_string(),
        true,
        vec![(
            "meshharbord-0.4.999-x86_64-pc-windows-msvc.msi".to_string(),
            500,
        )],
    )];
    for i in 0..149 {
        v.push((
            format!("agent-v0.4.{i}"),
            false,
            vec![
                (format!("meshharbord-0.4.{i}-x86_64-pc-windows-msvc.msi"), 2),
                (format!("meshharbord_0.4.{i}_amd64.deb"), 1),
                (format!("meshharbord_0.4.{i}_amd64.deb.asc"), 5),
            ],
        ));
    }
    // A helper: the vendored build our own CI downloads, counted apart.
    v.push((
        "vendored-ffmpeg-n7.1".to_string(),
        false,
        vec![(
            "ffmpeg-linux64-lgpl-shared-minimal.tar.xz".to_string(),
            1000,
        )],
    ));
    *f.releases.lock().unwrap() = v;
}

async fn fake_github() -> (String, Fake) {
    let fake = Fake::default();
    *fake.stars.lock().unwrap() = 100;
    seed_releases(&fake);
    let router = Router::new()
        .route("/repos/{o}/{r}", get(repo))
        .route("/repos/{o}/{r}/releases", get(releases))
        .route("/repos/{o}/{r}/traffic/popular/referrers", get(referrers))
        .route("/repos/{o}/{r}/traffic/{kind}", get(traffic))
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), fake)
}

fn client(base: &str, token: &str) -> GithubClient {
    GithubClient::from_settings(&GrowthSettings {
        github_repo: REPO.into(),
        github_api_url: base.into(),
        github_token: token.into(),
        ..Default::default()
    })
    .expect("a client")
}

async fn spawn_for(base: &str) -> TestApp {
    spawn_with_token(base, "").await
}

async fn spawn_with_token(base: &str, token: &str) -> TestApp {
    let (base, token) = (base.to_string(), token.to_string());
    TestApp::spawn_with_settings(move |s| {
        s.growth.github_repo = REPO.into();
        s.growth.github_api_url = base;
        s.growth.github_token = token;
    })
    .await
}

async fn daily(
    app: &TestApp,
    source: &str,
    day: &str,
    metric: &str,
    extra: Document,
) -> Option<i64> {
    let mut filter = doc! { "source": source, "day": day, "metric": metric };
    for (k, v) in extra {
        filter.insert(format!("dims.{k}"), v);
    }
    app.db
        .collection::<Document>(GROWTH_DAILY)
        .find_one(filter)
        .await
        .unwrap()
        .and_then(|d| d.get_i64("value").ok())
}

async fn pull_status(app: &TestApp, source: &str, day: &str) -> Option<(String, Option<String>)> {
    app.db
        .collection::<Document>(GROWTH_PULLS)
        .find_one(doc! { "_id": format!("{source}:{day}") })
        .await
        .unwrap()
        .map(|d| {
            (
                d.get_str("status").unwrap().to_string(),
                d.get_str("error").ok().map(str::to_string),
            )
        })
}

// ── The puller ──────────────────────────────────────────────────────────

/// The closed day's snapshot, read once inside its window: the releases
/// paged, the draft left out, flavours grouping the same artifact of every
/// release, and no traffic request without a token.
#[tokio::test]
async fn the_puller_snapshots_the_closed_day_once_inside_its_window() {
    let (base, fake) = fake_github().await;
    let app = spawn_for(&base).await;
    let gh = client(&base, "");
    let t = today();
    let y = ds(t - Duration::days(1));

    let r = github_pull::run_once(&app.state.core, &gh, at_day(t, 2))
        .await
        .unwrap();
    assert!(r.snapshot_due && r.snapshot_ok, "{r:?}");
    assert!(r.traffic_due.is_empty(), "no token: traffic is never asked");
    let seen = fake.seen();
    assert_eq!(
        seen.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(),
        [
            "/repos/acme/site",
            "/repos/acme/site/releases?page=1",
            "/repos/acme/site/releases?page=2",
        ],
        "one repo read and two pages of releases, nothing else"
    );
    assert!(seen.iter().all(|(_, auth)| auth.is_none()), "no token sent");

    let none = doc! {};
    assert_eq!(
        daily(&app, GITHUB_SOURCE, &y, "stars", none.clone()).await,
        Some(100)
    );
    assert_eq!(
        daily(&app, GITHUB_SOURCE, &y, "forks", none.clone()).await,
        Some(7)
    );
    assert_eq!(
        daily(&app, GITHUB_SOURCE, &y, "watchers", none.clone()).await,
        Some(3)
    );
    // 149 published product releases × (2 + 1); the draft's 500 is not
    // counted, nor the sidecars' 5 each, and the vendored build CI fetches
    // is counted apart.
    assert_eq!(
        daily(&app, GITHUB_SOURCE, &y, "downloads", doc! { "by": "repo" }).await,
        Some(447)
    );
    assert_eq!(
        daily(
            &app,
            GITHUB_SOURCE,
            &y,
            "helper_downloads",
            doc! { "by": "repo" }
        )
        .await,
        Some(1000)
    );
    assert_eq!(
        daily(
            &app,
            GITHUB_SOURCE,
            &y,
            "downloads",
            doc! { "by": "release", "release": "vendored-ffmpeg-n7.1", "kind": "helper" }
        )
        .await,
        Some(1000)
    );
    assert_eq!(
        daily(
            &app,
            GITHUB_SOURCE,
            &y,
            "downloads",
            doc! { "by": "release", "release": "agent-v0.4.7" }
        )
        .await,
        Some(3)
    );
    assert_eq!(
        daily(
            &app,
            GITHUB_SOURCE,
            &y,
            "downloads",
            doc! { "by": "release", "release": "agent-v0.4.999" }
        )
        .await,
        None,
        "the draft is out"
    );
    assert_eq!(
        daily(
            &app,
            GITHUB_SOURCE,
            &y,
            "downloads",
            doc! { "by": "flavour", "flavour": "meshharbord-x86_64-pc-windows-msvc.msi" }
        )
        .await,
        Some(298)
    );
    assert_eq!(
        daily(
            &app,
            GITHUB_SOURCE,
            &y,
            "downloads",
            doc! { "by": "flavour", "flavour": "meshharbord_amd64.deb" }
        )
        .await,
        Some(149)
    );
    assert_eq!(
        daily(
            &app,
            GITHUB_SOURCE,
            &y,
            "downloads",
            doc! { "by": "flavour", "flavour": "meshharbord_amd64.deb.asc" }
        )
        .await,
        None,
        "a sidecar is no flavour"
    );
    assert_eq!(
        pull_status(&app, GITHUB_SOURCE, &y).await,
        Some(("ok".into(), None))
    );
    assert_eq!(
        count(&app, GROWTH_DAILY, doc! { "source": GITHUB_TRAFFIC_SOURCE }).await,
        0
    );

    // The first good read of the window stands: a later tick asks nothing.
    *fake.stars.lock().unwrap() = 101;
    let again = github_pull::run_once(&app.state.core, &gh, at_day(t, 3))
        .await
        .unwrap();
    assert!(!again.snapshot_due, "{again:?}");
    assert_eq!(fake.seen().len(), 3);
    assert_eq!(
        daily(&app, GITHUB_SOURCE, &y, "stars", doc! {}).await,
        Some(100)
    );

    // Past the window nothing is owed, even for a day never snapshotted:
    // a cumulative counter cannot be read for the past.
    let other = spawn_for(&base).await;
    let late = github_pull::run_once(&other.state.core, &gh, at_day(t, 8))
        .await
        .unwrap();
    assert!(!late.snapshot_due);
    assert_eq!(count(&other, GROWTH_PULLS, doc! {}).await, 0);
}

/// With the token: the traffic requests carry it and the counters never
/// do, the closed days' buckets land inside the horizon (never today's
/// partial one, never one past the horizon), and the referrer ranking goes
/// under the latest closed day. A refused token is `failed` for every
/// traffic day it owed, and costs the counters nothing.
#[tokio::test]
async fn traffic_lands_with_a_token_and_a_refused_one_is_recorded_not_zeroed() {
    let (base, fake) = fake_github().await;
    let app = spawn_with_token(&base, "good").await;
    let t = today();
    let y = ds(t - Duration::days(1));

    let r = github_pull::run_once(&app.state.core, &client(&base, "good"), at_day(t, 2))
        .await
        .unwrap();
    assert!(r.snapshot_ok, "{r:?}");
    assert_eq!(r.traffic_due.len(), 13, "{r:?}");
    assert_eq!(r.traffic_pulled, 13);
    let seen = fake.seen();
    assert_eq!(
        seen.iter().filter(|(p, _)| p.contains("/traffic/")).count(),
        3
    );
    assert!(
        seen.iter().all(|(p, a)| if p.contains("/traffic/") {
            a.as_deref() == Some("Bearer good")
        } else {
            a.is_none()
        }),
        "the token rides the traffic requests only: {seen:?}"
    );
    assert_eq!(
        daily(
            &app,
            GITHUB_TRAFFIC_SOURCE,
            &y,
            "views",
            doc! { "by": "traffic" }
        )
        .await,
        Some(12)
    );
    assert_eq!(
        daily(
            &app,
            GITHUB_TRAFFIC_SOURCE,
            &y,
            "clones_uniques",
            doc! { "by": "traffic" }
        )
        .await,
        Some(1)
    );
    let d3 = ds(t - Duration::days(3));
    assert_eq!(
        daily(
            &app,
            GITHUB_TRAFFIC_SOURCE,
            &d3,
            "views",
            doc! { "by": "traffic" }
        )
        .await,
        Some(5)
    );
    assert_eq!(
        daily(&app, GITHUB_TRAFFIC_SOURCE, &ds(t), "views", doc! {}).await,
        None,
        "today's bucket is partial and never stored"
    );
    assert_eq!(
        daily(
            &app,
            GITHUB_TRAFFIC_SOURCE,
            &ds(t - Duration::days(20)),
            "views",
            doc! {}
        )
        .await,
        None,
        "past the horizon"
    );
    assert_eq!(
        daily(
            &app,
            GITHUB_TRAFFIC_SOURCE,
            &y,
            "referrer_views",
            doc! { "referrer": "news.ycombinator.com" }
        )
        .await,
        Some(10)
    );
    assert_eq!(
        count(
            &app,
            GROWTH_DAILY,
            doc! { "source": GITHUB_TRAFFIC_SOURCE, "dims.by": "referrer", "day": { "$ne": &y } }
        )
        .await,
        0,
        "the ranking is stored under the latest closed day only"
    );
    // A quiet day inside the horizon is pulled `ok` with no row: a zero.
    let d2 = ds(t - Duration::days(2));
    assert_eq!(
        pull_status(&app, GITHUB_TRAFFIC_SOURCE, &d2).await,
        Some(("ok".into(), None))
    );
    assert_eq!(
        daily(&app, GITHUB_TRAFFIC_SOURCE, &d2, "views", doc! {}).await,
        None
    );

    // The readers: traffic summed over the measured days.
    let s = github::section(&app.state, t - Duration::days(1))
        .await
        .unwrap();
    let j = serde_json::to_value(&s).unwrap();
    assert_eq!(
        j["traffic"]["views"],
        json!({ "day": 12, "d7": 17, "d28": 17 })
    );
    assert_eq!(j["traffic"]["measured_days"]["d7"], 7);
    assert_eq!(
        j["traffic"]["referrers"][0]["referrer"],
        "news.ycombinator.com"
    );
    assert_eq!(j["traffic"]["referrers_as_of"], json!(y));

    // A refused token (revoked, expired, sealed wrong): the traffic is
    // recorded as failed with the reason on every day it owed, and the
    // day's snapshot — which no later read could recover — is taken all
    // the same, because the counters never carry the token.
    let bad_app = spawn_with_token(&base, "revoked").await;
    let r = github_pull::run_once(&bad_app.state.core, &client(&base, "revoked"), at_day(t, 2))
        .await
        .unwrap();
    assert!(r.snapshot_due && r.snapshot_ok, "{r:?}");
    assert_eq!(r.traffic_pulled, 0);
    let reason = Some("github unreachable: unauthorized (401)".to_string());
    assert_eq!(
        pull_status(&bad_app, GITHUB_SOURCE, &y).await,
        Some(("ok".into(), None))
    );
    assert_eq!(
        pull_status(&bad_app, GITHUB_TRAFFIC_SOURCE, &y).await,
        Some(("failed".into(), reason))
    );
    assert_eq!(
        count(
            &bad_app,
            GROWTH_DAILY,
            doc! { "source": GITHUB_TRAFFIC_SOURCE }
        )
        .await,
        0,
        "never a 0 stored"
    );
    assert_eq!(
        daily(&bad_app, GITHUB_SOURCE, &y, "stars", doc! {}).await,
        Some(100)
    );
    // And the reader: the counters measured; the traffic not, and why.
    let s = github::section(&bad_app.state, t - Duration::days(1))
        .await
        .unwrap();
    let j = serde_json::to_value(&s).unwrap();
    assert_eq!(j["counters"]["stars"], 100, "{j}");
    assert!(
        j["traffic"]["not_measured"]
            .as_str()
            .is_some_and(|r| r.starts_with("no GitHub traffic pulled")),
        "{j}"
    );
}

/// A listing past the page bound is stored and marked `truncated`, and the
/// reader shows its downloads as a lower bound; a rate limit down to its
/// reserve stops the listing before it eats the hour the updater's release
/// cache shares, nothing partial is stored, and the next tick in the
/// window takes the snapshot.
#[tokio::test]
async fn a_long_listing_is_marked_and_a_spent_rate_limit_waits_for_the_next_tick() {
    let (base, fake) = fake_github().await;
    let t = today();
    let y = ds(t - Duration::days(1));

    // 151 releases against a bound of one page.
    let app = spawn_for(&base).await;
    let r = github_pull::run_once(
        &app.state.core,
        &client(&base, "").with_max_pages(1),
        at_day(t, 2),
    )
    .await
    .unwrap();
    assert!(r.snapshot_ok, "{r:?}");
    let pull = app
        .db
        .collection::<Document>(GROWTH_PULLS)
        .find_one(doc! { "_id": format!("{GITHUB_SOURCE}:{y}") })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pull.get_bool("truncated").ok(), Some(true), "{pull}");
    let s = github::section(&app.state, t - Duration::days(1))
        .await
        .unwrap();
    let c = serde_json::to_value(&s).unwrap()["counters"].clone();
    assert_eq!(c["downloads_truncated"], true, "{c}");
    assert_eq!(c["stars"], 100);
    // Page 1: the draft and 99 product releases of 2 + 1 each.
    assert_eq!(c["downloads"], 297);

    // The hour's requests down to 5: the repository is read, no page is
    // asked, and the day stays owed.
    let app2 = spawn_for(&base).await;
    *fake.remaining.lock().unwrap() = Some(5);
    let before = fake.seen().len();
    let r = github_pull::run_once(&app2.state.core, &client(&base, ""), at_day(t, 2))
        .await
        .unwrap();
    assert!(r.snapshot_due && !r.snapshot_ok, "{r:?}");
    let asked: Vec<String> = fake.seen()[before..]
        .iter()
        .map(|(p, _)| p.clone())
        .collect();
    assert_eq!(asked, ["/repos/acme/site"], "no page against the reserve");
    assert_eq!(
        pull_status(&app2, GITHUB_SOURCE, &y).await,
        Some((
            "failed".into(),
            Some(
                "github rate limit nearly spent (5 requests left this hour); retried next tick"
                    .into()
            )
        ))
    );
    assert_eq!(
        count(&app2, GROWTH_DAILY, doc! {}).await,
        0,
        "no partial snapshot"
    );
    // The next tick, the hour renewed, takes it.
    *fake.remaining.lock().unwrap() = Some(57);
    let r = github_pull::run_once(&app2.state.core, &client(&base, ""), at_day(t, 3))
        .await
        .unwrap();
    assert!(r.snapshot_ok, "{r:?}");
    assert_eq!(
        daily(&app2, GITHUB_SOURCE, &y, "downloads", doc! { "by": "repo" }).await,
        Some(447)
    );
}

/// The digest's section from snapshots taken on different days: a day
/// delta, a 7-day delta from its two ends across a gap, a delta across the
/// gap `null`, the latest snapshot read for a day without one, downloads
/// differenced per release, and the section in the computed digest.
#[tokio::test]
async fn the_digest_differences_snapshots_and_never_reads_a_gap_as_zero() {
    let (base, fake) = fake_github().await;
    let app = spawn_for(&base).await;
    let gh = client(&base, "");
    let t = today();
    let set_stars = |n: i64| *fake.stars.lock().unwrap() = n;
    let set_v7 = |n: i64| {
        let mut rs = fake.releases.lock().unwrap();
        let v7 = rs.iter_mut().find(|r| r.0 == "agent-v0.4.7").unwrap();
        v7.2[0].1 = n;
    };

    // Snapshots of t-10, t-4, t-3 and t-1; none of t-2 (its window passed
    // with no tick).
    for (taken, stars, v7) in [(9, 100, 2), (3, 104, 12), (2, 105, 13), (0, 107, 17)] {
        set_stars(stars);
        set_v7(v7);
        let r = github_pull::run_once(&app.state.core, &gh, at_day(t - Duration::days(taken), 2))
            .await
            .unwrap();
        assert!(r.snapshot_ok, "{r:?}");
    }

    let s3 = github::section(&app.state, t - Duration::days(3))
        .await
        .unwrap();
    let c = serde_json::to_value(&s3).unwrap()["counters"].clone();
    assert_eq!(c["at"], json!(ds(t - Duration::days(3))));
    assert_eq!(c["stars"], 105);
    assert_eq!(c["stars_delta"], json!({ "day": 1, "d7": 5, "d28": null }));
    // agent-v0.4.7's MSI went 12 → 13 over the day and 2 → 13 over the week.
    assert_eq!(c["downloads_delta"]["day"], 1);
    assert_eq!(c["downloads_delta"]["d7"], 11);
    assert_eq!(
        c["top_releases_7d"],
        json!([{ "key": "agent-v0.4.7", "count": 11 }])
    );

    // t-1: its day delta crosses the missing t-2 — null, never split.
    let s1 = github::section(&app.state, t - Duration::days(1))
        .await
        .unwrap();
    let c1 = serde_json::to_value(&s1).unwrap()["counters"].clone();
    assert_eq!(c1["stars_delta"]["day"], Value::Null);
    assert_eq!(c1["stars_delta"]["d7"], Value::Null, "no snapshot of t-8");
    assert!(c1["top_releases_7d"]["not_measured"].is_string());

    // t-2 has no snapshot: read at t-3's.
    let s2 = github::section(&app.state, t - Duration::days(2))
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&s2).unwrap()["counters"]["at"],
        json!(ds(t - Duration::days(3)))
    );

    // The digest carries the section; traffic says why it is absent.
    let sections = digest::compute(
        &app.state,
        t - Duration::days(3),
        &meshharbor_core::growth::ExclusionSet::none(),
        bson::DateTime::now(),
    )
    .await
    .unwrap();
    let j = serde_json::to_value(&sections).unwrap();
    assert_eq!(j["github"]["counters"]["stars"], 105);
    assert_eq!(
        j["github"]["traffic"]["not_measured"],
        "no GitHub token configured (MESHHARBOR__GROWTH__GITHUB_TOKEN)"
    );
}
