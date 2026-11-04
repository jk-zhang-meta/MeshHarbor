// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P7 — the search pullers against fakes of Google, Bing and the
//! blog's feed (spec §3k).
//!
//! * **Search Console** (`saas::search_pull::run_once`, an injected clock):
//!   the service account's assertion and the token exchange (the fake
//!   checks the claims), the token cached across a run, the property as one
//!   encoded path segment, only FINAL days pulled — a day from
//!   `firstIncompleteDate` on stays due and stores nothing — the four
//!   breakdowns, the impression-weighted position, and a refused token or a
//!   missing permission recorded per day, never a 0.
//! * **The feed and URL Inspection** (`saas::content_pull::run_once`): the
//!   blog's Atom feed into `growth_content`, a post that leaves it kept as
//!   `in_feed: false`, each post's verdict and last crawl, a 403 recorded on
//!   every owed post with the last good verdict and its time kept, a
//!   retried day asking only about the posts not inspected in its cycle, a
//!   slow URL as one post's failure and three in a row as the run's; a 404,
//!   a page that is not a feed, a redirect or a non-https URL a failed read
//!   that changes nothing.
//! * **Bing** (`saas::bing_pull::run_once`): the daily totals and the weekly
//!   buckets at Bing's own grain, Bing's `/Date(…)/` read with its offset, a
//!   rare query's text never stored, and a refused key recorded.
//! * **The readers** (P7c): the Content table per post — Google's 7 and 28
//!   days ending on the newest final day, rates only from 30, the index
//!   verdict, the sign-ups that landed on it with the exclusion set
//!   applied, the web plane "not measured" without purestat — and the
//!   digest's Search section through the same day.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    Form, Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use bson::{Document, doc};
use chrono::{Duration, NaiveDate};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Validation};
use meshharbor_config::GrowthSettings;
use meshharbor_mod_saas::{
    bing_pull::{self, BingClient},
    content_pull,
    search_console::{SCOPE, ScClient},
    search_pull,
};
use meshharbor_services::dao::{
    growth::{BING_SOURCE, BING_WEEKLY_SOURCE, GROWTH_DAILY, GROWTH_PULLS, SEARCH_CONSOLE_SOURCE},
    growth_content::GROWTH_CONTENT,
};
use serde_json::{Value, json};

use crate::{
    fixtures::test_app::TestApp,
    growth_campaigns_tests::{at_day, count, ds, today},
};

const SECRET: &[u8] = b"fake-google-signing-secret";
const SA: &str = "growth-reader@meshharbor-test.iam.gserviceaccount.com";
const SITE: &str = "sc-domain:meshharbor.itachi.fans";

// ── A fake Google ───────────────────────────────────────────────────────

/// Day → the answers of that day: `(the breakdown's dimensions, a row)`.
type DayData = HashMap<String, Vec<(Vec<&'static str>, Value)>>;

#[derive(Clone, Default)]
struct Google {
    /// The token endpoint's own URL — the audience a correct assertion names.
    token_uri: Arc<Mutex<String>>,
    tokens_issued: Arc<Mutex<u32>>,
    /// Search Analytics requests: `(decoded site, body)`.
    queries: Arc<Mutex<Vec<(String, Value)>>>,
    inspected: Arc<Mutex<Vec<String>>>,
    /// The first day Google calls not final.
    first_incomplete: Arc<Mutex<Option<String>>>,
    /// Day → `(dimensions, rows)` answers; a day absent has no data.
    data: Arc<Mutex<DayData>>,
    /// Refuse every API call 403, as Google refuses a non-user.
    forbid: Arc<Mutex<bool>>,
    /// Refuse URL Inspection only, as a Restricted user may be refused.
    forbid_inspection: Arc<Mutex<bool>>,
    /// Refuse the inspection of a URL ending so (403), once per entry.
    forbid_once: Arc<Mutex<Vec<String>>>,
    /// Answer the inspection of a URL ending so only after this long.
    slow: Arc<Mutex<Vec<(String, std::time::Duration)>>>,
}

async fn g_token(
    State(g): State<Google>,
    Form(form): Form<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let bad = |e: &str| (StatusCode::BAD_REQUEST, Json(json!({ "error": e })));
    if form.get("grant_type").map(String::as_str)
        != Some("urn:ietf:params:oauth:grant-type:jwt-bearer")
    {
        return bad("unsupported_grant_type");
    }
    let Some(assertion) = form.get("assertion") else {
        return bad("invalid_request");
    };
    let aud = g.token_uri.lock().unwrap().clone();
    let mut v = Validation::new(Algorithm::HS256);
    v.set_audience(&[aud]);
    let Ok(data) = jsonwebtoken::decode::<Value>(assertion, &DecodingKey::from_secret(SECRET), &v)
    else {
        return bad("invalid_grant");
    };
    let c = data.claims;
    let lifetime = c["exp"].as_i64().unwrap_or(0) - c["iat"].as_i64().unwrap_or(0);
    if c["iss"] != SA || c["scope"] != SCOPE || !(1..=3600).contains(&lifetime) {
        return bad("invalid_grant");
    }
    *g.tokens_issued.lock().unwrap() += 1;
    (
        StatusCode::OK,
        Json(json!({ "access_token": "ya29.fake", "expires_in": 3599, "token_type": "Bearer" })),
    )
}

fn authorised(headers: &HeaderMap) -> bool {
    headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer ya29.fake")
}

fn forbidden() -> (StatusCode, Json<Value>) {
    (
        StatusCode::FORBIDDEN,
        Json(json!({ "error": { "code": 403,
            "message": "User does not have sufficient permission for site 'sc-domain:meshharbor.itachi.fans'.",
            "status": "PERMISSION_DENIED" } })),
    )
}

async fn g_query(
    State(g): State<Google>,
    Path(site): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !authorised(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": { "code": 401 } })),
        );
    }
    g.queries.lock().unwrap().push((site, body.clone()));
    if *g.forbid.lock().unwrap() {
        return forbidden();
    }
    let dims: Vec<String> = body["dimensions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.as_str().unwrap().to_string())
        .collect();
    let (from, to) = (
        body["startDate"].as_str().unwrap(),
        body["endDate"].as_str().unwrap(),
    );
    let data = g.data.lock().unwrap().clone();
    let mut rows = Vec::new();
    if dims == ["date"] {
        // Property totals per date; `all` includes the unsettled days.
        let mut days: Vec<&String> = data
            .keys()
            .filter(|d| d.as_str() >= from && d.as_str() <= to)
            .collect();
        days.sort();
        for d in days {
            for (dset, r) in &data[d] {
                if *dset == ["date"] {
                    let mut r = r.clone();
                    r["keys"] = json!([d]);
                    rows.push(r);
                }
            }
        }
        let mut out = json!({ "rows": rows, "responseAggregationType": "byProperty" });
        if let Some(f) = g.first_incomplete.lock().unwrap().clone() {
            out["metadata"] = json!({ "firstIncompleteDate": f });
        }
        return (StatusCode::OK, Json(out));
    }
    assert_eq!(from, to, "a breakdown is asked one day at a time");
    assert_eq!(body["dataState"], "final");
    for (dset, r) in data.get(from).cloned().unwrap_or_default() {
        if dset == dims.iter().map(String::as_str).collect::<Vec<_>>() {
            rows.push(r);
        }
    }
    if rows.is_empty() {
        // Google leaves `rows` out of an empty answer.
        return (
            StatusCode::OK,
            Json(json!({ "responseAggregationType": "byPage" })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "rows": rows, "responseAggregationType": "byPage" })),
    )
}

async fn g_inspect(
    State(g): State<Google>,
    Path(action): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    assert_eq!(action, "index:inspect");
    if !authorised(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": { "code": 401 } })),
        );
    }
    if *g.forbid_inspection.lock().unwrap() || *g.forbid.lock().unwrap() {
        return forbidden();
    }
    assert_eq!(body["siteUrl"], SITE);
    let url = body["inspectionUrl"].as_str().unwrap().to_string();
    {
        let mut once = g.forbid_once.lock().unwrap();
        if let Some(i) = once.iter().position(|end| url.ends_with(end.as_str())) {
            once.remove(i);
            return forbidden();
        }
    }
    let delay = g
        .slow
        .lock()
        .unwrap()
        .iter()
        .find(|(end, _)| url.ends_with(end.as_str()))
        .map(|(_, d)| *d);
    if let Some(d) = delay {
        tokio::time::sleep(d).await;
    }
    g.inspected.lock().unwrap().push(url.clone());
    let status = if url.ends_with("/blog/a/") {
        json!({ "verdict": "PASS", "coverageState": "Submitted and indexed",
            "indexingState": "INDEXING_ALLOWED", "pageFetchState": "SUCCESSFUL",
            "robotsTxtState": "ALLOWED", "lastCrawlTime": "2026-10-12T08:00:00Z",
            "googleCanonical": url })
    } else {
        json!({ "verdict": "NEUTRAL", "coverageState": "Crawled - currently not indexed",
            "lastCrawlTime": "2026-10-10T08:00:00Z" })
    };
    (
        StatusCode::OK,
        Json(
            json!({ "inspectionResult": { "inspectionResultLink": "https://search.google.com/x",
            "indexStatusResult": status } }),
        ),
    )
}

/// The blog's feed: `None` answers 404 (a site mid-deploy, or one that
/// stopped publishing it).
#[derive(Clone, Default)]
struct Feed(Arc<Mutex<Option<String>>>);

async fn feed(State(f): State<Feed>) -> (StatusCode, String) {
    match f.0.lock().unwrap().clone() {
        Some(xml) => (StatusCode::OK, xml),
        None => (StatusCode::NOT_FOUND, String::new()),
    }
}

/// A feed that moved: a redirect to the real one, which must not be
/// followed.
async fn moved() -> (StatusCode, [(&'static str, &'static str); 1]) {
    (StatusCode::FOUND, [("location", "/blog/feed.xml")])
}

async fn fake_google() -> (String, Google, Feed) {
    let g = Google::default();
    let f = Feed::default();
    let router = Router::new()
        .route("/token", post(g_token))
        .route(
            "/webmasters/v3/sites/{site}/searchAnalytics/query",
            post(g_query),
        )
        .route("/v1/urlInspection/{action}", post(g_inspect))
        .with_state(g.clone())
        .merge(
            Router::new()
                .route("/blog/feed.xml", get(feed))
                .route("/blog/moved.xml", get(moved))
                .with_state(f.clone()),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let base = format!("http://{addr}");
    *g.token_uri.lock().unwrap() = format!("{base}/token");
    (base, g, f)
}

fn sc(base: &str, secret: &[u8]) -> ScClient {
    ScClient::with_signer(
        SITE,
        base,
        &format!("{base}/token"),
        SA,
        Some("kid-1".into()),
        EncodingKey::from_secret(secret),
        Algorithm::HS256,
    )
}

fn row(keys: &[&str], clicks: f64, impressions: f64, position: f64) -> Value {
    json!({ "keys": keys, "clicks": clicks, "impressions": impressions,
        "ctr": if impressions > 0.0 { clicks / impressions } else { 0.0 }, "position": position })
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

async fn pull(app: &TestApp, source: &str, day: &str) -> Option<(String, Option<String>)> {
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

// ── Search Console ──────────────────────────────────────────────────────

/// Only final days: the run asks the `date` breakdown once (with
/// `dataState: all`) to learn where Google's unsettled days start, pulls
/// every final day of the horizon with three breakdowns each, leaves the
/// unsettled ones due with nothing stored, and stores the position weighted
/// by impressions. One token serves the run.
#[tokio::test]
async fn search_console_pulls_final_days_only_and_weights_position() {
    let (base, g, _) = fake_google().await;
    let app = TestApp::spawn().await;
    let client = sc(&base, SECRET);
    let t = today();
    let d1 = ds(t - Duration::days(3));
    let unsettled = [ds(t - Duration::days(2)), ds(t - Duration::days(1))];
    *g.first_incomplete.lock().unwrap() = Some(unsettled[0].clone());
    {
        let mut data = g.data.lock().unwrap();
        data.insert(
            d1.clone(),
            vec![
                (vec!["date"], row(&[], 5.0, 200.0, 6.5)),
                (
                    vec!["page"],
                    row(&["https://meshharbor.itachi.fans/blog/a/"], 4.0, 150.0, 5.0),
                ),
                (
                    vec!["page"],
                    row(&["https://meshharbor.itachi.fans/blog/b/"], 1.0, 50.0, 11.0),
                ),
                (vec!["query"], row(&["remote desktop"], 3.0, 100.0, 4.0)),
                (
                    vec!["page", "query"],
                    row(
                        &["https://meshharbor.itachi.fans/blog/a/", "remote desktop"],
                        3.0,
                        90.0,
                        4.0,
                    ),
                ),
            ],
        );
        // An unsettled day Google already has partial numbers for.
        data.insert(
            unsettled[0].clone(),
            vec![(vec!["date"], row(&[], 1.0, 20.0, 9.0))],
        );
    }

    let r = search_pull::run_once(&app.state.core, &client, at_day(t, 3))
        .await
        .unwrap();
    assert_eq!(r.due.len(), 30, "the horizon, on the first cycle: {r:?}");
    assert_eq!(r.pending, unsettled.to_vec(), "{r:?}");
    assert_eq!((r.pulled, r.failed), (28, 0), "{r:?}");
    assert_eq!(*g.tokens_issued.lock().unwrap(), 1, "one token for the run");
    let queries = g.queries.lock().unwrap().clone();
    assert_eq!(queries.len(), 1 + 28 * 3);
    assert!(
        queries.iter().all(|(site, _)| site == SITE),
        "the property, decoded"
    );
    assert_eq!(queries[0].1["dimensions"], json!(["date"]));
    assert_eq!(queries[0].1["dataState"], "all");

    // The final day: every breakdown, the position weighted ×100.
    let site = doc! { "by": "site" };
    assert_eq!(
        daily(&app, SEARCH_CONSOLE_SOURCE, &d1, "clicks", site.clone()).await,
        Some(5)
    );
    assert_eq!(
        daily(
            &app,
            SEARCH_CONSOLE_SOURCE,
            &d1,
            "impressions",
            site.clone()
        )
        .await,
        Some(200)
    );
    assert_eq!(
        daily(&app, SEARCH_CONSOLE_SOURCE, &d1, "position_x100", site).await,
        Some(130_000),
        "6.5 × 200 × 100"
    );
    let a = doc! { "by": "page", "page": "https://meshharbor.itachi.fans/blog/a/" };
    assert_eq!(
        daily(&app, SEARCH_CONSOLE_SOURCE, &d1, "position_x100", a).await,
        Some(75_000)
    );
    let pq = doc! { "by": "page_query", "page": "https://meshharbor.itachi.fans/blog/a/", "query": "remote desktop" };
    assert_eq!(
        daily(&app, SEARCH_CONSOLE_SOURCE, &d1, "impressions", pq).await,
        Some(90)
    );
    assert_eq!(
        pull(&app, SEARCH_CONSOLE_SOURCE, &d1).await,
        Some(("ok".into(), None))
    );
    // A final day with no data is pulled `ok` with no row: a zero.
    let quiet = ds(t - Duration::days(10));
    assert_eq!(
        pull(&app, SEARCH_CONSOLE_SOURCE, &quiet).await,
        Some(("ok".into(), None))
    );
    // The unsettled days: nothing stored, no pull row — pending, not 0.
    for d in &unsettled {
        assert_eq!(pull(&app, SEARCH_CONSOLE_SOURCE, d).await, None, "{d}");
        assert_eq!(
            count(
                &app,
                GROWTH_DAILY,
                doc! { "source": SEARCH_CONSOLE_SOURCE, "day": d }
            )
            .await,
            0
        );
    }

    // Later in the same cycle: the settled days are done; the unsettled
    // ones are asked about again, and still left alone.
    let before = g.queries.lock().unwrap().len();
    let again = search_pull::run_once(&app.state.core, &client, at_day(t, 4))
        .await
        .unwrap();
    assert_eq!(again.due, unsettled.to_vec(), "{again:?}");
    assert_eq!(again.pulled, 0);
    assert_eq!(
        g.queries.lock().unwrap().len(),
        before + 1,
        "only the date breakdown"
    );

    // The next cycle: Google calls the first of them final now.
    *g.first_incomplete.lock().unwrap() = Some(unsettled[1].clone());
    let next = search_pull::run_once(&app.state.core, &client, at_day(t + Duration::days(1), 3))
        .await
        .unwrap();
    assert!(next.pending.contains(&unsettled[1]), "{next:?}");
    assert_eq!(
        pull(&app, SEARCH_CONSOLE_SOURCE, &unsettled[0]).await,
        Some(("ok".into(), None))
    );
    assert_eq!(
        daily(
            &app,
            SEARCH_CONSOLE_SOURCE,
            &unsettled[0],
            "clicks",
            doc! { "by": "site" }
        )
        .await,
        Some(1)
    );
}

/// A refused assertion and a property the account is not a user of are
/// both recorded on every day the run owed, with the reason; nothing is
/// stored.
#[tokio::test]
async fn a_refused_token_or_permission_is_recorded_never_zeroed() {
    let (base, g, _) = fake_google().await;
    let t = today();

    let app = TestApp::spawn().await;
    let r = search_pull::run_once(&app.state.core, &sc(&base, b"the-wrong-key"), at_day(t, 3))
        .await
        .unwrap();
    assert_eq!(r.failed, 30, "{r:?}");
    let reason = "search console unreachable: token refused (invalid_grant)";
    assert_eq!(r.error.as_deref(), Some(reason));
    assert_eq!(
        pull(&app, SEARCH_CONSOLE_SOURCE, &ds(t - Duration::days(5))).await,
        Some(("failed".into(), Some(reason.into())))
    );
    assert_eq!(count(&app, GROWTH_DAILY, doc! {}).await, 0);
    assert_eq!(*g.tokens_issued.lock().unwrap(), 0);

    *g.forbid.lock().unwrap() = true;
    let app = TestApp::spawn().await;
    let r = search_pull::run_once(&app.state.core, &sc(&base, SECRET), at_day(t, 3))
        .await
        .unwrap();
    assert_eq!(r.failed, 30, "{r:?}");
    let e = r.error.unwrap();
    assert!(
        e.starts_with(
            "search console unreachable: forbidden (403) User does not have sufficient permission"
        ),
        "{e}"
    );
    assert_eq!(count(&app, GROWTH_DAILY, doc! {}).await, 0);
}

// ── The feed and URL Inspection ─────────────────────────────────────────

fn feed_xml(posts: &[(&str, &str, &str)]) -> String {
    let mut s = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<feed xmlns=\"http://www.w3.org/2005/Atom\" xml:lang=\"en\">\n  <id>https://meshharbor.itachi.fans/blog/</id>\n  <title>MeshHarbor blog</title>\n",
    );
    for (slug, title, published) in posts {
        s.push_str(&format!(
            "  <entry>\n    <id>https://meshharbor.itachi.fans/blog/{slug}/</id>\n    <title>{title}</title>\n    <link rel=\"alternate\" type=\"text/html\" href=\"https://meshharbor.itachi.fans/blog/{slug}/\"/>\n    <published>{published}</published>\n    <updated>{published}</updated>\n    <author><name>Goran</name></author>\n  </entry>\n"
        ));
    }
    s.push_str("</feed>\n");
    s
}

async fn content_doc(app: &TestApp, path: &str) -> Document {
    app.db
        .collection::<Document>(GROWTH_CONTENT)
        .find_one(doc! { "_id": path })
        .await
        .unwrap()
        .unwrap()
}

/// The feed fills `growth_content`; URL Inspection adds each post's verdict
/// and last crawl; a post that leaves the feed is kept as `in_feed: false`;
/// a refused inspection keeps the last good verdict and the time it was
/// read, records the error and the attempt on EVERY post the run owed, and
/// fails the day's inspection row; a retried day asks Google only about
/// the posts not yet inspected in its cycle.
#[tokio::test]
async fn the_feed_and_url_inspection_fill_growth_content() {
    let (base, g, f) = fake_google().await;
    let app = TestApp::spawn().await;
    let client = sc(&base, SECRET);
    let feed_url = format!("{base}/blog/feed.xml");
    let t = today();
    *f.0.lock().unwrap() = Some(feed_xml(&[
        ("a", "Post &amp; A", "2026-09-25T22:45:13Z"),
        ("b", "Post B", "2026-10-01T08:00:00Z"),
    ]));

    let r = content_pull::run_once(&app.state.core, &feed_url, Some(&client), at_day(t, 3))
        .await
        .unwrap();
    assert!(r.feed_due && r.inspection_due, "{r:?}");
    assert_eq!(
        (r.posts, r.inspected, r.inspection_failed),
        (2, 2, 0),
        "{r:?}"
    );
    let a = content_doc(&app, "/blog/a/").await;
    assert_eq!(a.get_str("title").unwrap(), "Post & A");
    assert!(a.get_bool("in_feed").unwrap());
    let ia = a.get_document("inspection").unwrap();
    assert_eq!(ia.get_str("verdict").unwrap(), "PASS");
    assert_eq!(
        ia.get_str("coverage_state").unwrap(),
        "Submitted and indexed"
    );
    assert!(ia.get_datetime("last_crawl_time").is_ok());
    let first_read = *ia.get_datetime("inspected_at").unwrap();
    assert_eq!(first_read, at_day(t, 3), "the verdict's own time");
    assert_eq!(*ia.get_datetime("attempted_at").unwrap(), at_day(t, 3));
    let b = content_doc(&app, "/blog/b/").await;
    assert_eq!(
        b.get_document("inspection")
            .unwrap()
            .get_str("coverage_state")
            .unwrap(),
        "Crawled - currently not indexed"
    );
    let today_s = ds(t);
    assert_eq!(
        pull(&app, content_pull::CONTENT_SOURCE, &today_s).await,
        Some(("ok".into(), None))
    );
    assert_eq!(
        pull(&app, content_pull::INSPECTION_SOURCE, &today_s).await,
        Some(("ok".into(), None))
    );

    // Once per cycle: a later tick reads and inspects nothing.
    let again = content_pull::run_once(&app.state.core, &feed_url, Some(&client), at_day(t, 5))
        .await
        .unwrap();
    assert!(!again.feed_due && !again.inspection_due);
    assert_eq!(g.inspected.lock().unwrap().len(), 2);

    // The next day: B left the feed, C joined, and inspection is refused —
    // as Google refuses a Restricted user. The refusal is every owed
    // post's, not only the first one's.
    *f.0.lock().unwrap() = Some(feed_xml(&[
        ("a", "Post A", "2026-09-25T22:45:13Z"),
        ("c", "Post C", "2026-10-10T08:00:00Z"),
    ]));
    *g.forbid_inspection.lock().unwrap() = true;
    let next = t + Duration::days(1);
    let r = content_pull::run_once(&app.state.core, &feed_url, Some(&client), at_day(next, 3))
        .await
        .unwrap();
    assert_eq!((r.posts, r.left_feed), (2, 1), "{r:?}");
    assert_eq!(r.inspection_failed, 2, "{r:?}");
    let b = content_doc(&app, "/blog/b/").await;
    assert!(!b.get_bool("in_feed").unwrap(), "kept, out of the feed");
    let ia = content_doc(&app, "/blog/a/")
        .await
        .get_document("inspection")
        .unwrap()
        .clone();
    assert_eq!(
        ia.get_str("verdict").unwrap(),
        "PASS",
        "the last good verdict stays"
    );
    assert_eq!(
        *ia.get_datetime("inspected_at").unwrap(),
        first_read,
        "inspected when the verdict was read, not at the failed attempt"
    );
    assert_eq!(*ia.get_datetime("attempted_at").unwrap(), at_day(next, 3));
    assert!(ia.get_str("error").unwrap().contains("forbidden (403)"));
    let ic = content_doc(&app, "/blog/c/")
        .await
        .get_document("inspection")
        .unwrap()
        .clone();
    assert!(ic.get_str("error").unwrap().contains("forbidden (403)"));
    assert!(
        ic.get("verdict").is_none() && ic.get("inspected_at").is_none(),
        "never inspected: no verdict, no inspected_at: {ic}"
    );
    let (status, error) = pull(&app, content_pull::INSPECTION_SOURCE, &ds(next))
        .await
        .unwrap();
    assert_eq!(status, "failed");
    assert!(error.unwrap().contains("forbidden (403)"));

    // A later tick retries the day: C (newest) is inspected, A is refused
    // once more and stops the run.
    *g.forbid_inspection.lock().unwrap() = false;
    g.forbid_once.lock().unwrap().push("/blog/a/".into());
    let r = content_pull::run_once(&app.state.core, &feed_url, Some(&client), at_day(next, 4))
        .await
        .unwrap();
    assert!(r.inspection_due && !r.feed_due, "{r:?}");
    assert_eq!((r.inspected, r.inspection_failed), (1, 1), "{r:?}");
    // The tick after: only A is asked — C was inspected in this cycle.
    let r = content_pull::run_once(&app.state.core, &feed_url, Some(&client), at_day(next, 5))
        .await
        .unwrap();
    assert_eq!(
        (r.already_inspected, r.inspected, r.inspection_failed),
        (1, 1, 0),
        "{r:?}"
    );
    let asked = g.inspected.lock().unwrap().clone();
    assert_eq!(
        asked.iter().filter(|u| u.ends_with("/blog/c/")).count(),
        1,
        "C is not inspected twice in a cycle: {asked:?}"
    );
    assert_eq!(
        pull(&app, content_pull::INSPECTION_SOURCE, &ds(next)).await,
        Some(("ok".into(), None))
    );
    let ia = content_doc(&app, "/blog/a/")
        .await
        .get_document("inspection")
        .unwrap()
        .clone();
    assert!(
        ia.get("error").is_none_or(|e| e == &bson::Bson::Null),
        "{ia}"
    );
    assert_eq!(*ia.get_datetime("inspected_at").unwrap(), at_day(next, 5));
}

/// Only a feed moves the list. A 404, an answer that is not an Atom feed
/// (an SPA's index served for any path), a redirect, or a feed URL that is
/// not https is a failed read with its reason, and leaves every post as it
/// was — none is marked out of the feed on the strength of it.
#[tokio::test]
async fn a_read_that_is_not_the_feed_changes_nothing() {
    let (base, _g, f) = fake_google().await;
    let app = TestApp::spawn().await;
    let feed_url = format!("{base}/blog/feed.xml");
    let t = today();
    *f.0.lock().unwrap() = Some(feed_xml(&[
        ("a", "Post A", "2026-09-25T22:45:13Z"),
        ("b", "Post B", "2026-10-01T08:00:00Z"),
    ]));
    let r = content_pull::run_once(&app.state.core, &feed_url, None, at_day(t, 3))
        .await
        .unwrap();
    assert_eq!(r.posts, 2, "{r:?}");

    let next = t + Duration::days(1);
    let html = "<!DOCTYPE html><html><head><title>MeshHarbor</title></head><body><div id=\"app\"></div></body></html>";
    for (hour, answer, url, reason) in [
        (3, None, feed_url.clone(), "feed not found (404)"),
        (
            4,
            Some(html.to_string()),
            feed_url.clone(),
            "feed unreadable: the answer is not an Atom feed",
        ),
        (
            5,
            Some(feed_xml(&[])),
            format!("{base}/blog/moved.xml"),
            "a redirect, not followed",
        ),
        (
            6,
            Some(feed_xml(&[])),
            "http://meshharbor.itachi.fans/blog/feed.xml".to_string(),
            "its URL is not https",
        ),
    ] {
        *f.0.lock().unwrap() = answer;
        let r = content_pull::run_once(&app.state.core, &url, None, at_day(next, hour))
            .await
            .unwrap();
        assert!(r.feed_due, "a failed read leaves the day owed: {r:?}");
        assert_eq!((r.posts, r.left_feed), (0, 0), "{r:?}");
        assert!(
            r.error.as_deref().is_some_and(|e| e.contains(reason)),
            "{reason}: {r:?}"
        );
        let (status, error) = pull(&app, content_pull::CONTENT_SOURCE, &ds(next))
            .await
            .unwrap();
        assert_eq!(status, "failed");
        assert!(error.unwrap().contains(reason));
        for p in ["/blog/a/", "/blog/b/"] {
            assert!(
                content_doc(&app, p).await.get_bool("in_feed").unwrap(),
                "{p} stays in the feed after: {reason}"
            );
        }
    }
    // A feed none of whose entries parse is not a list either.
    *f.0.lock().unwrap() =
        Some(feed_xml(&[("x", "X", "2026-10-01T08:00:00Z")]).replace("<published>", "<when>"));
    let r = content_pull::run_once(&app.state.core, &feed_url, None, at_day(next, 7))
        .await
        .unwrap();
    assert!(
        r.error
            .as_deref()
            .is_some_and(|e| e.contains("none of its 1 entries parsed")),
        "{r:?}"
    );
    assert!(
        content_doc(&app, "/blog/a/")
            .await
            .get_bool("in_feed")
            .unwrap()
    );
}

/// One slow URL is that post's failure and the run goes on; three timeouts
/// in a row are Google down, which stops the run and records the reason on
/// every post the run still owed, unasked.
#[tokio::test]
async fn an_inspection_timeout_is_one_posts_failure_until_three_in_a_row() {
    let (base, g, f) = fake_google().await;
    let app = TestApp::spawn().await;
    let client = sc(&base, SECRET).with_timeout(std::time::Duration::from_millis(400));
    let feed_url = format!("{base}/blog/feed.xml");
    let t = today();
    *f.0.lock().unwrap() = Some(feed_xml(&[
        ("a", "Post A", "2026-09-25T22:45:13Z"),
        ("b", "Post B", "2026-10-01T08:00:00Z"),
        ("c", "Post C", "2026-10-05T08:00:00Z"),
        ("d", "Post D", "2026-10-09T08:00:00Z"),
    ]));
    let slow = std::time::Duration::from_millis(1500);
    g.slow.lock().unwrap().push(("/blog/c/".into(), slow));
    let r = content_pull::run_once(&app.state.core, &feed_url, Some(&client), at_day(t, 3))
        .await
        .unwrap();
    assert_eq!((r.inspected, r.inspection_failed), (3, 1), "{r:?}");
    assert_eq!(
        pull(&app, content_pull::INSPECTION_SOURCE, &ds(t)).await,
        Some(("ok".into(), None)),
        "one slow URL does not fail the day"
    );
    let ic = content_doc(&app, "/blog/c/")
        .await
        .get_document("inspection")
        .unwrap()
        .clone();
    assert_eq!(
        ic.get_str("error").unwrap(),
        "search console unreachable: timed out"
    );

    // The next day the three newest are slow: the run stops after the
    // third, and A — never asked — carries the reason too.
    let next = t + Duration::days(1);
    {
        let mut s = g.slow.lock().unwrap();
        s.clear();
        for p in ["/blog/d/", "/blog/c/", "/blog/b/"] {
            s.push((p.into(), slow));
        }
    }
    let asked_before = g.inspected.lock().unwrap().clone();
    let r = content_pull::run_once(&app.state.core, &feed_url, Some(&client), at_day(next, 3))
        .await
        .unwrap();
    assert_eq!((r.inspected, r.inspection_failed), (0, 4), "{r:?}");
    let (status, error) = pull(&app, content_pull::INSPECTION_SOURCE, &ds(next))
        .await
        .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(
        error.as_deref(),
        Some("search console unreachable: timed out (3 inspections in a row)")
    );
    let ia = content_doc(&app, "/blog/a/")
        .await
        .get_document("inspection")
        .unwrap()
        .clone();
    assert_eq!(
        ia.get_str("error").unwrap(),
        "search console unreachable: timed out"
    );
    assert_eq!(
        ia.get_str("verdict").unwrap(),
        "PASS",
        "its last verdict kept"
    );
    let a_asks = |list: &[String]| list.iter().filter(|u| u.ends_with("/blog/a/")).count();
    assert_eq!(
        a_asks(&g.inspected.lock().unwrap()),
        a_asks(&asked_before),
        "A was never asked on the second day"
    );
}

// ── Bing ────────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct BingFake {
    /// `(method, siteUrl)` per request.
    seen: Arc<Mutex<Vec<(String, String)>>>,
}

/// Bing's date for the Pacific day `d`: midnight there, -0700.
fn bing_date(d: NaiveDate) -> String {
    let ms = d.and_hms_opt(7, 0, 0).unwrap().and_utc().timestamp_millis();
    format!("/Date({ms}-0700)/")
}

async fn bing_call(
    State(b): State<BingFake>,
    Path(method): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    b.seen.lock().unwrap().push((
        method.clone(),
        q.get("siteUrl").cloned().unwrap_or_default(),
    ));
    if q.get("apikey").map(String::as_str) != Some("good") {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ErrorCode": 3, "Message": "ERROR!!! InvalidApiKey" })),
        );
    }
    let t = today();
    let d = |age: i64| bing_date(t - Duration::days(age));
    let body = match method.as_str() {
        "GetRankAndTrafficStats" => json!({ "d": [
            { "__type": "RankAndTrafficStats:#Microsoft.Bing.Webmaster.Api", "Date": d(2), "Clicks": 3, "Impressions": 90 },
            { "__type": "RankAndTrafficStats:#Microsoft.Bing.Webmaster.Api", "Date": d(40), "Clicks": 1, "Impressions": 10 },
        ] }),
        "GetQueryStats" => json!({ "d": [
            { "Query": "meshharbor", "Date": d(6), "Clicks": 2, "Impressions": 30, "AvgImpressionPosition": 4, "AvgClickPosition": 3 },
            // Below the floor: its text is never stored.
            { "Query": "jane doe meshharbor invoice", "Date": d(6), "Clicks": 1, "Impressions": 3, "AvgImpressionPosition": 1, "AvgClickPosition": 1 },
        ] }),
        "GetPageStats" => json!({ "d": [
            { "Query": "https://meshharbor.itachi.fans/blog/a/", "Date": d(6), "Clicks": 1, "Impressions": 12, "AvgImpressionPosition": 9, "AvgClickPosition": -1 },
        ] }),
        _ => return (StatusCode::NOT_FOUND, Json(json!({}))),
    };
    (StatusCode::OK, Json(body))
}

async fn fake_bing() -> (String, BingFake) {
    let b = BingFake::default();
    let router = Router::new()
        .route("/{method}", get(bing_call))
        .with_state(b.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), b)
}

fn bing(base: &str, key: &str) -> BingClient {
    BingClient::from_settings(&GrowthSettings {
        bing_api_key: key.into(),
        bing_api_url: base.into(),
        ..Default::default()
    })
    .unwrap()
}

/// The digest's Bing part for `day`, as JSON.
async fn read(state: &meshharbor_api::state::AppState, day: NaiveDate) -> Value {
    serde_json::to_value(
        meshharbor_api::growth::search::bing(state, day)
            .await
            .unwrap(),
    )
    .unwrap()
}

/// The daily totals and the weekly buckets land at Bing's own grain inside
/// their horizons, under Bing's (Pacific) dates; a refused key is recorded
/// on the cycle's row with Bing's code. The reader (P7c) shows Bing only
/// while a pull succeeded in its lookback, and a failing one says why.
#[tokio::test]
async fn bing_lands_at_its_own_grain_and_a_refused_key_is_recorded() {
    let (base, fake) = fake_bing().await;
    let with_key = |key: &'static str| {
        move |s: &mut meshharbor_config::Settings| s.growth.bing_api_key = key.into()
    };
    let app = TestApp::spawn_with_settings(with_key("good")).await;
    let t = today();
    let r = bing_pull::run_once(&app.state.core, &bing(&base, "good"), at_day(t, 4))
        .await
        .unwrap();
    assert!(r.due && r.ok, "{r:?}");
    let seen = fake.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 3);
    assert!(
        seen.iter().all(|(_, site)| site == "https://meshharbor.itachi.fans/"),
        "{seen:?}"
    );

    let d2 = ds(t - Duration::days(2));
    assert_eq!(
        daily(&app, BING_SOURCE, &d2, "clicks", doc! { "by": "site" }).await,
        Some(3)
    );
    assert_eq!(
        count(
            &app,
            GROWTH_DAILY,
            doc! { "source": BING_SOURCE, "day": ds(t - Duration::days(40)) }
        )
        .await,
        0,
        "older than the horizon: frozen, not written"
    );
    let w = ds(t - Duration::days(6));
    assert_eq!(
        daily(
            &app,
            BING_WEEKLY_SOURCE,
            &w,
            "impressions",
            doc! { "by": "query", "query": "meshharbor" }
        )
        .await,
        Some(30)
    );
    assert_eq!(
        count(
            &app,
            GROWTH_DAILY,
            doc! { "source": BING_WEEKLY_SOURCE, "dims.query": "jane doe meshharbor invoice" }
        )
        .await,
        0,
        "a query below the floor is not stored"
    );
    assert_eq!(
        daily(
            &app,
            BING_WEEKLY_SOURCE,
            &w,
            "avg_impression_position_x10",
            doc! { "by": "query" }
        )
        .await,
        Some(40)
    );
    assert_eq!(
        daily(
            &app,
            BING_WEEKLY_SOURCE,
            &w,
            "avg_click_position_x10",
            doc! { "by": "page" }
        )
        .await,
        None,
        "Bing's -1 is no position"
    );
    let y = ds(t - Duration::days(1));
    assert_eq!(pull(&app, BING_SOURCE, &y).await, Some(("ok".into(), None)));

    // Once per cycle.
    let again = bing_pull::run_once(&app.state.core, &bing(&base, "good"), at_day(t, 6))
        .await
        .unwrap();
    assert!(!again.due);

    // The reader: Bing as the pull for yesterday read it, its daily window
    // ending on its newest row.
    let b = read(&app.state, t - Duration::days(1)).await;
    assert_eq!(b["pulled"], json!(y), "{b}");
    assert_eq!(b["through"], json!(ds(t - Duration::days(2))));
    assert_eq!(b["clicks"]["day"], 3);
    // Four days on with no pull since, the same rows are not shown as
    // current: "not measured", and why.
    let stale = read(&app.state, t + Duration::days(3)).await;
    assert!(
        stale["not_measured"]
            .as_str()
            .is_some_and(|r| r.starts_with("no Bing pull in the 4 days to")),
        "{stale}"
    );

    let bad_app = TestApp::spawn_with_settings(with_key("revoked")).await;
    let r = bing_pull::run_once(&bad_app.state.core, &bing(&base, "revoked"), at_day(t, 4))
        .await
        .unwrap();
    assert!(r.due && !r.ok);
    let reason = "bing unreachable: refused (ErrorCode 3) ERROR!!! InvalidApiKey";
    assert_eq!(r.error.as_deref(), Some(reason));
    assert_eq!(
        pull(&bad_app, BING_SOURCE, &y).await,
        Some(("failed".into(), Some(reason.into())))
    );
    assert_eq!(count(&bad_app, GROWTH_DAILY, doc! {}).await, 0);
    // A failing pull reads as failing, with the attempt's own reason.
    let failing = read(&bad_app.state, t - Duration::days(1)).await;
    let why = failing["not_measured"].as_str().unwrap_or_default();
    assert!(
        why.starts_with("no Bing pull succeeded in the 4 days to") && why.contains(reason),
        "{failing}"
    );
}

// ── The readers: the Content table and the digest's Search section ──────

/// What the pullers stored, as the Content table and the digest read it:
/// per post, Google's 7 and 28 days ending on the newest final day (CTR and
/// position from 30 impressions), its top queries, the index verdict, the
/// sign-ups that landed on it (the trailing slash folded, the exclusion set
/// applied); the web plane "not measured" without a purestat key, never 0;
/// and the digest's Search section through the same final day.
#[tokio::test]
async fn the_content_table_and_the_digest_read_what_the_pullers_stored() {
    let (base, g, f) = fake_google().await;
    let admin = bson::oid::ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin.to_hex());
    })
    .await;
    let token = app
        .state
        .auth
        .generate_tokens(admin, "padmin@test.io", "padmin")
        .unwrap()
        .access_token;
    let client = sc(&base, SECRET);
    let t = today();
    let d1 = ds(t - Duration::days(3));
    *g.first_incomplete.lock().unwrap() = Some(ds(t - Duration::days(2)));
    g.data.lock().unwrap().insert(
        d1.clone(),
        vec![
            (vec!["date"], row(&[], 5.0, 200.0, 6.5)),
            (
                vec!["page"],
                row(&["https://meshharbor.itachi.fans/blog/a/"], 4.0, 150.0, 5.0),
            ),
            (
                vec!["page"],
                row(&["https://meshharbor.itachi.fans/blog/b/"], 1.0, 20.0, 11.0),
            ),
            (vec!["query"], row(&["remote desktop"], 3.0, 100.0, 4.0)),
            (
                vec!["page", "query"],
                row(
                    &["https://meshharbor.itachi.fans/blog/a/", "remote desktop"],
                    3.0,
                    90.0,
                    4.0,
                ),
            ),
        ],
    );
    *f.0.lock().unwrap() = Some(feed_xml(&[
        ("a", "Post A", "2026-09-25T22:45:13Z"),
        ("b", "Post B", "2026-10-01T08:00:00Z"),
    ]));
    search_pull::run_once(&app.state.core, &client, at_day(t, 3))
        .await
        .unwrap();
    content_pull::run_once(
        &app.state.core,
        &format!("{base}/blog/feed.xml"),
        Some(&client),
        at_day(t, 3),
    )
    .await
    .unwrap();
    // Two sign-ups landed on post A (one spelled without the slash), one
    // of them by an excluded person (the platform admin); one elsewhere.
    let users = app.db.collection::<Document>("users");
    let created = bson::DateTime::from_millis(at_day(t - Duration::days(5), 12).timestamp_millis());
    for (i, (id, landing)) in [
        (bson::oid::ObjectId::new(), "/blog/a"),
        (admin, "/blog/a/"),
        (bson::oid::ObjectId::new(), "/pricing"),
    ]
    .into_iter()
    .enumerate()
    {
        users
            .insert_one(doc! {
                "_id": id, "email": format!("u{i}@test.io"), "username": format!("u{i}"),
                "created_at": created, "deleted_at": bson::Bson::Null,
                "signup_attribution": { "source": "linkedin", "landing_path": landing },
            })
            .await
            .unwrap();
    }

    let r = app
        .auth_get("/api/admin/growth/content", &token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let j: Value = r.json().await.unwrap();
    assert_eq!(j["google_through"], json!(d1));
    // Every final day of both windows was pulled (no data is still a day).
    assert_eq!(j["google_days"], json!({ "d7": 7, "d28": 28 }), "{j}");
    assert_eq!(
        j["web_not_measured"]["not_measured"], "purestat key not configured",
        "{j}"
    );
    let rows = j["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["path"], "/blog/b/", "newest first");
    let a = &rows[1];
    assert_eq!(a["title"], "Post A");
    assert_eq!(a["web"]["not_measured"], "purestat key not configured");
    let d7 = &a["google"]["d7"];
    assert_eq!(
        (d7["clicks"].as_i64(), d7["impressions"].as_i64()),
        (Some(4), Some(150))
    );
    assert_eq!(d7["position"], 5.0);
    assert!((d7["ctr"].as_f64().unwrap() - 4.0 / 150.0).abs() < 1e-9);
    assert_eq!(a["google"]["top_queries_28d"][0]["key"], "remote desktop");
    assert_eq!(a["index"]["verdict"], "PASS");
    assert!(
        a["index"]["inspected_at"]
            .as_str()
            .is_some_and(|s| s.starts_with(&ds(t))),
        "the verdict's own time: {}",
        a["index"]
    );
    assert_eq!(a["signups"]["count"], 1, "the admin's sign-up is excluded");
    // Post B: 20 impressions — counts, no rate.
    let b = &rows[0];
    assert_eq!(b["google"]["d28"]["impressions"], 20);
    assert!(b["google"]["d28"].get("ctr").is_none());
    assert_eq!(
        b["index"]["coverage_state"],
        "Crawled - currently not indexed"
    );
    // With include_internal the admin's sign-up counts too.
    let raw: Value = app
        .auth_get("/api/admin/growth/content?include_internal=true", &token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(raw["rows"][1]["signups"]["count"], 2);

    // The digest's Search section for yesterday: Google through its newest
    // final day, Bing not configured.
    let sections = meshharbor_api::growth::digest::compute(
        &app.state,
        t - Duration::days(1),
        &meshharbor_core::growth::ExclusionSet::none(),
        bson::DateTime::now(),
    )
    .await
    .unwrap();
    let s = serde_json::to_value(&sections).unwrap()["search"].clone();
    assert_eq!(s["google"]["through"], json!(d1));
    assert_eq!(s["google"]["clicks"]["day"], 5);
    assert_eq!(s["google"]["d28"]["position"], 6.5);
    assert_eq!(s["google"]["top_queries_7d"][0]["key"], "remote desktop");
    assert!(s["bing"]["not_measured"].is_string());

    // Nobody else sees the table.
    let r = app
        .client
        .get(app.url("/api/admin/growth/content"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);
}
