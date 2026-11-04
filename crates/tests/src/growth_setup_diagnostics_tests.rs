// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P3b — the setup wizard's opt-in diagnostics, against a real
//! server (spec §3e item 5, D4; AC12's server half — the wizard half is
//! `agents/meshharbor-setup/src/diagnostics.rs`'s unit tests and the vmtest
//! wizard cell with a capture).
//!
//! * a valid record is stored with exactly its seven fields plus the
//!   server's `ts`, and nothing about the request: the whole collection is
//!   scanned for the User-Agent the request carried and the loopback
//!   address it came from;
//! * every invalid field is refused with a code and nothing is stored; so
//!   is a body that is not JSON, one carrying an eighth key, and one over
//!   the size cap;
//! * `growth.setup_diagnostics = false` answers the empty 404 of a path
//!   that does not exist — the same bytes `POST /api/<absent>` answers;
//! * a run cannot write past its cap;
//! * the nightly freeze writes per-day distinct-run counts into
//!   `growth_daily`, is idempotent, and leaves a day alone once it is past
//!   the recompute window, so the counts outlive the rows;
//! * the digest's `install.wizard_steps` reports opted-in runs per step and
//!   outcome, labelled with n, and reads "not measured" with the switch off.

use bson::{DateTime, Document, doc};
use chrono::NaiveDate;
use meshharbor_api::growth::{digest, org_daily};
use meshharbor_remote_control::setup_diagnostics::{MAX_BODY_BYTES, SetupDiagnostic};
use meshharbor_services::dao::setup_diagnostics::{MAX_ROWS_PER_RUN, SETUP_DIAGNOSTICS};
use meshharbor_core::growth::ExclusionSet;
use serde_json::{Value, json};

use crate::fixtures::test_app::TestApp;

const ROUTE: &str = "/api/setup/diagnostics";
const UA: &str = "meshharbor-setup/0.4.138";
const RUN: &str = "0123456789abcdef0123456789abcdef";

fn record(step: &str, outcome: &str, error_code: Option<&str>) -> SetupDiagnostic {
    SetupDiagnostic {
        run: RUN.into(),
        step: step.into(),
        outcome: outcome.into(),
        elapsed_ms: 1500,
        error_code: error_code.map(str::to_string),
        os: "windows".into(),
        wizard_version: "0.4.138".into(),
    }
}

async fn post_raw(app: &TestApp, body: &[u8]) -> reqwest::Response {
    app.client
        .post(app.url(ROUTE))
        .header("content-type", "application/json")
        .header("user-agent", UA)
        .body(body.to_vec())
        .send()
        .await
        .unwrap()
}

async fn post(app: &TestApp, d: &SetupDiagnostic) -> reqwest::Response {
    post_raw(app, &serde_json::to_vec(d).unwrap()).await
}

async fn all_rows(app: &TestApp) -> Vec<Document> {
    use futures::TryStreamExt;
    app.db
        .collection::<Document>(SETUP_DIAGNOSTICS)
        .find(doc! {})
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap()
}

/// Every string anywhere in a document, for the "nothing about the
/// request" scan.
fn strings_of(b: &bson::Bson, out: &mut Vec<String>) {
    match b {
        bson::Bson::String(s) => out.push(s.clone()),
        bson::Bson::Document(d) => d.values().for_each(|v| strings_of(v, out)),
        bson::Bson::Array(a) => a.iter().for_each(|v| strings_of(v, out)),
        _ => {}
    }
}

/// A row written straight into the collection, as the route would have.
async fn seed(
    app: &TestApp,
    run: &str,
    step: &str,
    outcome: &str,
    code: Option<&str>,
    os: &str,
    ts: DateTime,
) {
    app.db
        .collection::<Document>(SETUP_DIAGNOSTICS)
        .insert_one(doc! {
            "run": run, "step": step, "outcome": outcome, "elapsed_ms": 900_i64,
            "error_code": code.map(bson::Bson::from).unwrap_or(bson::Bson::Null),
            "os": os, "wizard_version": "0.4.138", "ts": ts,
        })
        .await
        .unwrap();
}

fn at(day: NaiveDate, h: u32, m: u32) -> DateTime {
    DateTime::from_millis(
        day.and_hms_opt(h, m, 0)
            .unwrap()
            .and_utc()
            .timestamp_millis(),
    )
}

async fn frozen_rows(app: &TestApp) -> Vec<(String, String, String, String, i64)> {
    use futures::TryStreamExt;
    let docs: Vec<Document> = app
        .db
        .collection::<Document>("growth_daily")
        .find(doc! { "source": "install", "metric": "wizard_step" })
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    let mut rows: Vec<_> = docs
        .iter()
        .map(|d| {
            let dims = d.get_document("dims").unwrap();
            (
                d.get_str("day").unwrap().to_string(),
                dims.get_str("step").unwrap().to_string(),
                dims.get_str("outcome").unwrap().to_string(),
                dims.get_str("os").unwrap().to_string(),
                d.get_i64("value").unwrap(),
            )
        })
        .collect();
    rows.sort();
    rows
}

// ── The route ────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_valid_record_is_stored_with_exactly_its_fields_and_nothing_about_the_request() {
    let app = TestApp::spawn().await;

    let r = post(&app, &record("download", "ok", None)).await;
    assert_eq!(r.status().as_u16(), 202);
    assert!(r.bytes().await.unwrap().is_empty(), "202 carries no body");
    let r = post(&app, &record("msi", "failed", Some("msi_user_cancel"))).await;
    assert_eq!(r.status().as_u16(), 202);
    let r = post(&app, &record("enroll", "cancelled", None)).await;
    assert_eq!(r.status().as_u16(), 202);

    let rows = all_rows(&app).await;
    assert_eq!(rows.len(), 3);
    for d in &rows {
        let mut keys: Vec<&str> = d.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "_id",
                "elapsed_ms",
                "error_code",
                "os",
                "outcome",
                "run",
                "step",
                "ts",
                "wizard_version"
            ],
            "exactly the record plus the server's clock"
        );
        assert_eq!(d.get_str("run").unwrap(), RUN);
        assert_eq!(d.get_i64("elapsed_ms").unwrap(), 1500);
        assert!(d.get_datetime("ts").is_ok(), "ts is the server's clock");
        let mut strings = Vec::new();
        strings_of(&bson::Bson::Document(d.clone()), &mut strings);
        for s in strings {
            assert!(!s.contains("127.0.0.1"), "an address reached the row: {s}");
            assert!(
                !s.contains("meshharbor-setup/"),
                "the User-Agent reached the row: {s}"
            );
            assert!(!s.contains("Mozilla"), "{s}");
        }
    }
    let msi = rows
        .iter()
        .find(|d| d.get_str("step") == Ok("msi"))
        .unwrap();
    assert_eq!(msi.get_str("error_code").unwrap(), "msi_user_cancel");
    let dl = rows
        .iter()
        .find(|d| d.get_str("step") == Ok("download"))
        .unwrap();
    assert_eq!(dl.get("error_code"), Some(&bson::Bson::Null));

    // The static segment wins over the proxy's `/{platform}` for every
    // method: a GET here is a 405 now (it used to be refused as an unknown
    // platform, 400), and the proxy's `/{platform}/health` is untouched.
    let r = app.client.get(app.url(ROUTE)).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 405);
    let r = app
        .client
        .get(app.url("/api/setup/diagnostics/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "the proxy's own refusal, as before"
    );
}

#[tokio::test]
async fn every_invalid_field_is_refused_with_a_code_and_nothing_is_stored() {
    let app = TestApp::spawn().await;

    let cases: Vec<(Value, &str)> = vec![
        (
            json!({ "run": "0123456789ABCDEF0123456789abcdef", "step": "download", "outcome": "ok", "elapsed_ms": 1, "error_code": null, "os": "windows", "wizard_version": "0.4.138" }),
            "invalid_run",
        ),
        (
            json!({ "run": "abc", "step": "download", "outcome": "ok", "elapsed_ms": 1, "error_code": null, "os": "windows", "wizard_version": "0.4.138" }),
            "invalid_run",
        ),
        (
            json!({ "run": RUN, "step": "install", "outcome": "ok", "elapsed_ms": 1, "error_code": null, "os": "windows", "wizard_version": "0.4.138" }),
            "unknown_step",
        ),
        (
            json!({ "run": RUN, "step": "download", "outcome": "error", "elapsed_ms": 1, "error_code": null, "os": "windows", "wizard_version": "0.4.138" }),
            "unknown_outcome",
        ),
        (
            json!({ "run": RUN, "step": "download", "outcome": "ok", "elapsed_ms": 86_400_001_u64, "error_code": null, "os": "windows", "wizard_version": "0.4.138" }),
            "elapsed_out_of_range",
        ),
        (
            json!({ "run": RUN, "step": "download", "outcome": "ok", "elapsed_ms": -1, "error_code": null, "os": "windows", "wizard_version": "0.4.138" }),
            "invalid_json",
        ),
        (
            json!({ "run": RUN, "step": "msi", "outcome": "failed", "elapsed_ms": 1, "error_code": "C:\\Users\\me\\AppData\\MSI1.log", "os": "windows", "wizard_version": "0.4.138" }),
            "unknown_error_code",
        ),
        (
            json!({ "run": RUN, "step": "msi", "outcome": "failed", "elapsed_ms": 1, "error_code": null, "os": "windows", "wizard_version": "0.4.138" }),
            "missing_error_code",
        ),
        (
            json!({ "run": RUN, "step": "msi", "outcome": "ok", "elapsed_ms": 1, "error_code": "other", "os": "windows", "wizard_version": "0.4.138" }),
            "unexpected_error_code",
        ),
        (
            json!({ "run": RUN, "step": "download", "outcome": "ok", "elapsed_ms": 1, "error_code": null, "os": "Windows 11 Pro", "wizard_version": "0.4.138" }),
            "unknown_os",
        ),
        (
            json!({ "run": RUN, "step": "download", "outcome": "ok", "elapsed_ms": 1, "error_code": null, "os": "windows", "wizard_version": "0.4.138 on DESKTOP-7" }),
            "invalid_wizard_version",
        ),
        (
            json!({ "run": RUN, "step": "download", "outcome": "ok", "elapsed_ms": 1, "error_code": null, "os": "windows", "wizard_version": "" }),
            "invalid_wizard_version",
        ),
        // An eighth key — whatever it carries — fails the parse.
        (
            json!({ "run": RUN, "step": "download", "outcome": "ok", "elapsed_ms": 1, "error_code": null, "os": "windows", "wizard_version": "0.4.138", "hostname": "DESKTOP-7" }),
            "invalid_json",
        ),
        // A missing key does too.
        (
            json!({ "run": RUN, "step": "download", "outcome": "ok", "elapsed_ms": 1, "os": "windows", "wizard_version": "0.4.138" }),
            "invalid_json",
        ),
        (json!("a string"), "invalid_json"),
    ];
    for (body, code) in cases {
        let r = post_raw(&app, &serde_json::to_vec(&body).unwrap()).await;
        assert_eq!(r.status().as_u16(), 422, "{body}");
        let v: Value = r.json().await.unwrap();
        assert_eq!(v["error"], code, "{body}");
        assert!(v.get("message").is_none(), "a code, never the value: {v}");
    }
    let r = post_raw(&app, b"{not json").await;
    assert_eq!(r.status().as_u16(), 422);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"], "invalid_json");

    // Over the size cap: refused by the route's layer before any parse.
    let mut big = serde_json::to_value(record("download", "ok", None)).unwrap();
    big["wizard_version"] = json!("0".repeat(MAX_BODY_BYTES + 1));
    let r = post_raw(&app, &serde_json::to_vec(&big).unwrap()).await;
    assert_eq!(r.status().as_u16(), 413);

    assert!(
        all_rows(&app).await.is_empty(),
        "nothing stored by a refusal"
    );
}

#[tokio::test]
async fn the_kill_switch_answers_the_empty_404_of_an_absent_path() {
    let app = TestApp::spawn_with_settings(|s| s.growth.setup_diagnostics = false).await;

    let absent = app
        .client
        .post(app.url("/api/this-path-does-not-exist"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    let absent_status = absent.status();
    let absent_type = absent.headers().get("content-type").cloned();
    let absent_body = absent.bytes().await.unwrap();
    assert_eq!(absent_status.as_u16(), 404);

    let r = post(&app, &record("download", "ok", None)).await;
    assert_eq!(r.status(), absent_status);
    assert_eq!(r.headers().get("content-type").cloned(), absent_type);
    assert_eq!(
        r.bytes().await.unwrap(),
        absent_body,
        "the same bytes as an absent path"
    );
    assert!(all_rows(&app).await.is_empty(), "nothing was written");
}

#[tokio::test]
async fn a_run_cannot_write_past_its_cap() {
    let app = TestApp::spawn().await;
    for i in 0..MAX_ROWS_PER_RUN {
        let r = post(&app, &record("preflight", "ok", None)).await;
        assert_eq!(r.status().as_u16(), 202, "row {i}");
    }
    let r = post(&app, &record("preflight", "ok", None)).await;
    assert_eq!(r.status().as_u16(), 429);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"], "run_capped");
    assert_eq!(all_rows(&app).await.len() as u64, MAX_ROWS_PER_RUN);

    // Another run is its own budget.
    let mut other = record("preflight", "ok", None);
    other.run = "f".repeat(32);
    let r = post(&app, &other).await;
    assert_eq!(r.status().as_u16(), 202);
}

// ── The freeze and the digest ────────────────────────────────────────────

#[tokio::test]
async fn the_nightly_freeze_writes_daily_distinct_run_counts_that_outlive_the_rows() {
    let app = TestApp::spawn().await;
    let now = DateTime::parse_rfc3339_str("2026-10-16T03:00:00Z").unwrap();
    let d1 = NaiveDate::from_ymd_opt(2026, 10, 15).unwrap(); // yesterday
    let d2 = NaiveDate::from_ymd_opt(2026, 10, 14).unwrap();
    let d_old = NaiveDate::from_ymd_opt(2026, 10, 1).unwrap(); // outside the window
    let a = "a".repeat(32);
    let b = "b".repeat(32);
    let c = "c".repeat(32);
    // Run A on d1: preflight ok, msi failed, msi ok (a retry), done ok.
    seed(&app, &a, "preflight", "ok", None, "windows", at(d1, 9, 0)).await;
    seed(
        &app,
        &a,
        "msi",
        "failed",
        Some("msi_fatal"),
        "windows",
        at(d1, 9, 1),
    )
    .await;
    seed(&app, &a, "msi", "ok", None, "windows", at(d1, 9, 3)).await;
    seed(&app, &a, "done", "ok", None, "windows", at(d1, 9, 4)).await;
    // Run B on d1: preflight ok, msi failed twice (both one run).
    seed(&app, &b, "preflight", "ok", None, "windows", at(d1, 10, 0)).await;
    seed(
        &app,
        &b,
        "msi",
        "failed",
        Some("msi_user_cancel"),
        "windows",
        at(d1, 10, 1),
    )
    .await;
    seed(
        &app,
        &b,
        "msi",
        "failed",
        Some("msi_user_cancel"),
        "windows",
        at(d1, 10, 2),
    )
    .await;
    // Run C on d2, a Linux tunnel install; and a row of a spelling this
    // build does not know, which must cost itself only.
    seed(&app, &c, "welcome", "ok", None, "linux", at(d2, 12, 0)).await;
    seed(&app, &c, "teleport", "ok", None, "linux", at(d2, 12, 1)).await;
    // Today's row is never frozen (the day is open).
    seed(
        &app,
        &c,
        "server",
        "ok",
        None,
        "linux",
        at(NaiveDate::from_ymd_opt(2026, 10, 16).unwrap(), 1, 0),
    )
    .await;
    // A row from long ago: outside the recompute window, never touched.
    seed(&app, &c, "token", "ok", None, "macos", at(d_old, 1, 0)).await;

    let changed = org_daily::freeze_setup_diagnostics(&app.state, now)
        .await
        .unwrap();
    assert_eq!(changed, vec!["2026-10-14", "2026-10-15"]);
    let expect = vec![
        (
            "2026-10-14".to_string(),
            "welcome".to_string(),
            "ok".to_string(),
            "linux".to_string(),
            1,
        ),
        (
            "2026-10-15".to_string(),
            "done".to_string(),
            "ok".to_string(),
            "windows".to_string(),
            1,
        ),
        (
            "2026-10-15".to_string(),
            "msi".to_string(),
            "failed".to_string(),
            "windows".to_string(),
            2,
        ),
        (
            "2026-10-15".to_string(),
            "msi".to_string(),
            "ok".to_string(),
            "windows".to_string(),
            1,
        ),
        (
            "2026-10-15".to_string(),
            "preflight".to_string(),
            "ok".to_string(),
            "windows".to_string(),
            2,
        ),
    ];
    assert_eq!(frozen_rows(&app).await, expect);

    // Idempotent: a second run changes nothing.
    let changed = org_daily::freeze_setup_diagnostics(&app.state, now)
        .await
        .unwrap();
    assert!(changed.is_empty(), "{changed:?}");
    assert_eq!(frozen_rows(&app).await, expect);

    // The rows expire (here: deleted); days past the recompute window are
    // never rewritten, so the frozen counts stay.
    app.db
        .collection::<Document>(SETUP_DIAGNOSTICS)
        .delete_many(doc! {})
        .await
        .unwrap();
    let later = DateTime::parse_rfc3339_str("2026-10-25T03:00:00Z").unwrap();
    let changed = org_daily::freeze_setup_diagnostics(&app.state, later)
        .await
        .unwrap();
    assert!(changed.is_empty(), "{changed:?}");
    assert_eq!(
        frozen_rows(&app).await,
        expect,
        "the counts outlive the rows"
    );
}

#[tokio::test]
async fn the_digest_reports_opted_in_runs_per_step_and_not_measured_when_off() {
    let app = TestApp::spawn().await;
    let day = NaiveDate::from_ymd_opt(2026, 10, 1).unwrap();
    let a = "a".repeat(32);
    let b = "b".repeat(32);
    let c = "c".repeat(32);
    let d = "d".repeat(32);
    // Run A, the day: every daemon step, done.
    for (i, step) in [
        "welcome",
        "server",
        "token",
        "preflight",
        "resolve",
        "download",
        "verify",
        "msi",
        "enroll",
        "done",
    ]
    .iter()
    .enumerate()
    {
        seed(&app, &a, step, "ok", None, "windows", at(day, 10, i as u32)).await;
    }
    // Run B, the day: failed at msi (declined UAC), retried, cancelled.
    seed(&app, &b, "welcome", "ok", None, "windows", at(day, 11, 0)).await;
    seed(
        &app,
        &b,
        "msi",
        "failed",
        Some("msi_user_cancel"),
        "windows",
        at(day, 11, 1),
    )
    .await;
    seed(
        &app,
        &b,
        "msi",
        "cancelled",
        None,
        "windows",
        at(day, 11, 2),
    )
    .await;
    // Run C, three days before: failed at enroll (a spent token).
    seed(
        &app,
        &c,
        "welcome",
        "ok",
        None,
        "linux",
        at(day - chrono::Duration::days(3), 9, 0),
    )
    .await;
    seed(
        &app,
        &c,
        "enroll",
        "failed",
        Some("enroll_rejected"),
        "linux",
        at(day - chrono::Duration::days(3), 9, 1),
    )
    .await;
    // Run D, twenty days before: welcome only. And one after the day,
    // which the day's digest must not see.
    seed(
        &app,
        &d,
        "welcome",
        "cancelled",
        None,
        "macos",
        at(day - chrono::Duration::days(20), 9, 0),
    )
    .await;
    seed(
        &app,
        &d,
        "welcome",
        "ok",
        None,
        "macos",
        at(day + chrono::Duration::days(1), 9, 0),
    )
    .await;

    let set = ExclusionSet::load(&app.state.core).await.unwrap();
    let sections = digest::compute(&app.state, day, &set, DateTime::now())
        .await
        .unwrap();
    let j = serde_json::to_value(&sections).unwrap();
    let ws = &j["install"]["wizard_steps"];
    assert_eq!(ws["runs"], json!({ "day": 2, "d7": 3, "d28": 4 }));
    assert_eq!(ws["n_floor"], 30);
    assert!(
        ws.get("done_share_28d").is_none(),
        "no share under the floor"
    );
    let steps = ws["steps"].as_array().unwrap();
    let names: Vec<&str> = steps.iter().map(|s| s["step"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "welcome",
            "server",
            "token",
            "preflight",
            "resolve",
            "download",
            "verify",
            "msi",
            "enroll",
            "done"
        ],
        "run order, only the steps some run reached"
    );
    let row = |name: &str| steps.iter().find(|s| s["step"] == name).unwrap().clone();
    assert_eq!(
        row("welcome")["reached"],
        json!({ "day": 2, "d7": 3, "d28": 4 })
    );
    assert_eq!(row("welcome")["ok"], json!({ "day": 2, "d7": 3, "d28": 3 }));
    assert_eq!(
        row("welcome")["cancelled"],
        json!({ "day": 0, "d7": 0, "d28": 1 })
    );
    // B reached msi once as a run, with two outcomes.
    assert_eq!(
        row("msi")["reached"],
        json!({ "day": 2, "d7": 2, "d28": 2 })
    );
    assert_eq!(row("msi")["ok"], json!({ "day": 1, "d7": 1, "d28": 1 }));
    assert_eq!(row("msi")["failed"], json!({ "day": 1, "d7": 1, "d28": 1 }));
    assert_eq!(
        row("msi")["cancelled"],
        json!({ "day": 1, "d7": 1, "d28": 1 })
    );
    assert_eq!(
        row("enroll")["failed"],
        json!({ "day": 0, "d7": 1, "d28": 1 })
    );
    assert_eq!(
        row("done")["reached"],
        json!({ "day": 1, "d7": 1, "d28": 1 })
    );
    assert_eq!(
        ws["errors"],
        json!([
            { "step": "msi", "error_code": "msi_user_cancel", "failures": { "day": 1, "d7": 1, "d28": 1 } },
            { "step": "enroll", "error_code": "enroll_rejected", "failures": { "day": 0, "d7": 1, "d28": 1 } },
        ])
    );
    // Nothing in the section names a person, an address or a host.
    let text = ws.to_string();
    assert!(!text.contains('@') && !text.contains("127.0.0.1"));

    // The switch off: not measured with the reason, never a zero.
    let off = TestApp::spawn_with_settings(|s| s.growth.setup_diagnostics = false).await;
    let set = ExclusionSet::load(&off.state.core).await.unwrap();
    let sections = digest::compute(&off.state, day, &set, DateTime::now())
        .await
        .unwrap();
    let j = serde_json::to_value(&sections).unwrap();
    let reason = j["install"]["wizard_steps"]["not_measured"]
        .as_str()
        .unwrap();
    assert!(reason.contains("off on this server"), "{reason}");
    assert!(j["install"]["wizard_steps"].get("arrives_with").is_none());
}
