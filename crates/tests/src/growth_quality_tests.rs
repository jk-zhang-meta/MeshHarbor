// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P9a — remote-desktop quality from what is already recorded,
//! against a real server (spec §3f).
//!
//! * the nightly freeze reads the four sources as they are REALLY written
//!   — `remote_sessions` (`created_at` / `started_at` / `ended_at` /
//!   `end_reason` / `stats`), the browser's `rc.connect` records and the
//!   agents' own batches in `agent_logs`, `agent_crashes` with its
//!   camelCase payload (`agentVersion`), `stats_machine_1d` — and writes
//!   one row per `(day, scope, agent_version)` with exact p50/p90, the
//!   version resolved from the device's own logs before its device row,
//!   both scopes, idempotently; a day past the 7-day log horizon is frozen
//!   without TTFF (not measured, never 0);
//! * the Quality view reads the frozen rows, pools them, orders versions
//!   newest first, and `include_internal=true` reads the `all` scope;
//! * the daily digest's quality section carries the day's TTFF and its
//!   per-version table from the frozen rows, the live outcome counts and
//!   distributions, crashes by their real version and per 100 device-days
//!   (a rate only from 30), and reads "not frozen yet" before the freeze;
//! * the weekly roll-up carries the same report for its week.

use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use chrono::NaiveDate;
use meshharbor_api::growth::{cohorts::week_start, digest, quality, weekly};
use meshharbor_core::growth::ExclusionSet;
use meshharbor_services::dao::growth_quality::{ALL_VERSIONS, GROWTH_QUALITY_DAILY, Scope};
use serde_json::{Value, json};

use crate::{
    fixtures::test_app::TestApp,
    growth_campaigns_tests::{at_day, ds, get_json, today},
};

// ── Seeds ────────────────────────────────────────────────────────────────

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

async fn user(app: &TestApp, id: ObjectId, created: DateTime) {
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

/// A device row with its CURRENT version — the fallback the freeze reads
/// when the device's own logs say nothing.
async fn agent(app: &TestApp, tenant: ObjectId, version: &str, created: DateTime) -> ObjectId {
    insert(
        app,
        "agents",
        doc! {
            "tenant_id": tenant, "owner_user_id": ObjectId::new(), "name": "box",
            "machine_id": format!("m-{}", ObjectId::new()), "os": "linux",
            "agent_version": version, "status": "offline",
            "created_at": created, "updated_at": created, "deleted_at": Bson::Null,
        },
    )
    .await
}

/// A `remote_sessions` row as the audit projection writes it: `created_at`
/// at the request, `started_at` when Active, `ended_at` + `end_reason` at
/// the end, `stats` merged by the device's samples (absent on a session
/// that never got that far).
#[allow(clippy::too_many_arguments)]
async fn session(
    app: &TestApp,
    tenant: ObjectId,
    agent_id: ObjectId,
    created: DateTime,
    started: Option<DateTime>,
    ended: Option<DateTime>,
    reason: Option<&str>,
    stats: Option<(f64, f64)>,
) -> ObjectId {
    let mut d = doc! {
        "agent_id": agent_id, "tenant_id": tenant, "controller_user_id": ObjectId::new(),
        "watchers": [], "permissions": 0_i32,
        "phase": match (started, ended) {
            (_, Some(_)) => "closed",
            (Some(_), None) => "active",
            (None, None) => "awaiting_consent",
        },
        "created_at": created,
        "started_at": started.map(Bson::DateTime).unwrap_or(Bson::Null),
        "ended_at": ended.map(Bson::DateTime).unwrap_or(Bson::Null),
        "end_reason": reason.map(|r| Bson::String(r.into())).unwrap_or(Bson::Null),
        "recording_url": Bson::Null,
    };
    if let Some((fps, rtt)) = stats {
        d.insert(
            "stats",
            doc! {
                "bytes_sent": 1000_i64, "bytes_recv": 100_i64, "peak_fps": fps, "avg_rtt_ms": rtt,
                "keyframe_requests": 0_i64, "input_events": 10_i64,
                "shared_seconds": 0_i64, "mixed_dial_seconds": 0_i64,
            },
        );
    }
    insert(app, "remote_sessions", d).await
}

/// An agent-source `agent_logs` batch: what says which version the device
/// ran, and under which session.
async fn agent_batch(
    app: &TestApp,
    tenant: ObjectId,
    agent_id: ObjectId,
    version: &str,
    session_id: Option<ObjectId>,
    at: DateTime,
) {
    let mut d = doc! {
        "tenant_id": tenant, "source": "agent", "agent_id": agent_id,
        "agent_version": version, "line_count": 1_i32, "created_at": at,
        "lines": [ { "ts": at, "level": "INFO", "target": "meshharbord::peer", "msg": "input dispatch", "fields": {} } ],
    };
    if let Some(s) = session_id {
        d.insert("session_id", s.to_hex());
    }
    insert(app, "agent_logs", d).await;
}

/// A browser `rc.connect` record, the exact shape `rcConnectTimingUpload.ts`
/// posts and the route stores (FR-22 part 4).
#[allow(clippy::too_many_arguments)]
async fn connect_record(
    app: &TestApp,
    tenant: ObjectId,
    agent_id: Option<ObjectId>,
    agent_org: Option<ObjectId>,
    session_id: Option<ObjectId>,
    outcome: &str,
    hidden: bool,
    attempt: i32,
    after_drop: bool,
    ttff_ms: Option<i64>,
    at: DateTime,
) {
    let mut fields = doc! {
        "v": 1_i32, "outcome": outcome, "attempt": attempt, "after_drop": after_drop,
        "hidden": hidden, "stalled_at": if ttff_ms.is_some() { Bson::Null } else { Bson::String("answer".into()) },
        "ttff_ms": ttff_ms.map(Bson::Int64).unwrap_or(Bson::Null),
        "agent_id": agent_id.map(|a| Bson::String(a.to_hex())).unwrap_or(Bson::Null),
        "marks": { "ws_ready": 12_i64 },
    };
    if let Some(o) = agent_org {
        fields.insert("agent_org_id", o.to_hex());
    }
    if let Some(ms) = ttff_ms {
        fields
            .get_document_mut("marks")
            .unwrap()
            .insert("first_frame", ms);
    }
    let mut d = doc! {
        "tenant_id": tenant, "source": "browser", "user_id": ObjectId::new(),
        "line_count": 1_i32, "created_at": at,
        "lines": [ {
            "ts": at, "level": if outcome == "first_frame" { "INFO" } else { "WARN" },
            "target": "rc.connect", "msg": "attempt 1 ttff 2736ms — ws_ready:+12", "fields": fields,
        } ],
    };
    if let Some(s) = session_id {
        d.insert("session_id", s.to_hex());
    }
    insert(app, "agent_logs", d).await;
}

/// An `agent_crashes` row as `AgentCrashDao::record` writes it: the record's
/// own fields snake_case, the payload flattened **camelCase**.
async fn crash(
    app: &TestApp,
    tenant: ObjectId,
    agent_id: ObjectId,
    version: Option<&str>,
    at: DateTime,
) {
    let mut d = doc! {
        "tenant_id": tenant, "agent_id": agent_id, "reported_at": at,
        "crashedAtUnix": at.timestamp_millis() / 1000, "reason": "panic", "summary": "boom",
        "logTail": "", "os": "linux", "hostname": "box", "pid": 4242_i64, "suppressedSinceLast": 0_i64,
    };
    if let Some(v) = version {
        d.insert("agentVersion", v);
    }
    insert(app, "agent_crashes", d).await;
}

/// A `stats_machine_1d` row as the rollup merges it: one per device per day.
async fn machine_day(
    app: &TestApp,
    tenant: ObjectId,
    agent_id: ObjectId,
    day: NaiveDate,
    online_minutes: i64,
) {
    app.db
        .collection::<Document>("stats_machine_1d")
        .insert_one(doc! {
            "_id": format!("{}:86400:{}", agent_id.to_hex(), ds(day)),
            "agent_id": agent_id, "tenant_id": tenant, "ts": at_day(day, 0),
            "sample_count": 10_i64, "online_minutes": online_minutes,
        })
        .await
        .unwrap();
}

fn plus_secs(t: DateTime, secs: i64) -> DateTime {
    DateTime::from_millis(t.timestamp_millis() + secs * 1000)
}

struct Seeded {
    app: TestApp,
    token: String,
    /// Yesterday: within the log horizon, closed.
    day: NaiveDate,
    /// An old day: sessions on record, logs long gone.
    old: NaiveDate,
}

/// Org A (external) with devices on three versions, org X owned by the
/// platform admin (implicitly excluded), and one day of everything.
async fn seed() -> Seeded {
    let admin = ObjectId::new();
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
    let day = today() - chrono::Duration::days(1);
    let old = today() - chrono::Duration::days(10);
    let born = at_day(old - chrono::Duration::days(30), 8);
    let owner = ObjectId::new();
    user(&app, owner, born).await;
    user(&app, admin, born).await;
    let a = org(&app, owner, "org-a", born).await;
    let x = org(&app, admin, "org-x", born).await;

    // a1 runs 0.4.137 (row and logs agree); a2's row still says 0.4.136 but
    // its logs that day say 0.4.137 (the logs win); a3 is on 0.4.120 and
    // uploads no logs (the row is all there is); ax is X's.
    let a1 = agent(&app, a, "0.4.137", born).await;
    let a2 = agent(&app, a, "0.4.136", born).await;
    let a3 = agent(&app, a, "0.4.120", born).await;
    let ax = agent(&app, x, "0.4.137", born).await;

    // Sessions requested on the day.
    let s1 = session(
        &app,
        a,
        a1,
        at_day(day, 10),
        Some(plus_secs(at_day(day, 10), 3)),
        Some(plus_secs(at_day(day, 10), 1803)),
        Some("controller_hangup"),
        Some((30.0, 40.0)),
    )
    .await;
    let s2 = session(
        &app,
        a,
        a1,
        at_day(day, 11),
        Some(plus_secs(at_day(day, 11), 2)),
        Some(plus_secs(at_day(day, 11), 62)),
        Some("agent_disconnect"),
        Some((24.0, 80.0)),
    )
    .await;
    let s3 = session(
        &app,
        a,
        a2,
        at_day(day, 12),
        None,
        Some(plus_secs(at_day(day, 12), 30)),
        Some("consent_timeout"),
        None,
    )
    .await;
    session(
        &app,
        a,
        a3,
        at_day(day, 13),
        None,
        Some(plus_secs(at_day(day, 13), 5)),
        Some("error"),
        None,
    )
    .await;
    // Still running at the freeze.
    session(
        &app,
        a,
        a1,
        at_day(day, 23),
        Some(plus_secs(at_day(day, 23), 4)),
        None,
        None,
        Some((0.0, 0.0)),
    )
    .await;
    // X's session: excluded from `external`, counted in `all`.
    session(
        &app,
        x,
        ax,
        at_day(day, 14),
        Some(plus_secs(at_day(day, 14), 1)),
        Some(plus_secs(at_day(day, 14), 601)),
        Some("controller_hangup"),
        Some((60.0, 20.0)),
    )
    .await;
    // The day before: not this day's.
    session(
        &app,
        a,
        a1,
        at_day(day - chrono::Duration::days(1), 10),
        Some(plus_secs(at_day(day - chrono::Duration::days(1), 10), 1)),
        Some(plus_secs(at_day(day - chrono::Duration::days(1), 10), 61)),
        Some("controller_hangup"),
        None,
    )
    .await;
    // An old day: on record, but its logs are gone.
    session(
        &app,
        a,
        a3,
        at_day(old, 10),
        Some(plus_secs(at_day(old, 10), 1)),
        Some(plus_secs(at_day(old, 10), 121)),
        Some("controller_hangup"),
        None,
    )
    .await;

    // The agents' own batches: a1 under s1 and s2, a2 under s3 (saying
    // 0.4.137 while its row says 0.4.136).
    agent_batch(
        &app,
        a,
        a1,
        "0.4.137",
        Some(s1),
        plus_secs(at_day(day, 10), 10),
    )
    .await;
    agent_batch(
        &app,
        a,
        a1,
        "0.4.137",
        Some(s2),
        plus_secs(at_day(day, 11), 10),
    )
    .await;
    agent_batch(&app, a, a1, "0.4.137", None, at_day(day, 9)).await;
    agent_batch(
        &app,
        a,
        a2,
        "0.4.137",
        Some(s3),
        plus_secs(at_day(day, 12), 1),
    )
    .await;

    // The browser's connect records.
    connect_record(
        &app,
        a,
        Some(a1),
        None,
        Some(s1),
        "first_frame",
        false,
        1,
        false,
        Some(2736),
        plus_secs(at_day(day, 10), 3),
    )
    .await;
    connect_record(
        &app,
        a,
        Some(a1),
        None,
        Some(s2),
        "first_frame",
        false,
        1,
        false,
        Some(1200),
        plus_secs(at_day(day, 11), 2),
    )
    .await;
    // A hidden tab: set aside.
    connect_record(
        &app,
        a,
        Some(a1),
        None,
        Some(s1),
        "first_frame",
        true,
        1,
        false,
        Some(90),
        plus_secs(at_day(day, 10), 40),
    )
    .await;
    // A second attempt: counted as a paint, not as a sample.
    connect_record(
        &app,
        a,
        Some(a1),
        None,
        Some(s2),
        "first_frame",
        false,
        2,
        false,
        Some(400),
        plus_secs(at_day(day, 11), 30),
    )
    .await;
    // The stall on a2's session, and a refused request on a3 with no session.
    connect_record(
        &app,
        a,
        Some(a2),
        None,
        Some(s3),
        "abandoned",
        false,
        1,
        false,
        None,
        plus_secs(at_day(day, 12), 15),
    )
    .await;
    connect_record(
        &app,
        a,
        Some(a3),
        None,
        None,
        "retried",
        false,
        1,
        false,
        None,
        at_day(day, 13),
    )
    .await;
    // X's own record, and a cross-org record filed under A's page for X's
    // device (FR-52): both excluded from `external`.
    connect_record(
        &app,
        x,
        Some(ax),
        None,
        None,
        "first_frame",
        false,
        1,
        false,
        Some(100),
        at_day(day, 14),
    )
    .await;
    connect_record(
        &app,
        a,
        Some(ax),
        Some(x),
        None,
        "first_frame",
        false,
        1,
        false,
        Some(5000),
        at_day(day, 15),
    )
    .await;

    // Crashes: a1's and a3's name their version, one names none; X's.
    crash(&app, a, a1, Some("0.4.137"), at_day(day, 16)).await;
    crash(&app, a, a3, Some("0.4.120"), at_day(day, 17)).await;
    crash(&app, a, a3, None, at_day(day, 18)).await;
    crash(&app, x, ax, Some("0.4.137"), at_day(day, 16)).await;

    // Devices online that day: a1 and a2 (a3 had no minutes); X's; and a1
    // the day before.
    machine_day(&app, a, a1, day, 600).await;
    machine_day(&app, a, a2, day, 10).await;
    machine_day(&app, a, a3, day, 0).await;
    machine_day(&app, x, ax, day, 100).await;
    machine_day(&app, a, a1, day - chrono::Duration::days(1), 300).await;

    Seeded {
        app,
        token,
        day,
        old,
    }
}

async fn frozen(app: &TestApp, scope: Scope, day: NaiveDate, version: &str) -> Option<Document> {
    app.db
        .collection::<Document>(GROWTH_QUALITY_DAILY)
        .find_one(doc! { "day": ds(day), "scope": scope.as_str(), "agent_version": version })
        .await
        .unwrap()
}

fn cell(sessions: &Document, reached: bool, reason: &str) -> Option<i64> {
    sessions
        .get_array("by_end_reason")
        .unwrap()
        .iter()
        .filter_map(|b| b.as_document())
        .find(|c| {
            c.get_bool("reached_active").unwrap() == reached
                && c.get_str("reason").unwrap() == reason
        })
        .map(|c| c.get_i64("count").unwrap())
}

// ── The freeze ───────────────────────────────────────────────────────────

#[tokio::test]
async fn the_freeze_writes_per_day_per_version_rows_from_the_four_sources() {
    let s = seed().await;
    let now = DateTime::now();
    let report = quality::freeze_range(&s.app.state, s.day, s.day, now)
        .await
        .unwrap();
    assert_eq!(report.days, 1);
    // External: every version + 0.4.137, 0.4.120, unknown; all: the same.
    assert_eq!(report.rows, 8, "{report:?}");

    let all = frozen(&s.app, Scope::External, s.day, ALL_VERSIONS)
        .await
        .expect("the every-version row");
    assert_eq!(
        all.get_str("_id").unwrap(),
        format!("{}:external:*", ds(s.day))
    );
    let sess = all.get_document("sessions").unwrap();
    assert_eq!(sess.get_i64("requested").unwrap(), 5, "{sess}");
    assert_eq!(sess.get_i64("reached_active").unwrap(), 3);
    assert_eq!(sess.get_i64("not_reached").unwrap(), 2);
    assert_eq!(sess.get_i64("pending").unwrap(), 0);
    assert_eq!(cell(sess, true, "controller_hangup"), Some(1));
    assert_eq!(cell(sess, true, "agent_disconnect"), Some(1));
    assert_eq!(cell(sess, false, "consent_timeout"), Some(1));
    assert_eq!(cell(sess, false, "error"), Some(1));
    assert_eq!(cell(sess, true, "open"), Some(1));
    let dur = sess.get_document("duration_ms").unwrap();
    assert_eq!(dur.get_i64("n").unwrap(), 2);
    assert_eq!(dur.get_i64("p50").unwrap(), 60_000);
    assert_eq!(dur.get_i64("p90").unwrap(), 1_800_000);
    let fps = sess.get_document("peak_fps").unwrap();
    assert_eq!(
        (
            fps.get_i64("n").unwrap(),
            fps.get_i64("p50").unwrap(),
            fps.get_i64("p90").unwrap()
        ),
        (2, 24, 30)
    );
    let rtt = sess.get_document("avg_rtt_ms").unwrap();
    assert_eq!(
        (
            rtt.get_i64("n").unwrap(),
            rtt.get_i64("p50").unwrap(),
            rtt.get_i64("p90").unwrap()
        ),
        (2, 40, 80)
    );

    // TTFF: two admissible paints; the hidden one and the second attempt
    // set aside; the stall and the refusal counted by outcome.
    let ttff = all.get_document("ttff").unwrap();
    let dist = ttff.get_document("dist").unwrap();
    assert_eq!(dist.get_i64("n").unwrap(), 2, "{ttff}");
    assert_eq!(dist.get_i64("p50").unwrap(), 1200);
    assert_eq!(dist.get_i64("p90").unwrap(), 2736);
    assert_eq!(ttff.get_i64("hidden").unwrap(), 1);
    assert_eq!(ttff.get_i64("later_attempts").unwrap(), 1);
    let outcomes = ttff.get_document("outcomes").unwrap();
    assert_eq!(outcomes.get_i64("first_frame").unwrap(), 3);
    assert_eq!(outcomes.get_i64("abandoned").unwrap(), 1);
    assert_eq!(outcomes.get_i64("retried").unwrap(), 1);
    // Crashes by their REAL field (`agentVersion`); device-days.
    assert_eq!(all.get_i64("crashes").unwrap(), 3);
    assert_eq!(all.get_i64("device_days").unwrap(), 2);

    // 0.4.137: a1's sessions and a2's (its logs say so, its row does not).
    let v137 = frozen(&s.app, Scope::External, s.day, "0.4.137")
        .await
        .unwrap();
    let sess = v137.get_document("sessions").unwrap();
    assert_eq!(sess.get_i64("requested").unwrap(), 4, "{sess}");
    assert_eq!(sess.get_i64("reached_active").unwrap(), 3);
    assert_eq!(sess.get_i64("not_reached").unwrap(), 1);
    assert_eq!(
        v137.get_document("ttff")
            .unwrap()
            .get_document("dist")
            .unwrap()
            .get_i64("n")
            .unwrap(),
        2
    );
    assert_eq!(v137.get_i64("crashes").unwrap(), 1);
    assert_eq!(
        v137.get_i64("device_days").unwrap(),
        2,
        "a1 and a2 both ran 0.4.137 that day"
    );
    // 0.4.120: a3, from its device row; its connect record was a retry.
    let v120 = frozen(&s.app, Scope::External, s.day, "0.4.120")
        .await
        .unwrap();
    let sess = v120.get_document("sessions").unwrap();
    assert_eq!(
        (
            sess.get_i64("requested").unwrap(),
            sess.get_i64("not_reached").unwrap()
        ),
        (1, 1)
    );
    let t = v120.get_document("ttff").unwrap();
    assert_eq!(t.get_document("dist").unwrap().get_i64("n").unwrap(), 0);
    assert_eq!(
        t.get_document("outcomes")
            .unwrap()
            .get_i64("retried")
            .unwrap(),
        1
    );
    assert_eq!(v120.get_i64("crashes").unwrap(), 1);
    assert_eq!(v120.get_i64("device_days").unwrap(), 0);
    // unknown: the crash that named no version.
    let unknown = frozen(&s.app, Scope::External, s.day, "unknown")
        .await
        .unwrap();
    assert_eq!(unknown.get_i64("crashes").unwrap(), 1);
    assert_eq!(
        unknown
            .get_document("sessions")
            .unwrap()
            .get_i64("requested")
            .unwrap(),
        0
    );
    assert!(
        frozen(&s.app, Scope::External, s.day, "0.4.136")
            .await
            .is_none(),
        "a2's row version is not what it ran"
    );

    // The `all` scope counts X too, and the cross-org record.
    let all_scope = frozen(&s.app, Scope::All, s.day, ALL_VERSIONS)
        .await
        .unwrap();
    assert_eq!(
        all_scope
            .get_document("sessions")
            .unwrap()
            .get_i64("requested")
            .unwrap(),
        6
    );
    assert_eq!(
        all_scope
            .get_document("ttff")
            .unwrap()
            .get_document("dist")
            .unwrap()
            .get_i64("n")
            .unwrap(),
        4
    );
    assert_eq!(all_scope.get_i64("crashes").unwrap(), 4);
    assert_eq!(all_scope.get_i64("device_days").unwrap(), 3);

    // Idempotent: the same rows again, nothing doubled.
    let again = quality::freeze_range(&s.app.state, s.day, s.day, now)
        .await
        .unwrap();
    assert_eq!(again.rows, 8);
    let count = s
        .app
        .db
        .collection::<Document>(GROWTH_QUALITY_DAILY)
        .count_documents(doc! { "day": ds(s.day) })
        .await
        .unwrap();
    assert_eq!(count, 8);
    let all2 = frozen(&s.app, Scope::External, s.day, ALL_VERSIONS)
        .await
        .unwrap();
    assert_eq!(
        all2.get_document("sessions").unwrap(),
        all.get_document("sessions").unwrap()
    );

    // An old day: its sessions are on record, its logs are gone — TTFF is
    // not measured (absent), never a zero; the version is the row's.
    quality::freeze_range(&s.app.state, s.old, s.old, now)
        .await
        .unwrap();
    let old = frozen(&s.app, Scope::External, s.old, ALL_VERSIONS)
        .await
        .unwrap();
    assert_eq!(
        old.get_document("sessions")
            .unwrap()
            .get_i64("reached_active")
            .unwrap(),
        1
    );
    assert!(old.get("ttff").is_none(), "{old}");
    assert_eq!(
        old.get_i64("crashes").unwrap(),
        0,
        "a measured zero: the crash rows exist for 90 days"
    );
    assert!(
        frozen(&s.app, Scope::External, s.old, "0.4.120")
            .await
            .is_some()
    );
}

// ── The view ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_view_pools_the_frozen_rows_and_include_internal_reads_the_all_scope() {
    let s = seed().await;
    let now = DateTime::now();
    let since = s.day - chrono::Duration::days(2);

    // Before the freeze: a reason, never zeros.
    let (status, j) = get_json(
        &s.app,
        &format!(
            "/api/admin/growth/quality?since={}&until={}",
            ds(since),
            ds(s.day)
        ),
        &s.token,
    )
    .await;
    assert_eq!(status, 200, "{j}");
    assert!(
        j["not_measured"]["not_measured"]
            .as_str()
            .unwrap()
            .contains("no frozen day"),
        "{j}"
    );
    assert!(j.get("totals").is_none());
    assert_eq!(j["frozen_days"], 0);
    assert_eq!(j["days"], 3);

    quality::freeze_range(&s.app.state, since, s.day, now)
        .await
        .unwrap();
    let (status, j) = get_json(
        &s.app,
        &format!(
            "/api/admin/growth/quality?since={}&until={}",
            ds(since),
            ds(s.day)
        ),
        &s.token,
    )
    .await;
    assert_eq!(status, 200, "{j}");
    assert_eq!(j["frozen_days"], 3);
    assert_eq!(j["ttff_horizon_days"], 7);
    assert_eq!(j["n_floor"], 30);
    assert_eq!(j["excluded"], json!({ "users": 1, "tenants": 1 }));
    let t = &j["totals"];
    assert_eq!(t["agent_version"], "*");
    // Three days: the day before's one session plus the day's five.
    assert_eq!(t["sessions"]["requested"], 6, "{t}");
    assert_eq!(t["sessions"]["reached_active"], 4);
    assert_eq!(t["sessions"]["not_reached"], 2);
    assert!(t["sessions"].get("reached_share").is_none(), "n < 30");
    assert_eq!(t["sessions"]["days"], 3);
    // Pooled over three days: an estimate, labelled so.
    assert_eq!(t["sessions"]["duration_ms"]["n"], 3);
    assert_eq!(t["sessions"]["duration_ms"]["exact"], false);
    assert_eq!(t["ttff"]["n"], 2);
    assert_eq!(
        t["ttff"]["days_measured"], 3,
        "every day in the horizon was measured"
    );
    assert_eq!(t["ttff"]["exact"], false);
    assert!(t["ttff"]["p50_ms"].is_number(), "{t}");
    assert_eq!(t["crashes"], 3);
    assert_eq!(t["device_days"], 3);
    assert!(
        t.get("crashes_per_100_device_days").is_none(),
        "3 device-days < 30"
    );
    let versions: Vec<&str> = j["by_agent_version"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["agent_version"].as_str().unwrap())
        .collect();
    assert_eq!(
        versions,
        ["0.4.137", "0.4.120", "unknown"],
        "newest first, unknown last"
    );
    let series = j["series"].as_array().unwrap();
    assert_eq!(series.len(), 3);
    let last = series.last().unwrap();
    assert_eq!(last["day"], ds(s.day));
    assert_eq!(last["requested"], 5);
    assert_eq!(last["ttff_p50_ms"], 1200);
    assert_eq!(last["ttff_p90_ms"], 2736);
    assert_eq!(last["crashes"], 3);
    let first = &series[0];
    assert_eq!(first["requested"], 0);
    assert_eq!(
        first["ttff_n"], 0,
        "a measured zero: the logs covered the day"
    );

    // The raw totals: X's session, record, crash and device.
    let (_, raw) = get_json(
        &s.app,
        &format!(
            "/api/admin/growth/quality?since={}&until={}&include_internal=true",
            ds(since),
            ds(s.day)
        ),
        &s.token,
    )
    .await;
    assert_eq!(raw["totals"]["sessions"]["requested"], 7);
    assert_eq!(raw["totals"]["ttff"]["n"], 4);
    assert_eq!(raw["totals"]["crashes"], 4);
    assert_eq!(raw["totals"]["device_days"], 4);
    assert_eq!(raw["excluded"], json!({ "users": 0, "tenants": 0 }));

    // The default range ends yesterday; an open day is clamped; a reversed
    // range is refused; a non-admin meets the 404 the surface hides behind.
    let (status, j) = get_json(&s.app, "/api/admin/growth/quality", &s.token).await;
    assert_eq!(status, 200);
    assert_eq!(j["until"], ds(s.day));
    assert_eq!(j["days"], 28);
    let (status, _) = get_json(
        &s.app,
        &format!(
            "/api/admin/growth/quality?since={}&until={}",
            ds(s.day),
            ds(since)
        ),
        &s.token,
    )
    .await;
    assert_eq!(status, 400);
    let plain = s
        .app
        .state
        .auth
        .generate_tokens(ObjectId::new(), "p@test.io", "p")
        .unwrap()
        .access_token;
    let (status, _) = get_json(&s.app, "/api/admin/growth/quality", &plain).await;
    assert_eq!(status, 404);

    // The backfill route re-freezes a closed range with the current set.
    let r = s
        .app
        .auth_post(
            &format!("/api/admin/growth/quality/backfill?since={}", ds(s.old)),
            &s.token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let b: Value = r.json().await.unwrap();
    assert_eq!(b["since"], ds(s.old));
    assert_eq!(b["until"], ds(s.day));
    assert_eq!(b["days"], 10);
    let (_, j) = get_json(
        &s.app,
        &format!(
            "/api/admin/growth/quality?since={}&until={}",
            ds(s.old),
            ds(s.day)
        ),
        &s.token,
    )
    .await;
    assert_eq!(j["frozen_days"], 10);
    // TTFF is measured only for the days whose logs are still complete —
    // `day_start + 7 d > now`, the last six closed days; the four older
    // days are frozen without it, never with a zero.
    assert_eq!(
        j["totals"]["ttff"]["days_measured"], 6,
        "{}",
        j["totals"]["ttff"]
    );
    let measured: Vec<bool> = j["series"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.get("ttff_n").is_some())
        .collect();
    assert_eq!(
        measured,
        [
            false, false, false, false, true, true, true, true, true, true
        ],
        "{measured:?}"
    );
    let r = s
        .app
        .auth_post(
            &format!("/api/admin/growth/quality/backfill?since={}", ds(today())),
            &s.token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400, "today is not closed");
}

// ── The digest and the weekly roll-up ────────────────────────────────────

#[tokio::test]
async fn the_digest_and_the_weekly_carry_the_frozen_quality() {
    let s = seed().await;
    let now = DateTime::now();
    let set = ExclusionSet::load(&s.app.state.core).await.unwrap();
    assert_eq!(set.counts(), (1, 1));

    // Before the freeze: the live parts measure, the frozen parts say why
    // they do not.
    let before = digest::compute(&s.app.state, s.day, &set, now)
        .await
        .unwrap();
    let j = serde_json::to_value(&before).unwrap();
    let q = &j["quality"];
    assert!(
        q["ttff"]["not_measured"]
            .as_str()
            .unwrap()
            .contains("not frozen yet"),
        "{q}"
    );
    assert!(
        q["by_agent_version"]["not_measured"]
            .as_str()
            .unwrap()
            .contains("not frozen yet")
    );
    assert_eq!(q["remote"]["requested"]["day"], 5, "{}", q["remote"]);
    assert_eq!(q["remote"]["reached_active"]["day"], 3);
    assert_eq!(q["remote"]["not_reached"]["day"], 2);
    assert_eq!(q["remote"]["requested"]["d7"], 6);
    assert!(q["remote"]["reached_share"].get("day").is_none(), "n < 30");
    assert_eq!(
        q["remote"]["duration_ms"]["day"],
        json!({ "n": 2, "p50": 60_000, "p90": 1_800_000 })
    );
    assert_eq!(q["remote"]["duration_ms"]["d7"]["n"], 3);
    assert_eq!(
        q["remote"]["peak_fps"]["day"],
        json!({ "n": 2, "p50": 24, "p90": 30 })
    );
    assert_eq!(
        q["remote"]["avg_rtt_ms"]["day"],
        json!({ "n": 2, "p50": 40, "p90": 80 })
    );
    // Crashes by their REAL field: before P9a every one of these read
    // "unknown".
    assert_eq!(q["crashes"]["total"]["day"], 3);
    assert_eq!(
        q["crashes"]["by_agent_version"],
        json!([{ "key": "0.4.120", "count": 1 }, { "key": "0.4.137", "count": 1 }, { "key": "unknown", "count": 1 }])
    );
    assert_eq!(
        q["crashes"]["device_days"],
        json!({ "day": 2, "d7": 3, "d28": 3 })
    );
    assert!(
        q["crashes"]["per_100_device_days"].get("day").is_none(),
        "n < 30 device-days"
    );

    quality::freeze_range(&s.app.state, s.day - chrono::Duration::days(1), s.day, now)
        .await
        .unwrap();
    let after = digest::compute(&s.app.state, s.day, &set, now)
        .await
        .unwrap();
    let j = serde_json::to_value(&after).unwrap();
    let q = &j["quality"];
    assert_eq!(
        q["ttff"]["n"],
        json!({ "day": 2, "d7": 2, "d28": 2 }),
        "{}",
        q["ttff"]
    );
    assert_eq!(
        q["ttff"]["days_measured"],
        json!({ "day": 1, "d7": 2, "d28": 2 })
    );
    assert_eq!(q["ttff"]["p50_ms"]["day"], 1200);
    assert_eq!(q["ttff"]["p90_ms"]["day"], 2736);
    assert_eq!(q["ttff"]["windows_estimated"], true);
    assert_eq!(q["ttff"]["hidden"]["day"], 1);
    assert_eq!(q["ttff"]["later_attempts"]["day"], 1);
    let rows = q["by_agent_version"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert_eq!(rows[0]["agent_version"], "0.4.137");
    assert_eq!(rows[0]["requested"], 4);
    assert_eq!(rows[0]["reached_active"], 3);
    assert_eq!(rows[0]["not_reached"], 1);
    assert_eq!(rows[0]["failures"], 1, "s2's agent_disconnect");
    assert_eq!(rows[0]["ttff_n"], 2);
    assert_eq!(rows[0]["ttff_p50_ms"], 1200);
    assert_eq!(rows[0]["crashes"], 1);
    assert_eq!(rows[0]["device_days"], 2);
    assert_eq!(rows[1]["agent_version"], "0.4.120");
    assert_eq!(rows[1]["failures"], 1, "s4's error, never Active");
    assert_eq!(rows[1]["ttff_n"], 0);
    assert_eq!(rows[2]["agent_version"], "unknown");
    assert_eq!(rows[2]["crashes"], 1);
    // The stored shape round-trips typed, with the new fields.
    let back: digest::Sections = bson::from_document(bson::to_document(&after).unwrap()).unwrap();
    assert_eq!(back, after);
    // A row stored before P9a reads the two new fields as not measured.
    let mut old = bson::to_document(&after).unwrap();
    let mut quality_doc = old.get_document("quality").unwrap().clone();
    quality_doc.remove("ttff");
    quality_doc.remove("by_agent_version");
    old.insert("quality", quality_doc);
    let older: digest::Sections = bson::from_document(old).unwrap();
    let j = serde_json::to_value(&older).unwrap();
    assert_eq!(j["quality"]["ttff"]["arrives_with"], "P9a");

    // The raw preview reads the `all` scope: X's record counted.
    let raw = digest::compute(&s.app.state, s.day, &ExclusionSet::none(), now)
        .await
        .unwrap();
    let j = serde_json::to_value(&raw).unwrap();
    assert_eq!(j["quality"]["ttff"]["n"]["day"], 4);
    assert_eq!(j["quality"]["remote"]["requested"]["day"], 6);

    // The weekly roll-up carries the view's report for its week.
    let monday = week_start(s.day);
    let sections = weekly::compute(&s.app.state, monday, &set, now)
        .await
        .unwrap();
    let j = serde_json::to_value(&sections).unwrap();
    let wq = &j["quality"];
    assert_eq!(wq["since"], ds(monday));
    assert_eq!(wq["days"], 7);
    assert!(wq["frozen_days"].as_i64().unwrap() >= 1, "{wq}");
    assert_eq!(wq["totals"]["agent_version"], "*");
    assert!(wq["totals"]["sessions"]["requested"].as_i64().unwrap() >= 5);
    assert_eq!(wq["totals"]["ttff"]["n"], 2);
    // Nothing here names a person, an address or a host.
    let text = j["quality"].to_string();
    assert!(
        !text.contains('@') && !text.contains("padmin") && !text.contains("box"),
        "{text}"
    );
}

// ── P9c — the Active sessions split by carrier ───────────────────────────

/// A `remote_sessions` row with a chosen carrier (or none), Active and ended
/// on the day, with fps/rtt so the per-carrier distributions have samples.
#[allow(clippy::too_many_arguments)]
async fn carrier_session(
    app: &TestApp,
    tenant: ObjectId,
    day: NaiveDate,
    start_h: u32,
    duration_secs: i64,
    fps: f64,
    rtt: f64,
    carrier: Option<&str>,
) {
    let created = at_day(day, start_h);
    let started = DateTime::from_millis(created.timestamp_millis() + 2000);
    let ended = DateTime::from_millis(started.timestamp_millis() + duration_secs * 1000);
    let mut d = doc! {
        "agent_id": ObjectId::new(), "tenant_id": tenant, "controller_user_id": ObjectId::new(),
        "watchers": [], "permissions": 1_i32, "phase": "closed",
        "created_at": created, "started_at": started, "ended_at": ended,
        "end_reason": "controller_hangup", "recording_url": Bson::Null,
        "stats": {
            "bytes_sent": 1000_i64, "bytes_recv": 100_i64, "peak_fps": fps, "avg_rtt_ms": rtt,
            "keyframe_requests": 0_i64, "input_events": 1_i64, "shared_seconds": 0_i64, "mixed_dial_seconds": 0_i64,
        },
    };
    if let Some(c) = carrier {
        d.insert("carrier", c);
    }
    insert(app, "remote_sessions", d).await;
}

/// The freeze splits the day's Active sessions by the carrier they rode; a
/// session the agent never recorded one for is `unknown`, never direct; and
/// the Quality view pools the split over its range.
#[tokio::test]
async fn the_freeze_splits_active_sessions_by_carrier() {
    let app = TestApp::spawn().await;
    let now = DateTime::now();
    let day = today() - chrono::Duration::days(1);
    let owner = ObjectId::new();
    app.db
        .collection::<Document>("tenants")
        .insert_one(doc! {
            "_id": owner, "name": "org", "slug": "cg-org", "owner_id": ObjectId::new(), "plan": "free",
            "features": [], "settings": {}, "created_at": at_day(day - chrono::Duration::days(10), 1),
            "updated_at": at_day(day, 1), "deleted_at": Bson::Null, "is_archived": false,
        })
        .await
        .unwrap();
    let t = owner;
    // Two DERP sessions, one direct, one org-relay, and one with no carrier.
    carrier_session(&app, t, day, 9, 600, 30.0, 120.0, Some("derp")).await;
    carrier_session(&app, t, day, 10, 300, 24.0, 160.0, Some("derp")).await;
    carrier_session(&app, t, day, 11, 1200, 60.0, 20.0, Some("direct")).await;
    carrier_session(&app, t, day, 12, 120, 15.0, 240.0, Some("org_relay")).await;
    carrier_session(&app, t, day, 13, 90, 30.0, 80.0, None).await;

    quality::freeze_range(&app.state, day, day, now)
        .await
        .unwrap();
    let row = app
        .db
        .collection::<Document>(GROWTH_QUALITY_DAILY)
        .find_one(doc! { "day": ds(day), "scope": "all", "agent_version": ALL_VERSIONS })
        .await
        .unwrap()
        .expect("the every-version row");
    let by: Vec<&Document> = row
        .get_document("sessions")
        .unwrap()
        .get_array("by_carrier")
        .unwrap()
        .iter()
        .filter_map(|b| b.as_document())
        .collect();
    let cell = |carrier: &str| {
        by.iter()
            .find(|c| c.get_str("carrier").unwrap() == carrier)
            .map(|c| c.get_i64("reached_active").unwrap())
    };
    // Most-ridden first: derp (2), then the singles alphabetically.
    assert_eq!(by[0].get_str("carrier").unwrap(), "derp");
    assert_eq!(cell("derp"), Some(2));
    assert_eq!(cell("direct"), Some(1));
    assert_eq!(cell("org_relay"), Some(1));
    assert_eq!(
        cell("unknown"),
        Some(1),
        "a session with no carrier is unknown, never direct"
    );
    assert_eq!(cell("overlay_direct"), None);
    // The derp cell's duration distribution saw both derp sessions.
    let derp = by
        .iter()
        .find(|c| c.get_str("carrier").unwrap() == "derp")
        .unwrap();
    assert_eq!(
        derp.get_document("duration_ms")
            .unwrap()
            .get_i64("n")
            .unwrap(),
        2
    );

    // The Quality view pools the same split over its range (include_internal,
    // since the org is not excluded here but the default set is empty anyway).
    let set = ExclusionSet::none();
    let report = quality::compute(&app.state, &set, day, day, true, now)
        .await
        .unwrap();
    let j = serde_json::to_value(&report).unwrap();
    let vcarriers = j["totals"]["sessions"]["by_carrier"].as_array().unwrap();
    assert_eq!(vcarriers[0]["carrier"], "derp");
    assert_eq!(vcarriers[0]["reached_active"], 2);
    assert!(
        vcarriers
            .iter()
            .any(|c| c["carrier"] == "unknown" && c["reached_active"] == 1)
    );
}
