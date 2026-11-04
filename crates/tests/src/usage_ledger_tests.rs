// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-20 — the cost ledger, against a real MongoDB.
//!
//! These close acceptance criteria the phase work did not: the ledger's
//! concurrency property, and the rule that only *carried* bytes are billed.
//!
//! ⚠ The concurrency test is the one the spec names explicitly ("two pods
//! writing the same bucket yield exactly one row"). It is not hypothetical: the
//! deployment runs two API pods, both flushing DERP bytes on their own 60 s
//! timer, and if the `_id` were not deterministic they would write two rows and
//! every bill would be split — silently, and in the *under*-reporting direction
//! that is hardest to notice.

use crate::fixtures::test_app::TestApp;
use bson::{doc, oid::ObjectId};
use meshharbor_services::dao::stats::{Meter, STATS_USAGE, USAGE_BUCKET_SECS, bucket_start};

#[tokio::test]
async fn concurrent_writers_produce_exactly_one_summed_bucket() {
    let app = TestApp::spawn().await;
    let tenant = ObjectId::new();
    let unix = 1_788_102_180i64;

    // Two writers, same tenant/meter/minute — the two-pod case.
    let (a, b) = (app.state.stats.clone(), app.state.stats.clone());
    let (ra, rb) = tokio::join!(
        a.add_usage(tenant, Meter::DerpBytes, unix, 1_000),
        // A different second INSIDE the same minute must land on the same
        // bucket — that is what makes the pods agree without coordinating.
        b.add_usage(tenant, Meter::DerpBytes, unix + 41, 2_345),
    );
    ra.expect("writer a");
    rb.expect("writer b");

    let rows: Vec<bson::Document> = app
        .state
        .stats
        .coll(STATS_USAGE)
        .find(doc! { "tenant_id": tenant })
        .await
        .unwrap()
        .try_collect_all()
        .await;

    assert_eq!(rows.len(), 1, "two pods must produce ONE row, got {rows:?}");
    assert_eq!(
        rows[0].get_i64("value").unwrap(),
        3_345,
        "the row must carry the SUM of both pods' contributions"
    );
    let expected_id = format!(
        "{}:{}:{}",
        tenant.to_hex(),
        Meter::DerpBytes.as_str(),
        bucket_start(unix, USAGE_BUCKET_SECS)
    );
    assert_eq!(rows[0].get_str("_id").unwrap(), expected_id);
}

/// Two meters for one tenant in one minute are two ledger lines. Without this
/// the `$merge`d derived meter and the `$inc`ed observed one could share a
/// document, and the SFU rollup would silently replace a bytes bucket.
#[tokio::test]
async fn different_meters_never_share_a_bucket() {
    let app = TestApp::spawn().await;
    let tenant = ObjectId::new();
    let unix = 1_788_102_180i64;

    app.state
        .stats
        .add_usage(tenant, Meter::DerpBytes, unix, 500)
        .await
        .unwrap();
    app.state
        .stats
        .add_usage(tenant, Meter::TurnBytes, unix, 700)
        .await
        .unwrap();

    let rows: Vec<bson::Document> = app
        .state
        .stats
        .coll(STATS_USAGE)
        .find(doc! { "tenant_id": tenant })
        .await
        .unwrap()
        .try_collect_all()
        .await;
    assert_eq!(rows.len(), 2, "one row per meter");
}

/// A tenant that relayed nothing has NO ledger rows — it does not get a zero
/// row. "No traffic" and "not monitored" must stay distinguishable all the way
/// to the UI, and a fabricated zero would collapse them.
#[tokio::test]
async fn a_tenant_with_no_traffic_has_no_rows() {
    let app = TestApp::spawn().await;
    let tenant = ObjectId::new();

    // A zero-valued write is a no-op by construction.
    app.state
        .stats
        .add_usage(tenant, Meter::DerpBytes, 1_788_102_180, 0)
        .await
        .unwrap();

    let n = app
        .state
        .stats
        .coll(STATS_USAGE)
        .count_documents(doc! { "tenant_id": tenant })
        .await
        .unwrap();
    assert_eq!(n, 0, "no traffic must mean no row, never a zero row");
}

/// Helper: collect a cursor without pulling in extra deps at the call sites.
trait CollectAll {
    async fn try_collect_all(self) -> Vec<bson::Document>;
}
impl CollectAll for mongodb::Cursor<bson::Document> {
    async fn try_collect_all(mut self) -> Vec<bson::Document> {
        use futures::TryStreamExt;
        let mut out = Vec::new();
        while let Some(d) = self.try_next().await.unwrap() {
            out.push(d);
        }
        out
    }
}
