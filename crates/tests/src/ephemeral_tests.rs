// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-51 P1 — ephemeral nodes: the reaper, and the shared removal sequence.
//!
//! Every test drives `run_ephemeral_reap` directly (the `run_presence_sweep`
//! pattern) instead of waiting out the timer, and reads the RAW collection to
//! tell "hard-deleted" from "tombstoned" — the distinction is the point of
//! FR-51 F4, and the HTTP list cannot see it (both states vanish from it).
//!
//! The load-bearing negative is `reaper_never_touches_a_permanent_row`: the
//! prod fleet has live rows unseen for >30 days, and the reaper's predicate
//! must be structurally unable to match them.

use bson::oid::ObjectId;
use serde_json::{Value, json};

use crate::fixtures::test_app::TestApp;

/// Enroll a device through the REAL route pair (admin mints the token, the
/// "device" posts it) so the row under test is the row production writes.
async fn enroll_agent(
    app: &TestApp,
    tenant_id: &str,
    admin_token: &str,
    machine_id: &str,
) -> ObjectId {
    let et: Value = app
        .auth_post(
            &format!("/api/tenant/{tenant_id}/agent/enroll-token"),
            admin_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let resp: Value = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": et["enrollment_token"].as_str().unwrap(),
            "machine_id": machine_id,
            "machine_name": format!("host-{machine_id}"),
            "os": "linux",
            "agent_version": "0.4.42",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    ObjectId::parse_str(resp["agent_id"].as_str().expect("agent_id")).unwrap()
}

/// Rewind a row's `last_seen_at` so the reaper sees `silence_secs` of quiet.
async fn rewind_last_seen(app: &TestApp, agent_id: ObjectId, silence_secs: i64) {
    let when =
        bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - silence_secs * 1000);
    app.db
        .collection::<bson::Document>("agents")
        .update_one(
            bson::doc! { "_id": agent_id },
            bson::doc! { "$set": { "last_seen_at": when } },
        )
        .await
        .expect("rewind last_seen_at");
}

/// Raw row count for one agent id — including tombstones, which is what
/// distinguishes a hard delete (0) from a soft delete (1 with `deleted_at`).
async fn raw_rows(app: &TestApp, agent_id: ObjectId) -> Vec<bson::Document> {
    let mut cur = app
        .db
        .collection::<bson::Document>("agents")
        .find(bson::doc! { "_id": agent_id })
        .await
        .unwrap();
    let mut out = Vec::new();
    while cur.advance().await.unwrap() {
        out.push(cur.deserialize_current().unwrap());
    }
    out
}

#[tokio::test]
async fn reaper_removes_expired_ephemeral_row_outright() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("ephem1").await;
    let aid = enroll_agent(&app, &t.tenant_id, &t.admin.access_token, "ephem1-m1").await;

    // The response surface says what the row is BEFORE it vanishes — the
    // grid badge is how an operator is never surprised by the vanishing.
    app.state
        .fleet()
        .agents
        .set_ephemeral(aid, Some(60))
        .await
        .expect("mark ephemeral");
    let list: Value = app
        .auth_get(
            &format!("/api/tenant/{}/agent", t.tenant_id),
            &t.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = list["items"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["id"] == json!(aid.to_hex()))
        .expect("enrolled agent listed");
    assert_eq!(row["ephemeral"], json!(true));

    // 5 minutes of silence against a 60 s deadline.
    rewind_last_seen(&app, aid, 300).await;
    let n = meshharbor_mod_network::ephemeral::run_ephemeral_reap(app.state.network()).await;
    assert_eq!(n, 1, "exactly this device is due");

    // Gone MEANS gone: zero raw rows (a tombstone would be one row with
    // `deleted_at` set), so the random machine_id is not reserved either.
    assert!(
        raw_rows(&app, aid).await.is_empty(),
        "an ephemeral row must be hard-deleted, never tombstoned"
    );

    // And a second cycle finds nothing — the reap is not replayable.
    let n = meshharbor_mod_network::ephemeral::run_ephemeral_reap(app.state.network()).await;
    assert_eq!(n, 0);
}

#[tokio::test]
async fn reaper_never_touches_a_permanent_row() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("ephem2").await;
    let aid = enroll_agent(&app, &t.tenant_id, &t.admin.access_token, "ephem2-m1").await;

    // 30 days of silence — the exact shape of the live prod rows AC5 guards
    // (five live devices unseen >7 days must survive an enabled reaper).
    rewind_last_seen(&app, aid, 30 * 86_400).await;
    let n = meshharbor_mod_network::ephemeral::run_ephemeral_reap(app.state.network()).await;
    assert_eq!(n, 0, "a permanent row is never the reaper's to touch");

    let rows = raw_rows(&app, aid).await;
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0]
            .get("deleted_at")
            .map(|d| d == &bson::Bson::Null)
            .unwrap_or(false),
        "still live, not even tombstoned"
    );
}

#[tokio::test]
async fn reaper_respects_the_row_own_deadline() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("ephem3").await;
    let aid = enroll_agent(&app, &t.tenant_id, &t.admin.access_token, "ephem3-m1").await;
    app.state
        .fleet()
        .agents
        .set_ephemeral(aid, Some(3600))
        .await
        .unwrap();

    // 5 minutes silent: past the 60 s candidate floor (so the row IS
    // fetched), well inside its own 1 h deadline (so it must survive the
    // per-row check).
    rewind_last_seen(&app, aid, 300).await;
    let n = meshharbor_mod_network::ephemeral::run_ephemeral_reap(app.state.network()).await;
    assert_eq!(n, 0, "candidate by the floor, but its own TTL is longer");
    assert_eq!(raw_rows(&app, aid).await.len(), 1);
}

#[tokio::test]
async fn reaper_clamps_the_ttl_floor() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("ephem4").await;
    let aid = enroll_agent(&app, &t.tenant_id, &t.admin.access_token, "ephem4-m1").await;
    // A pathological 1-second deadline must not turn a 30 s heartbeat gap
    // into a deleted device: the floor is 60 s however small the stored TTL.
    app.state
        .fleet()
        .agents
        .set_ephemeral(aid, Some(1))
        .await
        .unwrap();

    rewind_last_seen(&app, aid, 30).await;
    let n = meshharbor_mod_network::ephemeral::run_ephemeral_reap(app.state.network()).await;
    assert_eq!(
        n, 0,
        "30 s of silence is below the floor, whatever the TTL says"
    );
    assert_eq!(raw_rows(&app, aid).await.len(), 1);
}

#[tokio::test]
async fn admin_delete_hard_deletes_ephemeral_and_tombstones_permanent() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("ephem5").await;
    let permanent = enroll_agent(&app, &t.tenant_id, &t.admin.access_token, "ephem5-perm").await;
    let ephemeral = enroll_agent(&app, &t.tenant_id, &t.admin.access_token, "ephem5-eph").await;
    app.state
        .fleet()
        .agents
        .set_ephemeral(ephemeral, None)
        .await
        .unwrap();

    for aid in [permanent, ephemeral] {
        let resp = app
            .auth_delete(
                &format!("/api/tenant/{}/agent/{}", t.tenant_id, aid.to_hex()),
                &t.admin.access_token,
            )
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
    }

    // Same route, two different removals, chosen by the ROW's own nature:
    // the permanent machine keeps its tombstone (it may return and revive in
    // place), the ephemeral one leaves nothing behind.
    let perm_rows = raw_rows(&app, permanent).await;
    assert_eq!(
        perm_rows.len(),
        1,
        "permanent row tombstones exactly as before"
    );
    assert!(
        perm_rows[0]
            .get("deleted_at")
            .map(|d| d != &bson::Bson::Null)
            .unwrap_or(false)
    );
    assert!(
        raw_rows(&app, ephemeral).await.is_empty(),
        "ephemeral row is removed outright on the admin path too"
    );
}
