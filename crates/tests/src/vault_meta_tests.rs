// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-4b — what a session may know of the vault's secrets: a listing
//! and a description, over its device's control connection, decided by
//! Cedar's `secret:list` and never carrying a value.
//!
//! Driven through P3-3b's raw agent socket. What these lock is the SERVER:
//!
//! - listing is its own permission: a role allowed to use a secret lists
//!   nothing until a policy lets it list;
//! - a listing answers only what the role may list, and a description one
//!   secret, by path or this organization's RRN;
//! - both are believed only from the session's device, at its fence, while
//!   it is live, exactly as a lease is;
//! - neither ever carries a value, and each is recorded.

use std::time::Duration;

use bson::{doc, oid::ObjectId};
use futures::StreamExt;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use crate::vault_lease_tests::{
    Device, RUNS_HIVE, TAKES_LEASES, device, fresh_kek, post, rows, seed_vault, send, start,
};

async fn meta_app() -> TestApp {
    let kek = fresh_kek();
    TestApp::spawn_with_settings(move |s| {
        s.modules.hive = true;
        s.modules.vault = true;
        s.vault.kek = kek;
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await
}

/// `dev` may list what is under `db/`, as `seed_vault` lets it use it.
async fn let_dev_list_db(app: &TestApp, t: &SeededTenant) {
    let text = format!(
        r#"permit (principal in MeshHarbor::Role::"dev", action == MeshHarbor::Action::"secret:list", resource in MeshHarbor::SecretFolder::"rrn:{}:secret:db");"#,
        t.tenant_slug
    );
    let (code, body) = post(
        app,
        t,
        "/vault/policy",
        json!({ "name": "dev-lists-db", "text": text }),
    )
    .await;
    assert_eq!(code, 201, "{body}");
}

/// Send `frame` (`t` set) and wait for the vault's answer naming `req_id`.
async fn answer(dev: &mut Device, req_id: &str, mut frame: Value) -> Value {
    frame["req_id"] = json!(req_id);
    send(&mut dev.ws, frame).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let next = tokio::time::timeout(left, dev.ws.next())
            .await
            .expect("no answer within 10 s")
            .expect("agent socket closed")
            .expect("agent socket error");
        if let Message::Text(text) = next {
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            let t = v["t"].as_str().unwrap_or_default();
            if t.starts_with("rc:vault.") && v["req_id"] == req_id {
                return v;
            }
        }
    }
}

fn paths(listed: &Value) -> Vec<String> {
    assert_eq!(listed["t"], "rc:vault.listed", "{listed}");
    let mut p: Vec<String> = listed["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["path"].as_str().unwrap().to_string())
        .collect();
    p.sort();
    p
}

/// FR-90 P3-4b — a session lists what its role may list, and only that; a
/// use permit alone lists nothing; a description answers one secret by path
/// or RRN, and nothing carries a value.
#[tokio::test]
async fn a_session_lists_and_describes_what_its_role_may_list() {
    let app = meta_app().await;
    let t = app.seed_tenant("meta-list").await;
    let value = seed_vault(&app, &t).await;
    let mut dev = device(&app, &t, "meta-dev", "linux", TAKES_LEASES, true).await;
    let (sid, fence) = start(&app, &t, &mut dev, "/srv/m", Some("dev")).await;
    let list = |prefix: &str| {
        let mut f = json!({ "t": "rc:vault.list", "session_id": sid, "fence": fence });
        if !prefix.is_empty() {
            f["prefix"] = json!(prefix);
        }
        f
    };

    // A use permit lists nothing.
    let a = answer(&mut dev, "l0", list("")).await;
    assert_eq!(paths(&a), Vec::<String>::new(), "{a}");

    let_dev_list_db(&app, &t).await;
    let a = answer(&mut dev, "l1", list("")).await;
    assert_eq!(paths(&a), ["db/main", "db/off"], "{a}");
    assert!(a.get("more").is_none(), "{a}");
    let off = a["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["path"] == "db/off")
        .unwrap();
    assert_eq!(off["disabled"], true, "{off}");
    assert!(
        !a.to_string().contains(&value),
        "a listing never carries a value"
    );
    let a = answer(&mut dev, "l2", list("api/")).await;
    assert_eq!(paths(&a), Vec::<String>::new(), "{a}");

    let describe = |secret: &str| json!({ "t": "rc:vault.describe", "session_id": sid, "fence": fence, "secret": secret });
    let d = answer(&mut dev, "d1", describe("db/main")).await;
    assert_eq!(d["t"], "rc:vault.described", "{d}");
    let rrn = format!("rrn:{}:secret:db/main", t.tenant_slug);
    assert_eq!(d["secret"]["rrn"], rrn.as_str());
    assert_eq!(d["secret"]["fields"], json!(["value"]));
    assert!(
        !d.to_string().contains(&value),
        "a description never carries a value"
    );
    let d = answer(&mut dev, "d2", describe(&rrn)).await;
    assert_eq!(d["secret"]["path"], "db/main", "{d}");
    for (secret, word) in [
        ("api/key", "denied"),
        ("db/nope", "no_secret"),
        ("rrn:another-org:secret:db/main", "no_secret"),
    ] {
        let d = answer(&mut dev, &format!("x-{secret}"), describe(secret)).await;
        assert_eq!(d["t"], "rc:vault.refused", "{secret}: {d}");
        assert_eq!(d["reason"], word, "{secret}: {d}");
    }

    let tid = ObjectId::parse_str(&t.tenant_id).unwrap();
    let listings = rows(&app, "vault_audit", doc! { "tenant_id": tid, "op": "list" }).await;
    assert_eq!(listings.len(), 3, "one row a listing: {listings:?}");
    assert!(
        listings
            .iter()
            .all(|r| r.get_str("action").unwrap() == "secret:list")
    );
    assert!(
        listings.iter().all(|r| !r.contains_key("request")),
        "an aggregate is not replayable"
    );
    let described = rows(
        &app,
        "vault_audit",
        doc! { "tenant_id": tid, "op": "describe" },
    )
    .await;
    let decisions: Vec<&str> = described
        .iter()
        .filter(|r| r.contains_key("request"))
        .map(|r| r.get_str("decision").unwrap())
        .collect();
    assert_eq!(decisions, ["allow", "allow", "deny"], "{described:?}");
}

/// A listing and a description are believed as a lease is: only from the
/// device the session's record places it on, at its fence, while it is live,
/// from a connection that takes leases.
#[tokio::test]
async fn a_listing_is_believed_only_from_the_sessions_device() {
    let app = meta_app().await;
    let t = app.seed_tenant("meta-who").await;
    app.db
        .collection::<bson::Document>("tenants")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&t.tenant_id).unwrap() },
            doc! { "$set": { "plan": "pro" } },
        )
        .await
        .unwrap();
    seed_vault(&app, &t).await;
    let_dev_list_db(&app, &t).await;
    let mut dev = device(&app, &t, "meta-a", "linux", TAKES_LEASES, true).await;
    let mut other = device(&app, &t, "meta-b", "linux", TAKES_LEASES, true).await;
    let mut older = device(&app, &t, "meta-c", "linux", RUNS_HIVE, false).await;
    let (sid, fence) = start(&app, &t, &mut dev, "/srv/w", Some("dev")).await;
    let list = |f: u64| json!({ "t": "rc:vault.list", "session_id": sid, "fence": f });

    let a = answer(&mut other, "w1", list(fence)).await;
    assert_eq!(
        (a["t"].as_str(), a["reason"].as_str()),
        (Some("rc:vault.refused"), Some("not_located")),
        "{a}"
    );
    let a = answer(&mut older, "w2", list(fence)).await;
    assert_eq!(a["reason"], "unsupported", "{a}");
    let a = answer(&mut dev, "w3", list(fence + 1)).await;
    assert_eq!(a["reason"], "stale_fence", "{a}");
    let a = answer(&mut dev, "w4", list(fence)).await;
    assert_eq!(paths(&a), ["db/main", "db/off"]);
    app.db
        .collection::<bson::Document>("agent_sessions")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&sid).unwrap() },
            doc! { "$set": { "status": "ended" } },
        )
        .await
        .unwrap();
    let a = answer(&mut dev, "w5", list(fence)).await;
    assert_eq!(a["reason"], "ended", "{a}");
    let d = answer(
        &mut dev,
        "w6",
        json!({ "t": "rc:vault.describe", "session_id": sid, "fence": fence, "secret": "db/main" }),
    )
    .await;
    assert_eq!(d["reason"], "ended", "{d}");
}
