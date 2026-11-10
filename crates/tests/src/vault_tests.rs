// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-1 — the vault, the server side: the store, its KEK, its gates.
//!
//! What these lock: the module is off until turned on, and a `vault.tenants`
//! list both turns it on and keeps every other organization out; only an
//! organization's administrators reach its vault, and every decision is
//! recorded, allow and deny; a value goes in and NO answer carries it out;
//! what is stored is ciphertext bound to its place, so a value moved from
//! one version to another, or held to another KEK, does not open; without a
//! KEK the vault declares secrets and never seals; deleting a secret takes
//! its values with it.

use age::secrecy::ExposeSecret;
use bson::{Bson, Document, doc, oid::ObjectId};
use serde_json::{Value, json};

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;

/// A KEK made for the test, never written down.
fn fresh_kek() -> String {
    age::x25519::Identity::generate()
        .to_string()
        .expose_secret()
        .to_string()
}

async fn vault_app(kek: Option<String>) -> TestApp {
    TestApp::spawn_with_settings(move |s| {
        s.modules.vault = true;
        if let Some(k) = kek {
            s.vault.kek = k;
        }
        // Many calls per test: the default limiter would answer 429 first.
        s.app.rate_limit_per_sec = 100;
        s.app.rate_limit_burst = 1000;
    })
    .await
}

fn vpath(tid: &str, rest: &str) -> String {
    format!("/api/tenant/{tid}/vault{rest}")
}

/// Status, the raw body (to search it for a value), and the body as JSON.
async fn call(req: reqwest::RequestBuilder) -> (u16, String, Value) {
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let json = serde_json::from_str(&text).unwrap_or(Value::Null);
    (status, text, json)
}

fn patch(app: &TestApp, path: &str, token: &str) -> reqwest::RequestBuilder {
    app.client
        .patch(app.url(path))
        .header("Authorization", format!("Bearer {token}"))
}

async fn create(app: &TestApp, t: &SeededTenant, body: Value) -> (u16, String, Value) {
    call(
        app.auth_post(&vpath(&t.tenant_id, "/secret"), &t.admin.access_token)
            .json(&body),
    )
    .await
}

async fn put_value(app: &TestApp, t: &SeededTenant, id: &str, body: Value) -> (u16, String, Value) {
    call(
        app.auth_put(
            &vpath(&t.tenant_id, &format!("/secret/{id}/value")),
            &t.admin.access_token,
        )
        .json(&body),
    )
    .await
}

fn oid(v: &Value) -> ObjectId {
    ObjectId::parse_str(v.as_str().unwrap()).unwrap()
}

async fn audit_rows(app: &TestApp, filter: Document) -> Vec<Document> {
    use futures::TryStreamExt;
    app.db
        .collection::<Document>("vault_audit")
        .find(filter)
        .sort(doc! { "at": 1, "_id": 1 })
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap()
}

/// The module ships off: no route, and the server says it is switched off.
#[tokio::test]
async fn the_vault_is_off_until_turned_on() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("vaultoff").await;
    let (code, _, _) = call(app.auth_get(&vpath(&t.tenant_id, ""), &t.admin.access_token)).await;
    assert_eq!(code, 404, "not mounted ⇒ no route");
    let caps: Value = app
        .client
        .get(app.url("/api/capabilities"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let listed = |key: &str| caps[key].as_array().unwrap().iter().any(|m| m == "vault");
    assert!(!listed("modules") && listed("switched_off"), "{caps}");
}

/// `vault.tenants` set: the list alone mounts the module, its organizations
/// get the vault, any other is answered as if it were not there, and
/// someone outside an organization learns nothing about whether it is
/// served.
#[tokio::test]
async fn an_organization_the_vault_does_not_serve_sees_none_of_it() {
    let first = vault_app(None).await;
    let a = first.seed_tenant("vaultserved").await;
    let b = first.seed_tenant("vaultunserved").await;
    let db = first.db.name().to_string();
    let only_a = a.tenant_id.clone();
    let app = TestApp::spawn_with_settings(move |s| {
        s.database.name = db;
        s.vault.tenants = only_a;
    })
    .await;

    let (code, _, body) = call(app.auth_get(&vpath(&a.tenant_id, ""), &a.admin.access_token)).await;
    assert_eq!(
        (code, body["enabled"].clone()),
        (200, json!(true)),
        "{body}"
    );

    for (path, what) in [("", "status"), ("/secret", "list"), ("/audit", "audit")] {
        let (code, _, body) =
            call(app.auth_get(&vpath(&b.tenant_id, path), &b.admin.access_token)).await;
        assert_eq!(code, 404, "{what}: {body}");
        assert!(
            body["message"]
                .as_str()
                .unwrap_or("")
                .contains("not available"),
            "{what}: {body}"
        );
    }
    let (code, _, _) = create(&app, &b, json!({ "path": "db", "kind": "static" })).await;
    assert_eq!(code, 404, "no secret for an unserved org");

    let caps: Value = app
        .client
        .get(app.url("/api/capabilities"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let listed = |key: &str| caps[key].as_array().unwrap().iter().any(|m| m == "vault");
    assert!(listed("modules") && !listed("switched_off"), "{caps}");

    // Outside A: the answer is about membership, never about the gate.
    let (code, _, body) = call(app.auth_get(&vpath(&a.tenant_id, ""), &b.admin.access_token)).await;
    assert_eq!(
        (code, body["error"].clone()),
        (403, json!("not_a_member")),
        "{body}"
    );
}

/// A member who is not an administrator reaches nothing, and every `secret:*`
/// and `vault:verify` refusal is recorded with the reason.
#[tokio::test]
async fn only_an_organizations_administrators_reach_its_vault() {
    let app = vault_app(Some(fresh_kek())).await;
    let t = app.seed_tenant("vaultgate").await;
    let (code, _, s) = create(&app, &t, json!({ "path": "db", "kind": "static" })).await;
    assert_eq!(code, 201, "{s}");
    let id = s["id"].as_str().unwrap().to_string();
    let m = &t.member.access_token;
    let tid = &t.tenant_id;

    let tries = [
        ("status", app.auth_get(&vpath(tid, ""), m)),
        ("list", app.auth_get(&vpath(tid, "/secret"), m)),
        (
            "create",
            app.auth_post(&vpath(tid, "/secret"), m)
                .json(&json!({ "path": "mine", "kind": "static" })),
        ),
        (
            "describe",
            app.auth_get(&vpath(tid, &format!("/secret/{id}")), m),
        ),
        (
            "update",
            patch(&app, &vpath(tid, &format!("/secret/{id}")), m)
                .json(&json!({ "description": "x" })),
        ),
        (
            "value",
            app.auth_put(&vpath(tid, &format!("/secret/{id}/value")), m)
                .json(&json!({ "value": "nope" })),
        ),
        (
            "delete",
            app.auth_delete(&vpath(tid, &format!("/secret/{id}")), m),
        ),
        ("verify", app.auth_post(&vpath(tid, "/verify"), m)),
        ("audit", app.auth_get(&vpath(tid, "/audit"), m)),
    ];
    for (what, req) in tries {
        let (code, _, body) = call(req).await;
        assert_eq!(code, 403, "{what}: {body}");
        assert_ne!(body["error"], json!("not_a_member"), "{what}: {body}");
    }

    // The decisions are recorded; the status and the audit reads are not
    // decisions about a secret.
    let member = ObjectId::parse_str(&t.member.id).unwrap();
    let denied = audit_rows(&app, doc! { "user_id": member }).await;
    let ops: Vec<&str> = denied.iter().map(|d| d.get_str("op").unwrap()).collect();
    assert_eq!(
        ops,
        [
            "list", "create", "describe", "update", "value", "delete", "verify"
        ],
        "{denied:?}"
    );
    for d in &denied {
        assert_eq!(d.get_str("decision").unwrap(), "deny");
        assert_eq!(d.get_str("reason").unwrap(), "not_administrator");
        assert_eq!(d.get_str("principal").unwrap(), "user");
    }
    // Nothing the member asked was done.
    let s = app
        .db
        .collection::<Document>("vault_secrets")
        .find_one(doc! { "_id": oid(&json!(id)) })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s.get("deleted_at"), Some(&Bson::Null));
    assert_eq!(s.get_str("description").unwrap(), "");
    let count = app
        .db
        .collection::<Document>("vault_versions")
        .count_documents(doc! {})
        .await
        .unwrap();
    assert_eq!(count, 0);
}

/// The whole round: declare, write two versions, list, describe, verify —
/// and the value is in no answer, nor in what the database holds in clear.
#[tokio::test]
async fn a_secret_round_trip_never_answers_its_value() {
    let app = vault_app(Some(fresh_kek())).await;
    let t = app.seed_tenant("vaultround").await;
    let first = format!("hunter2-{}", ObjectId::new().to_hex());
    let second = format!("correct-horse-{}", ObjectId::new().to_hex());
    let mut answers = Vec::new();

    let (code, text, s) = create(
        &app,
        &t,
        json!({
            "path": "staging/db",
            "kind": "static",
            "description": "the staging database",
            "audiences": ["db.staging.internal:5432"],
            "exec_allow": ["psql"],
            "tags": ["staging"],
            "rotation_days": 90,
        }),
    )
    .await;
    assert_eq!(code, 201, "{text}");
    answers.push(text);
    assert_eq!(
        s["rrn"],
        json!(format!("rrn:{}:secret:staging/db", t.tenant_slug))
    );
    assert_eq!(s["fields"], json!([]), "no value yet");
    let id = s["id"].as_str().unwrap().to_string();

    for (value, n) in [(&first, 1), (&second, 2)] {
        let (code, text, body) = put_value(&app, &t, &id, json!({ "value": value })).await;
        assert_eq!(code, 200, "{text}");
        assert_eq!(
            (body["field"].clone(), body["n"].clone()),
            (json!("value"), json!(n))
        );
        answers.push(text);
    }

    let (code, text, status) =
        call(app.auth_get(&vpath(&t.tenant_id, ""), &t.admin.access_token)).await;
    assert_eq!(code, 200, "{text}");
    let recipient = status["kek"]["recipient"].as_str().unwrap().to_string();
    assert_eq!(status["kek"]["state"], json!("ready"));
    assert!(recipient.starts_with("age1"), "{status}");
    assert_eq!(
        (
            status["secrets"].clone(),
            status["versions"].clone(),
            status["other_kek"].clone()
        ),
        (json!(1), json!(2), json!(0)),
        "{status}"
    );
    answers.push(text);

    let (code, text, list) =
        call(app.auth_get(&vpath(&t.tenant_id, "/secret"), &t.admin.access_token)).await;
    assert_eq!(code, 200, "{text}");
    assert_eq!(list.as_array().unwrap().len(), 1, "{list}");
    assert_eq!(
        list[0]["fields"],
        json!([{ "name": "value", "current": 2, "updated_at": list[0]["fields"][0]["updated_at"] }])
    );
    answers.push(text);

    let (code, text, d) = call(app.auth_get(
        &vpath(&t.tenant_id, &format!("/secret/{id}")),
        &t.admin.access_token,
    ))
    .await;
    assert_eq!(code, 200, "{text}");
    let versions = d["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 2, "{d}");
    assert_eq!(
        (versions[0]["n"].clone(), versions[0]["current"].clone()),
        (json!(2), json!(true))
    );
    assert_eq!(
        (versions[1]["n"].clone(), versions[1]["current"].clone()),
        (json!(1), json!(false))
    );
    for v in versions {
        assert_eq!(v["kek"], json!(recipient));
        assert!(
            v.get("ciphertext").is_none() && v.get("dek_wrapped").is_none(),
            "{v}"
        );
    }
    assert_eq!(d["exec_allow"], json!(["psql"]));
    answers.push(text);

    let (code, text, verify) =
        call(app.auth_post(&vpath(&t.tenant_id, "/verify"), &t.admin.access_token)).await;
    assert_eq!(code, 200, "{text}");
    assert_eq!(
        (
            verify["versions"].clone(),
            verify["ok"].clone(),
            verify["failed"].clone()
        ),
        (json!(2), json!(2), json!(0)),
        "{verify}"
    );
    answers.push(text);

    let (code, text, audit) =
        call(app.auth_get(&vpath(&t.tenant_id, "/audit"), &t.admin.access_token)).await;
    assert_eq!(code, 200, "{text}");
    answers.push(text);

    // No answer carries a value.
    for a in &answers {
        assert!(
            !a.contains(&first) && !a.contains(&second),
            "a value leaked: {a}"
        );
    }

    // The database holds ciphertext, bound to the KEK it names.
    let rows: Vec<Document> = {
        use futures::TryStreamExt;
        app.db
            .collection::<Document>("vault_versions")
            .find(doc! { "secret_id": oid(&json!(id)) })
            .await
            .unwrap()
            .try_collect()
            .await
            .unwrap()
    };
    assert_eq!(rows.len(), 2);
    for r in &rows {
        assert_eq!(r.get_str("kek").unwrap(), recipient);
        for f in ["ciphertext", "nonce", "dek_wrapped"] {
            let Some(Bson::Binary(b)) = r.get(f) else {
                panic!("{f} is not binary: {r:?}");
            };
            for v in [&first, &second] {
                assert!(!b.bytes.windows(v.len()).any(|w| w == v.as_bytes()), "{f}");
            }
        }
    }

    // Every allow was recorded, with what it allowed, newest first.
    let ops: Vec<(String, Value)> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["op"].as_str().unwrap().to_string(), e["n"].clone()))
        .collect();
    assert_eq!(
        ops,
        [
            ("verify".to_string(), Value::Null),
            ("describe".to_string(), Value::Null),
            ("list".to_string(), Value::Null),
            ("value".to_string(), json!(2)),
            ("value".to_string(), json!(1)),
            ("create".to_string(), Value::Null),
        ],
        "{audit}"
    );
    for e in audit.as_array().unwrap() {
        assert_eq!(e["decision"], json!("allow"), "{e}");
        assert_eq!(e["reason"], json!("administrator"), "{e}");
    }
    assert_eq!(audit[0]["rrn"], Value::Null, "verify names no secret");
    assert_eq!(
        audit[3]["rrn"],
        json!(format!("rrn:{}:secret:staging/db", t.tenant_slug))
    );
}

/// Whoever writes the database can move sealed bytes between rows; they do
/// not open where they were moved to. And a version wrapped to another KEK
/// says so.
#[tokio::test]
async fn a_value_moved_or_held_to_another_kek_does_not_open() {
    let app = vault_app(Some(fresh_kek())).await;
    let t = app.seed_tenant("vaultmoved").await;
    let (_, _, s) = create(&app, &t, json!({ "path": "db", "kind": "static" })).await;
    let id = s["id"].as_str().unwrap().to_string();
    let (_, _, s2) = create(&app, &t, json!({ "path": "other", "kind": "static" })).await;
    let id2 = s2["id"].as_str().unwrap().to_string();
    for v in ["one", "two"] {
        let (code, text, _) = put_value(&app, &t, &id, json!({ "value": v })).await;
        assert_eq!(code, 200, "{text}");
    }
    let (code, text, _) = put_value(&app, &t, &id2, json!({ "value": "three" })).await;
    assert_eq!(code, 200, "{text}");

    let coll = app.db.collection::<Document>("vault_versions");
    let sid = oid(&json!(id));
    let v1 = coll
        .find_one(doc! { "secret_id": sid, "n": 1_i64 })
        .await
        .unwrap()
        .unwrap();
    let v2 = coll
        .find_one(doc! { "secret_id": sid, "n": 2_i64 })
        .await
        .unwrap()
        .unwrap();
    // Swap the sealed payloads, whole, between versions 1 and 2.
    for (from, to) in [(&v1, &v2), (&v2, &v1)] {
        let mut set = Document::new();
        for f in ["ciphertext", "nonce", "dek_wrapped"] {
            set.insert(f, from.get(f).unwrap().clone());
        }
        coll.update_one(
            doc! { "_id": to.get_object_id("_id").unwrap() },
            doc! { "$set": set },
        )
        .await
        .unwrap();
    }
    // And re-label the other secret's version as another KEK's.
    let other = age::x25519::Identity::generate().to_public().to_string();
    coll.update_one(
        doc! { "secret_id": oid(&json!(id2)) },
        doc! { "$set": { "kek": &other } },
    )
    .await
    .unwrap();

    let (code, text, verify) =
        call(app.auth_post(&vpath(&t.tenant_id, "/verify"), &t.admin.access_token)).await;
    assert_eq!(code, 200, "{text}");
    assert_eq!(
        (
            verify["versions"].clone(),
            verify["ok"].clone(),
            verify["failed"].clone()
        ),
        (json!(3), json!(0), json!(3)),
        "{verify}"
    );
    let mut reasons: Vec<(String, i64, String)> = verify["failures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["secret_id"].as_str().unwrap().to_string(),
                f["n"].as_i64().unwrap(),
                f["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    reasons.sort();
    let mut want = vec![
        (id.clone(), 1, "tampered".to_string()),
        (id.clone(), 2, "tampered".to_string()),
        (id2.clone(), 1, "other_kek".to_string()),
    ];
    want.sort();
    assert_eq!(reasons, want, "{verify}");

    let (_, _, status) = call(app.auth_get(&vpath(&t.tenant_id, ""), &t.admin.access_token)).await;
    assert_eq!(status["other_kek"], json!(1), "{status}");
}

/// No KEK: secrets are declared, nothing is sealed, and the routes that need
/// the key say why. An unusable KEK is said too — never echoed.
#[tokio::test]
async fn without_a_kek_the_vault_declares_but_never_seals() {
    let app = vault_app(None).await;
    let t = app.seed_tenant("vaultnokek").await;
    let (code, _, status) =
        call(app.auth_get(&vpath(&t.tenant_id, ""), &t.admin.access_token)).await;
    assert_eq!(code, 200);
    assert_eq!(status["kek"], json!({ "state": "missing" }), "{status}");
    assert_eq!(status["other_kek"], Value::Null);

    let (code, text, s) = create(&app, &t, json!({ "path": "db", "kind": "static" })).await;
    assert_eq!(code, 201, "{text}");
    let id = s["id"].as_str().unwrap().to_string();
    let (code, _, body) = put_value(&app, &t, &id, json!({ "value": "hunter2" })).await;
    assert_eq!(code, 503, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("key-encryption key"),
        "{body}"
    );
    let (code, _, body) =
        call(app.auth_post(&vpath(&t.tenant_id, "/verify"), &t.admin.access_token)).await;
    assert_eq!(code, 503, "{body}");
    let versions = app
        .db
        .collection::<Document>("vault_versions")
        .count_documents(doc! {})
        .await
        .unwrap();
    assert_eq!(versions, 0);
    // A refused-for-want-of-a-key write is not an allow acted on.
    let values = audit_rows(&app, doc! { "op": "value" }).await;
    assert!(values.is_empty(), "{values:?}");

    // An unusable KEK: the state says why, in the vault's words.
    let db = app.db.name().to_string();
    let bad = TestApp::spawn_with_settings(move |s| {
        s.database.name = db;
        s.modules.vault = true;
        s.vault.kek = "not-an-age-identity".into();
    })
    .await;
    let (code, text, status) =
        call(bad.auth_get(&vpath(&t.tenant_id, ""), &t.admin.access_token)).await;
    assert_eq!(code, 200, "{text}");
    assert_eq!(status["kek"]["state"], json!("invalid"), "{status}");
    assert!(!text.contains("not-an-age-identity"), "{text}");
}

/// Deleting a secret destroys its values, frees its path, and acts once.
#[tokio::test]
async fn a_deleted_secret_takes_its_values_with_it() {
    let app = vault_app(Some(fresh_kek())).await;
    let t = app.seed_tenant("vaultdelete").await;
    let (_, _, s) = create(&app, &t, json!({ "path": "prod/api", "kind": "static" })).await;
    let id = s["id"].as_str().unwrap().to_string();
    for v in ["one", "two"] {
        put_value(&app, &t, &id, json!({ "value": v })).await;
    }
    let one = vpath(&t.tenant_id, &format!("/secret/{id}"));
    let (code, text, body) = call(app.auth_delete(&one, &t.admin.access_token)).await;
    assert_eq!(code, 200, "{text}");
    assert_eq!(
        body,
        json!({ "deleted": true, "versions_destroyed": 2 }),
        "{body}"
    );
    let versions = app
        .db
        .collection::<Document>("vault_versions")
        .count_documents(doc! { "secret_id": oid(&json!(id)) })
        .await
        .unwrap();
    assert_eq!(versions, 0, "the values are gone");
    let row = app
        .db
        .collection::<Document>("vault_secrets")
        .find_one(doc! { "_id": oid(&json!(id)) })
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(row.get("deleted_at"), Some(Bson::DateTime(_))),
        "a tombstone"
    );

    for req in [
        app.auth_get(&one, &t.admin.access_token),
        app.auth_delete(&one, &t.admin.access_token),
        app.auth_put(&format!("{one}/value"), &t.admin.access_token)
            .json(&json!({ "value": "back" })),
    ] {
        let (code, _, body) = call(req).await;
        assert_eq!(code, 404, "{body}");
    }
    let (_, _, list) =
        call(app.auth_get(&vpath(&t.tenant_id, "/secret"), &t.admin.access_token)).await;
    assert_eq!(list, json!([]));

    // The path is free; the new secret is a new one.
    let (code, text, again) =
        create(&app, &t, json!({ "path": "prod/api", "kind": "static" })).await;
    assert_eq!(code, 201, "{text}");
    assert_ne!(again["id"], json!(id));
}

/// One live secret per path, one spelling per name, a kind's fields, and the
/// one way a value gets in.
#[tokio::test]
async fn names_kinds_and_fields_are_held_to_their_rules() {
    let app = vault_app(Some(fresh_kek())).await;
    let t = app.seed_tenant("vaultrules").await;
    let (code, _, s) = create(&app, &t, json!({ "path": "prod/api", "kind": "static" })).await;
    assert_eq!(code, 201);
    let id = s["id"].as_str().unwrap().to_string();

    let (code, _, body) = create(&app, &t, json!({ "path": "prod/api", "kind": "static" })).await;
    assert_eq!(code, 409, "{body}");
    for bad in [
        json!({ "path": "Prod/api", "kind": "static" }),
        json!({ "path": "prod//api", "kind": "static" }),
        json!({ "path": "../api", "kind": "static" }),
        json!({ "path": "api", "kind": "dynamic" }),
        json!({ "path": "api", "kind": "static", "tags": ["Prod"] }),
        json!({ "path": "api", "kind": "static", "audiences": ["a b"] }),
        json!({ "path": "api", "kind": "static", "exec_allow": ["psql", "psql"] }),
        // P3-4c — a program by its bare name: a path could only ever allow
        // nothing.
        json!({ "path": "api", "kind": "static", "exec_allow": ["/usr/bin/psql"] }),
        json!({ "path": "api", "kind": "static", "exec_allow": ["-rf"] }),
        json!({ "path": "api", "kind": "static", "rotation_days": 0 }),
        json!({ "path": "api", "kind": "static", "owner_id": ObjectId::new().to_hex() }),
    ] {
        let (code, _, body) = create(&app, &t, bad.clone()).await;
        assert_eq!(code, 400, "{bad} → {body}");
    }
    // A value has one way in: not here.
    let (code, _, _) = create(
        &app,
        &t,
        json!({ "path": "api", "kind": "static", "value": "hunter2" }),
    )
    .await;
    assert_eq!(code, 422);

    // A static secret has one field.
    let (code, _, body) =
        put_value(&app, &t, &id, json!({ "field": "password", "value": "x" })).await;
    assert_eq!(code, 400, "{body}");
    for bad in [
        json!({ "value": "" }),
        json!({ "value": "x", "expires_at": "2001-01-01T00:00:00Z" }),
        json!({ "value": "x", "expires_at": "tomorrow" }),
    ] {
        let (code, _, body) = put_value(&app, &t, &id, bad.clone()).await;
        assert_eq!(code, 400, "{bad} → {body}");
    }
    let (code, _, body) =
        put_value(&app, &t, &id, json!({ "value": "x".repeat(64 * 1024 + 1) })).await;
    assert_eq!(code, 400, "{body}");

    // A structured secret's named fields, each counting on its own.
    let (_, _, db) = create(&app, &t, json!({ "path": "prod/db", "kind": "structured" })).await;
    let db_id = db["id"].as_str().unwrap().to_string();
    for (field, n) in [("username", 1), ("password", 1), ("password", 2)] {
        let (code, text, body) =
            put_value(&app, &t, &db_id, json!({ "field": field, "value": "v" })).await;
        assert_eq!(code, 200, "{text}");
        assert_eq!(body["n"], json!(n), "{field}");
    }
    for bad in ["a.b", "$set", "Password"] {
        let (code, _, body) =
            put_value(&app, &t, &db_id, json!({ "field": bad, "value": "v" })).await;
        assert_eq!(code, 400, "{bad} → {body}");
    }
    let (_, _, d) = call(app.auth_get(
        &vpath(&t.tenant_id, &format!("/secret/{db_id}")),
        &t.admin.access_token,
    ))
    .await;
    let names: Vec<&str> = d["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["password", "username"], "{d}");
}

/// A field keeps its last ten versions; an older value is destroyed.
#[tokio::test]
async fn a_field_keeps_its_last_ten_versions() {
    let app = vault_app(Some(fresh_kek())).await;
    let t = app.seed_tenant("vaultkeep").await;
    let (_, _, s) = create(&app, &t, json!({ "path": "rotating", "kind": "static" })).await;
    let id = s["id"].as_str().unwrap().to_string();
    for i in 1..=12 {
        let (code, text, _) = put_value(&app, &t, &id, json!({ "value": format!("v{i}") })).await;
        assert_eq!(code, 200, "{text}");
    }
    let (_, _, d) = call(app.auth_get(
        &vpath(&t.tenant_id, &format!("/secret/{id}")),
        &t.admin.access_token,
    ))
    .await;
    let ns: Vec<i64> = d["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["n"].as_i64().unwrap())
        .collect();
    assert_eq!(ns, (3..=12).rev().collect::<Vec<i64>>(), "{d}");
    let (_, _, verify) =
        call(app.auth_post(&vpath(&t.tenant_id, "/verify"), &t.admin.access_token)).await;
    assert_eq!(
        (verify["versions"].clone(), verify["ok"].clone()),
        (json!(10), json!(10)),
        "{verify}"
    );
}

/// The rules change; the name and the kind never do.
#[tokio::test]
async fn patch_changes_the_rules_never_the_name() {
    let app = vault_app(Some(fresh_kek())).await;
    let t = app.seed_tenant("vaultpatch").await;
    let (_, _, s) = create(&app, &t, json!({ "path": "svc", "kind": "static" })).await;
    let one = vpath(
        &t.tenant_id,
        &format!("/secret/{}", s["id"].as_str().unwrap()),
    );
    let tok = &t.admin.access_token;

    let (code, text, body) = call(patch(&app, &one, tok).json(&json!({
        "description": "the service's key",
        "tags": ["prod"],
        "rotation_days": 30,
        "disabled": true,
        "owner_id": t.member.id,
    })))
    .await;
    assert_eq!(code, 200, "{text}");
    assert_eq!(body["description"], json!("the service's key"));
    assert_eq!(body["tags"], json!(["prod"]));
    assert_eq!(body["rotation_days"], json!(30));
    assert_eq!(body["disabled"], json!(true));
    assert_eq!(body["owner_id"], json!(t.member.id));

    let (code, _, body) = call(patch(&app, &one, tok).json(&json!({ "rotation_days": 0 }))).await;
    assert_eq!(
        (code, body["rotation_days"].clone()),
        (200, Value::Null),
        "{body}"
    );

    for (bad, want) in [
        (json!({ "path": "renamed" }), 422),
        (json!({ "kind": "structured" }), 422),
        (json!({}), 400),
        (json!({ "owner_id": ObjectId::new().to_hex() }), 400),
    ] {
        let (code, _, body) = call(patch(&app, &one, tok).json(&bad)).await;
        assert_eq!(code, want, "{bad} → {body}");
    }
    let (_, _, d) = call(app.auth_get(&one, tok)).await;
    assert_eq!(
        (d["path"].clone(), d["kind"].clone()),
        (json!("svc"), json!("static"))
    );
}

// ─── P3-2 — roles, policies, simulate ──────────────────────────────────────

async fn post_json(
    app: &TestApp,
    t: &SeededTenant,
    rest: &str,
    body: Value,
) -> (u16, String, Value) {
    call(
        app.auth_post(&vpath(&t.tenant_id, rest), &t.admin.access_token)
            .json(&body),
    )
    .await
}

/// Roles and policies: an administrator's, each policy checked before it is
/// kept (Cedar, the schema, this organization's names only), a write from
/// the revision read, a role no live policy names the only one that goes,
/// a guardrail never edited or removed, and every write recorded.
#[tokio::test]
async fn roles_and_policies_are_checked_before_they_are_kept() {
    let app = vault_app(Some(fresh_kek())).await;
    let t = app.seed_tenant("vaultpolicy").await;
    let tok = &t.admin.access_token;

    let (code, text, role) = post_json(&app, &t, "/role", json!({ "name": "dev" })).await;
    assert_eq!(code, 201, "{text}");
    assert_eq!(role["name"], json!("dev"));
    let (code, _, _) = post_json(&app, &t, "/role", json!({ "name": "dev" })).await;
    assert_eq!(code, 409, "one live role per name");
    let (code, _, _) = post_json(&app, &t, "/role", json!({ "name": "Dev" })).await;
    assert_eq!(code, 400, "one spelling");

    let permit = format!(
        r#"permit (principal in MeshHarbor::Role::"dev", action == MeshHarbor::Action::"secret:use", resource in MeshHarbor::SecretFolder::"rrn:{}:secret:staging");"#,
        t.tenant_slug
    );
    let (code, text, p) = post_json(
        &app,
        &t,
        "/policy",
        json!({ "name": "dev-staging", "text": permit }),
    )
    .await;
    assert_eq!(code, 201, "{text}");
    assert_eq!(
        (
            p["effect"].clone(),
            p["rev"].clone(),
            p["guardrail"].clone()
        ),
        (json!("permit"), json!(1), json!(false))
    );
    let pid = p["id"].as_str().unwrap().to_string();
    assert!(pid.starts_with("policy:"), "{pid}");

    for (text, why) in [
        (
            r#"permit (principal, action == MeshHarbor::Action::"secret:use", resource in MeshHarbor::SecretFolder::"rrn:someone-else:secret:prod");"#.to_string(),
            "not this organization",
        ),
        (
            r#"permit (principal in MeshHarbor::Role::"ghost", action, resource);"#.to_string(),
            "vault roles",
        ),
        (
            "permit (principal, action, resource)".to_string(),
            "not a Cedar policy",
        ),
        (
            r#"permit (principal, action == MeshHarbor::Action::"secret:read", resource);"#.to_string(),
            "schema",
        ),
        (
            format!(
                r#"forbid (principal == MeshHarbor::User::"{}", action, resource);"#,
                ObjectId::new().to_hex()
            ),
            "not a member",
        ),
    ] {
        let (code, _, body) =
            post_json(&app, &t, "/policy", json!({ "name": "bad", "text": text })).await;
        assert_eq!(code, 400, "{text}");
        assert!(
            body["message"].as_str().unwrap_or("").contains(why),
            "{text} → {body}"
        );
    }

    // The guardrails first, then the organization's own.
    let (_, _, list) = call(app.auth_get(&vpath(&t.tenant_id, "/policy"), tok)).await;
    let ids: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            "guardrail:windows-proxy-only",
            "guardrail:prod-never-materializes",
            "guardrail:exec-only-allowed-programs",
            "guardrail:proxy-only-named-audiences",
            "guardrail:dynamic-only-short-lived",
            "guardrail:short-lived-only-dynamic",
            // P3-9-1 — a person's own three, for `secret:connect`.
            "guardrail:connect-only-named-audiences",
            "guardrail:connect-never-dynamic",
            "guardrail:connect-never-prod",
            pid.as_str()
        ],
        "{list}"
    );

    // A write from the revision read.
    let one = vpath(&t.tenant_id, &format!("/policy/{pid}"));
    let put = |rev: i64| {
        app.client
            .put(app.url(&one))
            .header("Authorization", format!("Bearer {tok}"))
            .json(&json!({
                "name": "dev-staging",
                "description": "staging, by proxy",
                "text": permit,
                "rev": rev,
            }))
    };
    let (code, _, _) = call(put(7)).await;
    assert_eq!(code, 409, "a stale revision");
    let (code, text, p2) = call(put(1)).await;
    assert_eq!(code, 200, "{text}");
    assert_eq!(p2["rev"], json!(2));

    // A guardrail is never edited or removed.
    let g = vpath(&t.tenant_id, "/policy/guardrail:windows-proxy-only");
    let (code, _, _) = call(
        app.client
            .put(app.url(&g))
            .header("Authorization", format!("Bearer {tok}"))
            .json(&json!({ "name": "x", "text": permit, "rev": 1 })),
    )
    .await;
    assert_eq!(code, 400);
    let (code, _, _) = call(app.auth_delete(&g, tok)).await;
    assert_eq!(code, 400);

    // A role a live policy names does not go; once nothing names it, it does.
    let (code, _, body) = call(app.auth_delete(&vpath(&t.tenant_id, "/role/dev"), tok)).await;
    assert_eq!(code, 409, "{body}");
    assert!(
        body["message"].as_str().unwrap().contains("dev-staging"),
        "{body}"
    );
    let (code, _, _) = call(app.auth_delete(&one, tok)).await;
    assert_eq!(code, 200);
    let (code, _, _) = call(app.auth_delete(&vpath(&t.tenant_id, "/role/dev"), tok)).await;
    assert_eq!(code, 200);

    // A member reaches none of it; every write is recorded.
    let m = &t.member.access_token;
    for req in [
        app.auth_post(&vpath(&t.tenant_id, "/role"), m)
            .json(&json!({ "name": "mine" })),
        app.auth_post(&vpath(&t.tenant_id, "/policy"), m)
            .json(&json!({ "name": "mine", "text": "permit (principal, action, resource);" })),
        app.auth_get(&vpath(&t.tenant_id, "/policy"), m),
        app.auth_get(&vpath(&t.tenant_id, "/schema"), m),
    ] {
        let (code, _, body) = call(req).await;
        assert_eq!(code, 403, "{body}");
    }
    let writes = audit_rows(&app, doc! { "action": "policy:write" }).await;
    let seen: Vec<(String, String)> = writes
        .iter()
        .map(|d| {
            (
                d.get_str("op").unwrap().to_string(),
                d.get_str("decision").unwrap().to_string(),
            )
        })
        .collect();
    for want in [
        ("role_create", "allow"),
        ("policy_create", "allow"),
        ("policy_update", "allow"),
        ("policy_delete", "allow"),
        ("role_delete", "allow"),
        ("role_create", "deny"),
        ("policy_create", "deny"),
    ] {
        assert!(
            seen.contains(&(want.0.to_string(), want.1.to_string())),
            "{want:?} not recorded: {seen:?}"
        );
    }
}

/// `simulate`: the vault's own decision for a request it is asked about —
/// which policy permitted it, which guardrail forbade it, or nothing (the
/// default deny) — and the same with a change not yet made. It records
/// nothing.
#[tokio::test]
async fn simulate_says_what_would_decide_a_request() {
    let app = vault_app(Some(fresh_kek())).await;
    let t = app.seed_tenant("vaultsim").await;
    let me = t.admin.id.clone();
    let slug = t.tenant_slug.clone();
    post_json(&app, &t, "/role", json!({ "name": "dev" })).await;
    // P3-5a — each names the upstream a proxy may present it to.
    let (_, _, staging) = create(
        &app,
        &t,
        json!({ "path": "staging/db", "kind": "static", "audiences": ["db.internal:5432"] }),
    )
    .await;
    let (_, _, prod) = create(
        &app,
        &t,
        json!({ "path": "prod/db", "kind": "static", "audiences": ["db.internal:5432"] }),
    )
    .await;
    let staging = staging["id"].as_str().unwrap().to_string();
    let prod = prod["id"].as_str().unwrap().to_string();
    let permit = format!(
        r#"permit (principal in MeshHarbor::Role::"dev", action == MeshHarbor::Action::"secret:use", resource in MeshHarbor::SecretFolder::"rrn:{slug}:secret:staging");"#
    );
    let (_, _, p) = post_json(
        &app,
        &t,
        "/policy",
        json!({ "name": "dev-staging", "text": permit }),
    )
    .await;
    let pid = p["id"].as_str().unwrap().to_string();
    let assume = r#"permit (principal in MeshHarbor::Group::"member", action == MeshHarbor::Action::"role:assume", resource == MeshHarbor::Role::"dev") when { context.device.owner == principal };"#;
    let (code, text, _) = post_json(
        &app,
        &t,
        "/policy",
        json!({ "name": "members-assume-dev-on-own", "text": assume }),
    )
    .await;
    assert_eq!(code, 201, "{text}");
    let audit_before = audit_rows(&app, doc! {}).await.len();

    let sim = |secret: &str, mode: &str, os: &str, extra: Value| {
        let mut body = json!({
            "action": "secret:use",
            "principal": { "role": "dev", "owner_id": me },
            "resource": { "secret_id": secret },
            "mode": mode,
            "audience": "db.internal:5432",
            "device": { "os": os, "tags": [], "owner_id": me },
        });
        if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                b.insert(k.clone(), v.clone());
            }
        }
        post_json(&app, &t, "/simulate", body)
    };
    let decided = |v: &Value| -> (String, Vec<String>) {
        (
            v["decision"].as_str().unwrap().to_string(),
            v["determining"]
                .as_array()
                .unwrap()
                .iter()
                .map(|d| d["id"].as_str().unwrap().to_string())
                .collect(),
        )
    };

    let (code, text, v) = sim(&staging, "proxy", "linux", json!({})).await;
    assert_eq!(code, 200, "{text}");
    assert_eq!(decided(&v), ("allow".into(), vec![pid.clone()]), "{v}");
    assert_eq!(v["determining"][0]["name"], json!("dev-staging"));

    let (_, _, v) = sim(&prod, "proxy", "linux", json!({})).await;
    assert_eq!(
        decided(&v),
        ("deny".into(), vec![]),
        "nothing permits prod: {v}"
    );

    // P3-5a — a proxy toward an upstream the secret does not name.
    let (_, _, v) = sim(
        &staging,
        "proxy",
        "linux",
        json!({ "audience": "evil.example:5432" }),
    )
    .await;
    assert_eq!(
        decided(&v),
        (
            "deny".into(),
            vec!["guardrail:proxy-only-named-audiences".into()]
        ),
        "{v}"
    );

    let (_, _, v) = sim(&staging, "env", "windows", json!({})).await;
    assert_eq!(
        decided(&v),
        ("deny".into(), vec!["guardrail:windows-proxy-only".into()]),
        "{v}"
    );

    // A change not yet made: without the permit; with a broader one.
    let (_, _, v) = sim(&staging, "proxy", "linux", json!({ "without": [pid] })).await;
    assert_eq!(decided(&v).0, "deny", "{v}");
    let everything = r#"permit (principal in MeshHarbor::Role::"dev", action == MeshHarbor::Action::"secret:use", resource);"#;
    let (_, _, v) = sim(&prod, "proxy", "linux", json!({ "with": [everything] })).await;
    assert_eq!(decided(&v), ("allow".into(), vec!["with:0".into()]), "{v}");
    let (_, _, v) = sim(&prod, "env", "linux", json!({ "with": [everything] })).await;
    assert_eq!(
        decided(&v),
        (
            "deny".into(),
            vec!["guardrail:prod-never-materializes".into()]
        ),
        "a prod value never materializes, whatever permits it: {v}"
    );
    let (code, _, _) = sim(
        &prod,
        "proxy",
        "linux",
        json!({ "without": ["guardrail:windows-proxy-only"] }),
    )
    .await;
    assert_eq!(code, 400, "a guardrail cannot be left out");

    // role:assume reads the device: the member's own, yes; another's, no.
    let member = t.member.id.clone();
    let assume_on = |owner: &str| {
        post_json(
            &app,
            &t,
            "/simulate",
            json!({
                "action": "role:assume",
                "principal": { "user_id": member },
                "resource": { "role": "dev" },
                "device": { "os": "macos", "tags": [], "owner_id": owner },
            }),
        )
    };
    let (code, text, v) = assume_on(&member).await;
    assert_eq!(code, 200, "{text}");
    assert_eq!(decided(&v).0, "allow", "{v}");
    let (_, _, v) = assume_on(&me).await;
    assert_eq!(decided(&v).0, "deny", "{v}");

    // Bad requests are refused in words, and nothing was recorded.
    for bad in [
        json!({ "action": "secret:read", "device": { "os": "linux", "owner_id": me } }),
        json!({ "action": "secret:use", "principal": { "role": "ghost", "owner_id": me }, "resource": { "secret_id": staging }, "mode": "proxy", "device": { "os": "linux", "owner_id": me } }),
        json!({ "action": "secret:use", "principal": { "role": "dev", "owner_id": me }, "resource": { "secret_id": staging }, "mode": "raw", "device": { "os": "linux", "owner_id": me } }),
        json!({ "action": "secret:use", "principal": { "role": "dev", "owner_id": me }, "resource": { "secret_id": staging }, "mode": "proxy", "device": { "os": "Windows", "owner_id": me } }),
    ] {
        let (code, _, body) = post_json(&app, &t, "/simulate", bad.clone()).await;
        assert_eq!(code, 400, "{bad} → {body}");
    }
    assert_eq!(
        audit_rows(&app, doc! {}).await.len(),
        audit_before,
        "simulate records nothing"
    );
}

/// P3-7 — a policy may name an exit by its device's id only when it is a live
/// device of this organization; `simulate` decides `net:socks` and
/// `net:forward` from the node's row, its tags included.
#[tokio::test]
async fn net_policies_name_this_organizations_exits_and_simulate_decides_them() {
    let app = vault_app(Some(fresh_kek())).await;
    let t = app.seed_tenant("vaultnet").await;
    let other = app.seed_tenant("vaultnet2").await;
    let me = t.admin.id.clone();
    post_json(&app, &t, "/role", json!({ "name": "dev" })).await;
    let (office, _) = crate::vault_lease_tests::enroll(&app, &t, "net-office", "linux").await;
    let (lab, _) = crate::vault_lease_tests::enroll(&app, &t, "net-lab", "linux").await;
    let (foreign, _) = crate::vault_lease_tests::enroll(&app, &other, "net-foreign", "linux").await;
    app.db
        .collection::<Document>("agents")
        .update_one(
            doc! { "_id": ObjectId::parse_str(&office).unwrap() },
            doc! { "$set": { "tags": ["Office"] } },
        )
        .await
        .unwrap();

    let naming = |id: &str| {
        format!(
            r#"permit (principal in MeshHarbor::Role::"dev", action == MeshHarbor::Action::"net:socks", resource == MeshHarbor::Node::"{id}");"#
        )
    };
    let (code, text, _) = post_json(
        &app,
        &t,
        "/policy",
        json!({ "name": "socks-via-office", "text": naming(&office) }),
    )
    .await;
    assert_eq!(code, 201, "{text}");
    for (id, why) in [
        (foreign.clone(), "another organization's device"),
        (ObjectId::new().to_hex(), "no device at all"),
    ] {
        let (code, text, _) = post_json(
            &app,
            &t,
            "/policy",
            json!({ "name": "socks-elsewhere", "text": naming(&id) }),
        )
        .await;
        assert_eq!(code, 400, "{why}: {text}");
        assert!(
            text.contains("is not a device of this organization"),
            "{why}: {text}"
        );
    }
    let forward = r#"permit (principal in MeshHarbor::Role::"dev", action == MeshHarbor::Action::"net:forward", resource) when { resource.tags.contains("office") && context.port == 5432 };"#;
    let (code, text, _) = post_json(
        &app,
        &t,
        "/policy",
        json!({ "name": "pg-via-office", "text": forward }),
    )
    .await;
    assert_eq!(code, 201, "{text}");

    let sim = |action: &str, node: &str, extra: Value| {
        let mut body = json!({
            "action": action,
            "principal": { "role": "dev", "owner_id": me },
            "resource": { "node_id": node },
            "device": { "os": "macos", "tags": [], "owner_id": me },
        });
        if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                b.insert(k.clone(), v.clone());
            }
        }
        post_json(&app, &t, "/simulate", body)
    };
    let decision = |v: &Value| v["decision"].as_str().unwrap_or_default().to_string();
    let (code, text, v) = sim("net:socks", &office, json!({})).await;
    assert_eq!((code, decision(&v).as_str()), (200, "allow"), "{text}");
    let (_, _, v) = sim("net:socks", &lab, json!({})).await;
    assert_eq!(decision(&v), "deny", "another exit");
    let (_, _, v) = sim(
        "net:forward",
        &office,
        json!({ "host": "db.internal", "port": 5432 }),
    )
    .await;
    assert_eq!(decision(&v), "allow", "the office's tag, read from its row");
    let (_, _, v) = sim(
        "net:forward",
        &office,
        json!({ "host": "db.internal", "port": 22 }),
    )
    .await;
    assert_eq!(decision(&v), "deny", "another port");
    let (code, text, _) = sim("net:forward", &office, json!({})).await;
    assert_eq!(code, 400, "{text}");
    let (code, text, _) = sim("net:socks", &foreign, json!({})).await;
    assert_eq!(code, 400, "{text}");
    assert!(
        text.contains("is not a device of this organization"),
        "{text}"
    );
}

/// P3-2c — a policy that can never apply is refused when it is written,
/// and as a change `simulate` is asked about: a `forbid` like that would
/// forbid nothing its writer meant it to. Nothing is stored.
#[tokio::test]
async fn a_policy_that_can_never_apply_is_refused_when_written() {
    let app = vault_app(Some(fresh_kek())).await;
    let t = app.seed_tenant("vaultnever").await;
    let me = t.admin.id.clone();
    post_json(&app, &t, "/role", json!({ "name": "dev" })).await;
    let (node, _) = crate::vault_lease_tests::enroll(&app, &t, "never-node", "linux").await;
    let never = [
        format!(
            r#"forbid (principal, action == MeshHarbor::Action::"secret:use", resource == MeshHarbor::Node::"{node}");"#
        ),
        r#"forbid (principal, action == MeshHarbor::Action::"net:socks", resource) when { false };"#
            .to_string(),
    ];
    for (i, text) in never.iter().enumerate() {
        let (code, body, _) = post_json(
            &app,
            &t,
            "/policy",
            json!({ "name": format!("never-{i}"), "text": text }),
        )
        .await;
        assert_eq!(code, 400, "{text}: {body}");
        assert!(body.contains("can never apply"), "{text}: {body}");
        let (code, body, _) = post_json(
            &app,
            &t,
            "/simulate",
            json!({
                "action": "net:socks",
                "principal": { "role": "dev", "owner_id": me },
                "resource": { "node_id": node },
                "device": { "os": "linux", "tags": [], "owner_id": me },
                "with": [text],
            }),
        )
        .await;
        assert_eq!(code, 400, "simulate with {text}: {body}");
        assert!(
            body.contains("can never apply"),
            "simulate with {text}: {body}"
        );
    }
    assert_eq!(
        app.db
            .collection::<Document>("vault_policies")
            .count_documents(doc! {})
            .await
            .unwrap(),
        0,
        "nothing was stored"
    );
    // One that can apply is kept, as before.
    let can = r#"forbid (principal, action == MeshHarbor::Action::"net:forward", resource) when { context.port == 22 };"#;
    let (code, body, _) = post_json(
        &app,
        &t,
        "/policy",
        json!({ "name": "no-ssh", "text": can }),
    )
    .await;
    assert_eq!(code, 201, "{body}");
}

/// P3-2b — `simulate/replay`: the recorded Cedar decisions, each with the
/// request it decided, decided again under a change not yet made; it
/// answers the ones that would come out the other way, counts a row it
/// cannot read, and records nothing.
#[tokio::test]
async fn a_change_is_replayed_against_the_recorded_decisions() {
    let app = vault_app(Some(fresh_kek())).await;
    let t = app.seed_tenant("vaultreplay").await;
    let me = ObjectId::parse_str(&t.admin.id).unwrap();
    let tid = ObjectId::parse_str(&t.tenant_id).unwrap();
    post_json(&app, &t, "/role", json!({ "name": "dev" })).await;
    let text = format!(
        r#"permit (principal == MeshHarbor::User::"{}", action == MeshHarbor::Action::"role:assume", resource == MeshHarbor::Role::"dev") when {{ context.device.tags.contains("build") }};"#,
        t.admin.id
    );
    let (code, body, p) = post_json(
        &app,
        &t,
        "/policy",
        json!({ "name": "dev-on-build", "text": text }),
    )
    .await;
    assert_eq!(code, 201, "{body}");
    let pid = p["id"].as_str().unwrap().to_string();

    // Two decisions as the gate records them — one allowed on a build box,
    // one denied on a laptop — and a row a later version wrote.
    let row = |decision: &str, tags: Vec<&str>| {
        doc! {
            "tenant_id": tid,
            "principal": "user",
            "user_id": me,
            "action": "role:assume",
            "op": "start",
            "decision": decision,
            "reason": "recorded",
            "target": "role:dev",
            "session_id": ObjectId::new(),
            "device_id": ObjectId::new(),
            "request": {
                "action": "role:assume",
                "user": me,
                "groups": ["owner"],
                "role": "dev",
                "device": { "os": "linux", "tags": tags, "owner": me },
            },
            "at": bson::DateTime::now(),
        }
    };
    let audit = app.db.collection::<Document>("vault_audit");
    audit.insert_one(row("allow", vec!["build"])).await.unwrap();
    audit.insert_one(row("deny", vec![])).await.unwrap();
    let mut odd = row("allow", vec![]);
    odd.insert("request", doc! { "action": "secret:read" });
    audit.insert_one(odd).await.unwrap();
    let before = audit.count_documents(doc! {}).await.unwrap();

    let replay = |body: Value| post_json(&app, &t, "/simulate/replay", body);
    let counts = |v: &Value| {
        (
            v["replayed"].as_i64().unwrap(),
            v["unreadable"].as_i64().unwrap(),
            v["flipped"].as_i64().unwrap(),
        )
    };

    // No change: nothing flips; the odd row is counted, not guessed.
    let (code, text, v) = replay(json!({})).await;
    assert_eq!(code, 200, "{text}");
    assert_eq!(counts(&v), (2, 1, 0), "{v}");

    // Without the permit, the build box's allow would be a deny.
    let (_, _, v) = replay(json!({ "without": [pid] })).await;
    assert_eq!(counts(&v), (2, 1, 1), "{v}");
    assert_eq!(
        (v["flips"][0]["was"].clone(), v["flips"][0]["now"].clone()),
        (json!("allow"), json!("deny")),
        "{v}"
    );

    // With a permit for every device, the laptop's deny would be an allow.
    let anywhere = format!(
        r#"permit (principal == MeshHarbor::User::"{}", action == MeshHarbor::Action::"role:assume", resource == MeshHarbor::Role::"dev");"#,
        t.admin.id
    );
    let (_, _, v) = replay(json!({ "with": [anywhere] })).await;
    assert_eq!(counts(&v), (2, 1, 1), "{v}");
    assert_eq!(v["flips"][0]["now"], json!("allow"), "{v}");
    assert_eq!(v["flips"][0]["determining"], json!(["with:0"]), "{v}");

    for bad in [
        json!({ "days": 8 }),
        json!({ "without": ["guardrail:windows-proxy-only"] }),
    ] {
        let (code, _, body) = replay(bad.clone()).await;
        assert_eq!(code, 400, "{bad} → {body}");
    }
    assert_eq!(
        audit.count_documents(doc! {}).await.unwrap(),
        before,
        "a replay records nothing"
    );
}
