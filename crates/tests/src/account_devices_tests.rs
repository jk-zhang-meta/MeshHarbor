// SPDX-License-Identifier: AGPL-3.0-only
//! Real account-only HTTP/Mongo directory and existing grant-ledger metadata.
//! Synthetic identities, no agent session, desktop, production host or credentials.
use crate::fixtures::test_app::TestApp;
use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use roomler_ai_db::models::{AccountApprovalState, DeviceShareGrant, DeviceSharePermissions, User};
use roomler_ai_remote_control::models::{Agent, OsKind};
use roomler_ai_services::dao::agent::AgentDao;
use serde_json::{Value, json};

struct Actor {
    id: ObjectId,
    token: String,
}
struct Fixture {
    app: TestApp,
    me: Actor,
    other: Actor,
    admin: Actor,
    pending: Actor,
}
async fn actor(
    app: &TestApp,
    name: &str,
    fixed: Option<ObjectId>,
    state: AccountApprovalState,
) -> Actor {
    let hash = app
        .state
        .auth
        .hash_password("synthetic-account-directory-password")
        .unwrap();
    let mut u = app
        .state
        .users
        .create(
            format!("{name}@directory.example.test"),
            name.into(),
            name.into(),
            hash,
            None,
        )
        .await
        .unwrap();
    let generated = u.id.unwrap();
    let id = fixed.unwrap_or(generated);
    u.id = Some(id);
    u.is_verified = true;
    u.account_approval.state = state;
    let users = app.db.collection::<User>("users");
    if generated != id {
        users.delete_one(doc! {"_id":generated}).await.unwrap();
        users.insert_one(&u).await.unwrap();
    } else {
        users.replace_one(doc! {"_id":id}, &u).await.unwrap();
    }
    let token = app
        .state
        .auth
        .generate_tokens_at_revision(id, &u.email, &u.username, 0)
        .unwrap()
        .access_token;
    Actor { id, token }
}
async fn fixture() -> Fixture {
    let bootstrap = ObjectId::new();
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.auth.account_approval.enabled = true;
        s.auth.account_approval.owner_user_id = Some(bootstrap.to_hex());
        s.stats.platform_admins = Some(admin_id.to_hex());
    })
    .await;
    actor(
        &app,
        "bootstrap",
        Some(bootstrap),
        AccountApprovalState::Approved,
    )
    .await;
    let me = actor(&app, "directory_me", None, AccountApprovalState::Approved).await;
    let other = actor(
        &app,
        "directory_other",
        None,
        AccountApprovalState::Approved,
    )
    .await;
    let admin = actor(
        &app,
        "directory_admin",
        Some(admin_id),
        AccountApprovalState::Approved,
    )
    .await;
    let pending = actor(
        &app,
        "directory_pending",
        None,
        AccountApprovalState::Pending,
    )
    .await;
    Fixture {
        app,
        me,
        other,
        admin,
        pending,
    }
}
async fn tenant(f: &Fixture, name: &str) -> ObjectId {
    f.app
        .state
        .tenants
        .create(name.into(), format!("{name}-{}", ObjectId::new()), f.me.id)
        .await
        .unwrap()
        .id
        .unwrap()
}
async fn device(f: &Fixture, tid: ObjectId, owner: ObjectId, name: &str) -> ObjectId {
    AgentDao::new(&f.app.db)
        .create(
            tid,
            owner,
            name.into(),
            ObjectId::new().to_hex(),
            OsKind::Linux,
            "directory-fixture".into(),
            "synthetic-not-real-agent-token".into(),
            None,
        )
        .await
        .unwrap()
        .id
        .unwrap()
}
async fn get(f: &Fixture, who: &Actor, path: &str) -> Value {
    let response = f.app.auth_get(path, &who.token).send().await.unwrap();
    let status = response.status().as_u16();
    let body = response.text().await.unwrap();
    assert_eq!(
        status, 200,
        "unexpected account API response at {path}: {body}"
    );
    serde_json::from_str(&body).unwrap()
}
fn ids(value: &Value) -> Vec<String> {
    value["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn account_devices_actual_owner_two_orgs_and_membership_lifecycle_filters() {
    let f = fixture().await;
    let a = tenant(&f, "own-a").await;
    let b = tenant(&f, "own-b").await;
    let one = device(&f, a, f.me.id, "registered-one").await;
    let two = device(&f, b, f.me.id, "registered-two").await;
    f.app
        .db
        .collection::<Agent>("agents")
        .update_one(
            doc! {"_id":one},
            doc! {"$set":{"display_name":"Friendly personal device"}},
        )
        .await
        .unwrap();
    f.app
        .db
        .collection::<Agent>("agents")
        .update_one(doc! {"_id":two}, doc! {"$set":{"display_name":"  "}})
        .await
        .unwrap();
    // A real org member/platform admin still cannot call someone else's device "mine".
    f.app
        .state
        .tenants
        .add_member(a, f.admin.id, vec![], None)
        .await
        .unwrap();
    f.app
        .state
        .tenants
        .add_member(a, f.other.id, vec![], None)
        .await
        .unwrap();
    device(&f, a, f.other.id, "other-owned-same-org").await;
    let pending = tenant(&f, "pending-membership").await;
    f.app
        .state
        .tenants
        .members
        .collection()
        .update_one(
            doc! {"tenant_id":pending,"user_id":f.me.id},
            doc! {"$set":{"is_pending":true}},
        )
        .await
        .unwrap();
    device(&f, pending, f.me.id, "owned-but-pending").await;
    let archived = tenant(&f, "archived-tenant").await;
    f.app
        .state
        .tenants
        .base
        .collection()
        .update_one(doc! {"_id":archived}, doc! {"$set":{"is_archived":true}})
        .await
        .unwrap();
    device(&f, archived, f.me.id, "owned-but-archived").await;
    let deleted = tenant(&f, "deleted-tenant").await;
    f.app
        .state
        .tenants
        .base
        .collection()
        .update_one(
            doc! {"_id":deleted},
            doc! {"$set":{"deleted_at":DateTime::now()}},
        )
        .await
        .unwrap();
    device(&f, deleted, f.me.id, "owned-but-tenant-deleted").await;
    let removed = tenant(&f, "removed-membership").await;
    f.app
        .state
        .tenants
        .remove_member(removed, f.me.id)
        .await
        .unwrap();
    device(&f, removed, f.me.id, "owned-but-member-removed").await;
    device(&f, ObjectId::new(), f.me.id, "owned-but-missing-tenant").await;
    let tomb = device(&f, a, f.me.id, "deleted-device").await;
    f.app
        .db
        .collection::<Agent>("agents")
        .update_one(
            doc! {"_id":tomb},
            doc! {"$set":{"deleted_at":DateTime::now()}},
        )
        .await
        .unwrap();

    let all = get(&f, &f.me, "/api/account/devices?page=1&per_page=100").await;
    let mut expected = vec![one.to_hex(), two.to_hex()];
    expected.sort();
    assert_eq!(ids(&all), expected);
    assert_eq!(all["total"], 2);
    assert_eq!(all["page"], 1);
    for item in all["items"].as_array().unwrap() {
        let keys: std::collections::BTreeSet<_> = item
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            ["id", "name", "machine_name", "os", "status", "tenant_id"]
                .into_iter()
                .collect()
        );
        if item["id"] == one.to_hex() {
            assert_eq!(item["name"], "Friendly personal device");
            assert_eq!(item["machine_name"], "registered-one");
        } else {
            assert_eq!(item["name"], "registered-two");
            assert_eq!(item["machine_name"], "registered-two");
        }
    }
    let first = get(&f, &f.me, "/api/account/devices?page=1&per_page=1").await;
    let second = get(&f, &f.me, "/api/account/devices?page=2&per_page=1").await;
    assert_eq!(first["total"], 2);
    assert_eq!(second["total"], 2);
    assert_eq!([ids(&first), ids(&second)].concat(), expected);
    assert!(ids(&get(&f, &f.me, "/api/account/devices?page=3&per_page=1").await).is_empty());
    assert_eq!(get(&f, &f.admin, "/api/account/devices").await["total"], 0);
    let other = get(&f, &f.other, "/api/account/devices").await;
    assert_eq!(other["total"], 1);
    assert!(ids(&other).iter().all(|id| !expected.contains(id)));
    assert_eq!(
        get(&f, &f.me, "/api/account/devices/summary").await["own_devices"],
        2
    );
}

async fn grant(
    f: &Fixture,
    owner: ObjectId,
    recipient: ObjectId,
    device: ObjectId,
    expires: i64,
    revoked: bool,
    created: i64,
) -> DeviceShareGrant {
    let g = DeviceShareGrant {
        id: Some(ObjectId::new()),
        device_id: device,
        tenant_id: ObjectId::new(),
        owner_user_id: owner,
        recipient_user_id: recipient,
        permissions: DeviceSharePermissions {
            ssh: true,
            ..Default::default()
        },
        tcp_ports: vec![],
        created_at: DateTime::from_millis(created),
        expires_at: DateTime::from_millis(expires),
        revoked_at: revoked.then(|| DateTime::from_millis(created)),
        revision: u32::from(revoked),
    };
    f.app
        .db
        .collection::<DeviceShareGrant>(DeviceShareGrant::COLLECTION)
        .insert_one(&g)
        .await
        .unwrap();
    g
}
#[tokio::test]
async fn account_devices_summary_distinguishes_devices_grants_and_preserves_all_history() {
    let f = fixture().await;
    let now = DateTime::now().timestamp_millis();
    let live = now + 120_000;
    let expired = now - 120_000;
    let created = now - 240_000;
    let received_device = ObjectId::new();
    let sent_device = ObjectId::new();
    let mut received = Vec::new();
    received.push(
        grant(
            &f,
            f.other.id,
            f.me.id,
            received_device,
            live,
            false,
            created,
        )
        .await,
    );
    // Time-ledger "active" is not a PDP assertion, even with a future created_at or absent agent.
    received.push(
        grant(
            &f,
            f.other.id,
            f.me.id,
            received_device,
            live,
            false,
            now + 1_000,
        )
        .await,
    );
    received.push(
        grant(
            &f,
            f.other.id,
            f.me.id,
            ObjectId::new(),
            expired,
            false,
            created,
        )
        .await,
    );
    received.push(
        grant(
            &f,
            f.other.id,
            f.me.id,
            ObjectId::new(),
            expired,
            true,
            created,
        )
        .await,
    );
    received.push(
        grant(
            &f,
            f.other.id,
            f.me.id,
            ObjectId::new(),
            live,
            true,
            created,
        )
        .await,
    );
    for _ in 0..2 {
        grant(&f, f.me.id, f.other.id, sent_device, live, false, created).await;
    }
    grant(
        &f,
        f.me.id,
        f.other.id,
        ObjectId::new(),
        expired,
        false,
        created,
    )
    .await;
    grant(
        &f,
        f.me.id,
        f.other.id,
        ObjectId::new(),
        expired,
        true,
        created,
    )
    .await;
    // An unrelated pair must not enter either direction for this account/admin.
    grant(
        &f,
        f.other.id,
        f.admin.id,
        ObjectId::new(),
        live,
        false,
        created,
    )
    .await;
    let count = f
        .app
        .db
        .collection::<DeviceShareGrant>(DeviceShareGrant::COLLECTION)
        .count_documents(doc! {})
        .await
        .unwrap();
    assert_eq!(count, 10);
    let summary = get(&f, &f.me, "/api/account/devices/summary").await;
    assert_eq!(
        summary,
        json!({"own_devices":0,"received":{"active_devices":1,"active_grants":2,"total_records":5,"expired_records":1,"revoked_records":2},"sent":{"active_devices":1,"active_grants":2,"total_records":4,"expired_records":1,"revoked_records":1}})
    );
    let history = get(
        &f,
        &f.me,
        "/api/device-shares?direction=received&page=1&per_page=100",
    )
    .await;
    assert_eq!(history["total"], 5);
    for row in history["items"].as_array().unwrap() {
        let expected = received
            .iter()
            .find(|g| g.id.unwrap().to_hex() == row["id"])
            .unwrap();
        assert_eq!(row["created_at_ms"], expected.created_at.timestamp_millis());
        assert_eq!(row["revision"], expected.revision);
        for key in [
            "id",
            "device_id",
            "owner_user_id",
            "recipient_user_id",
            "permissions",
            "tcp_ports",
            "expires_at_ms",
            "revoked_at_ms",
        ] {
            assert!(row.get(key).is_some());
        }
    }
    assert_eq!(
        f.app
            .db
            .collection::<DeviceShareGrant>(DeviceShareGrant::COLLECTION)
            .count_documents(doc! {})
            .await
            .unwrap(),
        count
    );
}

#[tokio::test]
async fn account_devices_real_url_pagination_and_approved_account_guard() {
    let f = fixture().await;
    for path in ["/api/account/devices", "/api/account/devices/summary"] {
        assert_eq!(
            f.app
                .client
                .get(f.app.url(path))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            401
        );
        assert_eq!(
            f.app
                .auth_get(path, &f.pending.token)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            403
        );
    }
    assert_eq!(
        get(&f, &f.me, "/api/account/devices?page=0&per_page=0").await,
        json!({"items":[],"page":1,"total":0})
    );
    assert_eq!(
        get(&f, &f.me, "/api/account/devices?page=1&per_page=1000").await["total"],
        0
    );
    for path in [
        "/api/account/devices?page=18446744073709551615&per_page=100",
        "/api/account/devices?page=not-a-number",
        "/api/account/devices?owner_user_id=other",
    ] {
        assert_eq!(
            f.app
                .auth_get(path, &f.me.token)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            400
        );
    }
    let s = get(&f, &f.admin, "/api/account/devices/summary").await;
    for direction in ["received", "sent"] {
        assert_eq!(
            s[direction],
            json!({"active_devices":0,"active_grants":0,"total_records":0,"expired_records":0,"revoked_records":0})
        );
    }
}

// Raw persisted-document corruption is deliberately seeded locally: this does not
// claim normal typed writers can manufacture it. The API must still fail closed.
async fn own_count(f: &Fixture, expected: u64) {
    // Two existing /api tokens replenish before the pair of real HTTP reads.
    // Do not raise limits, retry a 429 or skip any malformed-document case.
    let period_ms = f.app.state.settings.app.rate_limit_period_ms();
    assert!(
        (1..=1_000).contains(&period_ms),
        "fixture API token period out of bounds"
    );
    tokio::time::sleep(std::time::Duration::from_millis(period_ms * 2)).await;
    let page = get(f, &f.me, "/api/account/devices?per_page=1").await;
    assert_eq!(page["total"], expected);
    assert_eq!(
        page["items"].as_array().unwrap().len(),
        expected.min(1) as usize
    );
    assert_eq!(
        get(f, &f.me, "/api/account/devices/summary").await["own_devices"],
        expected
    );
}
#[tokio::test]
async fn account_devices_raw_scalar_boundaries_reject_arrays_and_nonbooleans() {
    let f = fixture().await;
    let tid = tenant(&f, "scalar-boundary").await;
    let aid = device(&f, tid, f.me.id, "scalar-owned").await;
    let agents = f.app.db.collection::<Document>("agents");
    let members = f.app.db.collection::<Document>("tenant_members");
    let tenants = f.app.db.collection::<Document>("tenants");
    let member = members
        .find_one(doc! {"tenant_id":tid,"user_id":f.me.id})
        .await
        .unwrap()
        .unwrap();
    let mid = member.get_object_id("_id").unwrap();
    own_count(&f, 1).await;
    for bad in [
        Bson::Array(vec![f.me.id.into()]),
        Bson::Null,
        Bson::String(f.me.id.to_hex()),
        Bson::Int32(0),
    ] {
        agents
            .update_one(doc! {"_id":aid}, doc! {"$set":{"owner_user_id":bad}})
            .await
            .unwrap();
        own_count(&f, 0).await;
    }
    agents
        .update_one(doc! {"_id":aid}, doc! {"$set":{"owner_user_id":f.me.id}})
        .await
        .unwrap();
    for bad in [
        Bson::Array(vec![f.me.id.into()]),
        Bson::Null,
        Bson::String(f.me.id.to_hex()),
        Bson::Int32(0),
    ] {
        members
            .update_one(doc! {"_id":mid}, doc! {"$set":{"user_id":bad}})
            .await
            .unwrap();
        own_count(&f, 0).await;
    }
    members
        .update_one(doc! {"_id":mid}, doc! {"$set":{"user_id":f.me.id}})
        .await
        .unwrap();
    for (collection, id, field) in [(&agents, aid, "tenant_id"), (&members, mid, "tenant_id")] {
        collection
            .update_one(doc! {"_id":id}, doc! {"$set":{field:[tid]}})
            .await
            .unwrap();
        own_count(&f, 0).await;
        collection
            .update_one(doc! {"_id":id}, doc! {"$set":{field:tid}})
            .await
            .unwrap();
    }
    let bad_booleans = vec![
        Bson::Array(vec![false.into()]),
        Bson::Array(vec![false.into(), true.into()]),
        Bson::Null,
        Bson::String("false".into()),
        Bson::Int32(0),
        Bson::Document(doc! {"v":false}),
        Bson::Boolean(true),
    ];
    for (collection, id, field) in [
        (&members, mid, "is_pending"),
        (&tenants, tid, "is_archived"),
    ] {
        for bad in &bad_booleans {
            collection
                .update_one(doc! {"_id":id}, doc! {"$set":{field:bad.clone()}})
                .await
                .unwrap();
            own_count(&f, 0).await;
        }
        // Legacy missing defaults false, then normal explicit scalar false.
        collection
            .update_one(doc! {"_id":id}, doc! {"$unset":{field:""}})
            .await
            .unwrap();
        own_count(&f, 1).await;
        collection
            .update_one(doc! {"_id":id}, doc! {"$set":{field:false}})
            .await
            .unwrap();
        own_count(&f, 1).await;
    }
    for (collection, id) in [(&agents, aid), (&tenants, tid)] {
        collection
            .update_one(doc! {"_id":id}, doc! {"$set":{"deleted_at":[Bson::Null]}})
            .await
            .unwrap();
        own_count(&f, 0).await;
        collection
            .update_one(doc! {"_id":id}, doc! {"$unset":{"deleted_at":""}})
            .await
            .unwrap();
        own_count(&f, 1).await;
    }
    let now = DateTime::now().timestamp_millis();
    let receive = grant(
        &f,
        f.other.id,
        f.me.id,
        ObjectId::new(),
        now + 120_000,
        false,
        now - 1000,
    )
    .await;
    let send = grant(
        &f,
        f.me.id,
        f.other.id,
        ObjectId::new(),
        now + 120_000,
        false,
        now - 1000,
    )
    .await;
    let grants = f
        .app
        .db
        .collection::<Document>(DeviceShareGrant::COLLECTION);
    for original in [&receive, &send] {
        for field in [
            "owner_user_id",
            "recipient_user_id",
            "device_id",
            "tenant_id",
        ] {
            let mut bad = bson::to_document(original).unwrap();
            bad.insert("_id", ObjectId::new());
            bad.insert(field, Bson::Array(vec![bad.get(field).unwrap().clone()]));
            grants.insert_one(bad).await.unwrap();
        }
    }
    // An unrelated grant with array actors containing caller cannot enter either facet.
    let mut unrelated = bson::to_document(&receive).unwrap();
    unrelated.insert("_id", ObjectId::new());
    unrelated.insert("owner_user_id", vec![f.me.id]);
    unrelated.insert("recipient_user_id", vec![f.me.id]);
    grants.insert_one(unrelated).await.unwrap();
    let before = grants.count_documents(doc! {}).await.unwrap();
    assert_eq!(before, 11);
    let summary = get(&f, &f.me, "/api/account/devices/summary").await;
    for direction in ["received", "sent"] {
        assert_eq!(
            summary[direction],
            json!({"active_devices":1,"active_grants":1,"total_records":1,"expired_records":0,"revoked_records":0})
        );
    }
    assert_eq!(
        grants.count_documents(doc! {}).await.unwrap(),
        before,
        "reading summary never deletes malformed or historical records"
    );
}
