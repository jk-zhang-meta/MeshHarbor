// SPDX-License-Identifier: AGPL-3.0-only
//! Real HTTP/Mongo coverage for central account management, not a mocked DAO.
//! Uses TestApp's isolated database and loopback listener; never a production host.
use crate::fixtures::test_app::TestApp;
use bson::{DateTime, doc, oid::ObjectId};
use roomler_ai_db::models::{AccountApprovalState, User};
use serde_json::{Value, json};
use std::collections::BTreeSet;

struct Actor {
    id: ObjectId,
    token: String,
}

async fn app_with_owner(owner: ObjectId, stats_admin: Option<ObjectId>) -> TestApp {
    TestApp::spawn_with_settings(move |settings| {
        settings.auth.account_approval.enabled = true;
        settings.auth.account_approval.owner_user_id = Some(owner.to_hex());
        settings.stats.platform_admins = stats_admin.map(|id| id.to_hex());
    })
    .await
}

/// register_user() activates email and immediately logs in. It cannot seed a
/// pending user once approval is enabled. Seed explicit fixture identities in
/// Mongo instead, then sign test tokens with this TestApp's own AuthService.
/// No pending-account login is silently approved to make the helper succeed.
async fn actor(
    app: &TestApp,
    name: &str,
    fixed_id: Option<ObjectId>,
    state: AccountApprovalState,
    created_at: i64,
) -> Actor {
    let hash = app
        .state
        .auth
        .hash_password("fixture-only-not-a-real-password")
        .unwrap();
    let mut user = app
        .state
        .users
        .create(
            format!("{name}@approval.example.test"),
            name.to_owned(),
            name.to_owned(),
            hash,
            None,
        )
        .await
        .unwrap();
    let generated_id = user.id.unwrap();
    let id = fixed_id.unwrap_or(generated_id);
    user.id = Some(id);
    user.is_verified = true;
    user.account_approval.state = state;
    user.created_at = DateTime::from_millis(created_at);
    let users = app.db.collection::<User>("users");
    if id != generated_id {
        users
            .delete_one(doc! { "_id": generated_id })
            .await
            .unwrap();
        users.insert_one(&user).await.unwrap();
    } else {
        users.replace_one(doc! { "_id": id }, &user).await.unwrap();
    }
    let tokens = app
        .state
        .auth
        .generate_tokens_at_revision(id, &user.email, &user.username, 0)
        .unwrap();
    Actor {
        id,
        token: tokens.access_token,
    }
}

async fn ok(response: reqwest::Response) -> Value {
    let status = response.status().as_u16();
    let body = response.text().await.unwrap();
    assert_eq!(status, 200, "unexpected API response: {body}");
    serde_json::from_str(&body).unwrap()
}

async fn queue(app: &TestApp, owner: &Actor, query: &str) -> Value {
    ok(app
        .auth_get(&format!("/api/auth/approval{query}"), &owner.token)
        .send()
        .await
        .unwrap())
    .await
}

fn ordered_ids(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|user| user["user_id"].as_str().unwrap().to_owned())
        .collect()
}

fn ids(page: &Value) -> BTreeSet<String> {
    ordered_ids(page).into_iter().collect()
}

async fn stored(app: &TestApp, id: ObjectId) -> User {
    app.db
        .collection::<User>("users")
        .find_one(doc! { "_id": id })
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn approval_management_access_is_owner_only_not_platform_admin() {
    let owner_id = ObjectId::new();
    let admin_id = ObjectId::new();
    let app = app_with_owner(owner_id, Some(admin_id)).await;
    let owner = actor(
        &app,
        "owner",
        Some(owner_id),
        AccountApprovalState::Pending,
        1,
    )
    .await;
    let admin = actor(
        &app,
        "statsadmin",
        Some(admin_id),
        AccountApprovalState::Approved,
        2,
    )
    .await;
    assert!(app.state.platform_admins.contains(&admin_id));
    for (who, expected_owner) in [(&owner, true), (&admin, false)] {
        let response = ok(app
            .auth_get("/api/auth/approval/access", &who.token)
            .send()
            .await
            .unwrap())
        .await;
        assert_eq!(
            response,
            json!({ "enabled": true, "is_owner": expected_owner })
        );
    }
    assert_eq!(
        app.auth_get("/api/auth/approval", &admin.token)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    // Separate client: no cookie from any other fixture actor can authorize it.
    assert_eq!(
        reqwest::Client::new()
            .get(app.url("/api/auth/approval/access"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );
}

#[tokio::test]
async fn approval_management_queue_default_and_each_state_use_real_mongo_filters() {
    let owner_id = ObjectId::new();
    let app = app_with_owner(owner_id, None).await;
    let owner = actor(
        &app,
        "owner",
        Some(owner_id),
        AccountApprovalState::Pending,
        1,
    )
    .await;
    let pending = actor(&app, "pending", None, AccountApprovalState::Pending, 2).await;
    let legacy = actor(
        &app,
        "legacy",
        None,
        AccountApprovalState::LegacyUnreviewed,
        3,
    )
    .await;
    let missing = actor(&app, "missing", None, AccountApprovalState::Pending, 4).await;
    let approved = actor(&app, "approved", None, AccountApprovalState::Approved, 5).await;
    let rejected = actor(&app, "rejected", None, AccountApprovalState::Rejected, 6).await;
    let suspended = actor(&app, "suspended", None, AccountApprovalState::Suspended, 7).await;
    let deleted = actor(&app, "deleted", None, AccountApprovalState::Pending, 8).await;
    let users = app.db.collection::<bson::Document>("users");
    users
        .update_one(
            doc! { "_id": missing.id },
            doc! { "$unset": { "account_approval": "" } },
        )
        .await
        .unwrap();
    users
        .update_one(
            doc! { "_id": deleted.id },
            doc! { "$set": { "deleted_at": DateTime::now() } },
        )
        .await
        .unwrap();
    let default = queue(&app, &owner, "?page=1&per_page=20").await;
    assert_eq!(default["total"], 3);
    assert_eq!(
        ids(&default),
        BTreeSet::from([pending.id.to_hex(), legacy.id.to_hex(), missing.id.to_hex()])
    );
    assert!(!ids(&default).contains(&owner.id.to_hex()));
    assert!(!ids(&default).contains(&deleted.id.to_hex()));
    for user in default["items"].as_array().unwrap() {
        let keys = user
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            keys,
            BTreeSet::from([
                "user_id",
                "username",
                "email",
                "state",
                "revision",
                "email_verified"
            ])
        );
    }
    for (state, expected) in [
        ("pending", vec![pending.id.to_hex()]),
        ("approved", vec![approved.id.to_hex()]),
        ("rejected", vec![rejected.id.to_hex()]),
        ("suspended", vec![suspended.id.to_hex()]),
        (
            "legacy_unreviewed",
            vec![legacy.id.to_hex(), missing.id.to_hex()],
        ),
    ] {
        let result = queue(&app, &owner, &format!("?state={state}&page=1&per_page=20")).await;
        assert_eq!(
            ids(&result),
            expected.into_iter().collect(),
            "filter={state}"
        );
    }
}

#[tokio::test]
async fn approval_management_real_url_page_queries_do_not_flatten_or_repeat_rows() {
    let owner_id = ObjectId::new();
    let app = app_with_owner(owner_id, None).await;
    let owner = actor(
        &app,
        "owner",
        Some(owner_id),
        AccountApprovalState::Pending,
        1,
    )
    .await;
    let mut expected = Vec::new();
    // Distinct timestamps avoid relying on Mongo's tie ordering.
    for number in 0..5 {
        expected.push(
            actor(
                &app,
                &format!("pending{number}"),
                None,
                AccountApprovalState::Pending,
                100 + number,
            )
            .await
            .id
            .to_hex(),
        );
    }
    for (number, expected_ids) in [
        (1, expected[0..2].to_vec()),
        (2, expected[2..4].to_vec()),
        (3, expected[4..5].to_vec()),
    ] {
        let result = queue(
            &app,
            &owner,
            &format!("?state=pending&page={number}&per_page=2"),
        )
        .await;
        assert_eq!(result["page"], number);
        assert_eq!(result["total"], 5);
        assert_eq!(ordered_ids(&result), expected_ids);
    }
    for query in [
        "?state=not_a_state",
        "?page=18446744073709551615&per_page=100",
    ] {
        assert_eq!(
            app.auth_get(&format!("/api/auth/approval{query}"), &owner.token)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            400
        );
    }
}

#[tokio::test]
async fn approval_management_review_updates_mongo_and_stale_revision_is_409() {
    let owner_id = ObjectId::new();
    let app = app_with_owner(owner_id, None).await;
    let owner = actor(
        &app,
        "owner",
        Some(owner_id),
        AccountApprovalState::Pending,
        1,
    )
    .await;
    let nonowner = actor(&app, "member", None, AccountApprovalState::Approved, 2).await;
    let target = actor(&app, "target", None, AccountApprovalState::Pending, 3).await;
    let path = format!("/api/auth/approval/{}", target.id.to_hex());
    assert_eq!(
        app.auth_post(&path, &nonowner.token)
            .json(&json!({ "state": "approved", "expected_revision": 0 }))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        stored(&app, target.id).await.account_approval.state,
        AccountApprovalState::Pending
    );
    let approved = ok(app
        .auth_post(&path, &owner.token)
        .json(&json!({ "state": "approved", "expected_revision": 0 }))
        .send()
        .await
        .unwrap())
    .await;
    assert_eq!(approved["state"], "approved");
    assert_eq!(approved["revision"], 1);
    let row = stored(&app, target.id).await;
    assert_eq!(row.account_approval.state, AccountApprovalState::Approved);
    assert_eq!(row.account_approval.revision, 1);
    assert_eq!(row.account_approval.reviewed_by, Some(owner_id));
    assert!(row.account_approval.reviewed_at.is_some());
    assert_eq!(
        app.auth_post(&path, &owner.token)
            .json(&json!({ "state": "suspended", "expected_revision": 0 }))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        409
    );
    let unchanged = stored(&app, target.id).await;
    assert_eq!(
        unchanged.account_approval.state,
        AccountApprovalState::Approved
    );
    assert_eq!(unchanged.account_approval.revision, 1);
    let suspended = ok(app
        .auth_post(&path, &owner.token)
        .json(&json!({ "state": "suspended", "expected_revision": 1 }))
        .send()
        .await
        .unwrap())
    .await;
    assert_eq!(suspended["state"], "suspended");
    assert_eq!(suspended["revision"], 2);
    let row = stored(&app, target.id).await;
    assert_eq!(row.account_approval.state, AccountApprovalState::Suspended);
    assert_eq!(row.account_approval.revision, 2);
}

#[tokio::test]
async fn approval_management_suspension_fences_enrollment_renewal_and_live_agent_socket() {
    use futures::StreamExt;
    use std::time::Duration;
    use tokio_tungstenite::tungstenite::Message;
    let owner_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |settings| {
        settings.auth.account_approval.enabled = true;
        settings.auth.account_approval.owner_user_id = Some(owner_id.to_hex());
        settings.rc.token_renewal = true;
    })
    .await;
    let device_owner = actor(
        &app,
        "device-owner",
        None,
        AccountApprovalState::Approved,
        1,
    )
    .await;
    let tenant = app
        .state
        .tenants
        .create(
            "Device admission".into(),
            "device-admission".into(),
            device_owner.id,
        )
        .await
        .unwrap();
    let tid = tenant.id.unwrap();
    let (enrollment, _) = app
        .state
        .auth
        .issue_enrollment_token_with(device_owner.id, tid, 600, false)
        .unwrap();
    let (unused, _) = app
        .state
        .auth
        .issue_enrollment_token_with(device_owner.id, tid, 600, false)
        .unwrap();
    let response = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": enrollment, "machine_id": "admission-machine",
            "machine_name": "admission fixture", "os": "linux", "agent_version": "test"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let device: Value = response.json().await.unwrap();
    let token = device["agent_token"].as_str().unwrap();
    let mut ws = crate::agent_presence_tests::connect_agent(&app, token).await;
    assert_eq!(
        app.auth_post("/api/agent/self/renew", token)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    // Wait for actual hello processing, not just HTTP 101.
    let aid = ObjectId::parse_str(device["agent_id"].as_str().unwrap()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !app.state.fleet().rc_hub.is_agent_online(aid) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // A different approved account stays online and must receive an explicit
    // overlay removal, not merely a grey/offline row preserving cached keys.
    let peer_owner = actor(&app, "peer-owner", None, AccountApprovalState::Approved, 2).await;
    let (peer_enroll, _) = app
        .state
        .auth
        .issue_enrollment_token_with(peer_owner.id, tid, 600, false)
        .unwrap();
    let peer_device: Value = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": peer_enroll, "machine_id": "admission-peer",
            "machine_name": "peer fixture", "os": "linux", "agent_version": "test"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut peer_ws = crate::agent_presence_tests::connect_agent(
        &app,
        peer_device["agent_token"].as_str().unwrap(),
    )
    .await;
    use base64::Engine as _;
    use futures::SinkExt;
    for (socket, seed) in [(&mut ws, 41u8), (&mut peer_ws, 42u8)] {
        socket.send(Message::Text(json!({
            "t": "rc:overlay.join", "wg_public_key": base64::engine::general_purpose::STANDARD.encode([seed;32]),
            "mtu": 1280, "endpoints": [], "supports_org_relay": true
        }).to_string().into())).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(Ok(Message::Text(text))) = socket.next().await {
                    let v: Value = serde_json::from_str(&text).unwrap();
                    if v["t"] == "rc:overlay.netmap" {
                        break;
                    }
                }
            }
        })
        .await
        .unwrap();
    }
    let victim_node = app.state.network().admission_nodes.iter().find(|n|
        matches!(n.node_ref, roomler_ai_remote_control::models::NodeRef::Agent { agent_id } if agent_id == aid)
    ).unwrap().id.unwrap();
    let derp_url = format!("ws://{}/derp?token={}", app.addr, token);
    let (mut derp, _) = tokio_tungstenite::connect_async(&derp_url).await.unwrap();
    derp.send(Message::Binary(vec![41u8; 32].into()))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while app.state.network().derp_registry.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    app.db
        .collection::<bson::Document>("users")
        .update_one(
            doc! {"_id": device_owner.id},
            doc! {"$set": {"account_approval.state": "suspended", "account_approval.revision": 1}},
        )
        .await
        .unwrap();
    assert_eq!(
        app.auth_post("/api/agent/self/renew", token)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    let denied = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": unused, "machine_id": "must-not-enroll",
            "machine_name": "denied", "os": "linux", "agent_version": "test"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status().as_u16(), 403);
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            }
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "active agent socket must close on owner suspension"
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(Ok(Message::Text(text))) = peer_ws.next().await {
                let v: Value = serde_json::from_str(&text).unwrap();
                if v["t"] == "rc:overlay.netmap_delta"
                    && v["removes"]
                        .as_array()
                        .is_some_and(|ids| ids.iter().any(|id| id == &json!(victim_node.to_hex())))
                {
                    break;
                }
            }
        }
    })
    .await
    .expect("approved peer receives explicit key/route removal on suspension");
    assert!(
        app.state.fleet().rc_hub.is_agent_online(
            ObjectId::parse_str(peer_device["agent_id"].as_str().unwrap()).unwrap()
        )
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match derp.next().await {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            }
        }
    })
    .await
    .expect("DERP must not survive account revocation");
    assert!(tokio_tungstenite::connect_async(&derp_url).await.is_err());
    let ws_url = format!("ws://{}/ws?token={}&role=agent", app.addr, token);
    assert!(
        tokio_tungstenite::connect_async(&ws_url).await.is_err(),
        "old agent token cannot reconnect"
    );
}
