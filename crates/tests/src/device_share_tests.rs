// SPDX-License-Identifier: AGPL-3.0-only
//! Real loopback HTTP + isolated Mongo grant lifecycle; no agent or production host.
use crate::fixtures::test_app::TestApp;
use bson::{DateTime, doc, oid::ObjectId};
use meshharbor_db::models::{AccountApprovalState, DeviceShareGrant, User};
use meshharbor_remote_control::models::{Agent, AgentStatus, OsKind};
use meshharbor_services::dao::agent::AgentDao;
use serde_json::{Value, json};
struct Actor {
    id: ObjectId,
    token: String,
}
struct Fixture {
    app: TestApp,
    owner: Actor,
    recipient: Actor,
    outsider: Actor,
    pending: Actor,
    device: ObjectId,
    tenant: ObjectId,
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
        .hash_password("not-a-real-share-fixture-password")
        .unwrap();
    let mut u = app
        .state
        .users
        .create(
            format!("{name}@share.example.test"),
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
    if id != generated {
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
    fixture_with_settings(|_| {}).await
}
async fn fixture_with_settings(
    configure: impl FnOnce(&mut meshharbor_config::Settings),
) -> Fixture {
    let owner_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.auth.account_approval.enabled = true;
        s.auth.account_approval.owner_user_id = Some(owner_id.to_hex());
        configure(s);
    })
    .await;
    // Configured bootstrap owner remains pending; recipients NEVER get that exception.
    let owner = actor(
        &app,
        "share_owner",
        Some(owner_id),
        AccountApprovalState::Pending,
    )
    .await;
    let recipient = actor(
        &app,
        "share_recipient",
        None,
        AccountApprovalState::Approved,
    )
    .await;
    let outsider = actor(&app, "share_outsider", None, AccountApprovalState::Approved).await;
    let pending = actor(&app, "share_pending", None, AccountApprovalState::Pending).await;
    let tenant = app
        .state
        .tenants
        .create("Share fixture".into(), "share-fixture".into(), owner.id)
        .await
        .unwrap()
        .id
        .unwrap();
    let device = AgentDao::new(&app.db)
        .create(
            tenant,
            owner.id,
            "One shared box".into(),
            "share-fixture-machine".into(),
            OsKind::Linux,
            "fixture".into(),
            "not-a-real-agent-token".into(),
            None,
        )
        .await
        .unwrap()
        .id
        .unwrap();
    app.db
        .collection::<Agent>("agents")
        .update_one(
            doc! {"_id":device},
            doc! {"$set":{"capabilities.rpc":["shared-session-lease-v1"]}},
        )
        .await
        .unwrap();
    Fixture {
        app,
        owner,
        recipient,
        outsider,
        pending,
        device,
        tenant,
    }
}
fn create_body(f: &Fixture) -> Value {
    json!({"device_id":f.device.to_hex(),"recipient_user_id":f.recipient.id.to_hex(),"permissions":{"ssh":true},"tcp_ports":[22],"expires_in_secs":60,"ssh_account":"alice"})
}
async fn create(f: &Fixture) -> Value {
    let r = f
        .app
        .auth_post("/api/device-shares", &f.owner.token)
        .json(&create_body(f))
        .send()
        .await
        .unwrap();
    let status = r.status();
    let text = r.text().await.unwrap();
    assert_eq!(status.as_u16(), 200, "{text}");
    serde_json::from_str(&text).unwrap()
}
async fn check(f: &Fixture, id: &str, token: &str, body: Value) -> u16 {
    f.app
        .auth_post(&format!("/api/device-shares/{id}/check"), token)
        .json(&body)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}
#[tokio::test]
async fn device_share_exact_recipient_device_service_and_port_not_membership() {
    let f = fixture().await;
    let grant = create(&f).await;
    let id = grant["id"].as_str().unwrap();
    assert!(
        !f.app
            .state
            .tenants
            .is_member(f.tenant, f.recipient.id)
            .await
            .unwrap()
    );
    assert_eq!(
        check(&f, id, &f.recipient.token, json!({"operation":"ssh"})).await,
        200
    );
    let other = AgentDao::new(&f.app.db)
        .create(
            f.tenant,
            f.owner.id,
            "Not shared".into(),
            "unshared-fixture-machine".into(),
            OsKind::Linux,
            "fixture".into(),
            "not-a-real-agent-token".into(),
            None,
        )
        .await
        .unwrap();
    assert!(
        meshharbor_core::device_share::authorize(
            &f.app.state,
            f.recipient.id,
            other.id.unwrap(),
            meshharbor_db::models::DeviceShareOperation::Ssh
        )
        .await
        .is_err()
    );

    assert_eq!(
        check(
            &f,
            id,
            &f.recipient.token,
            json!({"operation":"tcp_connect","port":22})
        )
        .await,
        200
    );
    for body in [
        json!({"operation":"tcp_connect","port":23}),
        json!({"operation":"files_read"}),
        json!({"operation":"desktop_view"}),
    ] {
        assert_eq!(check(&f, id, &f.recipient.token, body).await, 403);
    }
    assert_eq!(
        check(&f, id, &f.outsider.token, json!({"operation":"ssh"})).await,
        404
    );
    assert_eq!(
        check(&f, id, &f.owner.token, json!({"operation":"ssh"})).await,
        404
    );
    assert_eq!(
        check(&f, id, &f.recipient.token, json!({"operation":"transit"})).await,
        400
    );
    let received: Value = f
        .app
        .auth_get(
            "/api/device-shares?direction=received&page=1&per_page=1",
            &f.recipient.token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(received["total"], 1);
    assert_eq!(received["items"][0]["device_id"], f.device.to_hex());
    assert!(received["items"][0].get("tenant_id").is_none());
    let outsider: Value = f
        .app
        .auth_get("/api/device-shares?direction=received", &f.outsider.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(outsider["total"], 0);
    assert!(
        !f.app
            .state
            .tenants
            .is_member(f.tenant, f.recipient.id)
            .await
            .unwrap()
    );
}
/// A person shares a device by naming the recipient — username, or email in any case — and
/// reads names, not ids, back. Every reason a NAMED recipient cannot be used answers the SAME
/// refusal, so the form is no oracle for which accounts exist or what state they are in.
#[tokio::test]
async fn device_share_names_the_recipient_and_lists_names_without_an_account_oracle() {
    let f = fixture().await;
    let post = |body: Value| {
        let f = &f;
        async move {
            let r = f
                .app
                .auth_post("/api/device-shares", &f.owner.token)
                .json(&body)
                .send()
                .await
                .unwrap();
            let status = r.status().as_u16();
            (status, r.json::<Value>().await.unwrap_or(Value::Null))
        }
    };
    let named = |recipient: &str| {
        json!({"device_id":f.device.to_hex(),"recipient":recipient,
               "permissions":{"ssh":true},"tcp_ports":[22],"expires_in_secs":60,"ssh_account":"alice"})
    };

    let (status, v) = post(named("share_recipient")).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["recipient_user_id"], f.recipient.id.to_hex());
    assert_eq!(v["recipient_username"], "share_recipient");
    assert_eq!(v["owner_username"], "share_owner");
    assert_eq!(v["device_name"], "One shared box");

    // Addresses match whatever case the person types.
    let (status, v) = post(named("  SHARE_RECIPIENT@share.example.test ")).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["recipient_user_id"], f.recipient.id.to_hex());

    // No account, a pending account, and a deleted-looking typo all read the same.
    let (s_unknown, unknown) = post(named("nobody_by_this_name")).await;
    let (s_pending, pending) = post(named("share_pending")).await;
    assert_eq!((s_unknown, s_pending), (400, 400));
    assert_eq!(unknown, pending, "the refusal must not tell the two apart");

    // Exactly one way of naming the recipient.
    let mut both = named("share_recipient");
    both["recipient_user_id"] = json!(f.recipient.id.to_hex());
    assert_eq!(post(both).await.0, 400);
    let mut neither = named("share_recipient");
    neither.as_object_mut().unwrap().remove("recipient");
    assert_eq!(post(neither).await.0, 400);

    // The id form is unchanged.
    let by_id = create(&f).await;
    assert_eq!(by_id["recipient_username"], "share_recipient");

    // Both sides read names back in their lists.
    for (token, direction) in [(&f.owner.token, "sent"), (&f.recipient.token, "received")] {
        let page: Value = f
            .app
            .auth_get(&format!("/api/device-shares?direction={direction}"), token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let items = page["items"].as_array().unwrap();
        assert_eq!(items.len(), 3, "{direction}: {page}");
        assert!(
            items.iter().all(|i| i["device_name"] == "One shared box"
                && i["owner_username"] == "share_owner"
                && i["recipient_username"] == "share_recipient"),
            "{direction}: {page}"
        );
    }
}

#[tokio::test]
async fn device_share_creation_refuses_nonowner_pending_and_broad_scope() {
    let f = fixture().await;
    let mut b = create_body(&f);
    b["recipient_user_id"] = json!(f.pending.id.to_hex());
    assert_eq!(
        f.app
            .auth_post("/api/device-shares", &f.owner.token)
            .json(&b)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        f.app
            .auth_post("/api/device-shares", &f.outsider.token)
            .json(&create_body(&f))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    let mut b = create_body(&f);
    b["tenant_id"] = json!(f.tenant.to_hex());
    assert_eq!(
        f.app
            .auth_post("/api/device-shares", &f.owner.token)
            .json(&b)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        422
    );
    for b in [
        {
            let mut b = create_body(&f);
            b["tcp_ports"] = json!([0]);
            b
        },
        {
            let mut b = create_body(&f);
            b["expires_in_secs"] = json!(DeviceShareGrant::MAX_LIFETIME_SECS + 1);
            b
        },
    ] {
        assert_eq!(
            f.app
                .auth_post("/api/device-shares", &f.owner.token)
                .json(&b)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            400
        );
    }
    assert_eq!(
        f.app
            .db
            .collection::<DeviceShareGrant>(DeviceShareGrant::COLLECTION)
            .count_documents(doc! {})
            .await
            .unwrap(),
        0
    );
}
#[tokio::test]
async fn device_share_revoke_cas_and_expiry_are_enforced_by_real_check_route() {
    let f = fixture().await;
    let g = create(&f).await;
    let id = g["id"].as_str().unwrap();
    let path = format!("/api/device-shares/{id}/revoke");
    assert_eq!(
        f.app
            .auth_post(&path, &f.outsider.token)
            .json(&json!({"expected_revision":0}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
    assert_eq!(
        f.app
            .auth_post(&path, &f.owner.token)
            .json(&json!({"expected_revision":1}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        409
    );
    assert_eq!(
        check(&f, id, &f.recipient.token, json!({"operation":"ssh"})).await,
        200
    );
    let revoked: Value = f
        .app
        .auth_post(&path, &f.owner.token)
        .json(&json!({"expected_revision":0}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(revoked["revision"], 1);
    assert!(revoked["revoked_at_ms"].is_number());
    assert_eq!(
        check(&f, id, &f.recipient.token, json!({"operation":"ssh"})).await,
        403
    );
    assert_eq!(
        f.app
            .auth_post(&path, &f.owner.token)
            .json(&json!({"expected_revision":0}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        409
    );
    let g = create(&f).await;
    let id = g["id"].as_str().unwrap();
    f.app
        .db
        .collection::<DeviceShareGrant>(DeviceShareGrant::COLLECTION)
        .update_one(
            doc! {"_id":ObjectId::parse_str(id).unwrap()},
            doc! {"$set":{"expires_at":DateTime::from_millis(1)}},
        )
        .await
        .unwrap();
    assert_eq!(
        check(&f, id, &f.recipient.token, json!({"operation":"ssh"})).await,
        403
    );
}
#[tokio::test]
async fn device_share_live_lookup_rejects_owner_change_quarantine_and_recipient_revocation() {
    let f = fixture().await;
    let g = create(&f).await;
    let id = g["id"].as_str().unwrap();
    let agents = f.app.db.collection::<Agent>("agents");
    // New owner is an active org member, so snapshot mismatch (not missing membership) denies.
    f.app
        .state
        .tenants
        .add_member(f.tenant, f.outsider.id, vec![], Some(f.owner.id))
        .await
        .unwrap();

    agents
        .update_one(
            doc! {"_id":f.device},
            doc! {"$set":{"owner_user_id":f.outsider.id}},
        )
        .await
        .unwrap();
    assert_eq!(
        check(&f, id, &f.recipient.token, json!({"operation":"ssh"})).await,
        403
    );
    agents.update_one(doc!{"_id":f.device},doc!{"$set":{"owner_user_id":f.owner.id,"status":bson::to_bson(&AgentStatus::Quarantined).unwrap()}}).await.unwrap();
    assert_eq!(
        check(&f, id, &f.recipient.token, json!({"operation":"ssh"})).await,
        403
    );
    agents
        .update_one(
            doc! {"_id":f.device},
            doc! {"$set":{"status":bson::to_bson(&AgentStatus::Offline).unwrap()}},
        )
        .await
        .unwrap();
    f.app.db.collection::<User>("users").update_one(doc!{"_id":f.recipient.id},doc!{"$set":{"account_approval.state":"suspended"},"$inc":{"account_approval.revision":1}}).await.unwrap();
    assert_eq!(
        check(&f, id, &f.recipient.token, json!({"operation":"ssh"})).await,
        403
    );
}

/// Real authenticated controller WebSocket -> actual Hub -> agent control channel,
/// then real HTTP revoke -> live watchdog -> exact session termination.
/// This proves server signaling/lifecycle, NOT native capture/WebRTC payload throughput.
#[tokio::test]
async fn device_share_remote_real_ws_session_and_live_revoke() {
    use futures::{SinkExt, StreamExt};
    use meshharbor_remote_control::signaling::ServerMsg;
    use std::time::Duration;
    use tokio_tungstenite::{connect_async, tungstenite::Message};
    let f = fixture().await;
    let mut body = create_body(&f);
    body["permissions"] =
        json!({"desktop_view":true,"desktop_control":true,"files_read":true,"files_write":true});
    body.as_object_mut().unwrap().remove("ssh_account");
    let grant: Value = f
        .app
        .auth_post("/api/device-shares", &f.owner.token)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = grant["id"].as_str().unwrap();
    // Public signing identity of this ONE device; never its private signing key.
    let public_key = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
    f.app
        .db
        .collection::<Agent>("agents")
        .update_one(
            doc! {"_id":f.device},
            doc! {"$set":{"peer_auth_key":public_key}},
        )
        .await
        .unwrap();
    let denied = f
        .app
        .auth_get(
            &format!("/api/device-shares/{id}/remote"),
            &f.outsider.token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        denied.status().as_u16(),
        404,
        "an unrelated user cannot see even the public device identity"
    );
    let metadata: Value = f
        .app
        .auth_get(
            &format!("/api/device-shares/{id}/remote"),
            &f.recipient.token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(metadata["id"], f.device.to_hex());
    assert!(metadata.get("tenant_id").is_none());
    assert_eq!(metadata["peer_auth_key"], public_key);
    assert!(metadata.get("peer_auth_private_key").is_none());
    assert!(metadata.get("token").is_none());
    let hub = &f.app.state.modules.fleet.as_ref().unwrap().rc_hub;
    let (_agent_tx, _cancel, mut agent_rx) = hub.register_agent(
        f.device,
        f.tenant,
        f.owner.id,
        OsKind::Linux,
        4,
        false,
        false,
    );
    let url = format!(
        "ws://{}/ws?token={}&role=controller",
        f.app.addr, f.recipient.token
    );
    let (mut ws, _) = connect_async(url).await.unwrap();
    ws.send(Message::Text(json!({"t":"rc:session.request","agent_id":f.device.to_hex(),"share_grant_id":id,"permissions":"VIEW | INPUT | FILES"}).to_string().into())).await.unwrap();
    let request = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if let Some(ServerMsg::Request {
                session_id,
                permissions,
                rc_overlay,
                ..
            }) = agent_rx.recv().await
            {
                break (session_id, permissions, rc_overlay);
            }
        }
    })
    .await
    .unwrap();
    assert!(
        request
            .1
            .contains(meshharbor_remote_control::permissions::Permissions::FILES)
    );
    assert!(!request.2);
    assert_eq!(hub.session_grant(request.0).unwrap().1, f.recipient.id);
    hub.deliver_consent(request.0, true, None).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(Ok(Message::Text(text))) = ws.next().await {
                let v: Value = serde_json::from_str(&text).unwrap();
                if v["t"] == "rc:ready" {
                    break;
                }
            }
        }
    })
    .await
    .unwrap();
    hub.forward_answer(
        request.0,
        "fixture-signaling-only-sdp".into(),
        None,
        None,
        None,
    )
    .unwrap();
    assert!(hub.session_grant(request.0).is_some());
    let status = f
        .app
        .auth_post(&format!("/api/device-shares/{id}/revoke"), &f.owner.token)
        .json(&json!({"expected_revision":0}))
        .send()
        .await
        .unwrap()
        .status();
    assert!(status.is_success());
    let revoked_metadata = f
        .app
        .auth_get(
            &format!("/api/device-shares/{id}/remote"),
            &f.recipient.token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        revoked_metadata.status().as_u16(),
        403,
        "revocation gates the public identity metadata through the same live PDP"
    );
    let ended = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if let Some(ServerMsg::Terminate { session_id, .. }) = agent_rx.recv().await {
                break session_id;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(ended, request.0);
    assert!(hub.session_grant(request.0).is_none());
    assert!(
        !f.app
            .state
            .tenants
            .is_member(f.tenant, f.recipient.id)
            .await
            .unwrap()
    );
    let _ = ws.close(None).await;
}
#[tokio::test]
async fn device_share_remote_escalation_and_unshared_org_request_are_denied() {
    use futures::{SinkExt, StreamExt};
    use std::time::Duration;
    use tokio_tungstenite::{connect_async, tungstenite::Message};
    let f = fixture().await;
    let mut body = create_body(&f);
    body["permissions"] = json!({"desktop_view":true,"files_read":true});
    body.as_object_mut().unwrap().remove("ssh_account");
    let g: Value = f
        .app
        .auth_post("/api/device-shares", &f.owner.token)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hub = &f.app.state.modules.fleet.as_ref().unwrap().rc_hub;
    let (_tx, _cancel, mut agent_rx) = hub.register_agent(
        f.device,
        f.tenant,
        f.owner.id,
        OsKind::Linux,
        4,
        false,
        false,
    );
    let (mut ws, _) = connect_async(format!(
        "ws://{}/ws?token={}&role=controller",
        f.app.addr, f.recipient.token
    ))
    .await
    .unwrap();
    for request in [
        json!({"t":"rc:session.request","agent_id":f.device.to_hex(),"share_grant_id":g["id"],"permissions":"VIEW | FILES"}),
        json!({"t":"rc:session.request","agent_id":f.device.to_hex(),"share_grant_id":g["id"],"permissions":"VIEW | INPUT"}),
        json!({"t":"rc:session.request","agent_id":f.device.to_hex(),"permissions":"VIEW"}),
    ] {
        ws.send(Message::Text(request.to_string().into()))
            .await
            .unwrap();
        let denied = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(Ok(Message::Text(t))) = ws.next().await {
                    let v: Value = serde_json::from_str(&t).unwrap();
                    if v["t"] == "rc:error" {
                        break v;
                    }
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(denied["code"], "permission_denied");
        assert!(agent_rx.try_recv().is_err());
    }
    assert_eq!(hub.live_sessions(), 0);
    let _ = ws.close(None).await;
}

#[tokio::test]
async fn device_share_remote_distinct_grants_do_not_coalesce_and_live_allowlist_revokes() {
    use futures::SinkExt;
    use meshharbor_remote_control::signaling::ServerMsg;
    use std::time::Duration;
    use tokio_tungstenite::{connect_async, tungstenite::Message};
    let f = fixture().await;
    f.app.set_plan(&f.tenant.to_hex(), "business").await;
    let mut body = create_body(&f);
    body["permissions"] = json!({"desktop_view":true});
    body.as_object_mut().unwrap().remove("ssh_account");
    let mut grants = Vec::new();
    for _ in 0..2 {
        let g: Value = f
            .app
            .auth_post("/api/device-shares", &f.owner.token)
            .json(&body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        grants.push(g["id"].as_str().unwrap().to_owned())
    }
    let hub = &f.app.state.modules.fleet.as_ref().unwrap().rc_hub;
    let (_tx, _cancel, mut agent_rx) = hub.register_agent(
        f.device,
        f.tenant,
        f.owner.id,
        OsKind::Linux,
        4,
        false,
        false,
    );
    let (mut ws, _) = connect_async(format!(
        "ws://{}/ws?token={}&role=controller",
        f.app.addr, f.recipient.token
    ))
    .await
    .unwrap();
    let mut sessions = Vec::new();
    for id in &grants {
        ws.send(Message::Text(json!({"t":"rc:session.request","agent_id":f.device.to_hex(),"share_grant_id":id,"permissions":"VIEW"}).to_string().into())).await.unwrap();
        let sid = tokio::time::timeout(Duration::from_secs(6), async {
            loop {
                if let Some(ServerMsg::Request { session_id, .. }) = agent_rx.recv().await {
                    break session_id;
                }
            }
        })
        .await
        .unwrap();
        sessions.push(sid);
    }
    assert_ne!(sessions[0], sessions[1]);
    let status = f
        .app
        .auth_post(
            &format!("/api/device-shares/{}/revoke", grants[0]),
            &f.owner.token,
        )
        .json(&json!({"expected_revision":0}))
        .send()
        .await
        .unwrap()
        .status();
    assert!(status.is_success());
    let sid = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if let Some(ServerMsg::Terminate { session_id, .. }) = agent_rx.recv().await {
                break session_id;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(sid, sessions[0]);
    assert!(hub.session_grant(sessions[1]).is_some());
    f.app
        .db
        .collection::<Agent>("agents")
        .update_one(
            doc! {"_id":f.device},
            doc! {"$set":{"access_policy.allowed_user_ids":[f.outsider.id]}},
        )
        .await
        .unwrap();
    let sid = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if let Some(ServerMsg::Terminate { session_id, .. }) = agent_rx.recv().await {
                break session_id;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(sid, sessions[1]);
    assert!(hub.session_grant(sessions[1]).is_none());
    let _ = ws.close(None).await;
}

/// Real HTTP ledger + controller WS + actual Hub + authenticated agent handler.
/// Native independent monotonic timer is tested separately; no fake WebRTC claim.
#[tokio::test]
async fn device_share_shared_lease_exact_agent_scope_and_live_policy_pdp() {
    use futures::{SinkExt, StreamExt};
    use meshharbor_core::{AgentCtx, AgentMsgHandler};
    use meshharbor_remote_control::signaling::{ClientMsg, ServerMsg};
    use std::time::Duration;
    use tokio_tungstenite::{connect_async, tungstenite::Message};
    let f = fixture().await;
    let mut body = create_body(&f);
    body["permissions"] = json!({"desktop_view":true});
    body.as_object_mut().unwrap().remove("ssh_account");
    let grant: Value = f
        .app
        .auth_post("/api/device-shares", &f.owner.token)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let grant_id = ObjectId::parse_str(grant["id"].as_str().unwrap()).unwrap();
    let remote = f.app.state.modules.remote.as_ref().unwrap();
    let hub = &f.app.state.modules.fleet.as_ref().unwrap().rc_hub;
    let (_, _, mut agent_rx) = hub.register_agent(
        f.device,
        f.tenant,
        f.owner.id,
        OsKind::Linux,
        4,
        false,
        false,
    );
    let (mut ws, _) = connect_async(format!(
        "ws://{}/ws?token={}&role=controller",
        f.app.addr, f.recipient.token
    ))
    .await
    .unwrap();
    ws.send(Message::Text(json!({"t":"rc:session.request","agent_id":f.device.to_hex(),"share_grant_id":grant_id.to_hex(),"permissions":"VIEW"}).to_string().into())).await.unwrap();
    let (sid, lease) = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if let Some(ServerMsg::Request {
                session_id,
                shared_lease: Some(lease),
                ..
            }) = agent_rx.recv().await
            {
                break (session_id, lease);
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(lease.grant_id, grant_id);
    assert_eq!(lease.lease_epoch.len(), 36);
    hub.deliver_consent(sid, true, None).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(Ok(Message::Text(text))) = ws.next().await {
                let v: Value = serde_json::from_str(&text).unwrap();
                if v["t"] == "rc:ready" {
                    break;
                }
            }
        }
    })
    .await
    .unwrap();
    // Scope is immutable LiveSession state, never a controller-selected field.
    hub.forward_offer(sid, "fixture-producer-scope-only".into(), None, None)
        .unwrap();
    let offered = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if let Some(ServerMsg::SdpOffer { shared_lease, .. }) = agent_rx.recv().await {
                break shared_lease;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(offered, Some(lease.clone()));
    let (tx, mut replies) = tokio::sync::mpsc::channel(8);
    let mut ctx = AgentCtx {
        conn_id: "shared-lease-fixture-only".into(),
        agent_id: ObjectId::new(),
        tenant_id: f.tenant,
        owner_user_id: f.owner.id,
        agent_version: "fixture".into(),
        os: OsKind::Linux,
        dialed_tid: None,
        conn_established_ms: 0,
        tx,
    };
    let handler = meshharbor_mod_remote::agent_socket::RemoteAgentSocket::new(remote.clone());
    let challenge = || ClientMsg::SharedLeaseChallenge {
        session_id: sid,
        grant_id,
        lease_epoch: lease.lease_epoch.clone(),
        challenge_id: 1,
    };
    handler.handle(&ctx, challenge()).await;
    assert!(
        replies.try_recv().is_err(),
        "another authenticated device cannot renew this session"
    );
    ctx.agent_id = f.device;
    // Wait for the controller dispatcher to install its exact immutable scope.
    tokio::time::timeout(Duration::from_secs(4), async { loop {
        handler.handle(&ctx, challenge()).await;
        if let Ok(m) = replies.try_recv() {
            assert!(matches!(m, ServerMsg::SharedLeaseRenewal { session_id, grant_id:g, challenge_id:1, .. } if session_id==sid && g==grant_id)); break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }}).await.unwrap();
    ws.send(Message::Text(
        serde_json::to_string(&challenge()).unwrap().into(),
    ))
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if let Some(Ok(Message::Text(t))) = ws.next().await {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["t"] == "rc:error" {
                    assert_eq!(v["code"], "permission_denied");
                    break;
                }
            }
        }
    })
    .await
    .unwrap();
    f.app
        .db
        .collection::<Agent>("agents")
        .update_one(
            doc! {"_id":f.device},
            doc! {"$set":{"access_policy.allowed_user_ids":[f.outsider.id]}},
        )
        .await
        .unwrap();
    handler
        .handle(
            &ctx,
            ClientMsg::SharedLeaseChallenge {
                session_id: sid,
                grant_id,
                lease_epoch: lease.lease_epoch.clone(),
                challenge_id: 2,
            },
        )
        .await;
    assert!(
        replies.try_recv().is_err(),
        "live allowlist change must never receive a lease ACK"
    );
    assert!(hub.session_grant(sid).is_none());
    // Old native builds cannot start any shared session, even with a valid ledger.
    f.app
        .db
        .collection::<Agent>("agents")
        .update_one(
            doc! {"_id":f.device},
            doc! {"$set":{"capabilities.rpc":[],"access_policy.allowed_user_ids":[]}},
        )
        .await
        .unwrap();
    ws.send(Message::Text(json!({"t":"rc:session.request","agent_id":f.device.to_hex(),"share_grant_id":grant_id.to_hex(),"permissions":"VIEW"}).to_string().into())).await.unwrap();
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if let Some(Ok(Message::Text(t))) = ws.next().await {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["t"] == "rc:error" {
                    assert_eq!(v["code"], "permission_denied");
                    assert!(v["message"].as_str().unwrap().contains("lease"));
                    break;
                }
            }
        }
    })
    .await
    .unwrap();
    let _ = ws.close(None).await;
}

// Shared SSH control-plane proofs: real HTTP + recipient WebSocket + actual
// NetworkAgentSocket/Hub relays. Native SSH/payload is a separate native test;
// these fixture SDP strings must not be reported as a real WebRTC handshake.
type SharedSshWs =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
fn shared_ssh_public_key() -> String {
    use base64::Engine;
    let mut b = vec![];
    b.extend_from_slice(&11u32.to_be_bytes());
    b.extend_from_slice(b"ssh-ed25519");
    b.extend_from_slice(&32u32.to_be_bytes());
    b.extend_from_slice(&[7u8; 32]);
    format!(
        "ssh-ed25519 {}",
        base64::engine::general_purpose::STANDARD.encode(b)
    )
}
async fn shared_ssh_fixture() -> Fixture {
    let f = fixture().await;
    let public = shared_ssh_public_key();
    f.app
        .db
        .collection::<bson::Document>("tenants")
        .update_one(
            doc! {"_id":f.tenant},
            doc! {"$set":{"settings.remote_ssh_enabled":true}},
        )
        .await
        .unwrap();
    f.app.db.collection::<Agent>("agents").update_one(doc! {"_id":f.device},doc! {"$set":{"ssh_host_pubkey":public,"ssh_policy.mode":"on","ssh_policy.consent_mode":"auto","capabilities.rpc":["ssh","ssh-consent","shared-session-lease-v1","shared-ssh-stream-v1"]}}).await.unwrap();
    f
}
async fn shared_ssh_start(
    f: &Fixture,
) -> (
    String,
    SharedSshWs,
    ObjectId,
    meshharbor_remote_control::signaling::SharedSshSetup,
    meshharbor_core::AgentCtx,
    meshharbor_mod_network::agent_socket::NetworkAgentSocket,
    tokio::sync::mpsc::Receiver<meshharbor_remote_control::signaling::ServerMsg>,
) {
    use futures::SinkExt;
    use meshharbor_core::{AgentMsgHandler, AgentSocketLifecycle};
    use meshharbor_remote_control::signaling::{ClientMsg, ServerMsg};
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let grant = create(f).await["id"].as_str().unwrap().to_owned();
    let (tx, _, mut target) = f
        .app
        .state
        .modules
        .fleet
        .as_ref()
        .unwrap()
        .rc_hub
        .register_agent(
            f.device,
            f.tenant,
            f.owner.id,
            OsKind::Linux,
            4,
            false,
            false,
        );
    let mut url = reqwest::Url::parse(&format!(
        "ws://{}/api/device-shares/{grant}/ssh/ws",
        f.app.addr
    ))
    .unwrap();
    url.query_pairs_mut()
        .append_pair("public_key", &shared_ssh_public_key())
        .append_pair("session_secs", "30");
    let mut request = url.as_str().into_client_request().unwrap();
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", f.recipient.token).parse().unwrap(),
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    let (sid, setup) = tokio::time::timeout(std::time::Duration::from_secs(8), async {
        loop {
            if let Some(ServerMsg::SharedSshSetup { session_id, setup }) = target.recv().await {
                break (session_id, setup);
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(setup.device_id, f.device);
    assert_eq!(setup.owner_user_id, f.owner.id);
    assert_eq!(setup.recipient_user_id, f.recipient.id);
    // The share's account crosses to the device, never the policy's (the fixture's is daemon).
    assert_eq!(
        setup.account_mode,
        meshharbor_remote_control::models::SshAccountMode::Named
    );
    assert_eq!(setup.account.as_deref(), Some("alice"));
    let ctx = meshharbor_core::AgentCtx {
        conn_id: format!("shared-ssh-test-{sid}"),
        agent_id: f.device,
        tenant_id: f.tenant,
        owner_user_id: f.owner.id,
        agent_version: "fixture".into(),
        os: OsKind::Linux,
        dialed_tid: None,
        conn_established_ms: 0,
        tx,
    };
    let handler = meshharbor_mod_network::agent_socket::NetworkAgentSocket::new(
        f.app.state.modules.network.as_ref().unwrap().clone(),
    );
    handler.hello(&ctx).await;
    handler
        .handle(
            &ctx,
            ClientMsg::SharedSshPrepared {
                session_id: sid,
                accepted: true,
            },
        )
        .await;
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        serde_json::to_string(&ClientMsg::TunnelOpen {
            agent_id: f.device,
            transport: "webrtc-dc-v1".into(),
            open_nonce: None,
            derp_pubkey: None,
            net_grant: None,
        })
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();
    let opened = shared_ssh_next(&mut ws).await;
    assert!(matches!(opened,ServerMsg::TunnelOpened {session_id,..} if session_id==sid));
    (grant, ws, sid, setup, ctx, handler, target)
}
async fn shared_ssh_next(ws: &mut SharedSshWs) -> meshharbor_remote_control::signaling::ServerMsg {
    use futures::StreamExt;
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
        loop {
            let message = ws
                .next()
                .await
                .expect("shared SSH socket closed before expected message")
                .expect("shared SSH transport failed before expected message");
            if let tokio_tungstenite::tungstenite::Message::Text(t) = message {
                break serde_json::from_str(&t).unwrap();
            }
            assert!(
                !matches!(message, tokio_tungstenite::tungstenite::Message::Close(_)),
                "shared SSH closed before expected message"
            );
        }
    })
    .await
    .unwrap()
}
#[tokio::test]
async fn device_share_shared_ssh_metadata_caps_and_bearer_only_recipient_boundary() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let f = shared_ssh_fixture().await;
    let grant = create(&f).await["id"].as_str().unwrap().to_owned();
    let _registered = f
        .app
        .state
        .modules
        .fleet
        .as_ref()
        .unwrap()
        .rc_hub
        .register_agent(
            f.device,
            f.tenant,
            f.owner.id,
            OsKind::Linux,
            4,
            false,
            false,
        );
    let response = f
        .app
        .auth_get(
            &format!("/api/device-shares/{grant}/ssh"),
            &f.recipient.token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let value: Value = response.json().await.unwrap();
    assert_eq!(value["id"], f.device.to_hex());
    assert_eq!(value["host_pubkey"], shared_ssh_public_key());
    assert!(value.get("tenant_id").is_none());
    assert!(value.get("token").is_none());
    let hidden = f
        .app
        .auth_get(
            &format!("/api/device-shares/{grant}/ssh"),
            &f.outsider.token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(hidden.status().as_u16(), 404);
    let hidden_body = hidden.bytes().await.unwrap();
    let missing_grant = ObjectId::new();
    let missing = f
        .app
        .auth_get(
            &format!("/api/device-shares/{missing_grant}/ssh"),
            &f.outsider.token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);
    let missing_body = missing.bytes().await.unwrap();
    assert_eq!(
        hidden_body, missing_body,
        "wrong-recipient and missing-grant HTTP bodies must be byte-identical"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&hidden_body).unwrap(),
        json!({"error":"not_found","message":"Resource not found"}),
        "both denials use the existing generic missing-resource body"
    );
    assert!(
        !f.app
            .state
            .tenants
            .is_member(f.tenant, f.recipient.id)
            .await
            .unwrap()
    );
    let mut url = reqwest::Url::parse(&format!(
        "ws://{}/api/device-shares/{grant}/ssh/ws",
        f.app.addr
    ))
    .unwrap();
    url.query_pairs_mut()
        .append_pair("public_key", &shared_ssh_public_key());
    let mut request = url.as_str().into_client_request().unwrap();
    request.headers_mut().insert(
        "Cookie",
        format!("access_token={}", f.recipient.token)
            .parse()
            .unwrap(),
    );
    request
        .headers_mut()
        .insert("Origin", "https://unrelated.example.test".parse().unwrap());
    let denied = tokio_tungstenite::connect_async(request).await.unwrap_err();
    assert!(
        matches!(denied,tokio_tungstenite::tungstenite::Error::Http(r) if r.status().as_u16()==401)
    );
    // A valid bearer removes the cookie-only/CSWSH refusal, but must still
    // take the SAME recipient-bound PDP before any WebSocket upgrade.
    let mut outsider_request = url.as_str().into_client_request().unwrap();
    outsider_request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", f.outsider.token).parse().unwrap(),
    );
    let denied = tokio_tungstenite::connect_async(outsider_request)
        .await
        .unwrap_err();
    let tokio_tungstenite::tungstenite::Error::Http(denied) = denied else {
        panic!("expected the non-recipient WebSocket handshake to fail at HTTP authorization");
    };
    assert_eq!(denied.status().as_u16(), 404);
    assert_eq!(denied.body().as_deref(), Some(hidden_body.as_ref()));
    let mut absent_url = url.clone();
    absent_url.set_path(&format!("/api/device-shares/{missing_grant}/ssh/ws"));
    let mut absent_request = absent_url.as_str().into_client_request().unwrap();
    absent_request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", f.outsider.token).parse().unwrap(),
    );
    let absent = tokio_tungstenite::connect_async(absent_request)
        .await
        .unwrap_err();
    let tokio_tungstenite::tungstenite::Error::Http(absent) = absent else {
        panic!("expected a missing-grant WebSocket handshake to fail at HTTP authorization");
    };
    assert_eq!(absent.status().as_u16(), 404);
    assert_eq!(
        absent.body(),
        denied.body(),
        "WebSocket rejection must not reveal grant existence"
    );
    f.app
        .db
        .collection::<Agent>("agents")
        .update_one(
            doc! {"_id":f.device},
            doc! {"$set":{"capabilities.rpc":["ssh","ssh-consent","shared-session-lease-v1"]}},
        )
        .await
        .unwrap();
    assert_eq!(
        f.app
            .auth_get(
                &format!("/api/device-shares/{grant}/ssh"),
                &f.recipient.token
            )
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403,
        "old native agent cannot silently ignore typed stream scope"
    );
}
#[tokio::test]
async fn device_share_shared_ssh_typed_single_flow_and_exact_target_reply_guard() {
    use futures::{SinkExt, StreamExt};
    use meshharbor_core::AgentMsgHandler;
    use meshharbor_remote_control::signaling::{ClientMsg, ServerMsg};
    let f = shared_ssh_fixture().await;
    let (_grant, mut ws, sid, setup, ctx, handler, mut target) = shared_ssh_start(&f).await;
    let send = ClientMsg::TunnelSdpOffer {
        session_id: sid,
        sdp: "fixture-signaling-only-offer".into(),
    };
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        serde_json::to_string(&send).unwrap().into(),
    ))
    .await
    .unwrap();
    let offer = tokio::time::timeout(std::time::Duration::from_secs(5), target.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(offer,ServerMsg::TunnelSdpOffer {shared_lease:Some(ref lease),..} if lease==&setup.shared_lease)
    );
    let mut wrong = ctx.clone();
    wrong.agent_id = ObjectId::new();
    handler
        .handle(
            &wrong,
            ClientMsg::TunnelSdpAnswer {
                session_id: sid,
                sdp: "forged-other-device".into(),
            },
        )
        .await;
    handler
        .handle(
            &ctx,
            ClientMsg::TunnelSdpAnswer {
                session_id: sid,
                sdp: "exact-device-signaling-only".into(),
            },
        )
        .await;
    assert!(
        matches!(shared_ssh_next(&mut ws).await,ServerMsg::TunnelSdpAnswer {sdp,..} if sdp=="exact-device-signaling-only")
    );
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        serde_json::to_string(&ClientMsg::SharedSshConnect {
            session_id: sid,
            flow_id: 7,
        })
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();
    assert!(
        matches!(tokio::time::timeout(std::time::Duration::from_secs(5),target.recv()).await.unwrap().unwrap(),ServerMsg::SharedSshForward {session_id,flow_id:7} if session_id==sid)
    );
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        serde_json::to_string(&ClientMsg::TcpForwardRequest {
            session_id: sid,
            flow_id: 8,
            dst_host: "10.0.0.1".into(),
            dst_port: 22,
        })
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();
    assert!(
        matches!(tokio::time::timeout(std::time::Duration::from_secs(5),target.recv()).await.unwrap().unwrap(),ServerMsg::TunnelTerminate {session_id,..} if session_id==sid)
    );
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next()).await;
}
#[tokio::test]
async fn device_share_shared_ssh_live_revoke_stops_scope_and_lease_echo() {
    use meshharbor_core::AgentMsgHandler;
    use meshharbor_remote_control::signaling::{ClientMsg, ServerMsg};
    let f = shared_ssh_fixture().await;
    let (grant, mut ws, sid, setup, ctx, handler, mut target) = shared_ssh_start(&f).await;
    handler
        .handle(
            &ctx,
            ClientMsg::SharedSshLeaseChallenge {
                session_id: sid,
                grant_id: setup.shared_lease.grant_id,
                lease_epoch: setup.shared_lease.lease_epoch.clone(),
                challenge_id: 1,
            },
        )
        .await;
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(5), target.recv())
            .await
            .unwrap()
            .unwrap(),
        ServerMsg::SharedSshLeaseRenewal {
            challenge_id: 1,
            ..
        }
    ));
    assert!(
        f.app
            .auth_post(
                &format!("/api/device-shares/{grant}/revoke"),
                &f.owner.token
            )
            .json(&json!({"expected_revision":0}))
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    assert!(
        matches!(tokio::time::timeout(std::time::Duration::from_secs(6),target.recv()).await.unwrap().unwrap(),ServerMsg::TunnelTerminate {session_id,..} if session_id==sid)
    );
    handler
        .handle(
            &ctx,
            ClientMsg::SharedSshLeaseChallenge {
                session_id: sid,
                grant_id: setup.shared_lease.grant_id,
                lease_epoch: setup.shared_lease.lease_epoch,
                challenge_id: 2,
            },
        )
        .await;
    assert!(
        target.try_recv().is_err(),
        "revoked grant cannot receive a renewal"
    );
    // Revocation may close the origin socket directly; it need not flush a
    // queued TunnelTerminate before dropping the transport. EOF is terminal,
    // never a reason to spin in a ready-future loop.
    {
        use futures::StreamExt;
        tokio::time::timeout(std::time::Duration::from_secs(6), async {
            loop {
                match ws.next().await {
                    None
                    | Some(Err(_))
                    | Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) => break,
                    Some(Ok(_)) => {}
                }
            }
        })
        .await
        .expect("revoked shared SSH origin socket must close");
    }
    assert!(
        !f.app
            .state
            .tenants
            .is_member(f.tenant, f.recipient.id)
            .await
            .unwrap()
    );
}

// Native shared-SSH authentication: real HTTP/Mongo + existing real WS fixture.
async fn native_ssh_login(
    f: &Fixture,
    username: &str,
    password: &str,
    grant: &str,
) -> reqwest::Response {
    f.app
        .client
        .post(f.app.url("/api/auth/native/share-ssh/login"))
        .json(&json!({"username":username,"password":password,"share_grant_id":grant}))
        .send()
        .await
        .unwrap()
}
/// Browser approval authenticates only this SSH request, never the CLI as an
/// account. This first slice uses real HTTP/isolated Mongo, without a live agent,
/// WebSocket or SSH process. Every identity and proof belongs to this fixture.
#[tokio::test]
async fn browser_shared_ssh_authorization_requires_approval_and_never_yields_account_token() {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let f = fixture().await;
    // Authorization cannot override default-off org/device SSH policy. Only
    // this synthetic HTTP fixture permits SSH; it still has no live agent.
    f.app
        .db
        .collection::<bson::Document>("tenants")
        .update_one(
            doc! {"_id": f.tenant},
            doc! {"$set": {"settings.remote_ssh_enabled": true}},
        )
        .await
        .unwrap();
    f.app
        .db
        .collection::<Agent>("agents")
        .update_one(
            doc! {"_id": f.device},
            doc! {"$set": {"ssh_policy.mode": "on"}},
        )
        .await
        .unwrap();
    let share = create(&f).await["id"].as_str().unwrap().to_owned();
    let public_key = shared_ssh_public_key();
    let verifier = "x17-synthetic-device-proof-verifier-012345678901234567890123456789";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let started = f
        .app
        .client
        .post(f.app.url("/api/native/share-ssh/authorizations"))
        .json(&json!({
            "share_grant_id": share,
            "public_key": public_key,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "session_secs": 60,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        started.status().as_u16(),
        201,
        "a native SSH request must provide an explicit browser-approval flow"
    );
    assert!(
        started
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .is_none()
    );
    let started: Value = started.json().await.unwrap();
    assert!(started.get("access_token").is_none());
    assert!(started.get("refresh_token").is_none());
    let authorization = started["authorization_id"].as_str().unwrap();
    let user_code = started["user_code"].as_str().unwrap();
    let device_code = started["device_code"].as_str().unwrap();
    let verification_uri = started["verification_uri"].as_str().unwrap();
    assert!(!authorization.is_empty() && !user_code.is_empty() && !device_code.is_empty());
    assert!(started["expires_in"].as_u64().is_some_and(|n| n > 0));
    assert!(started["interval"].as_u64().is_some_and(|n| n > 0));
    let approval_url = reqwest::Url::parse(verification_uri).unwrap();
    let frontend = reqwest::Url::parse(&f.app.settings.app.frontend_url).unwrap();
    assert_eq!(approval_url.origin(), frontend.origin());
    assert!(approval_url.username().is_empty() && approval_url.password().is_none());
    assert!(approval_url.query().is_none() && approval_url.fragment().is_none());
    for secret in [user_code, device_code, verifier] {
        assert!(
            !verification_uri.contains(secret),
            "approval URL must carry no proof or code"
        );
    }

    let exchange_body = json!({"device_code": device_code, "code_verifier": verifier});
    let exchange = || {
        f.app
            .client
            .post(f.app.url("/api/native/share-ssh/authorizations/exchange"))
            .json(&exchange_body)
    };
    let pending = exchange().send().await.unwrap();
    assert_eq!(pending.status().as_u16(), 409);
    assert!(
        pending
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .is_none()
    );
    let pending: Value = pending.json().await.unwrap();
    assert_eq!(pending["error"], "authorization_pending");
    for field in ["grant", "access_token", "refresh_token"] {
        assert!(
            pending.get(field).is_none(),
            "unapproved exchange must return no credential"
        );
    }

    let decision_url = f.app.url(&format!(
        "/api/native/share-ssh/authorizations/{authorization}/decision"
    ));
    let preview = browser_ssh_preview(&f, authorization, user_code).await;
    let decision = json!({"user_code": user_code, "approve": true,
        "expected_scope_revision": preview["scope_revision"]});
    let trusted_origin = frontend.origin().ascii_serialization();
    // A real recipient cookie is necessary; it is not enough for an arbitrary
    // signed-in account or a foreign origin to submit the approval form.
    for (token, origin) in [
        (f.outsider.token.as_str(), trusted_origin.as_str()),
        (
            f.recipient.token.as_str(),
            "https://x17-untrusted-origin.example.invalid",
        ),
    ] {
        let denied = f
            .app
            .client
            .post(&decision_url)
            .header("Cookie", format!("access_token={token}"))
            .header("Origin", origin)
            .json(&decision)
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status().as_u16(), 403);
    }
    let still_pending = exchange().send().await.unwrap();
    assert_eq!(still_pending.status().as_u16(), 409);
    assert_eq!(
        still_pending.json::<Value>().await.unwrap()["error"],
        "authorization_pending"
    );
    let approved = f
        .app
        .client
        .post(&decision_url)
        .header("Cookie", format!("access_token={}", f.recipient.token))
        .header("Origin", &trusted_origin)
        .json(&decision)
        .send()
        .await
        .unwrap();
    assert_eq!(approved.status().as_u16(), 200);
    assert!(
        approved
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .is_none()
    );
    assert_eq!(
        approved.json::<Value>().await.unwrap()["status"],
        "approved"
    );

    let exchanged = exchange().send().await.unwrap();
    assert_eq!(exchanged.status().as_u16(), 200);
    assert!(
        exchanged
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .is_none()
    );
    let exchanged: Value = exchanged.json().await.unwrap();
    assert!(exchanged.get("access_token").is_none());
    assert!(exchanged.get("refresh_token").is_none());
    let grant = exchanged["grant"].as_str().unwrap();
    assert!(!grant.is_empty());
    assert!(!verification_uri.contains(grant));
    assert!(exchanged["expires_in"].as_u64().is_some_and(|n| n > 0));
    assert_eq!(
        exchanged["scope"],
        json!({
            "operation": "ssh",
            "share_grant_id": share,
            "device_id": f.device.to_hex(),
            "recipient_user_id": f.recipient.id.to_hex(),
            "public_key": public_key,
            "session_secs": 60,
        }),
        "only the approved recipient/share/device/key/SSH request may be delegated"
    );
    assert_eq!(
        f.app
            .auth_get("/api/auth/me", &f.recipient.token)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200,
        "positive control: the ordinary account endpoint exists and accepts the recipient"
    );
    assert_eq!(
        f.app
            .auth_get("/api/auth/me", grant)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401,
        "a browser-approved SSH grant must never authenticate the CLI as an account"
    );
}

#[tokio::test]
async fn browser_shared_ssh_anonymous_start_limits_each_share_across_clients() {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let f = fixture_with_settings(|s| {
        // Only this isolated HTTP app trusts its loopback test proxy. Each XFF
        // address below represents a different client observed by that proxy.
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
    })
    .await;
    let mut shares = Vec::new();
    for recipient in [f.recipient.id, f.outsider.id] {
        let mut body = create_body(&f);
        body["recipient_user_id"] = json!(recipient.to_hex());
        let created = f
            .app
            .auth_post("/api/device-shares", &f.owner.token)
            .header("X-Forwarded-For", "192.0.2.250")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(created.status().as_u16(), 200);
        let created: Value = created.json().await.unwrap();
        shares.push(created["id"].as_str().unwrap().to_owned());
    }
    assert_ne!(shares[0], shares[1]);
    let verifier = "x17-synthetic-share-rate-verifier-012345678901234567890123456789";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let url = f.app.url("/api/native/share-ssh/authorizations");
    let mut body = json!({
        "share_grant_id": shares[0],
        "public_key": shared_ssh_public_key(),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "session_secs": 60,
    });
    for client in 1..=8 {
        let started = f
            .app
            .client
            .post(&url)
            .header("X-Forwarded-For", format!("192.0.2.{client}"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(started.status().as_u16(), 201, "client {client}");
    }
    let limited = f
        .app
        .client
        .post(&url)
        .header("X-Forwarded-For", "192.0.2.9")
        .json(&body)
        .send()
        .await
        .unwrap();
    body["share_grant_id"] = json!(shares[1]);
    let other_share = f
        .app
        .client
        .post(&url)
        .header("X-Forwarded-For", "192.0.2.9")
        .json(&body)
        .send()
        .await
        .unwrap();
    // Ten starts remain below the global 64 slots, and this ninth client has
    // made only two: rejecting the first share must be a share-specific limit.
    assert_eq!(other_share.status().as_u16(), 201);
    assert_eq!(limited.status().as_u16(), 429);
}

#[tokio::test]
async fn browser_shared_ssh_anonymous_start_does_not_enumerate_existing_or_unknown_shares() {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let f = fixture_with_settings(|s| {
        s.app.business_trusted_proxy_cidrs = vec!["127.0.0.1/32".into()];
        s.app.rate_limit_trusted_hops = 0;
    })
    .await;
    let created = f
        .app
        .auth_post("/api/device-shares", &f.owner.token)
        .header("X-Forwarded-For", "192.0.2.250")
        .json(&create_body(&f))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 200);
    let created: Value = created.json().await.unwrap();
    let existing = created["id"].as_str().unwrap().to_owned();
    let unknown_id = ObjectId::new();
    assert!(
        f.app
            .db
            .collection::<DeviceShareGrant>(DeviceShareGrant::COLLECTION)
            .find_one(doc! {"_id": unknown_id})
            .await
            .unwrap()
            .is_none()
    );
    let verifier = "x17-synthetic-share-enumeration-verifier-012345678901234567890123456789";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let url = f.app.url("/api/native/share-ssh/authorizations");
    let verification_uri = format!(
        "{}/native/share-ssh/approve",
        f.app.settings.app.frontend_url.trim_end_matches('/')
    );
    let mut successful_shapes = Vec::new();
    let mut limited_shapes = Vec::new();
    // Each of the eighteen requests has a distinct client IP; only sixteen
    // reserve slots. Neither the per-client 8 nor global 64 limit is reached.
    for (network, share) in [("192.0.2", existing), ("198.51.100", unknown_id.to_hex())] {
        for client in 1..=9 {
            let response = f
                .app
                .client
                .post(&url)
                .header("X-Forwarded-For", format!("{network}.{client}"))
                .json(&json!({
                    "share_grant_id": share,
                    "public_key": shared_ssh_public_key(),
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "session_secs": 60,
                }))
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status().as_u16(),
                if client <= 8 { 201 } else { 429 }
            );
            let headers = response.headers();
            assert_eq!(headers.get("content-type").unwrap(), "application/json");
            assert_eq!(headers.get("cache-control").unwrap(), "no-store");
            assert_eq!(headers.get("pragma").unwrap(), "no-cache");
            assert_eq!(
                headers.get("retry-after").and_then(|v| v.to_str().ok()),
                if client <= 8 { None } else { Some("300") }
            );
            for header in ["set-cookie", "location", "www-authenticate"] {
                assert!(headers.get_all(header).iter().next().is_none());
            }
            let header_shape: Vec<_> = ["content-type", "cache-control", "pragma", "retry-after"]
                .into_iter()
                .map(|name| {
                    (
                        name,
                        headers
                            .get_all(name)
                            .iter()
                            .map(|value| value.to_str().unwrap().to_owned())
                            .collect::<Vec<_>>(),
                    )
                })
                .collect();
            let mut body: Value = response.json().await.unwrap();
            if client <= 8 {
                // An exact field allowlist excludes recipient/owner, device,
                // OS account, policy, grant and account-token metadata.
                let mut keys: Vec<_> = body
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect();
                keys.sort_unstable();
                assert_eq!(
                    keys,
                    [
                        "authorization_id",
                        "device_code",
                        "expires_in",
                        "interval",
                        "user_code",
                        "verification_uri"
                    ]
                );
                assert!(ObjectId::parse_str(body["authorization_id"].as_str().unwrap()).is_ok());
                assert_ne!(body["authorization_id"].as_str().unwrap(), share);
                assert_eq!(
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(body["device_code"].as_str().unwrap())
                        .unwrap()
                        .len(),
                    32
                );
                assert_eq!(
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(body["user_code"].as_str().unwrap())
                        .unwrap()
                        .len(),
                    9
                );
                assert_eq!(body["verification_uri"], verification_uri);
                assert_eq!(body["expires_in"], 300);
                assert_eq!(body["interval"], 1);
                // Compare response shapes without printing synthetic codes.
                for field in ["authorization_id", "device_code", "user_code"] {
                    body[field] = json!("<opaque>");
                }
                successful_shapes.push((body, header_shape));
            } else {
                assert_eq!(body, json!({"error": "authorization_rate_limited"}));
                limited_shapes.push((body, header_shape));
            }
        }
    }
    assert_eq!(successful_shapes.len(), 16);
    assert!(
        successful_shapes
            .iter()
            .all(|shape| shape == &successful_shapes[0])
    );
    assert_eq!(limited_shapes.len(), 2);
    assert_eq!(limited_shapes[0], limited_shapes[1]);
}

async fn assert_browser_ssh_request_pending(f: &Fixture, device_code: &str, verifier: &str) {
    let response = f
        .app
        .client
        .post(f.app.url("/api/native/share-ssh/authorizations/exchange"))
        .json(&json!({"device_code": device_code, "code_verifier": verifier}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 409);
    assert!(
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .is_none()
    );
    let body: Value = response.json().await.unwrap();
    assert_eq!(body, json!({"error": "authorization_pending"}));
}

#[tokio::test]
async fn browser_shared_ssh_preview_requires_recipient_and_binds_explicit_decision_to_scope() {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let f = shared_ssh_fixture().await;
    let mut share_body = create_body(&f);
    // Keep the share lifetime longer than both the pending request and session,
    // so the displayed request expiry and session maximum are distinct facts.
    share_body["expires_in_secs"] = json!(3600);
    let created = f
        .app
        .auth_post("/api/device-shares", &f.owner.token)
        .json(&share_body)
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 200);
    let created: Value = created.json().await.unwrap();
    let share = created["id"].as_str().unwrap();
    let verifier = "x17-synthetic-scope-preview-verifier-012345678901234567890123456789";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let before_start = DateTime::now().timestamp_millis();
    let started = f
        .app
        .client
        .post(f.app.url("/api/native/share-ssh/authorizations"))
        .json(&json!({
            "share_grant_id": share,
            "public_key": shared_ssh_public_key(),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "session_secs": 90,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(started.status().as_u16(), 201);
    let started: Value = started.json().await.unwrap();
    let after_start = DateTime::now().timestamp_millis();
    let authorization = started["authorization_id"].as_str().unwrap();
    let user_code = started["user_code"].as_str().unwrap();
    let device_code = started["device_code"].as_str().unwrap();
    let base = format!("/api/native/share-ssh/authorizations/{authorization}");
    let origin = reqwest::Url::parse(&f.app.settings.app.frontend_url)
        .unwrap()
        .origin()
        .ascii_serialization();
    let preview = f
        .app
        .client
        .post(f.app.url(&format!("{base}/preview")))
        .header("Cookie", format!("access_token={}", f.recipient.token))
        .header("Origin", &origin)
        .json(&json!({"user_code": user_code}))
        .send()
        .await
        .unwrap();
    // This is the first new behavior: the current backend returns HTTP 404.
    assert_eq!(preview.status().as_u16(), 200);
    assert_eq!(preview.headers().get("cache-control").unwrap(), "no-store");
    assert!(
        preview
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .is_none()
    );
    let preview: Value = preview.json().await.unwrap();
    // Values come from the fixture's actual user, device, share and request,
    // never from a scope object supplied in the preview/decision JSON.
    assert_eq!(preview["authorization_id"], authorization);
    assert_eq!(preview["recipient"]["id"], f.recipient.id.to_hex());
    assert_eq!(preview["recipient"]["username"], "share_recipient");
    assert_eq!(preview["recipient"]["display_name"], "share_recipient");
    assert_eq!(preview["device"]["id"], f.device.to_hex());
    assert_eq!(preview["device"]["name"], "One shared box");
    assert_eq!(preview["device"]["os"], "linux");
    assert_eq!(preview["ssh_account"], "alice");
    assert_eq!(preview["session_secs"], 90);
    let expiry = preview["request_expires_at_ms"].as_i64().unwrap();
    assert!((before_start + 300_000..=after_start + 300_000).contains(&expiry));
    let revision = preview["scope_revision"].as_str().unwrap();
    assert!(!revision.is_empty());
    assert!(revision.is_ascii());
    for field in [
        "grant",
        "device_code",
        "user_code",
        "access_token",
        "refresh_token",
    ] {
        assert!(preview.get(field).is_none());
    }
    assert_browser_ssh_request_pending(&f, device_code, verifier).await;

    let wrong_code = format!(
        "{}{}",
        &user_code[..user_code.len() - 1],
        if user_code.ends_with('a') { 'b' } else { 'a' }
    );
    for (token, request_origin, code, expected) in [
        (Some(&f.outsider.token), origin.as_str(), user_code, 403),
        (
            Some(&f.recipient.token),
            origin.as_str(),
            wrong_code.as_str(),
            403,
        ),
        (
            Some(&f.recipient.token),
            "https://untrusted.example.test",
            user_code,
            403,
        ),
        (None, origin.as_str(), user_code, 401),
    ] {
        let mut request = f
            .app
            .client
            .post(f.app.url(&format!("{base}/preview")))
            .header("Origin", request_origin)
            .json(&json!({"user_code": code}));
        if let Some(token) = token {
            request = request.header("Cookie", format!("access_token={token}"));
        }
        let refused = request.send().await.unwrap();
        assert_eq!(refused.status().as_u16(), expected);
        assert!(
            refused
                .headers()
                .get_all("set-cookie")
                .iter()
                .next()
                .is_none()
        );
        let refused: Value = refused.json().await.unwrap();
        for field in [
            "recipient",
            "device",
            "ssh_account",
            "scope_revision",
            "grant",
            "device_code",
            "access_token",
            "refresh_token",
        ] {
            assert!(refused.get(field).is_none());
        }
        assert_browser_ssh_request_pending(&f, device_code, verifier).await;
    }

    // Tamper with the server-issued revision while preserving length and
    // characters valid for common opaque hash/base64url representations.
    let wrong_revision = format!(
        "{}{}",
        &revision[..revision.len() - 1],
        if revision.ends_with('a') { 'b' } else { 'a' }
    );
    for body in [
        json!({"user_code": user_code, "approve": true}),
        json!({"user_code": user_code, "approve": true, "expected_scope_revision": wrong_revision}),
    ] {
        let refused = f
            .app
            .client
            .post(f.app.url(&format!("{base}/decision")))
            .header("Cookie", format!("access_token={}", f.recipient.token))
            .header("Origin", &origin)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status().as_u16(), 403);
        assert!(
            refused
                .headers()
                .get_all("set-cookie")
                .iter()
                .next()
                .is_none()
        );
        assert_browser_ssh_request_pending(&f, device_code, verifier).await;
    }
    let approved = f
        .app
        .client
        .post(f.app.url(&format!("{base}/decision")))
        .header("Cookie", format!("access_token={}", f.recipient.token))
        .header("Origin", &origin)
        .json(
            &json!({"user_code": user_code, "approve": true, "expected_scope_revision": revision}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(approved.status().as_u16(), 200);
    assert!(
        approved
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .is_none()
    );
    let approved: Value = approved.json().await.unwrap();
    assert_eq!(approved, json!({"status": "approved"}));
    let exchanged = f
        .app
        .client
        .post(f.app.url("/api/native/share-ssh/authorizations/exchange"))
        .json(&json!({"device_code": device_code, "code_verifier": verifier}))
        .send()
        .await
        .unwrap();
    assert_eq!(exchanged.status().as_u16(), 200);
    assert!(
        exchanged
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .is_none()
    );
    let exchanged: Value = exchanged.json().await.unwrap();
    assert!(exchanged["grant"].as_str().is_some_and(|g| !g.is_empty()));
    assert_eq!(exchanged["scope"]["device_id"], preview["device"]["id"]);
    assert_eq!(
        exchanged["scope"]["recipient_user_id"],
        preview["recipient"]["id"]
    );
    assert_eq!(exchanged["scope"]["session_secs"], preview["session_secs"]);
    for field in ["access_token", "refresh_token", "device_code"] {
        assert!(exchanged.get(field).is_none());
    }
}

async fn browser_ssh_preview(f: &Fixture, authorization: &str, user_code: &str) -> Value {
    let origin = reqwest::Url::parse(&f.app.settings.app.frontend_url)
        .unwrap()
        .origin()
        .ascii_serialization();
    let response = f
        .app
        .client
        .post(f.app.url(&format!(
            "/api/native/share-ssh/authorizations/{authorization}/preview"
        )))
        .header("Cookie", format!("access_token={}", f.recipient.token))
        .header("Origin", origin)
        .json(&json!({"user_code": user_code}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    assert!(
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .is_none()
    );
    response.json().await.unwrap()
}

/// Prepare a synthetic request using public HTTP; no transport or real login.
async fn pending_browser_ssh_request(f: &Fixture) -> (Value, String) {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let share = create(f).await["id"].as_str().unwrap().to_owned();
    let verifier = "x17-synthetic-concurrent-exchange-verifier-012345678901234567890123456789";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let started = f
        .app
        .client
        .post(f.app.url("/api/native/share-ssh/authorizations"))
        .json(&json!({
            "share_grant_id": share,
            "public_key": shared_ssh_public_key(),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "session_secs": 60,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(started.status().as_u16(), 201);
    assert!(
        started
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .is_none()
    );
    let started: Value = started.json().await.unwrap();
    assert!(started.get("access_token").is_none());
    assert!(started.get("refresh_token").is_none());
    (started, verifier.to_owned())
}

async fn approved_browser_ssh_request(f: &Fixture) -> (String, String) {
    let (started, verifier) = pending_browser_ssh_request(f).await;
    let authorization = started["authorization_id"].as_str().unwrap();
    let preview =
        browser_ssh_preview(f, authorization, started["user_code"].as_str().unwrap()).await;
    let origin = reqwest::Url::parse(&f.app.settings.app.frontend_url)
        .unwrap()
        .origin()
        .ascii_serialization();
    let approved = f
        .app
        .client
        .post(f.app.url(&format!(
            "/api/native/share-ssh/authorizations/{authorization}/decision"
        )))
        .header("Cookie", format!("access_token={}", f.recipient.token))
        .header("Origin", origin)
        .json(&json!({"user_code": started["user_code"], "approve": true,
            "expected_scope_revision": preview["scope_revision"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(approved.status().as_u16(), 200);
    assert!(
        approved
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .is_none()
    );
    assert_eq!(
        approved.json::<Value>().await.unwrap()["status"],
        "approved"
    );
    (
        started["device_code"].as_str().unwrap().to_owned(),
        verifier,
    )
}

#[tokio::test]
async fn browser_shared_ssh_changed_snapshot_requires_preview_again_and_blocks_exchange() {
    let f = shared_ssh_fixture().await;
    let (started, verifier) = pending_browser_ssh_request(&f).await;
    let authorization = started["authorization_id"].as_str().unwrap();
    let user_code = started["user_code"].as_str().unwrap();
    let device_code = started["device_code"].as_str().unwrap();
    let mut preview = browser_ssh_preview(&f, authorization, user_code).await;
    let origin = reqwest::Url::parse(&f.app.settings.app.frontend_url)
        .unwrap()
        .origin()
        .ascii_serialization();
    let decision = |revision: &Value| {
        f.app
            .client
            .post(f.app.url(&format!(
                "/api/native/share-ssh/authorizations/{authorization}/decision"
            )))
            .header("Cookie", format!("access_token={}", f.recipient.token))
            .header("Origin", &origin)
            .json(
                &json!({"user_code":user_code, "approve":true, "expected_scope_revision":revision}),
            )
    };
    // Both changes leave this recipient authorized. Rejection must compare the
    // displayed/security snapshot, rather than just ask whether SSH is allowed.
    for change in [
        doc! {"access_policy.allowed_user_ids": [f.recipient.id]},
        doc! {"name": "Renamed shared host"},
    ] {
        f.app
            .db
            .collection::<Agent>("agents")
            .update_one(doc! {"_id": f.device}, doc! {"$set":change})
            .await
            .unwrap();
        let refused = decision(&preview["scope_revision"]).send().await.unwrap();
        assert_eq!(refused.status().as_u16(), 403);
        assert_browser_ssh_request_pending(&f, device_code, &verifier).await;
        let fresh = browser_ssh_preview(&f, authorization, user_code).await;
        assert!(fresh["scope_revision"] != preview["scope_revision"]);
        // Rotating a preview also invalidates the previous token even though
        // the current server scope now matches the newly displayed scope.
        assert_eq!(
            decision(&preview["scope_revision"])
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            403
        );
        preview = fresh;
    }
    assert_eq!(preview["device"]["name"], "Renamed shared host");
    assert_eq!(
        decision(&preview["scope_revision"])
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    // A relaxation after approval cannot silently replace the approved policy.
    f.app
        .db
        .collection::<Agent>("agents")
        .update_one(
            doc! {"_id":f.device},
            doc! {"$set":{"access_policy.allowed_user_ids":[]}},
        )
        .await
        .unwrap();
    let refused = f
        .app
        .client
        .post(f.app.url("/api/native/share-ssh/authorizations/exchange"))
        .json(&json!({"device_code":device_code,"code_verifier":verifier}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status().as_u16(), 403);
    assert!(
        refused
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .is_none()
    );
    let refused: Value = refused.json().await.unwrap();
    for field in ["grant", "access_token", "refresh_token"] {
        assert!(refused.get(field).is_none());
    }
}

#[tokio::test]
async fn browser_shared_ssh_legacy_approval_without_preview_binding_cannot_exchange() {
    let f = shared_ssh_fixture().await;
    let (device_code, verifier) = approved_browser_ssh_request(&f).await;
    // Simulate an unexpired approval produced before displayed-scope binding.
    let changed = f
        .app
        .db
        .collection::<bson::Document>("native_ssh_authorizations")
        .update_one(
            doc! {"state":"approved"},
            doc! {"$unset":{"scope.binding":""}},
        )
        .await
        .unwrap();
    assert_eq!(changed.modified_count, 1);
    let refused = f
        .app
        .client
        .post(f.app.url("/api/native/share-ssh/authorizations/exchange"))
        .json(&json!({"device_code":device_code,"code_verifier":verifier}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status().as_u16(), 403);
    assert!(
        refused
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .is_none()
    );
    let refused: Value = refused.json().await.unwrap();
    for field in ["grant", "access_token", "refresh_token"] {
        assert!(refused.get(field).is_none());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn browser_shared_ssh_exchange_rejects_wrong_proof_and_is_single_use_under_concurrency() {
    let f = shared_ssh_fixture().await;
    let (device_code, verifier) = approved_browser_ssh_request(&f).await;
    let url = f.app.url("/api/native/share-ssh/authorizations/exchange");
    // Same length and valid PKCE characters: this must exercise proof matching,
    // not just the request parser's malformed-input rejection.
    let wrong_verifier = format!("{}X", &verifier[..verifier.len() - 1]);
    assert_eq!(wrong_verifier.len(), verifier.len());
    assert_ne!(wrong_verifier, verifier);
    let wrong = f
        .app
        .client
        .post(&url)
        .json(&json!({"device_code": device_code, "code_verifier": wrong_verifier}))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status().as_u16(), 401);
    assert!(
        wrong
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .is_none()
    );
    let wrong: Value = wrong.json().await.unwrap();
    for field in ["grant", "access_token", "refresh_token"] {
        assert!(wrong.get(field).is_none());
    }

    let proof = json!({"device_code": device_code, "code_verifier": verifier});
    let ready = std::sync::Arc::new(tokio::sync::Barrier::new(5));
    let mut requests = Vec::new();
    for _ in 0..4 {
        let client = f.app.client.clone();
        let url = url.clone();
        let proof = proof.clone();
        let ready = ready.clone();
        requests.push(tokio::spawn(async move {
            ready.wait().await;
            client.post(url).json(&proof).send().await.unwrap()
        }));
    }
    // Release all four real HTTP requests together, without a production hook
    // or inspecting Mongo's authorization state to decide the outcome.
    ready.wait().await;
    let mut responses = Vec::new();
    for request in requests {
        responses.push(request.await.unwrap());
    }
    let mut statuses = Vec::new();
    let mut winner = None;
    for response in responses {
        let status = response.status().as_u16();
        statuses.push(status);
        assert!(
            response
                .headers()
                .get_all("set-cookie")
                .iter()
                .next()
                .is_none()
        );
        let body: Value = response.json().await.unwrap();
        assert!(body.get("access_token").is_none());
        assert!(body.get("refresh_token").is_none());
        if status == 200 {
            let grant = body["grant"].as_str().unwrap();
            assert!(!grant.is_empty());
            assert!(
                winner.replace(grant.to_owned()).is_none(),
                "only one exchange may win"
            );
        } else {
            assert_eq!(status, 403);
            assert!(body.get("grant").is_none());
        }
    }
    statuses.sort_unstable();
    assert_eq!(statuses, vec![200, 403, 403, 403]);
    let winner = winner.expect("the wrong verifier must not consume the approved request");
    let replay = f.app.client.post(&url).json(&proof).send().await.unwrap();
    assert_eq!(replay.status().as_u16(), 403);
    assert!(
        replay
            .headers()
            .get_all("set-cookie")
            .iter()
            .next()
            .is_none()
    );
    let replay: Value = replay.json().await.unwrap();
    for field in ["grant", "access_token", "refresh_token"] {
        assert!(replay.get(field).is_none());
    }
    assert_eq!(
        f.app
            .auth_get("/api/auth/me", &f.recipient.token)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200,
        "positive control: the account endpoint accepts the fixture recipient"
    );
    assert_eq!(
        f.app
            .auth_get("/api/auth/me", &winner)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401,
        "even the successful exchange must not issue an account credential"
    );
}

#[tokio::test]
async fn native_shared_ssh_login_real_http_nonmember_general_access_no_refresh_cookie() {
    let f = fixture().await;
    let id = create(&f).await["id"].as_str().unwrap().to_owned();
    let other = f
        .app
        .state
        .tenants
        .create(
            "Other MFA org".into(),
            "other-native-mfa".into(),
            f.owner.id,
        )
        .await
        .unwrap()
        .id
        .unwrap();
    f.app
        .db
        .collection::<bson::Document>("tenants")
        .update_one(
            doc! {"_id":other},
            doc! {"$set":{"settings.mfa_required":true}},
        )
        .await
        .unwrap();
    let r = native_ssh_login(
        &f,
        "share_recipient",
        "not-a-real-share-fixture-password",
        &id,
    )
    .await;
    assert_eq!(r.status().as_u16(), 200);
    assert!(r.headers().get_all("set-cookie").iter().next().is_none());
    let body: Value = r.json().await.unwrap();
    assert_eq!(body.as_object().unwrap().len(), 3);
    assert_eq!(body["user_id"], f.recipient.id.to_hex());
    assert!(body.get("refresh_token").is_none());
    let token = body["access_token"].as_str().unwrap();
    let claims = f.app.state.auth.verify_access_token(token).unwrap();
    assert_eq!(claims.sub, f.recipient.id.to_hex());
    assert_eq!(claims.approval_revision, 0);
    assert_eq!(body["expires_in"], f.app.settings.jwt.access_token_ttl_secs);
    assert!(
        f.app
            .auth_get("/api/auth/me", token)
            .send()
            .await
            .unwrap()
            .status()
            .is_success(),
        "ordinary account Access authority, not a share-only token"
    );
    assert!(
        !f.app
            .state
            .tenants
            .is_member(f.tenant, f.recipient.id)
            .await
            .unwrap()
    );
    let tenant_url = format!("/api/tenant/{}", f.tenant);
    let owner_response = f
        .app
        .auth_get(&tenant_url, &f.owner.token)
        .send()
        .await
        .unwrap();
    assert_eq!(
        owner_response.status().as_u16(),
        200,
        "positive control: the actual tenant endpoint exists for its owner"
    );
    let denied = f.app.auth_get(&tenant_url, token).send().await.unwrap();
    assert_eq!(denied.status().as_u16(), 403);
    let denied: Value = denied.json().await.unwrap();
    assert_eq!(denied["error"], "not_a_member");
}
#[tokio::test]
async fn native_shared_ssh_login_real_http_account_lifecycle_and_exact_grant_denials() {
    let f = fixture().await;
    let id = create(&f).await["id"].as_str().unwrap().to_owned();
    assert_eq!(
        native_ssh_login(&f, "share_recipient", "wrong-password", &id)
            .await
            .status()
            .as_u16(),
        401
    );
    assert_eq!(
        native_ssh_login(
            &f,
            "share_outsider",
            "not-a-real-share-fixture-password",
            &id
        )
        .await
        .status()
        .as_u16(),
        404
    );
    assert_eq!(
        native_ssh_login(
            &f,
            "share_recipient",
            "not-a-real-share-fixture-password",
            &ObjectId::new().to_hex()
        )
        .await
        .status()
        .as_u16(),
        404
    );
    for state in ["pending", "legacy_unreviewed", "rejected", "suspended"] {
        f.app
            .db
            .collection::<bson::Document>("users")
            .update_one(
                doc! {"_id":f.recipient.id},
                doc! {"$set":{"account_approval.state":state}},
            )
            .await
            .unwrap();
        assert_eq!(
            native_ssh_login(
                &f,
                "share_recipient",
                "not-a-real-share-fixture-password",
                &id
            )
            .await
            .status()
            .as_u16(),
            403,
            "{state}"
        );
    }
    f.app
        .db
        .collection::<bson::Document>("users")
        .update_one(
            doc! {"_id":f.recipient.id},
            doc! {"$set":{"account_approval.state":"approved","is_verified":false}},
        )
        .await
        .unwrap();
    assert_eq!(
        native_ssh_login(
            &f,
            "share_recipient",
            "not-a-real-share-fixture-password",
            &id
        )
        .await
        .status()
        .as_u16(),
        403
    );
    f.app
        .db
        .collection::<bson::Document>("users")
        .update_one(
            doc! {"_id":f.recipient.id},
            doc! {"$set":{"is_verified":true,"deleted_at":DateTime::now()}},
        )
        .await
        .unwrap();
    assert_eq!(
        native_ssh_login(
            &f,
            "share_recipient",
            "not-a-real-share-fixture-password",
            &id
        )
        .await
        .status()
        .as_u16(),
        401
    );
    assert_eq!(
        native_ssh_login(&f, "share_owner", "not-a-real-share-fixture-password", &id)
            .await
            .status()
            .as_u16(),
        403,
        "owner bootstrap cannot substitute explicit recipient approval"
    );
    f.app
        .db
        .collection::<bson::Document>("users")
        .update_one(
            doc! {"_id":f.recipient.id},
            doc! {"$set":{"is_verified":true,"deleted_at":bson::Bson::Null,"password_hash":bson::Bson::Null}},
        )
        .await
        .unwrap();
    assert_eq!(
        native_ssh_login(
            &f,
            "share_recipient",
            "not-a-real-share-fixture-password",
            &id
        )
        .await
        .status()
        .as_u16(),
        401,
        "OAuth-only account must not get a password fallback"
    );
}
#[tokio::test]
async fn native_shared_ssh_mfa_real_metadata_ws_and_web_refresh_cannot_bypass() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let f = shared_ssh_fixture().await;
    let id = create(&f).await["id"].as_str().unwrap().to_owned();
    let _registration = f
        .app
        .state
        .modules
        .fleet
        .as_ref()
        .unwrap()
        .rc_hub
        .register_agent(
            f.device,
            f.tenant,
            f.owner.id,
            OsKind::Linux,
            4,
            false,
            false,
        );
    let refresh = f
        .app
        .state
        .auth
        .generate_tokens_at_revision(
            f.recipient.id,
            "share_recipient@share.example.test",
            "share_recipient",
            0,
        )
        .unwrap()
        .refresh_token;
    for target in ["account", "tenant"] {
        if target == "account" {
            f.app
                .db
                .collection::<bson::Document>("users")
                .update_one(
                    doc! {"_id":f.recipient.id},
                    doc! {"$set":{"is_mfa_enabled":true}},
                )
                .await
                .unwrap();
        } else {
            f.app
                .db
                .collection::<bson::Document>("tenants")
                .update_one(
                    doc! {"_id":f.tenant},
                    doc! {"$set":{"settings.mfa_required":true}},
                )
                .await
                .unwrap();
        }
        assert_eq!(
            native_ssh_login(
                &f,
                "share_recipient",
                "not-a-real-share-fixture-password",
                &id
            )
            .await
            .status()
            .as_u16(),
            403
        );
        // Ordinary Web refresh remains unchanged in this narrowly scoped fix.
        let r = f
            .app
            .client
            .post(f.app.url("/api/auth/refresh"))
            .json(&json!({"refresh_token":refresh}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        let body: Value = r.json().await.unwrap();
        let token = body["access_token"].as_str().unwrap();
        for bearer in [f.recipient.token.as_str(), token] {
            assert_eq!(
                f.app
                    .auth_get(&format!("/api/device-shares/{id}/ssh"), bearer)
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .as_u16(),
                403
            );
            let mut url = reqwest::Url::parse(&format!(
                "ws://{}/api/device-shares/{id}/ssh/ws",
                f.app.addr
            ))
            .unwrap();
            url.query_pairs_mut()
                .append_pair("public_key", &shared_ssh_public_key());
            let mut request = url.as_str().into_client_request().unwrap();
            request
                .headers_mut()
                .insert("Authorization", format!("Bearer {bearer}").parse().unwrap());
            let error = tokio_tungstenite::connect_async(request).await.unwrap_err();
            assert!(
                matches!(error,tokio_tungstenite::tungstenite::Error::Http(r) if r.status().as_u16()==403)
            );
        }
        f.app
            .db
            .collection::<bson::Document>("users")
            .update_one(
                doc! {"_id":f.recipient.id},
                doc! {"$set":{"is_mfa_enabled":false}},
            )
            .await
            .unwrap();
        f.app
            .db
            .collection::<bson::Document>("tenants")
            .update_one(
                doc! {"_id":f.tenant},
                doc! {"$set":{"settings.mfa_required":false}},
            )
            .await
            .unwrap();
    }
}
#[tokio::test]
async fn native_shared_ssh_mfa_real_live_lease_stops_after_account_or_tenant_change() {
    use meshharbor_core::AgentMsgHandler;
    use meshharbor_remote_control::signaling::{ClientMsg, ServerMsg};
    for target in ["account", "tenant"] {
        let f = shared_ssh_fixture().await;
        let (_grant, _ws, sid, setup, ctx, handler, mut peer) = shared_ssh_start(&f).await;
        if target == "account" {
            f.app
                .db
                .collection::<bson::Document>("users")
                .update_one(
                    doc! {"_id":f.recipient.id},
                    doc! {"$set":{"is_mfa_enabled":true}},
                )
                .await
                .unwrap();
        } else {
            f.app
                .db
                .collection::<bson::Document>("tenants")
                .update_one(
                    doc! {"_id":f.tenant},
                    doc! {"$set":{"settings.mfa_required":true}},
                )
                .await
                .unwrap();
        }
        handler
            .handle(
                &ctx,
                ClientMsg::SharedSshLeaseChallenge {
                    session_id: sid,
                    grant_id: setup.shared_lease.grant_id,
                    lease_epoch: setup.shared_lease.lease_epoch,
                    challenge_id: 1,
                },
            )
            .await;
        tokio::time::timeout(std::time::Duration::from_secs(6),async {
            loop {let msg=peer.recv().await.expect("target stream unexpectedly closed");
                assert!(!matches!(msg,ServerMsg::SharedSshLeaseRenewal{session_id,..} if session_id==sid),"MFA-required shared session cannot renew");
                if matches!(msg,ServerMsg::TunnelTerminate{session_id,..} if session_id==sid){break;}
            }
        }).await.expect("current MFA requirement must terminate real shared scope");
    }
}
#[tokio::test]
async fn native_shared_ssh_login_real_http_credential_rate_limit_is_wired() {
    let app = TestApp::spawn_with_settings(|s| {
        s.app.auth_rate_limit_burst = 1;
        s.app.auth_rate_limit_per_min = 1;
    })
    .await;
    let body = json!({"username":"native_rate_fixture","password":"wrong","share_grant_id":ObjectId::new().to_hex()});
    let first = app
        .client
        .post(app.url("/api/auth/native/share-ssh/login"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status().as_u16(), 401);
    let second = app
        .client
        .post(app.url("/api/auth/native/share-ssh/login"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status().as_u16(), 429);
}
#[tokio::test]
async fn native_shared_ssh_login_real_http_expiry_revoke_and_service_scope() {
    let f = fixture().await;
    let id = create(&f).await["id"].as_str().unwrap().to_owned();
    let gid = ObjectId::parse_str(&id).unwrap();
    let grants = f
        .app
        .db
        .collection::<bson::Document>(DeviceShareGrant::COLLECTION);
    grants
        .update_one(
            doc! {"_id":gid},
            doc! {"$set":{"expires_at":DateTime::from_millis(1)}},
        )
        .await
        .unwrap();
    assert_eq!(
        native_ssh_login(
            &f,
            "share_recipient",
            "not-a-real-share-fixture-password",
            &id
        )
        .await
        .status()
        .as_u16(),
        403
    );
    grants.update_one(doc!{"_id":gid},doc!{"$set":{"expires_at":DateTime::from_millis(DateTime::now().timestamp_millis()+60000),"permissions.ssh":false}}).await.unwrap();
    assert_eq!(
        native_ssh_login(
            &f,
            "share_recipient",
            "not-a-real-share-fixture-password",
            &id
        )
        .await
        .status()
        .as_u16(),
        403
    );
    grants
        .update_one(
            doc! {"_id":gid},
            doc! {"$set":{"permissions.ssh":true,"revoked_at":DateTime::now()}},
        )
        .await
        .unwrap();
    assert_eq!(
        native_ssh_login(
            &f,
            "share_recipient",
            "not-a-real-share-fixture-password",
            &id
        )
        .await
        .status()
        .as_u16(),
        403
    );
}

// Linux composed native-login oracle. Separate child HOME/controlling PTY, real
// TestApp auth/PDP + signaling loop + WebRTC/DC + embedded SSH; no mock agent.
#[cfg(all(target_os = "linux", feature = "native-shared-ssh-composed"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "private agent child invoked only by composed parent"]
async fn native_login_agent_child() {
    tracing_subscriber::fmt()
        .with_env_filter("off,webrtc_ice::agent::agent_internal=warn")
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .try_init()
        .expect("isolated agent tracing must install");
    let path = std::path::PathBuf::from(std::env::var("MH_NATIVE_LOGIN_AGENT_CONFIG").unwrap());
    let cfg = meshharbord::config::load(&path).unwrap();
    let (stop, rx) = tokio::sync::watch::channel(false);
    let broker = meshharbord::consent::ConsentBroker::new(
        meshharbord::consent::Mode::AutoGrant,
        path.parent().unwrap().join("consent"),
    )
    .unwrap();
    let (view, _) = tokio::sync::watch::channel(Default::default());
    let device = tokio::spawn(meshharbord::signaling::run(
        meshharbord::signaling::OrgCtx::primary(meshharbord::token_slot::TokenSlot::new(
            cfg.agent_token.clone(),
        )),
        meshharbord::delegate::Delegation::Off,
        cfg,
        meshharbord::encode::EncoderPreference::Software,
        rx,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        view,
        Default::default(),
        broker,
        meshharbord::tunnel::client_mgr::TunnelClientHub::new("native-login-fixture".into()),
        meshharbord::remote_config::RemoteConfigServices::new(
            path,
            std::sync::Arc::new(tokio::sync::Mutex::new(())),
            false,
            false,
        ),
        meshharbord::rc_sessions::RcSessionRegistry::new(),
    ));
    tokio::task::spawn_blocking(|| {
        let mut b = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut b).unwrap();
    })
    .await
    .unwrap();
    let _ = stop.send(true);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(8), device).await;
}
#[cfg(all(target_os = "linux", feature = "native-shared-ssh-composed"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "private actual CLI child invoked only through controlling PTY"]
async fn native_login_cli_child() {
    let path = std::env::var("MH_NATIVE_LOGIN_CLI_CASE").unwrap();
    let x: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let nonce = x["nonce"].as_str().unwrap();
    assert_eq!(nonce.len(), 24);
    assert!(nonce.bytes().all(|b| b.is_ascii_hexdigit()));
    let mode = x["mode"].as_str().unwrap();
    assert!(matches!(mode, "nonce" | "live" | "reopen"));
    let command = if mode == "live" {
        format!("printf 'MH_NATIVE_LOGIN_READY_{nonce}\\n'; sleep 20")
    } else {
        format!("printf 'MH_NATIVE_LOGIN_NONCE_{nonce}\\n'")
    };
    meshharbor_cli::cli::run_from(
        vec![
            "meshharbor".to_owned(),
            "share-ssh".into(),
            "--server".into(),
            x["server"].as_str().unwrap().into(),
            "--share".into(),
            x["grant"].as_str().unwrap().into(),
            "--login".into(),
            "--username".into(),
            "share_recipient".into(),
            "--session-secs".into(),
            "30".into(),
            "--".into(),
            command,
        ],
        meshharbor_cli::cli::Origin::Standalone,
    )
    .await
    .expect("synthetic native CLI failed");
}
#[cfg(all(target_os = "linux", feature = "native-shared-ssh-composed"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_shared_ssh_composed_hidden_prompt_nonce_live_revoke_and_reopen() {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    // Only the test's explicitly created fixture identities. No human account.
    let f = fixture().await;
    assert!(
        f.app.settings.turn.url.is_none() && f.app.settings.turn.worker_urls.is_none(),
        "composed fixture must not use a public TURN server"
    );
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let enroll: Value = f
        .app
        .auth_post(
            &format!("/api/tenant/{}/agent/enroll-token", f.tenant),
            &f.owner.token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut cfg = meshharbord::enrollment::enroll(meshharbord::enrollment::EnrollInputs {
        server_url: &f.app.base_url,
        enrollment_token: enroll["enrollment_token"].as_str().unwrap(),
        machine_id: &format!("native-login-{}", ObjectId::new()),
        machine_name: "native-login-fixture",
        install: None,
    })
    .await
    .unwrap();
    cfg.ssh_enabled = true;
    cfg.ssh_host_key = Some(meshharbord::ssh::generate_host_key().unwrap());
    cfg.ssh_account_mode = Some("daemon".into());
    cfg.enable_remote_browse = false;
    cfg.auto_grant_session = false;
    cfg.exec_enabled = false;
    cfg.remote_config_enabled = false;
    cfg.overlay_enabled = false;
    let expected_host = meshharbord::ssh::host_public_key(&cfg);
    let device = ObjectId::parse_str(&cfg.agent_id).unwrap();
    f.app
        .db
        .collection::<bson::Document>("tenants")
        .update_one(
            doc! {"_id":f.tenant},
            doc! {"$set":{"settings.remote_ssh_enabled":true}},
        )
        .await
        .unwrap();
    f.app.db.collection::<Agent>("agents").update_one(doc!{"_id":device},doc!{"$set":{"ssh_policy.mode":"on","ssh_policy.account_mode":"daemon","ssh_policy.consent_mode":"auto"}}).await.unwrap();
    let config = root.path().join("agent.toml");
    meshharbord::config::save(&config, &cfg).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let agent_log = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.path().join("agent.stderr"))
        .unwrap();
    let mut agent = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "device_share_tests::native_login_agent_child",
            "--ignored",
            "--nocapture",
        ])
        .env("MH_NATIVE_LOGIN_AGENT_CONFIG", &config)
        .env("HOME", root.path())
        .env("XDG_CONFIG_HOME", root.path().join("xdg"))
        .env("TMPDIR", root.path())
        .env("RUST_LOG", "off")
        .env("NO_PROXY", "127.0.0.1,::1,localhost")
        .env("no_proxy", "127.0.0.1,::1,localhost")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(agent_log)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut agent_stdin = agent.stdin.take();
    use futures::FutureExt;
    let outcome=std::panic::AssertUnwindSafe(async {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        assert!(
            agent.try_wait().unwrap().is_none(),
            "real agent exited before online"
        );
        let row = f
            .app
            .db
            .collection::<Agent>("agents")
            .find_one(doc! {"_id":device})
            .await
            .unwrap()
            .unwrap();
        if f.app
            .state
            .modules
            .fleet
            .as_ref()
            .unwrap()
            .rc_hub
            .is_agent_online(device)
            && row.ssh_host_pubkey == expected_host
        {
            use meshharbor_remote_control::models::RpcCap;
            assert!(
                [
                    RpcCap::Ssh,
                    RpcCap::SshConsent,
                    RpcCap::SharedSessionLease,
                    RpcCap::SharedSshStream
                ]
                .iter()
                .all(|c| row.capabilities.has_rpc(*c)),
                "actual agent must advertise real shared SSH enforcement"
            );
            break;
        }
        assert!(
            std::time::Instant::now() < end,
            "real agent/hostkey not published"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let response=f.app.auth_post("/api/device-shares",&f.owner.token).json(&json!({"device_id":device.to_hex(),"recipient_user_id":f.recipient.id.to_hex(),"permissions":{"ssh":true},"tcp_ports":[],"expires_in_secs":120,"ssh_account":std::env::var("MESHHARBOR_SHARED_SSH_TEST_ACCOUNT").unwrap_or_else(|_| "nobody".into())})).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let share: Value = response.json().await.unwrap();
    let grant = share["id"].as_str().unwrap();
    let nonce = ObjectId::new().to_hex();
    assert!(
        !f.app
            .state
            .tenants
            .is_member(f.tenant, f.recipient.id)
            .await
            .unwrap()
    );
    let script = root.path().join("native_login_pty_helper.py");
    std::fs::write(&script, include_str!("fixtures/native_login_pty.py")).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut carrier_offset = 0u64;
    for mode in ["nonce", "live", "reopen"] {
        let case = root.path().join(format!("{mode}.json"));
        let transcript = root.path().join(format!("{mode}.transcript"));
        std::fs::write(
            &case,
            serde_json::to_vec(
                &json!({"mode":mode,"nonce":nonce,"server":f.app.base_url,"grant":grant}),
            )
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&case, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut child = tokio::process::Command::new("/usr/bin/python3")
            .arg(&script)
            .arg(std::env::current_exe().unwrap())
            .arg(&case)
            .arg(&transcript)
            .arg(mode)
            .env("HOME", root.path())
            .env("XDG_CONFIG_HOME", root.path().join("xdg"))
            .env("TMPDIR", root.path())
            .env("RUST_LOG", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        input
            .write_all(b"not-a-real-share-fixture-password\n")
            .await
            .unwrap();
        // Keep the private pipe open: EOF requests helper cleanup on any stage failure.
        let stage = std::panic::AssertUnwindSafe(async {
        let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let mut terminal = None;
        let mut hidden = false;
        let mut revoke_at = None;
        tokio::time::timeout(std::time::Duration::from_secs(45), async {
            while let Some(line) = lines.next_line().await.unwrap() {
                let event: Value = serde_json::from_str(&line).unwrap();
                match event["event"].as_str().unwrap() {
                    "password-entered" => {
                        assert_eq!(event["echo_off"], true);
                        hidden = true;
                    }
                    "remote-ready" => {
                        assert_eq!(mode, "live");
                        assert!(revoke_at.is_none());
                        revoke_at = Some(std::time::Instant::now());
                        let r = f
                            .app
                            .auth_post(
                                &format!("/api/device-shares/{grant}/revoke"),
                                &f.owner.token,
                            )
                            .json(&json!({"expected_revision":0}))
                            .send()
                            .await
                            .unwrap();
                        assert_eq!(r.status().as_u16(), 200);
                    }
                    "cleanup" => {
                        assert_eq!(event["pty_child_reaped"], true);
                    }
                    "terminal" => {
                        terminal = Some(event);
                        break;
                    }
                    _ => panic!("private PTY harness failed; no raw transcript printed"),
                }
            }
        })
        .await
        .expect("composed CLI terminal deadline");
        let result = terminal.expect("PTY helper must give authoritative child terminal");
        println!("COMPOSED_SAFE_TERMINAL mode={mode} evidence={result}");
        assert!(hidden);
        assert_eq!(result["password_absent"], true);
        let raw = std::fs::read(&transcript).unwrap();
        assert!(
            !raw.windows(b"not-a-real-share-fixture-password".len())
                .any(|w| w == b"not-a-real-share-fixture-password")
        );
        if mode != "reopen" {
            let check = tokio::time::timeout(std::time::Duration::from_secs(3),
                tokio::process::Command::new("/usr/bin/python3")
                .arg(&script).arg("--carrier-check")
                .arg(root.path().join("agent.stderr"))
                .arg(carrier_offset.to_string()).output()).await.unwrap().unwrap();
            assert!(check.status.success(), "actual carrier endpoints not proved host-local; private logs retained");
            let carrier: Value = serde_json::from_slice(&check.stdout).unwrap();
            assert_eq!(carrier["host_local_both_endpoints"], true);
            carrier_offset = carrier["end_offset"].as_u64().unwrap();
            println!("COMPOSED_SAFE_CARRIER mode={mode} evidence={carrier}");
        }
        if mode == "nonce" {
            assert_eq!(result["exit"], 0);
            assert_eq!(result["nonce_count"], 1);
        }
        if mode == "live" {
            assert!(revoke_at.unwrap().elapsed() < std::time::Duration::from_secs(8));
            assert_ne!(result["exit"], 0);
            assert_eq!(result["nonce_count"], 1);
        }
        if mode == "reopen" {
            assert_ne!(result["exit"], 0);
            assert_eq!(result["nonce_count"], 0);
            assert_eq!(result["native_login_http403"], true);
            // Same real endpoint/grant/recipient independently confirms actual status;
            // do not infer metadata authorization from arbitrary transcript text.
            let denied = f.app.auth_get(&format!("/api/device-shares/{grant}/ssh"), &f.recipient.token)
                .send().await.unwrap();
            assert_eq!(denied.status().as_u16(), 403);
        }
        }).catch_unwind().await;
        // Never drop/kill the helper before giving it bounded exact-group cleanup.
        drop(input);
        let helper = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
            .await.expect("owned helper cleanup terminal not observed; FAIL, not clean")
            .expect("owned helper wait failed");
        let cleanup_path = std::path::PathBuf::from(format!("{}.cleanup.json", transcript.display()));
        let cleanup: Value = serde_json::from_slice(&std::fs::read(cleanup_path)
            .expect("owned PTY cleanup receipt missing; FAIL, not clean")).unwrap();
        assert_eq!(cleanup["pty_child_reaped"], true);
        if let Err(panic) = stage { std::panic::resume_unwind(panic); }
        assert!(helper.success());
    }
    }).catch_unwind().await;
    drop(agent_stdin.take());
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), agent.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(status.success());
    if let Err(panic) = outcome {
        let path = root.keep();
        eprintln!("PRIVATE_COMPOSED_FAILURE_EVIDENCE={}", path.display());
        std::panic::resume_unwind(panic);
    }
    assert!(
        !f.app
            .state
            .tenants
            .is_member(f.tenant, f.recipient.id)
            .await
            .unwrap()
    );
}

/// An SSH share names the device account it runs as. Without one, with a malformed one, on a
/// Windows device, or on a share that is not SSH, creation is refused; and a row from before the
/// choice existed is refused at use rather than inheriting the device policy's account (root).
#[tokio::test]
async fn device_share_ssh_requires_its_own_account_and_never_inherits_the_policy_account() {
    let f = shared_ssh_fixture().await;
    let post = |body: Value| {
        let f = &f;
        async move {
            f.app
                .auth_post("/api/device-shares", &f.owner.token)
                .json(&body)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    let body = |permissions: Value, account: Option<&str>| {
        let mut b = json!({"device_id":f.device.to_hex(),"recipient_user_id":f.recipient.id.to_hex(),
                           "permissions":permissions,"expires_in_secs":60});
        if let Some(a) = account {
            b["ssh_account"] = json!(a);
        }
        b
    };
    let ssh = json!({"ssh":true});
    assert_eq!(post(body(ssh.clone(), None)).await, 400, "no account");
    for bad in ["", "  ", "root", "Root", "../etc", "a b", "a:b", "x\ny"] {
        assert_eq!(post(body(ssh.clone(), Some(bad))).await, 400, "{bad:?}");
    }
    assert_eq!(
        post(body(json!({"desktop_view":true}), Some("alice"))).await,
        400,
        "an account on a share that is not SSH"
    );
    let agents = f.app.db.collection::<bson::Document>("agents");
    let os = |k: OsKind| bson::to_bson(&k).unwrap();
    agents
        .update_one(
            doc! {"_id":f.device},
            doc! {"$set":{"os":os(OsKind::Windows)}},
        )
        .await
        .unwrap();
    assert_eq!(post(body(ssh.clone(), Some("alice"))).await, 400, "Windows");
    agents
        .update_one(
            doc! {"_id":f.device},
            doc! {"$set":{"os":os(OsKind::Linux)}},
        )
        .await
        .unwrap();
    let r = f
        .app
        .auth_post("/api/device-shares", &f.owner.token)
        .json(&body(ssh.clone(), Some(" alice ")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["ssh_account"], "alice", "trimmed and returned");

    // A legacy row: SSH permission, no account. The policy says daemon (root); it must not apply.
    let now = bson::DateTime::now();
    let legacy = meshharbor_db::models::DeviceShareGrant {
        id: None,
        device_id: f.device,
        tenant_id: f.tenant,
        owner_user_id: f.owner.id,
        recipient_user_id: f.recipient.id,
        permissions: meshharbor_db::models::DeviceSharePermissions {
            ssh: true,
            ..Default::default()
        },
        tcp_ports: vec![],
        created_at: now,
        expires_at: bson::DateTime::from_millis(now.timestamp_millis() + 60_000),
        revoked_at: None,
        revision: 0,
        ssh_account: None,
    };
    let id = f
        .app
        .db
        .collection::<meshharbor_db::models::DeviceShareGrant>(
            meshharbor_db::models::DeviceShareGrant::COLLECTION,
        )
        .insert_one(&legacy)
        .await
        .unwrap()
        .inserted_id
        .as_object_id()
        .unwrap();
    let _registered = f
        .app
        .state
        .modules
        .fleet
        .as_ref()
        .unwrap()
        .rc_hub
        .register_agent(
            f.device,
            f.tenant,
            f.owner.id,
            OsKind::Linux,
            4,
            false,
            false,
        );
    let ok = v["id"].as_str().unwrap();
    let meta = |id: String| {
        let f = &f;
        async move {
            f.app
                .auth_get(&format!("/api/device-shares/{id}/ssh"), &f.recipient.token)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    };
    assert_eq!(
        meta(ok.to_string()).await,
        200,
        "a share with its own account"
    );
    assert_eq!(meta(id.to_hex()).await, 403, "a legacy share without one");
}

/// MeshHarbor — the owner lists, and creates, the device's accounts through the device itself:
/// the route pushes `rc:accounts.request` to the connected device and answers with what the
/// device said, its refusal included. Only the owner; only a device that advertises it; a
/// name the server refuses never reaches the device.
#[tokio::test]
async fn local_accounts_reach_the_device_for_its_owner_only() {
    use meshharbor_remote_control::signaling::{LocalAccount, LocalAccountOp, ServerMsg};
    let f = fixture().await;
    let path = format!("/api/account/devices/{}/local-accounts", f.device.to_hex());
    let get = |token: String| {
        let (f, path) = (&f, path.clone());
        async move {
            let r = f.app.auth_get(&path, &token).send().await.unwrap();
            let status = r.status().as_u16();
            (status, r.json::<Value>().await.unwrap_or(Value::Null))
        }
    };
    let post = |body: Value| {
        let (f, path) = (&f, path.clone());
        async move {
            let r = f
                .app
                .auth_post(&path, &f.owner.token)
                .json(&body)
                .send()
                .await
                .unwrap();
            let status = r.status().as_u16();
            (status, r.json::<Value>().await.unwrap_or(Value::Null))
        }
    };
    assert_eq!(
        get(f.owner.token.clone()).await.0,
        400,
        "no capability advertised"
    );
    f.app
        .db
        .collection::<bson::Document>("agents")
        .update_one(
            doc! {"_id":f.device},
            doc! {"$set":{"capabilities.rpc":["local-accounts-v1"]}},
        )
        .await
        .unwrap();
    assert_eq!(get(f.recipient.token.clone()).await.0, 403, "not the owner");
    assert_eq!(get(f.owner.token.clone()).await.0, 409, "not connected");

    let hub = f.app.state.modules.fleet.as_ref().unwrap().rc_hub.clone();
    let (_tx, _, mut target) = hub.register_agent(
        f.device,
        f.tenant,
        f.owner.id,
        OsKind::Linux,
        4,
        false,
        false,
    );
    let device = tokio::spawn(async move {
        let mut seen = Vec::new();
        while seen.len() < 3 {
            let Some(msg) = target.recv().await else {
                break;
            };
            let ServerMsg::LocalAccountsRequest { request_id, op } = msg else {
                continue;
            };
            let answer = match &op {
                LocalAccountOp::List => Ok(vec![LocalAccount {
                    name: "alice".into(),
                    uid: 1000,
                    admin: false,
                }]),
                LocalAccountOp::Create { name, .. } if name == "taken" => {
                    Err("an account named taken already exists; choose it instead".to_string())
                }
                LocalAccountOp::Create { name, admin } => Ok(vec![LocalAccount {
                    name: name.clone(),
                    uid: 1001,
                    admin: *admin,
                }]),
            };
            hub.deliver_local_accounts(&request_id, answer);
            seen.push(op);
        }
        seen
    });
    let (status, v) = get(f.owner.token.clone()).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["accounts"][0]["name"], "alice");
    for bad in ["root", "Bad", "../x", ""] {
        assert_eq!(
            post(json!({"name":bad,"admin":true})).await.0,
            400,
            "{bad:?}"
        );
    }
    let (status, v) = post(json!({"name":"share1","admin":true})).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(
        v["accounts"][0],
        json!({"name":"share1","uid":1001,"admin":true})
    );
    let (status, v) = post(json!({"name":"taken"})).await;
    assert_eq!(status, 400);
    assert!(v.to_string().contains("The device refused"), "{v}");
    let seen = tokio::time::timeout(std::time::Duration::from_secs(5), device)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        seen,
        vec![
            LocalAccountOp::List,
            LocalAccountOp::Create {
                name: "share1".into(),
                admin: true
            },
            LocalAccountOp::Create {
                name: "taken".into(),
                admin: false
            },
        ],
        "only valid names reached the device"
    );
}
