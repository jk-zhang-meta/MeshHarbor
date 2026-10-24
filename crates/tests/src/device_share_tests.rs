// SPDX-License-Identifier: AGPL-3.0-only
//! Real loopback HTTP + isolated Mongo grant lifecycle; no agent or production host.
use crate::fixtures::test_app::TestApp;
use bson::{DateTime, doc, oid::ObjectId};
use roomler_ai_db::models::{AccountApprovalState, DeviceShareGrant, User};
use roomler_ai_remote_control::models::{Agent, AgentStatus, OsKind};
use roomler_ai_services::dao::agent::AgentDao;
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
    let owner_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.auth.account_approval.enabled = true;
        s.auth.account_approval.owner_user_id = Some(owner_id.to_hex());
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
    json!({"device_id":f.device.to_hex(),"recipient_user_id":f.recipient.id.to_hex(),"permissions":{"ssh":true},"tcp_ports":[22],"expires_in_secs":60})
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
        roomler_core::device_share::authorize(
            &f.app.state,
            f.recipient.id,
            other.id.unwrap(),
            roomler_ai_db::models::DeviceShareOperation::Ssh
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
    use roomler_ai_remote_control::signaling::ServerMsg;
    use std::time::Duration;
    use tokio_tungstenite::{connect_async, tungstenite::Message};
    let f = fixture().await;
    let mut body = create_body(&f);
    body["permissions"] =
        json!({"desktop_view":true,"desktop_control":true,"files_read":true,"files_write":true});
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
            .contains(roomler_ai_remote_control::permissions::Permissions::FILES)
    );
    assert_eq!(request.2, false);
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
    use roomler_ai_remote_control::signaling::ServerMsg;
    use std::time::Duration;
    use tokio_tungstenite::{connect_async, tungstenite::Message};
    let f = fixture().await;
    f.app.set_plan(&f.tenant.to_hex(), "business").await;
    let mut body = create_body(&f);
    body["permissions"] = json!({"desktop_view":true});
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
    use roomler_ai_remote_control::signaling::{ClientMsg, ServerMsg};
    use roomler_core::{AgentCtx, AgentMsgHandler};
    use std::time::Duration;
    use tokio_tungstenite::{connect_async, tungstenite::Message};
    let f = fixture().await;
    let mut body = create_body(&f);
    body["permissions"] = json!({"desktop_view":true});
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
    let handler = roomler_ai_mod_remote::agent_socket::RemoteAgentSocket::new(remote.clone());
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
    roomler_ai_remote_control::signaling::SharedSshSetup,
    roomler_core::AgentCtx,
    roomler_ai_mod_network::agent_socket::NetworkAgentSocket,
    tokio::sync::mpsc::Receiver<roomler_ai_remote_control::signaling::ServerMsg>,
) {
    use futures::SinkExt;
    use roomler_ai_remote_control::signaling::{ClientMsg, ServerMsg};
    use roomler_core::{AgentMsgHandler, AgentSocketLifecycle};
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
    let ctx = roomler_core::AgentCtx {
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
    let handler = roomler_ai_mod_network::agent_socket::NetworkAgentSocket::new(
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
async fn shared_ssh_next(ws: &mut SharedSshWs) -> roomler_ai_remote_control::signaling::ServerMsg {
    use futures::StreamExt;
    tokio::time::timeout(std::time::Duration::from_secs(6), async {
        loop {
            let message = ws.next().await.expect("shared SSH socket closed before expected message")
                .expect("shared SSH transport failed before expected message");
            if let tokio_tungstenite::tungstenite::Message::Text(t) = message {
                break serde_json::from_str(&t).unwrap();
            }
            assert!(!matches!(message, tokio_tungstenite::tungstenite::Message::Close(_)), "shared SSH closed before expected message");
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
    let hidden = f.app
        .auth_get(&format!("/api/device-shares/{grant}/ssh"), &f.outsider.token)
        .send().await.unwrap();
    assert_eq!(hidden.status().as_u16(), 404);
    let hidden_body = hidden.bytes().await.unwrap();
    let missing_grant = ObjectId::new();
    let missing = f.app
        .auth_get(&format!("/api/device-shares/{missing_grant}/ssh"), &f.outsider.token)
        .send().await.unwrap();
    assert_eq!(missing.status().as_u16(), 404);
    let missing_body = missing.bytes().await.unwrap();
    assert_eq!(hidden_body, missing_body, "wrong-recipient and missing-grant HTTP bodies must be byte-identical");
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
    let absent = tokio_tungstenite::connect_async(absent_request).await.unwrap_err();
    let tokio_tungstenite::tungstenite::Error::Http(absent) = absent else {
        panic!("expected a missing-grant WebSocket handshake to fail at HTTP authorization");
    };
    assert_eq!(absent.status().as_u16(), 404);
    assert_eq!(absent.body(), denied.body(), "WebSocket rejection must not reveal grant existence");
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
    use roomler_ai_remote_control::signaling::{ClientMsg, ServerMsg};
    use roomler_core::AgentMsgHandler;
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
    use roomler_ai_remote_control::signaling::{ClientMsg, ServerMsg};
    use roomler_core::AgentMsgHandler;
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
                    None | Some(Err(_)) | Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) => break,
                    Some(Ok(_)) => {}
                }
            }
        }).await.expect("revoked shared SSH origin socket must close");
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
    use roomler_ai_remote_control::signaling::{ClientMsg, ServerMsg};
    use roomler_core::AgentMsgHandler;
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
    let cfg = roomlerd::config::load(&path).unwrap();
    let (stop, rx) = tokio::sync::watch::channel(false);
    let broker = roomlerd::consent::ConsentBroker::new(
        roomlerd::consent::Mode::AutoGrant,
        path.parent().unwrap().join("consent"),
    )
    .unwrap();
    let (view, _) = tokio::sync::watch::channel(Default::default());
    let device = tokio::spawn(roomlerd::signaling::run(
        roomlerd::signaling::OrgCtx::primary(roomlerd::token_slot::TokenSlot::new(
            cfg.agent_token.clone(),
        )),
        roomlerd::delegate::Delegation::Off,
        cfg,
        roomlerd::encode::EncoderPreference::Software,
        rx,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        view,
        Default::default(),
        broker,
        roomlerd::tunnel::client_mgr::TunnelClientHub::new("native-login-fixture".into()),
        roomlerd::remote_config::RemoteConfigServices::new(
            path,
            std::sync::Arc::new(tokio::sync::Mutex::new(())),
            false,
            false,
        ),
        roomlerd::rc_sessions::RcSessionRegistry::new(),
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
    roomler_cli::cli::run_from(
        vec![
            "roomler".to_owned(),
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
        roomler_cli::cli::Origin::Standalone,
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
    let mut cfg = roomlerd::enrollment::enroll(roomlerd::enrollment::EnrollInputs {
        server_url: &f.app.base_url,
        enrollment_token: enroll["enrollment_token"].as_str().unwrap(),
        machine_id: &format!("native-login-{}", ObjectId::new()),
        machine_name: "native-login-fixture",
        install: None,
    })
    .await
    .unwrap();
    cfg.ssh_enabled = true;
    cfg.ssh_host_key = Some(roomlerd::ssh::generate_host_key().unwrap());
    cfg.ssh_account_mode = Some("daemon".into());
    cfg.enable_remote_browse = false;
    cfg.auto_grant_session = false;
    cfg.exec_enabled = false;
    cfg.remote_config_enabled = false;
    cfg.overlay_enabled = false;
    let expected_host = roomlerd::ssh::host_public_key(&cfg);
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
    roomlerd::config::save(&config, &cfg).unwrap();
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
            use roomler_ai_remote_control::models::RpcCap;
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
    let response=f.app.auth_post("/api/device-shares",&f.owner.token).json(&json!({"device_id":device.to_hex(),"recipient_user_id":f.recipient.id.to_hex(),"permissions":{"ssh":true},"tcp_ports":[],"expires_in_secs":120})).send().await.unwrap();
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
