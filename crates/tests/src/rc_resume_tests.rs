// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-130 P1a — the session-resume wire, row and scope, all inert, through a
//! real server, real sockets and a real MongoDB:
//!
//! * the resume scope (`/api/admin/rc-resume-scope`) is a platform admin's.
//!   Anyone else, an org's own admin included, gets the 404 every
//!   `/api/admin/*` route gives, for a malformed body too. The admin reads and
//!   replaces the list, and the hub's read of it (`covers`) follows;
//! * an audit listing that holds the two new kinds, and a kind no build knows
//!   yet, still reads: the rollback floor (spec §5);
//! * with the window at its default of 0 the new wire changes nothing. A
//!   hello that claims sessions and advertises `rc-resume` registers as before
//!   and is announced no window, with the scope at `all`; a request that names
//!   what it replaces is answered as before, without `resume_secs`; a rejoin
//!   is dropped unanswered; and a stats sample stamps the row's `stats_at`;
//! * the device's switch is the device's: a desired-config push naming it is
//!   refused 403 by its whole name, as `rc_media_canary` is.

use bson::{Document, doc, oid::ObjectId};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::fixtures::test_app::TestApp;
use crate::rc_resume_claim_tests::operator_token;
use crate::session_carrier_tests::{Ws, urlencode, wait_for_session_row};

const PATH: &str = "/api/admin/rc-resume-scope";

/// A server whose only platform admin is `operator`.
async fn spawn_with_operator(operator: ObjectId) -> TestApp {
    TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(operator.to_hex());
    })
    .await
}

/// One request with no cookie jar, so the bearer token is the only identity:
/// `app.client` keeps the cookie the last sign-up set.
async fn call(
    method: &str,
    app: &TestApp,
    token: Option<&str>,
    body: Option<&str>,
) -> (u16, Value) {
    let client = reqwest::Client::builder()
        .cookie_store(false)
        .build()
        .unwrap();
    let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
    let mut req = client.request(method, app.url(PATH));
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    if let Some(body) = body {
        req = req
            .header("content-type", "application/json")
            .body(body.to_string());
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

async fn scope_rows(app: &TestApp) -> Vec<Document> {
    let mut cursor = app
        .db
        .collection::<Document>("rc_resume_scope")
        .find(doc! {})
        .await
        .unwrap();
    let mut rows = Vec::new();
    while let Some(row) = cursor.next().await {
        rows.push(row.unwrap());
    }
    rows
}

#[tokio::test]
async fn the_resume_scope_is_for_platform_admins_only() {
    let operator = ObjectId::new();
    let app = spawn_with_operator(operator).await;
    let org = app.seed_tenant("fr130scope").await;
    let other = app.seed_tenant("fr130scope-out").await;
    let body = json!({ "entries": [{ "kind": "org", "id": org.tenant_id }] }).to_string();

    for (who, token) in [
        ("another org's admin", other.admin.access_token.as_str()),
        ("the org's own admin", org.admin.access_token.as_str()),
        ("the org's member", org.member.access_token.as_str()),
    ] {
        let (status, v) = call("GET", &app, Some(token), None).await;
        assert_eq!(status, 404, "{who} read the scope: {v}");
        let (status, v) = call("PUT", &app, Some(token), Some(&body)).await;
        assert_eq!(status, 404, "{who} saved the scope: {v}");
        // Refused before the body is read: a malformed one does not tell them
        // the route exists either.
        let (status, v) = call("PUT", &app, Some(token), Some("{not json")).await;
        assert_eq!(status, 404, "{who}'s malformed body: {v}");
    }
    assert!(
        scope_rows(&app).await.is_empty(),
        "a refused save stored nothing"
    );

    let (status, _) = call("GET", &app, None, None).await;
    assert_eq!(status, 401, "an anonymous caller");

    let token = operator_token(&app, operator).await;
    let (status, v) = call("GET", &app, Some(&token), None).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v, json!({ "window_secs": 0, "entries": [] }));
    let (status, v) = call("PUT", &app, Some(&token), Some(&body)).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["entries"][0]["kind"], "org");
    assert_eq!(v["entries"][0]["id"], org.tenant_id.as_str());
    assert_eq!(v["entries"][0]["by"], operator.to_hex());
    let (status, v) = call("PUT", &app, Some(&token), Some("{not json")).await;
    assert_eq!(status, 400, "the admin's malformed body is a 400: {v}");
    assert_eq!(scope_rows(&app).await.len(), 1);
}

#[tokio::test]
async fn the_scope_is_replaced_whole_and_the_hubs_read_follows_it() {
    let operator = ObjectId::new();
    let app = spawn_with_operator(operator).await;
    let token = operator_token(&app, operator).await;
    let scope = &app.state.fleet().rc_resume_scope;
    let (org_a, org_b) = (ObjectId::new(), ObjectId::new());
    let (dev_a, dev_b1, dev_b2) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
    let put = |entries: Value| json!({ "entries": entries }).to_string();

    assert!(
        !scope.covers(org_a, dev_a).await.unwrap(),
        "empty covers nothing"
    );

    let (status, v) = call(
        "PUT",
        &app,
        Some(&token),
        Some(&put(json!([
            { "kind": "org", "id": org_a.to_hex(), "note": "P3: the lab org" },
            { "kind": "device", "id": dev_b2.to_hex() },
            { "kind": "device", "id": dev_b2.to_hex(), "note": "named twice" },
        ]))),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["entries"].as_array().unwrap().len(), 2, "folded: {v}");
    assert!(scope.covers(org_a, dev_a).await.unwrap(), "by its org");
    assert!(scope.covers(org_b, dev_b2).await.unwrap(), "by itself");
    assert!(!scope.covers(org_b, dev_b1).await.unwrap(), "neither");
    let org_row_at = scope_rows(&app)
        .await
        .into_iter()
        .find(|r| r.get_str("kind") == Ok("org"))
        .unwrap()
        .get_datetime("at")
        .unwrap()
        .to_owned();

    // A refused save changes nothing.
    let (status, v) = call(
        "PUT",
        &app,
        Some(&token),
        Some(&put(json!([{ "kind": "tenant", "id": org_b.to_hex() }]))),
    )
    .await;
    assert_eq!(status, 400, "{v}");
    assert_eq!(scope_rows(&app).await.len(), 2);

    // The org stays (with when it was added), one device goes, one comes.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (status, v) = call(
        "PUT",
        &app,
        Some(&token),
        Some(&put(json!([
            { "kind": "org", "id": org_a.to_hex() },
            { "kind": "device", "id": dev_b1.to_hex() },
        ]))),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    assert!(scope.covers(org_b, dev_b1).await.unwrap());
    assert!(!scope.covers(org_b, dev_b2).await.unwrap(), "taken out");
    let rows = scope_rows(&app).await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    let org_row = rows
        .iter()
        .find(|r| r.get_str("kind") == Ok("org"))
        .unwrap();
    assert_eq!(
        org_row.get_datetime("at").unwrap(),
        &org_row_at,
        "a kept entry keeps its time"
    );
    assert!(
        matches!(org_row.get("note"), None | Some(bson::Bson::Null)),
        "the new save's note (none) replaced the old one: {org_row}"
    );

    // `all` covers every device; one entry at most.
    let (status, v) = call(
        "PUT",
        &app,
        Some(&token),
        Some(&put(
            json!([{ "kind": "all" }, { "kind": "all", "note": "again" }]),
        )),
    )
    .await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(
        v["entries"],
        json!([{
            "kind": "all",
            "by": operator.to_hex(),
            "at": v["entries"][0]["at"].clone(),
        }])
    );
    assert!(
        scope
            .covers(ObjectId::new(), ObjectId::new())
            .await
            .unwrap()
    );
    assert_eq!(scope_rows(&app).await.len(), 1);

    // An empty list takes everything out.
    let (status, v) = call("PUT", &app, Some(&token), Some(&put(json!([])))).await;
    assert_eq!(status, 200, "{v}");
    assert!(scope_rows(&app).await.is_empty());
    assert!(!scope.covers(org_a, dev_a).await.unwrap());
}

/// The audit listing reads a whole page of rows, so one kind it cannot read
/// fails the page (upstream FR-137 S-B5's class). Rows the production writer stores
/// for the two new kinds, and one a later build would write, all read back
/// through the production reader.
#[tokio::test]
async fn an_audit_listing_holding_the_new_kinds_and_an_unknown_one_still_reads() {
    use meshharbor_remote_control::audit::AuditSink;
    use meshharbor_remote_control::models::{AuditKind, RemoteAuditEvent};
    use meshharbor_remote_control::permissions::Permissions;

    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr130audit").await;
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let uid = ObjectId::parse_str(&seeded.admin.id).unwrap();
    let (sid, aid) = (ObjectId::new(), ObjectId::new());

    let (sink, flusher) = AuditSink::spawn(app.db.clone());
    sink.record(
        sid,
        aid,
        tid,
        AuditKind::SessionRequested {
            controller_user_id: uid,
            controller_name: "fr130audit Admin".into(),
            permissions: Permissions::VIEW,
            record_stripped: None,
            privacy_stripped: None,
            features_stripped: None,
            idle_secs: None,
            idle_enforced: None,
            lock_on_end: None,
            lock_enforced: None,
            external: false,
        },
    );
    sink.record(
        sid,
        aid,
        tid,
        AuditKind::SessionDetached {
            attach_seq: 0,
            resume_by: bson::DateTime::now(),
        },
    );
    sink.record(sid, aid, tid, AuditKind::SessionResumed { attach_seq: 1 });
    drop(sink);
    flusher.await.expect("audit flusher");
    app.db
        .collection::<Document>(RemoteAuditEvent::COLLECTION)
        .insert_one(doc! {
            "session_id": sid,
            "agent_id": aid,
            "tenant_id": tid,
            "at": bson::DateTime::now(),
            "event": { "kind": "session_paused_in_a_later_build", "why": "x" },
        })
        .await
        .unwrap();

    let resp = app
        .auth_get(
            &format!("/api/tenant/{}/session/{sid}/audit", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(status, 200, "the listing must read every row: {body}");
    let kinds: Vec<&str> = body["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["event"]["kind"].as_str().unwrap_or("?"))
        .collect();
    for want in [
        "session_requested",
        "session_detached",
        "session_resumed",
        "unknown",
    ] {
        assert!(kinds.contains(&want), "no {want} in {kinds:?}");
    }

    // A detach lands only on a live row at the fencing number it names, and a
    // resume is written by the claim itself, never by the sink (P1b-1): this
    // row never went live, so it reads with none of the resume fields.
    let row = app
        .db
        .collection::<Document>("remote_sessions")
        .find_one(doc! { "_id": sid })
        .await
        .unwrap()
        .expect("the row the sink projected");
    for key in ["attach_seq", "detached_at", "resume_by", "end_source"] {
        assert!(!row.contains_key(key), "{key} on the row: {row}");
    }
    let resp = app
        .auth_get(
            &format!("/api/tenant/{}/session/{sid}", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
}

/// Every frame `ws` receives within `quiet` of the last one, as JSON.
async fn frames(ws: &mut Ws, quiet: Duration) -> Vec<Value> {
    let mut out = Vec::new();
    while let Ok(Some(Ok(frame))) = tokio::time::timeout(quiet, ws.next()).await {
        if let Message::Text(text) = frame
            && let Ok(v) = serde_json::from_str::<Value>(&text)
        {
            out.push(v);
        }
    }
    out
}

fn tags(frames: &[Value]) -> Vec<String> {
    frames
        .iter()
        .map(|f| f["t"].as_str().unwrap_or("?").to_string())
        .collect()
}

#[tokio::test]
async fn at_window_zero_the_new_wire_changes_nothing() {
    let operator = ObjectId::new();
    let app = spawn_with_operator(operator).await;
    assert_eq!(app.settings.rc.session_resume_secs, 0, "the default is off");
    let seeded = app.seed_tenant("fr130inert").await;
    // The scope at `all`: still nothing, because the window is 0.
    let (status, v) = call(
        "PUT",
        &app,
        Some(&operator_token(&app, operator).await),
        Some(&json!({ "entries": [{ "kind": "all" }] }).to_string()),
    )
    .await;
    assert_eq!(status, 200, "{v}");

    // A device that advertises `rc-resume` and claims a session it kept.
    let (agent_id, agent_token) =
        crate::agent_presence_tests::enroll(&app, &seeded, "fr130-inert").await;
    let url = format!(
        "ws://{}/ws?token={}&role=agent",
        app.addr,
        urlencode(&agent_token)
    );
    let (mut agent, _) = connect_async(&url).await.expect("agent ws");
    let hello = json!({
        "t": "rc:agent.hello", "machine_name": "fr130-inert", "os": "linux", "agent_version": "0.4.208",
        "displays": [{ "index": 0, "name": "x", "width_px": 800, "height_px": 600, "scale": 1.0, "primary": true }],
        "caps": {
            "hw_encoders": [], "codecs": ["h264"], "has_input_permission": false,
            "supports_clipboard": false, "supports_file_transfer": false,
            "max_simultaneous_sessions": 2, "input": ["arbiter"], "rpc": ["rc-resume"],
        },
        "kept_sessions": [ObjectId::new().to_hex()],
    });
    agent
        .send(Message::Text(hello.to_string().into()))
        .await
        .unwrap();
    let seen = tags(&frames(&mut agent, Duration::from_millis(700)).await);
    assert!(
        !seen
            .iter()
            .any(|t| t == "rc:agent.resume_window" || t == "rc:session.resumed"),
        "no window and no claim answered at 0: {seen:?}"
    );

    // A request naming a session it replaces is answered as before.
    let (mut ctl, _) = connect_async(format!(
        "ws://{}/ws?token={}",
        app.addr,
        urlencode(&seeded.admin.access_token)
    ))
    .await
    .expect("controller ws");
    let _ = frames(&mut ctl, Duration::from_millis(200)).await;
    ctl.send(Message::Text(
        json!({
            "t": "rc:session.request", "agent_id": agent_id, "permissions": "VIEW",
            "replaces": ObjectId::new().to_hex(),
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    let answered = frames(&mut ctl, Duration::from_millis(700)).await;
    let created = answered
        .iter()
        .find(|f| f["t"] == "rc:session.created")
        .unwrap_or_else(|| panic!("no rc:session.created: {answered:?}"));
    assert!(created.get("resume_secs").is_none(), "{created}");
    let sid = created["session_id"].as_str().unwrap().to_string();

    // A rejoin is dropped unanswered, as a server before it drops it.
    ctl.send(Message::Text(
        json!({ "t": "rc:session.rejoin", "session_id": sid })
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    let after = tags(&frames(&mut ctl, Duration::from_millis(700)).await);
    assert!(
        !after.iter().any(|t| t == "rc:error"
            || t == "rc:session.resumed"
            || t == "rc:session.detached"
            || t == "rc:terminate"),
        "a rejoin is answered by nothing: {after:?}"
    );

    // A stats sample stamps `stats_at`, beside `stats`; nothing else of
    // FR-130's is on the row.
    wait_for_session_row(&app, &seeded, &sid).await;
    agent
        .send(Message::Text(
            json!({
                "t": "rc:session.stats", "session_id": sid,
                "bytes_sent": 1, "bytes_recv": 2, "fps": 30.0, "rtt_ms": 40.0,
                "keyframe_requests": 0, "input_events": 0,
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let oid = ObjectId::parse_str(&sid).unwrap();
    let mut row = Document::new();
    for _ in 0..50 {
        row = app
            .db
            .collection::<Document>("remote_sessions")
            .find_one(doc! { "_id": oid })
            .await
            .unwrap()
            .unwrap_or_default();
        if row.contains_key("stats_at") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(row.get_datetime("stats_at").is_ok(), "no stats_at: {row}");
    for key in ["attach_seq", "detached_at", "resume_by", "end_source"] {
        assert!(!row.contains_key(key), "{key} on the row: {row}");
    }
}

/// `rc_sessions_survive_reattach` is the device's switch, so a desired-config
/// push naming it is refused 403 by its whole name: dropped unread, it
/// answered 200 as if a push had taken that no device reads. The refusal
/// names the key, is on the record under the code `device_owned_switch`, and
/// stores nothing, the push's other keys included.
/// A key that only starts like the switch, or that the switch starts like, is
/// not it, and is dropped unread as before.
#[tokio::test]
async fn a_push_naming_the_resume_switch_is_refused_by_its_whole_name() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("fr130push").await;
    let (aid, _) = crate::rc_resume_claim_tests::enroll(&app, &seeded, "mach-fr130-push").await;
    let path = format!(
        "/api/tenant/{}/agent/{}/desired-config",
        seeded.tenant_id,
        aid.to_hex()
    );
    let owner = &seeded.admin.access_token;
    let put = |body: Value| app.auth_put(&path, owner).json(&body).send();

    for value in [json!(true), json!(false), json!("on")] {
        let resp = put(json!({ "fps_deny": "none", "rc_sessions_survive_reattach": value }))
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 403, "{value}");
        let body: Value = resp.json().await.unwrap();
        let message = body["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("rc_sessions_survive_reattach"),
            "the refusal names its own key: {body}"
        );
    }

    let refused = app
        .db
        .collection::<Document>("config_audit")
        .count_documents(doc! { "agent_id": aid, "denied": "device_owned_switch" })
        .await
        .unwrap();
    assert_eq!(refused, 3, "every refusal is on the record, under one code");
    let row = app
        .db
        .collection::<Document>("agents")
        .find_one(doc! { "_id": aid })
        .await
        .unwrap()
        .unwrap();
    assert!(
        row.get_document("desired_config")
            .map_or(true, |d| d.get_i64("revision").unwrap_or(0) == 0
                && d.get_i32("revision").unwrap_or(0) == 0),
        "a refused push stores nothing: {row:?}"
    );

    // Equality, never a prefix: the same push without the switch is the push
    // it always was.
    for near in ["rc_sessions_survive_reattach_v2", "rc_sessions_survive"] {
        let resp = put(json!({ "fps_deny": "none", near: true }))
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "{near} is not the switch");
    }
}
