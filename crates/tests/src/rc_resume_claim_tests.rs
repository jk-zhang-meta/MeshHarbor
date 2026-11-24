// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-130 P1b-1 — the device's half of the server's resume, through real
//! servers, real sockets and one MongoDB shared by two pods
//! (`TestApp::spawn_pair`):
//!
//! * **the announce**: a device that advertises `rc-resume`, under a window
//!   above 0 and inside the resume scope, is told `rc:agent.resume_window`;
//! * **the detach**: its live session outlives its control socket. The row
//!   stays open with `detached_at` and `resume_by`, the viewer is told
//!   `rc:session.detached`, and no pod holds the session;
//! * **the claim**: the device's next hello names the session and the pod it
//!   reaches resumes it at the next fencing number, or ends it with the reason
//!   (an end written during the gap, the gate a request runs, the org's
//!   maximum length, another device's session);
//! * **a removed device**: its redial is refused at the upgrade, so it claims
//!   nothing, and its viewer's next rejoin ends the session;
//! * **fencing**: a late detach from the pod that lost the session does not
//!   touch the row another pod resumed;
//! * **the registration read**: a row an earlier connection left open is ended
//!   at its own last clock, and says it was inferred (`end_source`);
//! * **off is today**: without the verb, outside the scope, or with the window
//!   at 0, a socket loss ends the session as it always has, and a row a dead
//!   pod left open stays open.
//!
//! AC4's bound is asserted where the harness can see it: a claim is answered
//! within 5 s of the hello that carries it, and a removed device's session
//! ends within 5 s of its refused redial.

use std::time::{Duration, Instant};

use bson::{Bson, DateTime, Document, doc, oid::ObjectId};
use futures::{SinkExt, StreamExt};
use meshharbor_services::dao::rc_resume_scope::{ResumeScopeEntry, ResumeScopeKind};
use serde_json::{Value, json};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::fixtures::seed::SeededTenant;
use crate::fixtures::test_app::TestApp;
use crate::rc_resume_rejoin_tests::{rejoin, rejoin_answer};

// FR-130 P1b-2 — the helpers below are shared with `rc_resume_rejoin_tests`,
// the viewer's half, which drives the same two pods.
pub(crate) type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// The window these tests run under, in seconds (D1's 60).
pub(crate) const WINDOW: u64 = 60;
/// The verb a device advertises to be announced a window.
pub(crate) const RESUME: &str = "rc-resume";
/// How long any one step may take; also AC4's bound on a claim's answer.
pub(crate) const WITHIN: Duration = Duration::from_secs(5);
/// How long a frame that must NOT come is waited for.
pub(crate) const QUIET: Duration = Duration::from_millis(800);

pub(crate) fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

/// A platform operator's token on `app`, with the account behind it. This
/// tree's admission reads the user's row on every request and refuses a
/// missing one, so the operator named in `stats.platform_admins` is given a
/// row under that id, once per database.
pub(crate) async fn operator_token(app: &TestApp, operator: ObjectId) -> String {
    let users = app.db.collection::<meshharbor_db::models::User>("users");
    if users
        .find_one(doc! { "_id": operator })
        .await
        .unwrap()
        .is_none()
    {
        let hash = app
            .state
            .auth
            .hash_password("fixture-only-not-a-real-password")
            .unwrap();
        let tag = operator.to_hex();
        let mut user = app
            .state
            .users
            .create(
                format!("operator-{tag}@fr130.example.test"),
                format!("fr130_operator_{tag}"),
                "Operator".to_owned(),
                hash,
                None,
            )
            .await
            .unwrap();
        let generated = user.id.unwrap();
        user.id = Some(operator);
        user.is_verified = true;
        users.delete_one(doc! { "_id": generated }).await.unwrap();
        users.insert_one(&user).await.unwrap();
    }
    app.state
        .auth
        .generate_tokens(operator, "operator@fr130.example.test", "fr130_operator")
        .unwrap()
        .access_token
}

pub(crate) fn oid(hex: &str) -> ObjectId {
    ObjectId::parse_str(hex).expect("a 24-hex id")
}

pub(crate) fn now_ms() -> i64 {
    DateTime::now().timestamp_millis()
}

/// Two pods over one database, each with the window `window`.
pub(crate) async fn pair(window: u64) -> (TestApp, TestApp) {
    TestApp::spawn_pair(move |s| {
        s.rc.session_resume_secs = window;
    })
    .await
}

/// One pod with the window `window`.
pub(crate) async fn one(window: u64) -> TestApp {
    TestApp::spawn_with_settings(move |s| {
        s.rc.session_resume_secs = window;
    })
    .await
}

/// Make the resume scope exactly `entries` (shared by every pod: it is a
/// collection).
pub(crate) async fn scope(app: &TestApp, entries: &[(ResumeScopeKind, Option<ObjectId>)]) {
    let rows: Vec<ResumeScopeEntry> = entries
        .iter()
        .map(|(kind, id)| ResumeScopeEntry {
            kind: *kind,
            id: *id,
            note: None,
            by: ObjectId::new(),
            at: DateTime::now(),
        })
        .collect();
    app.state
        .fleet()
        .rc_resume_scope
        .replace(&rows)
        .await
        .expect("the scope saves");
}

pub(crate) async fn scope_all(app: &TestApp) {
    scope(app, &[(ResumeScopeKind::All, None)]).await;
}

/// Enroll a device in `seeded`'s org, owned by its admin: (id, token).
pub(crate) async fn enroll(
    app: &TestApp,
    seeded: &SeededTenant,
    machine: &str,
) -> (ObjectId, String) {
    let (id, token) = crate::agent_presence_tests::enroll(app, seeded, machine).await;
    (oid(&id), token)
}

/// Open the device's control socket on `app` and say hello, advertising
/// `rpc` and claiming back `kept`.
pub(crate) async fn hello(app: &TestApp, token: &str, rpc: &[&str], kept: &[ObjectId]) -> Ws {
    hello_with(app, token, rpc, kept, 2).await
}

/// [`hello`], for a device that allows `max_sessions` sessions at once.
pub(crate) async fn hello_with(
    app: &TestApp,
    token: &str,
    rpc: &[&str],
    kept: &[ObjectId],
    max_sessions: u8,
) -> Ws {
    let url = format!("ws://{}/ws?token={}&role=agent", app.addr, urlencode(token));
    let (mut ws, _) = connect_async(&url).await.expect("agent ws");
    ws.send(Message::Text(
        hello_frame(rpc, kept, max_sessions).to_string().into(),
    ))
    .await
    .expect("the hello");
    ws
}

/// The device's `rc:agent.hello`, advertising `rpc` and claiming back `kept`.
fn hello_frame(rpc: &[&str], kept: &[ObjectId], max_sessions: u8) -> Value {
    let mut hello = json!({
        "t": "rc:agent.hello",
        "machine_name": "fr130 test box",
        "os": "linux",
        "agent_version": "0.4.208",
        "displays": [],
        "caps": {
            "hw_encoders": [], "codecs": ["h264"], "has_input_permission": true,
            "supports_clipboard": true, "supports_file_transfer": true,
            "max_simultaneous_sessions": max_sessions, "input": ["arbiter"], "rpc": rpc,
        },
    });
    if !kept.is_empty() {
        hello["kept_sessions"] = json!(kept.iter().map(|s| s.to_hex()).collect::<Vec<_>>());
    }
    hello
}

/// The next frame of type `t` on `ws` within `within`, or `None`.
pub(crate) async fn next_of(ws: &mut Ws, t: &str, within: Duration) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        let Ok(Some(Ok(Message::Text(text)))) =
            tokio::time::timeout(Duration::from_millis(200), ws.next()).await
        else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if v["t"] == t {
            return Some(v);
        }
    }
    None
}

/// The server's answer to a claim on `sid`: the first `rc:session.resumed` or
/// `rc:terminate` naming it, within `within`.
pub(crate) async fn answer_for(ws: &mut Ws, sid: ObjectId, within: Duration) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + within;
    let hex = sid.to_hex();
    while tokio::time::Instant::now() < deadline {
        let Ok(Some(Ok(Message::Text(text)))) =
            tokio::time::timeout(Duration::from_millis(200), ws.next()).await
        else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if (v["t"] == "rc:session.resumed" || v["t"] == "rc:terminate")
            && v["session_id"] == hex.as_str()
        {
            return Some(v);
        }
    }
    None
}

/// Open a session as `token` and drive it LIVE the way the two ends do: the
/// agent consents and answers the controller's offer. The controller's
/// socket and the session id.
pub(crate) async fn go_live(
    app: &TestApp,
    token: &str,
    agent_id: ObjectId,
    agent: &mut Ws,
) -> (Ws, ObjectId) {
    let url = format!("ws://{}/ws?token={}", app.addr, urlencode(token));
    let (mut ctl, _) = connect_async(&url).await.expect("controller ws");
    let _ = tokio::time::timeout(Duration::from_millis(200), ctl.next()).await;
    ctl.send(Message::Text(
        json!({
            "t": "rc:session.request",
            "agent_id": agent_id.to_hex(),
            "permissions": "VIEW | INPUT",
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    let created = next_of(&mut ctl, "rc:session.created", WITHIN)
        .await
        .expect("rc:session.created");
    let sid = created["session_id"].as_str().unwrap().to_string();
    next_of(agent, "rc:request", WITHIN)
        .await
        .expect("the agent's rc:request");
    agent
        .send(Message::Text(
            json!({ "t": "rc:consent", "session_id": sid, "granted": true })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    next_of(&mut ctl, "rc:ready", WITHIN)
        .await
        .expect("rc:ready");
    ctl.send(Message::Text(
        json!({ "t": "rc:sdp.offer", "session_id": sid, "sdp": "v=0" })
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    next_of(agent, "rc:sdp.offer", WITHIN)
        .await
        .expect("the agent's offer");
    agent
        .send(Message::Text(
            json!({ "t": "rc:sdp.answer", "session_id": sid, "sdp": "v=0" })
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    next_of(&mut ctl, "rc:sdp.answer", WITHIN)
        .await
        .expect("the controller's answer: the session is live");
    (ctl, oid(&sid))
}

/// The session's row as stored (empty when there is none).
pub(crate) async fn row(app: &TestApp, sid: ObjectId) -> Document {
    app.db
        .collection::<Document>("remote_sessions")
        .find_one(doc! { "_id": sid })
        .await
        .unwrap()
        .unwrap_or_default()
}

/// The row once `pred` holds, within [`WITHIN`]; panics with `what` otherwise.
pub(crate) async fn wait_row(
    app: &TestApp,
    sid: ObjectId,
    what: &str,
    pred: impl Fn(&Document) -> bool,
) -> Document {
    let deadline = Instant::now() + WITHIN;
    loop {
        let r = row(app, sid).await;
        if pred(&r) {
            return r;
        }
        assert!(Instant::now() < deadline, "{what}: {r}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The row's fencing number: absent reads 0, whichever integer type a write
/// left it in.
pub(crate) fn attach_seq(r: &Document) -> i64 {
    match r.get("attach_seq") {
        None | Some(Bson::Null) => 0,
        Some(Bson::Int32(n)) => i64::from(*n),
        Some(Bson::Int64(n)) => *n,
        Some(other) => panic!("attach_seq is {other}"),
    }
}

pub(crate) fn ended(r: &Document) -> bool {
    !matches!(r.get("ended_at"), None | Some(Bson::Null))
}

/// Live: Active and not ended.
pub(crate) fn open(r: &Document) -> bool {
    r.get_str("phase") == Ok("active") && !ended(r)
}

pub(crate) fn detached(r: &Document) -> bool {
    open(r) && r.get_datetime("detached_at").is_ok() && r.get_datetime("resume_by").is_ok()
}

pub(crate) fn end_reason(r: &Document) -> Option<&str> {
    r.get_str("end_reason").ok()
}

/// The `event` of every audit row of `sid`, oldest first.
pub(crate) async fn audit(app: &TestApp, sid: ObjectId) -> Vec<Document> {
    let mut cursor = app
        .db
        .collection::<Document>("remote_audit")
        .find(doc! { "session_id": sid })
        .sort(doc! { "at": 1 })
        .await
        .unwrap();
    let mut out = Vec::new();
    while let Some(ev) = cursor.next().await {
        if let Ok(e) = ev.unwrap().get_document("event") {
            out.push(e.clone());
        }
    }
    out
}

pub(crate) fn kinds(events: &[Document]) -> Vec<String> {
    events
        .iter()
        .map(|e| e.get_str("kind").unwrap_or("?").to_string())
        .collect()
}

/// Poll until the audit of `sid` holds an event of `kind`; its events then.
pub(crate) async fn wait_audit(app: &TestApp, sid: ObjectId, kind: &str) -> Vec<Document> {
    let deadline = Instant::now() + WITHIN;
    loop {
        let events = audit(app, sid).await;
        if kinds(&events).iter().any(|k| k == kind) {
            return events;
        }
        assert!(
            Instant::now() < deadline,
            "no {kind} in the audit: {:?}",
            kinds(&events)
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Close the device's control socket the way a dropped link ends it.
pub(crate) async fn drop_socket(mut ws: Ws) {
    let _ = ws.close(None).await;
    drop(ws);
}

pub(crate) fn tenant_of(seeded: &SeededTenant) -> ObjectId {
    oid(&seeded.tenant_id)
}

/// A row an earlier connection left open, as a pod that died writes none of
/// its end: Active, no `ended_at`, `extra` on top.
pub(crate) fn leftover(
    sid: ObjectId,
    agent: ObjectId,
    tenant: ObjectId,
    controller: ObjectId,
    created_ms: i64,
    extra: Document,
) -> Document {
    let mut d = doc! {
        "_id": sid,
        "agent_id": agent,
        "tenant_id": tenant,
        "controller_user_id": controller,
        "watchers": [],
        "permissions": "VIEW | INPUT",
        "phase": "active",
        "created_at": DateTime::from_millis(created_ms),
        "started_at": DateTime::from_millis(created_ms),
        "ended_at": Bson::Null,
        "end_reason": Bson::Null,
        "recording_url": Bson::Null,
    };
    d.extend(extra);
    d
}

pub(crate) async fn insert(app: &TestApp, row: Document) {
    app.db
        .collection::<Document>("remote_sessions")
        .insert_one(row)
        .await
        .expect("the row inserts");
}

/// A role carrying `mask`, given to the org's member (as
/// `remote_recording_tests` does).
pub(crate) async fn give_member(app: &TestApp, seeded: &SeededTenant, name: &str, mask: u64) {
    let role: Value = app
        .auth_post(
            &format!("/api/tenant/{}/role", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .json(&json!({ "name": name, "permissions": mask }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let role_id = role["id"].as_str().expect("a role id").to_string();
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/role/{}/assign/{}",
                seeded.tenant_id, role_id, seeded.member.id
            ),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "assign {name}");
}

pub(crate) const REMOTE_CONTROL: u64 = 1 << 25;

/// The org's maximum session length, written straight into its row: the
/// route accepts a minute at the least, and a test should not wait one.
async fn store_max_secs(app: &TestApp, seeded: &SeededTenant, secs: i64) {
    app.db
        .collection::<Document>("tenants")
        .update_one(
            doc! { "_id": tenant_of(seeded) },
            doc! { "$set": { "settings.rc_limits.max_secs": secs } },
        )
        .await
        .unwrap();
}

/// The agent's `PEER_CLOSE_BUDGET` (`agents/meshharbord/src/signaling.rs`), in
/// ms: AC4's outer bound is the window plus this.
const CLOSE_BUDGET_MS: i64 = 5_000;

/// What the server answered a removed device's redial.
#[derive(Debug)]
enum Redial {
    /// Refused before the upgrade, with this HTTP status.
    Refused(u16),
    /// Upgraded, then ended by the server, after these frames.
    Ended(Vec<Value>),
}

/// The device redials `app` and says hello, advertising `rc-resume` and
/// claiming back `kept`, as the daemon does; then reads until the server
/// ends the socket. Panics if the socket is still served after [`WITHIN`].
async fn redial(app: &TestApp, token: &str, kept: &[ObjectId]) -> Redial {
    let url = format!("ws://{}/ws?token={}&role=agent", app.addr, urlencode(token));
    let mut ws = match connect_async(&url).await {
        Ok((ws, _)) => ws,
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            return Redial::Refused(resp.status().as_u16());
        }
        Err(e) => panic!("the redial failed oddly: {e}"),
    };
    // The server may have closed the socket already: the send's result is
    // not the answer, what the socket carries is.
    let _ = ws
        .send(Message::Text(
            hello_frame(&[RESUME], kept, 2).to_string().into(),
        ))
        .await;
    let mut frames = Vec::new();
    let deadline = tokio::time::Instant::now() + WITHIN;
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                if let Ok(v) = serde_json::from_str::<Value>(&text) {
                    frames.push(v);
                }
            }
            Ok(Some(Ok(Message::Close(_))) | Some(Err(_)) | None) => {
                return Redial::Ended(frames);
            }
            Ok(Some(Ok(_))) => {}
            Err(_) => panic!("a removed device's socket is still served: {frames:?}"),
        }
    }
}

/// The claim, on the other pod. A live session whose device's control socket
/// drops is detached, not ended: the row stays open with `detached_at` and
/// `resume_by` (now plus the window), the viewer is told, and no pod holds it.
/// The device's next hello, on pod 2, claims it back: pod 2 answers
/// `rc:session.resumed` within 5 s, commits the next fencing number, clears
/// the detach, and holds the session with the controller it had.
#[tokio::test]
async fn a_session_whose_device_comes_back_on_the_other_pod_is_resumed_there() {
    let (app1, app2) = pair(WINDOW).await;
    let seeded = app1.seed_tenant("fr130resume").await;
    scope_all(&app1).await;
    let (agent_id, token) = enroll(&app1, &seeded, "fr130-resume").await;

    let mut agent = hello(&app1, &token, &[RESUME], &[]).await;
    let window = next_of(&mut agent, "rc:agent.resume_window", WITHIN)
        .await
        .expect("pod 1 announces the window to a device in the scope that advertises the verb");
    assert_eq!(window["secs"], WINDOW, "{window}");
    let (mut ctl, sid) = go_live(&app1, &seeded.admin.access_token, agent_id, &mut agent).await;
    wait_row(&app1, sid, "the session goes live", open).await;

    // The device's control socket drops.
    drop_socket(agent).await;
    let told = next_of(&mut ctl, "rc:session.detached", WITHIN)
        .await
        .expect("the viewer is told the session is kept");
    assert_eq!(told["session_id"], sid.to_hex().as_str(), "{told}");
    let resume_by = told["resume_by"].as_i64().expect("resume_by, unix ms");
    let now = now_ms();
    assert!(
        (now + 50_000..=now + 61_000).contains(&resume_by),
        "resume_by is the drop plus the window: {resume_by} against {now}"
    );
    let r = wait_row(&app1, sid, "the row records the detach", detached).await;
    assert_eq!(
        r.get_datetime("resume_by").unwrap().timestamp_millis(),
        resume_by,
        "the row and the viewer hold one resume_by: {r}"
    );
    assert_eq!(attach_seq(&r), 0, "{r}");
    assert!(
        app1.state.fleet().rc_hub.session_snapshot(sid).is_none(),
        "no pod holds a detached session"
    );

    // It comes back on pod 2 and claims the session.
    let claimed_at = Instant::now();
    let mut agent2 = hello(&app2, &token, &[RESUME], &[sid]).await;
    let window = next_of(&mut agent2, "rc:agent.resume_window", WITHIN)
        .await
        .expect("pod 2 announces the window before it answers the claim");
    assert_eq!(window["secs"], WINDOW, "{window}");
    let answer = answer_for(&mut agent2, sid, WITHIN)
        .await
        .expect("the claim is answered");
    assert_eq!(answer["t"], "rc:session.resumed", "{answer}");
    assert!(
        claimed_at.elapsed() < WITHIN,
        "AC4: answered within 5 s of the hello"
    );

    let r = row(&app2, sid).await;
    assert!(open(&r), "the same row, still open: {r}");
    assert_eq!(
        attach_seq(&r),
        1,
        "the claim committed the next number: {r}"
    );
    assert!(
        !r.contains_key("detached_at") && !r.contains_key("resume_by"),
        "the claim cleared the detach: {r}"
    );
    assert!(!r.contains_key("end_source"), "{r}");
    let admin = oid(&seeded.admin.id);
    assert_eq!(
        app2.state.fleet().rc_hub.session_snapshot(sid),
        Some((tenant_of(&seeded), admin)),
        "pod 2 holds the session now, under its own id and its controller"
    );
    assert!(app1.state.fleet().rc_hub.session_snapshot(sid).is_none());
    let events = wait_audit(&app2, sid, "session_resumed").await;
    let k = kinds(&events);
    assert!(k.iter().any(|k| k == "session_detached"), "{k:?}");
    assert!(!k.iter().any(|k| k == "session_ended"), "{k:?}");
}

/// Off is today, one: a device that does not advertise `rc-resume` is
/// announced no window, and a socket loss ends its session as it always has,
/// with the window on and the scope at `all`.
#[tokio::test]
async fn a_device_without_the_verb_ends_its_session_at_the_socket_loss_as_today() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130noverb").await;
    scope_all(&app).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-noverb").await;

    let mut agent = hello(&app, &token, &[], &[]).await;
    assert!(
        next_of(&mut agent, "rc:agent.resume_window", QUIET)
            .await
            .is_none(),
        "no window for a device without the verb"
    );
    let (mut ctl, sid) = go_live(&app, &seeded.admin.access_token, agent_id, &mut agent).await;
    wait_row(&app, sid, "the session goes live", open).await;

    drop_socket(agent).await;
    let end = next_of(&mut ctl, "rc:terminate", WITHIN)
        .await
        .expect("the viewer is told the session ended, as today");
    assert_eq!(end["reason"], "agent_disconnect", "{end}");
    let r = wait_row(&app, sid, "the row ends as today", ended).await;
    assert_eq!(end_reason(&r), Some("agent_disconnect"), "{r}");
    assert!(
        !r.contains_key("detached_at") && !r.contains_key("end_source"),
        "{r}"
    );
    assert!(
        !kinds(&audit(&app, sid).await)
            .iter()
            .any(|k| k == "session_detached")
    );
}

/// Off is today, two: a device outside the resume scope is announced no
/// window, a socket loss ends its session as today, and a claim it makes
/// anyway is answered `rc:terminate`, the row untouched.
#[tokio::test]
async fn a_device_outside_the_scope_ends_its_session_as_today_and_its_claim_is_refused() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130outside").await;
    // The scope names another device only.
    scope(&app, &[(ResumeScopeKind::Device, Some(ObjectId::new()))]).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-outside").await;

    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    assert!(
        next_of(&mut agent, "rc:agent.resume_window", QUIET)
            .await
            .is_none(),
        "no window outside the scope"
    );
    let (mut ctl, sid) = go_live(&app, &seeded.admin.access_token, agent_id, &mut agent).await;
    wait_row(&app, sid, "the session goes live", open).await;

    drop_socket(agent).await;
    let end = next_of(&mut ctl, "rc:terminate", WITHIN)
        .await
        .expect("the viewer is told the session ended, as today");
    assert_eq!(end["reason"], "agent_disconnect", "{end}");
    let before = wait_row(&app, sid, "the row ends as today", ended).await;
    assert!(!before.contains_key("detached_at"), "{before}");

    let mut agent = hello(&app, &token, &[RESUME], &[sid]).await;
    let answer = answer_for(&mut agent, sid, WITHIN)
        .await
        .expect("a claim with no window is answered");
    assert_eq!(answer["t"], "rc:terminate", "{answer}");
    assert_eq!(answer["reason"], "agent_disconnect", "{answer}");
    assert!(
        next_of(&mut agent, "rc:agent.resume_window", QUIET)
            .await
            .is_none()
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(row(&app, sid).await, before, "the claim wrote nothing");
}

/// A claim names the device's own sessions only. Another device of the same
/// org, and a device of another org, claiming the session are each refused
/// with `agent_disconnect`, and the row is untouched. The device that held it
/// then claims it back: the positive control.
#[tokio::test]
async fn a_claim_for_another_devices_session_is_refused() {
    let (app1, app2) = pair(WINDOW).await;
    let seeded = app1.seed_tenant("fr130another").await;
    let outsider = app1.seed_tenant("fr130another-out").await;
    scope_all(&app1).await;
    let (agent_a, token_a) = enroll(&app1, &seeded, "fr130-another-a").await;
    let (_agent_b, token_b) = enroll(&app1, &seeded, "fr130-another-b").await;
    let (_agent_c, token_c) = enroll(&app1, &outsider, "fr130-another-c").await;

    let mut a = hello(&app1, &token_a, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app1, &seeded.admin.access_token, agent_a, &mut a).await;
    wait_row(&app1, sid, "the session goes live", open).await;
    drop_socket(a).await;
    let before = wait_row(&app1, sid, "the row records the detach", detached).await;

    for (who, token) in [
        ("a device of the same org", &token_b),
        ("a device of another org", &token_c),
    ] {
        let mut ws = hello(&app2, token, &[RESUME], &[sid]).await;
        let answer = answer_for(&mut ws, sid, WITHIN)
            .await
            .unwrap_or_else(|| panic!("{who}: the claim is answered"));
        assert_eq!(answer["t"], "rc:terminate", "{who}: {answer}");
        assert_eq!(answer["reason"], "agent_disconnect", "{who}: {answer}");
        assert!(
            app2.state.fleet().rc_hub.session_snapshot(sid).is_none(),
            "{who}: pod 2 holds nothing for it"
        );
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(row(&app2, sid).await, before, "{who}: the row is untouched");
        drop_socket(ws).await;
    }

    let mut a = hello(&app2, &token_a, &[RESUME], &[sid]).await;
    let answer = answer_for(&mut a, sid, WITHIN)
        .await
        .expect("the device's own claim is answered");
    assert_eq!(answer["t"], "rc:session.resumed", "{answer}");
    assert_eq!(attach_seq(&row(&app2, sid).await), 1);
}

/// AC4 — an admin's end while no pod holds the session, through the real
/// `POST …/session/{id}/terminate` on pod 2, during the gap: the route writes
/// the end to the row (no hub on pod 2 holds the session), and the claim then
/// enforces it: pod 2 answers `rc:terminate` with the row's reason within
/// 5 s, holds nothing, and leaves the row's end as the route wrote it. An end
/// wins over a resume.
#[tokio::test]
async fn an_admins_end_during_the_gap_ends_the_session_at_the_claim() {
    let (app1, app2) = pair(WINDOW).await;
    let seeded = app1.seed_tenant("fr130kick").await;
    scope_all(&app1).await;
    let (agent_id, token) = enroll(&app1, &seeded, "fr130-kick").await;

    let mut agent = hello(&app1, &token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app1, &seeded.admin.access_token, agent_id, &mut agent).await;
    wait_row(&app1, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    wait_row(&app1, sid, "the row records the detach", detached).await;

    // The admin's end, on pod 2, during the gap, through the route.
    let before = now_ms();
    let resp = app2
        .auth_post(
            &format!("/api/tenant/{}/session/{}/terminate", seeded.tenant_id, sid),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "the admin's end is taken");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["terminated"], false, "no hub on pod 2 held it: {body}");
    assert_eq!(body["row_ended"], true, "the route ended its row: {body}");
    let after = now_ms();
    let r = wait_row(&app2, sid, "the route ends the row", ended).await;
    assert_eq!(end_reason(&r), Some("admin_terminated"), "{r}");
    let ended_at = *r.get_datetime("ended_at").unwrap();
    assert!(
        (before..=after).contains(&ended_at.timestamp_millis()),
        "the end is dated when the admin asked: {r}"
    );

    let claimed_at = Instant::now();
    let mut agent2 = hello(&app2, &token, &[RESUME], &[sid]).await;
    let answer = answer_for(&mut agent2, sid, WITHIN)
        .await
        .expect("the claim is answered");
    assert!(claimed_at.elapsed() < WITHIN, "AC4: within 5 s");
    assert_eq!(answer["t"], "rc:terminate", "an end wins: {answer}");
    assert_eq!(answer["reason"], "admin_terminated", "{answer}");
    assert!(app2.state.fleet().rc_hub.session_snapshot(sid).is_none());
    tokio::time::sleep(Duration::from_millis(400)).await;
    let r = row(&app2, sid).await;
    assert_eq!(end_reason(&r), Some("admin_terminated"), "{r}");
    assert_eq!(
        r.get_datetime("ended_at").unwrap(),
        &ended_at,
        "the end is the admin's: {r}"
    );
    assert_eq!(attach_seq(&r), 0, "nothing committed: {r}");
    assert!(!r.contains_key("end_source"), "{r}");
    assert!(
        !kinds(&audit(&app2, sid).await)
            .iter()
            .any(|k| k == "session_resumed")
    );
}

/// Fencing. The device's socket to pod 1 is half-open (a middlebox keeps it)
/// while the device is already back on pod 2 and claims its session there:
/// pod 2 resumes it at fencing number 1, though pod 1 still holds it. When
/// pod 1 finally loses its socket it detaches the session at number 0, late:
/// the detach is written (the audit has it) and the row, at 1, ignores it.
#[tokio::test]
async fn a_resume_on_the_other_pod_survives_the_first_pods_late_detach() {
    let (app1, app2) = pair(WINDOW).await;
    let seeded = app1.seed_tenant("fr130fence").await;
    scope_all(&app1).await;
    let (agent_id, token) = enroll(&app1, &seeded, "fr130-fence").await;

    let mut half_open = hello(&app1, &token, &[RESUME], &[]).await;
    let (mut ctl, sid) = go_live(&app1, &seeded.admin.access_token, agent_id, &mut half_open).await;
    wait_row(&app1, sid, "the session goes live", open).await;

    let mut agent2 = hello(&app2, &token, &[RESUME], &[sid]).await;
    let answer = answer_for(&mut agent2, sid, WITHIN)
        .await
        .expect("the claim is answered");
    assert_eq!(answer["t"], "rc:session.resumed", "{answer}");
    assert_eq!(attach_seq(&row(&app2, sid).await), 1);
    assert!(
        app1.state.fleet().rc_hub.session_snapshot(sid).is_some(),
        "pod 1 still holds it: its socket has not dropped yet"
    );

    // Pod 1's socket drops at last: its detach lands after the resume.
    drop_socket(half_open).await;
    next_of(&mut ctl, "rc:session.detached", WITHIN)
        .await
        .expect("pod 1 detached what it held");
    let events = wait_audit(&app1, sid, "session_detached").await;
    let late = events
        .iter()
        .find(|e| e.get_str("kind") == Ok("session_detached"))
        .unwrap();
    assert!(
        matches!(
            late.get("attach_seq"),
            None | Some(Bson::Int32(0)) | Some(Bson::Int64(0))
        ),
        "pod 1 wrote the number it held, 0: {late}"
    );
    // The sink batches for up to 200 ms: give the late write time to land.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let r = row(&app1, sid).await;
    assert!(open(&r), "{r}");
    assert_eq!(attach_seq(&r), 1, "{r}");
    assert!(
        !r.contains_key("detached_at") && !r.contains_key("resume_by"),
        "the late detach did not touch the resumed row: {r}"
    );
    assert!(app2.state.fleet().rc_hub.session_snapshot(sid).is_some());
}

/// Off is today, three: with the window at 0 (the default) the scope does not
/// matter. No window is announced, a socket loss ends the session as today,
/// a claim is answered `rc:terminate`, and a row a dead pod left open stays
/// exactly as it was: nothing reads it at registration.
#[tokio::test]
async fn with_the_window_at_zero_a_socket_loss_ends_as_today_and_a_dead_pods_row_stays() {
    let app = one(0).await;
    assert_eq!(app.settings.rc.session_resume_secs, 0);
    let seeded = app.seed_tenant("fr130zero").await;
    scope_all(&app).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-zero").await;

    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    assert!(
        next_of(&mut agent, "rc:agent.resume_window", QUIET)
            .await
            .is_none(),
        "no window at 0"
    );
    let (mut ctl, sid) = go_live(&app, &seeded.admin.access_token, agent_id, &mut agent).await;
    wait_row(&app, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    let end = next_of(&mut ctl, "rc:terminate", WITHIN)
        .await
        .expect("the viewer is told the session ended, as today");
    assert_eq!(end["reason"], "agent_disconnect", "{end}");
    let r = wait_row(&app, sid, "the row ends as today", ended).await;
    assert_eq!(end_reason(&r), Some("agent_disconnect"), "{r}");
    assert!(!r.contains_key("detached_at"), "{r}");

    // A row a dead pod left open, two hours old.
    let dead = ObjectId::new();
    let created = now_ms() - 2 * 3600 * 1000;
    let left = leftover(
        dead,
        agent_id,
        tenant_of(&seeded),
        oid(&seeded.admin.id),
        created,
        doc! { "stats_at": DateTime::from_millis(created + 600_000) },
    );
    insert(&app, left).await;
    let before = row(&app, dead).await;

    let mut agent = hello(&app, &token, &[RESUME], &[dead]).await;
    let answer = answer_for(&mut agent, dead, WITHIN)
        .await
        .expect("a claim at window 0 is answered");
    assert_eq!(answer["t"], "rc:terminate", "{answer}");
    assert_eq!(answer["reason"], "agent_disconnect", "{answer}");
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        row(&app, dead).await,
        before,
        "the dead pod's row stays as it was"
    );
}

/// AC9 — the registration read, window on: every row of this device an
/// earlier connection left open is ended at its own last clock (`detached_at`,
/// else `stats_at`, else `started_at`), as `agent_disconnect`, with
/// `end_source: registration`. A claimed row whose window has passed is
/// refused and ended the same way. Another device's row, an ended row, a row
/// not yet live and a row created after the registration are left alone.
#[tokio::test]
async fn an_inferred_end_is_dated_by_the_rows_own_clock_and_marked() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130infer").await;
    scope_all(&app).await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-infer").await;
    let (other_agent, _) = enroll(&app, &seeded, "fr130-infer-other").await;
    let tenant = tenant_of(&seeded);
    let ctl = oid(&seeded.admin.id);
    let h = 3600 * 1000;
    let base = now_ms() - 3 * h;
    let at = DateTime::from_millis;

    let (
        detached_row,
        stats_row,
        started_row,
        others_row,
        ended_row,
        pending_row,
        later_row,
        claimed_row,
    ) = (
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
        ObjectId::new(),
    );
    // A — detached, its window long past.
    insert(
        &app,
        leftover(
            detached_row,
            agent_id,
            tenant,
            ctl,
            base,
            doc! {
                "stats_at": at(base + h),
                "detached_at": at(base + 2 * h),
                "resume_by": at(base + 2 * h + 60_000),
            },
        ),
    )
    .await;
    // B — never detached: its last stats merge.
    insert(
        &app,
        leftover(
            stats_row,
            agent_id,
            tenant,
            ctl,
            base,
            doc! { "stats_at": at(base + h + 15_000) },
        ),
    )
    .await;
    // C — neither: when it went live.
    let mut row_c = leftover(started_row, agent_id, tenant, ctl, base, doc! {});
    row_c.insert("started_at", at(base + 30_000));
    insert(&app, row_c).await;
    // D — another device's open row.
    insert(
        &app,
        leftover(others_row, other_agent, tenant, ctl, base, doc! {}),
    )
    .await;
    // E — this device's row that already ended.
    insert(
        &app,
        leftover(
            ended_row,
            agent_id,
            tenant,
            ctl,
            base,
            doc! {
                "phase": "closed",
                "ended_at": at(base + h),
                "end_reason": "controller_hangup",
            },
        ),
    )
    .await;
    // F — this device's row that never went live.
    insert(
        &app,
        leftover(
            pending_row,
            agent_id,
            tenant,
            ctl,
            base,
            doc! { "phase": "awaiting_consent", "started_at": Bson::Null },
        ),
    )
    .await;
    // G — this device's open row created after the registration (a later clock).
    insert(
        &app,
        leftover(
            later_row,
            agent_id,
            tenant,
            ctl,
            now_ms() + 600_000,
            doc! {},
        ),
    )
    .await;
    // I — detached, its window past, and claimed by the hello below.
    insert(
        &app,
        leftover(
            claimed_row,
            agent_id,
            tenant,
            ctl,
            base,
            doc! {
                "detached_at": at(base + 2 * h + 5_000),
                "resume_by": at(base + 2 * h + 65_000),
            },
        ),
    )
    .await;
    let untouched = [
        (others_row, row(&app, others_row).await),
        (ended_row, row(&app, ended_row).await),
        (pending_row, row(&app, pending_row).await),
        (later_row, row(&app, later_row).await),
    ];

    let mut agent = hello(&app, &token, &[RESUME], &[claimed_row]).await;
    let answer = answer_for(&mut agent, claimed_row, WITHIN)
        .await
        .expect("the claim on an expired session is answered");
    assert_eq!(answer["t"], "rc:terminate", "{answer}");
    assert_eq!(answer["reason"], "agent_disconnect", "{answer}");

    for (sid, last_clock, what) in [
        (detached_row, at(base + 2 * h), "detached_at"),
        (stats_row, at(base + h + 15_000), "stats_at"),
        (started_row, at(base + 30_000), "started_at"),
        (
            claimed_row,
            at(base + 2 * h + 5_000),
            "detached_at (claimed, expired)",
        ),
    ] {
        let r = wait_row(&app, sid, what, ended).await;
        assert_eq!(r.get_str("phase"), Ok("closed"), "{what}: {r}");
        assert_eq!(end_reason(&r), Some("agent_disconnect"), "{what}: {r}");
        assert_eq!(r.get_str("end_source"), Ok("registration"), "{what}: {r}");
        assert_eq!(
            r.get_datetime("ended_at").unwrap(),
            &last_clock,
            "{what}: dated by the row's own clock, never the reader's: {r}"
        );
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    for (sid, before) in untouched {
        assert_eq!(row(&app, sid).await, before, "left alone: {sid}");
    }
}

/// AC4 — the claim re-runs the gate a request runs. A member who controlled
/// the device and is removed from the org while its socket is down is
/// refused at the claim with `admin_terminated`, within 5 s, and the row ends
/// with that reason.
#[tokio::test]
async fn a_controller_removed_from_the_org_during_the_gap_is_refused_at_the_claim() {
    let (app1, app2) = pair(WINDOW).await;
    let seeded = app1.seed_tenant("fr130gate").await;
    scope_all(&app1).await;
    give_member(&app1, &seeded, "controller", REMOTE_CONTROL).await;
    let (agent_id, token) = enroll(&app1, &seeded, "fr130-gate").await;

    let mut agent = hello(&app1, &token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app1, &seeded.member.access_token, agent_id, &mut agent).await;
    wait_row(&app1, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    wait_row(&app1, sid, "the row records the detach", detached).await;

    let resp = app2
        .auth_delete(
            &format!(
                "/api/tenant/{}/member/{}",
                seeded.tenant_id, seeded.member.id
            ),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "the member is removed");

    let claimed_at = Instant::now();
    let mut agent2 = hello(&app2, &token, &[RESUME], &[sid]).await;
    let answer = answer_for(&mut agent2, sid, WITHIN)
        .await
        .expect("the claim is answered");
    assert!(claimed_at.elapsed() < WITHIN, "AC4: within 5 s");
    assert_eq!(answer["t"], "rc:terminate", "{answer}");
    assert_eq!(answer["reason"], "admin_terminated", "{answer}");
    assert!(app2.state.fleet().rc_hub.session_snapshot(sid).is_none());
    let r = wait_row(&app2, sid, "the refusal ends the row", ended).await;
    assert_eq!(end_reason(&r), Some("admin_terminated"), "{r}");
    assert!(
        !r.contains_key("end_source"),
        "a refusal is an end someone saw: {r}"
    );
}

/// AC4 — the device's removal while its socket is down, through the route the
/// UI uses (`DELETE …/agent/{id}`, fleet's `delete_agent`), on pod 2 during
/// the gap, once for each kind of device. Its redial is refused at the
/// upgrade, so no pod registers it and the claim its hello carries is never
/// read: an ephemeral device's row is deleted outright and its token is
/// refused 401 (the daemon's `AuthRejected`, as in the field's cell (b)); a
/// permanent device's tombstone hears `rc:goodbye agent_deleted`.
///
/// Neither the removal nor the refusal writes the detached row: no hub holds
/// the device, so the removal's kick ends nothing. The viewer's rejoin does.
/// The page asks once a second while it holds, and the gate it runs (at most
/// once per 5 s for it) finds the device removed (`resume_gate`): the row ends
/// `admin_terminated` with no `end_source` (`row_end::revoked`), an end the
/// server decided, as cell (b) read, and the viewer is told so. The end lands
/// within 5 s of the refused redial and before the window plus the close
/// budget, and nothing resumes the session. With no viewer asking, the sweep
/// ends the row at the window, as `agent_disconnect` with `end_source: sweep`
/// (`rc_resume_sweep_tests`). The device's half, its kept peer closed at the
/// refusal, is the agent's unit tests
/// `a_refused_token_closes_every_peer_kept_ones_included` and
/// `a_terminal_exit_closes_kept_sessions_too`: the device here holds no peer.
#[tokio::test]
async fn a_device_removed_during_the_gap_is_refused_at_its_redial_and_its_session_ends() {
    let (app1, app2) = pair(WINDOW).await;
    scope_all(&app1).await;
    for (kind, ephemeral) in [("a permanent device", false), ("an ephemeral device", true)] {
        let tag = if ephemeral { "eph" } else { "perm" };
        let seeded = app1.seed_tenant(&format!("fr130gone{tag}")).await;
        let (agent_id, token) = enroll(&app1, &seeded, &format!("fr130-gone-{tag}")).await;
        if ephemeral {
            assert!(
                app1.state
                    .fleet()
                    .agents
                    .set_ephemeral(agent_id, None)
                    .await
                    .unwrap(),
                "{kind}: marked ephemeral"
            );
        }

        let mut agent = hello(&app1, &token, &[RESUME], &[]).await;
        let (mut ctl, sid) = go_live(&app1, &seeded.admin.access_token, agent_id, &mut agent).await;
        wait_row(&app1, sid, "the session goes live", open).await;
        drop_socket(agent).await;
        let told = next_of(&mut ctl, "rc:session.detached", WITHIN)
            .await
            .unwrap_or_else(|| panic!("{kind}: the viewer is told the session is kept"));
        let resume_by = told["resume_by"].as_i64().expect("resume_by, unix ms");
        wait_row(&app1, sid, "the row records the detach", detached).await;

        // The viewer holds and asks for the session back, as the page does:
        // the gate runs, the device is there, so it is told to wait for it.
        rejoin(&mut ctl, sid).await;
        let waiting = rejoin_answer(&mut ctl, sid, WITHIN)
            .await
            .unwrap_or_else(|| panic!("{kind}: the rejoin is answered"));
        let gated_at = tokio::time::Instant::now();
        assert_eq!(
            waiting["t"], "rc:session.detached",
            "{kind}: before the removal the viewer waits for the device: {waiting}"
        );
        assert_eq!(waiting["resume_by"].as_i64(), Some(resume_by), "{kind}");

        // The removal comes later in the gap, as cell (b)'s came 8 s in, after
        // the gate's 5 s for this viewer: the asks inside them run no gate.
        tokio::time::sleep_until(gated_at + Duration::from_millis(5_300)).await;
        assert!(
            detached(&row(&app1, sid).await),
            "{kind}: kept until the removal"
        );
        let removed_at = now_ms();
        let resp = app2
            .auth_delete(
                &format!("/api/tenant/{}/agent/{}", seeded.tenant_id, agent_id),
                &seeded.admin.access_token,
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "{kind}: the device is removed");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["deleted"], true, "{kind}: {body}");

        // The device redials, on pod 2, and claims its session back.
        let answer = redial(&app2, &token, &[sid]).await;
        let refused_at = now_ms();
        let refused = Instant::now();
        match (ephemeral, &answer) {
            (true, Redial::Refused(status)) => {
                assert_eq!(*status, 401, "{kind}: its token is refused at the upgrade");
            }
            (false, Redial::Ended(frames)) => {
                assert!(
                    frames
                        .iter()
                        .any(|f| f["t"] == "rc:goodbye" && f["reason"] == "agent_deleted"),
                    "{kind}: the upgrade says why it refuses: {frames:?}"
                );
                assert!(
                    !frames.iter().any(|f| f["t"] == "rc:agent.resume_window"
                        || f["session_id"] == sid.to_hex().as_str()),
                    "{kind}: no window, and no answer to the claim: {frames:?}"
                );
            }
            (_, other) => panic!("{kind}: the redial was answered {other:?}"),
        }
        for (pod, app) in [("pod 1", &app1), ("pod 2", &app2)] {
            let hub = &app.state.fleet().rc_hub;
            assert!(
                !hub.is_agent_online(agent_id),
                "{kind}: {pod} registered the removed device"
            );
            assert!(
                hub.session_snapshot(sid).is_none(),
                "{kind}: {pod} holds its session"
            );
        }

        // The viewer's next ask: the gate finds the device removed.
        rejoin(&mut ctl, sid).await;
        let end = rejoin_answer(&mut ctl, sid, WITHIN)
            .await
            .unwrap_or_else(|| panic!("{kind}: the rejoin is answered"));
        assert!(
            refused.elapsed() < WITHIN,
            "{kind}: AC4: within 5 s of the refused redial"
        );
        assert_eq!(end["t"], "rc:terminate", "{kind}: {end}");
        assert_eq!(end["reason"], "admin_terminated", "{kind}: {end}");

        let r = wait_row(
            &app1,
            sid,
            &format!("{kind}: the removal ends the row"),
            ended,
        )
        .await;
        assert_eq!(end_reason(&r), Some("admin_terminated"), "{kind}: {r}");
        assert!(
            !r.contains_key("end_source"),
            "{kind}: an end the server decided, not one it inferred: {r}"
        );
        assert_eq!(attach_seq(&r), 0, "{kind}: nothing claimed it: {r}");
        let ended_at = r.get_datetime("ended_at").unwrap().timestamp_millis();
        assert!(
            (removed_at..=refused_at + 5_000).contains(&ended_at),
            "{kind}: AC4: the end lands after the removal and within 5 s of the refused redial: {r}"
        );
        assert!(
            ended_at <= resume_by + CLOSE_BUDGET_MS,
            "{kind}: AC4: never later than the window plus the close budget: {r}"
        );
        let k = kinds(&wait_audit(&app1, sid, "session_ended").await);
        assert!(k.iter().any(|k| k == "session_detached"), "{kind}: {k:?}");
        assert!(!k.iter().any(|k| k == "session_resumed"), "{kind}: {k:?}");
    }
}

/// FR-101 — a resumed session keeps the maximum length it went live under:
/// the timer is armed again from the row's `started_at`, never from the
/// resume, so the session ends when it would have without the gap.
#[tokio::test]
async fn a_resumed_session_keeps_the_maximum_length_it_went_live_under() {
    const MAX_SECS: u64 = 8;
    let (app1, app2) = pair(WINDOW).await;
    let seeded = app1.seed_tenant("fr130maxlen").await;
    scope_all(&app1).await;
    store_max_secs(&app1, &seeded, MAX_SECS as i64).await;
    let (agent_id, token) = enroll(&app1, &seeded, "fr130-maxlen").await;

    let mut agent = hello(&app1, &token, &[RESUME], &[]).await;
    let (_ctl, sid) = go_live(&app1, &seeded.admin.access_token, agent_id, &mut agent).await;
    let live_at = Instant::now();
    wait_row(&app1, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    wait_row(&app1, sid, "the row records the detach", detached).await;
    // A gap long enough that a timer armed from the resume would end the
    // session well past the limit.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let mut agent2 = hello(&app2, &token, &[RESUME], &[sid]).await;
    let first = answer_for(&mut agent2, sid, WITHIN)
        .await
        .expect("the claim is answered");
    // A slow runner may reach the claim after the limit, which refuses it
    // with the same reason: the end is what the test reads.
    let end = if first["t"] == "rc:session.resumed" {
        next_of(
            &mut agent2,
            "rc:terminate",
            Duration::from_secs(MAX_SECS + 4),
        )
        .await
        .expect("the resumed session ends at its maximum length")
    } else {
        first
    };
    let at = live_at.elapsed();
    assert_eq!(end["reason"], "idle_timeout", "{end}");
    assert_eq!(end["limit"], "max_duration", "{end}");
    assert!(
        at < Duration::from_millis(MAX_SECS * 1000 + 1500),
        "armed from started_at, not from the resume: ended {at:?} after going live"
    );
    let r = wait_row(&app2, sid, "the row ends", ended).await;
    assert_eq!(end_reason(&r), Some("idle_timeout"), "{r}");
}

/// Off is today, three (FR-130 P4-0): a resume scope the server cannot read at
/// the hello announces no window, though it would cover the device, and the
/// session then ends at the socket loss as it always has, never kept on a
/// guess. Once the scope reads again, the device's next hello is announced its
/// window: the positive control.
#[tokio::test]
async fn a_scope_that_cannot_be_read_at_the_hello_announces_no_window() {
    let app = one(WINDOW).await;
    let seeded = app.seed_tenant("fr130unread").await;
    let (agent_id, token) = enroll(&app, &seeded, "fr130-unread").await;
    unreadable_scope(&app).await;

    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    assert!(
        next_of(&mut agent, "rc:agent.resume_window", QUIET)
            .await
            .is_none(),
        "no window from a scope that cannot be read"
    );
    let (mut ctl, sid) = go_live(&app, &seeded.admin.access_token, agent_id, &mut agent).await;
    wait_row(&app, sid, "the session goes live", open).await;
    drop_socket(agent).await;
    let end = next_of(&mut ctl, "rc:terminate", WITHIN)
        .await
        .expect("the viewer is told the session ended, as today");
    assert_eq!(end["reason"], "agent_disconnect", "{end}");
    let r = wait_row(&app, sid, "the row ends as today", ended).await;
    assert_eq!(end_reason(&r), Some("agent_disconnect"), "{r}");
    assert!(!r.contains_key("detached_at"), "{r}");

    readable_scope_all(&app).await;
    let mut agent = hello(&app, &token, &[RESUME], &[]).await;
    let window = next_of(&mut agent, "rc:agent.resume_window", WITHIN)
        .await
        .expect("a window once the scope reads");
    assert_eq!(window["secs"], WINDOW, "{window}");
}

/// The resume scope's collection replaced by a view whose pipeline fails on
/// every read. Its one row is `all`, so a read that worked would cover every
/// device.
async fn unreadable_scope(app: &TestApp) {
    use meshharbor_services::dao::rc_resume_scope::RC_RESUME_SCOPE;
    const SOURCE: &str = "fr130_unreadable_scope";
    app.db
        .collection::<Document>(RC_RESUME_SCOPE)
        .drop()
        .await
        .expect("the scope's collection drops");
    app.db
        .collection::<Document>(SOURCE)
        .insert_one(doc! { "kind": "all", "zero": 0 })
        .await
        .expect("the row the view fails on");
    // A field, not a constant, so the division fails on each read, never at
    // the view's creation; in a `$match`, so no projection can skip it.
    app.db
        .run_command(doc! {
            "create": RC_RESUME_SCOPE,
            "viewOn": SOURCE,
            "pipeline": [ { "$match": { "$expr": { "$gt": [ { "$divide": [1, "$zero"] }, 0 ] } } } ],
        })
        .await
        .expect("the failing view");
    assert!(
        app.state
            .fleet()
            .rc_resume_scope
            .covers(ObjectId::new(), ObjectId::new())
            .await
            .is_err(),
        "the hello's read of the scope fails"
    );
}

/// The view gone, and the scope `all` again, as a collection.
async fn readable_scope_all(app: &TestApp) {
    use meshharbor_services::dao::rc_resume_scope::RC_RESUME_SCOPE;
    app.db
        .collection::<Document>(RC_RESUME_SCOPE)
        .drop()
        .await
        .expect("the view drops");
    scope_all(app).await;
    assert!(
        app.state
            .fleet()
            .rc_resume_scope
            .covers(ObjectId::new(), ObjectId::new())
            .await
            .expect("the scope reads"),
        "`all` covers every device"
    );
}
