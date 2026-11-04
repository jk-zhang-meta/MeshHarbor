// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Fleet RPC end-to-end: the browser/API leg driven against a live `TestApp`
//! with the real `roomlerd` library on the other end.
//!
//! What these lock is the thing unit tests can't: that the four gates are
//! actually wired into the ONE path a command takes, that a refusal is a
//! result rather than a hang, and that every attempt — allowed or denied —
//! leaves an audit row. A gate that exists in `authorize()` but is bypassed
//! by some other route into the push would pass every unit test and fail
//! here.

use crate::fixtures::test_app::TestApp;
use meshharbord::{config::AgentConfig, encode::EncoderPreference, enrollment, signaling};
use serde_json::{Value, json};
use std::time::Duration;

/// A command that prints `hello` on whichever shell the host defaults to.
/// CI is Linux, the dev box is Windows, and the agent resolves `""` to the
/// host's own default — so the test has to speak both.
fn echo_hello() -> &'static str {
    if cfg!(windows) {
        "Write-Output hello"
    } else {
        "echo hello"
    }
}

/// Spawn the agent signalling loop, mirroring `run_cmd`'s wiring. Local copy
/// rather than a shared helper because this module needs to vary the config
/// (`exec_enabled`) per test, which is the whole point of gate 4.
fn spawn_agent(
    cfg: AgentConfig,
    stop_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let connected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (view_tx, _view_rx) = tokio::sync::watch::channel(Default::default());
        let broker = meshharbord::consent::ConsentBroker::new(
            meshharbord::consent::Mode::AutoGrant,
            std::env::temp_dir().join(format!("roomler-exec-consent-{}", cfg.agent_id)),
        )
        .expect("consent broker init");
        // Read before `cfg` is moved into the call below.
        let exec_enabled = cfg.exec_enabled;
        let remote_config_enabled = cfg.remote_config_enabled;
        let _ = signaling::run(
            signaling::OrgCtx::primary(meshharbord::token_slot::TokenSlot::new(
                cfg.agent_token.clone(),
            )),
            // FR-43 P2b — no GUI-worker delegation in tests: `Off` is not a
            // stub but the real production value on every platform except a
            // macOS daemon supervising a worker, or the worker it supervises.
            meshharbord::delegate::Delegation::Off,
            cfg,
            EncoderPreference::Software,
            stop_rx,
            connected,
            view_tx,
            Default::default(),
            broker,
            meshharbord::tunnel::client_mgr::TunnelClientHub::new("test".into()),
            // Remote config: tests never PUSH one, but the live `exec_enabled`
            // must still be SEEDED from the config this agent was handed —
            // which is exactly what `main.rs` does. Hardcoding `false` made the
            // harness disagree with production about gate 4, so every test that
            // sets `cfg.exec_enabled = true` was answered "remote execution is
            // disabled on this device".
            meshharbord::remote_config::RemoteConfigServices::new(
                std::path::PathBuf::from("unused-in-tests.toml"),
                std::sync::Arc::new(tokio::sync::Mutex::new(())),
                exec_enabled,
                remote_config_enabled,
            ),
            // FR-27 — the live remote-control session registry. Tests never
            // read it back, but the signalling loop registers into it, so a
            // fresh one per harness is the honest value (not a shared global
            // that would leak sessions between tests).
            meshharbord::rc_sessions::RcSessionRegistry::new(),
        )
        .await;
    })
}

async fn enrol(
    app: &TestApp,
    seeded: &crate::fixtures::seed::SeededTenant,
    machine_id: &str,
) -> AgentConfig {
    let et: Value = app
        .auth_post(
            &format!("/api/tenant/{}/agent/enroll-token", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    enrollment::enroll(enrollment::EnrollInputs {
        server_url: &app.base_url,
        enrollment_token: et["enrollment_token"].as_str().unwrap(),
        machine_id,
        machine_name: "Exec test host",
        install: None,
    })
    .await
    .expect("agent enrollment")
}

/// Wait for the agent's row to report online — the exec push needs a live WS,
/// not just an enrolled row.
async fn wait_online(app: &TestApp, seeded: &crate::fixtures::seed::SeededTenant, agent_id: &str) {
    for _ in 0..80 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let row: Value = app
            .auth_get(
                &format!("/api/tenant/{}/agent/{}", seeded.tenant_id, agent_id),
                &seeded.admin.access_token,
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if row["is_online"].as_bool() == Some(true) {
            return;
        }
    }
    panic!("agent never came online");
}

async fn set_org_exec(app: &TestApp, seeded: &crate::fixtures::seed::SeededTenant, on: bool) {
    let resp = app
        .auth_put(
            &format!("/api/tenant/{}/exec-settings", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .json(&json!({ "remote_exec_enabled": on }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "org switch: {:?}",
        resp.status()
    );
}

async fn set_device_policy(
    app: &TestApp,
    seeded: &crate::fixtures::seed::SeededTenant,
    agent_id: &str,
    body: Value,
) {
    let resp = app
        .auth_put(
            &format!(
                "/api/tenant/{}/agent/{}/exec-policy",
                seeded.tenant_id, agent_id
            ),
            &seeded.admin.access_token,
        )
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "policy: {:?}", resp.status());
}

async fn run_exec(
    app: &TestApp,
    seeded: &crate::fixtures::seed::SeededTenant,
    token: &str,
    agent_id: &str,
    command: &str,
) -> Value {
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/agent/{}/exec", seeded.tenant_id, agent_id),
            token,
        )
        .json(&json!({ "command": command, "timeout_ms": 20_000 }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "exec route returned {:?} — a POLICY refusal must be a 200 with an \
         error body, not a transport failure",
        resp.status()
    );
    resp.json().await.unwrap()
}

async fn audit_rows(app: &TestApp, seeded: &crate::fixtures::seed::SeededTenant) -> Vec<Value> {
    let body: Value = app
        .auth_get(
            &format!("/api/tenant/{}/exec-audit", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["items"].as_array().cloned().unwrap_or_default()
}

/// The happy path, end to end: all four gates open, a real process runs on the
/// agent side, its stdout comes back, and the attempt is audited.
#[tokio::test]
async fn exec_runs_a_command_and_audits_it() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("execok").await;
    let mut cfg = enrol(&app, &seeded, "mach-exec-ok").await;
    // Gate 4 — the device owner allows it.
    cfg.exec_enabled = true;

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let task = spawn_agent(cfg.clone(), stop_rx);
    wait_online(&app, &seeded, &cfg.agent_id).await;

    set_org_exec(&app, &seeded, true).await;
    set_device_policy(
        &app,
        &seeded,
        &cfg.agent_id,
        json!({ "mode": "on", "consent_mode": "auto" }),
    )
    .await;

    let out = run_exec(
        &app,
        &seeded,
        &seeded.admin.access_token,
        &cfg.agent_id,
        echo_hello(),
    )
    .await;

    assert_eq!(out["error"], Value::Null, "command should have run: {out}");
    assert_eq!(out["exit_code"], json!(0));
    assert!(
        out["stdout"].as_str().unwrap_or_default().contains("hello"),
        "stdout was {:?}",
        out["stdout"]
    );

    let rows = audit_rows(&app, &seeded).await;
    assert_eq!(rows.len(), 1, "exactly one attempt should be recorded");
    assert_eq!(rows[0]["denied"], Value::Null);
    assert_eq!(rows[0]["exit_code"], json!(0));
    assert_eq!(rows[0]["command"], json!(echo_hello()));
    assert_eq!(rows[0]["source"], json!("ui"));

    // Ids and timestamps must be plain strings, not bson extended JSON.
    // Serialising `ExecAuditEvent` straight to the client yields
    // `{"$oid": …}` / `{"$date": …}`, which no client here parses — the audit
    // table would render `[object Object]` for every id.
    assert!(
        rows[0]["agent_id"].is_string(),
        "agent_id must be a hex string, got {:?}",
        rows[0]["agent_id"]
    );
    assert!(
        rows[0]["user_id"].is_string(),
        "user_id must be a hex string, got {:?}",
        rows[0]["user_id"]
    );
    assert!(
        rows[0]["at"].is_string(),
        "at must be an RFC3339 string, got {:?}",
        rows[0]["at"]
    );
    assert_eq!(rows[0]["agent_id"], json!(cfg.agent_id));

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

/// A non-zero exit is a RESULT, not an error: `error` stays null and the code
/// passes through. The console and the CLI both key off that distinction.
#[tokio::test]
async fn nonzero_exit_is_not_an_error() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("execexit").await;
    let mut cfg = enrol(&app, &seeded, "mach-exec-exit").await;
    cfg.exec_enabled = true;

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let task = spawn_agent(cfg.clone(), stop_rx);
    wait_online(&app, &seeded, &cfg.agent_id).await;

    set_org_exec(&app, &seeded, true).await;
    set_device_policy(
        &app,
        &seeded,
        &cfg.agent_id,
        json!({ "mode": "on", "consent_mode": "auto" }),
    )
    .await;

    let out = run_exec(
        &app,
        &seeded,
        &seeded.admin.access_token,
        &cfg.agent_id,
        "exit 3",
    )
    .await;
    assert_eq!(
        out["error"],
        Value::Null,
        "a failing command is not a refusal"
    );
    assert_eq!(out["exit_code"], json!(3));

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

/// Gate 1 — the org kill-switch. Off by DEFAULT, so this also proves the
/// feature is inert until an org owner deliberately turns it on.
#[tokio::test]
async fn gate1_org_switch_off_denies_and_is_audited() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("execgate1").await;
    let mut cfg = enrol(&app, &seeded, "mach-exec-g1").await;
    cfg.exec_enabled = true;

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let task = spawn_agent(cfg.clone(), stop_rx);
    wait_online(&app, &seeded, &cfg.agent_id).await;

    // Device fully open; ONLY the org switch is shut (never touched — this is
    // the default state of a fresh tenant).
    set_device_policy(
        &app,
        &seeded,
        &cfg.agent_id,
        json!({ "mode": "on", "consent_mode": "auto" }),
    )
    .await;

    let out = run_exec(
        &app,
        &seeded,
        &seeded.admin.access_token,
        &cfg.agent_id,
        echo_hello(),
    )
    .await;
    assert!(
        out["error"]
            .as_str()
            .unwrap_or_default()
            .contains("organization"),
        "expected an org-level refusal, got {out}"
    );
    assert_eq!(out["exit_code"], Value::Null);

    let rows = audit_rows(&app, &seeded).await;
    assert_eq!(rows.len(), 1, "a REFUSAL must be audited too");
    assert_eq!(rows[0]["denied"], json!("org_disabled"));

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

/// Gate 2 — the caller's permission. The seeded `member` holds
/// `DEFAULT_MEMBER`, which deliberately excludes `EXEC_DEVICE`.
#[tokio::test]
async fn gate2_missing_permission_denies() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("execgate2").await;
    let mut cfg = enrol(&app, &seeded, "mach-exec-g2").await;
    cfg.exec_enabled = true;

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let task = spawn_agent(cfg.clone(), stop_rx);
    wait_online(&app, &seeded, &cfg.agent_id).await;

    set_org_exec(&app, &seeded, true).await;
    set_device_policy(
        &app,
        &seeded,
        &cfg.agent_id,
        json!({ "mode": "on", "consent_mode": "auto" }),
    )
    .await;

    // Everything open EXCEPT the caller's role.
    let out = run_exec(
        &app,
        &seeded,
        &seeded.member.access_token,
        &cfg.agent_id,
        echo_hello(),
    )
    .await;
    assert!(
        out["error"]
            .as_str()
            .unwrap_or_default()
            .contains("permission"),
        "expected a permission refusal, got {out}"
    );

    let rows = audit_rows(&app, &seeded).await;
    assert_eq!(rows[0]["denied"], json!("no_permission"));
    assert_eq!(
        rows[0]["user_id"],
        json!(seeded.member.id),
        "the audit row must name WHO was refused"
    );

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

/// Gate 3 — the device's own policy, which is `off` on every device that
/// existed before the feature.
#[tokio::test]
async fn gate3_device_policy_off_denies() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("execgate3").await;
    let mut cfg = enrol(&app, &seeded, "mach-exec-g3").await;
    cfg.exec_enabled = true;

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let task = spawn_agent(cfg.clone(), stop_rx);
    wait_online(&app, &seeded, &cfg.agent_id).await;

    set_org_exec(&app, &seeded, true).await;
    // Device policy deliberately NOT set — the enrolled default must refuse.

    let out = run_exec(
        &app,
        &seeded,
        &seeded.admin.access_token,
        &cfg.agent_id,
        echo_hello(),
    )
    .await;
    assert!(
        out["error"].as_str().unwrap_or_default().contains("device"),
        "expected a device-level refusal, got {out}"
    );

    let rows = audit_rows(&app, &seeded).await;
    assert_eq!(rows[0]["denied"], json!("device_disabled"));

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

/// Gate 4 — the device's own `exec_enabled`. The server says yes to
/// everything; the AGENT refuses, and that refusal has to travel back as a
/// result rather than as silence, or the caller would hang out its deadline.
#[tokio::test]
async fn gate4_agent_local_switch_off_denies() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("execgate4").await;
    let cfg = enrol(&app, &seeded, "mach-exec-g4").await;
    assert!(
        !cfg.exec_enabled,
        "a freshly enrolled device must default to exec_enabled=false"
    );

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let task = spawn_agent(cfg.clone(), stop_rx);
    wait_online(&app, &seeded, &cfg.agent_id).await;

    set_org_exec(&app, &seeded, true).await;
    set_device_policy(
        &app,
        &seeded,
        &cfg.agent_id,
        json!({ "mode": "on", "consent_mode": "auto" }),
    )
    .await;

    let out = run_exec(
        &app,
        &seeded,
        &seeded.admin.access_token,
        &cfg.agent_id,
        echo_hello(),
    )
    .await;
    assert!(
        out["error"]
            .as_str()
            .unwrap_or_default()
            .contains("disabled on this device"),
        "expected the agent's own refusal, got {out}"
    );
    assert_eq!(out["exit_code"], Value::Null);

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

/// A shell the device's policy doesn't list is refused BEFORE anything is
/// pushed — the narrowing is real, not decorative.
#[tokio::test]
async fn shell_allowlist_is_enforced() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("execshell").await;
    let mut cfg = enrol(&app, &seeded, "mach-exec-shell").await;
    cfg.exec_enabled = true;

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let task = spawn_agent(cfg.clone(), stop_rx);
    wait_online(&app, &seeded, &cfg.agent_id).await;

    set_org_exec(&app, &seeded, true).await;
    set_device_policy(
        &app,
        &seeded,
        &cfg.agent_id,
        json!({ "mode": "on", "consent_mode": "auto", "shells": ["nushell"] }),
    )
    .await;

    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/agent/{}/exec",
                seeded.tenant_id, cfg.agent_id
            ),
            &seeded.admin.access_token,
        )
        .json(&json!({ "shell": "bash", "command": "id", "timeout_ms": 10_000 }))
        .send()
        .await
        .unwrap();
    let out: Value = resp.json().await.unwrap();
    assert!(
        out["error"].as_str().unwrap_or_default().contains("shell"),
        "expected a shell refusal, got {out}"
    );

    let rows = audit_rows(&app, &seeded).await;
    assert_eq!(rows[0]["denied"], json!("shell_not_allowed"));

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

/// A device that is enrolled but has no live WS can't be pushed to. The
/// caller must get a prompt "offline", not a deadline-length wait.
#[tokio::test]
async fn offline_device_fails_fast() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("execoffline").await;
    let cfg = enrol(&app, &seeded, "mach-exec-offline").await;
    // Deliberately never start the signalling loop.

    set_org_exec(&app, &seeded, true).await;
    set_device_policy(
        &app,
        &seeded,
        &cfg.agent_id,
        json!({ "mode": "on", "consent_mode": "auto" }),
    )
    .await;

    let started = std::time::Instant::now();
    let out = run_exec(
        &app,
        &seeded,
        &seeded.admin.access_token,
        &cfg.agent_id,
        echo_hello(),
    )
    .await;
    assert!(
        out["error"]
            .as_str()
            .unwrap_or_default()
            .contains("offline"),
        "expected an offline refusal, got {out}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "an offline device must fail fast, took {:?}",
        started.elapsed()
    );

    let rows = audit_rows(&app, &seeded).await;
    assert_eq!(rows[0]["denied"], json!("offline"));
}

/// Cross-tenant: a device enrolled in org A must not be reachable through
/// org B's route even by someone who knows its id.
#[tokio::test]
async fn cross_tenant_exec_is_refused() {
    let app = TestApp::spawn().await;
    let a = app.seed_tenant("execorga").await;
    let b = app.seed_tenant("execorgb").await;
    let mut cfg = enrol(&app, &a, "mach-exec-xorg").await;
    cfg.exec_enabled = true;

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let task = spawn_agent(cfg.clone(), stop_rx);
    wait_online(&app, &a, &cfg.agent_id).await;

    set_org_exec(&app, &a, true).await;
    set_org_exec(&app, &b, true).await;
    set_device_policy(
        &app,
        &a,
        &cfg.agent_id,
        json!({ "mode": "on", "consent_mode": "auto" }),
    )
    .await;

    // Org B's admin, org B's route, org A's device.
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/agent/{}/exec", b.tenant_id, cfg.agent_id),
            &b.admin.access_token,
        )
        .json(&json!({ "command": echo_hello() }))
        .send()
        .await
        .unwrap();
    assert!(
        !resp.status().is_success(),
        "a foreign device must not resolve inside another org, got {:?}",
        resp.status()
    );

    // …and org B's audit must hold nothing: the request never reached the
    // dispatch path, so there is no attempt to record for that org.
    let rows = audit_rows(&app, &b).await;
    assert!(rows.is_empty(), "org B should have no audit rows: {rows:?}");

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}

/// A non-member is refused BEFORE the device is looked up, so the response
/// can't be used to enumerate an org's fleet.
///
/// Gate 2 lives inside `authorize` so its refusals are audited — which means
/// without a membership check the handler would reach the device lookup on
/// behalf of a total stranger and hand back device names in the refusal body.
#[tokio::test]
async fn non_member_cannot_enumerate_devices_via_exec() {
    let app = TestApp::spawn().await;
    let a = app.seed_tenant("execmemba").await;
    let b = app.seed_tenant("execmembb").await;
    let cfg = enrol(&app, &a, "mach-exec-memb").await;

    set_org_exec(&app, &a, true).await;
    set_device_policy(
        &app,
        &a,
        &cfg.agent_id,
        json!({ "mode": "on", "consent_mode": "auto" }),
    )
    .await;

    // Org B's admin is a stranger to org A.
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/agent/{}/exec", a.tenant_id, cfg.agent_id),
            &b.admin.access_token,
        )
        .json(&json!({ "command": echo_hello() }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "a non-member must be refused outright, not handed a device name"
    );
    let body = resp.text().await.unwrap_or_default();
    assert!(
        !body.contains("Exec test host"),
        "the refusal must not leak the device name: {body}"
    );

    // The fleet sweep must be closed the same way.
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/agent/exec", a.tenant_id),
            &b.admin.access_token,
        )
        .json(&json!({ "command": echo_hello() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403, "bulk sweep leaks the roster");
}

/// The audit sample is capped, and long output is flagged truncated rather
/// than silently shortened.
#[tokio::test]
async fn long_output_is_capped_and_flagged() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("exectrunc").await;
    let mut cfg = enrol(&app, &seeded, "mach-exec-trunc").await;
    cfg.exec_enabled = true;

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let task = spawn_agent(cfg.clone(), stop_rx);
    wait_online(&app, &seeded, &cfg.agent_id).await;

    set_org_exec(&app, &seeded, true).await;
    set_device_policy(
        &app,
        &seeded,
        &cfg.agent_id,
        json!({ "mode": "on", "consent_mode": "auto" }),
    )
    .await;

    let flood = if cfg!(windows) {
        "1..3000 | ForEach-Object { 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' }"
    } else {
        "for i in $(seq 1 3000); do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done"
    };
    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/agent/{}/exec",
                seeded.tenant_id, cfg.agent_id
            ),
            &seeded.admin.access_token,
        )
        .json(&json!({ "command": flood, "timeout_ms": 30_000, "max_output_bytes": 4096 }))
        .send()
        .await
        .unwrap();
    let out: Value = resp.json().await.unwrap();
    assert_eq!(out["truncated"], json!(true), "expected truncation: {out}");
    let len = out["stdout"].as_str().unwrap_or_default().len();
    assert!(len <= 4096, "returned {len} bytes past a 4096 cap");

    let rows = audit_rows(&app, &seeded).await;
    assert_eq!(rows[0]["truncated"], json!(true));
    assert!(
        rows[0]["output_sha256"].as_str().unwrap_or_default().len() == 64,
        "the audit row must carry a full-output hash even when the sample is cut"
    );

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}
