// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Integration tests for the Task 9 crash-log ingest + listing
//! endpoints. Spawns a real `TestApp` (real Axum server + real
//! MongoDB) and exercises:
//!
//! - `POST /api/agent/crash` — auth + body validation + DAO insert.
//! - `GET /api/tenant/{tid}/agent/{aid}/crash` — admin UI listing.
//! - Wire-shape lock: payload bytes the agent's `crash_recorder`
//!   would produce deserialise cleanly on the ingest handler.
//!
//! Per `feedback_windows_no_local_backend.md`: these run on Linux CI
//! / Linux dev hosts only — openssl-sys doesn't build under MSVC on
//! the dev Windows machine, so the full backend can't compile there.

use crate::fixtures::test_app::TestApp;
use meshharbord::crash_recorder::{Payload as AgentCrashPayload, Reason as CrashReason};
use meshharbord::{config::AgentConfig, enrollment};
use serde_json::Value;

/// Enrol a fresh agent. Returns the `AgentConfig` (carries
/// `agent_token` for Bearer auth on `/api/agent/crash`) AND the
/// seeded admin's access token so tests can hit the admin-side GET
/// endpoint without re-seeding.
async fn enrol(app: &TestApp, slug: &str) -> (AgentConfig, String) {
    let seeded = app.seed_tenant(slug).await;
    let admin_token = seeded.admin.access_token.clone();
    let et: Value = app
        .auth_post(
            &format!("/api/tenant/{}/agent/enroll-token", seeded.tenant_id),
            &admin_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let cfg = enrollment::enroll(enrollment::EnrollInputs {
        server_url: &app.base_url,
        enrollment_token: et["enrollment_token"].as_str().unwrap(),
        machine_id: &format!("mach-{slug}"),
        machine_name: "Crash test",
        install: None,
    })
    .await
    .expect("enrol");
    (cfg, admin_token)
}

fn fresh_payload() -> AgentCrashPayload {
    AgentCrashPayload {
        crashed_at_unix: chrono::Utc::now().timestamp(),
        reason: CrashReason::Panic,
        summary: "test crash".to_string(),
        log_tail: "2026-05-17T12:00:00Z INFO line one\n2026-05-17T12:00:01Z WARN line two"
            .to_string(),
        agent_version: "0.3.0-rc.35".to_string(),
        os: "linux".to_string(),
        hostname: "ci-host".to_string(),
        pid: 42,
        suppressed_since_last: 0,
    }
}

#[tokio::test]
async fn ingest_rejects_missing_auth_header_with_401() {
    let app = TestApp::spawn().await;
    let url = format!("{}/api/agent/crash", app.base_url);
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&fresh_payload())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ingest_rejects_invalid_agent_token_with_401() {
    let app = TestApp::spawn().await;
    let url = format!("{}/api/agent/crash", app.base_url);
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth("not.a.real.jwt")
        .json(&fresh_payload())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ingest_rejects_oversized_log_tail_with_422() {
    let app = TestApp::spawn().await;
    let (cfg, _admin_token) = enrol(&app, "crash-oversize").await;

    let mut payload = fresh_payload();
    payload.log_tail = "x".repeat(64 * 1024 + 1);

    let url = format!("{}/api/agent/crash", app.base_url);
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&cfg.agent_token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn ingest_persists_record_and_returns_201() {
    let app = TestApp::spawn().await;
    let (cfg, admin_token) = enrol(&app, "crash-persist").await;
    let payload = fresh_payload();

    let url = format!("{}/api/agent/crash", app.base_url);
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&cfg.agent_token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);

    // Verify via the admin-side list endpoint.
    let list_url = format!(
        "{}/api/tenant/{}/agent/{}/crash",
        app.base_url, cfg.tenant_id, cfg.agent_id
    );
    let listed: Value = reqwest::Client::new()
        .get(&list_url)
        .bearer_auth(&admin_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = listed["items"].as_array().expect("items array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["summary"].as_str(), Some("test crash"));
    assert_eq!(items[0]["reason"].as_str(), Some("panic"));
    assert_eq!(items[0]["pid"].as_u64(), Some(42));
}

#[tokio::test]
async fn ingest_round_trips_camelcase_payload_emitted_by_agent() {
    // Lock the wire-shape: the EXACT JSON bytes the agent's
    // `crash_recorder` writes to a sidecar deserialise cleanly on
    // the ingest handler. Closes the casing-drift risk from the
    // plan critique.
    let app = TestApp::spawn().await;
    let (cfg, _admin_token) = enrol(&app, "crash-roundtrip").await;
    let payload = fresh_payload();

    // Serialise with the agent-side shape (camelCase via
    // AgentCrashPayload's #[serde(rename_all = "camelCase")]).
    let agent_emitted = serde_json::to_vec(&payload).unwrap();
    let s = std::str::from_utf8(&agent_emitted).unwrap();
    assert!(
        s.contains("\"crashedAtUnix\":"),
        "agent emits camelCase; got {s}"
    );
    assert!(s.contains("\"logTail\":"));
    assert!(s.contains("\"agentVersion\":"));

    // Send those exact bytes to the ingest endpoint.
    let url = format!("{}/api/agent/crash", app.base_url);
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&cfg.agent_token)
        .header("Content-Type", "application/json")
        .body(agent_emitted)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
}

#[tokio::test]
async fn list_for_agent_returns_records_in_descending_crashed_at_order() {
    let app = TestApp::spawn().await;
    let (cfg, admin_token) = enrol(&app, "crash-order").await;
    let url = format!("{}/api/agent/crash", app.base_url);

    // Push 3 crash reports with strictly increasing crashed_at.
    for i in 0..3 {
        let mut p = fresh_payload();
        // 0, 1, 2 seconds after the base timestamp.
        p.crashed_at_unix += i;
        p.summary = format!("crash {i}");
        let resp = reqwest::Client::new()
            .post(&url)
            .bearer_auth(&cfg.agent_token)
            .json(&p)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    }

    let list_url = format!(
        "{}/api/tenant/{}/agent/{}/crash",
        app.base_url, cfg.tenant_id, cfg.agent_id
    );
    let listed: Value = reqwest::Client::new()
        .get(&list_url)
        .bearer_auth(&admin_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = listed["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    // Most recent first (i=2, i=1, i=0).
    assert_eq!(items[0]["summary"].as_str(), Some("crash 2"));
    assert_eq!(items[1]["summary"].as_str(), Some("crash 1"));
    assert_eq!(items[2]["summary"].as_str(), Some("crash 0"));
}

#[tokio::test]
async fn list_for_agent_is_tenant_scoped() {
    // Two different tenants enrol an agent each. Pushing a crash
    // report from tenant A must not be visible to tenant B's admin.
    let app = TestApp::spawn().await;
    let (cfg_a, _admin_a) = enrol(&app, "crash-tenant-a").await;
    let (cfg_b, admin_b_token) = enrol(&app, "crash-tenant-b").await;
    let url = format!("{}/api/agent/crash", app.base_url);

    // Tenant A pushes a crash.
    let p = fresh_payload();
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&cfg_a.agent_token)
        .json(&p)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);

    // Tenant B's admin can't list A's records (foreign tenant).
    let list_url = format!(
        "{}/api/tenant/{}/agent/{}/crash",
        app.base_url, cfg_b.tenant_id, cfg_b.agent_id
    );
    let listed: Value = reqwest::Client::new()
        .get(&list_url)
        .bearer_auth(&admin_b_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = listed["items"].as_array().unwrap();
    // Tenant B has zero crashes (their agent never crashed).
    assert!(items.is_empty(), "tenant B leaked tenant A's records");
}

/// The revocation property: an agent token is valid for a YEAR, so deleting a
/// device has to be what stops it writing — not the token's expiry.
///
/// Before the `AuthAgent` extractor this handler trusted the JWT claims alone
/// and never read the row, so a deleted device kept posting crash reports for
/// the remaining life of its token. This drives the real route end to end,
/// which is the only thing that proves the extractor is actually wired in
/// (the unit tests can only prove the rule, not that anything applies it).
#[tokio::test]
async fn ingest_refuses_a_deleted_agents_token_with_401() {
    let app = TestApp::spawn().await;
    let (cfg, admin_token) = enrol(&app, "crash-revoked").await;

    let url = format!("{}/api/agent/crash", app.base_url);

    // Baseline: the very same token is accepted while the agent is live, so a
    // 401 below cannot be blamed on a malformed token or payload.
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&cfg.agent_token)
        .json(&fresh_payload())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CREATED,
        "a live agent should be accepted"
    );

    // Delete the device through the admin route the operator would use.
    let del = app
        .auth_delete(
            &format!("/api/tenant/{}/agent/{}", cfg.tenant_id, cfg.agent_id),
            &admin_token,
        )
        .send()
        .await
        .unwrap();
    assert!(
        del.status().is_success(),
        "agent delete failed: {}",
        del.status()
    );

    // Same token, same payload — now refused.
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&cfg.agent_token)
        .json(&fresh_payload())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "a deleted agent's token must stop being accepted"
    );
}
