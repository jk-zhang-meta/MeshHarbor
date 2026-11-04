// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Phase 5 — tunnel subsystem integration tests.
//!
//! Covers the REST + ACL surface end-to-end against a live `TestApp`.
//! Higher-leverage than unit tests in `crates/tunnel-core/` because
//! it exercises the full request → DAO → response cycle (incl. JSON
//! adjacent-tagged serde for `PolicySubject` / `PolicyTarget` /
//! `DestinationRule`), the cross-tenant gate, and the tunnel-client
//! enrollment idempotence the rehydrate path is supposed to guarantee.
//!
//! Tests:
//!
//! * `policy_crud_round_trips` — POST → GET list → GET one → PUT →
//!   GET one (verifies update applied) → DELETE → gone-from-listing.
//!   Locks the policy CRUD wire shape (`{kind, id}` subjects) that the
//!   admin UI consumes; a serde drift on any of the adjacently-tagged
//!   enums (e.g. someone renames `kind` to `t`) would break the admin
//!   UI silently — this catches it server-side first.
//!
//! * `tunnel_client_enrollment_idempotent_on_same_machine_id` —
//!   enrol → enrol again with the same `machine_id` → assert the
//!   second response carries the same `tunnel_client_id`. Locks the
//!   `find_by_tenant_and_machine` + `rehydrate` path. Without this
//!   the operator who re-runs `meshharbor enroll` after a config
//!   loss would mint a fresh row each time and the listing UI would
//!   show ghosts.
//!
//! * `cross_tenant_enrollment_rejected` — admin from tenant A
//!   cannot issue an enrollment token for tenant B. Validates the
//!   `is_member` gate at the route level. Sev0 per the tunnel
//!   architecture (cross-tenant boundary is the only defence
//!   against an admin in tenant A exfiltrating an enrollment token
//!   that grants tunnel access into tenant B's agents).
//!
//! * `agent_originates_tunnel_authorized_and_relayed_to_target` (P3b-2)
//!   — an agent drives the tunnel-CLIENT role over its own agent WS
//!   (`Principal::Agent`), opens a tunnel to another agent, and the
//!   server authorizes it (via an `all_users` policy) + relays the TCP
//!   forward to the target. Locks the identity-model-(b) origination
//!   path end-to-end.
//!
//! * `agent_tunnel_open_cross_tenant_rejected` (P3b-2) — the cross-tenant
//!   wall holds for an agent origin (a tenant-1 agent must not open a
//!   tunnel to a tenant-2 agent).
//!
//! * `agent_daemon_originated_forward_reaches_target` (P3b-2 PR-C) — the
//!   DAEMON consumer end-to-end: origin A's REAL signaling loop runs with a
//!   `TunnelClientHub`, the test drives `create_forward` on it (the LocalAPI
//!   verb's path), and then polls `flows()` until the flow reports its
//!   NEGOTIATED transport — which the per-session source records only when it
//!   yields `rc:tunnel.opened` to the driver. That proves the whole consumer
//!   path: `create_forward` → nonce-stamped `rc:tunnel.open` → server
//!   `Principal::Agent` authz (all_users policy) → `rc:tunnel.opened` demuxed
//!   BACK BY NONCE. Also asserts `flows()` reflects the flow + `kill_flow`
//!   tears it down. (Target B stays online so the open passes the server's
//!   target-online check.)
//!
//! * `tunnel_grace_defers_then_terminates_when_target_stays_offline` (R3) — with
//!   `rc.tunnel_grace_secs > 0`, dropping the TARGET agent's WS does NOT
//!   immediately push `rc:tunnel.terminate` to the client; the server holds the
//!   session for the window and terminates only after the agent stays offline.
//!
//! * `tunnel_grace_reregister_cancels_terminate` (R3) — the target re-registers
//!   inside the window and the pending terminate is cancelled, so the client's
//!   session survives the control-WS blip (the server half of peer-survival).
//!
//! The assertion deliberately stops at the OPEN handshake. The subsequent
//! WebRTC DC data plane (peer build → SDP offer → answer → DC pool → TCP byte
//! exchange) is NOT covered here — the in-process ICE flakiness in
//! `agent_tests::agent_answers_sdp_offer_with_real_webrtc_peer` (see its
//! "best-effort" comment) makes it too unstable for CI without a TURN fixture.
//! The flow is killed right after the open, before that data plane; the
//! byte-level round-trip is validated on real hosts via the `tunnel-fleet-test`
//! field gate.

use crate::fixtures::test_app::TestApp;
use futures::{SinkExt, StreamExt};
use meshharbord::config::AgentConfig;
use meshharbord::encode::EncoderPreference;
use meshharbord::tunnel::client_mgr::TunnelClientHub;
use meshharbord::{enrollment, signaling};
use serde_json::{Value, json};
use std::time::Duration;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};

#[tokio::test]
async fn policy_crud_round_trips() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("tunnel-policy-crud").await;

    // --- CREATE ---
    // Subjects: the seeded admin user.
    // Targets: AllAgents (catch-all — tenant-wide).
    // Allowlist: one rule allowing the loopback range on a high port.
    // Wire shape locks (see crates/remote_control/src/models.rs):
    //   - HostPattern: adjacently-tagged `{kind, value}`,
    //     variants snake_cased — `cidr` / `exact` / `wildcard`.
    //   - PolicySubject: internally-tagged `{kind, id}` — `kind` names
    //     the variant (`user_id` / `role_id` / `tunnel_client_id` /
    //     `agent_id` / `all_users`) and the data field is ALWAYS `id`
    //     (`#[serde(rename = "id")]`), NOT the kind's own name. Locked
    //     against the admin UI, which posts `{kind, id}` (see
    //     ui/src/stores/tunnelPolicies.ts). `all_users` is a bare
    //     `{kind: "all_users"}` unit.
    //   - PolicyTarget: internally-tagged the same way — `{kind, id}`
    //     for `agent_id`, bare `{kind}` for `all_agents`.
    let create_body = json!({
        "name": "loopback-test",
        "subjects": [
            { "kind": "user_id", "id": seeded.admin.id }
        ],
        "targets": [
            { "kind": "all_agents" }
        ],
        "allowlist": [
            {
                "host_pattern": { "kind": "cidr", "value": "127.0.0.0/8" },
                "port_range": { "low": 9000, "high": 9999 }
            }
        ],
        "max_concurrent_flows": 32,
        "max_bytes_per_session": 1048576
    });
    let created: Value = app
        .auth_post(
            &format!("/api/tenant/{}/tunnel-policy", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .json(&create_body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let policy_id = created["id"]
        .as_str()
        .expect("policy id in create response");
    assert_eq!(created["name"].as_str(), Some("loopback-test"));
    assert_eq!(
        created["tenant_id"].as_str(),
        Some(seeded.tenant_id.as_str()),
        "policy must be tenant-scoped"
    );
    assert_eq!(
        created["max_concurrent_flows"].as_u64(),
        Some(32),
        "max_concurrent_flows round-trips"
    );

    // --- LIST ---
    let list: Value = app
        .auth_get(
            &format!("/api/tenant/{}/tunnel-policy", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = list["items"].as_array().expect("items in list response");
    assert_eq!(items.len(), 1, "exactly one policy");
    assert_eq!(items[0]["id"].as_str(), Some(policy_id));

    // --- GET one ---
    let fetched: Value = app
        .auth_get(
            &format!(
                "/api/tenant/{}/tunnel-policy/{}",
                seeded.tenant_id, policy_id
            ),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fetched["name"].as_str(), Some("loopback-test"));
    // Adjacent-tag wire-shape lock: the allowlist must round-trip with
    // the exact `kind` discriminator the admin UI's TypeScript expects.
    let allowlist = fetched["allowlist"].as_array().expect("allowlist array");
    assert_eq!(allowlist.len(), 1);
    assert_eq!(
        allowlist[0]["host_pattern"]["kind"].as_str(),
        Some("cidr"),
        "host_pattern.kind must serialise as adjacently-tagged 'cidr'"
    );
    assert_eq!(
        allowlist[0]["host_pattern"]["value"].as_str(),
        Some("127.0.0.0/8")
    );

    // --- UPDATE (rename + clear max_concurrent_flows via null) ---
    let update_body = json!({
        "name": "loopback-renamed",
        "max_concurrent_flows": null
    });
    let updated: Value = app
        .auth_put(
            &format!(
                "/api/tenant/{}/tunnel-policy/{}",
                seeded.tenant_id, policy_id
            ),
            &seeded.admin.access_token,
        )
        .json(&update_body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        updated["name"].as_str(),
        Some("loopback-renamed"),
        "update must apply"
    );
    assert!(
        updated["max_concurrent_flows"].is_null(),
        "max_concurrent_flows null clears the ceiling"
    );
    // Subjects/targets/allowlist were OMITTED in the update body —
    // they must be unchanged (locks the partial-update semantic).
    let allowlist_after = updated["allowlist"]
        .as_array()
        .expect("allowlist still present");
    assert_eq!(
        allowlist_after.len(),
        1,
        "omitted fields must NOT be cleared by partial update"
    );

    // --- DELETE ---
    let resp = app
        .auth_delete(
            &format!(
                "/api/tenant/{}/tunnel-policy/{}",
                seeded.tenant_id, policy_id
            ),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "delete returns 2xx; got {}",
        resp.status()
    );

    // --- After delete: removal is FINAL on every per-policy route (#1829) ---
    // `soft_delete` sets `deleted_at` and the row stays as a tombstone. The
    // listing the admin UI reads and the forward gate's compile set
    // (`list_for_tenant` / `list_active_for_tenant`) filter `deleted_at:
    // null`, and the per-id lookup now agrees with them: GET-one is a 404,
    // PUT is a 404 and writes nothing, a repeat DELETE is a 404. This
    // assertion once said "GET-one still returns the tombstone — a deferred
    // API-semantics call"; #1824 made that call for agents, and a deleted
    // POLICY has even less business being served or edited.
    //
    // Negative control (recorded on the PR): with the `deleted_at` predicate
    // taken out of the lookup this fails at "GET of a removed policy" with
    // 200; with it taken out of the write filter, at "a write must not land
    // on a tombstone".
    use bson::{Bson, doc, oid::ObjectId};
    use meshharbor_services::dao::base::DaoError;
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let pid = ObjectId::parse_str(policy_id).unwrap();
    let policies = app.db.collection::<bson::Document>("tunnel_policies");
    let row = policies
        .find_one(doc! { "_id": pid })
        .await
        .unwrap()
        .expect("a deleted policy tombstones in place");
    let removed_at = match row.get("deleted_at") {
        Some(Bson::DateTime(at)) => *at,
        other => panic!("tombstone must carry a removal time, got {other:?}"),
    };
    let one = format!(
        "/api/tenant/{}/tunnel-policy/{}",
        seeded.tenant_id, policy_id
    );

    // GET: 404, exactly like a bogus id.
    let resp = app
        .auth_get(&one, &seeded.admin.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "GET of a removed policy");

    // PUT: 404 — and nothing lands on the tombstone (the earlier PUT left
    // the name at `loopback-renamed`; that is what the row must still say).
    let resp = app
        .auth_put(&one, &seeded.admin.access_token)
        .json(&json!({ "name": "zombie" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "PUT on a removed policy");
    let row = policies
        .find_one(doc! { "_id": pid })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.get_str("name").unwrap(),
        "loopback-renamed",
        "the PUT must not land on the tombstone"
    );

    // The writes are live-scoped on their own, not only behind the routes'
    // lookup ("a gate applies at every entry point, or it is a courtesy").
    let network = app.state.network();
    assert!(
        !network
            .tunnel_policies
            .update(tid, pid, Some("dao".into()), None, None, None, None, None)
            .await
            .unwrap(),
        "a write must not land on a tombstone"
    );
    // The removal time is written once: a repeat tombstoning is a no-op.
    assert!(!network.tunnel_policies.soft_delete(tid, pid).await.unwrap());
    let row = policies
        .find_one(doc! { "_id": pid })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.get_datetime("deleted_at").unwrap(), &removed_at);
    assert_eq!(row.get_str("name").unwrap(), "loopback-renamed");

    // The two lookups differ by NAME: LIVE is NotFound, ANY still sees the
    // tombstone (the reader an audit log of this policy would need).
    assert!(matches!(
        network.tunnel_policies.find_live_in_tenant(tid, pid).await,
        Err(DaoError::NotFound)
    ));
    assert!(
        network
            .tunnel_policies
            .find_any_in_tenant(tid, pid)
            .await
            .unwrap()
            .deleted_at
            .is_some()
    );

    // The gate's compile input no longer carries it — a deleted policy is
    // never COMPILED, and the evaluator would skip it even if it were
    // (`tunnel_core::policy`, locked by `soft_deleted_policy_is_ignored`).
    let active = network
        .tunnel_policies
        .list_active_for_tenant(tid)
        .await
        .unwrap();
    assert!(
        active.iter().all(|p| p.id != Some(pid)),
        "a deleted policy must not reach the forward gate"
    );

    // A repeat DELETE is a 404 — the same answer the listing gives, and the
    // one that leaves the removal time alone.
    let resp = app
        .auth_delete(&one, &seeded.admin.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "a repeat DELETE");

    // --- LIST after delete → policy gone from the active listing ---
    let list_after: Value = app
        .auth_get(
            &format!("/api/tenant/{}/tunnel-policy", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let remaining = list_after["items"].as_array().expect("items after delete");
    assert!(
        remaining
            .iter()
            .all(|p| p["id"].as_str() != Some(policy_id)),
        "soft-deleted policy must not appear in the active listing"
    );
}

/// #1829 — the live predicate is `deleted_at: null`, which is null OR
/// ABSENT: a row that never carried the field was never tombstoned, and it is
/// the predicate the listing and the gate's compile set use, so the three
/// views agree by construction. `tunnel_policies` has no `$type: "null"`
/// partial index to mirror (no unique index at all — only the plain
/// `(tenant_id, deleted_at)` compound that serves this very equality); a
/// `$type` predicate here would 404 a live policy whose field is missing and
/// drop it from the per-id view while the gate still compiled it.
#[tokio::test]
async fn a_live_tunnel_policy_whose_deleted_at_field_is_absent_is_still_live() {
    use bson::{doc, oid::ObjectId};

    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("tunnel-policy-absent").await;
    let admin = &seeded.admin.access_token;
    let created: Value = app
        .auth_post(
            &format!("/api/tenant/{}/tunnel-policy", seeded.tenant_id),
            admin,
        )
        .json(&json!({
            "name": "absent-field",
            "subjects": [{ "kind": "all_users" }],
            "targets": [{ "kind": "all_agents" }],
            "allowlist": [{
                "host_pattern": { "kind": "cidr", "value": "127.0.0.0/8" },
                "port_range": { "low": 9000, "high": 9999 }
            }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let policy_id = created["id"].as_str().expect("policy id").to_string();
    let pid = ObjectId::parse_str(&policy_id).unwrap();
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let one = format!(
        "/api/tenant/{}/tunnel-policy/{}",
        seeded.tenant_id, policy_id
    );

    app.db
        .collection::<bson::Document>("tunnel_policies")
        .update_one(doc! { "_id": pid }, doc! { "$unset": { "deleted_at": "" } })
        .await
        .unwrap();

    let resp = app.auth_get(&one, admin).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200, "GET: absent is live");
    let resp = app
        .auth_put(&one, admin)
        .json(&json!({ "name": "still-here" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "PUT: absent is live");
    let list: Value = app
        .auth_get(
            &format!("/api/tenant/{}/tunnel-policy", seeded.tenant_id),
            admin,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        list["items"].as_array().unwrap().len(),
        1,
        "the listing agrees"
    );
    let active = app
        .state
        .network()
        .tunnel_policies
        .list_active_for_tenant(tid)
        .await
        .unwrap();
    assert!(
        active.iter().any(|p| p.id == Some(pid)),
        "the gate still compiles it"
    );
}

/// Enrol a tunnel client the way the CLI does: an admin mints the enrollment
/// token, the client exchanges it. Returns the new row's id.
async fn enroll_tunnel_client(
    app: &TestApp,
    seeded: &crate::fixtures::seed::SeededTenant,
    machine_id: &str,
    machine_name: &str,
) -> String {
    let et: Value = app
        .auth_post(
            &format!(
                "/api/tenant/{}/tunnel-client/enroll-token",
                seeded.tenant_id
            ),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let enrolled: Value = app
        .client
        .post(format!("{}/api/tunnel-client/enroll", app.base_url))
        .json(&json!({
            "enrollment_token": et["enrollment_token"].as_str().expect("enrollment_token"),
            "machine_id": machine_id,
            "machine_name": machine_name,
            "os": "linux",
            "client_version": "0.3.0-test"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    enrolled["tunnel_client_id"]
        .as_str()
        .expect("tunnel_client_id in enroll response")
        .to_string()
}

/// #1829 — removal is FINAL on the per-client routes, not only in the
/// listing. `find_by_id_in_tenant` filtered `{_id, tenant_id}` and nothing
/// else, so after `DELETE …/tunnel-client/{id}` the tombstone still took
/// `PUT` (rename, display name, tags) and a repeat `DELETE` re-ran the whole
/// removal on it. The lookup both routes sit on is live-scoped now, and so
/// are the admin setters underneath it. (There is no `GET …/{id}` for tunnel
/// clients — the listing is the only read.)
///
/// Negative control (recorded on the PR): with the `deleted_at` predicate
/// taken out of the lookup this fails at "PUT on a removed client" with 200;
/// with it taken out of the setters' filter, at "a setter must not land on a
/// tombstone".
#[tokio::test]
async fn a_removed_tunnel_client_is_a_404_on_its_per_client_routes() {
    use bson::{Bson, doc, oid::ObjectId};
    use meshharbor_services::dao::base::DaoError;

    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("tunnel-client-gone").await;
    let admin = seeded.admin.access_token.clone();
    let client_id = enroll_tunnel_client(&app, &seeded, "mach-tcgone-A", "Gone laptop").await;
    let one = format!(
        "/api/tenant/{}/tunnel-client/{}",
        seeded.tenant_id, client_id
    );
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let cid = ObjectId::parse_str(&client_id).unwrap();
    let clients = app.db.collection::<bson::Document>("tunnel_clients");

    // The positive control: the LAST write before the removal — what the
    // tombstone must still say after every write below it has been refused.
    let resp = app
        .auth_put(&one, &admin)
        .json(&json!({ "tags": ["before"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "control: settings write on a live client"
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["client"]["tags"], json!(["before"]));

    // Remove it.
    let resp = app.auth_delete(&one, &admin).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["deleted"], true);

    // The row is a TOMBSTONE, not gone — the case the bug lived in.
    let row = clients
        .find_one(doc! { "_id": cid })
        .await
        .unwrap()
        .expect("a removed tunnel client tombstones in place");
    let removed_at = match row.get("deleted_at") {
        Some(Bson::DateTime(at)) => *at,
        other => panic!("tombstone must carry a removal time, got {other:?}"),
    };

    // PUT: 404, exactly like a bogus id — and none of its three writes
    // reaches the tombstone.
    let resp = app
        .auth_put(&one, &admin)
        .json(&json!({ "name": "zombie", "display_name": "Zombie", "tags": ["after"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "PUT on a removed client");
    let row = clients
        .find_one(doc! { "_id": cid })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.get_str("name").unwrap(), "Gone laptop");
    assert!(row.get("display_name").is_none());
    assert_eq!(
        row.get_array("tags").unwrap(),
        &vec![Bson::String("before".into())],
        "the settings write must not land on the tombstone"
    );

    // The setters are live-scoped on their own, not only behind the route's
    // lookup ("a gate applies at every entry point, or it is a courtesy").
    let network = app.state.network();
    assert!(
        !network
            .tunnel_clients
            .set_tags(tid, cid, &["dao".into()])
            .await
            .unwrap(),
        "a setter must not land on a tombstone"
    );
    assert!(
        !network
            .tunnel_clients
            .rename(tid, cid, "dao")
            .await
            .unwrap()
    );
    // The removal time is written once: a repeat tombstoning is a no-op.
    assert!(!network.tunnel_clients.soft_delete(tid, cid).await.unwrap());
    let row = clients
        .find_one(doc! { "_id": cid })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.get_datetime("deleted_at").unwrap(), &removed_at);
    assert_eq!(row.get_str("name").unwrap(), "Gone laptop");

    // The two lookups differ by NAME. LIVE is NotFound; ANY still sees the
    // tombstone — the contract the tunnel WS connect-time check and the 60 s
    // revocation poll rely on to send the typed `rc:tunnel.revoked` (a LIVE
    // read there would turn a removal into "lookup failed; keeping
    // connection open").
    assert!(matches!(
        network.tunnel_clients.find_live_in_tenant(tid, cid).await,
        Err(DaoError::NotFound)
    ));
    assert!(
        network
            .tunnel_clients
            .find_any_in_tenant(tid, cid)
            .await
            .unwrap()
            .deleted_at
            .is_some()
    );

    // A repeat DELETE is a 404 — the same answer the listing gives, and the
    // one that leaves the state alone (re-finding the tombstone would re-run
    // the overlay release and re-stamp the removal time).
    let resp = app.auth_delete(&one, &admin).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 404, "a repeat DELETE");

    // The two views agree: gone from the listing too.
    let list: Value = app
        .auth_get(
            &format!("/api/tenant/{}/tunnel-client", seeded.tenant_id),
            &admin,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["items"].as_array().unwrap().len(), 0);
}

/// #1829 — the live predicate is `deleted_at: null` (null OR ABSENT), the
/// one every live listing on `tunnel_clients` uses, so the per-id view and
/// the listing agree by construction. The collection's unique index is
/// unconditional (re-enrolling a machine rehydrates its tombstone, as for
/// agents), so no `$type: "null"` partial-index rule binds here; in a query
/// that spelling would 404 a live client whose field is missing.
#[tokio::test]
async fn a_live_tunnel_client_whose_deleted_at_field_is_absent_is_still_live() {
    use bson::{doc, oid::ObjectId};

    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("tunnel-client-absent").await;
    let admin = &seeded.admin.access_token;
    let client_id = enroll_tunnel_client(&app, &seeded, "mach-tcabsent-A", "Absent laptop").await;
    let cid = ObjectId::parse_str(&client_id).unwrap();
    let one = format!(
        "/api/tenant/{}/tunnel-client/{}",
        seeded.tenant_id, client_id
    );

    app.db
        .collection::<bson::Document>("tunnel_clients")
        .update_one(doc! { "_id": cid }, doc! { "$unset": { "deleted_at": "" } })
        .await
        .unwrap();

    let resp = app
        .auth_put(&one, admin)
        .json(&json!({ "tags": ["still-here"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "PUT: absent is live");
    let list: Value = app
        .auth_get(
            &format!("/api/tenant/{}/tunnel-client", seeded.tenant_id),
            admin,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        list["items"].as_array().unwrap().len(),
        1,
        "the listing agrees"
    );
}

#[tokio::test]
async fn tunnel_client_enrollment_idempotent_on_same_machine_id() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("tunnel-enroll-idemp").await;

    // Mint an enrollment token (admin).
    let et: Value = app
        .auth_post(
            &format!(
                "/api/tenant/{}/tunnel-client/enroll-token",
                seeded.tenant_id
            ),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let enroll_token = et["enrollment_token"]
        .as_str()
        .expect("enrollment_token in response")
        .to_string();

    // Enrol once.
    let machine_id = "tunnel-mach-idemp-1";
    let first: Value = app
        .client
        .post(format!("{}/api/tunnel-client/enroll", app.base_url))
        .json(&json!({
            "enrollment_token": enroll_token,
            "machine_id": machine_id,
            "machine_name": "Operator Laptop A",
            "os": "linux",
            "client_version": "0.3.0-test"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let first_id = first["tunnel_client_id"]
        .as_str()
        .expect("tunnel_client_id in first enroll");
    assert!(!first["tunnel_client_token"].as_str().unwrap().is_empty());

    // Mint a second enrollment token. The first one is single-use
    // (JTI tracked server-side) and won't work again.
    let et2: Value = app
        .auth_post(
            &format!(
                "/api/tenant/{}/tunnel-client/enroll-token",
                seeded.tenant_id
            ),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Enrol again with the SAME machine_id but a different label —
    // server should rehydrate the existing row, not mint a new one.
    let second: Value = app
        .client
        .post(format!("{}/api/tunnel-client/enroll", app.base_url))
        .json(&json!({
            "enrollment_token": et2["enrollment_token"].as_str().unwrap(),
            "machine_id": machine_id,
            "machine_name": "Operator Laptop A (renamed)",
            "os": "linux",
            "client_version": "0.3.0-test"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let second_id = second["tunnel_client_id"]
        .as_str()
        .expect("tunnel_client_id in second enroll");

    assert_eq!(
        first_id, second_id,
        "re-enrolment with same machine_id must reuse the row (rehydrate); \
         minting a fresh row would surface as ghost rows in the admin UI"
    );

    // List should show exactly ONE client, not two.
    let list: Value = app
        .auth_get(
            &format!("/api/tenant/{}/tunnel-client", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let items = list["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "rehydrate must not duplicate the row");
    // The rehydrate also updated the friendly name.
    assert_eq!(
        items[0]["name"].as_str(),
        Some("Operator Laptop A (renamed)"),
        "rehydrate must apply the new name"
    );
}

#[tokio::test]
async fn cross_tenant_enrollment_token_request_rejected() {
    // Two separate tenants; admin from tenant A tries to mint an
    // enrollment token for tenant B's id. Server's `is_member` gate
    // must reject with 403. Locks the cross-tenant boundary at the
    // REST layer — the WS-layer cross-tenant gate (in handle_tunnel_
    // open) is a second line of defence; this one is the first.
    let app = TestApp::spawn().await;
    let tenant_a = app.seed_tenant("tunnel-xtenant-a").await;
    let tenant_b = app.seed_tenant("tunnel-xtenant-b").await;

    let resp = app
        .auth_post(
            &format!(
                "/api/tenant/{}/tunnel-client/enroll-token",
                tenant_b.tenant_id
            ),
            &tenant_a.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        403,
        "admin from tenant A must not mint enrollment tokens for tenant B; \
         got {}",
        resp.status()
    );
}

// ────────────────────────────────────────────────────────────────────────────
// P3b-2: an agent drives the tunnel-CLIENT role over its own agent WS
// ────────────────────────────────────────────────────────────────────────────

type AgentWs = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Enroll an agent via the REST flow; returns `(agent_id_hex, agent_token)`.
/// Mirrors `remote_control_tests::enroll_helper` (duplicated so the tunnel
/// suite stands alone).
pub(crate) async fn enroll_agent(
    app: &TestApp,
    seeded: &crate::fixtures::seed::SeededTenant,
    machine_id: &str,
    machine_name: &str,
) -> (String, String) {
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
    let ej: Value = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": et["enrollment_token"].as_str().unwrap(),
            "machine_id": machine_id,
            "machine_name": machine_name,
            "os": "linux",
            "agent_version": "0.3.0",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (
        ej["agent_id"].as_str().unwrap().to_string(),
        ej["agent_token"].as_str().unwrap().to_string(),
    )
}

fn urlencode(s: &str) -> String {
    s.replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D")
}

/// Connect a RAW agent WS (`?role=agent`) and send `rc:agent.hello` so the
/// Hub registers the agent. Returns the live stream.
pub(crate) async fn connect_agent_ws(
    app: &TestApp,
    agent_token: &str,
    machine_name: &str,
) -> AgentWs {
    connect_agent_ws_inner(app, agent_token, machine_name, None).await
}

/// PR-1 — keyed variant: dials with the S6 tenant-affinity `tid=` like a
/// real (rc.29x+) agent build does. The rehome direction rule only trusts
/// keyed, provably-newer conns, so cross-pod tests that expect a NUDGE
/// must dial keyed.
pub(crate) async fn connect_agent_ws_keyed(
    app: &TestApp,
    agent_token: &str,
    machine_name: &str,
    tid: &str,
) -> AgentWs {
    connect_agent_ws_inner(app, agent_token, machine_name, Some(tid)).await
}

async fn connect_agent_ws_inner(
    app: &TestApp,
    agent_token: &str,
    machine_name: &str,
    tid: Option<&str>,
) -> AgentWs {
    let tid_param = tid.map(|t| format!("&tid={t}")).unwrap_or_default();
    let ws_url = format!(
        "ws://{}/ws?token={}&role=agent{tid_param}",
        app.addr,
        urlencode(agent_token)
    );
    let (mut ws, _) = connect_async(&ws_url).await.expect("agent ws connect");
    ws.send(Message::Text(
        json!({
            "t": "rc:agent.hello",
            "machine_name": machine_name,
            "os": "linux",
            "agent_version": "0.3.0",
            "displays": [],
            "caps": {
                "hw_encoders": [],
                "codecs": ["h264"],
                "has_input_permission": true,
                "supports_clipboard": false,
                "supports_file_transfer": false,
                "max_simultaneous_sessions": 4,
            }
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    ws
}

/// Poll the agent row until `status == "online"` (hello processed → Hub
/// registered), so a subsequent `send_to_agent` relay lands.
///
/// Up to 10 s: it returns the moment the row says online. ⚠️ A reconnect
/// waits for [`wait_agent_offline`] first. Raising this from 2 s to 10 s for
/// a `vault_revoke_tests` failure read as load (2026-10-18, run 39155622658)
/// did not help: that failure was the reconnect race, and it came back on
/// 10 s (2026-10-19, run 39306461861).
pub(crate) async fn wait_agent_online(
    app: &TestApp,
    seeded: &crate::fixtures::seed::SeededTenant,
    agent_id: &str,
) {
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(50)).await;
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
        if row["status"].as_str() == Some("online") {
            return;
        }
    }
    panic!("agent {agent_id} never came online");
}

/// Poll the agent row until it no longer says online: the closed
/// connection's teardown has run. A reconnect waits for this first, as a real
/// restart's gap does.
///
/// ⚠️ Without it, the new hello can race the old connection's teardown. The
/// hello writes `online` before it registers with the hub, so the teardown
/// can still find the hub's slot its own and write `offline`, and that write
/// can land after the hello's. The row then reads offline while the hub holds
/// the new connection. Only a heartbeat writes it online again, and no test
/// device sends one.
pub(crate) async fn wait_agent_offline(
    app: &TestApp,
    seeded: &crate::fixtures::seed::SeededTenant,
    agent_id: &str,
) {
    for _ in 0..200 {
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
        if row["status"].as_str() != Some("online") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("agent {agent_id} never went offline");
}

/// Read WS frames until one arrives whose `t` == `want`, or a 5 s deadline
/// elapses. Non-matching frames are skipped.
pub(crate) async fn read_until(ws: &mut AgentWs, want: &str) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(250), ws.next()).await {
            Ok(Some(Ok(Message::Text(text)))) => {
                if let Ok(v) = serde_json::from_str::<Value>(&text)
                    && v.get("t").and_then(|x| x.as_str()) == Some(want)
                {
                    return Some(v);
                }
            }
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(_))) | Ok(None) => return None,
            Err(_) => continue,
        }
    }
    None
}

#[tokio::test]
async fn agent_originates_tunnel_authorized_and_relayed_to_target() {
    // P3b-2 identity model (b): agent A opens a tunnel to agent B (same
    // tenant) over A's OWN agent WS (Principal::Agent). An `all_users`
    // policy authorizes the forward — PR-A proved AllUsers matches an agent
    // principal — and the server relays the TCP forward to target B.
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("p3b2-agentorig").await;

    // Policy: any user (⇒ any principal, incl. an agent) may reach
    // 127.0.0.1:9000-9999 on any agent in the tenant.
    let policy = json!({
        "name": "allow-loopback",
        "subjects": [{ "kind": "all_users" }],
        "targets": [{ "kind": "all_agents" }],
        "allowlist": [{
            "host_pattern": { "kind": "cidr", "value": "127.0.0.0/8" },
            "port_range": { "low": 9000, "high": 9999 }
        }],
        "max_concurrent_flows": 32,
        "max_bytes_per_session": 1048576
    });
    app.auth_post(
        &format!("/api/tenant/{}/tunnel-policy", seeded.tenant_id),
        &seeded.admin.access_token,
    )
    .json(&policy)
    .send()
    .await
    .unwrap();

    let (a_id, a_tok) = enroll_agent(&app, &seeded, "mach-p3b2-A", "origin-A").await;
    let (b_id, b_tok) = enroll_agent(&app, &seeded, "mach-p3b2-B", "target-B").await;
    let mut a_ws = connect_agent_ws(&app, &a_tok, "origin-A").await;
    let mut b_ws = connect_agent_ws(&app, &b_tok, "target-B").await;
    wait_agent_online(&app, &seeded, &a_id).await;
    wait_agent_online(&app, &seeded, &b_id).await;

    // A drives the tunnel-client role: hello, then open a peer to B.
    a_ws.send(Message::Text(
        json!({
            "t": "rc:tunnel.hello",
            "role": "client",
            "version": "0.3.0",
            "supported_transports": ["webrtc-dc-v1"],
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    a_ws.send(Message::Text(
        json!({
            "t": "rc:tunnel.open",
            "agent_id": b_id,
            "transport": "webrtc-dc-v1",
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();

    let opened = read_until(&mut a_ws, "rc:tunnel.opened")
        .await
        .expect("agent A must receive rc:tunnel.opened for its own origination");
    let session_id = opened["session_id"]
        .as_str()
        .expect("session_id in rc:tunnel.opened")
        .to_string();

    // A requests a TCP forward to 127.0.0.1:9000 — the all_users policy
    // authorizes it for the agent principal.
    a_ws.send(Message::Text(
        json!({
            "t": "rc:tunnel.tcp.request",
            "session_id": session_id,
            "flow_id": 1,
            "dst_host": "127.0.0.1",
            "dst_port": 9000,
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();

    // The server must relay the forward to TARGET agent B — proving the
    // agent-principal authz passed AND the relay reached the target.
    let fwd = read_until(&mut b_ws, "rc:tunnel.tcp.forward")
        .await
        .expect("target agent B must receive the relayed rc:tunnel.tcp.forward");
    assert_eq!(fwd["session_id"].as_str(), Some(session_id.as_str()));
    assert_eq!(fwd["dst_host"].as_str(), Some("127.0.0.1"));
    assert_eq!(fwd["dst_port"].as_u64(), Some(9000));
}

#[tokio::test]
async fn agent_tunnel_open_cross_tenant_rejected() {
    // The cross-tenant wall holds for the agent-origination path: an agent
    // in tenant 1 must not open a tunnel to an agent in tenant 2.
    let app = TestApp::spawn().await;
    let t1 = app.seed_tenant("p3b2-xtenant-1").await;
    let t2 = app.seed_tenant("p3b2-xtenant-2").await;

    let (_a_id, a_tok) = enroll_agent(&app, &t1, "mach-p3b2-xt-A", "A").await;
    let (c_id, _c_tok) = enroll_agent(&app, &t2, "mach-p3b2-xt-C", "C").await;

    let mut a_ws = connect_agent_ws(&app, &a_tok, "A").await;

    a_ws.send(Message::Text(
        json!({
            "t": "rc:tunnel.open",
            "agent_id": c_id,
            "transport": "webrtc-dc-v1",
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();

    let err = read_until(&mut a_ws, "rc:error")
        .await
        .expect("agent A must receive rc:error for a cross-tenant open");
    assert_eq!(
        err["code"].as_str(),
        Some("cross_tenant"),
        "cross-tenant open must be refused with code=cross_tenant"
    );
}

/// Enroll an agent via the agent LIBRARY (returns a full `AgentConfig` pointed
/// at the test server), so we can run its real `signaling::run` loop in-process.
/// Mirrors `agent_tests::enrol_via_agent_lib` (duplicated so the tunnel suite
/// stands alone).
async fn enrol_agent_lib(
    app: &TestApp,
    seeded: &crate::fixtures::seed::SeededTenant,
    machine_id: &str,
    machine_name: &str,
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
        machine_name,
        install: None,
    })
    .await
    .expect("agent enrollment")
}

/// Run the origin agent's real signaling loop with a caller-supplied
/// [`TunnelClientHub`] (so the test can drive `create_forward` on the SAME hub
/// the loop publishes its egress into). Mirrors
/// `agent_tests::spawn_agent_signaling` + the extra P3b-2 PR-C hub arg.
fn spawn_origin_signaling(
    cfg: AgentConfig,
    hub: TunnelClientHub,
    stop_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let connected = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (view_tx, _view_rx) = tokio::sync::watch::channel(Default::default());
        let broker = meshharbord::consent::ConsentBroker::new(
            meshharbord::consent::Mode::AutoGrant,
            std::env::temp_dir().join(format!("meshharbor-test-consent-{}", cfg.agent_id)),
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
            // B1 — the RTT-prober bridge slot. Tests never install a hook, so
            // an empty slot is the correct value, not a stub.
            Default::default(),
            broker,
            hub,
            // Remote config: tests never PUSH one, but the live `exec_enabled`
            // must still be SEEDED from the config this agent was handed —
            // which is exactly what `main.rs` does. See agent_exec_tests for
            // the failure hardcoding `false` produced.
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

/// A free loopback TCP port (bind :0 → read the port → drop). The daemon's
/// `create_forward` re-binds it; the tiny window is a non-issue in a test.
async fn free_local_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

#[tokio::test]
async fn agent_daemon_originated_forward_reaches_target() {
    // P3b-2 PR-C — the DAEMON consumer, end-to-end. Origin agent A runs its REAL
    // signaling loop with a `TunnelClientHub`; the test drives `create_forward`
    // on that same hub (as the LocalAPI verb does). This exercises the full
    // daemon-origination path through BOTH the PR-B2 server code and the PR-C
    // client code:
    //   create_forward → supervised session → DaemonSink stamps `open_nonce`
    //   onto rc:tunnel.open → server relay_tunnel_client_msg_from_agent →
    //   Principal::Agent authz (all_users policy) → rc:tunnel.opened →
    //   client_mgr::intercept_server_msg demuxes it BACK BY NONCE → the driver
    //   builds its peer + sends the SDP offer → the server relays it to target B.
    // Asserting B receives rc:tunnel.sdp.offer is robust: the offer is sent right
    // after create_offer(), NOT gated on ICE completion (the in-process-ICE
    // flakiness the suite avoids happens later, at DC-pool establishment, which
    // this test never reaches — it kills the flow first).
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("p3b2c-daemon-orig").await;

    // all_users loopback policy authorizes A's agent principal to reach B.
    let policy = json!({
        "name": "allow-loopback",
        "subjects": [{ "kind": "all_users" }],
        "targets": [{ "kind": "all_agents" }],
        "allowlist": [{
            "host_pattern": { "kind": "cidr", "value": "127.0.0.0/8" },
            "port_range": { "low": 9000, "high": 9999 }
        }],
        "max_concurrent_flows": 32,
        "max_bytes_per_session": 1048576
    });
    app.auth_post(
        &format!("/api/tenant/{}/tunnel-policy", seeded.tenant_id),
        &seeded.admin.access_token,
    )
    .json(&policy)
    .send()
    .await
    .unwrap();

    // Target B: a raw agent WS kept alive so B stays online (the server checks
    // the target is online at open time). We assert on A's flow state, not B's
    // frames, so B is a keep-alive only.
    let (b_id, b_tok) = enroll_agent(&app, &seeded, "mach-p3b2c-B", "target-B").await;
    let mut b_ws = connect_agent_ws(&app, &b_tok, "target-B").await;
    wait_agent_online(&app, &seeded, &b_id).await;

    // Origin A: its REAL signaling loop + the hub we drive.
    let a_cfg = enrol_agent_lib(&app, &seeded, "mach-p3b2c-A", "origin-A").await;
    let a_id = a_cfg.agent_id.clone();
    let hub = TunnelClientHub::new("0.3.0-test".into());
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let sig = spawn_origin_signaling(a_cfg, hub.clone(), stop_rx);
    wait_agent_online(&app, &seeded, &a_id).await;

    // Drive the daemon consumer: open a forward to B over A's own agent WS.
    let local = free_local_port().await;
    let flow_id = hub
        .create_forward(&b_id, local, "127.0.0.1:9000", "webrtc", "")
        .await
        .expect("create_forward registers the flow");

    // `flows()` reflects the live flow (structural fields; throughput is P3b-3).
    let snap = hub.flows_snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].id, flow_id);
    assert_eq!(snap[0].target.as_deref(), Some("127.0.0.1:9000"));
    assert_eq!(snap[0].node.as_deref(), Some(b_id.as_str()));

    // FR-86 P1 (AC3) — the flow owns its listener: it is bound when the
    // supervisor starts, before any session exists, so a client that connects
    // while the open is still in flight is ACCEPTED and held — not refused as
    // it was when the session bound the port only after its data plane came
    // up (which this test never reaches). The supervisor binds asynchronously,
    // so the connect is polled briefly.
    let mut early_client = None;
    for _ in 0..40 {
        match tokio::net::TcpStream::connect(("127.0.0.1", local)).await {
            Ok(s) => {
                early_client = Some(s);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    let mut early_client =
        early_client.expect("the flow's listener must accept a client before any carrier is ready");
    {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 4];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), early_client.read(&mut buf))
                .await
                .is_err(),
            "a connection arriving before a carrier is held open, not closed"
        );
    }

    // Poll until the flow records its NEGOTIATED transport — proving the open
    // handshake completed AND the hub demuxed `rc:tunnel.opened` BACK BY NONCE
    // (the per-session `ChannelSource` records the negotiated transport only
    // when it yields the `opened` frame to the driver). This is the full
    // daemon-consumer path: create_forward → nonce-stamped `rc:tunnel.open` →
    // server `Principal::Agent` authz (all_users policy) → `rc:tunnel.opened` →
    // nonce demux. It stops at the OPEN, before the in-process WebRTC DC data
    // plane the suite avoids as flaky — the subsequent peer build + offer are
    // aborted with the flow below.
    let mut negotiated = None;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Some(t) = hub.negotiated_transport(&flow_id) {
            negotiated = Some(t);
            break;
        }
    }
    assert_eq!(
        negotiated.as_deref(),
        Some("webrtc-dc-v1"),
        "the daemon-originated session must open + demux rc:tunnel.opened by nonce \
         (negotiated transport recorded on the flow)"
    );
    // #1685 — an open the server ACCEPTED is not a serving flow: this test never
    // reaches the data plane, so no listener is bound, and the Flows column
    // keeps its liveness word instead of claiming the transport.
    let shown = hub.flows_snapshot()[0].transport.clone();
    assert!(
        shown == "connecting" || shown == "down",
        "an accepted open with no bound listener must not read as serving: {shown}"
    );

    // kill_flow tears it down + deregisters.
    assert!(
        hub.kill_flow(&flow_id),
        "kill_flow removes the registered flow"
    );
    assert!(hub.flows_snapshot().is_empty(), "flows() empty after kill");

    // FR-86 P1 — the kill releases the held connection (the client sees EOF)
    // and unbinds the flow's port.
    {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 4];
        match tokio::time::timeout(Duration::from_secs(2), early_client.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("expected the held connection to close on kill, read {n} bytes"),
            Err(_) => panic!("kill_flow must release a connection the flow was holding"),
        }
    }
    let mut rebound = false;
    for _ in 0..40 {
        if tokio::net::TcpListener::bind(("127.0.0.1", local))
            .await
            .is_ok()
        {
            rebound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(rebound, "kill_flow must unbind the flow's port");

    // #1754 — killing the flow must TELL THE EXIT AGENT, so it drops its
    // per-session peer (ICE sockets + the DC pool) instead of leaking it. B is a
    // raw agent WS here, so we assert the wire contract end to end: kill_flow →
    // `rc:tunnel.terminate` on A's WS → server
    // (`relay_tunnel_client_msg_from_agent`) → `rc:tunnel.terminate` relayed to
    // target B. Before the fix, kill_flow only aborted the supervisor and no
    // terminate was ever sent — field-measured on 0.4.110, a macOS root exit
    // agent's UDP sockets climbed 5 → 11 → 16 across five kills. (A client that
    // never sends one is layer B's job: the agent reaps on its own signals,
    // `agents/meshharbord/src/tunnel/reap.rs`.)
    let terminated = read_until(&mut b_ws, "rc:tunnel.terminate").await;
    assert!(
        terminated.is_some(),
        "after kill_flow the exit agent (B) must receive rc:tunnel.terminate (#1754)"
    );

    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(3), sig).await;
}

/// R3 grace fixture — a tunnel CLIENT (agent A) with an OPEN session to target
/// agent B, on an app whose `rc.tunnel_grace_secs` is `grace`. Returns A's WS
/// (watch it for `rc:tunnel.terminate`), B's WS (drop it to fire
/// `terminate_sessions_targeting_agent`), and the pieces to RE-connect B.
struct GraceRig {
    app: TestApp,
    seeded: crate::fixtures::seed::SeededTenant,
    a_ws: AgentWs,
    b_ws: AgentWs,
    b_id: String,
    b_tok: String,
}

async fn open_client_tunnel_to_target(grace: u64, tag: &str) -> GraceRig {
    let app = TestApp::spawn_with_settings(move |s| {
        s.rc.tunnel_grace_secs = grace;
        // Fast presence writes so an offline→online transition on a reconnect
        // lands well inside `wait_agent_online`'s budget.
        s.rc.presence_batch_ms = 50;
    })
    .await;
    let seeded = app.seed_tenant(tag).await;

    // any user (⇒ any principal, incl. an agent) may reach 127.0.0.1:9000-9999
    let policy = json!({
        "name": "allow-loopback",
        "subjects": [{ "kind": "all_users" }],
        "targets": [{ "kind": "all_agents" }],
        "allowlist": [{
            "host_pattern": { "kind": "cidr", "value": "127.0.0.0/8" },
            "port_range": { "low": 9000, "high": 9999 }
        }],
        "max_concurrent_flows": 32,
        "max_bytes_per_session": 1048576
    });
    app.auth_post(
        &format!("/api/tenant/{}/tunnel-policy", seeded.tenant_id),
        &seeded.admin.access_token,
    )
    .json(&policy)
    .send()
    .await
    .unwrap();

    let (a_id, a_tok) = enroll_agent(&app, &seeded, &format!("mach-{tag}-A"), "origin-A").await;
    let (b_id, b_tok) = enroll_agent(&app, &seeded, &format!("mach-{tag}-B"), "target-B").await;
    let mut a_ws = connect_agent_ws(&app, &a_tok, "origin-A").await;
    let b_ws = connect_agent_ws(&app, &b_tok, "target-B").await;
    wait_agent_online(&app, &seeded, &a_id).await;
    wait_agent_online(&app, &seeded, &b_id).await;

    // A drives the tunnel-client role and opens a session to target B — this is
    // what populates `tunnel_sessions_by_target_agent[b_id]`.
    a_ws.send(Message::Text(
        json!({
            "t": "rc:tunnel.hello",
            "role": "client",
            "version": "0.3.0",
            "supported_transports": ["webrtc-dc-v1"],
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    a_ws.send(Message::Text(
        json!({
            "t": "rc:tunnel.open",
            "agent_id": b_id,
            "transport": "webrtc-dc-v1",
        })
        .to_string()
        .into(),
    ))
    .await
    .unwrap();
    read_until(&mut a_ws, "rc:tunnel.opened")
        .await
        .expect("A must receive rc:tunnel.opened for its own origination");

    GraceRig {
        app,
        seeded,
        a_ws,
        b_ws,
        b_id,
        b_tok,
    }
}

#[tokio::test]
async fn tunnel_grace_defers_then_terminates_when_target_stays_offline() {
    // R3 — with `rc.tunnel_grace_secs > 0`, a target agent's control-WS drop
    // must NOT immediately terminate the sessions aimed at it (the pre-R3
    // behaviour with grace=0): the server holds them for the window, then
    // terminates BECAUSE the agent stayed offline. This is the server half that
    // lets the agent's surviving QUIC peers ride out a WS blip.
    let mut rig = open_client_tunnel_to_target(2, "r3-grace-expire").await;

    // The event that fires `terminate_sessions_targeting_agent(b_id)`.
    rig.b_ws.close(None).await.ok();

    // Inside the grace window the client (A) must see NO terminate. Earliest a
    // terminate could arrive is detection + 2 s, so a 1 s watch must time out.
    let early = tokio::time::timeout(
        Duration::from_millis(1000),
        read_until(&mut rig.a_ws, "rc:tunnel.terminate"),
    )
    .await;
    assert!(
        early.is_err(),
        "grace must DEFER termination: A received rc:tunnel.terminate inside the grace window"
    );

    // After the window (target still offline) the server DOES terminate; A gets
    // the push. read_until's own 5 s deadline covers the remaining ~1 s + slop.
    let terminated = read_until(&mut rig.a_ws, "rc:tunnel.terminate").await;
    assert!(
        terminated.is_some(),
        "grace expired with the target still offline ⇒ the session must terminate"
    );
}

#[tokio::test]
async fn tunnel_grace_reregister_cancels_terminate() {
    // R3 — if the target agent re-registers within the grace window, the
    // pending termination is CANCELLED and the client's session is preserved:
    // exactly the WS-blip survival the pairing exists for. A 4 s grace leaves
    // the reconnect + hub re-registration comfortably ahead of the deadline.
    let mut rig = open_client_tunnel_to_target(4, "r3-grace-cancel").await;

    // Target's WS blips...
    rig.b_ws.close(None).await.ok();
    // ...a real blip has a GAP: let the server observe the drop (teardown +
    // offline mark) BEFORE the reconnect, so the new hello can't race the old
    // connection's teardown (a presence-layer concern, not this test's
    // subject). Then it reconnects on the SAME machine id (⇒ same agent row /
    // hub key) well inside the 4 s window.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let _b_ws2 = connect_agent_ws(&rig.app, &rig.b_tok, "target-B").await;
    wait_agent_online(&rig.app, &rig.seeded, &rig.b_id).await;

    // Watch A across the grace deadline (~4 s from the drop, i.e. ~3 s from
    // here) and assert NO `rc:tunnel.terminate` arrives — the re-registration
    // cancelled it. A self-controlled 5 s watch (not `read_until`, whose own
    // 5 s cap could stop short of a late deadline) straddles it.
    let saw_terminate = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match rig.a_ws.next().await {
                Some(Ok(Message::Text(text))) => {
                    if let Ok(v) = serde_json::from_str::<Value>(&text)
                        && v.get("t").and_then(|x| x.as_str()) == Some("rc:tunnel.terminate")
                    {
                        return true;
                    }
                }
                Some(Ok(_)) => continue,
                Some(Err(_)) | None => return false,
            }
        }
    })
    .await;
    assert!(
        !matches!(saw_terminate, Ok(true)),
        "a re-register within grace must CANCEL the pending terminate (A received one)"
    );
}
