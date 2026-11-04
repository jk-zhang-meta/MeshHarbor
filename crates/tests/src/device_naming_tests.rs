// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Device naming: admin rename (fleet + overlay/MagicDNS propagation),
//! display_name, tags — and the rehydrate-clobber rule.
//!
//! The rename route existed for months while every re-enroll silently
//! reverted its effect (`rehydrate` unconditionally `$set` the machine-
//! reported name). These tests lock the repaired contract: an admin rename
//! is sticky (`name_admin_set`), a never-renamed device keeps following its
//! machine-reported name, and a rename lands on the device's live overlay
//! node (deduped within the network) so peers resolve the new label.

use bson::oid::ObjectId;
use meshharbor_remote_control::models::NodeRef;
use meshharbor_services::dao::overlay_network::OverlayNetworkDao;
use meshharbor_services::dao::overlay_node::{NewOverlayNode, OverlayNodeDao};
use serde_json::{Value, json};

use crate::fixtures::test_app::TestApp;

// ─── Helpers ────────────────────────────────────────────────────

async fn mint_enroll_token(app: &TestApp, tenant_id: &str, admin_token: &str) -> String {
    let et: Value = app
        .auth_post(
            &format!("/api/tenant/{tenant_id}/agent/enroll-token"),
            admin_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    et["enrollment_token"].as_str().unwrap().to_string()
}

/// Enroll (or re-enroll — same machine_id) an agent over HTTP; returns agent_id.
async fn enroll(
    app: &TestApp,
    tenant_id: &str,
    admin_token: &str,
    machine_id: &str,
    machine_name: &str,
    version: &str,
) -> String {
    let token = mint_enroll_token(app, tenant_id, admin_token).await;
    let resp: Value = app
        .client
        .post(app.url("/api/agent/enroll"))
        .json(&json!({
            "enrollment_token": token,
            "machine_id": machine_id,
            "machine_name": machine_name,
            "os": "linux",
            "agent_version": version,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp["agent_id"].as_str().expect("agent_id").to_string()
}

async fn get_agent(app: &TestApp, tenant_id: &str, agent_id: &str, token: &str) -> Value {
    app.auth_get(&format!("/api/tenant/{tenant_id}/agent/{agent_id}"), token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

// ─── Tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn admin_rename_survives_reenroll_and_reports_in_responses() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("devname1").await;

    let aid = enroll(
        &app,
        &t.tenant_id,
        &t.admin.access_token,
        "mach-devname-1",
        "Original Box",
        "0.3.0",
    )
    .await;

    // Rename via the update route — the response now carries the fresh row.
    let resp: Value = app
        .auth_put(
            &format!("/api/tenant/{}/agent/{aid}", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&json!({ "name": "renamed-device" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["updated"].as_bool(), Some(true));
    assert_eq!(resp["agent"]["name"].as_str(), Some("renamed-device"));
    // No overlay node exists for this device — the DNS half must say so
    // by staying null, not by claiming a rename that never happened.
    assert!(resp["dns_renamed"].is_null());

    // Re-enroll the SAME machine with the machine-reported name + a newer
    // version: the version half must refresh, the admin rename must survive.
    enroll(
        &app,
        &t.tenant_id,
        &t.admin.access_token,
        "mach-devname-1",
        "Original Box",
        "0.3.1",
    )
    .await;

    let agent = get_agent(&app, &t.tenant_id, &aid, &t.admin.access_token).await;
    assert_eq!(
        agent["name"].as_str(),
        Some("renamed-device"),
        "re-enroll clobbered an admin rename"
    );
    assert_eq!(agent["agent_version"].as_str(), Some("0.3.1"));
}

#[tokio::test]
async fn machine_reported_name_flows_when_never_renamed() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("devname2").await;

    let aid = enroll(
        &app,
        &t.tenant_id,
        &t.admin.access_token,
        "mach-devname-2",
        "Old Hostname",
        "0.3.0",
    )
    .await;

    // No admin rename in between: a re-enroll under a new hostname is the
    // machine renaming itself, and the fleet should follow it.
    enroll(
        &app,
        &t.tenant_id,
        &t.admin.access_token,
        "mach-devname-2",
        "New Hostname",
        "0.3.0",
    )
    .await;

    let agent = get_agent(&app, &t.tenant_id, &aid, &t.admin.access_token).await;
    assert_eq!(agent["name"].as_str(), Some("New Hostname"));
}

#[tokio::test]
async fn display_name_and_tags_roundtrip_and_normalize() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("devname3").await;

    let aid = enroll(
        &app,
        &t.tenant_id,
        &t.admin.access_token,
        "mach-devname-3",
        "Label Box",
        "0.3.0",
    )
    .await;

    // Tags are trimmed, de-duped (order kept), empties dropped.
    let resp: Value = app
        .auth_put(
            &format!("/api/tenant/{}/agent/{aid}", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&json!({
            "display_name": "  Büro PC  ",
            "tags": [" prod ", "prod", "", "vienna"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["agent"]["display_name"].as_str(), Some("Büro PC"));
    assert_eq!(
        resp["agent"]["tags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["prod", "vienna"]
    );

    // Empty string clears the display name; empty list clears tags — both
    // then vanish from the wire (skip_serializing on empty).
    let resp: Value = app
        .auth_put(
            &format!("/api/tenant/{}/agent/{aid}", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&json!({ "display_name": "", "tags": [] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(resp["agent"]["display_name"].is_null());
    assert!(resp["agent"]["tags"].is_null());

    // A 41-char tag is refused.
    let resp = app
        .auth_put(
            &format!("/api/tenant/{}/agent/{aid}", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&json!({ "tags": ["x".repeat(41)] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
}

#[tokio::test]
async fn rename_propagates_to_live_overlay_node_with_dedup() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("devname4").await;

    let aid = enroll(
        &app,
        &t.tenant_id,
        &t.admin.access_token,
        "mach-devname-4",
        "Mesh Box",
        "0.3.0",
    )
    .await;
    let aid_oid = ObjectId::parse_str(&aid).unwrap();
    let tid_oid = ObjectId::parse_str(&t.tenant_id).unwrap();

    // Seed the overlay side directly, as handle_overlay_join would (the WS
    // join is exercised elsewhere; this test is about the rename hook).
    let networks = OverlayNetworkDao::new(&app.db);
    let nodes = OverlayNodeDao::new(&app.db);
    let network_id = networks.get_or_create(tid_oid).await.unwrap().id.unwrap();
    let mk_node = |node_ref: NodeRef, machine: &str, name: &str, ip: &str| NewOverlayNode {
        tenant_id: tid_oid,
        node_ref,
        network_id,
        machine_id: machine.to_string(),
        name: name.to_string(),
        overlay_ip: ip.to_string(),
        wg_public_key: format!("pk-{machine}"),
        key_epoch: 0,
        endpoints: vec![],
        supports_quic: false,
        supports_relay_single: false,
        supports_derp: false,
        supports_forced_derp: false,
        supports_server_relay_strategy: false,
        supports_derp_floor: false,
        supports_overlay_echo: false,
        supports_org_relay: false,
        advertised_routes: vec![],
        route_offer_withheld: None,
    };
    // A neighbour already OWNS the label the rename will want — forces the
    // in-network de-dup onto the `-2` suffix.
    nodes
        .create(mk_node(
            NodeRef::Agent {
                agent_id: ObjectId::new(),
            },
            "mach-devname-4b",
            "shiny-new-name",
            "100.64.0.9",
        ))
        .await
        .unwrap();
    let node = nodes
        .create(mk_node(
            NodeRef::Agent { agent_id: aid_oid },
            "mach-devname-4",
            "mesh-box",
            "100.64.0.8",
        ))
        .await
        .unwrap();

    let resp: Value = app
        .auth_put(
            &format!("/api/tenant/{}/agent/{aid}", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&json!({ "name": "Shiny New Name" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["dns_renamed"].as_bool(), Some(true));
    assert_eq!(resp["dns_name"].as_str(), Some("shiny-new-name-2"));

    let renamed = nodes.base.find_by_id(node.id.unwrap()).await.unwrap();
    assert_eq!(renamed.name, "shiny-new-name-2");

    // No-op rename: the label must stay put (exclude-self in the de-dup),
    // not walk to `-3`.
    let resp: Value = app
        .auth_put(
            &format!("/api/tenant/{}/agent/{aid}", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&json!({ "name": "Shiny New Name" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["dns_name"].as_str(), Some("shiny-new-name-2"));
}

#[tokio::test]
async fn tunnel_client_update_renames_and_labels() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("devname5").await;

    let et: Value = app
        .auth_post(
            &format!("/api/tenant/{}/tunnel-client/enroll-token", t.tenant_id),
            &t.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let enrolled: Value = app
        .client
        .post(app.url("/api/tunnel-client/enroll"))
        .json(&json!({
            "enrollment_token": et["enrollment_token"].as_str().unwrap(),
            "machine_id": "tunnel-mach-devname-5",
            "machine_name": "Operator Laptop",
            "os": "linux",
            "client_version": "0.3.0-test",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cid = enrolled["tunnel_client_id"].as_str().unwrap();

    let resp: Value = app
        .auth_put(
            &format!("/api/tenant/{}/tunnel-client/{cid}", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&json!({
            "name": "roadwarrior",
            "display_name": "Goran's laptop",
            "tags": ["laptop"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["updated"].as_bool(), Some(true));
    assert_eq!(resp["client"]["name"].as_str(), Some("roadwarrior"));
    assert_eq!(
        resp["client"]["display_name"].as_str(),
        Some("Goran's laptop")
    );
    assert_eq!(resp["client"]["tags"][0].as_str(), Some("laptop"));

    // A plain member holds no MANAGE_AGENTS — refused.
    let resp = app
        .auth_put(
            &format!("/api/tenant/{}/tunnel-client/{cid}", t.tenant_id),
            &t.member.access_token,
        )
        .json(&json!({ "name": "hijack" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}

// ─── FR-2: pin-update downgrade guard (2026-08-27) ─────────────

/// The incident this guards: a stale operator script pinned rc.484 at a
/// fleet already on 0.4.1 and five hosts downgraded. The server knows both
/// versions at push time — it refuses a strictly-older pin unless forced.
#[tokio::test]
async fn stale_pin_is_refused_unless_forced() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("fr2a").await;

    let aid = enroll(
        &app,
        &t.tenant_id,
        &t.admin.access_token,
        "mach-fr2-a",
        "Guarded Box",
        "0.4.1",
    )
    .await;

    // Strictly older pin → 409 naming both versions.
    let resp = app
        .auth_post(
            &format!("/api/tenant/{}/agent/{aid}/update", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&json!({ "pin": "agent-v0.3.0-rc.484" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 409);
    let body = resp.text().await.unwrap_or_default();
    assert!(
        body.contains("0.3.0-rc.484") && body.contains("0.4.1"),
        "{body}"
    );

    // force=true is the deliberate-downgrade escape hatch (agent offline in
    // tests ⇒ delivered=false, but the push is ACCEPTED).
    let resp: Value = app
        .auth_post(
            &format!("/api/tenant/{}/agent/{aid}/update", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&json!({ "pin": "agent-v0.3.0-rc.484", "force": true }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["delivered"].as_bool(), Some(false));
    assert!(resp["refused"].is_null());

    // Equal pin = re-install; newer pin = upgrade — both pass.
    for pin in ["agent-v0.4.1", "agent-v0.4.2"] {
        let resp = app
            .auth_post(
                &format!("/api/tenant/{}/agent/{aid}/update", t.tenant_id),
                &t.admin.access_token,
            )
            .json(&json!({ "pin": pin }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "pin {pin} must pass");
    }
}

/// Bulk pushes skip (per-agent `refused`) rather than failing the batch —
/// one already-updated device must not veto a fleet push.
#[tokio::test]
async fn bulk_stale_pin_skips_per_agent() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("fr2b").await;

    let old = enroll(
        &app,
        &t.tenant_id,
        &t.admin.access_token,
        "mach-fr2-old",
        "Old Box",
        "0.3.0-rc.400",
    )
    .await;
    let new = enroll(
        &app,
        &t.tenant_id,
        &t.admin.access_token,
        "mach-fr2-new",
        "New Box",
        "0.4.2",
    )
    .await;

    let resp: Value = app
        .auth_post(
            &format!("/api/tenant/{}/agent/update", t.tenant_id),
            &t.admin.access_token,
        )
        .json(&json!({ "agent_ids": [old, new], "pin": "agent-v0.4.1" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["requested"].as_u64(), Some(2));
    assert_eq!(resp["refused"].as_u64(), Some(1));
    let results = resp["results"].as_array().unwrap();
    let refused_row = results
        .iter()
        .find(|r| r["refused"].is_string())
        .expect("one refused row");
    // The 0.4.2 box is the one protected; the rc.400 box gets the push.
    assert!(refused_row["refused"].as_str().unwrap().contains("0.4.2"));
    assert_eq!(refused_row["refused_code"], "pin_downgrade");
}

// ─── FR-67 P7: an update the device said it will not act on ────

/// Stamp what a device's hello would have said about a pushed update
/// (`capabilities.update_mode`) onto its row: a device enrolled over HTTP
/// never says hello. `None` = an agent from before P7, which says nothing.
async fn set_update_mode(app: &TestApp, agent_id: &str, mode: Option<&str>) {
    let aid = ObjectId::parse_str(agent_id).unwrap();
    let update = match mode {
        Some(m) => bson::doc! { "$set": { "capabilities.update_mode": m } },
        None => bson::doc! { "$unset": { "capabilities.update_mode": "" } },
    };
    let res = app
        .db
        .collection::<bson::Document>("agents")
        .update_one(bson::doc! { "_id": aid }, update)
        .await
        .unwrap();
    assert_eq!(res.matched_count, 1, "no agent row {agent_id}");
}

/// The 2026-10-19 incident: "Update all" counted a device as pushed three
/// times while the device logged `rc:agent.update ignored` three times — a
/// secondary enrollment, and only a machine's primary drives its updater. The
/// server now refuses, up front and with the reason, a push the device said
/// it will not act on: a 409 on one device, a `refused` row with its
/// `refused_code` in a bulk. A device that says nothing (an older agent) is
/// pushed as before.
#[tokio::test]
async fn an_update_the_device_said_it_will_not_act_on_is_refused_with_why() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("fr67p7").await;
    let admin = &t.admin.access_token;

    // Three devices, the free plan's cap: the third plays both a device that
    // acts on the push (`self`) and one from before P7 (no word at all).
    let mut ids = Vec::new();
    for (mach, name, mode) in [
        ("mach-p7-sec", "Secondary Box", Some("primary_org")),
        ("mach-p7-off", "Frozen Box", Some("off")),
        ("mach-p7-self", "Updating Box", Some("self")),
    ] {
        let aid = enroll(&app, &t.tenant_id, admin, mach, name, "0.4.146").await;
        set_update_mode(&app, &aid, mode).await;
        ids.push(aid);
    }
    let [secondary, off, acts] = &ids[..] else {
        unreachable!()
    };

    // The dashboard reads the same word off the device row.
    let row = get_agent(&app, &t.tenant_id, secondary, admin).await;
    assert_eq!(row["capabilities"]["update_mode"], "primary_org");

    // One device: a 409 naming the way out. `force` does not override it:
    // force overrides the server's own downgrade guard, while the device
    // ignores or drops the frame whatever the server sends.
    for (aid, want) in [(secondary, "set-primary"), (off, "auto_update")] {
        for body in [json!({}), json!({ "force": true })] {
            let resp = app
                .auth_post(
                    &format!("/api/tenant/{}/agent/{aid}/update", t.tenant_id),
                    admin,
                )
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 409, "{want} {body}");
            let text = resp.text().await.unwrap_or_default();
            assert!(text.contains(want), "{want}: {text}");
        }
    }
    // A device that acts on it, or says nothing, is pushed as before (offline
    // in tests ⇒ delivered=false, but the push is ACCEPTED).
    for mode in [Some("self"), None] {
        set_update_mode(&app, acts, mode).await;
        let resp: Value = app
            .auth_post(
                &format!("/api/tenant/{}/agent/{acts}/update", t.tenant_id),
                admin,
            )
            .json(&json!({}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(resp["delivered"].as_bool(), Some(false), "{mode:?} {resp}");
        assert!(resp.get("refused").is_none(), "{mode:?} {resp}");
        assert!(resp.get("refused_code").is_none(), "{mode:?} {resp}");
    }

    // "Update all": the two are skipped, each with a code a client branches
    // on, and the batch does not fail.
    let bulk = |body: Value| {
        let app = &app;
        let tid = t.tenant_id.clone();
        async move {
            app.auth_post(&format!("/api/tenant/{tid}/agent/update"), admin)
                .json(&body)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let code_of = |resp: &Value, aid: &str| -> Value {
        resp["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["agent_id"] == aid)
            .map(|r| r["refused_code"].clone())
            .unwrap_or_else(|| panic!("no row for {aid}: {resp}"))
    };
    for mode in [Some("self"), None] {
        set_update_mode(&app, acts, mode).await;
        let resp = bulk(json!({})).await;
        assert_eq!(resp["requested"].as_u64(), Some(3), "{mode:?} {resp}");
        assert_eq!(resp["refused"].as_u64(), Some(2), "{mode:?} {resp}");
        assert_eq!(code_of(&resp, secondary), "primary_org");
        assert_eq!(code_of(&resp, off), "auto_update_off");
        assert!(code_of(&resp, acts).is_null(), "{mode:?} {resp}");
    }

    // A pin that would downgrade carries FR-2's own code; with `force` the
    // pin passes FR-2's guard and still meets the device's refusal.
    let resp = bulk(json!({ "agent_ids": [secondary, acts], "pin": "agent-v0.4.140" })).await;
    assert_eq!(code_of(&resp, secondary), "pin_downgrade");
    assert_eq!(code_of(&resp, acts), "pin_downgrade");
    let resp = bulk(json!({
        "agent_ids": [secondary, acts],
        "pin": "agent-v0.4.140",
        "force": true,
    }))
    .await;
    assert_eq!(code_of(&resp, secondary), "primary_org");
    assert!(code_of(&resp, acts).is_null(), "{resp}");
    assert_eq!(resp["refused"].as_u64(), Some(1), "{resp}");
}
