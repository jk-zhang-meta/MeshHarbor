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

    let (aid, token) =
        crate::tunnel_tests::enroll_agent(&app, &t, "mach-devname-4", "Mesh Box").await;
    let aid_oid = ObjectId::parse_str(&aid).unwrap();
    let tid_oid = ObjectId::parse_str(&t.tenant_id).unwrap();

    // Seed the overlay side directly, as handle_overlay_join would (the WS
    // join is exercised elsewhere; this test is about the rename hook).
    let networks = OverlayNetworkDao::new(&app.db);
    let nodes = OverlayNodeDao::new(&app.db);
    let network_id = networks.get_or_create(tid_oid).await.unwrap().id.unwrap();
    let mk_node = |node_ref: NodeRef, machine: &str, name: &str, ip: &str| NewOverlayNode {
        supports_invite_deadlines: true,
        personal_access_owner_id: None,
        temporary: None,
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

    // Capture the old join name before the website commits a new revision.
    let captured_join_name = node.name.clone();
    let mut ws = name_ws(&app, &token, "device-name-sync").await;
    let initial = next_name(&mut ws, "0").await;
    ack_name(&mut ws, initial, "applied").await;
    name_state(&app, &t.tenant_id, &aid, &t.admin.access_token, "synced").await;

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
    // The same-name revision 2 still advances the projection fence. A
    // delayed writer from revision 1 cannot change it after that no-op.
    let delayed = nodes
        .set_name_revision(node.id.unwrap(), "stale-name", 1)
        .await
        .unwrap();
    assert_eq!(delayed.name, "shiny-new-name-2");
    let latest = next_name(&mut ws, "2").await;
    ack_name(&mut ws, latest, "applied").await;
    name_state(&app, &t.tenant_id, &aid, &t.admin.access_token, "synced").await;
    // Resume the original join with its already-captured old DNS name.
    // Real Mongo rehydrate must preserve the newly committed/ACKed name.
    let joined = nodes
        .rehydrate(
            node.id.unwrap(),
            &node.node_ref,
            &captured_join_name,
            &node.wg_public_key,
            node.key_epoch,
            &[],
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            &[],
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        joined.name, "shiny-new-name-2",
        "late normal join must not overwrite a renamed node"
    );
    assert_eq!(joined.wg_public_key, node.wg_public_key);
    assert_eq!(joined.key_epoch, node.key_epoch);
    let doc = app
        .db
        .collection::<bson::Document>("overlay_nodes")
        .find_one(bson::doc! {"_id":node.id.unwrap()})
        .await
        .unwrap()
        .unwrap();
    assert_eq!(doc.get_i64("name_sync_revision").unwrap(), 2);
    let mapped: Value = app
        .auth_get(
            &format!("/api/tenant/{}/device", t.tenant_id),
            &t.admin.access_token,
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = mapped["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == aid)
        .unwrap();
    assert_eq!(row["magic_dns_name"], "shiny-new-name-2");
    // A genuinely empty legacy name still receives its initial backfill;
    // normal key/epoch and join refresh semantics remain unchanged.
    let empty = nodes
        .create(mk_node(
            NodeRef::Agent {
                agent_id: ObjectId::new(),
            },
            "empty-name",
            "",
            "100.64.0.10",
        ))
        .await
        .unwrap();
    let filled = nodes
        .rehydrate(
            empty.id.unwrap(),
            &empty.node_ref,
            "legacy-backfilled",
            &empty.wg_public_key,
            empty.key_epoch,
            &[],
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            &[],
            None,
        )
        .await
        .unwrap();
    assert_eq!(filled.name, "legacy-backfilled");
    assert_eq!(filled.key_epoch, empty.key_epoch);
    assert_eq!(filled.wg_public_key, empty.wg_public_key);
    let missing = nodes
        .create(mk_node(
            NodeRef::Agent {
                agent_id: ObjectId::new(),
            },
            "missing-name",
            "",
            "100.64.0.11",
        ))
        .await
        .unwrap();
    app.db
        .collection::<bson::Document>("overlay_nodes")
        .update_one(
            bson::doc! {"_id":missing.id.unwrap()},
            bson::doc! {"$unset":{"name":""}},
        )
        .await
        .unwrap();
    let filled = nodes
        .rehydrate(
            missing.id.unwrap(),
            &missing.node_ref,
            "missing-backfilled",
            &missing.wg_public_key,
            missing.key_epoch,
            &[],
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            &[],
            None,
        )
        .await
        .unwrap();
    assert_eq!(filled.name, "missing-backfilled");
    assert_eq!(filled.key_epoch, missing.key_epoch);
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

#[tokio::test]
async fn rename_records_durable_revision_without_claiming_old_client_synced() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("name-sync-old").await;
    let aid = enroll(
        &app,
        &t.tenant_id,
        &t.admin.access_token,
        "name-sync-old",
        "before",
        "0.4.160",
    )
    .await;
    let before = get_agent(&app, &t.tenant_id, &aid, &t.admin.access_token).await;
    assert_eq!(before["name_sync"]["state"], "unverified");
    let url = format!("/api/tenant/{}/agent/{aid}", t.tenant_id);
    let changed: Value = app
        .auth_put(&url, &t.admin.access_token)
        .json(&json!({"name":"after"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(changed["agent"]["name_sync"]["revision"], "1");
    assert_eq!(changed["agent"]["name_sync"]["state"], "unsupported");
    assert!(changed["agent"]["name_sync"]["acked_revision"].is_null());
    let fetched = get_agent(&app, &t.tenant_id, &aid, &t.admin.access_token).await;
    assert_eq!(changed["agent"]["name_sync"], fetched["name_sync"]);
}

use futures::{SinkExt, StreamExt};
use std::time::Duration;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};
type NameWs = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

async fn name_ws(app: &TestApp, token: &str, cap: &str) -> NameWs {
    let (mut ws, _) = connect_async(format!("ws://{}/ws?token={token}&role=agent", app.addr))
        .await
        .unwrap();
    ws.send(Message::Text(json!({"t":"rc:agent.hello","machine_name":"old-local","os":"linux","agent_version":"0.4.160",
        "displays":[],"caps":{"hw_encoders":[],"codecs":["h264"],"has_input_permission":true,"supports_clipboard":false,
        "supports_file_transfer":false,"max_simultaneous_sessions":4,"rpc":[cap]}}).to_string().into())).await.unwrap();
    ws
}
async fn next_name(ws: &mut NameWs, revision: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(Ok(Message::Text(text))) = ws.next().await {
                let v: Value = serde_json::from_str(&text).unwrap();
                if v["t"] == "rc:agent.name" && v["revision"] == revision {
                    return v;
                }
            }
        }
    })
    .await
    .expect("name sync delivery without reconnect")
}
async fn name_state(app: &TestApp, tenant: &str, aid: &str, admin: &str, expected: &str) -> Value {
    for _ in 0..80 {
        let a = get_agent(app, tenant, aid, admin).await;
        if a["name_sync"]["state"] == expected {
            return a;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("expected name state {expected}")
}
async fn ack_name(ws: &mut NameWs, mut frame: Value, outcome: &str) {
    frame["t"] = json!("rc:agent.name.ack");
    frame["outcome"] = json!(outcome);
    ws.send(Message::Text(frame.to_string().into()))
        .await
        .unwrap();
}

#[tokio::test]
async fn live_name_ack_is_revision_name_identity_and_connection_fenced() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("live-name-ack").await;
    let (aid, token) = crate::tunnel_tests::enroll_agent(&app, &t, "name-ack", "original").await;
    let mut ws = name_ws(&app, &token, "device-name-sync").await;
    let initial = next_name(&mut ws, "0").await;
    assert_eq!(initial["name"], "original");
    ack_name(&mut ws, initial, "applied").await;
    name_state(&app, &t.tenant_id, &aid, &t.admin.access_token, "synced").await;
    let url = format!("/api/tenant/{}/agent/{aid}", t.tenant_id);
    for (name, rev) in [("first", "1"), ("second", "2")] {
        let p: Value = app
            .auth_put(&url, &t.admin.access_token)
            .json(&json!({"name":name}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(p["agent"]["name_sync"]["revision"], rev);
    }
    let old = next_name(&mut ws, "1").await;
    let current = next_name(&mut ws, "2").await;
    ack_name(&mut ws, old, "applied").await;
    let mut wrong = current.clone();
    wrong["name"] = json!("wrong");
    ack_name(&mut ws, wrong, "applied").await;
    let mut other = current.clone();
    other["agent_id"] = json!(ObjectId::new().to_hex());
    ack_name(&mut ws, other, "applied").await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let pending = get_agent(&app, &t.tenant_id, &aid, &t.admin.access_token).await;
    assert_eq!(pending["name_sync"]["state"], "pending");
    assert_eq!(pending["name"], "second");
    ack_name(&mut ws, current.clone(), "failed").await;
    let failed = name_state(&app, &t.tenant_id, &aid, &t.admin.access_token, "failed").await;
    ack_name(&mut ws, current.clone(), "applied").await;
    let synced = name_state(&app, &t.tenant_id, &aid, &t.admin.access_token, "synced").await;
    assert!(
        synced["name_sync"]["event_seq"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > failed["name_sync"]["event_seq"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
    );
    ack_name(&mut ws, current, "failed").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        get_agent(&app, &t.tenant_id, &aid, &t.admin.access_token).await["name_sync"],
        synced["name_sync"]
    );
    ws.close(None).await.unwrap();
    let changed: Value = app
        .auth_put(&url, &t.admin.access_token)
        .json(&json!({"name":"offline-new"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(changed["agent"]["name_sync"]["state"], "pending");
    let mut ws = name_ws(&app, &token, "device-name-sync").await;
    let latest = next_name(&mut ws, "3").await;
    assert_eq!(latest["name"], "offline-new");
    ack_name(&mut ws, latest, "applied").await;
    name_state(&app, &t.tenant_id, &aid, &t.admin.access_token, "synced").await;
}

#[tokio::test]
async fn local_name_proposal_cas_and_secondary_alias_cannot_write_global_name() {
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("name-proposal").await;
    let (aid, token) =
        crate::tunnel_tests::enroll_agent(&app, &t, "name-proposal", "original").await;
    let mut ws = name_ws(&app, &token, "device-name-sync").await;
    next_name(&mut ws, "0").await;
    let url = app.url("/api/agent/self/name");
    assert_eq!(
        app.client
            .post(&url)
            .json(&json!({"name":"bad","expected_revision":"0"}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );
    let post = app
        .client
        .post(&url)
        .bearer_auth(&token)
        .json(&json!({"name":"local-new","expected_revision":"0"}))
        .send()
        .await
        .unwrap();
    assert_eq!(post.status().as_u16(), 200);
    let accepted: Value = post.json().await.unwrap();
    assert_eq!(accepted["revision"], "1");
    assert_eq!(accepted["agent_id"], aid);
    let stale = app
        .client
        .post(&url)
        .bearer_auth(&token)
        .json(&json!({"name":"stale","expected_revision":"0"}))
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409);
    let conflict: Value = stale.json().await.unwrap();
    assert_eq!(conflict["name"], "local-new");
    assert_eq!(conflict["revision"], "1");
    ws.close(None).await.unwrap();
    let _secondary = name_ws(&app, &token, "organization-name-alias").await;
    let row = name_state(
        &app,
        &t.tenant_id,
        &aid,
        &t.admin.access_token,
        "unsupported",
    )
    .await;
    assert_eq!(row["name_sync"]["scope"], "organization_alias");
    assert_eq!(
        app.client
            .post(&url)
            .bearer_auth(&token)
            .json(&json!({"name":"bad","expected_revision":"1"}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    assert_eq!(
        get_agent(&app, &t.tenant_id, &aid, &t.admin.access_token).await["name"],
        "local-new"
    );
}

#[tokio::test]
async fn name_ack_connection_cas_big_revision_and_explicit_retry() {
    use bson::doc;
    use meshharbor_services::dao::agent::AgentDao;
    let app = TestApp::spawn().await;
    let t = app.seed_tenant("name-conn-fence").await;
    let (aid, token) = crate::tunnel_tests::enroll_agent(&app, &t, "name-conn", "original").await;
    let mut ws = name_ws(&app, &token, "device-name-sync").await;
    next_name(&mut ws, "0").await;
    let a = ObjectId::parse_str(&aid).unwrap();
    let tenant = ObjectId::parse_str(&t.tenant_id).unwrap();
    let collection = app.db.collection::<bson::Document>("agents");
    let before = collection.find_one(doc! {"_id":a}).await.unwrap().unwrap();
    let old_conn = before.get_str("conn_id").unwrap().to_owned();
    ws.close(None).await.unwrap();
    let mut current = name_ws(&app, &token, "device-name-sync").await;
    next_name(&mut current, "0").await;
    let dao = AgentDao::new(&app.db);
    assert!(
        dao.acknowledge_name(tenant, a, &old_conn, 0, "original", true, None)
            .await
            .unwrap()
            .is_none()
    );
    let untouched = get_agent(&app, &t.tenant_id, &aid, &t.admin.access_token).await;
    assert_ne!(untouched["name_sync"]["state"], "synced");
    collection
        .update_one(
            doc! {"_id":a},
            doc! {"$set":{"name_sync.revision":9007199254740992_i64}},
        )
        .await
        .unwrap();
    let url = format!("/api/tenant/{}/agent/{aid}", t.tenant_id);
    let response: Value = app
        .auth_put(&url, &t.admin.access_token)
        .json(&json!({"name":"original"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        response["agent"]["name_sync"]["revision"],
        "9007199254740993"
    );
    assert_eq!(response["agent"]["name_sync"]["state"], "pending");
    let frame = next_name(&mut current, "9007199254740993").await;
    ack_name(&mut current, frame, "applied").await;
    name_state(&app, &t.tenant_id, &aid, &t.admin.access_token, "synced").await;
    assert!(
        dao.rename_if_revision(tenant, a, "wrong-generation", Some((9007199254740993, 999)))
            .await
            .unwrap()
            .is_none()
    );
    for name in ["\n", "a\nb", &"é".repeat(33)] {
        let p = app
            .auth_put(&url, &t.admin.access_token)
            .json(&json!({"name":name}))
            .send()
            .await
            .unwrap();
        assert_eq!(p.status().as_u16(), 400);
    }
    assert_eq!(
        get_agent(&app, &t.tenant_id, &aid, &t.admin.access_token).await["name_sync"]["revision"],
        "9007199254740993"
    );
}
