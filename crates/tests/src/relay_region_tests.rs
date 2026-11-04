// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Multi-region relay PoPs — integration coverage for the region registry.
//!
//! The load-bearing guarantee is the FLAG-OFF one: with
//! `relay.regions_enabled=false` (the deployed default) every issuance path
//! must serve exactly the legacy single-region output, byte-for-byte, even
//! with regions configured. The unit suites lock the selection logic
//! (`turn_creds`); these tests lock the HTTP surface end-to-end through a
//! real `AppState`.

use crate::fixtures::test_app::TestApp;
use serde_json::Value;

const REGIONS_JSON: &str = r#"[
  {"id":"us-east",
   "turn_url":"turn:coturn-us-east.example:3478",
   "derp_url":"wss://derp-us-east.example/derp",
   "caps":{"tls_443_tcp":false}},
  {"id":"staged",
   "turn_url":"turn:coturn-staged.example:3478",
   "enabled":false}
]"#;

/// The exact legacy six-variant list for the configured base — what every
/// pre-region deployment serves and what flag-off must keep serving.
fn legacy_urls() -> Vec<String> {
    [
        "turn:coturn.example:3478",
        "turn:coturn.example:443?transport=udp",
        "turn:coturn.example:3478?transport=tcp",
        "turns:coturn.example:5349?transport=tcp",
        "turns:coturn.example:443?transport=udp",
        "turns:coturn.example:443?transport=tcp",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn relay_settings(s: &mut meshharbor_config::Settings, enabled: bool) {
    s.turn.url = Some("turn:coturn.example:3478".into());
    s.turn.shared_secret = Some("integration-test-secret".into());
    s.relay.regions_enabled = enabled;
    s.relay.regions = Some(REGIONS_JSON.into());
}

#[tokio::test]
async fn flag_off_credentials_are_byte_identical_legacy() {
    let app = TestApp::spawn_with_settings(|s| relay_settings(s, false)).await;
    let seeded = app.seed_tenant("relayoff").await;

    let resp = app
        .auth_get("/api/turn/credentials", &seeded.admin.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = resp.json().await.unwrap();
    let servers = body["ice_servers"].as_array().unwrap();
    // [0] = the STUN warm-up entry, [1] = the TURN cred entry.
    assert_eq!(servers[0]["urls"][0], "stun:stun.cloudflare.com:3478");
    assert_eq!(servers[0]["urls"][1], "stun:stun.l.google.com:19302");
    let urls: Vec<String> = servers[1]["urls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u.as_str().unwrap().to_string())
        .collect();
    assert_eq!(urls, legacy_urls(), "flag-off must serve the legacy list");
    assert!(servers[1]["username"].as_str().unwrap().contains(':'));

    // The topology endpoint reports the flag truthfully (specs are parsed
    // for observability even while disabled).
    let resp = app
        .auth_get("/api/relay/regions", &seeded.admin.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let topo: Value = resp.json().await.unwrap();
    assert_eq!(topo["regions_enabled"], false);

    // In-process: a disabled map answers the default for ANY region key —
    // the same invariant the unit suite locks, here through the real
    // settings->AppState build path.
    let cfg = app.state.turn_map.cfg_for(Some("us-east")).unwrap();
    assert_eq!(cfg.urls, legacy_urls());
}

#[tokio::test]
async fn flag_on_compiles_regions_and_keeps_sessionless_creds_on_default() {
    let app = TestApp::spawn_with_settings(|s| relay_settings(s, true)).await;
    let seeded = app.seed_tenant("relayon").await;

    // Sessionless pre-fetch stays on the default region BY DESIGN (the
    // per-agent region pick happens on the Hub/overlay issuance paths).
    let resp = app
        .auth_get("/api/turn/credentials", &seeded.admin.access_token)
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let urls: Vec<String> = body["ice_servers"][1]["urls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u.as_str().unwrap().to_string())
        .collect();
    assert_eq!(urls, legacy_urls());

    // Topology lists both specs (incl. the staged-disabled one) truthfully.
    let resp = app
        .auth_get("/api/relay/regions", &seeded.admin.access_token)
        .send()
        .await
        .unwrap();
    let topo: Value = resp.json().await.unwrap();
    assert_eq!(topo["regions_enabled"], true);
    let regions = topo["regions"].as_array().unwrap();
    assert_eq!(regions.len(), 2);
    let us = regions.iter().find(|r| r["id"] == "us-east").unwrap();
    assert_eq!(us["derp_url"], "wss://derp-us-east.example/derp");
    assert_eq!(us["enabled"], true);
    let staged = regions.iter().find(|r| r["id"] == "staged").unwrap();
    assert_eq!(staged["enabled"], false);

    // In-process: the enabled map resolves the region's own config — with
    // the PoP's capability set applied (no turns:443?tcp: that port belongs
    // to the region's DERP relay behind the SNI split).
    let cfg = app.state.turn_map.cfg_for(Some("us-east")).unwrap();
    assert_eq!(cfg.urls[0], "turn:coturn-us-east.example:3478");
    assert!(
        !cfg.urls
            .iter()
            .any(|u| u.starts_with("turns:") && u.contains(":443") && u.contains("transport=tcp")),
        "tls_443_tcp:false must suppress the turns-tcp-443 variant"
    );
    // The DISABLED spec never compiles into an issuing region.
    let staged_cfg = app.state.turn_map.cfg_for(Some("staged")).unwrap();
    assert_eq!(
        staged_cfg.urls,
        legacy_urls(),
        "disabled spec degrades to default"
    );
    // The wire push (what capability-flagged agents receive) carries only
    // the enabled region, with its STUN probe target + DERP endpoint.
    let (wire, _rev) =
        meshharbor_remote_control::turn_creds::relay_regions_wire(&app.state.turn_map)
            .expect("enabled map with one usable region");
    assert_eq!(wire.len(), 1);
    assert_eq!(wire[0].id, "us-east");
    assert_eq!(wire[0].stun, "coturn-us-east.example:3478");
    assert_eq!(
        wire[0].derp_url.as_deref(),
        Some("wss://derp-us-east.example/derp")
    );
}
