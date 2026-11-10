// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! Stats PR-1 — collector + rollup integration tests (real MongoDB).
//!
//! Locks the three storage invariants the multi-pod design leans on:
//! deterministic-`_id` upserts are idempotent, the relay healthy-vote is
//! monotonic (a failure can never clobber a success in the same bucket),
//! and the rollup compactor is re-runnable without drift.

use bson::{Document, doc, oid::ObjectId};

use crate::fixtures::test_app::TestApp;
use meshharbor_api::stats_rollup::{pass_count, run_stats_rollup_once};
use meshharbor_mod_conference::maintenance::close_orphaned_call_state;
use meshharbor_services::dao::stats::{RelaySample, bucket_start};

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Aggregation `$sum` outputs are Int32 for small values but may widen to
/// Int64 — assert on the numeric value, not the BSON width.
fn int(doc: &Document, key: &str) -> i64 {
    match doc.get(key) {
        Some(bson::Bson::Int32(v)) => i64::from(*v),
        Some(bson::Bson::Int64(v)) => *v,
        Some(bson::Bson::Double(v)) => *v as i64,
        other => panic!("field {key} not numeric: {other:?}"),
    }
}

async fn count(app: &TestApp, coll: &str, filter: Document) -> u64 {
    app.state
        .db
        .collection::<Document>(coll)
        .count_documents(filter)
        .await
        .expect("count")
}

async fn find_one(app: &TestApp, coll: &str, filter: Document) -> Option<Document> {
    app.state
        .db
        .collection::<Document>(coll)
        .find_one(filter)
        .await
        .expect("find_one")
}

#[tokio::test]
async fn machine_sample_upserts_are_idempotent() {
    let app = TestApp::spawn().await;
    let tenant = ObjectId::new();
    let agent = ObjectId::new();
    let unix = unix_now();

    // Two heartbeats inside the same minute bucket (30 s cadence) → ONE
    // document, last write's gauge wins.
    app.state
        .stats
        .upsert_machine_sample(tenant, agent, unix, 1, None)
        .await
        .expect("first upsert");
    app.state
        .stats
        .upsert_machine_sample(tenant, agent, unix, 2, None)
        .await
        .expect("second upsert");

    let bucket = bucket_start(unix, 60);
    let id = format!("{}:{}", agent.to_hex(), bucket);
    assert_eq!(count(&app, "stats_machine", doc! {}).await, 1);
    let doc = find_one(&app, "stats_machine", doc! { "_id": &id })
        .await
        .expect("bucket doc");
    assert_eq!(doc.get_i32("active_sessions").unwrap(), 2);
    assert!(doc.get_bool("online").unwrap());
}

#[tokio::test]
async fn relay_healthy_vote_failure_never_clobbers_success() {
    let app = TestApp::spawn().await;
    let unix = unix_now();
    let sample = RelaySample {
        region: "us-east".into(),
        unix,
        poll_rtt_ms: 42,
        cpus: 2.0,
        load1: 0.5,
        load5: 0.4,
        mem_total_kb: 4_000_000.0,
        mem_available_kb: 2_000_000.0,
        rx_mbps: 1.0,
        tx_mbps: 2.0,
        allocations: 3.0,
        coturn_sessions: 1.0,
        derp_registrations: 5.0,
        uptime_s: 1000.0,
    };
    let id = format!("us-east:{}", bucket_start(unix, 30));

    // Pod A succeeds, pod B fails the SAME bucket → healthy must stay true
    // ($setOnInsert-only failure path).
    app.state
        .stats
        .upsert_relay_sample(&sample)
        .await
        .expect("success upsert");
    app.state
        .stats
        .upsert_relay_unreachable("us-east", unix)
        .await
        .expect("failure upsert");
    let doc = find_one(&app, "stats_relay", doc! { "_id": &id })
        .await
        .expect("bucket");
    assert!(doc.get_bool("healthy").unwrap());
    assert_eq!(doc.get_i64("poll_rtt_ms").unwrap(), 42);

    // Reverse order in a DIFFERENT bucket: failure first inserts
    // healthy:false, the late success overwrites it.
    let unix2 = unix + 30;
    let id2 = format!("us-east:{}", bucket_start(unix2, 30));
    app.state
        .stats
        .upsert_relay_unreachable("us-east", unix2)
        .await
        .expect("failure first");
    let doc2 = find_one(&app, "stats_relay", doc! { "_id": &id2 })
        .await
        .expect("failure bucket");
    assert!(!doc2.get_bool("healthy").unwrap());
    let late = RelaySample {
        unix: unix2,
        ..sample.clone()
    };
    app.state
        .stats
        .upsert_relay_sample(&late)
        .await
        .expect("late success");
    let doc2 = find_one(&app, "stats_relay", doc! { "_id": &id2 })
        .await
        .expect("healed bucket");
    assert!(doc2.get_bool("healthy").unwrap());
}

#[tokio::test]
async fn rollup_builds_hourly_and_daily_buckets_idempotently() {
    let app = TestApp::spawn().await;
    let tenant = ObjectId::new();
    let agent = ObjectId::new();
    let room = ObjectId::new();
    let call = ObjectId::new();

    // Seed into the PREVIOUS (closed) hour so the assertion set is stable
    // across the two rollup runs.
    let hour = bucket_start(unix_now(), 3600) - 3600;

    // 3 machine minute-buckets in that hour.
    for i in 0..3i64 {
        app.state
            .stats
            .upsert_machine_sample(tenant, agent, hour + i * 60, 1, None)
            .await
            .expect("machine seed");
    }
    // 2 relay buckets: one healthy, one unreachable.
    let s = RelaySample {
        region: "eu-north".into(),
        unix: hour,
        poll_rtt_ms: 50,
        cpus: 2.0,
        load1: 0.2,
        load5: 0.1,
        mem_total_kb: 4_000_000.0,
        mem_available_kb: 3_000_000.0,
        rx_mbps: 1.0,
        tx_mbps: 2.0,
        allocations: 0.0,
        coturn_sessions: 0.0,
        derp_registrations: 2.0,
        uptime_s: 10.0,
    };
    app.state
        .stats
        .upsert_relay_sample(&s)
        .await
        .expect("relay seed");
    app.state
        .stats
        .upsert_relay_unreachable("eu-north", hour + 30)
        .await
        .expect("relay unreachable seed");
    // 2 call buckets (shape written by the PR-2 sampler): 3 then 5
    // participants, 1 relayed each.
    for (i, participants) in [(0i64, 3i32), (1, 5)] {
        app.state
            .db
            .collection::<Document>("stats_call")
            .insert_one(doc! {
                "_id": format!("{}:{}", room.to_hex(), hour + i * 30),
                "tenant_id": tenant,
                "room_id": room,
                "call_id": call,
                "ts": bson::DateTime::from_millis((hour + i * 30) * 1000),
                "participants": participants,
                "relayed": 1i32,
                "direct": participants - 1,
                "send_bps": 500_000.0,
                "recv_bps": 400_000.0,
                "loss_pct": 0.5,
            })
            .await
            .expect("call seed");
    }

    let first = run_stats_rollup_once(&app.state).await;
    // Against the table, not a literal. This asserted `6` from the day it was
    // written and stayed there when the `call_user` usage ledger took the real
    // count to 8 — a stale expectation, never a rollup bug, and invisible
    // because `crates/tests` had stopped compiling. `pass_count()` keeps the
    // check honest (a pass that silently fails still trips it) while a new
    // family updates it automatically.
    assert_eq!(
        first,
        pass_count(),
        "every merge pass in the rollup table should run"
    );

    let mid = format!("{}:{}", agent.to_hex(), hour);
    let m1h = find_one(&app, "stats_machine_1h", doc! { "_id": &mid })
        .await
        .expect("machine 1h bucket");
    assert_eq!(int(&m1h, "online_minutes"), 3);
    assert_eq!(int(&m1h, "sample_count"), 3);

    let rid = format!("eu-north:{hour}");
    let r1h = find_one(&app, "stats_relay_1h", doc! { "_id": &rid })
        .await
        .expect("relay 1h bucket");
    assert_eq!(int(&r1h, "sample_count"), 2);
    assert_eq!(int(&r1h, "healthy_count"), 1);

    let cid = format!("{}:{}", tenant.to_hex(), hour);
    let c1h = find_one(&app, "stats_call_1h", doc! { "_id": &cid })
        .await
        .expect("call 1h bucket");
    // (3 + 5) participants × 30 s buckets.
    assert_eq!(int(&c1h, "participant_seconds"), 240);
    assert_eq!(int(&c1h, "relayed_seconds"), 60);
    assert_eq!(int(&c1h, "call_seconds"), 60);
    assert_eq!(int(&c1h, "distinct_rooms"), 1);

    // Daily buckets exist and carry the sums.
    let day = hour - hour.rem_euclid(86_400);
    let m1d = find_one(
        &app,
        "stats_machine_1d",
        doc! { "_id": format!("{}:{}", agent.to_hex(), day) },
    )
    .await
    .expect("machine 1d bucket");
    assert_eq!(int(&m1d, "online_minutes"), 3);

    // Re-running must not drift any counter (whole-bucket replace).
    let second = run_stats_rollup_once(&app.state).await;
    assert_eq!(second, pass_count());
    let m1h_again = find_one(&app, "stats_machine_1h", doc! { "_id": &mid })
        .await
        .expect("machine 1h after rerun");
    assert_eq!(int(&m1h_again, "online_minutes"), 3);
    assert_eq!(int(&m1h_again, "sample_count"), 3);
    let c1h_again = find_one(&app, "stats_call_1h", doc! { "_id": &cid })
        .await
        .expect("call 1h after rerun");
    assert_eq!(int(&c1h_again, "participant_seconds"), 240);
}

#[tokio::test]
async fn presence_events_ledger_appends() {
    let app = TestApp::spawn().await;
    let tenant = ObjectId::new();
    let agent = ObjectId::new();
    app.state
        .stats
        .append_presence_event(tenant, agent, "online")
        .await
        .expect("append online");
    app.state
        .stats
        .append_presence_event(tenant, agent, "offline")
        .await
        .expect("append offline");
    assert_eq!(
        count(&app, "stats_events", doc! { "agent_id": agent }).await,
        2
    );
}

// ── Stats PR-2 — call lifecycle + orphan sweep ──────────────────────────

#[tokio::test]
async fn call_lifecycle_books_call_session_and_fills_dead_fields() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("statscall").await;
    let tid = &seeded.tenant_id;
    let rid_hex = &seeded.rooms[0].id;
    let token = &seeded.admin.access_token;
    let rid = ObjectId::parse_str(rid_hex).unwrap();
    let base = format!("/api/tenant/{tid}/room/{rid_hex}");

    // start ×2 → exactly ONE call instance, started_at stable (the
    // transition gate: a re-invoked start must not reset the clock).
    let r = app
        .auth_post(&format!("{base}/call/start"), token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let call1 = find_one(&app, "call_sessions", doc! { "room_id": rid })
        .await
        .expect("call doc created");
    let started_first = *call1.get_datetime("started_at").unwrap();
    let r = app
        .auth_post(&format!("{base}/call/start"), token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(
        count(&app, "call_sessions", doc! { "room_id": rid }).await,
        1
    );
    let room = find_one(&app, "rooms", doc! { "_id": rid }).await.unwrap();
    let call_id = room
        .get_object_id("current_call_id")
        .expect("current_call_id set");
    let call_again = find_one(&app, "call_sessions", doc! { "_id": call_id })
        .await
        .unwrap();
    assert_eq!(
        *call_again.get_datetime("started_at").unwrap(),
        started_first
    );

    // join → previously-dead rooms.peak_participant_count fills.
    let r = app
        .auth_post(&format!("{base}/call/join"), token)
        .json(&serde_json::json!({ "connection_id": "c1" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let room = find_one(&app, "rooms", doc! { "_id": rid }).await.unwrap();
    assert!(int(&room, "peak_participant_count") >= 1);

    // Hold the session >1 s so the booked seconds are non-zero.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // leave (last participant) → session closed WITH duration (dead field),
    // total_duration incremented, call minutes booked, call auto-ended.
    let r = app
        .auth_post(&format!("{base}/call/leave"), token)
        .json(&serde_json::json!({ "connection_id": "c1" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

    let member = find_one(
        &app,
        "room_members",
        doc! { "room_id": rid, "sessions.duration": { "$gte": 1 } },
    )
    .await;
    assert!(member.is_some(), "closed session should carry a duration");
    let member = member.unwrap();
    assert!(int(&member, "total_duration") >= 1);

    let call = find_one(&app, "call_sessions", doc! { "_id": call_id })
        .await
        .unwrap();
    assert!(int(&call, "participant_seconds") >= 1);
    assert!(
        call.get_datetime("ended_at").is_ok(),
        "last leaver must auto-end the call instance"
    );
    assert_eq!(call.get_str("end_reason").unwrap(), "last_left");
    let room = find_one(&app, "rooms", doc! { "_id": rid }).await.unwrap();
    assert!(
        room.get_object_id("current_call_id").is_err(),
        "current_call_id cleared on end"
    );
}

#[tokio::test]
async fn orphan_sweep_closes_stale_call_state() {
    let app = TestApp::spawn().await;
    let tenant = ObjectId::new();
    let room = ObjectId::new();
    let call = ObjectId::new();
    let hour_ago =
        bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() - 3_600_000);

    // A call doc + an open member session for a room that is NOT
    // in_progress (no room doc at all — same class as a crashed pod's
    // leftovers).
    app.state
        .db
        .collection::<Document>("call_sessions")
        .insert_one(doc! {
            "_id": call,
            "tenant_id": tenant,
            "room_id": room,
            "started_by": tenant,
            "started_at": hour_ago,
            "ended_at": bson::Bson::Null,
            "peak_participants": 2_i32,
            "participant_seconds": 0_i64,
        })
        .await
        .unwrap();
    app.state
        .db
        .collection::<Document>("room_members")
        .insert_one(doc! {
            "tenant_id": tenant,
            "room_id": room,
            "sessions": [ {
                "joined_at": hour_ago,
                "left_at": bson::Bson::Null,
                "duration": bson::Bson::Null,
                "device_type": "web",
                "connection_id": "dead-conn",
            } ],
            "total_duration": 0_i64,
        })
        .await
        .unwrap();

    let (calls, sessions) = close_orphaned_call_state(
        app.state
            .modules
            .conference
            .as_ref()
            .expect("the conference module is mounted in tests"),
    )
    .await;
    assert_eq!(calls, 1);
    assert_eq!(sessions, 1);

    let call_doc = find_one(&app, "call_sessions", doc! { "_id": call })
        .await
        .unwrap();
    assert!(call_doc.get_datetime("ended_at").is_ok());
    assert_eq!(call_doc.get_str("end_reason").unwrap(), "stale_reset");
    let member = find_one(&app, "room_members", doc! { "room_id": room })
        .await
        .unwrap();
    let sess = member.get_array("sessions").unwrap()[0]
        .as_document()
        .unwrap();
    assert!(sess.get_datetime("left_at").is_ok());
    let d = match sess.get("duration") {
        Some(bson::Bson::Int64(v)) => *v,
        Some(bson::Bson::Int32(v)) => i64::from(*v),
        other => panic!("duration not filled: {other:?}"),
    };
    assert!((3500..3700).contains(&d), "duration ≈1h, got {d}");
}

// ── Stats PR-3 — platform admin + query APIs ────────────────────────────

#[tokio::test]
async fn admin_stats_gate_is_objectid_allowlist_with_404_miss() {
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
    })
    .await;
    // The admin endpoints never read the users collection — a minted
    // token for the allowlisted id suffices to exercise the gate.
    let tokens = app
        .state
        .auth
        .generate_tokens(admin_id, "padmin@test.io", "padmin")
        .unwrap();
    let r = app
        .auth_get("/api/admin/stats/relay/current", &tokens.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["enabled"], serde_json::json!(true));
    let r = app
        .auth_get("/api/admin/stats/orgs", &tokens.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

    // Any other authed user → 404 (NEVER 403: the platform-admin allowlist
    // is itself what is being hidden, so a 403 would confirm the surface).
    let user = app
        .register_user(
            "nobody@test.io",
            "nobody",
            "No Body",
            "Password123!",
            None,
            None,
        )
        .await;
    let r = app
        .auth_get("/api/admin/stats/relay/current", &user.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
}

#[tokio::test]
async fn tenant_stats_visibility_member_vs_admin_vs_outsider() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("statsvis").await;
    let tid = &seeded.tenant_id;

    // overview: any member 200.
    let r = app
        .auth_get(
            &format!("/api/tenant/{tid}/stats/overview"),
            &seeded.member.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["enabled"], serde_json::json!(true));
    assert!(body["machines"]["total"].is_number());

    // Queryable series: plain member (no MANAGE_AGENTS) → 404; owner → 200.
    let r = app
        .auth_get(
            &format!("/api/tenant/{tid}/stats/machines?range=7d"),
            &seeded.member.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
    let r = app
        .auth_get(
            &format!("/api/tenant/{tid}/stats/machines?range=7d"),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let r = app
        .auth_get(
            &format!("/api/tenant/{tid}/stats/tunnels"),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

    // Outsider (authed, not a member): overview → 404.
    let outsider = app
        .register_user(
            "out@statsvis.io",
            "outsider",
            "Out Sider",
            "Password123!",
            None,
            None,
        )
        .await;
    let r = app
        .auth_get(
            &format!("/api/tenant/{tid}/stats/overview"),
            &outsider.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
}

#[tokio::test]
async fn me_payload_carries_platform_admin_flag() {
    let app = TestApp::spawn().await;
    let user = app
        .register_user(
            "flag@test.io",
            "flaguser",
            "Flag User",
            "Password123!",
            None,
            None,
        )
        .await;
    let r = app
        .auth_get("/api/auth/me", &user.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["is_platform_admin"], serde_json::json!(false));
}

#[tokio::test]
async fn tenant_calls_series_reads_rollups() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("statsq").await;
    let tid_oid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let hour = bucket_start(unix_now(), 3600) - 3600;
    app.state
        .db
        .collection::<Document>("stats_call_1h")
        .insert_one(doc! {
            "_id": format!("{}:{}", tid_oid.to_hex(), hour),
            "tenant_id": tid_oid,
            "ts": bson::DateTime::from_millis(hour * 1000),
            "sample_count": 10,
            "participant_seconds": 600_i64,
            "relayed_seconds": 60_i64,
            "direct_seconds": 540_i64,
            "call_seconds": 300_i64,
            "peak_participants": 4,
            "send_bps": 1_000_000.0,
            "recv_bps": 800_000.0,
            "loss_pct": 0.2,
            "distinct_rooms": 1,
        })
        .await
        .unwrap();
    let r = app
        .auth_get(
            &format!("/api/tenant/{}/stats/calls?range=7d", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    let series = body["series"].as_array().unwrap();
    assert_eq!(series.len(), 1);
    assert_eq!(series[0]["participant_seconds"], serde_json::json!(600));
    assert!(series[0]["t"].is_number());
    assert!(body["totals"]["calls"].is_number());
}

// ── FR-93 P2b — Linux desktops and the arm serving each (AC13) ──────────

#[tokio::test]
async fn desktops_are_counted_by_type_and_arm_per_org_and_fleet_wide() {
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
    })
    .await;
    let seeded = app.seed_tenant("statsdesk").await;
    let other = app.seed_tenant("statsdesk2").await;
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let other_tid = ObjectId::parse_str(&other.tenant_id).unwrap();
    let brief = |kind: &str, arm: &str| {
        doc! {
            "session": "user", "type": kind, "capture_arm": arm, "input_reach": "none",
        }
    };
    let agents = app.state.db.collection::<Document>("agents");
    let rows = [
        // (tenant, name, presence, desktop brief, deleted)
        (
            tid,
            "gnome-user",
            "online",
            Some(brief("wayland", "mutter")),
            false,
        ),
        (
            tid,
            "kde-user",
            "offline",
            Some(brief("wayland", "none")),
            false,
        ),
        (tid, "xorg", "online", Some(brief("x11", "x11")), false),
        // Never sent a brief (Windows, an older agent): not counted.
        (tid, "windows", "online", None, false),
        // Removed: not counted.
        (
            tid,
            "gone",
            "online",
            Some(brief("wayland", "mutter")),
            true,
        ),
        // Another org: in the fleet-wide count only.
        (
            other_tid,
            "elsewhere",
            "online",
            Some(brief("wayland", "mutter")),
            false,
        ),
    ];
    for (tenant, name, presence, desktop, deleted) in rows {
        let mut caps = doc! { "codecs": ["h264"] };
        if let Some(d) = desktop {
            caps.insert("desktop", d);
        }
        let deleted_at = if deleted {
            bson::Bson::DateTime(bson::DateTime::now())
        } else {
            bson::Bson::Null
        };
        agents
            .insert_one(doc! {
                "_id": ObjectId::new(), "tenant_id": tenant, "name": name,
                // The plain unique {tenant_id, machine_id} index (see the
                // uptime test below): every row needs its own.
                "machine_id": format!("machine-{name}"),
                "last_presence": presence,
                "capabilities": caps,
                "deleted_at": deleted_at,
            })
            .await
            .unwrap();
    }

    let r = app
        .auth_get(
            &format!("/api/tenant/{}/stats/overview", seeded.tenant_id),
            &seeded.member.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        body["desktops"],
        serde_json::json!([
            { "type": "wayland", "capture_arm": "mutter", "total": 1, "online": 1 },
            { "type": "wayland", "capture_arm": "none", "total": 1, "online": 0 },
            { "type": "x11", "capture_arm": "x11", "total": 1, "online": 1 },
        ]),
        "{body}"
    );

    let tokens = app
        .state
        .auth
        .generate_tokens(admin_id, "padmin@test.io", "padmin")
        .unwrap();
    let r = app
        .auth_get("/api/admin/stats/orgs", &tokens.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    let mutter = body["desktops"]
        .as_array()
        .expect("desktops array")
        .iter()
        .find(|d| d["type"] == "wayland" && d["capture_arm"] == "mutter")
        .cloned()
        .expect("a wayland/mutter row");
    // Both orgs' GNOME devices, never the removed one.
    assert_eq!(mutter["total"], serde_json::json!(2), "{body}");
}

// ── Stats follow-up — uptime strips from the presence ledger ────────────

#[tokio::test]
async fn uptime_intervals_reconstruct_presence_and_admit_ignorance() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("statsup").await;
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let now = unix_now();

    // Two devices: one that transitioned inside the window, one that has
    // never transitioned since the ledger began.
    let flappy = ObjectId::new();
    let quiet = ObjectId::new();
    // FR-116 D4 — `flappy` has a friendly name, `quiet` none.
    for (id, name, display, presence) in [
        (flappy, "flappy", Some("Flappy build box"), "offline"),
        (quiet, "quiet", None, "online"),
    ] {
        app.state
            .db
            .collection::<Document>("agents")
            .insert_one(doc! {
                "_id": id, "tenant_id": tid, "name": name, "display_name": display,
                // `machine_id` is REQUIRED here even though nothing in this
                // test reads it: `agents` carries a plain (non-partial) unique
                // index on {tenant_id, machine_id}, so two rows omitting the
                // field both index as null and the second insert 11000s.
                // Enrollment always sets one, so a row without it is not a
                // shape the product ever produces.
                "machine_id": format!("machine-{name}"),
                "last_presence": presence, "deleted_at": bson::Bson::Null,
            })
            .await
            .unwrap();
    }
    // Ledger begins 6 h ago (the feature's own start), flappy goes
    // offline 2 h ago. `quiet` never appears in the ledger.
    let ev = |agent: ObjectId, secs_ago: i64, presence: &str| {
        doc! {
            "tenant_id": tid, "agent_id": agent,
            "ts": bson::DateTime::from_millis((now - secs_ago) * 1000),
            "presence": presence,
        }
    };
    app.state
        .db
        .collection::<Document>("stats_events")
        .insert_many(vec![
            ev(flappy, 6 * 3600, "online"),
            ev(flappy, 2 * 3600, "offline"),
        ])
        .await
        .unwrap();

    let r = app
        .auth_get(
            &format!("/api/tenant/{}/stats/machines?range=24h", seeded.tenant_id),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    let uptime = body["uptime"].as_array().expect("uptime array");

    let row = |name: &str| -> serde_json::Value {
        uptime
            .iter()
            .find(|u| u["name"] == serde_json::json!(name))
            .cloned()
            .unwrap_or_else(|| panic!("no uptime row for {name}"))
    };

    // flappy: unknown before the ledger existed → online → offline (tail).
    let f = row("flappy");
    let ivs = f["intervals"].as_array().unwrap();
    let seq: Vec<&str> = ivs
        .iter()
        .map(|i| i["presence"].as_str().unwrap())
        .collect();
    assert_eq!(seq, vec!["unknown", "online", "offline"], "got {seq:?}");
    // Intervals tile the window contiguously.
    for w in ivs.windows(2) {
        assert_eq!(w[0]["to"], w[1]["from"], "intervals must be contiguous");
    }
    assert!(ivs.last().unwrap()["to"].as_i64().unwrap() >= now - 5);

    // quiet: never transitioned. The stretch BEFORE the ledger existed is
    // `unknown` — not back-filled with today's state — and only the
    // recorded era claims its current presence.
    let q = row("quiet");
    let ivs = q["intervals"].as_array().unwrap();
    let seq: Vec<&str> = ivs
        .iter()
        .map(|i| i["presence"].as_str().unwrap())
        .collect();
    assert_eq!(seq, vec!["unknown", "online"], "got {seq:?}");
    let boundary = ivs[0]["to"].as_i64().unwrap();
    assert!(
        (boundary - (now - 6 * 3600)).abs() <= 5,
        "the unknown stretch must end where the ledger starts, got {boundary}"
    );

    // FR-116 D4 — the friendly name rides beside the machine name (additive:
    // `name` keeps meaning the machine's), and a device without one says null.
    assert_eq!(f["display_name"], serde_json::json!("Flappy build box"));
    assert!(q["display_name"].is_null(), "got {:?}", q["display_name"]);
}

// FR-116 D4 — a person's usage names each device by its friendly name too.
// The machine name stays in `agent_name` (additive), and a device without a
// friendly name says null rather than repeating the machine's.
#[tokio::test]
async fn usage_detail_names_each_device_by_its_display_name() {
    let app = TestApp::spawn().await;
    let seeded = app.seed_tenant("statsusage").await;
    let tid = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let uid = ObjectId::parse_str(&seeded.admin.id).unwrap();
    let now = unix_now();

    let named = ObjectId::new();
    let unnamed = ObjectId::new();
    for (id, name, display) in [
        (named, "build-01", Some("Build server")),
        (unnamed, "kiosk-03", None),
    ] {
        app.state
            .db
            .collection::<Document>("agents")
            .insert_one(doc! {
                "_id": id, "tenant_id": tid, "name": name, "display_name": display,
                // The {tenant_id, machine_id} unique index — see the uptime test.
                "machine_id": format!("machine-{name}"),
                "deleted_at": bson::Bson::Null,
            })
            .await
            .unwrap();
    }
    // One finished remote session against each device, both inside the window.
    let at = |secs_ago: i64| bson::DateTime::from_millis((now - secs_ago) * 1000);
    let session = |agent: ObjectId, from: i64, to: i64| {
        doc! {
            "_id": ObjectId::new(), "tenant_id": tid, "agent_id": agent,
            "controller_user_id": uid, "started_at": at(from), "ended_at": at(to),
        }
    };
    app.state
        .db
        .collection::<Document>("remote_sessions")
        .insert_many(vec![
            session(named, 3 * 3600, 2 * 3600),
            session(unnamed, 3600, 1800),
        ])
        .await
        .unwrap();

    let r = app
        .auth_get(
            &format!(
                "/api/tenant/{}/stats/usage/{}?range=24h",
                seeded.tenant_id, seeded.admin.id
            ),
            &seeded.admin.access_token,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    let viewing = body["viewing"].as_array().expect("viewing array");
    let window = |agent: ObjectId| -> serde_json::Value {
        viewing
            .iter()
            .find(|w| w["agent_id"] == serde_json::json!(agent.to_hex()))
            .cloned()
            .unwrap_or_else(|| panic!("no window for {agent}: {body}"))
    };

    let n = window(named);
    assert_eq!(n["agent_name"], serde_json::json!("build-01"));
    assert_eq!(n["agent_display_name"], serde_json::json!("Build server"));
    let u = window(unnamed);
    assert_eq!(u["agent_name"], serde_json::json!("kiosk-03"));
    assert!(
        u["agent_display_name"].is_null(),
        "got {:?}",
        u["agent_display_name"]
    );
}

// ── Wave 2 — platform user analytics ────────────────────────────────────

#[tokio::test]
async fn page_view_beacon_normalizes_paths_and_admin_reads_them_back() {
    let admin_id = ObjectId::new();
    let app = TestApp::spawn_with_settings(move |s| {
        s.stats.platform_admins = Some(admin_id.to_hex());
    })
    .await;
    let user = app
        .register_user(
            "beacon@test.io",
            "beacon",
            "Beacon User",
            "Password123!",
            None,
            None,
        )
        .await;

    // A real SPA path carrying two ObjectIds plus a query string.
    let r = app
        .auth_post("/api/stats/pageview", &user.access_token)
        .json(&serde_json::json!({
            "paths": [
                "/tenant/69a1dbbad2000f26adc875ce/room/69a1dbc8d2000f26adc875d5?tab=all",
                "/observability",
            ]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

    // Stored paths must carry NO identifiers.
    let stored: Vec<String> = {
        let mut out = Vec::new();
        let mut cur = app
            .state
            .db
            .collection::<Document>("page_views")
            .find(doc! {})
            .await
            .unwrap();
        while let Ok(Some(d)) = futures::TryStreamExt::try_next(&mut cur).await {
            out.push(d.get_str("path").unwrap_or_default().to_string());
        }
        out.sort();
        out
    };
    assert_eq!(
        stored,
        vec![
            "/observability".to_string(),
            "/tenant/:id/room/:id".to_string()
        ],
        "ids and query strings must never reach an analytics row"
    );

    // The platform view reads them back, and is platform-admin gated.
    let tokens = app
        .state
        .auth
        .generate_tokens(admin_id, "padmin@test.io", "padmin")
        .unwrap();
    let r = app
        .auth_get("/api/admin/stats/users?range=24h", &tokens.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["enabled"], serde_json::json!(true));
    // No GeoIP database in tests ⇒ the flag says so rather than the
    // payload pretending it resolved countries.
    assert_eq!(body["geoip"], serde_json::json!(false));
    // ...and names no database, so the dashboard credits no data source
    // (#1896: the credit follows the database actually loaded). `.get`, not
    // indexing: `body["…"]` reads `Null` for a MISSING key too, and then
    // this could not fail.
    assert_eq!(body.get("geoip_database"), Some(&serde_json::Value::Null));
    let pages = body["pages"].as_array().unwrap();
    assert!(
        pages.iter().any(|p| p["path"] == "/tenant/:id/room/:id"),
        "normalised page should be reported: {pages:?}"
    );

    // A non-admin must not see the platform analytics (404, never 403 — a
    // 403 would confirm the surface exists).
    let r = app
        .auth_get("/api/admin/stats/users?range=24h", &user.access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 404);
}
