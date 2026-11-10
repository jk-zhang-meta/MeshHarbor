// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P2e-4 and P2e-5 — a device's frames of a promotion, end to end: a real
//! server and a real device in-process, as the canary (`hive_canary.rs`; this
//! is its own binary for the same reason: the device's Hive supervisor is
//! process-global).
//!
//! Each step is seeded on the record and its frame sent over the device's
//! control connection, as that step sends it, so one device answers each
//! step on its own, including the ones a real promotion never asks of it in
//! this order. A promotion the route starts, between two real devices, is
//! `hive_promote.rs` (P2e-5c).
//! What the test reads is the server's own: the record, and the room its
//! handler of the device's answer wrote to, and the device's answers to
//! prompts over the owner's viewer peer.
//!
//! | step | the device | what the test reads |
//! |---|---|---|
//! | the drain, a promotion `draining` this device | takes no new prompt; answers `rc:hive.drained` with its store's tip | the record moved on to `syncing`, holding that tip; a prompt refused in words |
//! | the word, `rc:hive.lease` at its fence | lifts the drain | a prompt answered, and in the harness's stdin |
//! | the prepare, a promotion `preparing` toward this device (P2e-5) | runs a start's gates: it holds no copy of the session to take it over from | the room, in the device's own words |
//! | a member's join after a move (P2e-5b), naming where fence 1 ended | refuses one naming an end it cannot read; joins the one the server sends | the record's member: its answer, in the device's word |
#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

use bson::oid::ObjectId;
use meshharbor_mod_hive::dao::AgentSessionDao;
use meshharbor_mod_hive::model::{
    AgentSession, FenceMark, MemberState, Promotion, PromotionState, ReplicaMember, Replicaset,
    SessionStatus,
};
use meshharbor_remote_control::hive::{HiveFenceMark, HiveReplicaRole};
use meshharbor_remote_control::signaling::ServerMsg;
use meshharbor_tests::fixtures::test_app::TestApp;
use serde_json::{Value, json};

mod hive_support;
use hive_support::*;

/// A stand-in for Claude Code that records what it is told: each line on
/// stdin goes to `harness-stdin.log` in the session's folder, and each prompt
/// gets a turn.
const HARNESS: &str = r#"#!/bin/sh
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$PWD/harness-stdin.log"
  echo '{"type":"system","subtype":"init","session_id":"fake","model":"m","cwd":"'"$PWD"'","tools":[]}'
  echo '{"type":"assistant","message":{"content":[{"type":"text","text":"ok"}]}}'
  echo '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"duration_ms":5,"total_cost_usd":0.0}'
done
"#;

/// What a prompt hears while its session drains.
const MOVING: &str = "the session is moving to another device — ask again in a minute";

/// P2e-5 — a prepare's refusal from a device that holds no copy.
const NO_COPY: &str = "holds no copy of the session to take it over from";

/// Each prompt the harness has read so far, as text.
fn harness_read(folder: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(folder.join("harness-stdin.log"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| {
            v["message"]["content"][0]["text"]
                .as_str()
                .map(str::to_string)
        })
        .collect()
}

/// Poll until the harness has read `n` prompts, or the patience runs out.
async fn until_read(folder: &std::path::Path, n: usize) -> Vec<String> {
    let deadline = Instant::now() + WAIT;
    loop {
        let read = harness_read(folder);
        if read.len() >= n || Instant::now() > deadline {
            return read;
        }
        tokio::time::sleep(POLL).await;
    }
}

/// The one member of a session this test placed by hand.
fn member_of(s: &AgentSession) -> &ReplicaMember {
    &s.replicaset.as_ref().expect("placed").members[0]
}

/// Poll the stored session until `pred` holds.
async fn until_stored(
    dao: &AgentSessionDao,
    sid: ObjectId,
    what: &str,
    pred: impl Fn(&AgentSession) -> bool,
) -> AgentSession {
    let deadline = Instant::now() + WAIT;
    loop {
        let s = dao.find(sid).await.unwrap().expect("the session's record");
        if pred(&s) {
            return s;
        }
        assert!(Instant::now() < deadline, "{what}: {:?}", s.promotion);
        tokio::time::sleep(POLL).await;
    }
}

#[test]
fn a_drain_and_a_prepare_over_the_control_connection_are_answered_in_the_devices_words() {
    // Its own thread with a deep stack, and a current-thread runtime, as the
    // canary: several servers' worth of tasks live in one body.
    let joined = std::thread::Builder::new()
        .name("hive-drain".into())
        .stack_size(16 << 20)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(scenario())
        })
        .unwrap()
        .join();
    if let Err(panic) = joined {
        std::panic::resume_unwind(panic);
    }
}

async fn scenario() {
    let app = TestApp::spawn_with_settings(|s| {
        s.modules.hive = true;
        s.hive.replicaset = true;
        s.app.rate_limit_per_sec = 1_000;
        s.app.rate_limit_burst = 10_000;
    })
    .await;
    let seeded = app.seed_tenant("hivedrain").await;
    let owner = seeded.admin.access_token.clone();

    let dir = tempfile::tempdir().unwrap();
    let roots = dir.path().join("roots");
    let work = roots.join("work");
    let home = dir.path().join("home");
    for d in [&work, &home] {
        std::fs::create_dir_all(d).unwrap();
    }
    let harness = dir.path().join("claude");
    std::fs::write(&harness, HARNESS).unwrap();
    std::fs::set_permissions(&harness, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut cfg = enrol(&app, &seeded, "hive-drain").await;
    cfg.hive_enabled = true;
    // P2e-5b — it holds copies too, so a member's join reaches it.
    cfg.hive_replica = true;
    cfg.hive_accounts
        .insert(seeded.admin.id.clone(), "drainer".into());
    cfg.hive_roots = vec![roots.display().to_string()];
    cfg.hive_harness = Some(harness.display().to_string());
    meshharbord::hive::init_as_daemon(
        &cfg,
        &dir.path().join("hive.db"),
        &dir.path().join("run"),
        &home,
    )
    .expect("the test launcher");
    let device = cfg.agent_id.clone();
    let (stop_device, stop_rx) = tokio::sync::watch::channel(false);
    let device_task = spawn_device(cfg, stop_rx);
    wait_online(&app, &seeded, &device).await;

    let s = start(&app, &seeded, &device, &work).await;
    let sid = s["id"].as_str().unwrap().to_string();
    assert!(
        reached(&app, &seeded, &sid, "idle").await,
        "the session never came up"
    );
    let mut ows = UserWs::open(&app, &owner).await;
    let mut own = view(&mut ows, &sid).await;
    own.send(json!({"op": "hello"})).await;
    assert_eq!(own.recv_op("hello").await["may_prompt"], true);
    own.send(json!({"op": "prompt", "id": "p1", "text": "first"}))
        .await;
    assert_eq!(own.recv_op("prompt").await["ok"], true);
    assert_eq!(until_read(&work, 1).await.len(), 1, "the first prompt");

    // ── The server's drain step, as a promotion takes it ────────────────────
    let dao = AgentSessionDao::new(&app.db);
    let session_id = ObjectId::parse_str(&sid).unwrap();
    let rec = dao.find(session_id).await.unwrap().unwrap();
    let in_two_minutes =
        bson::DateTime::from_millis(bson::DateTime::now().timestamp_millis() + 120_000);
    let promotion = Promotion {
        id: ObjectId::new(),
        to: ObjectId::new(),
        to_name: "a member".into(),
        to_role: "owner".into(),
        folder: rec.location.folder.clone(),
        from: rec.location.clone(),
        from_fence: rec.fence,
        by: rec.owner_id,
        state: PromotionState::Draining,
        started_at: bson::DateTime::now(),
        deadline: in_two_minutes,
        drained: None,
        unreachable_from: false,
        prior: None,
        teleport: false,
        fork: None,
    };
    assert!(
        dao.begin_promotion(rec.tenant_id, rec.owner_id, session_id, &promotion, false)
            .await
            .unwrap(),
        "the promotion begins on the record"
    );
    let agent = ObjectId::parse_str(&device).unwrap();
    let tenant = ObjectId::parse_str(&seeded.tenant_id).unwrap();
    let fence = u64::try_from(rec.fence).unwrap();
    app.state
        .fleet()
        .rc_hub
        .push_hive(agent, tenant, ServerMsg::HiveDrain { session_id, fence })
        .expect("the drain reaches the device");

    let drained = until_stored(&dao, session_id, "the server never heard it drained", |s| {
        s.promotion
            .as_ref()
            .is_some_and(|p| p.state == PromotionState::Syncing)
    })
    .await;
    let tip = drained
        .promotion
        .and_then(|p| p.drained)
        .expect("the drained tip, on the record");
    assert!(
        tip.seq >= 4,
        "the turn's events are below the tip (the prompt, the init, the text, the turn): {tip:?}"
    );
    assert!(
        meshharbor_remote_control::hive::is_hash_hex(&tip.hash),
        "{tip:?}"
    );

    own.send(json!({"op": "prompt", "id": "p2", "text": "second"}))
        .await;
    let ack = own.recv_op("prompt").await;
    assert_eq!(ack["ok"], false, "drained: {ack}");
    assert_eq!(ack["error"], MOVING, "{ack}");

    // ── The word: the lease stayed ──────────────────────────────────────────
    app.state
        .fleet()
        .rc_hub
        .push_hive(agent, tenant, ServerMsg::HiveLease { session_id, fence })
        .expect("the word reaches the device");
    let deadline = Instant::now() + WAIT;
    let mut n = 3;
    loop {
        own.send(json!({"op": "prompt", "id": format!("p{n}"), "text": "third"}))
            .await;
        let ack = own.recv_op("prompt").await;
        if ack["ok"] == true {
            break;
        }
        assert_eq!(ack["error"], MOVING, "only the drain refuses it: {ack}");
        assert!(Instant::now() < deadline, "the word never lifted the drain");
        n += 1;
        tokio::time::sleep(POLL).await;
    }
    let read = until_read(&work, 2).await;

    // ── A member's prepare (P2e-5), toward this very device ─────────────────
    // The drain's promotion over, one preparing toward this device asks it
    // whether it could take the session over at the next fence. It runs it at
    // this one, and holds no checkpoint of it (no member: never replicated),
    // so it refuses, and the room says so in the device's own words.
    assert!(
        dao.end_promotion(session_id, promotion.id, &[PromotionState::Syncing])
            .await
            .unwrap()
            .is_some(),
        "the drain's promotion, ended"
    );
    let preparing = Promotion {
        id: ObjectId::new(),
        to: agent,
        state: PromotionState::Preparing,
        drained: None,
        ..promotion.clone()
    };
    assert!(
        dao.begin_promotion(rec.tenant_id, rec.owner_id, session_id, &preparing, false)
            .await
            .unwrap(),
        "the prepare's promotion begins"
    );
    let room = s["room_id"].as_str().unwrap().to_string();
    app.state
        .fleet()
        .rc_hub
        .push_hive(
            agent,
            tenant,
            ServerMsg::HivePrepare {
                session_id,
                fence: fence + 1,
                harness: rec.harness.id.clone(),
                harness_session: rec.harness.session.clone(),
                folder: rec.location.folder.clone(),
                user_id: rec.owner_id,
                user_email: seeded.admin.email.clone(),
                caller: "hivedrain Admin".into(),
                teleport: false,
                have_want: false,
            },
        )
        .expect("the prepare reaches the device");
    let deadline = Instant::now() + WAIT;
    loop {
        let said = room_messages(&app, &seeded, &room)
            .await
            .iter()
            .any(|m| m["content"].as_str().is_some_and(|c| c.contains(NO_COPY)));
        if said {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the device's answer to the prepare never reached the room"
        );
        tokio::time::sleep(POLL).await;
    }

    // ── A member's join after a move (P2e-5b), on this same connection ─────
    // Another session, moved once, names this device a member at fence 2. A
    // join naming an end the device cannot read (of the join's own fence) is
    // refused whole; the one the server sends, where fence 1 ended, is joined.
    let other = ObjectId::new();
    let mut moved = rec.clone();
    moved.id = Some(other);
    moved.fence = 2;
    moved.status = SessionStatus::Ended;
    moved.location.device_id = ObjectId::new();
    moved.room_id = None;
    moved.promotion = None;
    moved.fences = vec![FenceMark {
        fence: 1,
        seq: 5,
        hash: "ab".repeat(32),
    }];
    moved.replicaset = Some(Replicaset {
        policy_revision: 0,
        min: 2,
        max: 4,
        restricted_tags: Vec::new(),
        members: vec![ReplicaMember {
            device_id: agent,
            role: "owner".into(),
            state: MemberState::Pending,
            refusal: None,
            answered_at: None,
            tip: None,
            purging: None,
            forking: None,
        }],
        short: None,
        placed_at: bson::DateTime::now(),
    });
    dao.create(&moved).await.unwrap();
    let join = |fence_of_end: u64| ServerMsg::HiveReplicaJoin {
        session_id: other,
        fence: 2,
        role: Some(HiveReplicaRole::Owner),
        fences: vec![HiveFenceMark {
            fence: fence_of_end,
            seq: 5,
            hash: "ab".repeat(32),
        }],
    };
    let answer_after = |after: Option<bson::DateTime>| {
        let dao = &dao;
        async move {
            let s = until_stored(dao, other, "the device never answered the join", |s| {
                member_of(s).answered_at.is_some() && member_of(s).answered_at != after
            })
            .await;
            member_of(&s).clone()
        }
    };
    let hub = &app.state.fleet().rc_hub;
    hub.push_hive_replica(agent, tenant, join(2))
        .expect("the join reaches the device");
    let refused = answer_after(None).await;
    assert_eq!(
        (refused.state, refused.refusal.as_deref()),
        (MemberState::Refused, Some("other")),
        "an end of the join's own fence, which the device cannot read, refused whole"
    );
    hub.push_hive_replica(agent, tenant, join(1))
        .expect("the join reaches the device");
    let joined = answer_after(refused.answered_at).await;
    assert_eq!(
        (joined.state, joined.refusal.as_deref()),
        (MemberState::Joined, None),
        "where fence 1 ended: joined"
    );
    own.close(&mut ows).await;
    let _ = stop_device.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(10), device_task).await;
    assert_eq!(read.len(), 2, "{read:?}");
    assert!(read[0].ends_with("first"), "{read:?}");
    assert!(
        read[1].ends_with("third"),
        "the word let the prompt in, and the refused one never reached the harness: {read:?}"
    );
}
