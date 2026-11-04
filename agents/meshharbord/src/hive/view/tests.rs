// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! The viewer peer, end to end on one host: the supervisor's own rig (a fake
//! harness, an in-memory store), and a webrtc-rs peer standing in for the
//! browser. The signalling the server would relay is relayed here by a pump
//! between the rig's report channel and the "browser".

use std::time::Duration;

use bytes::Bytes;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use webrtc::api::APIBuilder;
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::ice_transport::ice_candidate::{RTCIceCandidate, RTCIceCandidateInit};
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use super::super::supervisor::tests::{
    Rig, dev, harness_asks, next_state, order, release, rig, rig_with, until_awaiting,
};
use super::*;

const WAIT: Duration = Duration::from_secs(15);

fn grant(session: ObjectId, user: ObjectId, may_prompt: bool, ttl_secs: u32) -> ViewGrant {
    ViewGrant {
        grant_id: ObjectId::new(),
        session_id: session,
        user_id: user,
        user_name: "Viewer".into(),
        may_prompt,
        user_email: None,
        driving_refused: None,
        copy: false,
        ttl_secs,
        search: None,
    }
}

/// Start a session, run one turn, and wait until it is idle again.
async fn session_with_a_turn(r: &mut Rig) -> ObjectId {
    let o = order(r);
    let sid = o.session_id;
    assert!(r.sup.start(o, true).await.refused.is_none());
    assert_eq!(next_state(r, sid).await.0, HiveRunState::Idle);
    r.sup.prompt(sid, dev(r), "first".into()).unwrap();
    assert_eq!(next_state(r, sid).await.0, HiveRunState::Running);
    assert_eq!(next_state(r, sid).await.0, HiveRunState::Idle);
    sid
}

/// The next `rc:hive.view.closed` on the rig's channel.
async fn next_closed(r: &mut Rig) -> (ObjectId, String) {
    loop {
        let msg = tokio::time::timeout(WAIT, r.reports.recv())
            .await
            .expect("a report in time")
            .expect("the reporter is open");
        if let ClientMsg::HiveViewClosed { grant_id, reason } = msg {
            return (grant_id, reason);
        }
    }
}

async fn wait_viewers(r: &Rig, n: usize) {
    let deadline = Instant::now() + WAIT;
    while r.sup.viewers().count() != n {
        assert!(Instant::now() < deadline, "viewers never reached {n}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_grant_passes_the_devices_gates_or_names_the_one_that_said_no() {
    let off = rig(false, 4);
    let g = grant(ObjectId::new(), off.user, false, 60);
    assert_eq!(
        off.sup.view_grant(g, true).await.unwrap_err().0,
        HiveViewRefusal::HiveDisabled
    );

    let mut r = rig(true, 4);
    let sid = session_with_a_turn(&mut r).await;
    assert_eq!(
        r.sup
            .view_grant(grant(sid, r.user, false, 60), false)
            .await
            .unwrap_err()
            .0,
        HiveViewRefusal::HiveDisabled,
        "a secondary organization reads nothing here"
    );
    assert_eq!(
        r.sup
            .view_grant(grant(ObjectId::new(), r.user, false, 60), true)
            .await
            .unwrap_err()
            .0,
        HiveViewRefusal::NoSession
    );

    // Idempotent on the grant id; bounded per session.
    let first = grant(sid, r.user, false, 60);
    r.sup.view_grant(first.clone(), true).await.unwrap();
    r.sup.view_grant(first.clone(), true).await.unwrap();
    assert_eq!(
        r.sup.viewers().count(),
        1,
        "a re-sent grant is not a second viewer"
    );
    let mut held = vec![first.grant_id];
    for _ in 1..view_limits::MAX_PER_SESSION {
        let g = grant(sid, r.user, false, 60);
        held.push(g.grant_id);
        r.sup.view_grant(g, true).await.unwrap();
    }
    assert_eq!(
        r.sup
            .view_grant(grant(sid, r.user, false, 60), true)
            .await
            .unwrap_err()
            .0,
        HiveViewRefusal::AtCapacity
    );
    // The server's close ends each one, and says nothing back.
    for g in held {
        r.sup.viewers().command(g, Cmd::Close("test".into()));
    }
    wait_viewers(&r, 0).await;
    r.sup.stop(sid, 1, "owner".into());
}

/// A grant holds a place; one nobody dials frees it, and the server hears
/// why, so the grant leaves its table too.
#[tokio::test]
async fn a_grant_nobody_dials_ends_and_says_so() {
    let mut r = rig(true, 4);
    let sid = session_with_a_turn(&mut r).await;
    let g = grant(sid, r.user, false, 60);
    let gid = g.grant_id;
    r.sup.view_grant(g, true).await.unwrap();
    assert_eq!(next_closed(&mut r).await, (gid, "no_offer".into()));
    wait_viewers(&r, 0).await;
    r.sup.stop(sid, 1, "owner".into());
}

/// The TTL is the device's own clock; a renewal moves it.
#[tokio::test]
async fn an_unrenewed_grant_expires_and_a_renewed_one_does_not() {
    let mut r = rig(true, 4);
    let sid = session_with_a_turn(&mut r).await;
    let short = grant(sid, r.user, false, 1);
    let gid = short.grant_id;
    r.sup.view_grant(short, true).await.unwrap();
    assert_eq!(next_closed(&mut r).await, (gid, "expired".into()));

    let renewed = grant(sid, r.user, false, 1);
    let gid = renewed.grant_id;
    r.sup.view_grant(renewed, true).await.unwrap();
    r.sup.viewers().command(gid, Cmd::Renew(60));
    // Past the first TTL it is still held — and then it ends for the OTHER
    // reason, which proves the renewal moved the deadline.
    assert_eq!(next_closed(&mut r).await, (gid, "no_offer".into()));
    r.sup.stop(sid, 1, "owner".into());
}

/// The browser's side of one viewer peer.
struct Browser {
    pc: Arc<RTCPeerConnection>,
    dc: Arc<RTCDataChannel>,
    inbox: mpsc::Receiver<Value>,
    next_id: u32,
}

impl Browser {
    async fn send(&mut self, v: Value) {
        let bytes = serde_json::to_vec(&v).unwrap();
        for frame in framing::encode(self.next_id, &bytes) {
            self.dc.send(&Bytes::from(frame)).await.unwrap();
        }
        self.next_id += 1;
    }

    /// The next message with `op`, skipping others (state pushes and the
    /// like), up to the test's patience.
    async fn recv_op(&mut self, op: &str) -> Value {
        loop {
            let v = tokio::time::timeout(WAIT, self.inbox.recv())
                .await
                .unwrap_or_else(|_| panic!("no {op:?} in time"))
                .expect("the channel is open");
            if v["op"] == op {
                return v;
            }
        }
    }

    /// The next message, whatever it is: a search grant (P2i-1) pushes
    /// nothing of its own, so its answers arrive exactly in order.
    async fn recv(&mut self) -> Value {
        tokio::time::timeout(WAIT, self.inbox.recv())
            .await
            .expect("a message in time")
            .expect("the channel is open")
    }

    /// Every transcript event that arrives until `until` matches one.
    async fn events_until(&mut self, until: impl Fn(&Value) -> bool) -> Vec<Value> {
        let mut got = Vec::new();
        loop {
            let v = self.recv_op("events").await;
            for e in v["events"].as_array().unwrap() {
                got.push(e.clone());
                if until(e) {
                    return got;
                }
            }
        }
    }
}

/// Dial `grant`'s viewer like a browser would: a `hive` channel, an offer,
/// and the device's answer and candidates relayed back from the rig's
/// report channel (everything else on it is passed through).
async fn dial(r: &mut Rig, gid: ObjectId) -> Browser {
    let api = APIBuilder::new().build();
    let pc = Arc::new(
        api.new_peer_connection(RTCConfiguration::default())
            .await
            .unwrap(),
    );
    let dc = pc.create_data_channel(CHANNEL, None).await.unwrap();
    let (inbox_tx, inbox) = mpsc::channel(256);
    {
        let reasm = Arc::new(std::sync::Mutex::new(Reassembler::new(Bounds {
            max_message_bytes: 8 * 1024 * 1024,
            max_in_flight: 4,
        })));
        dc.on_message(Box::new(move |msg| {
            let inbox = inbox_tx.clone();
            let reasm = Arc::clone(&reasm);
            Box::pin(async move {
                let done = reasm
                    .lock()
                    .unwrap()
                    .push(&msg.data)
                    .expect("a valid frame");
                if let Some(m) = done {
                    let _ = inbox.send(serde_json::from_slice(&m).unwrap()).await;
                }
            })
        }));
    }
    // The browser's candidates wait until the offer has gone: the server
    // relays them in the order the browser sent them.
    let (cand_tx, mut cand_rx) = mpsc::channel::<Value>(64);
    pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
        let tx = cand_tx.clone();
        Box::pin(async move {
            if let Some(c) = c
                && let Ok(init) = c.to_json()
            {
                let _ = tx.send(serde_json::to_value(init).unwrap()).await;
            }
        })
    }));
    let offer = pc.create_offer(None).await.unwrap();
    pc.set_local_description(offer.clone()).await.unwrap();
    r.sup.viewers().command(
        gid,
        Cmd::Offer {
            sdp: offer.sdp,
            ice_servers: vec![],
        },
    );
    let sup = Arc::clone(&r.sup);
    tokio::spawn(async move {
        while let Some(c) = cand_rx.recv().await {
            sup.viewers().command(gid, Cmd::Ice(c));
        }
    });

    // The pump: the server's relay, for this grant.
    let (pass_tx, pass_rx) = mpsc::channel(256);
    let mut from_device = std::mem::replace(&mut r.reports, pass_rx);
    let browser_pc = Arc::clone(&pc);
    tokio::spawn(async move {
        while let Some(msg) = from_device.recv().await {
            match msg {
                ClientMsg::HiveViewAnswer { grant_id, sdp } if grant_id == gid => {
                    let answer = RTCSessionDescription::answer(sdp).unwrap();
                    browser_pc.set_remote_description(answer).await.unwrap();
                }
                ClientMsg::HiveViewIce {
                    grant_id,
                    candidate,
                } if grant_id == gid => {
                    let init: RTCIceCandidateInit = serde_json::from_value(candidate).unwrap();
                    let _ = browser_pc.add_ice_candidate(init).await;
                }
                other => {
                    let _ = pass_tx.send(other).await;
                }
            }
        }
    });

    let deadline = Instant::now() + WAIT;
    while dc.ready_state() != RTCDataChannelState::Open {
        assert!(Instant::now() < deadline, "the viewer channel never opened");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Browser {
        pc,
        dc,
        inbox,
        next_id: 0,
    }
}

#[tokio::test]
async fn a_viewer_pages_follows_and_prompts_over_the_peer() {
    let mut r = rig(true, 4);
    let sid = session_with_a_turn(&mut r).await;
    let g = grant(sid, r.user, true, 60);
    let gid = g.grant_id;
    r.sup.view_grant(g, true).await.unwrap();
    let mut b = dial(&mut r, gid).await;

    b.send(json!({"op": "hello"})).await;
    let hello = b.recv_op("hello").await;
    assert_eq!(hello["session"], sid.to_hex());
    assert_eq!(hello["may_prompt"], true);
    assert_eq!(hello["live"], true);
    assert_eq!(hello["state"], "idle");
    let tip = hello["tip"].as_u64().unwrap();
    assert!(tip >= 4, "the first turn is in the store: {hello}");

    // A page is bounded and says there is more.
    b.send(json!({"op": "page", "after": 0, "limit": 2})).await;
    let page = b.recv_op("page").await;
    let events = page["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["seq"], 1);
    assert_eq!(events[0]["event"]["kind"], "user_message");
    assert_eq!(page["more"], true);

    // Following from the tip, then prompting over the peer: the turn
    // streams back, attributed to this viewer.
    b.send(json!({"op": "follow", "after": tip})).await;
    b.send(json!({"op": "prompt", "id": "p1", "text": "second"}))
        .await;
    let ack = b.recv_op("prompt").await;
    assert_eq!(ack, json!({"op": "prompt", "id": "p1", "ok": true}));
    let live = b.events_until(|e| e["event"]["kind"] == "turn").await;
    assert_eq!(
        live[0]["seq"],
        tip + 1,
        "live picks up exactly after the tip"
    );
    assert_eq!(live[0]["event"]["kind"], "user_message");
    assert_eq!(live[0]["event"]["author"], "Viewer");
    assert_eq!(live[0]["event"]["text"], "second");
    let seqs: Vec<u64> = live.iter().map(|e| e["seq"].as_u64().unwrap()).collect();
    assert!(
        seqs.windows(2).all(|w| w[1] == w[0] + 1),
        "no gap, no repeat: {seqs:?}"
    );

    // The server closes it: the device closes the peer and says nothing
    // back, because the server already knows.
    r.sup
        .viewers()
        .command(gid, Cmd::Close("viewer_left".into()));
    wait_viewers(&r, 0).await;
    let deadline = Instant::now() + WAIT;
    while b.dc.ready_state() == RTCDataChannelState::Open {
        assert!(
            Instant::now() < deadline,
            "the device never closed the peer"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = b.pc.close().await;
    r.sup.stop(sid, 1, "owner".into());
}

/// A grant that may read is not one that may drive: the prompt is refused
/// on the device, and nothing reaches the harness.
#[tokio::test]
async fn a_read_only_viewer_cannot_prompt() {
    let mut r = rig(true, 4);
    let sid = session_with_a_turn(&mut r).await;
    let g = grant(sid, r.user, false, 60);
    let gid = g.grant_id;
    r.sup.view_grant(g, true).await.unwrap();
    let mut b = dial(&mut r, gid).await;

    b.send(json!({"op": "hello"})).await;
    let tip = b.recv_op("hello").await["tip"].as_u64().unwrap();
    b.send(json!({"op": "prompt", "id": "x", "text": "rm -rf"}))
        .await;
    let ack = b.recv_op("prompt").await;
    assert_eq!(ack["ok"], false);
    assert!(
        ack["error"].as_str().unwrap().starts_with("read_only"),
        "{ack}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        r.store.tip(&sid.to_hex()).await,
        Some(tip),
        "nothing reached the harness"
    );

    // The viewer closes its side: the device notices and tells the server.
    b.pc.close().await.unwrap();
    let (closed, reason) = next_closed(&mut r).await;
    assert_eq!(closed, gid);
    assert!(
        reason == "viewer_left" || reason == "peer_failed",
        "{reason}"
    );
    wait_viewers(&r, 0).await;
    r.sup.stop(sid, 1, "owner".into());
}

/// P1c-2 — a viewer the SERVER names a driver, whom this device's own
/// `hive_accounts` does not map to the session's account, reads but does not
/// drive here — told why in `hello`, and nothing it sends reaches the harness.
#[tokio::test]
async fn a_driver_this_device_does_not_map_reads_and_is_told_why() {
    let mut r = rig(true, 4);
    let sid = session_with_a_turn(&mut r).await;
    let g = ViewGrant {
        user_email: Some("dave@example.com".into()),
        ..grant(sid, ObjectId::new(), true, 60)
    };
    let gid = g.grant_id;
    r.sup.view_grant(g, true).await.unwrap();
    let mut b = dial(&mut r, gid).await;

    b.send(json!({"op": "hello"})).await;
    let hello = b.recv_op("hello").await;
    assert_eq!(hello["may_prompt"], false, "{hello}");
    assert_eq!(hello["may_answer"], false, "{hello}");
    assert!(
        hello["driving_refused"]
            .as_str()
            .is_some_and(|w| w.contains("hive_accounts")),
        "{hello}"
    );
    let tip = hello["tip"].as_u64().unwrap();
    b.send(json!({"op": "prompt", "id": "x", "text": "rm -rf"}))
        .await;
    let ack = b.recv_op("prompt").await;
    assert_eq!(ack["ok"], false, "{ack}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        r.store.tip(&sid.to_hex()).await,
        Some(tip),
        "nothing reached the harness"
    );

    // The starter's own grant is the server's word, untouched.
    let own = grant(sid, r.user, true, 60);
    let oid = own.grant_id;
    r.sup.view_grant(own, true).await.unwrap();
    let mut o = dial(&mut r, oid).await;
    o.send(json!({"op": "hello"})).await;
    let hello = o.recv_op("hello").await;
    assert_eq!(hello["may_prompt"], true, "{hello}");
    assert!(hello["driving_refused"].is_null(), "{hello}");

    for g in [gid, oid] {
        r.sup.viewers().command(g, Cmd::Close("test".into()));
    }
    wait_viewers(&r, 0).await;
    let _ = b.pc.close().await;
    let _ = o.pc.close().await;
    r.sup.stop(sid, 1, "owner".into());
}

/// P2d-5 — a member serves a viewer from the copy it holds of a session run
/// elsewhere on `hive_replica` alone, with agent sessions themselves off: read
/// only whoever the server named, its hello saying it is a copy, and a prompt
/// refused. An owner who no longer holds copies serves none of those still on
/// disk, `hive_enabled` or not.
#[tokio::test]
async fn a_member_serves_its_copy_read_only_on_hive_replica_alone() {
    let mut r = rig_with(false, 4, |c| c.replica = true, |s| s);
    let sid = ObjectId::new();
    r.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
    r.store.append(
        &sid.to_hex(),
        1,
        meshharbor_hive_node::TranscriptEvent::Note {
            text: "held".into(),
        },
    );
    // The starter's grant, as a server that names them a driver mints it.
    let g = grant(sid, r.user, true, 60);
    let gid = g.grant_id;
    r.sup
        .view_grant(g, true)
        .await
        .expect("a copy is served on hive_replica alone");
    let mut b = dial(&mut r, gid).await;
    b.send(json!({"op": "hello"})).await;
    let hello = b.recv_op("hello").await;
    assert_eq!(
        (
            hello["copy"].as_bool(),
            hello["may_prompt"].as_bool(),
            hello["may_answer"].as_bool(),
            hello["live"].as_bool(),
        ),
        (Some(true), Some(false), Some(false), Some(false)),
        "a copy, read only: {hello}"
    );
    assert!(hello["driving_refused"].is_null(), "{hello}");
    let tip = hello["tip"].as_u64().unwrap();
    assert!(tip >= 1, "the copy's own tip: {hello}");
    b.send(json!({"op": "prompt", "id": "x", "text": "rm -rf"}))
        .await;
    let ack = b.recv_op("prompt").await;
    assert_eq!(ack["ok"], false, "{ack}");
    assert!(
        ack["error"].as_str().unwrap().starts_with("read_only"),
        "{ack}"
    );
    r.sup.viewers().command(gid, Cmd::Close("test".into()));
    wait_viewers(&r, 0).await;
    let _ = b.pc.close().await;

    for enabled in [false, true] {
        let off = rig_with(enabled, 4, |c| c.replica = false, |s| s);
        off.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
        off.store.append(
            &sid.to_hex(),
            1,
            meshharbor_hive_node::TranscriptEvent::Note {
                text: "held".into(),
            },
        );
        let refused = off
            .sup
            .view_grant(grant(sid, off.user, false, 60), true)
            .await
            .expect_err("no copies held: no copy served");
        assert_eq!(
            refused.0,
            HiveViewRefusal::HiveDisabled,
            "no copies held, hive_enabled {enabled}: {}",
            refused.1
        );
        assert!(refused.1.contains("hive_replica"), "{}", refused.1);
    }
}

/// Frames a viewer sends are bounded: a message larger than a prompt may be
/// is refused at its first frame, and garbage is not a request.
#[tokio::test]
async fn a_viewer_cannot_send_unbounded_or_garbage_messages() {
    let mut r = rig(true, 4);
    let sid = session_with_a_turn(&mut r).await;
    let g = grant(sid, r.user, true, 60);
    let gid = g.grant_id;
    r.sup.view_grant(g, true).await.unwrap();
    let mut b = dial(&mut r, gid).await;

    let huge = vec![b'a'; INBOUND.max_message_bytes + framing::MAX_PAYLOAD];
    for frame in framing::encode(99, &huge) {
        b.dc.send(&Bytes::from(frame)).await.unwrap();
    }
    b.dc.send(&Bytes::from_static(b"not a frame"))
        .await
        .unwrap();
    b.send(json!("not an object")).await;
    let err = b.recv_op("error").await;
    assert!(err["error"].as_str().is_some(), "{err}");
    // Still serving after all of it.
    b.send(json!({"op": "hello"})).await;
    assert_eq!(b.recv_op("hello").await["session"], sid.to_hex());

    r.sup.viewers().command(gid, Cmd::Close("test".into()));
    wait_viewers(&r, 0).await;
    let _ = b.pc.close().await;
    r.sup.stop(sid, 1, "owner".into());
}

/// An approval over the peer (P1a): every viewer sees which are open; a
/// reader cannot answer one; a driver can, and the harness gets the answer
/// with the driver's words; then every viewer hears it is closed.
#[tokio::test]
async fn a_driver_answers_an_approval_over_the_peer_and_a_reader_cannot() {
    let mut r = rig(true, 4);
    let sid = session_with_a_turn(&mut r).await;
    r.sup.prompt(sid, dev(&r), "hold".into()).unwrap();
    let mut harness = harness_asks(&r, sid, 2, "whoami").await;
    let approval = until_awaiting(&mut r, sid).await;

    let reader = grant(sid, ObjectId::new(), false, 60);
    let rid = reader.grant_id;
    r.sup.view_grant(reader, true).await.unwrap();
    let mut reader = dial(&mut r, rid).await;
    reader.send(json!({"op": "hello"})).await;
    let hello = reader.recv_op("hello").await;
    assert_eq!(hello["approvals"], json!([approval]), "{hello}");
    assert_eq!(hello["may_answer"], false);
    assert_eq!(hello["state"], "awaiting_approval");
    reader
        .send(json!({"op": "answer", "id": "r1", "approval": approval, "decision": "allow"}))
        .await;
    let ack = reader.recv_op("answer").await;
    assert_eq!(ack["ok"], false);
    assert!(
        ack["error"].as_str().unwrap().starts_with("read_only"),
        "{ack}"
    );
    assert_eq!(
        r.sup.pending_approvals(sid),
        std::slice::from_ref(&approval),
        "a reader's answer changed nothing"
    );

    let driver = grant(sid, r.user, true, 60);
    let did = driver.grant_id;
    r.sup.view_grant(driver, true).await.unwrap();
    let mut driver = dial(&mut r, did).await;
    driver.send(json!({"op": "hello"})).await;
    assert_eq!(driver.recv_op("hello").await["may_answer"], true);
    driver
        .send(json!({"op": "answer", "id": "d0", "approval": approval, "decision": "maybe"}))
        .await;
    assert_eq!(driver.recv_op("answer").await["ok"], false);
    driver
        .send(
            json!({"op": "answer", "id": "d1", "approval": approval, "decision": "deny",
            "message": "  not on this box  "}),
        )
        .await;
    assert_eq!(
        driver.recv_op("answer").await,
        json!({"op": "answer", "id": "d1", "ok": true})
    );
    assert_eq!(
        harness.verdict(2).await,
        json!({"behavior": "deny", "message": "Viewer denied this: not on this box"})
    );
    assert_eq!(driver.recv_op("approvals").await["pending"], json!([]));
    assert_eq!(reader.recv_op("approvals").await["pending"], json!([]));
    driver
        .send(json!({"op": "answer", "id": "d2", "approval": approval, "decision": "allow"}))
        .await;
    let again = driver.recv_op("answer").await;
    assert_eq!(again["ok"], false, "answered once: {again}");

    release(&r);
    for gid in [rid, did] {
        r.sup.viewers().command(gid, Cmd::Close("test".into()));
    }
    wait_viewers(&r, 0).await;
    let _ = reader.pc.close().await;
    let _ = driver.pc.close().await;
    r.sup.stop(sid, 1, "owner".into());
}

// ─── FR-90 P2i-1 — a search grant ───────────────────────────────────────────

// The gate test views a copy past as many searches as a session has viewers.
const _: () = assert!(search_limits::MAX_PER_DEVICE >= view_limits::MAX_PER_SESSION);

fn search_grant(sessions: Vec<ObjectId>) -> SearchGrant {
    SearchGrant {
        grant_id: ObjectId::new(),
        user_id: ObjectId::new(),
        sessions,
        ttl_secs: 60,
    }
}

/// A device with agent sessions themselves off and its owner's
/// `hive_archive` and `hive_replica` as given: with both, an archive replica.
fn archive(archive: bool, replica: bool) -> Rig {
    rig_with(
        false,
        4,
        |c| {
            c.archive = archive;
            c.replica = replica;
        },
        |s| s,
    )
}

fn note(text: &str) -> meshharbor_hive_node::TranscriptEvent {
    meshharbor_hive_node::TranscriptEvent::Note { text: text.into() }
}

/// A copy of `sid` that the rig's device holds as a member, `notes` in it.
async fn copy_of(r: &Rig, sid: ObjectId, notes: &[&str]) {
    r.store.join(&sid.to_hex(), "owner", 1).await.unwrap();
    for text in notes {
        r.store.append(&sid.to_hex(), 1, note(text));
    }
}

/// What the device logs, as text.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Logs {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(|e| e.into_inner())).into_owned()
    }

    /// Everything this thread logs while what it returns lives. A
    /// `#[tokio::test]` runs on a current-thread runtime, so that is every
    /// task the test spawns.
    ///
    /// ⚠️ Two dispatchers, never one. With a single one registered, tracing
    /// takes a callsite's interest from the default of whichever thread
    /// reaches it first and caches it for every thread: a parallel test's,
    /// with no subscriber, makes it `never`, and this capture would never see
    /// that line (measured: the search tests reach the actor's lines in
    /// parallel). A second registered dispatcher makes every callsite ask the
    /// thread's own each time.
    fn capture(&self) -> (tracing::Dispatch, tracing::dispatcher::DefaultGuard) {
        let second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        let logs = self.clone();
        let guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .with_writer(move || logs.clone())
                .finish(),
        );
        (second, guard)
    }
}

/// The device's refusal of `g`, or a panic that it served what it must not.
async fn refused(
    r: &Rig,
    g: SearchGrant,
    is_primary: bool,
    what: &str,
) -> (HiveViewRefusal, String) {
    match r.sup.search_grant(g, is_primary).await {
        Err(e) => e,
        Ok(()) => panic!("served a search it must refuse: {what}"),
    }
}

/// P2i-1 — a search grant passes the device's own gates or names the one
/// that said no: served only by an archive replica (its owner's
/// `hive_archive` and `hive_replica`, whatever the server asks), only to the
/// primary organization, and only over the copies it holds of the sessions
/// the grant names; idempotent on the grant id and bounded per device — and
/// a search is no session's viewer.
#[tokio::test]
async fn a_search_grant_passes_the_devices_gates_or_names_the_one_that_said_no() {
    let sid = ObjectId::new();
    // `hive_archive` without `hive_replica` is a config the device never
    // resolves (`gates`); refused here all the same.
    for (archive_on, replica_on) in [(false, true), (true, false), (false, false)] {
        let r = archive(archive_on, replica_on);
        copy_of(&r, sid, &["held"]).await;
        let what = format!("hive_archive {archive_on}, hive_replica {replica_on}");
        let (why, detail) = refused(&r, search_grant(vec![sid]), true, &what).await;
        assert_eq!(why, HiveViewRefusal::HiveDisabled, "{what}: {detail}");
        assert!(detail.contains("hive_archive"), "{detail}");
    }

    let r = archive(true, true);
    copy_of(&r, sid, &["held"]).await;
    // In the store, but as a session this device ran: not a member's copy.
    let own = ObjectId::new();
    r.store.append(&own.to_hex(), 1, note("its own"));
    let (why, detail) = refused(
        &r,
        search_grant(vec![sid]),
        false,
        "a secondary organization",
    )
    .await;
    assert_eq!(why, HiveViewRefusal::HiveDisabled, "{detail}");
    for (what, named) in [
        ("none of them held", vec![ObjectId::new()]),
        ("none named", vec![]),
        ("one this device ran, not a copy", vec![own]),
    ] {
        let (why, detail) = refused(&r, search_grant(named), true, what).await;
        assert_eq!(why, HiveViewRefusal::NoSession, "{what}: {detail}");
    }
    // As many sessions as the store takes as a filter, and not one more.
    let named = |n: usize| -> Vec<ObjectId> {
        std::iter::once(sid)
            .chain((1..n).map(|_| ObjectId::new()))
            .collect()
    };
    let (why, detail) = refused(
        &r,
        search_grant(named(search_limits::MAX_SESSIONS + 1)),
        true,
        "one session past the store's filter",
    )
    .await;
    assert_eq!(why, HiveViewRefusal::Other, "{detail}");
    let most = search_grant(named(search_limits::MAX_SESSIONS));
    let most_id = most.grant_id;
    r.sup
        .search_grant(most, true)
        .await
        .expect("as many sessions as the store takes");
    r.sup.viewers().command(most_id, Cmd::Close("test".into()));
    wait_viewers(&r, 0).await;

    // Idempotent on the grant id; bounded per device.
    let first = search_grant(vec![sid]);
    r.sup.search_grant(first.clone(), true).await.unwrap();
    r.sup.search_grant(first.clone(), true).await.unwrap();
    assert_eq!(
        r.sup.viewers().count(),
        1,
        "a re-sent grant is not a second search"
    );
    let mut held = vec![first.grant_id];
    for _ in 1..search_limits::MAX_PER_DEVICE {
        let g = search_grant(vec![sid]);
        held.push(g.grant_id);
        r.sup.search_grant(g, true).await.unwrap();
    }
    let (why, detail) = refused(
        &r,
        search_grant(vec![sid]),
        true,
        "one past the device's searches",
    )
    .await;
    assert_eq!(why, HiveViewRefusal::AtCapacity, "{detail}");
    assert!(detail.contains("searches"), "{detail}");
    // No session's viewer: the copy they all search is viewed still, past as
    // many searches as a session has viewers.
    let view = grant(sid, r.user, false, 60);
    held.push(view.grant_id);
    r.sup
        .view_grant(view, true)
        .await
        .expect("a search counts toward no session's viewers");
    for g in held {
        r.sup.viewers().command(g, Cmd::Close("test".into()));
    }
    wait_viewers(&r, 0).await;
}

/// P2i-1 — a search over the peer finds what its grant names and this
/// device holds a copy of, and nothing else: a copy the grant does not name
/// is never searched, and a session it names that this device holds no copy
/// of is left out, the hello saying how many are searched. A hit names its
/// session and its event, the words marked.
#[tokio::test]
async fn a_search_finds_only_the_copies_its_grant_names() {
    let mut r = archive(true, true);
    let [s1, s2, unnamed, own]: [ObjectId; 4] = std::array::from_fn(|_| ObjectId::new());
    copy_of(&r, s1, &["the kubelet restarted at noon"]).await;
    copy_of(&r, s2, &["nothing to see", "the kubelet again"]).await;
    copy_of(
        &r,
        unnamed,
        &["a kubelet in a copy the grant does not name"],
    )
    .await;
    r.store.append(
        &own.to_hex(),
        1,
        note("a kubelet in a session this device ran"),
    );
    let g = search_grant(vec![s1, own, s2, s1]);
    let gid = g.grant_id;
    r.sup.search_grant(g, true).await.unwrap();
    let mut b = dial(&mut r, gid).await;

    b.send(json!({"op": "hello"})).await;
    assert_eq!(
        b.recv().await,
        json!({"op": "hello", "v": 1, "search": true, "sessions": 2}),
        "the hello counts the copies searched"
    );
    b.send(json!({"op": "search", "id": "q1", "q": "kubelet"}))
        .await;
    let found = b.recv().await;
    assert_eq!(
        (
            found["op"].as_str(),
            found["id"].as_str(),
            found["ok"].as_bool()
        ),
        (Some("search"), Some("q1"), Some(true)),
        "{found}"
    );
    let mut hits: Vec<(String, u64)> = found["hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            assert!(h["snippet"].as_str().unwrap().contains("[kubelet]"), "{h}");
            (
                h["session"].as_str().unwrap().to_string(),
                h["seq"].as_u64().unwrap(),
            )
        })
        .collect();
    hits.sort();
    let mut want = vec![(s1.to_hex(), 1), (s2.to_hex(), 2)];
    want.sort();
    assert_eq!(hits, want, "found only the copies the grant names: {found}");

    r.sup.viewers().command(gid, Cmd::Close("test".into()));
    wait_viewers(&r, 0).await;
    let _ = b.pc.close().await;
}

/// P2i-1 — a search grant does nothing a view does: no page, no feed, no
/// prompt, no answer — each refused, nothing else said, and a search still
/// answered.
#[tokio::test]
async fn a_search_grant_does_nothing_a_view_does() {
    let mut r = archive(true, true);
    let sid = ObjectId::new();
    copy_of(&r, sid, &["the kubelet restarted"]).await;
    let g = search_grant(vec![sid]);
    let gid = g.grant_id;
    r.sup.search_grant(g, true).await.unwrap();
    let mut b = dial(&mut r, gid).await;

    for (op, req) in [
        ("page", json!({"op": "page", "after": 0})),
        ("follow", json!({"op": "follow", "after": 0})),
        (
            "prompt",
            json!({"op": "prompt", "id": "p", "text": "rm -rf"}),
        ),
        (
            "answer",
            json!({"op": "answer", "id": "a", "approval": "x", "decision": "allow"}),
        ),
    ] {
        b.send(req).await;
        let refused = b.recv().await;
        assert_eq!(
            refused["op"], "error",
            "a search grant does no {op}: {refused}"
        );
        assert!(refused["error"].as_str().unwrap().contains(op), "{refused}");
    }
    b.send(json!({"op": "search", "id": "q", "q": "kubelet"}))
        .await;
    let found = b.recv().await;
    assert_eq!(
        (found["op"].as_str(), found["ok"].as_bool()),
        (Some("search"), Some(true)),
        "nothing came between: {found}"
    );

    r.sup.viewers().command(gid, Cmd::Close("test".into()));
    wait_viewers(&r, 0).await;
    let _ = b.pc.close().await;
}

/// P2i-1 — what a search may ask is bounded on the device: one sooner than
/// [`search_limits::MIN_INTERVAL_MS`] after the last is refused; an empty
/// one, or one longer than [`search_limits::MAX_QUERY_CHARS`] characters —
/// characters, not bytes — is refused without counting as a search; it
/// answers at most [`search_limits::MAX_HITS`] hits, and
/// [`search_limits::DEFAULT_HITS`] when it does not say. And neither the
/// query nor what it finds reaches the device's log, which may reach the
/// server.
#[tokio::test]
async fn a_search_is_bounded_and_never_logged() {
    let logs = Logs::default();
    let _capture = logs.capture();
    let mut r = archive(true, true);
    let sid = ObjectId::new();
    let notes: Vec<String> = (0..60).map(|i| format!("quokkafleet event {i}")).collect();
    let notes: Vec<&str> = notes.iter().map(String::as_str).collect();
    copy_of(&r, sid, &notes).await;
    let g = search_grant(vec![sid]);
    let gid = g.grant_id;
    r.sup.search_grant(g, true).await.unwrap();
    let mut b = dial(&mut r, gid).await;
    let hits = |v: &Value| v["hits"].as_array().map(Vec::len);
    let pause = || tokio::time::sleep(Duration::from_millis(search_limits::MIN_INTERVAL_MS + 50));

    // Two at once: the second is too soon.
    b.send(json!({"op": "search", "id": "a", "q": "quokkafleet", "limit": 10_000}))
        .await;
    b.send(json!({"op": "search", "id": "b", "q": "quokkafleet"}))
        .await;
    let a = b.recv().await;
    assert_eq!(
        (a["id"].as_str(), a["ok"].as_bool(), hits(&a)),
        (Some("a"), Some(true), Some(search_limits::MAX_HITS)),
        "a search answers at most MAX_HITS hits: {a}"
    );
    let soon = b.recv().await;
    assert!(
        soon["id"] == "b"
            && soon["ok"] == false
            && soon["error"]
                .as_str()
                .is_some_and(|e| e.starts_with("too_soon")),
        "the second search, sent at once, is too soon: {soon}"
    );

    pause().await;
    b.send(json!({"op": "search", "id": "c", "q": "quokkafleet"}))
        .await;
    assert_eq!(
        hits(&b.recv().await),
        Some(search_limits::DEFAULT_HITS),
        "a search that does not say answers DEFAULT_HITS"
    );
    pause().await;
    b.send(json!({"op": "search", "id": "d", "q": "quokkafleet", "limit": 0}))
        .await;
    assert_eq!(hits(&b.recv().await), Some(1), "a limit of 0 answers one");

    // Refused before the rate is asked, so neither counts as a search: an
    // empty one, and one a character too long. Then the longest, in
    // characters — twice as many bytes — is the first search since the pause.
    pause().await;
    let longest = "é".repeat(search_limits::MAX_QUERY_CHARS);
    b.send(json!({"op": "search", "id": "e", "q": "   "})).await;
    b.send(json!({"op": "search", "id": "f",
        "q": "q".repeat(search_limits::MAX_QUERY_CHARS + 1)}))
        .await;
    b.send(json!({"op": "search", "id": "g", "q": longest}))
        .await;
    let e = b.recv().await;
    assert_eq!(
        (e["id"].as_str(), e["ok"].as_bool(), e["error"].as_str()),
        (Some("e"), Some(false), Some("an empty search")),
        "an empty search is refused: {e}"
    );
    let f = b.recv().await;
    assert!(
        f["id"] == "f"
            && f["ok"] == false
            && f["error"].as_str().is_some_and(|e| e.contains("at most")),
        "one a character too long is refused: {f}"
    );
    let g = b.recv().await;
    assert!(
        !g["error"]
            .as_str()
            .is_some_and(|e| e.starts_with("too_soon")),
        "a refused search counted as one: {g}"
    );
    assert_eq!(
        (g["id"].as_str(), g["ok"].as_bool(), hits(&g)),
        (Some("g"), Some(true), Some(0)),
        "the longest query, in characters, is asked: {g}"
    );

    r.sup.viewers().command(gid, Cmd::Close("test".into()));
    // The capture sees the actor's own task, or its silence proves nothing.
    let deadline = Instant::now() + WAIT;
    while !logs.text().contains("hive: view closed by the server") {
        assert!(
            Instant::now() < deadline,
            "the actor's end never reached the capture:\n{}",
            logs.text()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = b.pc.close().await;
    let logged = logs.text();
    assert!(
        logged.contains("hive: search granted"),
        "the grant never reached the capture:\n{logged}"
    );
    assert!(
        !logged.contains("quokkafleet"),
        "a query or a hit reached the log:\n{logged}"
    );
}
