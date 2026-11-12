// SPDX-License-Identifier: AGPL-3.0-only
//! Path quality, end to end over real agent WebSockets: two enrolled agents
//! join the overlay, report windows of their direct and relay paths
//! (`rc:overlay.path_quality`), and the server's prefer-relay verdict must
//! reach BOTH of them on the other's netmap row (`prefer_relay_ms`), be
//! carried by every later row while it stands, and be withdrawn out loud.
//!
//! Field, 2026-11-11 (lab): a pair stayed on a direct path at 960 ms
//! while its relay measured about 620 ms, because nothing compared the two.
//!
//! What these lock is the wiring: the report's dispatch, the both-members
//! rule, the stamp on every row-building path, the withdrawal, and the mode
//! switch. The judgement itself (`path_quality::note`) and the member's
//! measurement are unit-tested where they live.

use crate::agent_presence_tests::enroll;
use crate::fixtures::test_app::TestApp;
use crate::peer_relay_mint_tests::{Ws, connect_from, node_id, recv_t};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bson::oid::ObjectId;
use futures::{SinkExt, StreamExt};
use meshharbor_mod_network::path_quality::Mode;
use serde_json::{Value, json};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

struct Rig {
    app: TestApp,
    a: Ws,
    b: Ws,
    a_node: ObjectId,
    b_node: ObjectId,
    /// What each join's netmap said about `path_quality_v1`.
    asked: [bool; 2],
}

/// Join as a DERP-capable node; returns the netmap that answers.
async fn join(ws: &mut Ws, seed: u8, endpoint: &str) -> Value {
    let msg = json!({
        "t": "rc:overlay.join",
        "wg_public_key": BASE64.encode([seed; 32]),
        "mtu": 1280,
        "endpoints": [endpoint],
        "supports_derp": true,
    });
    ws.send(Message::Text(msg.to_string().into()))
        .await
        .expect("send join");
    recv_t(ws, "rc:overlay.netmap", Duration::from_secs(5))
        .await
        .expect("a netmap answers the join")
}

impl Rig {
    async fn up(slug: &str, mode: Mode) -> Self {
        let app = TestApp::spawn().await;
        app.state.network().path_quality.set_mode(mode);
        let seeded = app.seed_tenant(slug).await;
        let (_, a_tok) = enroll(&app, &seeded, &format!("{slug}-a")).await;
        let (_, b_tok) = enroll(&app, &seeded, &format!("{slug}-b")).await;
        let mut a = connect_from(&app, &a_tok, &[], None).await;
        let mut b = connect_from(&app, &b_tok, &[], None).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let na = join(&mut a, 1, "203.0.113.10:41641").await;
        let nb = join(&mut b, 2, "203.0.113.11:41641").await;
        let asked = [&na, &nb].map(|n| n["network"]["path_quality_v1"] == json!(true));
        let oid = |hex: String| ObjectId::parse_str(&hex).unwrap();
        let a_node = oid(node_id(&app, &seeded, &format!("{slug}-a")).await);
        let b_node = oid(node_id(&app, &seeded, &format!("{slug}-b")).await);
        let mut rig = Self {
            app,
            a,
            b,
            a_node,
            b_node,
            asked,
        };
        // The joins' own deltas are not what a test waits for.
        rig.drain().await;
        rig
    }

    async fn drain(&mut self) {
        for ws in [&mut self.a, &mut self.b] {
            while let Ok(Some(Ok(_))) =
                tokio::time::timeout(Duration::from_millis(200), ws.next()).await
            {}
        }
    }

    fn standing(&self) -> bool {
        self.app
            .state
            .network()
            .path_quality
            .is_standing(self.a_node, self.b_node)
    }
}

/// One member's window: `direct` and `relay` as `(lost of 11, median ms)`.
async fn report(
    ws: &mut Ws,
    peer: ObjectId,
    direct: (u32, Option<u32>),
    relay: (u32, Option<u32>),
    on_relay: bool,
) {
    let mut msg = json!({
        "t": "rc:overlay.path_quality",
        "peer_node_id": peer.to_hex(),
        "window_ms": 10_000,
        "direct_sent": 11,
        "direct_lost": direct.0,
        "relay_sent": 11,
        "relay_lost": relay.0,
        "on_relay": on_relay,
    });
    if let Some(ms) = direct.1 {
        msg["direct_rtt_ms"] = json!(ms);
    }
    if let Some(ms) = relay.1 {
        msg["relay_rtt_ms"] = json!(ms);
    }
    ws.send(Message::Text(msg.to_string().into()))
        .await
        .expect("send report");
}

/// The `prefer_relay_ms` of `peer`'s row in the next netmap delta that
/// upserts it: `Some(None)` = a row came and said nothing, `None` = no row.
async fn next_row(ws: &mut Ws, peer: ObjectId, wait: Duration) -> Option<Option<u64>> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let delta = recv_t(ws, "rc:overlay.netmap_delta", left).await?;
        let row = delta["upserts"]
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["node_id"] == json!(peer.to_hex())));
        if let Some(row) = row {
            return Some(row.get("prefer_relay_ms").and_then(Value::as_u64));
        }
    }
}

/// The next row of `peer` that states a verdict, skipping rows that say
/// nothing.
async fn next_verdict(ws: &mut Ws, peer: ObjectId, wait: Duration) -> Option<u64> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if let Some(ms) = next_row(ws, peer, left).await? {
            return Some(ms);
        }
    }
}

const SLOW: (u32, Option<u32>) = (0, Some(960));
const FAST: (u32, Option<u32>) = (0, Some(1));
const RELAY: (u32, Option<u32>) = (0, Some(620));

/// Both members measure the direct path at 960 ms against a 620 ms relay:
/// each receives the other's row with the verdict's lifetime. One member's
/// reports alone move nothing, however many it sends.
#[tokio::test]
async fn both_members_reports_stamp_a_prefer_relay_verdict_on_both_rows() {
    let mut rig = Rig::up("pq-enter", Mode::On).await;
    assert_eq!(
        rig.asked,
        [true, true],
        "the netmap asks both for the report"
    );
    for _ in 0..2 {
        report(&mut rig.a, rig.b_node, SLOW, RELAY, false).await;
        assert_eq!(
            next_verdict(&mut rig.a, rig.b_node, Duration::from_millis(1100)).await,
            None,
            "one member's word is not a verdict"
        );
    }
    assert!(!rig.standing());

    report(&mut rig.b, rig.a_node, SLOW, RELAY, false).await;
    let at_b = next_verdict(&mut rig.b, rig.a_node, Duration::from_secs(5))
        .await
        .expect("the reporter gets its peer's row stamped");
    let at_a = next_verdict(&mut rig.a, rig.b_node, Duration::from_secs(5))
        .await
        .expect("and so does the other end");
    for ms in [at_a, at_b] {
        assert!(
            (50_000..=60_000).contains(&ms),
            "a remaining lifetime of about the verdict's 60 s, got {ms}"
        );
    }
    assert!(rig.standing());
}

/// While the verdict stands, a row built for any other reason carries its
/// remaining lifetime too: here `a` trickles new endpoints, and the row `b`
/// gets for it re-anchors `b`'s hold instead of saying nothing.
#[tokio::test]
async fn a_row_fanned_for_another_reason_carries_the_standing_verdict() {
    let mut rig = Rig::up("pq-refan", Mode::On).await;
    report(&mut rig.a, rig.b_node, SLOW, RELAY, false).await;
    report(&mut rig.b, rig.a_node, SLOW, RELAY, false).await;
    next_verdict(&mut rig.b, rig.a_node, Duration::from_secs(5))
        .await
        .expect("verdict");
    rig.drain().await;

    let trickle = json!({"t": "rc:overlay.endpoints", "candidates": ["203.0.113.10:41642"]});
    rig.a
        .send(Message::Text(trickle.to_string().into()))
        .await
        .unwrap();
    let ms = next_row(&mut rig.b, rig.a_node, Duration::from_secs(5))
        .await
        .expect("the endpoint change is fanned")
        .expect("and its row carries the standing verdict");
    assert!((1..=60_000).contains(&ms), "{ms}");
}

/// Once both members measure the direct path healthy for long enough, the
/// verdict is withdrawn with an explicit zero on both rows: an absent field
/// would leave each member holding until its own lifetime ran out.
#[tokio::test]
async fn a_healed_direct_path_withdraws_the_verdict_on_both_rows() {
    let mut rig = Rig::up("pq-exit", Mode::On).await;
    report(&mut rig.a, rig.b_node, SLOW, RELAY, false).await;
    report(&mut rig.b, rig.a_node, SLOW, RELAY, false).await;
    next_verdict(&mut rig.a, rig.b_node, Duration::from_secs(5))
        .await
        .expect("verdict");
    rig.drain().await;
    // A member's reports closer than a second apart are dropped.
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Healthy at once is not enough: the verdict holds for its minimum, and
    // a healthy stretch must last.
    report(&mut rig.a, rig.b_node, FAST, RELAY, true).await;
    report(&mut rig.b, rig.a_node, FAST, RELAY, true).await;
    assert_eq!(
        next_verdict(&mut rig.a, rig.b_node, Duration::from_millis(700)).await,
        None
    );
    assert!(rig.standing());

    // Half a minute later both still measure it healthy.
    let pq = &rig.app.state.network().path_quality;
    pq.age_verdict(rig.a_node, rig.b_node, Duration::from_secs(30));
    report(&mut rig.b, rig.a_node, FAST, RELAY, true).await;
    report(&mut rig.a, rig.b_node, FAST, RELAY, true).await;
    for (ws, peer) in [(&mut rig.a, rig.b_node), (&mut rig.b, rig.a_node)] {
        assert_eq!(
            next_verdict(ws, peer, Duration::from_secs(5)).await,
            Some(0),
            "withdrawn out loud, on both ends"
        );
    }
    assert!(!rig.standing());
}

/// The server's kill switch. With the mode off the netmap does not ask for
/// the report, a report that comes anyway is not judged, and no row is ever
/// stamped: the pair behaves as it did before the feature.
#[tokio::test]
async fn with_the_mode_off_nothing_is_asked_judged_or_stamped() {
    let mut rig = Rig::up("pq-off", Mode::Off).await;
    assert_eq!(rig.asked, [false, false], "no report is asked for");
    report(&mut rig.a, rig.b_node, SLOW, RELAY, false).await;
    report(&mut rig.b, rig.a_node, SLOW, RELAY, false).await;
    assert_eq!(
        next_verdict(&mut rig.b, rig.a_node, Duration::from_millis(800)).await,
        None
    );
    assert!(!rig.standing(), "nothing was judged");
}

/// Shadow mode asks for the reports and judges them, so the would-be
/// verdicts can be read off the log, but stamps nothing: not at the moment
/// of the verdict, and not on a later row.
#[tokio::test]
async fn shadow_mode_judges_without_stamping() {
    let mut rig = Rig::up("pq-shadow", Mode::Shadow).await;
    assert_eq!(rig.asked, [true, true]);
    report(&mut rig.a, rig.b_node, SLOW, RELAY, false).await;
    report(&mut rig.b, rig.a_node, SLOW, RELAY, false).await;
    assert_eq!(
        next_verdict(&mut rig.b, rig.a_node, Duration::from_millis(800)).await,
        None
    );
    assert!(rig.standing(), "the verdict was reached");
    let trickle = json!({"t": "rc:overlay.endpoints", "candidates": ["203.0.113.10:41642"]});
    rig.a
        .send(Message::Text(trickle.to_string().into()))
        .await
        .unwrap();
    assert_eq!(
        next_row(&mut rig.b, rig.a_node, Duration::from_secs(5)).await,
        Some(None),
        "a later row says nothing either"
    );
}
