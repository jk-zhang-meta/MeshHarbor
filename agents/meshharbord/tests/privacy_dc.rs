// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-99 P1b — the `privacy` DataChannel, end to end.
//!
//! Two `webrtc-rs` PeerConnections in loopback; the device side runs the
//! PRODUCTION handlers (`meshharbord::privacy::attach` / `attach_refusing`, as
//! `peer.rs` routes them), and the curtain is a recorder standing in for the
//! overlay. What is checked is what a controller sees on the channel and what
//! the overlay was asked to draw — a refused "on" must never reach it. Since
//! P1d each cell also reads what the device reported to the server
//! (`rc:privacy.activity`): every curtain, every take-down with its reason,
//! every refusal.
//!
//! The owner's gate is process-wide, so the tests run one at a time.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bson::oid::ObjectId;
use meshharbor_remote_control::signaling::ClientMsg;
use meshharbord::host_mute::{HostMute, Speakers};
use meshharbord::privacy::{self, CurtainHost, PrivacyCtx};
use serde_json::{Value, json};
use tokio::sync::{Mutex, mpsc, oneshot};
use webrtc::api::APIBuilder;
use webrtc::api::media_engine::MediaEngine;
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::ice_transport::ice_candidate::RTCIceCandidate;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;

/// One owner gate per process: one test at a time.
static SERIAL: Mutex<()> = Mutex::const_new(());

/// The overlay's stand-in: records every call, answers an "up" with `up_ok`.
struct Overlay {
    calls: StdMutex<Vec<bool>>,
    up_ok: bool,
}

impl CurtainHost for Overlay {
    fn set_curtain(&self, _session: ObjectId, on: bool, _controller: &str) -> bool {
        self.calls.lock().unwrap().push(on);
        on && self.up_ok
    }
}

impl Overlay {
    fn calls(&self) -> Vec<bool> {
        self.calls.lock().unwrap().clone()
    }
}

/// P4 — the host's speakers as a flag (`None` = no endpoint), so no cell ever
/// touches the real speakers of the machine it runs on.
struct Endpoint(StdMutex<Option<bool>>);

impl Speakers for Endpoint {
    fn muted(&self) -> Option<bool> {
        *self.0.lock().unwrap()
    }
    fn set_muted(&self, mute: bool) -> bool {
        let mut m = self.0.lock().unwrap();
        if m.is_some() {
            *m = Some(mute);
        }
        true
    }
}

struct Rig {
    dc: Arc<RTCDataChannel>,
    strings: mpsc::UnboundedReceiver<String>,
    overlay: Arc<Overlay>,
    pcs: (Arc<RTCPeerConnection>, Arc<RTCPeerConnection>),
    /// P1d — what the device reported to the server, in order.
    reports: Option<mpsc::Receiver<ClientMsg>>,
    /// P4 — the host's speakers, as the device left them.
    endpoint: Arc<Endpoint>,
    /// The ledger's directory, alive as long as the rig.
    _dir: tempfile::TempDir,
}

/// (kind, reason) of every report queued so far.
fn reported(rx: &mut mpsc::Receiver<ClientMsg>) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    while let Ok(m) = rx.try_recv() {
        match m {
            ClientMsg::PrivacyActivity { kind, reason, .. } => out.push((
                serde_json::to_value(kind)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string(),
                reason,
            )),
            other => panic!("not a privacy report: {other:?}"),
        }
    }
    out
}

fn rep(kind: &str, reason: Option<&str>) -> (String, Option<String>) {
    (kind.to_string(), reason.map(str::to_string))
}

impl Rig {
    fn reported(&mut self) -> Vec<(String, Option<String>)> {
        reported(self.reports.as_mut().expect("reports not taken"))
    }

    async fn send(&self, v: Value) -> Result<()> {
        self.dc.send_text(v.to_string()).await.context("send")?;
        Ok(())
    }

    /// The next `rc:privacy.state`, within `within`.
    async fn state(&mut self, within: Duration) -> Result<Value> {
        let s = tokio::time::timeout(within, self.strings.recv())
            .await
            .map_err(|_| anyhow!("no rc:privacy.state within {within:?}"))?
            .ok_or_else(|| anyhow!("the channel closed"))?;
        let v: Value = serde_json::from_str(&s)?;
        assert_eq!(v["t"], "rc:privacy.state", "{v}");
        Ok(v)
    }

    async fn set(&mut self, id: &str, on: bool) -> Result<Value> {
        self.send(json!({"t": "rc:privacy.set", "id": id, "on": on}))
            .await?;
        self.state(Duration::from_secs(30)).await
    }

    async fn close(self) {
        let _ = self.pcs.0.close().await;
        let _ = self.pcs.1.close().await;
    }
}

/// How the device side attaches, as `peer.rs` decides it.
enum Attach {
    /// The grant lacks `PRIVACY`.
    NotGranted,
    /// The grant holds it; `possible` is gate 3.
    Granted { possible: fn() -> bool },
}

async fn rig(attach: Attach, up_ok: bool) -> Result<Rig> {
    rig_with(attach, up_ok, None).await
}

/// [`rig`] over a host endpoint that starts as `speakers` (P4; `None` = none).
async fn rig_with(attach: Attach, up_ok: bool, speakers: Option<bool>) -> Result<Rig> {
    let (browser_pc, agent_pc) = mk_pc_pair().await?;
    let endpoint = Arc::new(Endpoint(StdMutex::new(speakers)));
    let session_id = ObjectId::new();
    let overlay = Arc::new(Overlay {
        calls: StdMutex::new(Vec::new()),
        up_ok,
    });

    let browser_dc = browser_pc
        .create_data_channel("privacy", None)
        .await
        .context("create_data_channel(privacy)")?;
    let (agent_dc_tx, agent_dc_rx) = oneshot::channel::<Arc<RTCDataChannel>>();
    let agent_dc_tx = Arc::new(Mutex::new(Some(agent_dc_tx)));
    agent_pc.on_data_channel(Box::new(move |dc| {
        let tx = agent_dc_tx.clone();
        Box::pin(async move {
            if let Some(tx) = tx.lock().await.take() {
                let _ = tx.send(dc);
            }
        })
    }));
    let (strings_tx, strings_rx) = mpsc::unbounded_channel::<String>();
    browser_dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let tx = strings_tx.clone();
        Box::pin(async move {
            if msg.is_string
                && let Ok(s) = std::str::from_utf8(&msg.data)
            {
                let _ = tx.send(s.to_string());
            }
        })
    }));
    exchange(&browser_pc, &agent_pc).await?;
    let agent_dc = tokio::time::timeout(Duration::from_secs(30), agent_dc_rx)
        .await
        .map_err(|_| anyhow!("agent on_data_channel timed out"))??;
    let dir = tempfile::tempdir()?;
    let (outbound, reports) = mpsc::channel::<ClientMsg>(32);
    match attach {
        Attach::NotGranted => privacy::attach_refusing(agent_dc, session_id, "not_granted"),
        Attach::Granted { possible } => privacy::attach(
            agent_dc,
            PrivacyCtx {
                session_id,
                controller_name: "Tester".into(),
                host: overlay.clone(),
                possible,
                report: privacy::Reporter {
                    outbound,
                    tenant_id: ObjectId::new().to_hex(),
                    ledger: Arc::new(privacy::Ledger::at(dir.path().join("ledger.json"))),
                },
                mute: Arc::new(HostMute::new(endpoint.clone(), None)),
            },
        ),
    }
    let (open_tx, open_rx) = oneshot::channel::<()>();
    let open_tx = Arc::new(Mutex::new(Some(open_tx)));
    browser_dc.on_open(Box::new(move || {
        let tx = open_tx.clone();
        Box::pin(async move {
            if let Some(tx) = tx.lock().await.take() {
                let _ = tx.send(());
            }
        })
    }));
    // An already-open channel does not fire `on_open` again.
    if browser_dc.ready_state()
        != webrtc::data_channel::data_channel_state::RTCDataChannelState::Open
    {
        tokio::time::timeout(Duration::from_secs(30), open_rx)
            .await
            .map_err(|_| anyhow!("privacy DC open timed out"))??;
    }
    Ok(Rig {
        dc: browser_dc,
        strings: strings_rx,
        overlay,
        pcs: (browser_pc, agent_pc),
        reports: Some(reports),
        endpoint,
        _dir: dir,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grant_without_privacy_is_refused_by_name() -> Result<()> {
    let _g = SERIAL.lock().await;
    privacy::set_device_allowed(true);
    let mut r = rig(Attach::NotGranted, true).await?;
    let s = r.set("a", true).await?;
    assert_eq!(
        s,
        json!({"t":"rc:privacy.state","id":"a","on":false,"reason":"not_granted"})
    );
    assert!(r.overlay.calls().is_empty());
    // Nothing reported: the server would drop it anyway, no PRIVACY in the grant.
    assert!(r.reported().is_empty());
    r.close().await;
    Ok(())
}

/// The owner's gate is read at the "on", and it refuses before the overlay is
/// ever asked; the positive control below is the same rig with the gate on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_owner_gate_refuses_before_the_overlay_is_asked() -> Result<()> {
    let _g = SERIAL.lock().await;
    privacy::set_device_allowed(false);
    let mut r = rig(Attach::Granted { possible: || true }, true).await?;
    let s = r.set("1", true).await?;
    assert_eq!(s["reason"], "disabled_on_device", "{s}");
    assert_eq!(s["on"], false);
    assert!(r.overlay.calls().is_empty());
    // The owner allows it: the same request now covers the screen.
    privacy::set_device_allowed(true);
    let s = r.set("2", true).await?;
    assert_eq!(s, json!({"t":"rc:privacy.state","id":"2","on":true}));
    assert_eq!(r.overlay.calls(), vec![true]);
    assert_eq!(
        r.reported(),
        vec![rep("refused", Some("disabled_on_device")), rep("on", None)]
    );
    r.close().await;
    privacy::set_device_allowed(false);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_status_and_off_draw_and_clear_the_curtain() -> Result<()> {
    let _g = SERIAL.lock().await;
    privacy::set_device_allowed(true);
    let mut r = rig(Attach::Granted { possible: || true }, true).await?;
    assert_eq!(r.set("1", true).await?["on"], true);
    r.send(json!({"t": "rc:privacy.status", "id": "s"})).await?;
    let s = r.state(Duration::from_secs(30)).await?;
    assert_eq!(s, json!({"t":"rc:privacy.state","id":"s","on":true}));
    let s = r.set("2", false).await?;
    assert_eq!(s, json!({"t":"rc:privacy.state","id":"2","on":false}));
    assert_eq!(r.overlay.calls(), vec![true, false]);
    assert_eq!(
        r.reported(),
        vec![rep("on", None), rep("off", Some("controller"))]
    );
    r.close().await;
    privacy::set_device_allowed(false);
    Ok(())
}

/// P4 — on a device with speakers, the curtain mutes them and the controller
/// is told, on the answer and on a status; the take-down restores them and the
/// word goes away.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_curtain_mutes_the_host_and_the_controller_is_told() -> Result<()> {
    let _g = SERIAL.lock().await;
    privacy::set_device_allowed(true);
    let mut r = rig_with(Attach::Granted { possible: || true }, true, Some(false)).await?;
    let s = r.set("1", true).await?;
    assert_eq!(
        s,
        json!({"t":"rc:privacy.state","id":"1","on":true,"host_muted":true})
    );
    assert_eq!(*r.endpoint.0.lock().unwrap(), Some(true), "muted while up");
    r.send(json!({"t": "rc:privacy.status", "id": "s"})).await?;
    let s = r.state(Duration::from_secs(30)).await?;
    assert_eq!(
        s,
        json!({"t":"rc:privacy.state","id":"s","on":true,"host_muted":true})
    );
    let s = r.set("2", false).await?;
    assert_eq!(s, json!({"t":"rc:privacy.state","id":"2","on":false}));
    assert_eq!(*r.endpoint.0.lock().unwrap(), Some(false), "restored");
    r.close().await;
    privacy::set_device_allowed(false);
    Ok(())
}

/// Gate 3 (no curtain possible here) and gate 4 (the overlay could not put
/// one up, out of capture) are each named, and neither claims a curtain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_curtain_possible_and_a_failing_overlay_are_named() -> Result<()> {
    let _g = SERIAL.lock().await;
    privacy::set_device_allowed(true);
    let mut r = rig(Attach::Granted { possible: || false }, true).await?;
    let s = r.set("1", true).await?;
    assert_eq!(s["reason"], "unavailable", "{s}");
    assert!(r.overlay.calls().is_empty());
    assert_eq!(r.reported(), vec![rep("refused", Some("unavailable"))]);
    r.close().await;

    let mut r = rig(Attach::Granted { possible: || true }, false).await?;
    let s = r.set("2", true).await?;
    assert_eq!(
        s,
        json!({"t":"rc:privacy.state","id":"2","on":false,"reason":"no_curtain"})
    );
    assert_eq!(r.reported(), vec![rep("refused", Some("no_curtain"))]);
    r.close().await;
    privacy::set_device_allowed(false);
    Ok(())
}

/// The owner switches privacy mode off mid-session: the curtain comes down at
/// once and the viewer is TOLD, unasked, rather than left showing "on".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_owner_switching_off_takes_it_down_and_tells_the_viewer() -> Result<()> {
    let _g = SERIAL.lock().await;
    privacy::set_device_allowed(true);
    let mut r = rig(Attach::Granted { possible: || true }, true).await?;
    assert_eq!(r.set("1", true).await?["on"], true);
    privacy::set_device_allowed(false);
    let s = r.state(Duration::from_secs(30)).await?;
    assert_eq!(s["on"], false, "{s}");
    assert_eq!(s["reason"], "disabled_on_device", "{s}");
    assert_eq!(r.overlay.calls(), vec![true, false]);
    assert_eq!(
        r.reported(),
        vec![rep("on", None), rep("off", Some("disabled_on_device"))]
    );
    r.close().await;
    Ok(())
}

/// The session ending (here: the controller's side goes away) takes the
/// curtain down without anyone asking.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_channel_going_away_takes_the_curtain_down() -> Result<()> {
    let _g = SERIAL.lock().await;
    privacy::set_device_allowed(true);
    let mut r = rig(Attach::Granted { possible: || true }, true).await?;
    assert_eq!(r.set("1", true).await?["on"], true);
    let overlay = r.overlay.clone();
    let mut reports = r.reports.take().expect("reports");
    r.close().await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while overlay.calls() != vec![true, false] {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the curtain was not taken down: {:?}",
            overlay.calls()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // The report follows the take-down on the same blocking call.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut seen = Vec::new();
    while seen.len() < 2 && tokio::time::Instant::now() < deadline {
        seen.extend(reported(&mut reports));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(seen, vec![rep("on", None), rep("off", Some("session_end"))]);
    privacy::set_device_allowed(false);
    Ok(())
}

async fn exchange(browser_pc: &RTCPeerConnection, agent_pc: &RTCPeerConnection) -> Result<()> {
    let offer = browser_pc.create_offer(None).await?;
    browser_pc.set_local_description(offer.clone()).await?;
    agent_pc.set_remote_description(offer).await?;
    let answer = agent_pc.create_answer(None).await?;
    agent_pc.set_local_description(answer.clone()).await?;
    browser_pc.set_remote_description(answer).await?;
    Ok(())
}

async fn mk_pc_pair() -> Result<(Arc<RTCPeerConnection>, Arc<RTCPeerConnection>)> {
    let api = || -> Result<_> {
        let mut me = MediaEngine::default();
        me.register_default_codecs()?;
        Ok(APIBuilder::new().with_media_engine(me).build())
    };
    let cfg = RTCConfiguration {
        ice_servers: vec![],
        ..Default::default()
    };
    let browser_pc = Arc::new(api()?.new_peer_connection(cfg.clone()).await?);
    let agent_pc = Arc::new(api()?.new_peer_connection(cfg).await?);
    let a = agent_pc.clone();
    browser_pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
        let a = a.clone();
        Box::pin(async move {
            if let Some(c) = c
                && let Ok(j) = c.to_json()
            {
                let _ = a.add_ice_candidate(j).await;
            }
        })
    }));
    let b = browser_pc.clone();
    agent_pc.on_ice_candidate(Box::new(move |c: Option<RTCIceCandidate>| {
        let b = b.clone();
        Box::pin(async move {
            if let Some(c) = c
                && let Ok(j) = c.to_json()
            {
                let _ = b.add_ice_candidate(j).await;
            }
        })
    }));
    Ok((browser_pc, agent_pc))
}
