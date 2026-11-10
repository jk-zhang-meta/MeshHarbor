// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-85 P3b — the `record` DataChannel, end to end.
//!
//! Two `webrtc-rs` PeerConnections in loopback; the "agent" side runs the
//! PRODUCTION handler (`meshharbord::recording::remote::attach`), which drives
//! the PRODUCTION recorder supervisor, which launches the real `meshharbord
//! record` child on the synthetic frame source. The "controller" side speaks
//! the wire. What is checked is what a controller would see (the states),
//! what the device reports to the server (the activity queue), what the
//! banner shows (the session registry), and what lands on disk.
//!
//! No real companion is ever launched: the handler's `Companion` answer is
//! fixed per test. One process-wide recorder and gate set, so the tests run
//! one at a time.

#![cfg(all(
    feature = "recording",
    feature = "openh264-encoder",
    feature = "synthetic-frame-source"
))]

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use bson::oid::ObjectId;
use meshharbor_remote_control::models::RecordingActivityKind;
use meshharbor_remote_control::signaling::ClientMsg;
use meshharbord::consent::{ConsentBroker, Mode};
use meshharbord::indicator::ViewerIndicator;
use meshharbord::rc_sessions::RcSessionRegistry;
use meshharbord::recording::manager::{GRACE_POLL, RecordingManager};
use meshharbord::recording::remote::{self, Companion, SessionCtx};
use meshharbord::recording::sidecar::{Initiator, Sidecar};
use serde_json::{Value, json};
use tokio::sync::{Mutex, mpsc, oneshot};
use webrtc::api::APIBuilder;
use webrtc::api::media_engine::MediaEngine;
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::ice_transport::ice_candidate::RTCIceCandidate;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;

/// One recorder and one gate set per process: one test at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// P3b-3 — the re-attach grace in these tests: long enough to set up the
/// controller's next session, short enough not to slow every drop.
const GRACE: Duration = Duration::from_secs(6);

struct Setup {
    /// Where recordings land (the configured `record_dir`).
    out: PathBuf,
    /// P1f — where an UNATTENDED recording lands (the daemon's own folder;
    /// a scratch one here).
    unattended: PathBuf,
    /// Consent markers, one sub-directory per test.
    consent_root: PathBuf,
    manager: Arc<RecordingManager>,
    _dir: tempfile::TempDir,
}

/// The process-wide recorder, installed once: the real `meshharbord record` on
/// the synthetic source, recording into a scratch folder.
fn setup() -> &'static Setup {
    static SETUP: OnceLock<Setup> = OnceLock::new();
    SETUP.get_or_init(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("Recordings");
        let unattended = dir.path().join("Unattended");
        let consent_root = dir.path().join("consent");
        std::fs::create_dir_all(&consent_root).unwrap();
        let cfg_path = dir.path().join("config.toml");
        let mut cfg = meshharbor_node_core::config::test_fixture();
        cfg.record_dir = Some(out.to_string_lossy().into_owned());
        meshharbor_node_core::config::save(&cfg_path, &cfg).unwrap();
        let manager = Arc::new(
            RecordingManager::new(PathBuf::from(env!("CARGO_BIN_EXE_meshharbord")), cfg_path)
                .with_service_identity(false)
                .with_unattended_dir(unattended.clone())
                .with_reattach_grace(GRACE)
                .with_child_env([("MESHHARBORD_SYNTHETIC_FRAMES", "1")]),
        );
        remote::install(manager.clone());
        Setup {
            out,
            unattended,
            consent_root,
            manager,
            _dir: dir,
        }
    })
}

/// Start a test from an idle recorder. A test that failed mid-recording
/// leaves the process-wide recorder running, and every later test would then
/// read `busy` instead of its own answer — one failure reported as five.
async fn idle(s: &Setup) {
    if s.manager.state().active {
        s.manager.stop_with(None).await;
    }
}

/// ONE runtime for every test in this file.
///
/// The recorder supervisor is process-wide, and the tasks it spawns (the
/// child's event reader, a recording's follower) live on the runtime that
/// started them. With a runtime per test (`#[tokio::test]`), a test that
/// failed mid-recording takes the reader down with its runtime: the
/// supervisor's state then says "recording" forever, [`idle`] cannot stop
/// what nothing reads, and every later test reads `busy` — one failure
/// reported as four (measured: the first negative-control run).
fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("the test runtime")
    })
}

#[test]
fn the_gates_refuse_by_name_before_anything_runs() -> Result<()> {
    rt().block_on(the_gates_refuse_by_name_before_anything_runs_cell())
}

#[test]
fn no_indicator_surface_means_no_recording() -> Result<()> {
    rt().block_on(no_indicator_surface_means_no_recording_cell())
}

#[test]
fn an_auto_granted_session_records_and_stops() -> Result<()> {
    rt().block_on(an_auto_granted_session_records_and_stops_cell())
}

#[test]
fn the_host_is_asked_again_and_a_deny_holds() -> Result<()> {
    rt().block_on(the_host_is_asked_again_and_a_deny_holds_cell())
}

#[test]
fn every_way_it_ends_is_named() -> Result<()> {
    rt().block_on(every_way_it_ends_is_named_cell())
}

#[test]
fn a_controller_downloads_only_its_own_recordings_and_can_resume() -> Result<()> {
    rt().block_on(a_controller_downloads_only_its_own_recordings_and_can_resume_cell())
}

#[test]
fn an_unattended_host_records_into_its_own_locked_folder() -> Result<()> {
    rt().block_on(an_unattended_host_records_into_its_own_locked_folder_cell())
}

#[test]
fn a_dropped_session_is_picked_up_by_its_controller() -> Result<()> {
    rt().block_on(a_dropped_session_is_picked_up_by_its_controller_cell())
}

#[test]
fn only_its_own_controller_picks_up_a_dropped_recording() -> Result<()> {
    rt().block_on(only_its_own_controller_picks_up_a_dropped_recording_cell())
}

#[test]
fn a_dropped_unattended_recording_still_stops_when_someone_signs_in() -> Result<()> {
    rt().block_on(a_dropped_unattended_recording_still_stops_when_someone_signs_in_cell())
}

#[test]
fn a_host_at_its_login_screen_is_refused_by_name_and_never_asked() -> Result<()> {
    rt().block_on(a_host_at_its_login_screen_is_refused_by_name_and_never_asked_cell())
}

#[test]
fn an_unattended_recording_stops_when_a_login_screen_appears() -> Result<()> {
    rt().block_on(an_unattended_recording_stops_when_a_login_screen_appears_cell())
}

#[test]
fn a_question_whose_session_dropped_is_withdrawn() -> Result<()> {
    rt().block_on(a_question_whose_session_dropped_is_withdrawn_cell())
}

#[test]
fn the_hosts_disconnect_stops_the_recording() -> Result<()> {
    rt().block_on(the_hosts_disconnect_stops_the_recording_cell())
}

#[test]
fn a_session_the_loop_ends_is_detached_though_its_channel_stays_open() -> Result<()> {
    rt().block_on(a_session_the_loop_ends_is_detached_though_its_channel_stays_open_cell())
}

#[test]
fn the_grace_never_stops_another_recording() -> Result<()> {
    rt().block_on(the_grace_never_stops_another_recording_cell())
}

#[test]
fn a_reoffer_on_the_same_session_keeps_its_banner() -> Result<()> {
    rt().block_on(a_reoffer_on_the_same_session_keeps_its_banner_cell())
}

/// The owner's two gates, as a local `ConfigSet` would set them.
fn gates(enabled: bool, audio: bool) {
    let mut cfg = meshharbor_node_core::config::test_fixture();
    cfg.record_remote_enabled = enabled;
    cfg.record_remote_audio = audio;
    remote::adopt(&cfg);
}

fn mp4s(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "mp4"))
                .collect()
        })
        .unwrap_or_default()
}

/// P3b-3 — one device's session surfaces, shared by every session of its
/// signalling loop: the banner (the registry) and the indicator over it.
#[derive(Clone)]
struct Device {
    registry: RcSessionRegistry,
    indicator: ViewerIndicator,
}

impl Device {
    fn new() -> (Self, mpsc::Receiver<ObjectId>) {
        let registry = RcSessionRegistry::new();
        let (kill_tx, kill_rx) = mpsc::channel(4);
        let indicator = ViewerIndicator::disabled().with_registry(kill_tx, registry.clone());
        (
            Self {
                registry,
                indicator,
            },
            kill_rx,
        )
    }
}

/// How a test session is set up on the device side.
struct Opts {
    /// `false` = the grant lacks RECORD (the refusing channel).
    granted: bool,
    /// `Some` = the session was consented on the host, so it asks again.
    prompt_window: Option<Duration>,
    /// The companion's answer (the only indicator surface in these tests:
    /// the native badge is not built here).
    companion: bool,
    /// The session is on the banner (the registry) at all.
    listed: bool,
    /// P3b-3 — the device this session is on (a fresh one when `None`).
    device: Option<Device>,
    /// P3b-3 — who controls (a fresh user when `None`).
    controller: Option<ObjectId>,
    /// P3b-3 — the session (a fresh one when `None`): the same one again is
    /// a re-offer, its old peer replaced.
    session_id: Option<ObjectId>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            granted: true,
            prompt_window: None,
            companion: true,
            listed: true,
            device: None,
            controller: None,
            session_id: None,
        }
    }
}

/// One session's controller end, plus what the test observes on the device.
struct Rig {
    dc: Arc<RTCDataChannel>,
    strings: mpsc::UnboundedReceiver<String>,
    /// Binary messages: a download's chunks.
    bytes: mpsc::UnboundedReceiver<Vec<u8>>,
    activity: mpsc::Receiver<ClientMsg>,
    registry: RcSessionRegistry,
    indicator: ViewerIndicator,
    broker: ConsentBroker,
    session_id: ObjectId,
    controller_user_id: ObjectId,
    pcs: (Arc<RTCPeerConnection>, Arc<RTCPeerConnection>),
    _kill_rx: Option<mpsc::Receiver<ObjectId>>,
}

impl Rig {
    async fn send(&self, v: Value) -> Result<()> {
        self.dc.send_text(v.to_string()).await.context("send")?;
        Ok(())
    }

    /// The next `rc:record.state`, within `within`.
    async fn state(&mut self, within: Duration) -> Result<Value> {
        let s = tokio::time::timeout(within, self.strings.recv())
            .await
            .map_err(|_| anyhow!("no rc:record.state within {within:?}"))?
            .ok_or_else(|| anyhow!("the channel closed"))?;
        let v: Value = serde_json::from_str(&s)?;
        assert_eq!(v["t"], "rc:record.state", "{v}");
        Ok(v)
    }

    /// States until one whose `state` is not `recording` (progress ticks).
    async fn until_not_recording(&mut self, within: Duration) -> Result<Value> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let v = self.state(left).await?;
            if v["state"] != "recording" {
                return Ok(v);
            }
        }
    }

    /// Everything the device reported so far (non-blocking).
    fn reports(&mut self) -> Vec<(RecordingActivityKind, Option<String>, Option<u64>)> {
        let mut out = Vec::new();
        while let Ok(m) = self.activity.try_recv() {
            if let ClientMsg::RecordingActivity {
                session_id,
                kind,
                reason,
                bytes,
                ..
            } = m
            {
                assert_eq!(
                    session_id, self.session_id,
                    "a report about another session"
                );
                out.push((kind, reason, bytes));
            }
        }
        out
    }

    /// The next message of type `t`, skipping anything else (a recording's
    /// progress, say), within `within`.
    async fn next_of(&mut self, t: &str, within: Duration) -> Result<Value> {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let s = tokio::time::timeout(left, self.strings.recv())
                .await
                .map_err(|_| anyhow!("no {t} within {within:?}"))?
                .ok_or_else(|| anyhow!("the channel closed"))?;
            let v: Value = serde_json::from_str(&s)?;
            if v["t"] == t {
                return Ok(v);
            }
        }
    }

    /// Fetch `name` from `offset`: `Ok((header, bytes, done))`, or the
    /// refusal's reason as `Err`.
    async fn download(
        &mut self,
        name: &str,
        offset: u64,
    ) -> Result<std::result::Result<(Value, Vec<u8>, Value), String>> {
        let id = format!("dl-{offset}");
        self.send(json!({"t": "rc:record.get", "id": id, "name": name, "offset": offset}))
            .await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let mut header = Value::Null;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let s = tokio::time::timeout(left, self.strings.recv())
                .await
                .map_err(|_| anyhow!("the download of {name} did not finish"))?
                .ok_or_else(|| anyhow!("the channel closed"))?;
            let v: Value = serde_json::from_str(&s)?;
            if v["id"] != id.as_str() {
                continue;
            }
            match v["t"].as_str() {
                Some("rc:record.error") => {
                    return Ok(Err(v["reason"].as_str().unwrap_or_default().to_string()));
                }
                Some("rc:record.file") => header = v,
                Some("rc:record.done") => {
                    let mut got = Vec::new();
                    while let Ok(chunk) = self.bytes.try_recv() {
                        got.extend_from_slice(&chunk);
                    }
                    return Ok(Ok((header, got, v)));
                }
                _ => {}
            }
        }
    }

    fn banner_says_recording(&self) -> bool {
        self.registry.list().iter().any(|s| s.recording)
    }

    /// P3b-3 — the session drops the way it does on a real device when the
    /// network goes: nothing arrives from the controller, the DEVICE closes
    /// its own peer (its session watchdog does, once the peer stops being
    /// usable), and the signalling loop hides the session from the banner.
    ///
    /// ⚠️ The device's peer first, on purpose: that is the order a network
    /// drop takes. A channel closed from its own side often never reaches
    /// `Closed` nor fires `on_close` (a race inside webrtc-rs: both outcomes
    /// happen in these cells), and the handler must see the end either way.
    /// Closing the controller's peer first let its reset reach the device
    /// first on every Windows run, which hid that path; Linux failed.
    async fn drop_session(&self) -> Result<()> {
        // Best-effort: closing a peer whose association is already torn
        // down can fail ("sending reset packet in non-Established state"),
        // which is a drop, not a test failure.
        let _ = self.pcs.1.close().await;
        self.indicator.hide_session(self.session_id.to_hex());
        let _ = self.pcs.0.close().await;
        Ok(())
    }
}

async fn rig(opts: Opts) -> Result<Rig> {
    let s = setup();
    let (browser_pc, agent_pc) = mk_pc_pair().await?;
    let session_id = opts.session_id.unwrap_or_default();
    // `ObjectId`'s default is a fresh one: a new user unless the test names one.
    let controller_user_id = opts.controller.unwrap_or_default();

    // The device side's surfaces: a real consent broker (its own marker
    // dir), and the session registry the companion's banner reads.
    let consent_dir = s.consent_root.join(session_id.to_hex());
    let broker = ConsentBroker::new(
        Mode::Prompt {
            timeout: Duration::from_secs(30),
        },
        consent_dir,
    )?;
    let (device, kill_rx) = match opts.device.clone() {
        Some(d) => (d, None),
        None => {
            let (d, rx) = Device::new();
            (d, Some(rx))
        }
    };
    let registry = device.registry.clone();
    let indicator = device.indicator.clone();
    if opts.listed {
        indicator.show_session_full(
            session_id,
            "Tester".into(),
            "VIEW | RECORD".into(),
            String::new(),
        );
    }
    let (activity_tx, activity_rx) = mpsc::channel(64);
    let ctx = SessionCtx {
        session_id,
        controller_user_id,
        controller_name: "Tester".into(),
        org: String::new(),
        prompt_window: opts.prompt_window,
        consent: broker.clone(),
        indicator: indicator.clone(),
        outbound: activity_tx,
        companion: Companion::Fixed(opts.companion),
    };

    let browser_dc = browser_pc
        .create_data_channel("record", None)
        .await
        .context("create_data_channel(record)")?;
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
    let (bytes_tx, bytes_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    // One callback, in channel order: when a `done` reaches `strings`, every
    // chunk sent before it is already in `bytes`.
    browser_dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let tx = strings_tx.clone();
        let btx = bytes_tx.clone();
        Box::pin(async move {
            if !msg.is_string {
                let _ = btx.send(msg.data.to_vec());
            } else if let Ok(s) = std::str::from_utf8(&msg.data) {
                let _ = tx.send(s.to_string());
            }
        })
    }));
    exchange(&browser_pc, &agent_pc).await?;
    let agent_dc = tokio::time::timeout(Duration::from_secs(30), agent_dc_rx)
        .await
        .map_err(|_| anyhow!("agent on_data_channel timed out"))??;
    // The attach-time gate, as `peer.rs` runs it.
    if opts.granted {
        remote::attach(agent_dc, ctx);
    } else {
        remote::attach_refusing(agent_dc, session_id, "not_granted");
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
        tokio::time::timeout(Duration::from_secs(10), open_rx)
            .await
            .map_err(|_| anyhow!("record DC open timed out"))??;
    }
    Ok(Rig {
        dc: browser_dc,
        strings: strings_rx,
        bytes: bytes_rx,
        activity: activity_rx,
        registry,
        indicator,
        broker,
        session_id,
        controller_user_id,
        pcs: (browser_pc, agent_pc),
        _kill_rx: kill_rx,
    })
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

/// The prompt standing for this session: its marker's id and body.
async fn standing_prompt(r: &Rig) -> Result<(String, Value)> {
    let dir = r.broker.sentinel_dir().to_path_buf();
    for _ in 0..100 {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().is_some_and(|x| x == "pending")
                    && let Ok(body) = std::fs::read_to_string(&p)
                    && let Ok(v) = serde_json::from_str::<Value>(&body)
                {
                    let id = p.file_stem().unwrap().to_string_lossy().into_owned();
                    return Ok((id, v));
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(anyhow!("no prompt appeared"))
}

/// Answer the standing prompt the way the native panel or the companion does
/// (the broker counts only an answer to a question it is asking, so retry
/// until it is).
async fn answer(r: &Rig, id: &str, allow: bool) {
    for _ in 0..100 {
        if r.broker.record_decision(id, allow) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the broker never took the answer");
}

const START: Duration = Duration::from_secs(25);
const STOP: Duration = Duration::from_secs(30);

/// Nothing starts without the owner's gate; each refusal says why, reaches
/// the server as a claim, and leaves no file and no banner behind.
async fn the_gates_refuse_by_name_before_anything_runs_cell() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;
    let before = mp4s(&s.out).len();

    gates(false, false);
    let mut r = rig(Opts::default()).await?;
    r.send(json!({"t": "rc:record.start", "id": "g1"})).await?;
    let v = r.state(START).await?;
    assert_eq!(
        (v["id"].as_str(), v["state"].as_str()),
        (Some("g1"), Some("refused"))
    );
    assert_eq!(v["reason"], "disabled_on_device");

    gates(true, false);
    r.send(json!({"t": "rc:record.start", "id": "g2", "audio": true}))
        .await?;
    let v = r.state(START).await?;
    // #1760 — the audio gate's refusal is `audio_not_allowed` where this
    // build can record computer audio, and `audio_unsupported` (ahead of the
    // owner's gate, with the words) where it cannot: the CI lane runs this
    // without the `audio` feature, a Mac has the feature and no loopback.
    let audio_refusal = if meshharbord::recording::system_audio_supported() {
        "audio_not_allowed"
    } else {
        "audio_unsupported"
    };
    assert_eq!(v["reason"], audio_refusal, "{v}");
    if audio_refusal == "audio_unsupported" {
        assert_eq!(
            v["detail"],
            meshharbord::recording::SYSTEM_AUDIO_UNSUPPORTED,
            "{v}"
        );
    }
    // Every state says whether computer audio could be included, so the
    // viewer can grey its box out before a start.
    assert_eq!(v["audio_unavailable"], audio_refusal, "{v}");

    let reports = r.reports();
    assert_eq!(
        reports
            .iter()
            .map(|(k, why, _)| (*k, why.clone()))
            .collect::<Vec<_>>(),
        vec![
            (
                RecordingActivityKind::Refused,
                Some("disabled_on_device".into())
            ),
            (RecordingActivityKind::Refused, Some(audio_refusal.into())),
        ]
    );
    assert!(!r.banner_says_recording());
    assert_eq!(mp4s(&s.out).len(), before, "a refused start wrote a file");

    // A session whose grant lacks RECORD gets a channel that refuses.
    let mut denied = rig(Opts {
        granted: false,
        ..Default::default()
    })
    .await?;
    denied
        .send(json!({"t": "rc:record.start", "id": "n1"}))
        .await?;
    let v = denied.state(START).await?;
    assert_eq!(
        (v["state"].as_str(), v["reason"].as_str()),
        (Some("refused"), Some("not_granted"))
    );
    Ok(())
}

/// ⚠️ Nothing on screen to say "recording" ⇒ no recording, and no frame.
async fn no_indicator_surface_means_no_recording_cell() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;
    let before = mp4s(&s.out).len();
    gates(true, false);
    let mut r = rig(Opts {
        companion: false,
        ..Default::default()
    })
    .await?;
    r.send(json!({"t": "rc:record.start", "id": "i1"})).await?;
    let v = r.state(START).await?;
    assert_eq!(v["reason"], "no_indicator_surface", "{v}");
    assert!(
        !r.banner_says_recording(),
        "the mark was not taken back down"
    );
    assert!(!s.manager.state().active, "a recorder is running anyway");
    assert_eq!(mp4s(&s.out).len(), before);

    // The same with the companion up but the session not on the banner.
    let mut r = rig(Opts {
        listed: false,
        ..Default::default()
    })
    .await?;
    r.send(json!({"t": "rc:record.start", "id": "i2"})).await?;
    let v = r.state(START).await?;
    assert_eq!(v["reason"], "no_indicator_surface", "{v}");
    Ok(())
}

/// An auto-granted session records: the banner is up before the file is
/// written, progress arrives, a Stop ends it `requested`, the sidecar names
/// the CONTROLLER (downloads are owned by user), and the device reports it.
async fn an_auto_granted_session_records_and_stops_cell() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;
    gates(true, false);
    let mut r = rig(Opts::default()).await?;
    r.send(json!({"t": "rc:record.start", "id": "a1"})).await?;
    let v = r.state(START).await?;
    assert_eq!(v["state"], "recording", "{v}");
    let name = v["name"].as_str().expect("a file name").to_string();
    assert!(
        !name.contains('/') && !name.contains('\\'),
        "the controller is told a name, never a path: {name}"
    );
    assert!(r.banner_says_recording(), "no banner while recording");
    assert_eq!(
        s.manager.state().remote_controller.as_deref(),
        Some("Tester"),
        "the host's own surfaces must say who it is for"
    );

    // A second start while this one runs is refused, by name.
    r.send(json!({"t": "rc:record.start", "id": "a2"})).await?;
    let v = r.until_not_recording(START).await?;
    assert_eq!(
        (v["id"].as_str(), v["reason"].as_str()),
        (Some("a2"), Some("busy"))
    );

    tokio::time::sleep(Duration::from_millis(2500)).await;
    r.send(json!({"t": "rc:record.stop", "id": "a1"})).await?;
    let v = r.until_not_recording(STOP).await?;
    assert_eq!(v["state"], "stopped", "{v}");
    assert_eq!(v["reason"], "requested");
    assert!(v["bytes"].as_u64().unwrap_or(0) > 0, "{v}");
    assert_eq!(v["name"].as_str(), Some(name.as_str()));
    assert!(
        !r.banner_says_recording(),
        "the banner outlived the recording"
    );

    let file = s.out.join(&name);
    assert!(file.is_file(), "{} missing", file.display());
    let sc: Sidecar = serde_json::from_str(&std::fs::read_to_string(Sidecar::path_for(&file))?)?;
    match &sc.initiator {
        Initiator::Remote {
            controller_user_id, ..
        } => assert_eq!(controller_user_id, &r.controller_user_id.to_hex()),
        other => panic!("the sidecar does not name the controller: {other:?}"),
    }
    assert!(
        !sc.audio.microphone,
        "a remote recording never takes the microphone"
    );

    let kinds: Vec<_> = r
        .reports()
        .into_iter()
        .map(|(k, why, bytes)| (k, why, bytes.is_some_and(|b| b > 0)))
        .collect();
    assert_eq!(
        kinds.first().map(|k| k.0),
        Some(RecordingActivityKind::Started)
    );
    assert!(
        kinds.contains(&(
            RecordingActivityKind::Stopped,
            Some("requested".into()),
            true
        )),
        "{kinds:?}"
    );
    let _ = std::fs::remove_file(Sidecar::path_for(&file));
    let _ = std::fs::remove_file(&file);
    Ok(())
}

/// A session consented ON THE HOST asks the host again, with a FRESH id.
/// A deny is final for a minute; an approval records.
async fn the_host_is_asked_again_and_a_deny_holds_cell() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;
    gates(true, false);
    let prompted = || Opts {
        prompt_window: Some(Duration::from_secs(20)),
        ..Default::default()
    };

    let mut r = rig(prompted()).await?;
    r.send(json!({"t": "rc:record.start", "id": "p1"})).await?;
    let v = r.state(START).await?;
    assert_eq!(v["state"], "pending_consent", "{v}");
    let (prompt_id, body) = standing_prompt(&r).await?;
    assert_eq!(body["kind"], "record", "{body}");
    assert_ne!(
        prompt_id,
        r.session_id.to_hex(),
        "the recording prompt reused the SESSION's id — its answer could be the session's"
    );
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or("")
            .contains("record this screen"),
        "an older companion shows only the detail line: {body}"
    );
    answer(&r, &prompt_id, false).await;
    let v = r.state(START).await?;
    assert_eq!(
        (v["state"].as_str(), v["reason"].as_str()),
        (Some("refused"), Some("consent_denied"))
    );
    // Asking again straight away is refused without bothering the host.
    r.send(json!({"t": "rc:record.start", "id": "p2"})).await?;
    let v = r.state(START).await?;
    assert_eq!(v["reason"], "rate_limited", "{v}");
    let kinds: Vec<_> = r
        .reports()
        .into_iter()
        .map(|(k, why, _)| (k, why))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (RecordingActivityKind::PromptDenied, None),
            (
                RecordingActivityKind::Refused,
                Some("consent_denied".into())
            ),
            (RecordingActivityKind::Refused, Some("rate_limited".into())),
        ]
    );

    // Another session: the host approves, and it records.
    let mut r = rig(prompted()).await?;
    r.send(json!({"t": "rc:record.start", "id": "p3"})).await?;
    assert_eq!(r.state(START).await?["state"], "pending_consent");
    let (prompt_id, _) = standing_prompt(&r).await?;
    answer(&r, &prompt_id, true).await;
    let v = r.state(START).await?;
    assert_eq!(v["state"], "recording", "{v}");
    let name = v["name"].as_str().unwrap().to_string();
    r.send(json!({"t": "rc:record.stop", "id": "p3"})).await?;
    let v = r.until_not_recording(STOP).await?;
    assert_eq!(v["state"], "stopped", "{v}");
    let kinds: Vec<_> = r.reports().into_iter().map(|(k, _, _)| k).collect();
    assert_eq!(kinds.first(), Some(&RecordingActivityKind::PromptGranted));
    let file = s.out.join(&name);
    let _ = std::fs::remove_file(Sidecar::path_for(&file));
    let _ = std::fs::remove_file(&file);
    Ok(())
}

/// The owner switching remote recording off stops it (`gate_revoked`); the
/// host's own Stop is `host_stopped`; the session ending is `session_ended`.
async fn every_way_it_ends_is_named_cell() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;

    // The owner's OFF.
    gates(true, false);
    let mut r = rig(Opts::default()).await?;
    r.send(json!({"t": "rc:record.start", "id": "e1"})).await?;
    assert_eq!(r.state(START).await?["state"], "recording");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    gates(false, false);
    let v = r.until_not_recording(STOP).await?;
    assert_eq!(
        (v["state"].as_str(), v["reason"].as_str()),
        (Some("stopped"), Some("gate_revoked")),
        "{v}"
    );
    let _ = remove(&s.out, &v);

    // The host's Stop (the LocalAPI verb, the banner, the tray).
    gates(true, false);
    let mut r = rig(Opts::default()).await?;
    r.send(json!({"t": "rc:record.start", "id": "e2"})).await?;
    assert_eq!(r.state(START).await?["state"], "recording");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    s.manager.stop().await;
    let v = r.until_not_recording(STOP).await?;
    assert_eq!(v["reason"], "host_stopped", "{v}");
    let _ = remove(&s.out, &v);

    // The session ending, and nobody coming back for it (P3b-3): the
    // recording waits out the re-attach grace, its banner still up and
    // saying so, then ends `session_ended`, reported on the session it
    // belonged to, and the banner comes down with it.
    let r = rig(Opts::default()).await?;
    let mut r = r;
    r.send(json!({"t": "rc:record.start", "id": "e3"})).await?;
    let v = r.state(START).await?;
    assert_eq!(v["state"], "recording");
    let name = v["name"].as_str().unwrap().to_string();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    r.drop_session().await?;
    tokio::time::sleep(Duration::from_millis(1000)).await;
    assert!(
        s.manager.state().active,
        "the recording ended with its session: there was no grace to come back in"
    );
    let banner = r.registry.list();
    assert!(
        banner.len() == 1 && banner[0].recording && banner[0].reconnecting,
        "a recording ran on with no banner saying so: {banner:?}"
    );
    let deadline = tokio::time::Instant::now() + GRACE + STOP;
    while s.manager.state().active && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let st = s.manager.state();
    assert!(!st.active, "the recording outlived its grace");
    assert_eq!(
        st.last.as_ref().map(|l| l.reason.as_str()),
        Some("session_ended")
    );
    // The ending is reported once, on the session it belonged to.
    let mut stopped = Vec::new();
    for _ in 0..50 {
        stopped.extend(
            r.reports()
                .into_iter()
                .filter(|(k, _, _)| *k == RecordingActivityKind::Stopped),
        );
        if !stopped.is_empty() && r.registry.list().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        stopped
            .iter()
            .map(|(_, why, _)| why.clone())
            .collect::<Vec<_>>(),
        vec![Some("session_ended".to_string())],
        "{stopped:?}"
    );
    assert!(
        r.registry.list().is_empty(),
        "the banner outlived the recording"
    );
    let file = s.out.join(&name);
    let _ = std::fs::remove_file(Sidecar::path_for(&file));
    let _ = std::fs::remove_file(&file);
    Ok(())
}

/// P3b-2 — the download. A controller lists and fetches its OWN recordings,
/// whole or resumed from an offset, and the device's SHA-256 is of the whole
/// file either way. A second controller of the same device sees nothing and
/// cannot fetch it by name; a name that could leave the folder and an offset
/// past the end are refused by name; each finished transfer is reported.
async fn a_controller_downloads_only_its_own_recordings_and_can_resume_cell() -> Result<()> {
    use sha2::{Digest, Sha256};
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;
    gates(true, false);

    let mut a = rig(Opts::default()).await?;
    a.send(json!({"t": "rc:record.start", "id": "d1"})).await?;
    let v = a.state(START).await?;
    assert_eq!(v["state"], "recording", "{v}");
    let name = v["name"].as_str().unwrap().to_string();
    tokio::time::sleep(Duration::from_millis(2000)).await;
    a.send(json!({"t": "rc:record.stop", "id": "d1"})).await?;
    let v = a.until_not_recording(STOP).await?;
    assert_eq!(v["state"], "stopped", "{v}");
    let file = s.out.join(&name);
    let on_disk = std::fs::read(&file)?;
    let size = on_disk.len() as u64;
    let whole = hex::encode(Sha256::digest(&on_disk));
    let _ = a.reports();

    // Listed for its controller.
    a.send(json!({"t": "rc:record.list", "id": "l1"})).await?;
    let v = a.next_of("rc:record.list", START).await?;
    let names: Vec<&str> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["name"].as_str())
        .collect();
    assert!(names.contains(&name.as_str()), "{v}");

    // Whole.
    let (header, got, done) = a.download(&name, 0).await?.expect("the download");
    assert_eq!(
        (header["offset"].as_u64(), header["size"].as_u64()),
        (Some(0), Some(size))
    );
    assert!(
        got == on_disk,
        "the bytes differ from the file ({} of {size})",
        got.len()
    );
    assert_eq!(done["sha256"].as_str(), Some(whole.as_str()));
    assert_eq!(done["bytes"].as_u64(), Some(size));

    // Resumed from the middle: only the rest is sent, the hash is still the
    // whole file's.
    let half = size / 2;
    let (header, got, done) = a
        .download(&name, half)
        .await?
        .expect("the resumed download");
    assert_eq!(header["offset"].as_u64(), Some(half));
    assert!(
        got[..] == on_disk[half as usize..],
        "the resumed bytes differ"
    );
    assert_eq!(done["sha256"].as_str(), Some(whole.as_str()));
    assert_eq!(done["bytes"].as_u64(), Some(size - half));

    // Refusals, by name.
    assert_eq!(
        a.download("../escape.mp4", 0).await?.err().as_deref(),
        Some("bad_name")
    );
    assert_eq!(
        a.download(&name, size + 1).await?.err().as_deref(),
        Some("bad_offset")
    );
    assert_eq!(
        a.download("no such.mp4", 0).await?.err().as_deref(),
        Some("not_found")
    );

    let downloaded: Vec<_> = a
        .reports()
        .into_iter()
        .filter(|(k, _, _)| *k == RecordingActivityKind::Downloaded)
        .map(|(_, _, bytes)| bytes)
        .collect();
    assert_eq!(downloaded, vec![Some(size), Some(size - half)]);

    // ⚠️ Another controller of the SAME device: nothing listed, and the name
    // alone does not fetch it — indistinguishable from a file that is not there.
    let mut b = rig(Opts::default()).await?;
    b.send(json!({"t": "rc:record.list", "id": "l2"})).await?;
    let v = b.next_of("rc:record.list", START).await?;
    assert_eq!(v["items"].as_array().map(|i| i.len()), Some(0), "{v}");
    assert_eq!(
        b.download(&name, 0).await?.err().as_deref(),
        Some("not_found")
    );

    let _ = std::fs::remove_file(Sidecar::path_for(&file));
    let _ = std::fs::remove_file(&file);
    Ok(())
}

/// P1f — an UNATTENDED host (a service with nobody signed in) records a
/// remote session with no banner, because there is nobody to show one to:
/// the owner's gate is what allows it, and the controller is told it records
/// unattended. A LOCAL start there is still refused. The file goes into the
/// daemon's own folder, locked to the service side, never the person's
/// `record_dir`. When someone SIGNS IN, the recording they never saw start
/// ends `session_changed` (red without the watch: it runs on, bannerless),
/// and it stays listed and downloadable for the controller afterwards.
async fn an_unattended_host_records_into_its_own_locked_folder_cell() -> Result<()> {
    use meshharbord::recording::launch::{Identity, Refusal};
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;
    gates(true, false);
    s.manager.set_identity(Some(Err(Refusal::NoConsoleUser)));
    let outcome = async {
        // A local start needs someone at the device.
        match s
            .manager
            .start(tunnel_core::localapi::RecordStartOpts::default())
            .await
        {
            tunnel_core::localapi::Response::Error { message } => {
                assert!(message.contains("nobody is signed in"), "{message}")
            }
            other => panic!("a local recording started unattended: {other:?}"),
        }

        let before = mp4s(&s.out).len();
        // Nothing at all could show a banner: the companion down, the
        // session not on the registry.
        let mut r = rig(Opts {
            companion: false,
            listed: false,
            ..Default::default()
        })
        .await?;
        r.send(json!({"t": "rc:record.start", "id": "u1"})).await?;
        let v = r.state(START).await?;
        assert_eq!(v["state"], "recording", "{v}");
        assert_eq!(v["unattended"], true, "the controller is not told: {v}");
        let name = v["name"].as_str().expect("a file name").to_string();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(s.manager.state().active, "it stopped on its own");

        // Someone signs in at the device.
        s.manager.set_identity(Some(Ok(Identity::Inherit)));
        let v = r.until_not_recording(STOP).await?;
        assert_eq!(v["state"], "stopped", "{v}");
        assert_eq!(
            v["reason"], "session_changed",
            "an unattended recording ran on after someone signed in: {v}"
        );

        let file = s.unattended.join(&name);
        assert!(
            file.is_file(),
            "not in the daemon's own folder: {}",
            file.display()
        );
        assert_eq!(
            mp4s(&s.out).len(),
            before,
            "an unattended recording reached the person's folder"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&s.unattended)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "the folder is not locked to the service");
        }

        // Someone is signed in now, and the controller still lists it and
        // downloads it whole (the unattended folder, read as the daemon).
        r.send(json!({"t": "rc:record.list", "id": "ul"})).await?;
        let v = r.next_of("rc:record.list", START).await?;
        assert!(
            v["items"]
                .as_array()
                .is_some_and(|i| i.iter().any(|i| i["name"] == name.as_str())),
            "{v}"
        );
        let on_disk = std::fs::read(&file)?;
        let (_, got, _) = r.download(&name, 0).await?.expect("the download");
        assert!(got == on_disk, "the download differs from the file");

        let _ = std::fs::remove_file(Sidecar::path_for(&file));
        let _ = std::fs::remove_file(&file);
        Ok::<(), anyhow::Error>(())
    }
    .await;
    s.manager.set_identity(Some(Ok(Identity::Inherit)));
    outcome
}

/// P3b-3 — a session that drops (a relay flap, a reloaded viewer) does not
/// cost its recording. The recording waits for its controller, its banner up
/// and saying so; the SAME controller on a new session picks it up by asking
/// for the status: the same recording (its id, its file) now answers to the
/// new session, the new session's banner says it, and the old one is gone.
/// The pick-up is reported, and the ending once, on the new session.
async fn a_dropped_session_is_picked_up_by_its_controller_cell() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;
    gates(true, false);
    let (device, _kill) = Device::new();
    let user = ObjectId::new();
    let on_device = || Opts {
        device: Some(device.clone()),
        controller: Some(user),
        ..Default::default()
    };

    let mut a = rig(on_device()).await?;
    a.send(json!({"t": "rc:record.start", "id": "r1"})).await?;
    let v = a.state(START).await?;
    assert_eq!(v["state"], "recording", "{v}");
    let name = v["name"].as_str().expect("a file name").to_string();
    tokio::time::sleep(Duration::from_millis(1500)).await;

    a.drop_session().await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        s.manager.state().active,
        "the recording ended with its session"
    );
    let banner = device.registry.list();
    assert!(
        banner.len() == 1
            && banner[0].session_id == a.session_id.to_hex()
            && banner[0].recording
            && banner[0].reconnecting,
        "the host is not told the recording goes on: {banner:?}"
    );

    // The controller is back, on a new session.
    let mut b = rig(on_device()).await?;
    b.send(json!({"t": "rc:record.status"})).await?;
    let v = b.state(START).await?;
    assert_eq!(
        (v["state"].as_str(), v["id"].as_str(), v["name"].as_str()),
        (Some("recording"), Some("r1"), Some(name.as_str())),
        "the same recording must answer to the controller's new session: {v}"
    );
    let banner = device.registry.list();
    assert!(
        banner.len() == 1
            && banner[0].session_id == b.session_id.to_hex()
            && banner[0].recording
            && !banner[0].reconnecting,
        "the new session's banner must say it, and the old one be gone: {banner:?}"
    );

    tokio::time::sleep(Duration::from_millis(1500)).await;
    b.send(json!({"t": "rc:record.stop", "id": "r1"})).await?;
    let v = b.until_not_recording(STOP).await?;
    assert_eq!(
        (v["state"].as_str(), v["reason"].as_str()),
        (Some("stopped"), Some("requested")),
        "{v}"
    );
    assert!(device.registry.list().iter().all(|s| !s.recording));

    // One recording, one file, one ending: where it began on the old
    // session, where it continued and how it ended on the new one.
    let a_kinds: Vec<_> = a.reports().into_iter().map(|(k, _, _)| k).collect();
    assert_eq!(a_kinds, vec![RecordingActivityKind::Started], "{a_kinds:?}");
    let b_kinds: Vec<_> = b
        .reports()
        .into_iter()
        .map(|(k, why, _)| (k, why))
        .collect();
    assert_eq!(
        b_kinds,
        vec![
            (RecordingActivityKind::Reattached, None),
            (RecordingActivityKind::Stopped, Some("requested".into())),
        ]
    );
    let file = s.out.join(&name);
    assert!(file.is_file(), "{} missing", file.display());
    let sc: Sidecar = serde_json::from_str(&std::fs::read_to_string(Sidecar::path_for(&file))?)?;
    match &sc.initiator {
        Initiator::Remote {
            controller_user_id, ..
        } => assert_eq!(controller_user_id, &user.to_hex()),
        other => panic!("the sidecar does not name the controller: {other:?}"),
    }
    let _ = std::fs::remove_file(Sidecar::path_for(&file));
    let _ = std::fs::remove_file(&file);
    Ok(())
}

/// P3b-3 — a dropped recording is its controller's alone: another
/// controller of the same device, on a session holding RECORD, is told
/// nothing is recording, and the recording goes on waiting until its grace
/// runs out, then ends `session_ended`.
async fn only_its_own_controller_picks_up_a_dropped_recording_cell() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;
    gates(true, false);
    let (device, _kill) = Device::new();
    let mut a = rig(Opts {
        device: Some(device.clone()),
        ..Default::default()
    })
    .await?;
    a.send(json!({"t": "rc:record.start", "id": "o1"})).await?;
    let v = a.state(START).await?;
    assert_eq!(v["state"], "recording", "{v}");
    let name = v["name"].as_str().unwrap().to_string();
    tokio::time::sleep(Duration::from_millis(1000)).await;
    a.drop_session().await?;

    let mut c = rig(Opts {
        device: Some(device.clone()),
        ..Default::default()
    })
    .await?;
    assert_ne!(c.controller_user_id, a.controller_user_id);
    c.send(json!({"t": "rc:record.status"})).await?;
    let v = c.state(START).await?;
    assert_eq!(
        v["state"], "idle",
        "another controller picked up someone else's recording: {v}"
    );
    assert!(
        s.manager.state().active,
        "asking for the status must not end it"
    );
    assert!(
        device
            .registry
            .list()
            .iter()
            .any(|e| e.session_id == a.session_id.to_hex() && e.reconnecting),
        "the dropped recording's banner went"
    );
    assert!(
        c.reports().is_empty(),
        "the other controller's session reported"
    );

    let deadline = tokio::time::Instant::now() + GRACE + STOP;
    while s.manager.state().active && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let st = s.manager.state();
    assert!(!st.active, "the recording outlived its grace");
    assert_eq!(
        st.last.as_ref().map(|l| l.reason.as_str()),
        Some("session_ended")
    );
    let file = s.out.join(&name);
    let _ = std::fs::remove_file(Sidecar::path_for(&file));
    let _ = std::fs::remove_file(&file);
    Ok(())
}

/// P3b-3 with P1f — an UNATTENDED recording whose session dropped is still
/// watched for someone signing in: the moment they do, it ends
/// `session_changed`, not a grace later (red without the watch in the
/// grace: it runs on, bannerless, for the rest of the minute).
async fn a_dropped_unattended_recording_still_stops_when_someone_signs_in_cell() -> Result<()> {
    use meshharbord::recording::launch::{Identity, Refusal};
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;
    gates(true, false);
    s.manager.set_identity(Some(Err(Refusal::NoConsoleUser)));
    let outcome = async {
        let r = rig(Opts {
            companion: false,
            listed: false,
            ..Default::default()
        })
        .await?;
        let mut r = r;
        r.send(json!({"t": "rc:record.start", "id": "du1"})).await?;
        let v = r.state(START).await?;
        assert_eq!(
            (v["state"].as_str(), v["unattended"].as_bool()),
            (Some("recording"), Some(true)),
            "{v}"
        );
        let name = v["name"].as_str().unwrap().to_string();
        tokio::time::sleep(Duration::from_millis(1000)).await;
        r.drop_session().await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(s.manager.state().active, "it ended with its session");

        // Someone signs in while it waits for its controller.
        let signed_in_at = tokio::time::Instant::now();
        s.manager.set_identity(Some(Ok(Identity::Inherit)));
        while s.manager.state().active && signed_in_at.elapsed() < STOP {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let st = s.manager.state();
        assert!(!st.active, "it ran on after someone signed in");
        assert_eq!(
            st.last.as_ref().map(|l| l.reason.as_str()),
            Some("session_changed"),
            "a detached unattended recording was not stopped for the sign-in"
        );
        let file = s.unattended.join(&name);
        let _ = std::fs::remove_file(Sidecar::path_for(&file));
        let _ = std::fs::remove_file(&file);
        Ok::<(), anyhow::Error>(())
    }
    .await;
    s.manager.set_identity(Some(Ok(Identity::Inherit)));
    outcome
}

/// FR-85 decision 6 — a device at its LOGIN SCREEN is not "nobody signed
/// in": someone may be standing at it, and nothing on a sign-in screen can
/// say a recording runs. So it never records unattended. A start is refused
/// by its own name, with the words, before anyone is asked (whoever stands at
/// a sign-in screen must not be asked to approve what could never run), and
/// with nothing at all to show a banner it is still `login_screen`, never an
/// unattended recording. The device goes on advertising that it can record:
/// who is at the screen changes, the capability does not.
///
/// Red: the login screen read as "nobody" (it records, unattended); the
/// early refusal gone (the host is asked first); the code folded into
/// `unavailable`; the capability tied to who is signed in (no `available`).
async fn a_host_at_its_login_screen_is_refused_by_name_and_never_asked_cell() -> Result<()> {
    use meshharbord::recording::launch::{Identity, Refusal};
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;
    gates(true, false);
    s.manager.set_identity(Some(Err(Refusal::LoginScreen)));
    let outcome = async {
        let caps = remote::advertised();
        assert!(
            caps.iter().any(|c| c == "available") && caps.iter().any(|c| c == "remote"),
            "a device at its login screen stopped advertising it can record: {caps:?}"
        );

        // A local start: nobody there to ask for one either.
        match s
            .manager
            .start(tunnel_core::localapi::RecordStartOpts::default())
            .await
        {
            tunnel_core::localapi::Response::Error { message } => assert!(
                message.contains("sign-in screen") || message.contains("login screen"),
                "{message}"
            ),
            other => panic!("a local recording started at a login screen: {other:?}"),
        }

        let before = (mp4s(&s.out).len(), mp4s(&s.unattended).len());

        // A session consented on the host: refused before the question.
        let mut r = rig(Opts {
            prompt_window: Some(Duration::from_secs(20)),
            ..Default::default()
        })
        .await?;
        r.send(json!({"t": "rc:record.start", "id": "ls1"})).await?;
        let v = r.state(START).await?;
        assert_eq!(
            (v["id"].as_str(), v["state"].as_str(), v["reason"].as_str()),
            (Some("ls1"), Some("refused"), Some("login_screen")),
            "{v}"
        );
        let detail = v["detail"].as_str().unwrap_or_default();
        assert!(
            detail.contains("screen") && detail.contains("record"),
            "the refusal carries no words: {v}"
        );
        let asked = std::fs::read_dir(r.broker.sentinel_dir())
            .map(|rd| {
                rd.flatten()
                    .any(|e| e.path().extension().is_some_and(|x| x == "pending"))
            })
            .unwrap_or(false);
        assert!(
            !asked,
            "the person at a sign-in screen was asked to approve"
        );
        assert_eq!(
            r.reports()
                .into_iter()
                .map(|(k, why, _)| (k, why))
                .collect::<Vec<_>>(),
            vec![(RecordingActivityKind::Refused, Some("login_screen".into()))]
        );

        // Nothing at all to show a banner: still refused, never unattended.
        let mut r = rig(Opts {
            companion: false,
            listed: false,
            ..Default::default()
        })
        .await?;
        r.send(json!({"t": "rc:record.start", "id": "ls2"})).await?;
        let v = r.state(START).await?;
        assert_eq!(
            (v["state"].as_str(), v["reason"].as_str()),
            (Some("refused"), Some("login_screen")),
            "a login screen recorded as if nobody were there: {v}"
        );
        assert!(v.get("unattended").is_none(), "{v}");
        assert!(!s.manager.state().active, "a recorder is running anyway");
        assert!(!r.banner_says_recording());
        assert_eq!(
            (mp4s(&s.out).len(), mp4s(&s.unattended).len()),
            before,
            "a refused start wrote a file"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    s.manager.set_identity(Some(Ok(Identity::Inherit)));
    outcome
}

/// FR-85 decision 6 — an UNATTENDED recording (nobody at any screen) ends
/// `session_changed` the moment the device shows a login screen: it has one
/// to show now, and someone may be at it. What it recorded stays its
/// controller's: listed and downloadable while the device sits at that login
/// screen, where nothing new can be recorded.
///
/// Red: the watch stopping only for a SIGN-IN (it runs on, bannerless, in
/// front of the login screen); the unattended folder listed only while the
/// device could record unattended (the file vanishes from the list).
async fn an_unattended_recording_stops_when_a_login_screen_appears_cell() -> Result<()> {
    use meshharbord::recording::launch::{Identity, Refusal};
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;
    gates(true, false);
    s.manager.set_identity(Some(Err(Refusal::NoConsoleUser)));
    let outcome = async {
        let mut r = rig(Opts {
            companion: false,
            listed: false,
            ..Default::default()
        })
        .await?;
        r.send(json!({"t": "rc:record.start", "id": "lu1"})).await?;
        let v = r.state(START).await?;
        assert_eq!(
            (v["state"].as_str(), v["unattended"].as_bool()),
            (Some("recording"), Some(true)),
            "{v}"
        );
        let name = v["name"].as_str().expect("a file name").to_string();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(s.manager.state().active, "it stopped on its own");

        // The device's display manager puts up its login screen.
        s.manager.set_identity(Some(Err(Refusal::LoginScreen)));
        let v = r.until_not_recording(STOP).await?;
        assert_eq!(
            (v["state"].as_str(), v["reason"].as_str()),
            (Some("stopped"), Some("session_changed")),
            "an unattended recording ran on in front of a login screen: {v}"
        );

        let file = s.unattended.join(&name);
        assert!(file.is_file(), "{} missing", file.display());
        r.send(json!({"t": "rc:record.list", "id": "lul"})).await?;
        let v = r.next_of("rc:record.list", START).await?;
        assert!(
            v["items"]
                .as_array()
                .is_some_and(|i| i.iter().any(|i| i["name"] == name.as_str())),
            "at the login screen the controller's recording is gone from its list: {v}"
        );
        let on_disk = std::fs::read(&file)?;
        let (_, got, _) = r.download(&name, 0).await?.expect("the download");
        assert!(got == on_disk, "the download differs from the file");

        let _ = std::fs::remove_file(Sidecar::path_for(&file));
        let _ = std::fs::remove_file(&file);
        Ok::<(), anyhow::Error>(())
    }
    .await;
    s.manager.set_identity(Some(Ok(Identity::Inherit)));
    outcome
}

/// Sessions [`a_question_whose_session_dropped_is_withdrawn_cell`] drops.
const QUESTION_ROUNDS: usize = 6;

/// A session that drops while the host is being asked takes the question
/// with it. The device closed its own peer, so its channel often fires no
/// `on_close`, and no follower exists before a recording: then only the
/// handler's watch on the channel's state can see the end. The question comes
/// off the host's screen, and an answer that arrives anyway starts nothing.
///
/// ⚠️ Several sessions, because one proves little: a drop whose close lands
/// on `Closed` fires `on_close` and passes without the watch. Measured
/// without it, one session was red in 3 runs of 4; six are red unless every
/// one of them lands on `Closed`.
async fn a_question_whose_session_dropped_is_withdrawn_cell() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;
    gates(true, false);
    for round in 1..=QUESTION_ROUNDS {
        let mut r = rig(Opts {
            prompt_window: Some(Duration::from_secs(20)),
            ..Default::default()
        })
        .await?;
        r.send(json!({"t": "rc:record.start", "id": format!("w{round}")}))
            .await?;
        assert_eq!(r.state(START).await?["state"], "pending_consent");
        let (prompt_id, _) = standing_prompt(&r).await?;
        let marker = r.broker.pending_path(&prompt_id);
        assert!(marker.exists(), "round {round}: no question on the screen");

        r.drop_session().await?;
        let dropped_at = tokio::time::Instant::now();
        while marker.exists() && dropped_at.elapsed() < Duration::from_secs(5) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            !marker.exists(),
            "round {round}: the question stayed on the host's screen after its session went"
        );
        assert!(
            !r.broker.record_decision(&prompt_id, true),
            "round {round}: the host could still answer for a session that is gone"
        );
        assert!(!r.banner_says_recording(), "round {round}");
        let kinds: Vec<_> = r.reports().into_iter().map(|(k, _, _)| k).collect();
        assert!(
            !kinds.contains(&RecordingActivityKind::PromptGranted)
                && !kinds.contains(&RecordingActivityKind::Started),
            "round {round}: {kinds:?}"
        );
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !s.manager.state().active,
        "a recording started for a session that is gone"
    );
    Ok(())
}

/// Every report of `r` until one of `kind` arrives, or `within` passes.
async fn reports_until(
    r: &mut Rig,
    kind: RecordingActivityKind,
    within: Duration,
) -> Vec<(RecordingActivityKind, Option<String>)> {
    let deadline = tokio::time::Instant::now() + within;
    let mut out = Vec::new();
    loop {
        out.extend(r.reports().into_iter().map(|(k, why, _)| (k, why)));
        if out.iter().any(|(k, _)| *k == kind) || tokio::time::Instant::now() >= deadline {
            return out;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Whether `cond` holds within `within`.
async fn eventually(within: Duration, cond: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while !cond() {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    true
}

/// P3b-3 — the HOST's Disconnect is not a drop. The person at the device
/// sent the controller away, so the recording stops then and there,
/// `host_stopped`, reported once, its banner down, and the controller's
/// next session finds nothing to pick up (red when it is detached like a
/// drop: it runs on, waiting for them, and ends `session_ended`).
async fn the_hosts_disconnect_stops_the_recording_cell() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;
    gates(true, false);
    let (device, _kill) = Device::new();
    let user = ObjectId::new();
    let on_device = || Opts {
        device: Some(device.clone()),
        controller: Some(user),
        ..Default::default()
    };
    let mut a = rig(on_device()).await?;
    a.send(json!({"t": "rc:record.start", "id": "h1"})).await?;
    let v = a.state(START).await?;
    assert_eq!(v["state"], "recording", "{v}");
    let name = v["name"].as_str().expect("a file name").to_string();
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // The signalling loop's kill arm: the recording first, then the peer
    // and the banner, as for any session end.
    remote::host_ended(a.session_id);
    a.drop_session().await?;
    let t = tokio::time::Instant::now();
    while s.manager.state().active && t.elapsed() < STOP {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let st = s.manager.state();
    assert!(
        !st.active,
        "the host's Disconnect left the recording running"
    );
    assert_eq!(
        st.last.as_ref().map(|l| l.reason.as_str()),
        Some("host_stopped"),
        "the host's Disconnect did not stop it"
    );
    let kinds = reports_until(
        &mut a,
        RecordingActivityKind::Stopped,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        kinds,
        vec![
            (RecordingActivityKind::Started, None),
            (RecordingActivityKind::Stopped, Some("host_stopped".into())),
        ]
    );
    assert!(
        eventually(Duration::from_secs(3), || device
            .registry
            .list()
            .iter()
            .all(|e| !e.recording))
        .await,
        "the banner outlived the recording"
    );
    // The controller comes back: there is nothing to pick up.
    let mut b = rig(on_device()).await?;
    b.send(json!({"t": "rc:record.status"})).await?;
    assert_eq!(b.state(START).await?["state"], "idle");
    let file = s.out.join(&name);
    let _ = std::fs::remove_file(Sidecar::path_for(&file));
    let _ = std::fs::remove_file(&file);
    Ok(())
}

/// P3b-3 — a session the signalling loop ends (the server's terminate, the
/// control connection lost) is over even when its channel never closes: a
/// peer whose close overran its budget is dropped before its channels are
/// touched. The recording is detached, and its controller picks it up (red
/// without `session_ended`: nothing detaches, and they are told `idle`).
async fn a_session_the_loop_ends_is_detached_though_its_channel_stays_open_cell() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;
    gates(true, false);
    let (device, _kill) = Device::new();
    let user = ObjectId::new();
    let on_device = || Opts {
        device: Some(device.clone()),
        controller: Some(user),
        ..Default::default()
    };
    let mut a = rig(on_device()).await?;
    a.send(json!({"t": "rc:record.start", "id": "l1"})).await?;
    let v = a.state(START).await?;
    assert_eq!(v["state"], "recording", "{v}");
    let name = v["name"].as_str().expect("a file name").to_string();
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // The loop ends the session; its peer is never closed.
    remote::session_ended(a.session_id);
    a.indicator.hide_session(a.session_id.to_hex());

    let mut b = rig(on_device()).await?;
    b.send(json!({"t": "rc:record.status"})).await?;
    let v = b.state(START).await?;
    assert_eq!(
        (v["state"].as_str(), v["id"].as_str(), v["name"].as_str()),
        (Some("recording"), Some("l1"), Some(name.as_str())),
        "a session the loop ended kept its recording: {v}"
    );
    b.send(json!({"t": "rc:record.stop", "id": "l1"})).await?;
    let v = b.until_not_recording(STOP).await?;
    assert_eq!(v["reason"], "requested", "{v}");
    let b_kinds = reports_until(
        &mut b,
        RecordingActivityKind::Stopped,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        b_kinds,
        vec![
            (RecordingActivityKind::Reattached, None),
            (RecordingActivityKind::Stopped, Some("requested".into())),
        ]
    );
    let a_kinds: Vec<_> = a.reports().into_iter().map(|(k, _, _)| k).collect();
    assert_eq!(a_kinds, vec![RecordingActivityKind::Started]);
    a.drop_session().await?;
    let file = s.out.join(&name);
    let _ = std::fs::remove_file(Sidecar::path_for(&file));
    let _ = std::fs::remove_file(&file);
    Ok(())
}

/// P3b-3 — the grace acts on ITS recording only. A detached recording ends
/// by itself (the host's Stop) and another controller starts one before the
/// grace looks again: at that look the grace finds its own recording over
/// and reports THAT, once, on its own session, and leaves the other one be
/// (red when it looks at "whatever is recording": it stops the other
/// controller's recording `session_ended`).
async fn the_grace_never_stops_another_recording_cell() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;
    gates(true, false);
    // A long pause between the grace's looks, for the second recording to
    // begin inside it.
    let poll = Duration::from_secs(15);
    s.manager.set_grace_poll(poll);
    let outcome = async {
        let (device, _kill) = Device::new();
        let on_device = || Opts {
            device: Some(device.clone()),
            ..Default::default()
        };
        let mut a = rig(on_device()).await?;
        a.send(json!({"t": "rc:record.start", "id": "n1"})).await?;
        let v = a.state(START).await?;
        assert_eq!(v["state"], "recording", "{v}");
        let name_a = v["name"].as_str().unwrap().to_string();
        tokio::time::sleep(Duration::from_millis(1000)).await;
        a.drop_session().await?;
        let dropped = tokio::time::Instant::now();
        // The drop is seen (≤ 500 ms) and the grace's first look passes.
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // The host stops it, and another controller starts a recording.
        let _ = s.manager.stop().await;
        assert!(!s.manager.state().active, "the host's Stop did not stop it");
        let mut c = rig(on_device()).await?;
        c.send(json!({"t": "rc:record.start", "id": "n2"})).await?;
        let v = c.state(START).await?;
        assert_eq!(v["state"], "recording", "{v}");
        let name_c = v["name"].as_str().unwrap().to_string();
        assert!(
            dropped.elapsed() < poll - Duration::from_secs(1),
            "the second recording began after the grace looked again: this cell proves nothing"
        );

        // Past A's grace and the grace's next look.
        tokio::time::sleep_until(dropped + poll + Duration::from_secs(2)).await;
        assert!(
            s.manager
                .active_remote()
                .is_some_and(|r| r.session_id == c.session_id),
            "the grace stopped another controller's recording"
        );
        let a_kinds = reports_until(
            &mut a,
            RecordingActivityKind::Stopped,
            Duration::from_secs(3),
        )
        .await;
        assert_eq!(
            a_kinds,
            vec![
                (RecordingActivityKind::Started, None),
                (RecordingActivityKind::Stopped, Some("host_stopped".into())),
            ]
        );
        let banner = device.registry.list();
        assert!(
            banner.len() == 1
                && banner[0].session_id == c.session_id.to_hex()
                && banner[0].recording,
            "the banners are wrong: {banner:?}"
        );
        c.send(json!({"t": "rc:record.stop", "id": "n2"})).await?;
        let v = c.until_not_recording(STOP).await?;
        assert_eq!(v["reason"], "requested", "{v}");
        let c_kinds: Vec<_> = c.reports().into_iter().map(|(k, _, _)| k).collect();
        assert_eq!(c_kinds.first(), Some(&RecordingActivityKind::Started));
        for n in [&name_a, &name_c] {
            let file = s.out.join(n);
            let _ = std::fs::remove_file(Sidecar::path_for(&file));
            let _ = std::fs::remove_file(&file);
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    s.manager.set_grace_poll(GRACE_POLL);
    outcome
}

/// P3b-3 — a re-offer on the SAME session id (its old peer replaced; the
/// session goes on): the recording carries on under the new peer, and its
/// banner keeps saying so (red when the pick-up takes "the old banner"
/// down: it is this one).
async fn a_reoffer_on_the_same_session_keeps_its_banner_cell() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let s = setup();
    idle(s).await;
    gates(true, false);
    let (device, _kill) = Device::new();
    let user = ObjectId::new();
    let session = ObjectId::new();
    let same = |listed| Opts {
        device: Some(device.clone()),
        controller: Some(user),
        session_id: Some(session),
        listed,
        ..Default::default()
    };
    let mut a = rig(same(true)).await?;
    a.send(json!({"t": "rc:record.start", "id": "s1"})).await?;
    let v = a.state(START).await?;
    assert_eq!(v["state"], "recording", "{v}");
    let name = v["name"].as_str().unwrap().to_string();
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // The loop replaces the peer. No `hide_session`: the session goes on.
    let _ = a.pcs.1.close().await;
    let _ = a.pcs.0.close().await;
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // The session is listed already.
    let mut b = rig(same(false)).await?;
    b.send(json!({"t": "rc:record.status"})).await?;
    let v = b.state(START).await?;
    assert_eq!(
        (v["state"].as_str(), v["id"].as_str()),
        (Some("recording"), Some("s1")),
        "{v}"
    );
    let banner = device.registry.list();
    assert!(
        banner.len() == 1
            && banner[0].session_id == session.to_hex()
            && banner[0].recording
            && !banner[0].reconnecting,
        "the re-offer took the banner down while it records: {banner:?}"
    );
    b.send(json!({"t": "rc:record.stop", "id": "s1"})).await?;
    let v = b.until_not_recording(STOP).await?;
    assert_eq!(v["reason"], "requested", "{v}");
    let file = s.out.join(&name);
    let _ = std::fs::remove_file(Sidecar::path_for(&file));
    let _ = std::fs::remove_file(&file);
    Ok(())
}

fn remove(out: &Path, v: &Value) -> Option<()> {
    let file = out.join(v["name"].as_str()?);
    let _ = std::fs::remove_file(Sidecar::path_for(&file));
    std::fs::remove_file(&file).ok()
}
