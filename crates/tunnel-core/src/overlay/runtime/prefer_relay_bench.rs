//! Path quality lab harness: does a pair leave a direct path for a clearly
//! better relay, stay there, and come back, without flapping? Measured end to
//! end on the production carrier logic, with a real degraded direct path.
//!
//! Built like [`failover_bench`](super::failover_bench): two RELAY-mode
//! runtimes, each on its own [`CarrierPlane`], a fake control plane, and a
//! fake `/derp` relay that cross-wires their [`DerpMux`]es. Three things
//! differ:
//!
//! * the relay delays every frame ([`RELAY_ONE_WAY`] each way), so the relay
//!   path has a round trip to be better or worse than;
//! * the direct path is degraded for real, with `tc netem` on the loopback
//!   of a PRIVATE network namespace (the two planes' addresses are both local
//!   to it, so their datagrams ride `lo`). The harness refuses to run in the
//!   host's namespace, where that would slow every loopback socket there is;
//! * the fake control plane judges `rc:overlay.path_quality` reports and
//!   stamps `prefer_relay_ms`, with the server's thresholds ([`Judge`], a
//!   stand-in for `meshharbor_mod_network::path_quality`, which this crate
//!   cannot depend on).
//!
//! Phases (seconds, `MH_PQ_SCALE` stretches them): stable, mild latency
//! (direct 1.2x the relay round trip), severe latency (relay + 400 ms), heavy
//! loss (25% each way), recovery, heavy loss again from direct, recovery.
//! The assertions are the acceptance oracle; with
//! `MESHHARBORD_OVERLAY_PREFER_RELAY=0` the severe-latency one fails, which is
//! the control (`MH_PQ_CONTROL=1` asserts the opposite: nothing moves).
//!
//! Ignored (real time, ~7 min, needs root in a private netns holding
//! `MH_PQ_LAN_A`/`_B`, default 10.254.42.1/.2). Run with
//! `MESHHARBORD_OVERLAY_DIRECT_PORT=0`, `--ignored --nocapture --exact`.

use super::tests::{MockTun, net, peer, synthetic_ipv4};
use super::*;
use crate::overlay::carrier_plane::CarrierPlane;
use crate::transport::derp::OutboundFrame;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// The fake relay's delay per direction: a 600 ms relay round trip.
const RELAY_ONE_WAY: Duration = Duration::from_millis(300);
const RELAY_RTT_MS: u64 = 600;
/// Stream cadence per direction (20 pps): enough to count as business traffic
/// and to time a stall to 50 ms.
const TICK: Duration = Duration::from_millis(50);
const PAYLOAD: usize = 204;

type Stamps = Arc<StdMutex<Vec<Instant>>>;
/// `(when, on_relay)` each time a node's carrier class for its peer changes.
type Timeline = Arc<StdMutex<Vec<(Instant, bool)>>>;

struct Node {
    ip: Ipv4Addr,
    kp: WgKeypair,
    mux: Arc<DerpMux>,
    inject: mpsc::UnboundedSender<Vec<u8>>,
    delivered: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    events: mpsc::Sender<OverlayEvent>,
    out: Option<mpsc::Receiver<ClientMsg>>,
    mux_out: Option<mpsc::Receiver<OutboundFrame>>,
    view: watch::Receiver<OverlayView>,
}

impl Node {
    fn start(ip: Ipv4Addr, lan: Ipv4Addr) -> Self {
        let kp = WgKeypair::generate();
        let (out_tx, out) = mpsc::channel(256);
        let (events, events_rx) = mpsc::channel(64);
        let (tun, inject, delivered) = MockTun::new();
        let tf: TunFactory = Box::new(move |_, _, _| Ok(tun.clone() as Arc<dyn TunIo>));
        let (mux, mux_out) = DerpMux::new(kp.public.to_bytes());
        let plane = CarrierPlane::new();
        *plane.lan_only.lock().unwrap() = Some(vec![lan]);
        let m = mux.clone();
        let (view_tx, view) = watch::channel(OverlayView::default());
        let rt = OverlayRuntime::new_relay(kp.clone(), out_tx, tf, 1280)
            .with_derp_mux_factory(Some(Box::new(move || m)))
            .with_carrier_plane(Some(plane))
            .with_peer_view(view_tx);
        tokio::spawn(rt.run(events_rx, Vec::new()));
        Self {
            ip,
            kp,
            mux,
            inject,
            delivered: Some(delivered),
            events,
            out: Some(out),
            mux_out: Some(mux_out),
            view,
        }
    }

    async fn joined(&mut self) -> Vec<String> {
        let out = self.out.as_mut().expect("control channel");
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(left, out.recv()).await {
                Ok(Some(ClientMsg::OverlayJoin { endpoints, .. })) => return endpoints,
                Ok(Some(_)) => {}
                _ => panic!("no rc:overlay.join from {} within 15 s", self.ip),
            }
        }
    }

    fn as_peer(&self, endpoints: &[String]) -> NetmapPeer {
        let mut p = peer(&self.kp, &self.ip.to_string());
        p.endpoints = endpoints.to_vec();
        p.lan_endpoints = endpoints.to_vec();
        p.supports_derp = true;
        p.supports_derp_floor = true;
        p
    }
}

/// One direction of the fake `/derp` relay, [`RELAY_ONE_WAY`] late and in
/// order: a frame `from` addresses to the other mux arrives there prefixed
/// with `from`, as the real relay stamps the authenticated sender.
fn relay(from: [u8; 32], mut rx: mpsc::Receiver<OutboundFrame>, to: Arc<DerpMux>) {
    let to_pk = to.self_pubkey();
    let (line_tx, mut line_rx) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    tokio::spawn(async move {
        while let Some((_, frame)) = rx.recv().await {
            if frame.len() < 32 || frame[..32] != to_pk[..] {
                continue;
            }
            let mut inbound = from.to_vec();
            inbound.extend_from_slice(&frame[32..]);
            if line_tx
                .send((Instant::now() + RELAY_ONE_WAY, inbound))
                .is_err()
            {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some((due, inbound)) = line_rx.recv().await {
            tokio::time::sleep_until(due.into()).await;
            to.deliver(&inbound);
        }
    });
}

fn stream(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    inject: mpsc::UnboundedSender<Vec<u8>>,
    stop: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(TICK);
        for seq in 0u32.. {
            tick.tick().await;
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let mut payload = [0u8; PAYLOAD];
            payload[..4].copy_from_slice(&seq.to_be_bytes());
            if inject.send(synthetic_ipv4(src, dst, &payload)).is_err() {
                break;
            }
        }
    });
}

fn arrivals(from: Ipv4Addr, mut delivered: mpsc::UnboundedReceiver<Vec<u8>>, seen: Stamps) {
    tokio::spawn(async move {
        while let Some(p) = delivered.recv().await {
            if p.len() == 20 + PAYLOAD && p[12..16] == from.octets() {
                seen.lock().unwrap().push(Instant::now());
            }
        }
    });
}

/// Sample a node's view of its one peer every 100 ms and keep the changes of
/// carrier class (a relay carrier with a direct probe in flight is relay).
fn carrier_timeline(view: watch::Receiver<OverlayView>, log: Timeline, stop: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let mut last = None;
        while !stop.load(Ordering::Relaxed) {
            let now = view
                .borrow()
                .peers
                .first()
                .and_then(|p| match p.connection {
                    ConnectionType::Direct => Some(false),
                    ConnectionType::Relay => Some(true),
                    _ => None,
                });
            if let Some(cur) = now
                && now != last
            {
                log.lock().unwrap().push((Instant::now(), cur));
                last = now;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
}

/// What one report says, by the server's thresholds
/// (`meshharbor_mod_network::path_quality::grade`).
#[derive(Clone, Copy, PartialEq, Debug)]
enum Grade {
    Thin,
    Dead,
    Worse,
    Between,
    Healthy,
}

struct Seen {
    at: Instant,
    grade: Grade,
}

/// A stand-in for the server's judge: both members' reports in, a verdict
/// stamped on both rows out. Same rules, same numbers.
#[derive(Default)]
struct Judge {
    last: [Option<Seen>; 2],
    until: Option<Instant>,
    entered: Option<Instant>,
    pushed: Option<Instant>,
    healthy_since: Option<Instant>,
    healthy_reports: u32,
    /// `(when, "enter" | "withdraw")`, for the summary.
    log: Vec<(Instant, &'static str)>,
}

#[allow(clippy::too_many_arguments)]
fn grade(
    window_ms: u32,
    d_sent: u32,
    d_lost: u32,
    d_rtt: Option<u32>,
    r_sent: u32,
    r_lost: u32,
    r_rtt: Option<u32>,
) -> Grade {
    if window_ms < 8_000 || d_sent < 8 || r_sent < 3 {
        return Grade::Thin;
    }
    let Some(r) = r_rtt.map(u64::from).filter(|_| r_lost * 10 <= r_sent) else {
        return Grade::Thin; // a relay that cannot be preferred: nothing to do here
    };
    let Some(d) = d_rtt.map(u64::from).filter(|_| d_lost < d_sent) else {
        return Grade::Dead;
    };
    if d_lost * 100 >= d_sent * 20 || (d * 100 >= r * 135 && d >= r + 100) {
        return Grade::Worse;
    }
    if d_lost * 100 <= d_sent * 5 && (d * 100 <= r * 115 || d <= r + 30) {
        return Grade::Healthy;
    }
    Grade::Between
}

/// What the judge wants sent to both members: a lifetime, or a withdrawal.
impl Judge {
    fn note(&mut self, who: usize, g: Grade, on_relay: bool, now: Instant) -> Option<u32> {
        self.last[who] = Some(Seen { at: now, grade: g });
        let fresh = |s: &Option<Seen>| {
            s.as_ref()
                .filter(|s| now.saturating_duration_since(s.at) <= Duration::from_secs(15))
                .map(|s| s.grade)
        };
        let other = fresh(&self.last[1 - who]);
        if self.until.is_none_or(|u| u <= now) {
            self.until = None;
            (self.healthy_since, self.healthy_reports) = (None, 0);
            let both = other == Some(Grade::Worse);
            let fell = on_relay && other.is_some_and(|o| o != Grade::Healthy);
            if g != Grade::Worse || !(both || fell) {
                return None;
            }
            self.until = Some(now + Duration::from_secs(60));
            (self.entered, self.pushed) = (Some(now), Some(now));
            self.log.push((now, "enter"));
            return Some(60_000);
        }
        match g {
            Grade::Thin => return None,
            Grade::Healthy => {
                let since = *self.healthy_since.get_or_insert(now);
                self.healthy_reports += 1;
                if self.healthy_reports >= 2
                    && now.saturating_duration_since(since) >= Duration::from_secs(10)
                    && self.entered.is_some_and(|t| {
                        now.saturating_duration_since(t) >= Duration::from_secs(20)
                    })
                    && other.is_none_or(|o| o == Grade::Healthy)
                {
                    self.until = None;
                    self.log.push((now, "withdraw"));
                    return Some(0);
                }
            }
            _ => (self.healthy_since, self.healthy_reports) = (None, 0),
        }
        self.until = Some(now + Duration::from_secs(60));
        let stale = self
            .pushed
            .is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_secs(20));
        let straggler = !on_relay
            && self
                .pushed
                .is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_secs(5));
        if stale || straggler {
            self.pushed = Some(now);
            return Some(60_000);
        }
        None
    }
}

/// `tc netem` on this namespace's loopback; `None` clears it.
fn netem(spec: Option<&str>) {
    let mut cmd = std::process::Command::new("tc");
    match spec {
        Some(s) => cmd
            .args(["qdisc", "replace", "dev", "lo", "root", "netem"])
            .args(s.split_whitespace()),
        None => cmd.args(["qdisc", "del", "dev", "lo", "root"]),
    };
    let out = cmd.output().expect("tc is installed");
    assert!(
        out.status.success() || spec.is_none(),
        "tc netem {spec:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

struct NetemGuard;
impl Drop for NetemGuard {
    fn drop(&mut self) {
        netem(None);
    }
}

/// A private network namespace: not the one PID 1 lives in.
fn in_private_netns() -> bool {
    match (
        std::fs::read_link("/proc/self/ns/net"),
        std::fs::read_link("/proc/1/ns/net"),
    ) {
        (Ok(mine), Ok(host)) => mine != host,
        _ => false,
    }
}

fn switches(log: &[(Instant, bool)], from: Instant, to: Instant) -> (usize, usize) {
    let (mut into_relay, mut into_direct) = (0, 0);
    let mut prev = log.iter().rev().find(|(t, _)| *t <= from).map(|(_, r)| *r);
    for (_, r) in log.iter().filter(|(t, _)| *t > from && *t <= to) {
        if prev.is_some_and(|p| p != *r) {
            if *r {
                into_relay += 1;
            } else {
                into_direct += 1;
            }
        }
        prev = Some(*r);
    }
    (into_relay, into_direct)
}

/// Seconds from `from` until the node is first on `relay` (already there = 0).
fn first_on(log: &[(Instant, bool)], relay: bool, from: Instant, to: Instant) -> Option<f64> {
    if log
        .iter()
        .rev()
        .find(|(t, _)| *t <= from)
        .is_some_and(|(_, r)| *r == relay)
    {
        return Some(0.0);
    }
    log.iter()
        .find(|(t, r)| *t > from && *t <= to && *r == relay)
        .map(|(t, _)| (*t - from).as_secs_f64())
}

fn longest_gap(seen: &[Instant], from: Instant, to: Instant) -> Duration {
    let mut prev = seen.iter().rev().find(|t| **t <= from).copied();
    let mut worst = Duration::ZERO;
    for &t in seen.iter().filter(|t| **t > from && **t <= to) {
        if let Some(p) = prev {
            worst = worst.max(t - p);
        }
        prev = Some(t);
    }
    if let Some(p) = prev {
        worst = worst.max(to.saturating_duration_since(p));
    }
    worst
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "path quality lab harness: real time, ~7 min, root in a private netns; --ignored --nocapture"]
async fn prefer_relay_phases() {
    assert!(
        in_private_netns(),
        "this harness shapes `lo` with tc netem: run it in a private network namespace"
    );
    let control = std::env::var("MH_PQ_CONTROL").is_ok_and(|v| v == "1");
    let scale: f64 = std::env::var("MH_PQ_SCALE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1.0);
    let lan = |k: &str, d: &str| -> Ipv4Addr {
        std::env::var(k)
            .unwrap_or_else(|_| d.into())
            .parse()
            .expect(k)
    };
    let _restore = NetemGuard;
    netem(None);
    let mut a = Node::start(
        Ipv4Addr::new(100, 64, 0, 1),
        lan("MH_PQ_LAN_A", "10.254.42.1"),
    );
    let mut b = Node::start(
        Ipv4Addr::new(100, 64, 0, 2),
        lan("MH_PQ_LAN_B", "10.254.42.2"),
    );
    let (ea, eb) = (a.joined().await, b.joined().await);
    assert!(
        !ea.is_empty() && !eb.is_empty(),
        "no LAN endpoint to go direct on (needs MESHHARBORD_OVERLAY_DIRECT_PORT=0)"
    );
    relay(
        a.kp.public.to_bytes(),
        a.mux_out.take().unwrap(),
        b.mux.clone(),
    );
    relay(
        b.kp.public.to_bytes(),
        b.mux_out.take().unwrap(),
        a.mux.clone(),
    );
    // `rows[i]` is node i as its peer's netmap names it.
    let rows = [a.as_peer(&ea), b.as_peer(&eb)];
    let network = OverlayNetworkInfo {
        path_quality_v1: true,
        ..net()
    };
    for (n, other) in [(&a, rows[1].clone()), (&b, rows[0].clone())] {
        n.events
            .send(OverlayEvent::Netmap {
                self_ip: n.ip.to_string(),
                network: network.clone(),
                peers: vec![other],
                org_relay_discovery: false,
                path_trial_v1: false,
            })
            .await
            .unwrap();
    }

    // The fake control plane: reports in, verdict rows out to both.
    let judge = Arc::new(StdMutex::new(Judge::default()));
    let reports = Arc::new(StdMutex::new([0u32; 2]));
    let events = [a.events.clone(), b.events.clone()];
    for (who, n) in [&mut a, &mut b].into_iter().enumerate() {
        let mut out = n.out.take().unwrap();
        let (judge, reports, events, rows) =
            (judge.clone(), reports.clone(), events.clone(), rows.clone());
        tokio::spawn(async move {
            while let Some(msg) = out.recv().await {
                let ClientMsg::OverlayPathQuality {
                    window_ms,
                    direct_sent,
                    direct_lost,
                    direct_rtt_ms,
                    relay_sent,
                    relay_lost,
                    relay_rtt_ms,
                    on_relay,
                    ..
                } = msg
                else {
                    continue;
                };
                reports.lock().unwrap()[who] += 1;
                let g = grade(
                    window_ms,
                    direct_sent,
                    direct_lost,
                    direct_rtt_ms,
                    relay_sent,
                    relay_lost,
                    relay_rtt_ms,
                );
                let verdict = judge.lock().unwrap().note(who, g, on_relay, Instant::now());
                let Some(ms) = verdict else { continue };
                for to in 0..2 {
                    let _ = events[to]
                        .send(OverlayEvent::NetmapDelta {
                            // The two senders' epochs would interleave: 0 is unordered.
                            epoch: 0,
                            auth_revision: 0,
                            upserts: vec![NetmapPeer {
                                prefer_relay_ms: Some(ms),
                                ..rows[1 - to].clone()
                            }],
                            removes: vec![],
                        })
                        .await;
                }
            }
        });
    }

    let stop = Arc::new(AtomicBool::new(false));
    let (at_a, at_b): (Stamps, Stamps) = Default::default();
    arrivals(a.ip, b.delivered.take().unwrap(), at_b.clone());
    arrivals(b.ip, a.delivered.take().unwrap(), at_a.clone());
    stream(a.ip, b.ip, a.inject.clone(), stop.clone());
    stream(b.ip, a.ip, b.inject.clone(), stop.clone());
    let (tl_a, tl_b): (Timeline, Timeline) = Default::default();
    carrier_timeline(a.view.clone(), tl_a.clone(), stop.clone());
    carrier_timeline(b.view.clone(), tl_b.clone(), stop.clone());

    // Settle on direct, past the direct carrier's warm-up.
    let t0 = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let direct = [&tl_a, &tl_b]
            .iter()
            .all(|t| t.lock().unwrap().last().is_some_and(|(_, relay)| !relay));
        if direct {
            break;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(90),
            "never settled on direct within 90 s"
        );
    }
    tokio::time::sleep(crate::overlay::lifecycle::DIRECT_GRACE + Duration::from_secs(4)).await;

    // (name, netem on `lo`, seconds). netem delays each direction once.
    let half = |rtt_ms: u64| format!("delay {}ms", rtt_ms / 2);
    let phases: Vec<(&str, Option<String>, u64)> = vec![
        ("stable", None, 30),
        ("mild", Some(half(RELAY_RTT_MS * 12 / 10)), 60),
        ("severe_delay", Some(half(RELAY_RTT_MS + 400)), 75),
        ("severe_loss", Some("delay 1ms loss 25%".into()), 75),
        ("recover", None, 75),
        ("loss_direct", Some("delay 1ms loss 25%".into()), 75),
        ("recover2", None, 60),
    ];
    let mut marks: Vec<(&str, Instant, Instant)> = Vec::new();
    for (name, spec, secs) in &phases {
        let from = Instant::now();
        netem(spec.as_deref());
        tokio::time::sleep(Duration::from_secs_f64(*secs as f64 * scale)).await;
        marks.push((name, from, Instant::now()));
    }
    netem(None);
    stop.store(true, Ordering::Relaxed);

    let (tl_a, tl_b) = (tl_a.lock().unwrap().clone(), tl_b.lock().unwrap().clone());
    let (at_a, at_b) = (at_a.lock().unwrap().clone(), at_b.lock().unwrap().clone());
    let mut fails: Vec<String> = Vec::new();
    for (name, from, to) in &marks {
        let (sa, sb) = (switches(&tl_a, *from, *to), switches(&tl_b, *from, *to));
        let relay_s = (
            first_on(&tl_a, true, *from, *to),
            first_on(&tl_b, true, *from, *to),
        );
        let direct_s = (
            first_on(&tl_a, false, *from, *to),
            first_on(&tl_b, false, *from, *to),
        );
        let gap = longest_gap(&at_a, *from, *to).max(longest_gap(&at_b, *from, *to));
        println!(
            "PQ-PHASE {{\"phase\":\"{name}\",\"into_relay\":[{},{}],\"into_direct\":[{},{}],\
             \"first_relay_s\":{relay_s:?},\"first_direct_s\":{direct_s:?},\"worst_gap_ms\":{}}}",
            sa.0,
            sb.0,
            sa.1,
            sb.1,
            gap.as_millis()
        );
        let moved = sa.0 + sb.0 + sa.1 + sb.1;
        let mut need = |ok: bool, what: &str| {
            if !ok {
                fails.push(format!("{name}: {what}"));
            }
        };
        if control {
            // Switched off: latency never moves the pair (today's behavior).
            if matches!(*name, "stable" | "mild" | "severe_delay") {
                need(moved == 0, "the pair moved with the feature switched off");
            }
            continue;
        }
        match *name {
            "stable" | "mild" => need(moved == 0, "the pair switched"),
            "severe_delay" => {
                let within = |s: Option<f64>| s.is_some_and(|s| s <= 30.0 * scale.max(1.0));
                need(
                    within(relay_s.0) && within(relay_s.1),
                    "not on the relay within 30 s",
                );
                need(sa == (1, 0) && sb == (1, 0), "did not stay on the relay");
            }
            "severe_loss" | "loss_direct" => {
                need(
                    sa.0 <= 1 && sb.0 <= 1,
                    "more than one switch into the relay",
                );
                need(
                    sa.1 == 0 && sb.1 == 0,
                    "bounced back to the lossy direct path",
                );
            }
            _ => {
                let within = |s: Option<f64>| s.is_some_and(|s| s <= 60.0 * scale.max(1.0));
                need(
                    within(direct_s.0) && within(direct_s.1),
                    "not back on direct within 60 s",
                );
            }
        }
    }
    let judged = judge.lock().unwrap();
    let verdicts: Vec<String> = judged
        .log
        .iter()
        .map(|(t, what)| format!("{:.1}:{what}", (*t - marks[0].1).as_secs_f64()))
        .collect();
    println!(
        "PQ-SUMMARY {{\"prefer_relay\":\"{}\",\"control\":{control},\"scale\":{scale},\
         \"reports\":{:?},\"verdicts\":{verdicts:?},\"frames_a\":{},\"frames_b\":{},\"fails\":{fails:?}}}",
        std::env::var("MESHHARBORD_OVERLAY_PREFER_RELAY").unwrap_or_else(|_| "-".into()),
        reports.lock().unwrap(),
        at_a.len(),
        at_b.len(),
    );
    assert!(fails.is_empty(), "{fails:#?}");
}
