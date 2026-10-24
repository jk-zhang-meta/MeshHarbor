//! F0 — failover measurement harness (handoff §6.3): the business stall on a
//! dead direct path, and the return to direct once it heals, measured end to
//! end on the production carrier logic instead of asserted on one detector.
//!
//! Two RELAY-mode runtimes (`new_relay`, as `roomlerd` builds them), each on
//! its OWN [`CarrierPlane`] — two machines, not two orgs of one — joined by a
//! fake control plane that answers each `rc:overlay.join` with a netmap naming
//! the other, and a fake `/derp` relay that cross-wires their [`DerpMux`]es
//! and stamps every business-sized frame it carries. The fault is
//! `CarrierPlane::blackhole` on both planes: every direct datagram is dropped
//! on receipt, both directions dark while sends still leave — a NAT mapping or
//! Wi-Fi path dying under live traffic — and `/derp` keeps working. A 50 pps
//! stream each way gives:
//!
//! - `stall_*_ms`: the longest arrival gap per direction across the outage;
//! - `return_ms`: the last business frame on `/derp` after the heal, i.e. when
//!   BOTH ends carry the stream on direct again (`null` = not in the window);
//! - `heal_gap_*_ms`: the longest gap after the heal (make-before-break ⇒ ~tick).
//!
//! Ignored (real time, ~2 min). One binary measures each phase through the
//! kill switches `ROOMLERD_OVERLAY_BUSINESS_POKE_FAST=0` (F1 off) and
//! `ROOMLERD_OVERLAY_FAST_RETURN=0` (F3 off). Knobs: `MH_FO_BLOCK_S` (25),
//! `MH_FO_OBSERVE_S` (75). Each plane binds ONE address of the shared netns
//! (`MH_FO_LAN_A`/`_B`, default the suite's veth 10.254.41.1/.2), because a
//! peer endpoint on one of our own addresses is never a LAN candidate; run
//! with `ROOMLERD_OVERLAY_DIRECT_PORT=0` so the two planes don't race a port.

use super::tests::{MockTun, net, peer, synthetic_ipv4};
use super::*;
use crate::overlay::carrier_plane::CarrierPlane;
use crate::transport::derp::OutboundFrame;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Stream cadence per direction (50 pps), i.e. the stall resolution.
const TICK: Duration = Duration::from_millis(20);
/// 20 B header + 204 = 224 B inner: a 256 B WG data message, larger than any
/// handshake (148/92), cookie (64) or keepalive (32), so the relay tells the
/// stream from control traffic by size alone.
const PAYLOAD: usize = 204;
const BUSINESS_MIN_WG: usize = 200;
/// How long `/derp` must stay free of the stream to count as "on direct".
const QUIET: Duration = Duration::from_secs(3);

type Stamps = Arc<StdMutex<Vec<Instant>>>;
/// `(when, "Connection/relay_kind")` each time a node's view of its peer changes.
type Timeline = Arc<StdMutex<Vec<(Instant, String)>>>;

fn env_secs(name: &str, default: u64) -> Duration {
    Duration::from_secs(
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default),
    )
}

struct Node {
    ip: Ipv4Addr,
    kp: WgKeypair,
    plane: Arc<CarrierPlane>,
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
            .with_carrier_plane(Some(plane.clone()))
            .with_peer_view(view_tx);
        tokio::spawn(rt.run(events_rx, Vec::new()));
        Self {
            ip,
            kp,
            plane,
            mux,
            inject,
            delivered: Some(delivered),
            events,
            out: Some(out),
            mux_out: Some(mux_out),
            view,
        }
    }

    /// The endpoints its first `rc:overlay.join` advertises (its plane's binds).
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

    /// This node as its peer's netmap names it — the server's shape for a LAN
    /// node: `lan_endpoints` unioned into `endpoints`.
    fn as_peer(&self, endpoints: &[String]) -> NetmapPeer {
        let mut p = peer(&self.kp, &self.ip.to_string());
        p.endpoints = endpoints.to_vec();
        p.lan_endpoints = endpoints.to_vec();
        p.supports_derp = true;
        p.supports_derp_floor = true;
        p
    }
}

/// One direction of the fake `/derp` relay: a frame `from` addresses to the
/// other mux's pubkey arrives there prefixed with `from`, as the real relay
/// stamps the authenticated sender; every business-sized frame is timed.
fn relay(from: [u8; 32], mut rx: mpsc::Receiver<OutboundFrame>, to: Arc<DerpMux>, seen: Stamps) {
    let to_pk = to.self_pubkey();
    tokio::spawn(async move {
        while let Some((_, frame)) = rx.recv().await {
            if frame.len() < 32 || frame[..32] != to_pk[..] {
                continue;
            }
            if frame.len() - 32 >= BUSINESS_MIN_WG {
                seen.lock().unwrap().push(Instant::now());
            }
            let mut inbound = from.to_vec();
            inbound.extend_from_slice(&frame[32..]);
            to.deliver(&inbound);
        }
    });
}

fn stream(src: Ipv4Addr, dst: Ipv4Addr, inject: mpsc::UnboundedSender<Vec<u8>>, stop: Arc<AtomicBool>) {
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

/// Arrival times of `from`'s stream at the receiving TUN.
fn arrivals(from: Ipv4Addr, mut delivered: mpsc::UnboundedReceiver<Vec<u8>>, seen: Stamps) {
    tokio::spawn(async move {
        while let Some(p) = delivered.recv().await {
            if p.len() == 20 + PAYLOAD && p[12..16] == from.octets() {
                seen.lock().unwrap().push(Instant::now());
            }
        }
    });
}

/// Sample the runtime's published view of its one peer every 100 ms and keep
/// the transitions: which carrier each end believes it holds, and when.
fn carrier_timeline(view: watch::Receiver<OverlayView>, log: Timeline, stop: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let mut last = String::new();
        while !stop.load(Ordering::Relaxed) {
            let now = view.borrow().peers.first().map_or_else(
                || "none".to_string(),
                |p| format!("{:?}/{}", p.connection, p.relay_kind.as_deref().unwrap_or("-")),
            );
            if now != last {
                log.lock().unwrap().push((Instant::now(), now.clone()));
                last = now;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
}

/// `[+ms:state, ...]` relative to `cut` (negative = before the outage).
fn render(log: &[(Instant, String)], cut: Instant) -> String {
    let at = |t: Instant| {
        if t >= cut {
            (t - cut).as_millis() as i128
        } else {
            -((cut - t).as_millis() as i128)
        }
    };
    let parts: Vec<String> = log.iter().map(|(t, s)| format!("{}:{s}", at(*t))).collect();
    format!("[{}]", parts.join(", "))
}

/// The longest gap between consecutive arrivals ending inside `(from, to]`,
/// a stream still dark at `to` counting up to `to`.
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
#[ignore = "F0 failover harness: real time, ~2 min; run with --ignored --nocapture"]
async fn failover_stall_and_return() {
    let block = env_secs("MH_FO_BLOCK_S", 25);
    let observe = env_secs("MH_FO_OBSERVE_S", 75);
    let lan = |k: &str, d: &str| -> Ipv4Addr {
        std::env::var(k).unwrap_or_else(|_| d.into()).parse().expect(k)
    };
    let mut a = Node::start(Ipv4Addr::new(100, 64, 0, 1), lan("MH_FO_LAN_A", "10.254.41.1"));
    let mut b = Node::start(Ipv4Addr::new(100, 64, 0, 2), lan("MH_FO_LAN_B", "10.254.41.2"));
    let (ea, eb) = (a.joined().await, b.joined().await);
    assert!(
        !ea.is_empty() && !eb.is_empty(),
        "no LAN endpoint to go direct on: a={ea:?} b={eb:?} \
         (needs a LAN interface and ROOMLERD_OVERLAY_DIRECT_PORT=0)"
    );
    println!("FAILOVER-ENDPOINTS a={ea:?} b={eb:?}");

    let on_derp: Stamps = Default::default();
    relay(a.kp.public.to_bytes(), a.mux_out.take().unwrap(), b.mux.clone(), on_derp.clone());
    relay(b.kp.public.to_bytes(), b.mux_out.take().unwrap(), a.mux.clone(), on_derp.clone());
    let (pa, pb) = (a.as_peer(&ea), b.as_peer(&eb));
    for (n, other) in [(&a, pb), (&b, pa)] {
        n.events
            .send(OverlayEvent::Netmap {
                self_ip: n.ip.to_string(),
                network: net(),
                peers: vec![other],
                org_relay_discovery: false,
                path_trial_v1: false,
            })
            .await
            .unwrap();
    }
    for n in [&mut a, &mut b] {
        let mut out = n.out.take().unwrap();
        tokio::spawn(async move { while out.recv().await.is_some() {} });
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

    // Settle: both directions flowing while `/derp` carries none of it.
    let t0 = Instant::now();
    let direct_after = loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let now = Instant::now();
        let flowing = [&at_a, &at_b].iter().all(|s| {
            s.lock()
                .unwrap()
                .last()
                .is_some_and(|t| now - *t < Duration::from_millis(500))
        });
        let quiet = on_derp.lock().unwrap().last().is_none_or(|t| now - *t >= QUIET);
        if flowing && quiet && now - t0 >= QUIET {
            break now - t0;
        }
        assert!(
            now - t0 < Duration::from_secs(90),
            "never settled on direct within 90 s ({} stream frames on /derp)",
            on_derp.lock().unwrap().len()
        );
    };

    // Cut only once the direct carrier is past `DIRECT_GRACE`, which blinds
    // the business scout and `carrier_tick` alike: a cut inside it measures
    // the grace, not the failover (the first F0 runs cut 3 s in).
    tokio::time::sleep(crate::overlay::lifecycle::DIRECT_GRACE + Duration::from_secs(4)).await;
    let cut = Instant::now();
    a.plane.blackhole.store(true, Ordering::Relaxed);
    b.plane.blackhole.store(true, Ordering::Relaxed);
    tokio::time::sleep(block).await;
    let heal = Instant::now();
    a.plane.blackhole.store(false, Ordering::Relaxed);
    b.plane.blackhole.store(false, Ordering::Relaxed);
    tokio::time::sleep(observe).await;
    let end = Instant::now();
    stop.store(true, Ordering::Relaxed);

    let (at_a, at_b) = (at_a.lock().unwrap().clone(), at_b.lock().unwrap().clone());
    let on_derp = on_derp.lock().unwrap().clone();
    let (stall_ab, stall_ba) = (longest_gap(&at_b, cut, heal), longest_gap(&at_a, cut, heal));
    let (heal_ab, heal_ba) = (longest_gap(&at_b, heal, end), longest_gap(&at_a, heal, end));
    let floored = on_derp.iter().filter(|t| **t > cut && **t <= heal).count();
    let last_on_derp = on_derp.iter().rev().find(|t| **t > heal).copied();
    let return_ms = match last_on_derp {
        None => Some(0),
        Some(t) if end - t >= QUIET => Some((t - heal).as_millis()),
        Some(_) => None,
    };
    let env = |k: &str| std::env::var(format!("ROOMLERD_{k}")).unwrap_or_else(|_| "-".into());
    println!(
        "FAILOVER {{\"poke_fast\":\"{}\",\"fast_return\":\"{}\",\"direct_after_ms\":{},\"block_s\":{},\
         \"stall_ab_ms\":{},\"stall_ba_ms\":{},\"floor_frames\":{},\"return_ms\":{},\
         \"heal_gap_ab_ms\":{},\"heal_gap_ba_ms\":{}}}",
        env("OVERLAY_BUSINESS_POKE_FAST"),
        env("OVERLAY_FAST_RETURN"),
        direct_after.as_millis(),
        block.as_secs(),
        stall_ab.as_millis(),
        stall_ba.as_millis(),
        floored,
        return_ms.map_or_else(|| "null".into(), |v| v.to_string()),
        heal_ab.as_millis(),
        heal_ba.as_millis(),
    );
    println!(
        "FAILOVER-TIMELINE a={} b={}",
        render(&tl_a.lock().unwrap(), cut),
        render(&tl_b.lock().unwrap(), cut)
    );
    assert!(floored > 0, "the stream never reached the /derp floor during the outage");
    assert!(
        stall_ab < block && stall_ba < block,
        "a direction stayed dark for the whole outage"
    );
}
