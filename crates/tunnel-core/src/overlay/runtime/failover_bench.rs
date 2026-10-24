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
//! `MH_FO_OBSERVE_S` (75), `MH_FO_JITTER_MS` (0: a random extra wait before
//! the cut, so repeated runs sample the runtime's 1 s / 5 s tick phases
//! instead of hitting the same one every time). Each plane binds ONE address of the shared netns
//! (`MH_FO_LAN_A`/`_B`, default the suite's veth 10.254.41.1/.2), because a
//! peer endpoint on one of our own addresses is never a LAN candidate; run
//! with `ROOMLERD_OVERLAY_DIRECT_PORT=0` so the two planes don't race a port.
//!
//! [`failover_wan_node`] is the same measurement split across two machines
//! (one runtime each, a real WAN path, real STUN), see its doc.

use super::tests::{MockTun, net, peer, synthetic_ipv4};
use super::*;
use crate::overlay::carrier_plane::CarrierPlane;
use crate::transport::derp::OutboundFrame;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
fn relay(
    from: [u8; 32],
    mut rx: mpsc::Receiver<OutboundFrame>,
    to: Arc<DerpMux>,
    seen: Stamps,
    copies: Stamps,
) {
    let to_pk = to.self_pubkey();
    tokio::spawn(async move {
        while let Some((_, frame)) = rx.recv().await {
            if frame.len() < 32 || frame[..32] != to_pk[..] {
                continue;
            }
            if frame[32..].starts_with(crate::transport::derp::STANDBY_MAGIC) {
                copies.lock().unwrap().push(Instant::now());
            } else if frame.len() - 32 >= BUSINESS_MIN_WG {
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
/// the transitions: which carrier each end believes it holds, whether an
/// upgrade probe is in flight (`+probe`), and when.
fn carrier_timeline(view: watch::Receiver<OverlayView>, log: Timeline, stop: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let mut last = String::new();
        while !stop.load(Ordering::Relaxed) {
            let now = view.borrow().peers.first().map_or_else(
                || "none".to_string(),
                |p| {
                    let probing = if p.upgrading { "+probe" } else { "" };
                    format!("{:?}/{}{probing}", p.connection, p.relay_kind.as_deref().unwrap_or("-"))
                },
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

    let (on_derp, copies): (Stamps, Stamps) = Default::default();
    relay(a.kp.public.to_bytes(), a.mux_out.take().unwrap(), b.mux.clone(), on_derp.clone(), copies.clone());
    relay(b.kp.public.to_bytes(), b.mux_out.take().unwrap(), a.mux.clone(), on_derp.clone(), copies.clone());
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
    let jitter_ms: u64 = std::env::var("MH_FO_JITTER_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if jitter_ms > 0 {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        tokio::time::sleep(Duration::from_millis(u64::from(nanos) % jitter_ms)).await;
    }
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
    let standby_copies = copies.lock().unwrap().len();
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
         \"heal_gap_ab_ms\":{},\"heal_gap_ba_ms\":{},\"standby_copies\":{}}}",
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
        standby_copies,
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

/// F0-WAN frame kinds on the node ↔ relay TCP link: `u32` BE length of
/// `kind ‖ body`, then `kind`, then `body`. The relay is a dumb pipe between
/// the first two connections (any TCP splice will do), so each node
/// addresses `/derp` frames to "the other end" implicitly.
const WAN_HELLO: u8 = 0;
const WAN_DERP: u8 = 1;
const WAN_CTL: u8 = 2;

async fn wan_read(rd: &mut tokio::net::tcp::OwnedReadHalf) -> Option<(u8, Vec<u8>)> {
    let len = rd.read_u32().await.ok()? as usize;
    if len == 0 || len > 1 << 20 {
        return None;
    }
    let mut buf = vec![0u8; len];
    rd.read_exact(&mut buf).await.ok()?;
    let kind = buf.remove(0);
    Some((kind, buf))
}

async fn wan_wait(ctl: &mut mpsc::UnboundedReceiver<String>, want: &str, secs: u64) -> String {
    match tokio::time::timeout(Duration::from_secs(secs), ctl.recv()).await {
        Ok(Some(s)) if s.starts_with(want) => s,
        other => panic!("expected {want:?} within {secs} s, got {other:?}"),
    }
}

fn wan_netmap(me: Ipv4Addr, network: &OverlayNetworkInfo, far: &NetmapPeer) -> OverlayEvent {
    OverlayEvent::Netmap {
        self_ip: me.to_string(),
        network: network.clone(),
        peers: vec![far.clone()],
        org_relay_discovery: false,
        path_trial_v1: false,
    }
}

fn flowing(seen: &Stamps, now: Instant) -> bool {
    seen.lock()
        .unwrap()
        .last()
        .is_some_and(|t| now - *t < Duration::from_millis(500))
}

fn derp_quiet(on_derp: &Stamps, now: Instant) -> bool {
    on_derp.lock().unwrap().last().is_none_or(|t| now - *t >= QUIET)
}

/// F0-WAN — one end of [`failover_stall_and_return`] per machine, so the
/// direct path is a real WAN path (real RTT, real NIC/NAT, real STUN-learned
/// srflx mapping, the fleet-default tier for two public hosts) instead of a
/// veth. Both runtimes are the production `new_relay` build; what stays fake
/// is the control plane and `/derp`: a TCP relay (`MH_FO_RELAY`, a plain
/// splice of two connections, ideally on a third host) carries the hello
/// (key + join endpoints), the `rc:overlay.srflx` adverts the server would
/// echo into each netmap, the `/derp` frames, and the run's control words.
///
/// Role `a` (`MH_FO_ROLE=a`) runs the clock: it waits until both directions
/// flow with `/derp` quiet, cuts after `DIRECT_GRACE` + 4 s (+ jitter) by
/// telling both planes to blackhole (as the local harness does), heals after
/// `MH_FO_BLOCK_S`, observes `MH_FO_OBSERVE_S`, then collects `b`'s numbers
/// (each end measures arrivals on its own clock, so no clock sync is needed;
/// `b`'s window lags `a`'s by one relay hop) and prints one `FAILOVER-WAN`
/// line. Other knobs: `MH_FO_BIND` (this host's NIC IPv4 for the plane),
/// `MH_FO_STUN` (comma-separated `stun:IP:port`), `MH_FO_JITTER_MS`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "F0-WAN: one end per machine; needs MH_FO_ROLE, MH_FO_RELAY, MH_FO_BIND"]
async fn failover_wan_node() {
    let role_a = match std::env::var("MH_FO_ROLE").as_deref() {
        Ok("a") => true,
        Ok("b") => false,
        other => panic!("MH_FO_ROLE must be a or b, got {other:?}"),
    };
    let relay_addr = std::env::var("MH_FO_RELAY").expect("MH_FO_RELAY=host:port");
    let bind: Ipv4Addr = std::env::var("MH_FO_BIND")
        .expect("MH_FO_BIND=this host's NIC IPv4")
        .parse()
        .expect("MH_FO_BIND");
    let stun: Vec<String> = std::env::var("MH_FO_STUN")
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();
    let block = env_secs("MH_FO_BLOCK_S", 25);
    let observe = env_secs("MH_FO_OBSERVE_S", 75);
    let (ip_a, ip_b) = (Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(100, 64, 0, 2));
    let (me, them) = if role_a { (ip_a, ip_b) } else { (ip_b, ip_a) };

    let mut n = Node::start(me, bind);
    let eps = n.joined().await;
    assert!(!eps.is_empty(), "no endpoint bound on {bind}");
    let sock = tokio::net::TcpStream::connect(&relay_addr)
        .await
        .expect("connect MH_FO_RELAY");
    sock.set_nodelay(true).ok();
    let (mut rd, mut wr) = sock.into_split();
    let (tx, mut txq) = mpsc::unbounded_channel::<(u8, Vec<u8>)>();
    tokio::spawn(async move {
        while let Some((kind, body)) = txq.recv().await {
            let mut f = Vec::with_capacity(5 + body.len());
            f.extend_from_slice(&(body.len() as u32 + 1).to_be_bytes());
            f.push(kind);
            f.extend_from_slice(&body);
            if wr.write_all(&f).await.is_err() {
                break;
            }
        }
    });
    let hello = serde_json::json!({
        "pk": hex::encode(n.kp.public.to_bytes()),
        "wg": n.kp.public_base64(),
        "eps": eps,
    });
    tx.send((WAN_HELLO, hello.to_string().into_bytes())).unwrap();
    let theirs = match tokio::time::timeout(Duration::from_secs(120), wan_read(&mut rd)).await {
        Ok(Some((WAN_HELLO, body))) => serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        other => panic!("no peer hello within 120 s: {other:?}"),
    };
    let peer_pk: [u8; 32] = hex::decode(theirs["pk"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let peer_eps: Vec<String> = serde_json::from_value(theirs["eps"].clone()).unwrap();
    println!("FAILOVER-ENDPOINTS me={eps:?} peer={peer_eps:?}");
    // The far end as the server's netmap names it; `node_id` stays fixed so
    // a re-sent netmap (srflx learned) upserts the same peer.
    let mut far = peer(&n.kp, &them.to_string());
    far.wg_public_key = theirs["wg"].as_str().unwrap().into();
    far.endpoints = peer_eps.clone();
    far.lan_endpoints = peer_eps;
    far.supports_derp = true;
    far.supports_derp_floor = true;
    let mut network = net();
    network.stun_urls = stun;
    n.events.send(wan_netmap(me, &network, &far)).await.unwrap();

    // `/derp` out: frames for the far end go down the pipe; business frames
    // and standby copies are stamped on the way out (each end stamps its
    // own direction).
    let (on_derp, copies): (Stamps, Stamps) = Default::default();
    let mut mux_out = n.mux_out.take().unwrap();
    {
        let (tx, on_derp, copies) = (tx.clone(), on_derp.clone(), copies.clone());
        tokio::spawn(async move {
            while let Some((_, frame)) = mux_out.recv().await {
                if frame.len() < 32 || frame[..32] != peer_pk[..] {
                    continue;
                }
                let body = &frame[32..];
                if body.starts_with(crate::transport::derp::STANDBY_MAGIC) {
                    copies.lock().unwrap().push(Instant::now());
                } else if body.len() >= BUSINESS_MIN_WG {
                    on_derp.lock().unwrap().push(Instant::now());
                }
                if tx.send((WAN_DERP, body.to_vec())).is_err() {
                    break;
                }
            }
        });
    }
    // Control out: the srflx advert the server would fold into the peer's
    // netmap.
    let mut out = n.out.take().unwrap();
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            while let Some(m) = out.recv().await {
                if let ClientMsg::OverlaySrflx { candidates, nat, .. } = m {
                    let j = serde_json::json!({ "c": candidates, "nat": nat });
                    let _ = tx.send((WAN_CTL, format!("srflx {j}").into_bytes()));
                }
            }
        });
    }
    // Pipe in: `/derp` frames into the mux, srflx adverts into a fresh
    // netmap, status words into `peer_ok`, everything else to the phases.
    let peer_ok: Arc<StdMutex<Option<Instant>>> = Default::default();
    let (ctl_tx, mut ctl) = mpsc::unbounded_channel::<String>();
    {
        let (mux, events, peer_ok) = (n.mux.clone(), n.events.clone(), peer_ok.clone());
        tokio::spawn(async move {
            while let Some((kind, body)) = wan_read(&mut rd).await {
                match kind {
                    WAN_DERP => {
                        let mut inbound = peer_pk.to_vec();
                        inbound.extend_from_slice(&body);
                        mux.deliver(&inbound);
                    }
                    WAN_CTL => {
                        let s = String::from_utf8_lossy(&body).into_owned();
                        if let Some(j) = s.strip_prefix("srflx ") {
                            let j: serde_json::Value = serde_json::from_str(j).unwrap();
                            far.srflx_endpoints = serde_json::from_value(j["c"].clone()).unwrap();
                            far.srflx_nat = j["nat"].as_str().map(str::to_string);
                            println!("FAILOVER-SRFLX peer={:?} nat={:?}", far.srflx_endpoints, far.srflx_nat);
                            if events.send(wan_netmap(me, &network, &far)).await.is_err() {
                                break;
                            }
                        } else if s == "st 1" {
                            *peer_ok.lock().unwrap() = Some(Instant::now());
                        } else if s != "st 0" && ctl_tx.send(s).is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        });
    }

    let stop = Arc::new(AtomicBool::new(false));
    let seen: Stamps = Default::default();
    arrivals(them, n.delivered.take().unwrap(), seen.clone());
    stream(me, them, n.inject.clone(), stop.clone());
    let tl: Timeline = Default::default();
    carrier_timeline(n.view.clone(), tl.clone(), stop.clone());
    // Status out: "st 1" while our direction arrives here and our `/derp`
    // carries none of our stream.
    {
        let (tx, seen, on_derp, stop) = (tx.clone(), seen.clone(), on_derp.clone(), stop.clone());
        tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let now = Instant::now();
                let ok = flowing(&seen, now) && derp_quiet(&on_derp, now);
                let _ = tx.send((WAN_CTL, if ok { "st 1" } else { "st 0" }.into()));
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
    }

    let t0 = Instant::now();
    let (cut, heal, end, direct_after) = if role_a {
        let direct_after = loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let now = Instant::now();
            let far_ok = peer_ok
                .lock()
                .unwrap()
                .is_some_and(|t| now - t < Duration::from_secs(1));
            if far_ok && flowing(&seen, now) && derp_quiet(&on_derp, now) && now - t0 >= QUIET {
                break now - t0;
            }
            assert!(
                now - t0 < Duration::from_secs(120),
                "never settled on direct within 120 s ({} of our frames on /derp)",
                on_derp.lock().unwrap().len()
            );
        };
        tokio::time::sleep(crate::overlay::lifecycle::DIRECT_GRACE + Duration::from_secs(4)).await;
        let jitter_ms: u64 = std::env::var("MH_FO_JITTER_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if jitter_ms > 0 {
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            tokio::time::sleep(Duration::from_millis(u64::from(nanos) % jitter_ms)).await;
        }
        tx.send((WAN_CTL, b"cut".to_vec())).unwrap();
        let cut = Instant::now();
        n.plane.blackhole.store(true, Ordering::Relaxed);
        tokio::time::sleep(block).await;
        tx.send((WAN_CTL, b"heal".to_vec())).unwrap();
        let heal = Instant::now();
        n.plane.blackhole.store(false, Ordering::Relaxed);
        tokio::time::sleep(observe).await;
        tx.send((WAN_CTL, b"stop".to_vec())).unwrap();
        (cut, heal, Instant::now(), Some(direct_after))
    } else {
        wan_wait(&mut ctl, "cut", 300).await;
        let cut = Instant::now();
        n.plane.blackhole.store(true, Ordering::Relaxed);
        wan_wait(&mut ctl, "heal", block.as_secs() + 60).await;
        let heal = Instant::now();
        n.plane.blackhole.store(false, Ordering::Relaxed);
        wan_wait(&mut ctl, "stop", observe.as_secs() + 60).await;
        (cut, heal, Instant::now(), None)
    };
    stop.store(true, Ordering::Relaxed);

    // This end's numbers, on its own clock: `in` = the far end's stream
    // arriving here, `out` = our stream on `/derp`.
    let seen = seen.lock().unwrap().clone();
    let on_derp = on_derp.lock().unwrap().clone();
    let last_on_derp = on_derp.iter().rev().find(|t| **t > heal).copied();
    let return_out = match last_on_derp {
        None => Some(0),
        Some(t) if end - t >= QUIET => Some((t - heal).as_millis() as u64),
        Some(_) => None,
    };
    let mine = serde_json::json!({
        "stall_in_ms": longest_gap(&seen, cut, heal).as_millis() as u64,
        "heal_gap_in_ms": longest_gap(&seen, heal, end).as_millis() as u64,
        "floor_out": on_derp.iter().filter(|t| **t > cut && **t <= heal).count(),
        "return_out_ms": return_out,
        "copies_out": copies.lock().unwrap().len(),
        "timeline": render(&tl.lock().unwrap(), cut),
    });
    if !role_a {
        tx.send((WAN_CTL, format!("result {mine}").into_bytes())).unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        println!("FAILOVER-WAN-B {mine}");
        return;
    }
    let b: serde_json::Value = serde_json::from_str(
        wan_wait(&mut ctl, "result ", 30).await.strip_prefix("result ").unwrap(),
    )
    .unwrap();
    let ret = |v: &serde_json::Value| v["return_out_ms"].as_u64();
    let return_ms = ret(&mine).zip(ret(&b)).map(|(x, y)| x.max(y));
    let env = |k: &str| std::env::var(format!("ROOMLERD_{k}")).unwrap_or_else(|_| "-".into());
    let line = serde_json::json!({
        "standby_copies_env": env("OVERLAY_STANDBY_COPIES"),
        "poke_fast": env("OVERLAY_BUSINESS_POKE_FAST"),
        "fast_return": env("OVERLAY_FAST_RETURN"),
        "direct_after_ms": direct_after.map(|d| d.as_millis() as u64),
        "block_s": block.as_secs(),
        "stall_ab_ms": b["stall_in_ms"],
        "stall_ba_ms": mine["stall_in_ms"],
        "floor_frames": mine["floor_out"].as_u64().unwrap_or(0) + b["floor_out"].as_u64().unwrap_or(0),
        "return_ms": return_ms,
        "heal_gap_ab_ms": b["heal_gap_in_ms"],
        "heal_gap_ba_ms": mine["heal_gap_in_ms"],
        "standby_copies": mine["copies_out"].as_u64().unwrap_or(0) + b["copies_out"].as_u64().unwrap_or(0),
    });
    println!("FAILOVER-WAN {line}");
    println!("FAILOVER-TIMELINE a={} b={}", mine["timeline"].as_str().unwrap(), b["timeline"].as_str().unwrap());
    assert!(
        mine["floor_out"].as_u64().unwrap_or(0) + b["floor_out"].as_u64().unwrap_or(0) > 0,
        "the stream never reached the /derp floor during the outage"
    );
}
