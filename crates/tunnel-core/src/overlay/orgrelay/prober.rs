// SPDX-License-Identifier: MPL-2.0
//! MeshHarbor #5 — this node's RTT to every org relay it may bind to, measured
//! before any session exists.
//!
//! The center ranks a pair's candidate relays by the sum of both members' RTT
//! (`plan_mint_candidates_reusing`), but it used to learn an RTT only from a
//! bind to a relay it had already minted for the member, so a pair's first
//! session went to an unmeasured relay. The full netmap now names the relays
//! this node may use (`OverlayNetworkInfo::relay_probe_targets`); this task
//! measures each and the runtime reports the results as ordinary
//! `rc:overlay.relay_probe` rows.
//!
//! #5 step B: a backbone-ready relay is also offered the LINES it may carry a
//! pair over (`backbone_probe_targets`: the exit relay at the edge's private
//! endpoint). Those are probed only on the backbone interface, from a socket
//! pinned to it, and only where the local backbone policy permits the
//! endpoint; with no such policy they are not probed at all, so a line is
//! never measured over the public path.
//!
//! A probe is the relay's unauthenticated echo ([`build_probe`], answered byte
//! for byte by the relay's responder), so it needs no session, secret or VNI,
//! and it cannot amplify. [`SAMPLES`] per endpoint stays inside the
//! responder's per-source budget (4 per 2 s).

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bson::oid::ObjectId;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, timeout};

use super::wire::{PROBE_TOKEN_LEN, build_probe, parse_probe};

/// How often every target is measured again: well inside the center's
/// 600-s `PROBE_TTL_SECS`, so a fresh RTT is always on file.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(240);
/// Echoes sent per endpoint; the minimum RTT is reported.
pub const SAMPLES: usize = 3;
/// How long one echo is waited for.
pub const SAMPLE_WAIT: Duration = Duration::from_millis(1500);
/// The VNI the probe frames carry. Any value answers; a probe is not a session.
const PROBE_VNI: u32 = 1;

/// One relay the netmap offered, with its endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub relay_node_id: ObjectId,
    pub endpoints: Vec<SocketAddr>,
    /// The backbone interface a line is probed on; `None` = the default route.
    pub via: Option<String>,
}

/// One endpoint's measurement: `None` when no echo came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub relay_node_id: ObjectId,
    pub endpoint: SocketAddr,
    pub rtt: Option<Duration>,
}

/// The netmap's targets as this module takes them; an endpoint that does not
/// parse is dropped. The lines (`backbone`) are kept only where `policy`, the
/// device's own backbone opt-in, permits the endpoint, and carry its
/// interface.
pub fn targets_from_wire(
    relays: &[meshharbor_remote_control::signaling::RelayProbeTargetWire],
    backbone: &[meshharbor_remote_control::signaling::RelayProbeTargetWire],
    policy: Option<&super::backbone::LocalBackbonePolicy>,
) -> Vec<Target> {
    let parse = |t: &meshharbor_remote_control::signaling::RelayProbeTargetWire| {
        t.endpoints
            .iter()
            .filter_map(|e| e.parse().ok())
            .collect::<Vec<SocketAddr>>()
    };
    let own = relays.iter().map(|t| Target {
        relay_node_id: t.relay_node_id,
        endpoints: parse(t),
        via: None,
    });
    let lines = policy.into_iter().flat_map(|p| {
        backbone.iter().map(move |t| Target {
            relay_node_id: t.relay_node_id,
            endpoints: parse(t).into_iter().filter(|e| p.permits(*e)).collect(),
            via: Some(p.interface.clone()),
        })
    });
    own.chain(lines)
        .filter(|t| !t.endpoints.is_empty())
        .collect()
}

/// The minimum echo RTT to `endpoint` over [`SAMPLES`] probes, on a socket of
/// its own (so concurrent endpoints never share a responder budget), pinned
/// to interface `via` when given.
pub async fn probe_rtt(endpoint: SocketAddr, via: Option<&str>) -> Option<Duration> {
    let bind: SocketAddr = if endpoint.is_ipv4() {
        "0.0.0.0:0".parse().ok()?
    } else {
        "[::]:0".parse().ok()?
    };
    let sock = match via {
        None => UdpSocket::bind(bind).await.ok()?,
        Some(interface) => {
            let std = std::net::UdpSocket::bind(bind).ok()?;
            super::backbone::pin_interface(&socket2::SockRef::from(&std), interface).ok()?;
            std.set_nonblocking(true).ok()?;
            UdpSocket::from_std(std).ok()?
        }
    };
    let mut best: Option<Duration> = None;
    let mut buf = [0u8; 256];
    for _ in 0..SAMPLES {
        let token: [u8; PROBE_TOKEN_LEN] = rand::random();
        let sent = Instant::now();
        if sock
            .send_to(&build_probe(PROBE_VNI, &token), endpoint)
            .await
            .is_err()
        {
            return best;
        }
        let deadline = sent + SAMPLE_WAIT;
        // Only this echo counts: another source, or a late echo of an earlier
        // sample, is skipped rather than timed.
        while let Ok(Ok((n, from))) = timeout(
            deadline.saturating_duration_since(Instant::now()),
            sock.recv_from(&mut buf),
        )
        .await
        {
            if from == endpoint && parse_probe(&buf[..n]).is_some_and(|(_, t)| t == token) {
                let rtt = sent.elapsed();
                best = Some(best.map_or(rtt, |b| b.min(rtt)));
                break;
            }
        }
    }
    best
}

/// Measure every endpoint of every target, concurrently.
pub async fn probe_all(targets: &[Target]) -> Vec<Outcome> {
    let jobs = targets.iter().flat_map(|t| {
        t.endpoints.iter().map(move |&endpoint| async move {
            Outcome {
                relay_node_id: t.relay_node_id,
                endpoint,
                rtt: probe_rtt(endpoint, t.via.as_deref()).await,
            }
        })
    });
    futures::future::join_all(jobs).await
}

/// Probe the current targets now, whenever they change, and every
/// [`PROBE_INTERVAL`]; hand each round to `results`. Ends when the runtime
/// drops either channel.
pub fn spawn(
    targets: watch::Receiver<Vec<Target>>,
    results: mpsc::Sender<Vec<Outcome>>,
) -> tokio::task::JoinHandle<()> {
    spawn_reactive(targets, results).0
}

const REACTIVE_GAP: Duration = Duration::from_secs(5);
const REACTIVE_ROUNDS: usize = 4;
const REACTIVE_PEERS: usize = 32;

fn next_periodic_deadline(previous: Instant, full_round: bool, now: Instant) -> Instant {
    if full_round {
        now + PROBE_INTERVAL
    } else {
        previous
    }
}

struct ReactivePeer {
    serial: u64,
    last_started: Option<Instant>,
    pending: bool,
}

#[derive(Default)]
struct ReactiveState {
    peers: HashMap<ObjectId, ReactivePeer>,
    pending: VecDeque<ObjectId>,
    // Keep the identity and serial for the same bounded sliding window, so
    // withdrawing and reoffering a target cannot discard its live budget.
    starts: VecDeque<(ObjectId, u64, Instant)>,
}

impl ReactiveState {
    fn retain_offered(&mut self, targets: &[Target]) {
        let offered: HashSet<_> = targets
            .iter()
            .filter(|t| !t.endpoints.is_empty())
            .map(|t| t.relay_node_id)
            .collect();
        self.peers.retain(|id, _| offered.contains(id));
        self.pending.retain(|id| offered.contains(id));
    }

    fn request(&mut self, id: ObjectId, serial: u64) -> bool {
        if let Some(peer) = self.peers.get_mut(&id) {
            if serial <= peer.serial {
                return false;
            }
            peer.serial = serial;
            if !peer.pending {
                peer.pending = true;
                self.pending.push_back(id);
            }
        } else {
            if self.peers.len() >= REACTIVE_PEERS {
                return false;
            }
            let recent = self.starts.iter().rev().find(|(peer, _, _)| *peer == id);
            if recent.is_some_and(|(_, previous, _)| serial <= *previous) {
                return false;
            }
            self.peers.insert(
                id,
                ReactivePeer {
                    serial,
                    last_started: recent.map(|(_, _, at)| *at),
                    pending: true,
                },
            );
            self.pending.push_back(id);
        }
        true
    }

    fn next(&mut self, now: Instant) -> Option<(ObjectId, Instant)> {
        while self
            .starts
            .front()
            .is_some_and(|(_, _, at)| now.saturating_duration_since(*at) >= REACTIVE_GAP)
        {
            self.starts.pop_front();
        }
        let global = if self.starts.len() >= REACTIVE_ROUNDS {
            self.starts[0].2 + REACTIVE_GAP
        } else {
            now
        };
        // Earliest eligible first; FIFO breaks ties so a chatty relay cannot
        // keep a different, ready relay behind its own cooldown.
        self.pending
            .iter()
            .filter_map(|id| {
                let peer = self.peers.get(id)?;
                let due = peer
                    .last_started
                    .map_or(now, |at| (at + REACTIVE_GAP).max(now));
                Some((*id, due.max(global)))
            })
            .min_by_key(|(_, due)| *due)
    }

    fn take_due(&mut self, now: Instant) -> Option<ObjectId> {
        let (id, due) = self.next(now)?;
        if due > now {
            return None;
        }
        self.pending.retain(|queued| *queued != id);
        let peer = self.peers.get_mut(&id)?;
        peer.pending = false;
        peer.last_started = Some(now);
        self.starts.push_back((id, peer.serial, now));
        Some(id)
    }
}

/// Bounded hints for relays in the current, policy-filtered target list.
/// A newer serial coalesces with an existing pending wake; duplicate or older
/// serials are ignored. At most 32 relay identities are retained until their
/// targets are withdrawn; a full table refuses new identities.
#[derive(Clone)]
pub struct ReactiveProbes {
    targets: watch::Receiver<Vec<Target>>,
    state: Arc<Mutex<ReactiveState>>,
    wakes: mpsc::Sender<()>,
}

impl ReactiveProbes {
    /// Retain a novel, currently offered hint without blocking or sending UDP.
    pub fn request(&self, relay_node_id: ObjectId, local_event_serial: u64) -> bool {
        if self.wakes.is_closed() || self.targets.has_changed().is_err() {
            return false;
        }
        let targets = self.targets.borrow();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.retain_offered(&targets);
        if !targets
            .iter()
            .any(|t| t.relay_node_id == relay_node_id && !t.endpoints.is_empty())
            || !state.request(relay_node_id, local_event_serial)
        {
            return false;
        }
        // A full wake channel already guarantees the task will inspect the
        // shared, coalesced state. Never block the runtime's control loop.
        !matches!(
            self.wakes.try_send(()),
            Err(mpsc::error::TrySendError::Closed(_))
        )
    }
}

/// Keep the ordinary initial/target-change/240-second rounds, and allow
/// targeted rounds without moving that periodic deadline. One relay round
/// includes all its offered public and permitted backbone targets. Reactive
/// rounds are limited to one per relay per five seconds and four total starts
/// in any sliding five-second window. All probing stays on this single task.
pub fn spawn_reactive(
    targets: watch::Receiver<Vec<Target>>,
    results: mpsc::Sender<Vec<Outcome>>,
) -> (tokio::task::JoinHandle<()>, ReactiveProbes) {
    spawn_reactive_with(targets, results, |targets| async move {
        probe_all(&targets).await
    })
}

fn spawn_reactive_with<F, Fut>(
    mut targets: watch::Receiver<Vec<Target>>,
    results: mpsc::Sender<Vec<Outcome>>,
    probe: F,
) -> (tokio::task::JoinHandle<()>, ReactiveProbes)
where
    F: Fn(Vec<Target>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Vec<Outcome>> + Send,
{
    let state = Arc::new(Mutex::new(ReactiveState::default()));
    let (wakes, mut wake_rx) = mpsc::channel(REACTIVE_PEERS);
    let handle = ReactiveProbes {
        targets: targets.clone(),
        state: state.clone(),
        wakes,
    };
    let task = tokio::spawn(async move {
        let mut periodic_due = Instant::now();
        let mut hints_open = true;
        loop {
            if results.is_closed() || targets.has_changed().is_err() {
                return;
            }
            if targets.has_changed().unwrap_or(false) {
                periodic_due = Instant::now();
            }
            let current = targets.borrow_and_update().clone();
            let now = Instant::now();
            let mut full_round = false;
            let round_targets = {
                let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
                state.retain_offered(&current);
                if now >= periodic_due {
                    full_round = true;
                    current
                } else if let Some(id) = state.take_due(now) {
                    current
                        .into_iter()
                        .filter(|t| t.relay_node_id == id && !t.endpoints.is_empty())
                        .collect()
                } else {
                    Vec::new()
                }
            };
            if !round_targets.is_empty() {
                let round = tokio::select! {
                    round = probe(round_targets) => round,
                    _ = results.closed() => return,
                };
                if results.send(round).await.is_err() {
                    return;
                }
            }
            // Measured from completion of an ordinary round; targeted rounds
            // never push the periodic sweep back, even under a hint storm.
            periodic_due = next_periodic_deadline(periodic_due, full_round, Instant::now());
            if full_round {
                continue;
            }
            let next_hint = state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .next(Instant::now())
                .map(|(_, due)| due);
            tokio::select! {
                changed = targets.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    periodic_due = Instant::now();
                }
                wake = wake_rx.recv(), if hints_open => {
                    if wake.is_none() {
                        hints_open = false;
                    }
                }
                _ = tokio::time::sleep_until(periodic_due) => {}
                _ = tokio::time::sleep_until(next_hint.unwrap_or(periodic_due)), if next_hint.is_some() => {}
                _ = results.closed() => return,
            }
        }
    });
    (task, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::orgrelay::bind::CookieKey;
    use crate::overlay::orgrelay::server::{RelayServer, RelayStats};
    use std::sync::Arc;

    #[test]
    fn reactive_rounds_obey_sliding_global_budget_and_fair_peer_cooldowns() {
        let now = Instant::now();
        let ids: Vec<_> = (0..6).map(|_| ObjectId::new()).collect();
        let mut state = ReactiveState::default();
        for &id in &ids {
            assert!(state.request(id, 1));
        }
        for &id in &ids[..4] {
            assert_eq!(state.take_due(now), Some(id));
        }
        assert_eq!(
            state.take_due(now + REACTIVE_GAP - Duration::from_nanos(1)),
            None
        );
        assert!(!state.request(ids[0], 1));
        assert!(state.request(ids[0], 2));
        assert!(state.request(ids[0], 3));
        assert_eq!(state.pending.iter().filter(|id| **id == ids[0]).count(), 1);
        // Older, ready peers go first; the busy first relay cannot jump them.
        assert_eq!(state.take_due(now + REACTIVE_GAP), Some(ids[4]));
        assert_eq!(state.take_due(now + REACTIVE_GAP), Some(ids[5]));
        assert_eq!(state.take_due(now + REACTIVE_GAP), Some(ids[0]));
        assert!(state.request(ids[0], 4));
        assert_eq!(state.take_due(now + REACTIVE_GAP), None);
        assert_eq!(state.take_due(now + REACTIVE_GAP * 2), Some(ids[0]));
        assert_eq!(
            state.take_due(now + REACTIVE_GAP * 10),
            None,
            "a consumed serial must not leave a delayed duplicate"
        );

        // A fixed five-second bucket would incorrectly allow eight starts
        // across this boundary. The sliding window keeps all four live.
        let mut boundary = ReactiveState::default();
        for &id in &ids {
            assert!(boundary.request(id, 1));
        }
        let late = now + REACTIVE_GAP - Duration::from_millis(1);
        for _ in 0..4 {
            assert!(boundary.take_due(late).is_some());
        }
        assert_eq!(boundary.take_due(now + REACTIVE_GAP), None);
        assert!(boundary.take_due(late + REACTIVE_GAP).is_some());
    }

    #[test]
    fn reactive_hints_coalesce_and_withdrawal_releases_bounded_identity_state() {
        let id = ObjectId::new();
        let targets = vec![Target {
            relay_node_id: id,
            endpoints: vec!["127.0.0.1:9".parse().unwrap()],
            via: None,
        }];
        let now = Instant::now();
        let mut state = ReactiveState::default();
        assert!(state.request(id, 10));
        assert_eq!(state.take_due(now), Some(id));
        assert!(!state.request(id, 10));
        assert!(!state.request(id, 9));
        assert!(state.request(id, 11));
        assert!(state.request(id, 12));
        assert_eq!(state.pending.len(), 1);
        assert_eq!(
            state.take_due(now + REACTIVE_GAP - Duration::from_nanos(1)),
            None
        );
        assert_eq!(state.take_due(now + REACTIVE_GAP), Some(id));
        assert_eq!(state.take_due(now + REACTIVE_GAP * 2), None);
        assert!(state.request(id, 13));
        state.retain_offered(&[]);
        assert!(state.peers.is_empty() && state.pending.is_empty());
        assert_eq!(state.take_due(now + REACTIVE_GAP * 3), None);

        for _ in 0..REACTIVE_PEERS {
            assert!(state.request(ObjectId::new(), 1));
        }
        assert!(
            !state.request(id, 14),
            "never evict a live clock to admit a 33rd identity"
        );
        state.retain_offered(&targets);
        assert!(state.request(id, 14));
        assert_eq!(state.peers.len(), 1);
    }

    #[test]
    fn withdrawing_and_reoffering_a_relay_cannot_reset_its_live_probe_budget() {
        let id = ObjectId::new();
        let now = Instant::now();
        let targets = vec![Target {
            relay_node_id: id,
            endpoints: vec!["127.0.0.1:9".parse().unwrap()],
            via: None,
        }];
        let mut state = ReactiveState::default();
        assert!(state.request(id, 10));
        assert_eq!(state.take_due(now), Some(id));
        state.retain_offered(&[]);
        state.retain_offered(&targets);
        assert!(
            !state.request(id, 10),
            "withdrawing a target must not replay its dispatched hint"
        );
        assert!(state.request(id, 11));
        assert_eq!(state.take_due(now + Duration::from_secs(1)), None);
        assert_eq!(state.take_due(now + REACTIVE_GAP), Some(id));
    }

    #[tokio::test(start_paused = true)]
    async fn targeted_rounds_leave_the_ordinary_periodic_deadline_unchanged() {
        // Exercise the actual scheduling task with an empty-result runner.
        // Real UDP and positive reachability have separate integration tests.
        let start = Instant::now();
        let id = ObjectId::new();
        let (targets, target_rx) = watch::channel(vec![Target {
            relay_node_id: id,
            endpoints: vec!["127.0.0.1:9".parse().unwrap()],
            via: None,
        }]);
        let (results, mut rounds) = mpsc::channel(8);
        let (task, hints) = spawn_reactive_with(target_rx, results, |_| async { Vec::new() });
        assert_eq!(rounds.recv().await, Some(Vec::new()));
        assert_eq!(Instant::now(), start);
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(hints.request(id, 1));
        assert_eq!(rounds.recv().await, Some(Vec::new()));
        assert_eq!(Instant::now(), start + Duration::from_secs(60));
        tokio::time::advance(Duration::from_secs(179)).await;
        tokio::task::yield_now().await;
        assert!(matches!(
            rounds.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(rounds.recv().await, Some(Vec::new()));
        assert_eq!(
            Instant::now(),
            start + PROBE_INTERVAL,
            "reactive traffic cannot starve the periodic round"
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        drop(targets);
    }

    #[tokio::test]
    async fn targeted_real_probe_leaves_the_other_offered_relay_quiet() {
        let mut servers = Vec::new();
        let mut targets = Vec::new();
        let mut stats = Vec::new();
        for _ in 0..3 {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let counts = Arc::new(RelayStats::default());
            let (server, _handle) =
                RelayServer::new(CookieKey::from_bytes([3; 32]), counts.clone());
            targets.push(Target {
                relay_node_id: ObjectId::new(),
                endpoints: vec![socket.local_addr().unwrap()],
                via: None,
            });
            stats.push(counts);
            servers.push((tokio::spawn(server.serve(socket)), _handle));
        }
        // Distinct offered rows (as public/backbone rows can be) belonging to
        // the same relay must be dispatched together as a single relay round.
        targets[1].relay_node_id = targets[0].relay_node_id;
        let (target_tx, target_rx) = watch::channel(targets.clone());
        let (result_tx, mut result_rx) = mpsc::channel(4);
        let (task, reactive) = spawn_reactive(target_rx, result_tx);
        let initial = timeout(Duration::from_secs(5), result_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(initial.len(), 3);
        assert!(initial.iter().all(|o| o.rtt.is_some()));
        let unrelated = stats[2].probe.snapshot();
        let id = targets[0].relay_node_id;
        assert!(!reactive.request(ObjectId::new(), 1));
        assert!(reactive.request(id, 1));
        assert!(!reactive.request(id, 1));
        let targeted = timeout(Duration::from_secs(5), result_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(targeted.len(), 2);
        assert!(
            targeted
                .iter()
                .all(|o| o.relay_node_id == id && o.rtt.is_some())
        );
        assert_eq!(stats[2].probe.snapshot(), unrelated);

        // A novel hint waits inside the per-relay gap. Withdraw its authority
        // before dispatch: the ordinary changed-target round probes only B.
        assert!(reactive.request(id, 2));
        assert!(reactive.request(id, 3));
        target_tx.send_replace(vec![targets[2].clone()]);
        assert!(!reactive.request(id, 4));
        let changed = timeout(Duration::from_secs(5), result_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].relay_node_id, targets[2].relay_node_id);
        let withdrawn = [stats[0].probe.snapshot(), stats[1].probe.snapshot()];
        assert!(
            timeout(REACTIVE_GAP + Duration::from_millis(50), result_rx.recv())
                .await
                .is_err()
        );
        assert_eq!(
            [stats[0].probe.snapshot(), stats[1].probe.snapshot()],
            withdrawn
        );
        drop(target_tx);
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        for (server, _handle) in servers {
            server.abort();
            let _ = server.await;
        }
    }

    #[tokio::test]
    async fn reactive_task_ends_when_results_close_even_with_no_targets() {
        let (_target_tx, target_rx) = watch::channel(Vec::new());
        let (result_tx, result_rx) = mpsc::channel(1);
        let (task, reactive) = spawn_reactive(target_rx, result_tx);
        drop(result_rx);
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(!reactive.request(ObjectId::new(), 1));
    }

    #[tokio::test]
    async fn reactive_policy_refused_line_never_sends_udp() {
        use meshharbor_remote_control::signaling::RelayProbeTargetWire;
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let id = ObjectId::new();
        let offered = targets_from_wire(
            &[],
            &[RelayProbeTargetWire {
                relay_node_id: id,
                endpoints: vec![socket.local_addr().unwrap().to_string()],
            }],
            None,
        );
        assert!(offered.is_empty(), "no local policy authorizes this line");
        let (target_tx, target_rx) = watch::channel(offered);
        let (result_tx, _result_rx) = mpsc::channel(1);
        let (task, reactive) = spawn_reactive(target_rx, result_tx);
        assert!(!reactive.request(id, 1));
        let mut packet = [0; 128];
        assert!(
            timeout(Duration::from_millis(50), socket.recv_from(&mut packet))
                .await
                .is_err()
        );
        drop(target_tx);
        timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(!reactive.request(id, 2));
    }

    #[tokio::test]
    async fn a_relay_answers_a_probe_and_a_silent_endpoint_does_not() {
        let relay_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay = relay_sock.local_addr().unwrap();
        let (server, _handle) = RelayServer::new(
            CookieKey::from_bytes([1; 32]),
            Arc::new(RelayStats::default()),
        );
        tokio::spawn(server.serve(relay_sock));
        // A bound socket nobody reads: the probe goes nowhere.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_ep = silent.local_addr().unwrap();

        let id = ObjectId::new();
        let out = probe_all(&[Target {
            relay_node_id: id,
            endpoints: vec![relay, silent_ep],
            via: None,
        }])
        .await;
        assert_eq!(out.len(), 2);
        let rtt = out.iter().find(|o| o.endpoint == relay).unwrap().rtt;
        assert!(
            rtt.is_some_and(|r| r < SAMPLE_WAIT),
            "the relay echoes: {rtt:?}"
        );
        assert_eq!(
            out.iter().find(|o| o.endpoint == silent_ep).unwrap().rtt,
            None
        );
    }

    #[tokio::test]
    async fn the_task_measures_new_targets_at_once() {
        let relay_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay = relay_sock.local_addr().unwrap();
        let (server, _handle) = RelayServer::new(
            CookieKey::from_bytes([2; 32]),
            Arc::new(RelayStats::default()),
        );
        tokio::spawn(server.serve(relay_sock));

        let (tx, rx) = watch::channel(Vec::new());
        let (res_tx, mut res_rx) = mpsc::channel(4);
        let task = spawn(rx, res_tx);
        let id = ObjectId::new();
        tx.send_replace(vec![Target {
            relay_node_id: id,
            endpoints: vec![relay],
            via: None,
        }]);
        let round = timeout(Duration::from_secs(5), res_rx.recv())
            .await
            .expect("a round within 5 s")
            .unwrap();
        assert_eq!(round.len(), 1);
        assert_eq!(round[0].relay_node_id, id);
        assert!(round[0].rtt.is_some());
        drop(tx);
        timeout(Duration::from_secs(2), task)
            .await
            .expect("the task ends with its runtime")
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_line_is_probed_only_where_the_backbone_policy_permits_it() {
        use meshharbor_remote_control::signaling::RelayProbeTargetWire;
        let (relay, exit) = (ObjectId::new(), ObjectId::new());
        let own = [RelayProbeTargetWire {
            relay_node_id: relay,
            endpoints: vec!["203.0.113.7:3478".into()],
        }];
        let lines = [RelayProbeTargetWire {
            relay_node_id: exit,
            endpoints: vec!["10.42.2.114:3478".into(), "192.0.2.9:3478".into()],
        }];
        // No local opt-in: a line is never measured, least of all over the
        // public path.
        let none = targets_from_wire(&own, &lines, None);
        assert_eq!(none.len(), 1);
        assert_eq!(
            (none[0].relay_node_id, none[0].via.as_deref()),
            (relay, None)
        );

        let policy = super::super::backbone::LocalBackbonePolicy {
            enabled: true,
            interface: "eth1".into(),
            allowed_cidrs: vec!["10.42.0.0/16".parse().unwrap()],
            overlay_cidrs: vec!["100.64.0.0/10".parse().unwrap()],
        };
        let with = targets_from_wire(&own, &lines, Some(&policy));
        assert_eq!(with.len(), 2);
        let line = with.iter().find(|t| t.relay_node_id == exit).unwrap();
        assert_eq!(
            line.via.as_deref(),
            Some("eth1"),
            "pinned to the backbone NIC"
        );
        assert_eq!(
            line.endpoints,
            vec!["10.42.2.114:3478".parse::<SocketAddr>().unwrap()],
            "an endpoint outside the allowed CIDRs is dropped"
        );
    }
}
