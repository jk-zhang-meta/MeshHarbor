// SPDX-License-Identifier: MPL-2.0
//! Bilateral path trials: identical authenticated echo metrics on the incumbent
//! and shadow; the server's two-member Commit is the only promotion authority.
use super::*;
use crate::overlay::{
    disco,
    orgrelay::{client::OrgRelayConn, member::OrgSession},
};
use crate::transport::relay::RelayConn;
use roomler_ai_remote_control::signaling::{OrgRelayCandidateWire, ServerMsg};

mod observation;
pub(super) use observation::{
    ViewGuard as ObservationViewGuard, clear_view as clear_observation_view,
    publish_view as publish_observation_view,
};
const ROUND_GAP: Duration = Duration::from_millis(500);
const ROUND_TIMEOUT: Duration = Duration::from_millis(900);
const PREPARE_TIMEOUT: Duration = Duration::from_secs(30);
const SAMPLE_FRESH: Duration = Duration::from_secs(10);
const MAX_TRIALS: usize = 4;

pub(super) fn enabled() -> bool {
    crate::env::flag("PATH_TRIAL", false)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Binding,
    Measuring,
    Ready,
    Committed,
    Finalized,
    ReturnPreparing,
    ReturnReady,
    Returned,
}
#[derive(Clone, Copy)]
enum ProbePath {
    Direct,
    Relay,
}
#[derive(Clone, Copy)]
struct Attempt {
    nonce: [u8; 8],
    at: Instant,
    dst: Option<SocketAddr>,
    result: Option<Option<f64>>,
}
struct Round {
    direct: Attempt,
    relay: Attempt,
}
#[derive(Default)]
struct Measurements {
    round: Option<Round>,
    windows: Vec<(Option<f64>, Option<f64>, Instant)>,
    good: u8,
    direct_good: u8,
    fresh_good: Option<Instant>,
    last_round: Option<Instant>,
    seq: u64,
}
impl Measurements {
    fn frame(&mut self, key: &WgKeypair, peer: &[u8; 32], now: Instant) -> (Attempt, Vec<u8>) {
        // Distinct, monotonically increasing nonces within this trial. Seeded
        // randomly below so trials/engines cannot credit one another's pongs.
        self.seq = self
            .seq
            .checked_add(1)
            .expect("trial nonce space exhausted");
        let nonce = self.seq.to_be_bytes();
        (
            Attempt {
                nonce,
                at: now,
                dst: None,
                result: None,
            },
            disco::build(
                disco::KIND_PING,
                nonce,
                key.public.as_bytes(),
                None,
                &disco::shared_secret(&key.secret, &boringtun::x25519::PublicKey::from(*peer)),
            ),
        )
    }
    fn pong(&mut self, path: ProbePath, expected: &[u8; 32], p: &disco::DiscoInbound) {
        let Some(round) = self.round.as_mut() else {
            return;
        };
        let a = match path {
            ProbePath::Direct => &mut round.direct,
            ProbePath::Relay => &mut round.relay,
        };
        if a.result.is_none()
            && p.sender == *expected
            && p.nonce == a.nonce
            && Some(p.src) == a.dst
            && p.at.saturating_duration_since(a.at) <= ROUND_TIMEOUT
        {
            a.result = Some(Some(
                p.at.saturating_duration_since(a.at).as_secs_f64() * 1000.0,
            ));
        }
    }
    fn finish(&mut self, now: Instant) {
        let Some(r) = self.round.as_mut() else { return };
        for a in [&mut r.direct, &mut r.relay] {
            if a.result.is_none() && now.saturating_duration_since(a.at) >= ROUND_TIMEOUT {
                a.result = Some(None);
            }
        }
        if r.direct.result.is_none() || r.relay.result.is_none() {
            return;
        }
        let r = self.round.take().unwrap();
        self.windows.push((
            r.direct.result.unwrap(),
            r.relay.result.unwrap(),
            r.direct.at.min(r.relay.at),
        ));
        if self.windows.len() > 9 {
            self.windows.remove(0);
        }
        let median = |mut v: Vec<f64>| {
            v.sort_by(f64::total_cmp);
            v[v.len() / 2]
        };
        // Three consecutive paired windows; each failed write/timeout stays in
        // the denominator. Freshness is the actual send time, never dequeue time.
        let good = self.windows.len() == 9
            && self.windows.chunks(3).all(|w| {
                let d: Vec<_> = w.iter().filter_map(|p| p.0).collect();
                let c: Vec<_> = w.iter().filter_map(|p| p.1).collect();
                d.len() >= 2 && c.len() >= d.len() && {
                    let (d, c) = (median(d), median(c));
                    c <= d * 0.75 && d - c >= 20.0
                }
            });
        let direct_good = self.windows.len() == 9
            && self.windows.chunks(3).all(|w| {
                let d: Vec<_> = w.iter().filter_map(|p| p.0).collect();
                let r: Vec<_> = w.iter().filter_map(|p| p.1).collect();
                d.len() >= 2
                    && d.len() >= r.len()
                    && (r.is_empty() || median(d) <= median(r) * 1.10)
            });
        self.direct_good = if direct_good { 3 } else { 0 };
        self.good = if good { 3 } else { 0 };
        self.fresh_good = (good || direct_good).then(|| self.windows[0].2);
    }
    fn return_ready(&self, now: Instant) -> bool {
        self.direct_good >= 3
            && self
                .fresh_good
                .is_some_and(|at| now.saturating_duration_since(at) <= SAMPLE_FRESH)
    }
    fn ready(&self, now: Instant) -> bool {
        self.good >= 3
            && self
                .fresh_good
                .is_some_and(|at| now.saturating_duration_since(at) <= SAMPLE_FRESH)
    }
}
#[derive(Clone)]
struct RequestedCandidate {
    peer_id: ObjectId,
    request_id: u64,
    identity: (String, String),
    candidate: OrgRelayCandidateWire,
    at: Instant,
}
struct Trial {
    peer_id: ObjectId,
    peer: PeerConfig,
    original: Installed,
    started: Instant,
    phase: Phase,
    conn: Option<Arc<OrgRelayConn>>,
    measurements: Measurements,
    committed_since: Option<Instant>,
    last_control: Instant,
    return_id: Option<ObjectId>,
    return_retired: Vec<ObjectId>,
    return_started: Option<Instant>,
    next_return: Instant,
    // One retained-shadow attempt at a time, paced by the existing tier's
    // handshake deadline. This does not renew the relay session/grant.
    direct_refreshed: Option<Instant>,
    requested: Option<RequestedCandidate>,
}
pub(super) struct Bound {
    id: ObjectId,
    conn: Option<Arc<OrgRelayConn>>,
}
pub(super) struct Engine {
    observation: observation::Observation,
    trials: HashMap<ObjectId, Trial>,
    retired: Vec<ObjectId>,
    tx: mpsc::Sender<Bound>,
    rx: mpsc::Receiver<Bound>,
    serial: u64,
    next_request: Instant,
    pending_request: Option<RequestedCandidate>,
    failed_requests: Vec<RequestedCandidate>,
}
impl Engine {
    pub(super) fn new() -> Self {
        let (tx, rx) = mpsc::channel(MAX_TRIALS * 2);
        Self {
            observation: observation::Observation::new(),
            trials: HashMap::new(),
            retired: Vec::new(),
            tx,
            rx,
            serial: rand::random::<u64>() / 2,
            next_request: Instant::now(),
            pending_request: None,
            failed_requests: Vec::new(),
        }
    }
    fn current(
        t: &Trial,
        peers: &HashMap<ObjectId, NetmapPeer>,
        installed: &HashMap<ObjectId, Installed>,
    ) -> bool {
        peers
            .get(&t.peer_id)
            .and_then(peer_config_from_netmap)
            .is_some_and(|p| p.public_key == t.peer.public_key && p.overlay_ip == t.peer.overlay_ip)
            && installed.get(&t.peer_id).is_some_and(|p| {
                p.pubkey == t.peer.public_key
                    && p.overlay_ip == t.peer.overlay_ip
                    && p.since == t.committed_since.unwrap_or(t.original.since)
            })
    }
    async fn send(out: &ControlTx, msg: ClientMsg) -> bool {
        matches!(
            tokio::time::timeout(Duration::from_millis(10), out.send(msg)).await,
            Ok(Ok(()))
        )
    }
    pub(super) fn active_pong(&mut self, p: &disco::DiscoInbound) {
        for t in self.trials.values_mut() {
            t.measurements
                .pong(ProbePath::Direct, &t.peer.public_key, p);
        }
    }
    fn retired(&mut self, id: ObjectId) {
        self.retired.push(id);
        if self.retired.len() > 128 {
            self.retired.remove(0);
        }
    }
    async fn cancel(
        &mut self,
        id: ObjectId,
        ctx: &OverlayRuntime,
        wg: &mut WgDevice,
        peers: &HashMap<ObjectId, NetmapPeer>,
        installed: &mut HashMap<ObjectId, Installed>,
        notify: bool,
    ) {
        let Some(t) = self.trials.remove(&id) else {
            return;
        };
        if matches!(t.phase, Phase::Binding | Phase::Measuring | Phase::Ready) {
            if let Some(requested) = t.requested.clone() {
                if self.failed_requests.len() >= MAX_TRIALS {
                    self.failed_requests.remove(0);
                }
                self.failed_requests.push(requested);
            }
        }
        let current = Self::current(&t, peers, installed);
        // A revoked/removed/rekeyed trial may never restore the captured peer.
        // Retire only the exact owned Tunn; never remove an unrelated newer peer.
        let removed_active = wg.retire_path_trial(id).await;
        if current && removed_active {
            installed.remove(&t.peer_id);
        }
        if let Some(c) = t.conn {
            c.close();
        }
        ctx.path_trial_managed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&t.peer_id);
        self.retired(id);
        if notify && enabled() && ctx.org_primary {
            Self::send(
                &ctx.outbound,
                ClientMsg::OverlayPathTrialAbort { trial_id: id },
            )
            .await;
        }
    }
    pub(super) async fn control(
        &mut self,
        msg: ServerMsg,
        ctx: &OverlayRuntime,
        wg: &mut WgDevice,
        peers: &HashMap<ObjectId, NetmapPeer>,
        installed: &mut HashMap<ObjectId, Installed>,
        supported: bool,
    ) {
        self.control_enabled(msg, ctx, wg, peers, installed, supported, enabled())
            .await;
    }
    async fn control_enabled(
        &mut self,
        msg: ServerMsg,
        ctx: &OverlayRuntime,
        wg: &mut WgDevice,
        peers: &HashMap<ObjectId, NetmapPeer>,
        installed: &mut HashMap<ObjectId, Installed>,
        supported: bool,
        local_enabled: bool,
    ) {
        let before = self.observation_phases();
        let event = observation::event(&msg);
        self.control_enabled_inner(msg, ctx, wg, peers, installed, supported, local_enabled)
            .await;
        if local_enabled && supported && ctx.org_primary {
            let after = self.observation_phases();
            self.observation.record(before, after, event);
        } else {
            self.observation.reset(if !local_enabled {
                crate::localapi::PathTrialResetReason::HandleLocalDisabled
            } else if !supported {
                crate::localapi::PathTrialResetReason::HandleServerUnsupported
            } else {
                crate::localapi::PathTrialResetReason::HandleNonPrimary
            });
        }
    }
    async fn control_enabled_inner(
        &mut self,
        msg: ServerMsg,
        ctx: &OverlayRuntime,
        wg: &mut WgDevice,
        peers: &HashMap<ObjectId, NetmapPeer>,
        installed: &mut HashMap<ObjectId, Installed>,
        supported: bool,
        local_enabled: bool,
    ) {
        match msg {
            ServerMsg::OverlayPathTrialStart {
                trial_id,
                request_id,
                peer_node_id,
                peer_wg_public_key,
                vni,
                generation,
                relay_node_id,
                relay_endpoints,
                bind_secret,
                bind_secs,
                max_lifetime_secs,
                ..
            } => {
                if !local_enabled || !ctx.org_primary || !supported {
                    return;
                }
                if self.trials.contains_key(&trial_id) || self.retired.contains(&trial_id) {
                    return;
                }
                let allowed = local_enabled
                    && ctx.org_primary
                    && supported
                    && self.trials.len() < MAX_TRIALS
                    && !self.trials.values().any(|t| t.peer_id == peer_node_id);
                let config = peers.get(&peer_node_id).and_then(peer_config_from_netmap);
                let original = installed
                    .get(&peer_node_id)
                    .filter(|p| p.is_direct && !p.stalled)
                    .cloned();
                let session = OrgSession::from_wire(
                    vni,
                    generation,
                    relay_node_id,
                    &relay_endpoints,
                    &bind_secret,
                    bind_secs,
                    max_lifetime_secs,
                );
                let Some((peer, original, session)) = config
                    .zip(original)
                    .zip(session)
                    .map(|((p, o), s)| (p, o, s))
                else {
                    Self::send(&ctx.outbound, ClientMsg::OverlayPathTrialAbort { trial_id }).await;
                    return;
                };
                if !allowed
                    || super::super::decode_public(&peer_wg_public_key) != Some(peer.public_key)
                    || original.pubkey != peer.public_key
                    || original.overlay_ip != peer.overlay_ip
                {
                    Self::send(&ctx.outbound, ClientMsg::OverlayPathTrialAbort { trial_id }).await;
                    return;
                }
                let now = Instant::now();
                let requested = self
                    .pending_request
                    .as_ref()
                    .filter(|r| {
                        r.request_id == request_id
                            && r.peer_id == peer_node_id
                            && r.candidate.relay_node_id == relay_node_id
                            && now.saturating_duration_since(r.at) < PREPARE_TIMEOUT
                            && peers.get(&peer_node_id).is_some_and(|p| {
                                (p.wg_public_key.clone(), p.overlay_ip.clone()) == r.identity
                            })
                    })
                    .cloned();
                if requested.is_some() {
                    self.pending_request = None;
                }
                self.trials.insert(
                    trial_id,
                    Trial {
                        peer_id: peer_node_id,
                        peer,
                        original,
                        started: now,
                        phase: Phase::Binding,
                        conn: None,
                        measurements: Measurements {
                            seq: rand::random::<u64>() / 2,
                            ..Default::default()
                        },
                        committed_since: None,
                        last_control: now,
                        return_id: None,
                        return_retired: Vec::new(),
                        return_started: None,
                        next_return: now + Duration::from_secs(15),
                        direct_refreshed: None,
                        requested,
                    },
                );
                let tx = self.tx.clone();
                tokio::spawn(async move {
                    use crate::overlay::orgrelay::client::{BindError, bind_any};
                    let conn = match bind_any(
                        &session.endpoints,
                        session.vni,
                        session.generation,
                        &session.secret,
                        crate::overlay::orgrelay::member::per_endpoint_budget(
                            session.bind_budget,
                            session.endpoints.len(),
                        ),
                    )
                    .await
                    {
                        Ok((sock, relay, _)) => Some(Arc::new(OrgRelayConn::new(
                            Arc::new(sock),
                            relay,
                            session.vni,
                            "path-trial".into(),
                        ))),
                        Err((error, _)) => {
                            // Log typed metadata only, never error/credential context.
                            let (failure_class, io_error) = match &error {
                                BindError::Timeout => ("timeout", None),
                                BindError::Unreachable(error) => ("unreachable", Some(error)),
                                BindError::NoEndpoint => ("no_endpoint", None),
                                BindError::Io(error) => ("io", Some(error)),
                            };
                            tracing::warn!(
                                %trial_id,
                                stage = "bind_any",
                                failure_class,
                                io_kind = ?io_error.map(std::io::Error::kind),
                                os_code = ?io_error.and_then(std::io::Error::raw_os_error),
                                "path-trial candidate bind failed"
                            );
                            None
                        }
                    };
                    if let Err(e) = tx.send(Bound { id: trial_id, conn }).await {
                        if let Some(c) = e.0.conn {
                            c.close();
                        }
                    }
                });
            }
            ServerMsg::OverlayPathTrialCommit { trial_id } => {
                let Some(t) = self.trials.get_mut(&trial_id) else {
                    return;
                };
                if !local_enabled || !ctx.org_primary || !supported {
                    return;
                }
                if !Self::current(t, peers, installed) {
                    self.cancel(trial_id, ctx, wg, peers, installed, true).await;
                    return;
                }
                if matches!(
                    t.phase,
                    Phase::ReturnPreparing | Phase::ReturnReady | Phase::Returned
                ) {
                    return;
                }
                if matches!(t.phase, Phase::Committed | Phase::Finalized) {
                    Self::send(
                        &ctx.outbound,
                        ClientMsg::OverlayPathTrialCommitted { trial_id },
                    )
                    .await;
                    return;
                }
                if t.phase != Phase::Ready
                    || !Self::current(t, peers, installed)
                    || !t.measurements.ready(Instant::now())
                    || !wg.commit_path_trial(trial_id)
                {
                    self.cancel(trial_id, ctx, wg, peers, installed, true).await;
                    return;
                }
                let now = Instant::now();
                installed.insert(
                    t.peer_id,
                    Installed {
                        hs_done: true,
                        initiated: true,
                        relay_kind: Some(RelayKind::Org),
                        carrier_local: t.conn.as_ref().and_then(|c| c.local_addr().ok()),
                        carrier_dst: t.conn.as_ref().map(|c| c.synth_peer()),
                        ..Installed::base(
                            t.peer.public_key,
                            t.peer.overlay_ip,
                            DirectTier::Relay,
                            now,
                        )
                    },
                );
                t.committed_since = Some(now);
                t.phase = Phase::Committed;
                t.last_control = now;
                ctx.path_trial_managed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(t.peer_id);
                Self::send(
                    &ctx.outbound,
                    ClientMsg::OverlayPathTrialCommitted { trial_id },
                )
                .await;
            }
            ServerMsg::OverlayPathTrialFinalize { trial_id } => {
                if let Some(t) = self.trials.get_mut(&trial_id) {
                    if t.phase == Phase::Committed
                        && Self::current(t, peers, installed)
                        && wg.finalize_path_trial(trial_id)
                    {
                        t.phase = Phase::Finalized;
                    }
                }
            }
            ServerMsg::OverlayPathTrialReturnPrepare {
                trial_id,
                return_id,
            } => {
                if !local_enabled || !ctx.org_primary || !supported {
                    return;
                }
                let Some(t) = self.trials.get_mut(&trial_id) else {
                    return;
                };
                if !Self::current(t, peers, installed) || t.return_retired.contains(&return_id) {
                    return;
                }
                if let Some(current) = t.return_id {
                    if current != return_id {
                        // A local request is only a proposal. The server's
                        // authenticated Prepare chooses the winning attempt
                        // when both members request simultaneously. Once we
                        // prepared/returned, never accept another attempt id.
                        if t.phase != Phase::Finalized {
                            return;
                        }
                        t.return_retired.push(current);
                        if t.return_retired.len() > 64 {
                            t.return_retired.remove(0);
                        }
                        t.return_id = Some(return_id);
                        t.return_started = Some(Instant::now());
                    }
                } else if !matches!(t.phase, Phase::Finalized | Phase::Committed) {
                    return;
                }
                if t.phase == Phase::Committed {
                    if !wg.finalize_path_trial(trial_id) {
                        return;
                    }
                    t.phase = Phase::Finalized;
                }
                if t.return_id.is_none() {
                    t.return_id = Some(return_id);
                    t.return_started = Some(Instant::now());
                }
                if t.phase == Phase::Returned {
                    Self::send(
                        &ctx.outbound,
                        ClientMsg::OverlayPathTrialReturned {
                            trial_id,
                            return_id,
                        },
                    )
                    .await;
                } else {
                    t.phase = Phase::ReturnPreparing;
                }
            }
            ServerMsg::OverlayPathTrialReturnCommit {
                trial_id,
                return_id,
            } => {
                if !local_enabled || !ctx.org_primary || !supported {
                    return;
                }
                let Some(t) = self.trials.get_mut(&trial_id) else {
                    return;
                };
                if t.return_id != Some(return_id) || !Self::current(t, peers, installed) {
                    return;
                }
                if t.phase != Phase::Returned {
                    if t.phase != Phase::ReturnReady
                        || !t.measurements.return_ready(Instant::now())
                        || !wg.path_trial_direct_ready(trial_id)
                        || !wg.commit_path_trial_return(trial_id)
                    {
                        Self::send(
                            &ctx.outbound,
                            ClientMsg::OverlayPathTrialReturnAbort {
                                trial_id,
                                return_id,
                            },
                        )
                        .await;
                        return;
                    }
                    let now = Instant::now();
                    let mut direct = t.original.clone();
                    direct.since = now;
                    installed.insert(t.peer_id, direct);
                    t.committed_since = Some(now);
                    t.phase = Phase::Returned;
                }
                t.last_control = Instant::now();
                Self::send(
                    &ctx.outbound,
                    ClientMsg::OverlayPathTrialReturned {
                        trial_id,
                        return_id,
                    },
                )
                .await;
            }
            ServerMsg::OverlayPathTrialReturnFinalize {
                trial_id,
                return_id,
            } => {
                let ok = self.trials.get(&trial_id).is_some_and(|t| {
                    t.return_id == Some(return_id)
                        && t.phase == Phase::Returned
                        && Self::current(t, peers, installed)
                });
                if ok && wg.finalize_path_trial_return(trial_id) {
                    let t = self.trials.remove(&trial_id).unwrap();
                    if let Some(c) = t.conn {
                        c.close();
                    }
                    ctx.path_trial_managed
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&t.peer_id);
                    self.retired(trial_id);
                }
            }
            ServerMsg::OverlayPathTrialReturnAbort {
                trial_id,
                return_id,
            } => {
                let Some(t) = self.trials.get_mut(&trial_id) else {
                    return;
                };
                if t.return_id != Some(return_id) || !Self::current(t, peers, installed) {
                    return;
                }
                if t.phase == Phase::Returned {
                    if !wg.abort_path_trial_return(trial_id) {
                        return;
                    }
                    let now = Instant::now();
                    installed.insert(
                        t.peer_id,
                        Installed {
                            hs_done: true,
                            initiated: true,
                            relay_kind: Some(RelayKind::Org),
                            carrier_local: t.conn.as_ref().and_then(|c| c.local_addr().ok()),
                            carrier_dst: t.conn.as_ref().map(|c| c.synth_peer()),
                            ..Installed::base(
                                t.peer.public_key,
                                t.peer.overlay_ip,
                                DirectTier::Relay,
                                now,
                            )
                        },
                    );
                    t.committed_since = Some(now);
                }
                t.return_retired.push(return_id);
                if t.return_retired.len() > 64 {
                    t.return_retired.remove(0);
                }
                t.return_id = None;
                t.return_started = None;
                t.phase = Phase::Finalized;
                t.next_return = Instant::now() + Duration::from_secs(30);
            }
            ServerMsg::OverlayPathTrialAbort { trial_id } => {
                self.cancel(trial_id, ctx, wg, peers, installed, false)
                    .await
            }
            _ => {}
        }
    }
    pub(super) async fn tick(
        &mut self,
        ctx: &OverlayRuntime,
        wg: &mut WgDevice,
        peers: &HashMap<ObjectId, NetmapPeer>,
        installed: &mut HashMap<ObjectId, Installed>,
        discovery: &mut super::super::orgrelay::discovery::Discovery,
        supported: bool,
    ) {
        self.tick_enabled(ctx, wg, peers, installed, discovery, supported, enabled())
            .await;
    }
    async fn tick_enabled(
        &mut self,
        ctx: &OverlayRuntime,
        wg: &mut WgDevice,
        peers: &HashMap<ObjectId, NetmapPeer>,
        installed: &mut HashMap<ObjectId, Installed>,
        discovery: &mut super::super::orgrelay::discovery::Discovery,
        supported: bool,
        local_enabled: bool,
    ) {
        let before = self.observation_phases();
        let event = crate::localapi::PathTrialEvent::Tick;
        self.tick_enabled_inner(
            ctx,
            wg,
            peers,
            installed,
            discovery,
            supported,
            local_enabled,
        )
        .await;
        if local_enabled && supported && ctx.org_primary {
            let after = self.observation_phases();
            self.observation.record(before, after, event);
        } else {
            self.observation.reset(if !local_enabled {
                crate::localapi::PathTrialResetReason::TickLocalDisabled
            } else if !supported {
                crate::localapi::PathTrialResetReason::TickServerUnsupported
            } else {
                crate::localapi::PathTrialResetReason::TickNonPrimary
            });
        }
    }
    async fn tick_enabled_inner(
        &mut self,
        ctx: &OverlayRuntime,
        wg: &mut WgDevice,
        peers: &HashMap<ObjectId, NetmapPeer>,
        installed: &mut HashMap<ObjectId, Installed>,
        discovery: &mut super::super::orgrelay::discovery::Discovery,
        supported: bool,
        local_enabled: bool,
    ) {
        let now = Instant::now();
        wg.reap_path_trial_drains(now);
        for failed in self.failed_requests.drain(..) {
            discovery.note_failure(
                peers,
                failed.peer_id,
                &failed.identity,
                &failed.candidate,
                now,
            );
        }
        if self
            .pending_request
            .as_ref()
            .is_some_and(|r| now.saturating_duration_since(r.at) >= PREPARE_TIMEOUT)
        {
            self.pending_request = None;
        }
        while let Ok(done) = self.rx.try_recv() {
            let valid = self.trials.get(&done.id).is_some_and(|t| {
                local_enabled
                    && ctx.org_primary
                    && supported
                    && t.phase == Phase::Binding
                    && Self::current(t, peers, installed)
            });
            if valid {
                if let Some(conn) = done.conn {
                    let t = self.trials.get_mut(&done.id).unwrap();
                    if wg.start_path_trial(
                        done.id,
                        t.peer.public_key,
                        t.peer.overlay_ip,
                        Carrier::relay(conn.clone(), conn.synth_peer()),
                    ) {
                        t.conn = Some(conn);
                        t.phase = Phase::Measuring;
                    } else {
                        conn.close();
                        self.cancel(done.id, ctx, wg, peers, installed, supported)
                            .await;
                    }
                } else {
                    self.cancel(done.id, ctx, wg, peers, installed, supported)
                        .await;
                }
            } else {
                if let Some(c) = done.conn {
                    c.close();
                }
            }
        }
        let ids: Vec<_> = self.trials.keys().copied().collect();
        for id in ids {
            // Membership/key/IP/generation reconciliation is unconditional.
            // Reconnect/legacy fallback may preserve a CURRENT carrier, never
            // stale ownership that could fence a newly installed identity.
            if !Self::current(&self.trials[&id], peers, installed) {
                self.cancel(
                    id,
                    ctx,
                    wg,
                    peers,
                    installed,
                    supported && local_enabled && ctx.org_primary,
                )
                .await;
                continue;
            }
            if !supported || !local_enabled || !ctx.org_primary {
                if matches!(
                    self.trials[&id].phase,
                    Phase::Binding | Phase::Measuring | Phase::Ready
                ) {
                    self.cancel(id, ctx, wg, peers, installed, false).await;
                }
                continue;
            }
            let stale = {
                let t = &self.trials[&id];
                !Self::current(t, peers, installed)
                    || (matches!(t.phase, Phase::Binding | Phase::Measuring | Phase::Ready)
                        && now.duration_since(t.started) >= PREPARE_TIMEOUT)
            };
            if stale {
                self.cancel(id, ctx, wg, peers, installed, true).await;
                continue;
            }
            let t = self.trials.get_mut(&id).unwrap();
            // A dead retained Tunn cannot be resurrected by stateless echo.
            // Repair only the non-active shadow and only before a Ready vote;
            // Returned/Committed decisions must keep both receivers unchanged.
            if matches!(t.phase, Phase::Finalized | Phase::ReturnPreparing)
                && !wg.path_trial_direct_ready(id)
                && t.direct_refreshed.is_none_or(|at| {
                    now.saturating_duration_since(at) >= t.original.tier.handshake_deadline()
                })
            {
                t.direct_refreshed = Some(now);
                if wg.rebuild_path_trial_direct(id).await {
                    // Old endpoint/nonce/timing samples may not authorize this
                    // independent crypto session. Require nine actual new rounds.
                    t.measurements = Measurements {
                        seq: rand::random::<u64>() / 2,
                        ..Default::default()
                    };
                    t.original.carrier_dst = wg.path_trial_direct_endpoint(id);
                    t.original.public_direct_dst =
                        matches!(t.original.tier, DirectTier::Public | DirectTier::Srflx)
                            .then_some(t.original.carrier_dst)
                            .flatten();
                }
            }
            for p in wg.drain_path_trial_disco(id) {
                t.measurements
                    .pong(ProbePath::Relay, &t.peer.public_key, &p);
            }
            t.measurements.finish(now);
            if t.phase == Phase::Committed {
                if now.duration_since(t.last_control) >= Duration::from_secs(5) {
                    t.last_control = now;
                    Self::send(
                        &ctx.outbound,
                        ClientMsg::OverlayPathTrialCommitted { trial_id: id },
                    )
                    .await;
                }
                continue;
            }
            if t.phase == Phase::Binding {
                continue;
            }
            if matches!(t.phase, Phase::Measuring | Phase::Ready) {
                if t.measurements.ready(now) && wg.path_trial_handshake_done(id) {
                    if t.phase != Phase::Ready
                        && Self::send(
                            &ctx.outbound,
                            ClientMsg::OverlayPathTrialReady { trial_id: id },
                        )
                        .await
                    {
                        t.phase = Phase::Ready;
                    }
                } else if t.phase == Phase::Ready {
                    self.cancel(id, ctx, wg, peers, installed, true).await;
                    continue;
                }
            } else if t.phase == Phase::Finalized
                && now >= t.next_return
                && t.measurements.return_ready(now)
                && wg.path_trial_direct_ready(id)
            {
                let return_id = t.return_id.unwrap_or_else(ObjectId::new);
                if now.duration_since(t.last_control) < Duration::from_secs(5) {
                    continue;
                }
                if Self::send(
                    &ctx.outbound,
                    ClientMsg::OverlayPathTrialReturnRequest {
                        trial_id: id,
                        return_id,
                    },
                )
                .await
                {
                    t.return_id = Some(return_id);
                    t.return_started = Some(now);
                    t.last_control = now;
                }
            } else if matches!(t.phase, Phase::ReturnPreparing | Phase::ReturnReady) {
                let return_id = t.return_id.unwrap();
                if t.measurements.return_ready(now) && wg.path_trial_direct_ready(id) {
                    if t.phase != Phase::ReturnReady
                        || now.duration_since(t.last_control) >= Duration::from_secs(5)
                    {
                        if Self::send(
                            &ctx.outbound,
                            ClientMsg::OverlayPathTrialReturnReady {
                                trial_id: id,
                                return_id,
                            },
                        )
                        .await
                        {
                            t.phase = Phase::ReturnReady;
                            t.last_control = now;
                        }
                    }
                } else if t.phase == Phase::ReturnReady
                    || t.return_started
                        .is_some_and(|at| now.duration_since(at) >= PREPARE_TIMEOUT)
                {
                    Self::send(
                        &ctx.outbound,
                        ClientMsg::OverlayPathTrialReturnAbort {
                            trial_id: id,
                            return_id,
                        },
                    )
                    .await;
                    // Do not discard the id until the server acknowledges Abort;
                    // a Commit decision may already be in flight.
                    t.last_control = now;
                }
            } else if t.phase == Phase::Returned {
                if now.duration_since(t.last_control) >= Duration::from_secs(5) {
                    t.last_control = now;
                    Self::send(
                        &ctx.outbound,
                        ClientMsg::OverlayPathTrialReturned {
                            trial_id: id,
                            return_id: t.return_id.unwrap(),
                        },
                    )
                    .await;
                }
            }
            let t = self.trials.get_mut(&id).unwrap();
            if t.measurements.round.is_none()
                && t.measurements
                    .last_round
                    .is_none_or(|at| now.duration_since(at) >= ROUND_GAP)
            {
                let (mut d, df) =
                    t.measurements
                        .frame(&ctx.keypair, &t.peer.public_key, Instant::now());
                let dst = wg.send_path_trial_direct_disco(id, &df).await;
                d.dst = dst;
                if dst.is_none() {
                    d.result = Some(None);
                }
                let (mut r, rf) =
                    t.measurements
                        .frame(&ctx.keypair, &t.peer.public_key, Instant::now());
                let dst = wg.send_path_trial_disco(id, &rf).await;
                r.dst = dst;
                if dst.is_none() {
                    r.result = Some(None);
                }
                t.measurements.round = Some(Round {
                    direct: d,
                    relay: r,
                });
                t.measurements.last_round = Some(now);
            }
        }
        if !local_enabled
            || !ctx.org_primary
            || !supported
            || now < self.next_request
            || self.trials.len() >= MAX_TRIALS
        {
            return;
        }
        let choice = installed
            .iter()
            .filter(|(_, p)| p.is_direct && !p.stalled)
            .filter(|(id, _)| !self.trials.values().any(|t| &t.peer_id == *id))
            .filter_map(|(id, p)| {
                discovery
                    .candidate_for(peers, *id, now)
                    .map(|c| (*id, p, c))
            })
            .min_by_key(|(id, _, _)| *id);
        if let Some((peer, _, candidate)) = choice {
            if candidate.exit_relay_node_id.is_some()
                && !crate::overlay::orgrelay::backbone::path_enabled()
            {
                return;
            }
            let Some(np) = peers.get(&peer) else { return };
            let identity = (np.wg_public_key.clone(), np.overlay_ip.clone());
            let Some(serial) = self.serial.checked_add(1) else {
                return;
            };
            self.serial = serial;
            self.next_request = now + Duration::from_secs(60);
            if Self::send(
                &ctx.outbound,
                ClientMsg::OverlayPathTrialRequest {
                    peer_node_id: peer,
                    relay_node_id: candidate.relay_node_id,
                    request_id: serial,
                    exit_relay_node_id: candidate.exit_relay_node_id,
                },
            )
            .await
            {
                discovery.note_attempt(peers, peer, &candidate, now);
                self.pending_request = Some(RequestedCandidate {
                    peer_id: peer,
                    request_id: serial,
                    identity,
                    candidate,
                    at: now,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn feed(m: &mut Measurements, at: Instant, d: Option<f64>, c: Option<f64>, now: Instant) {
        let a = |result| Attempt {
            nonce: [0; 8],
            at,
            dst: None,
            result: Some(result),
        };
        m.round = Some(Round {
            direct: a(d),
            relay: a(c),
        });
        m.finish(now);
    }
    #[test]
    fn path_trial_three_fresh_windows_and_material_threshold() {
        let now = Instant::now();
        let mut m = Measurements::default();
        for i in 0..8 {
            feed(
                &mut m,
                now + Duration::from_millis(i * 500),
                Some(100.0),
                Some(60.0),
                now + Duration::from_millis(i * 500),
            );
            assert!(!m.ready(now + Duration::from_millis(i * 500)));
        }
        feed(
            &mut m,
            now + Duration::from_secs(4),
            Some(100.0),
            Some(60.0),
            now + Duration::from_secs(4),
        );
        assert!(m.ready(now + Duration::from_secs(4)));
        assert!(!m.ready(now + Duration::from_secs(11)));
        feed(
            &mut m,
            now + Duration::from_secs(5),
            Some(100.0),
            Some(90.0),
            now + Duration::from_secs(5),
        );
        feed(
            &mut m,
            now + Duration::from_secs(6),
            Some(100.0),
            Some(90.0),
            now + Duration::from_secs(6),
        );
        assert!(!m.ready(now + Duration::from_secs(6)));
    }
    #[test]
    fn path_trial_failure_timeout_and_delayed_processing_never_improve_score() {
        let now = Instant::now();
        let mut m = Measurements::default();
        for _ in 0..9 {
            feed(&mut m, now, Some(100.0), None, now);
        }
        assert!(!m.ready(now));
        let mut m = Measurements::default();
        for _ in 0..9 {
            feed(
                &mut m,
                now,
                Some(100.0),
                Some(50.0),
                now + Duration::from_secs(20),
            );
        }
        assert!(!m.ready(now + Duration::from_secs(20)));
        let mut m = Measurements::default();
        for _ in 0..9 {
            feed(&mut m, now, None, Some(10.0), now);
        }
        assert!(!m.ready(now));
    }
}

#[cfg(test)]
mod return_tests {
    use super::*;
    fn feed(m: &mut Measurements, now: Instant, d: Option<f64>, r: Option<f64>) {
        let a = |result| Attempt {
            nonce: [1; 8],
            at: now,
            dst: None,
            result: Some(result),
        };
        m.round = Some(Round {
            direct: a(d),
            relay: a(r),
        });
        m.finish(now);
    }
    #[test]
    fn path_trial_return_prefers_healthy_p2p_with_loss_and_hysteresis() {
        let now = Instant::now();
        let mut m = Measurements::default();
        for _ in 0..8 {
            feed(&mut m, now, Some(55.0), Some(50.0));
            assert!(!m.return_ready(now));
        }
        feed(&mut m, now, Some(55.0), Some(50.0));
        assert!(m.return_ready(now));
        assert!(!m.ready(now));
        assert!(!m.return_ready(now + Duration::from_secs(11)));
        let mut m = Measurements::default();
        for _ in 0..9 {
            feed(&mut m, now, None, Some(50.0));
        }
        assert!(!m.return_ready(now));
        let mut m = Measurements::default();
        for _ in 0..9 {
            feed(&mut m, now, Some(60.0), None);
        }
        assert!(m.return_ready(now));
    }
}

#[cfg(test)]
mod ownership_regression {
    use super::*;
    // The actual tick state machine runs under explicit local capability values,
    // avoiding global env mutation and permitting both cases in parallel tests.
    async fn stale_identity_is_retired(supported: bool, local_enabled: bool) {
        for change in 0..3 {
            let own = WgKeypair::generate();
            let key = WgKeypair::generate();
            let replacement = WgKeypair::generate();
            let id = ObjectId::new();
            let trial = ObjectId::new();
            let np:NetmapPeer=serde_json::from_value(serde_json::json!({"node_id":id.to_hex(),"overlay_ip":"100.64.0.2","wg_public_key":key.public_base64(),"reachable":true})).unwrap();
            let peer = peer_config_from_netmap(&np).unwrap();
            let original = Installed::base(
                peer.public_key,
                peer.overlay_ip,
                DirectTier::Public,
                Instant::now(),
            );
            let (out, mut rx) = mpsc::channel(16);
            let ctx = OverlayRuntime::new_relay(
                own.clone(),
                out,
                Box::new(|_, _, _| Err(std::io::Error::other("TUN must never open in this test"))),
                1280,
            )
            .with_org_primary(true);
            ctx.path_trial_managed.lock().unwrap().insert(id);
            let mut engine = Engine::new();
            let now = Instant::now();
            engine.trials.insert(
                trial,
                Trial {
                    peer_id: id,
                    peer,
                    original: original.clone(),
                    started: now,
                    phase: Phase::Finalized,
                    conn: None,
                    measurements: Measurements::default(),
                    committed_since: Some(original.since),
                    last_control: now,
                    return_id: None,
                    return_retired: Vec::new(),
                    return_started: None,
                    next_return: now,
                    direct_refreshed: None,
                    requested: None,
                },
            );
            let mut peers = HashMap::new();
            let mut installed = HashMap::new();
            if change != 0 {
                let mut changed = np.clone();
                if change == 1 {
                    changed.wg_public_key = replacement.public_base64();
                } else {
                    changed.overlay_ip = "100.64.0.3".into();
                }
                let cfg = peer_config_from_netmap(&changed).unwrap();
                peers.insert(id, changed);
                installed.insert(
                    id,
                    Installed::base(
                        cfg.public_key,
                        cfg.overlay_ip,
                        DirectTier::Public,
                        Instant::now(),
                    ),
                );
            }
            let expected = installed
                .get(&id)
                .map(|p| (p.pubkey, p.overlay_ip, p.since));
            let (mut wg, _) = WgDevice::new(own.secret.clone());
            engine
                .tick_enabled(
                    &ctx,
                    &mut wg,
                    &peers,
                    &mut installed,
                    &mut super::super::super::orgrelay::discovery::Discovery::default(),
                    supported,
                    local_enabled,
                )
                .await;
            assert!(engine.trials.is_empty());
            assert!(!ctx.path_trial_managed.lock().unwrap().contains(&id));
            assert_eq!(wg.peer_count(), 0);
            assert_eq!(
                installed
                    .get(&id)
                    .map(|p| (p.pubkey, p.overlay_ip, p.since)),
                expected,
                "stale trial must not remove a newer same-id installation"
            );
            assert!(
                rx.try_recv().is_err(),
                "legacy/default-off reconciliation emits no new protocol"
            );
        }
    }
    #[tokio::test]
    async fn path_trial_legacy_server_still_reconciles_removed_rekeyed_and_reip_peer() {
        stale_identity_is_retired(false, true).await;
    }
    #[tokio::test]
    async fn path_trial_default_off_still_reconciles_removed_rekeyed_and_reip_peer() {
        stale_identity_is_retired(true, false).await;
    }
}

#[cfg(test)]
mod simultaneous_return_regression {
    use super::*;
    #[tokio::test]
    async fn path_trial_simultaneous_return_requests_follow_one_server_prepare_and_reject_old_ids()
    {
        let winner = ObjectId::new();
        let loser = ObjectId::new();
        // Both clients have independently queued different proposals. Replay
        // the SAME real server Prepare through each actual control handler.
        for proposed in [winner, loser] {
            let own = WgKeypair::generate();
            let key = WgKeypair::generate();
            let id = ObjectId::new();
            let trial = ObjectId::new();
            let now = Instant::now();
            let np:NetmapPeer=serde_json::from_value(serde_json::json!({"node_id":id.to_hex(),"overlay_ip":"100.64.0.2","wg_public_key":key.public_base64(),"reachable":true})).unwrap();
            let peer = peer_config_from_netmap(&np).unwrap();
            let original =
                Installed::base(peer.public_key, peer.overlay_ip, DirectTier::Relay, now);
            let (out, mut rx) = mpsc::channel(16);
            let ctx = OverlayRuntime::new_relay(
                own.clone(),
                out,
                Box::new(|_, _, _| Err(std::io::Error::other("TUN must never open"))),
                1280,
            )
            .with_org_primary(true);
            let mut installed = HashMap::from([(id, original.clone())]);
            let peers = HashMap::from([(id, np)]);
            let (mut wg, _) = WgDevice::new(own.secret.clone());
            let mut engine = Engine::new();
            engine.trials.insert(
                trial,
                Trial {
                    peer_id: id,
                    peer,
                    original,
                    started: now,
                    phase: Phase::Finalized,
                    conn: None,
                    measurements: Measurements::default(),
                    committed_since: Some(now),
                    last_control: now,
                    return_id: Some(proposed),
                    return_retired: Vec::new(),
                    return_started: Some(now),
                    next_return: now,
                    direct_refreshed: None,
                    requested: None,
                },
            );
            engine
                .control_enabled(
                    ServerMsg::OverlayPathTrialReturnPrepare {
                        trial_id: trial,
                        return_id: winner,
                    },
                    &ctx,
                    &mut wg,
                    &peers,
                    &mut installed,
                    true,
                    true,
                )
                .await;
            assert_eq!(engine.trials[&trial].return_id, Some(winner));
            assert!(engine.trials[&trial].phase == Phase::ReturnPreparing);
            let observed = engine.observation(&peers, &installed, true).unwrap();
            assert_eq!(observed.transitions.len(), 1);
            assert_eq!(
                observed.transitions[0].event,
                crate::localapi::PathTrialEvent::ReturnPrepare
            );
            assert_eq!(observed.active.len(), 1);
            assert_eq!(observed.active[0].return_id, Some(winner.to_hex()));
            assert_eq!(observed.transitions[0].return_id, Some(winner.to_hex()));
            let sequence = observed.transitions[0].sequence;
            let _read_again = engine.observation(&peers, &installed, true).unwrap();
            assert_eq!(
                engine
                    .observation(&peers, &installed, true)
                    .unwrap()
                    .transitions[0]
                    .sequence,
                sequence,
                "read-only projection must not mutate Engine"
            );
            // A different id is forbidden after Prepare, including a delayed
            // proposal, its Commit, and its Abort. No sender may be changed.
            for msg in [
                ServerMsg::OverlayPathTrialReturnPrepare {
                    trial_id: trial,
                    return_id: loser,
                },
                ServerMsg::OverlayPathTrialReturnCommit {
                    trial_id: trial,
                    return_id: loser,
                },
                ServerMsg::OverlayPathTrialReturnAbort {
                    trial_id: trial,
                    return_id: loser,
                },
            ] {
                engine
                    .control_enabled(msg, &ctx, &mut wg, &peers, &mut installed, true, true)
                    .await;
                assert_eq!(engine.trials[&trial].return_id, Some(winner));
                assert!(engine.trials[&trial].phase == Phase::ReturnPreparing);
                assert_eq!(
                    engine
                        .observation(&peers, &installed, true)
                        .unwrap()
                        .transitions
                        .len(),
                    1,
                    "rejected/late return controls cannot forge accepted transitions"
                );
            }
            assert_eq!(wg.peer_count(), 0);
            assert!(rx.try_recv().is_err());
        }
    }
}

#[cfg(test)]
mod failure_feedback_regression {
    use super::*;
    #[tokio::test]
    async fn path_trial_actual_cancel_tick_feedback_cools_only_correlated_local_candidate() {
        let own = WgKeypair::generate();
        let key = WgKeypair::generate();
        let peer_id = ObjectId::new();
        let trial = ObjectId::new();
        let now = Instant::now();
        let np:NetmapPeer=serde_json::from_value(serde_json::json!({"node_id":peer_id.to_hex(),"overlay_ip":"100.64.0.2","wg_public_key":key.public_base64(),"reachable":true,"supports_org_relay":true})).unwrap();
        let peers = HashMap::from([(peer_id, np.clone())]);
        let peer = peer_config_from_netmap(&np).unwrap();
        let original = Installed::base(peer.public_key, peer.overlay_ip, DirectTier::Public, now);
        let (out, mut rx) = mpsc::channel(16);
        let ctx = OverlayRuntime::new_relay(
            own.clone(),
            out,
            Box::new(|_, _, _| Err(std::io::Error::other("TUN must never open"))),
            1280,
        )
        .with_org_primary(true);
        let mut discovery = super::super::super::orgrelay::discovery::Discovery::default();
        discovery
            .request(true, true, &peers, &ctx.outbound, now)
            .await;
        let ClientMsg::OverlayOrgRelayDiscover { request_id, .. } = rx.recv().await.unwrap() else {
            panic!("actual discovery")
        };
        let first = OrgRelayCandidateWire {
            relay_node_id: ObjectId::new(),
            exit_relay_node_id: Some(ObjectId::new()),
            endpoints: vec!["8.8.8.8:3478".into()],
        };
        let second = OrgRelayCandidateWire {
            relay_node_id: ObjectId::new(),
            exit_relay_node_id: None,
            endpoints: vec!["1.1.1.1:3478".into()],
        };
        assert_eq!(
            discovery.receive(
                &peers,
                peer_id,
                request_id,
                vec![first.clone(), second.clone()],
                30,
                now
            ),
            2
        );
        discovery.note_attempt(&peers, peer_id, &first, now);
        let mut engine = Engine::new();
        let mut installed = HashMap::from([(peer_id, original.clone())]);
        let (mut wg, _) = WgDevice::new(own.secret.clone());
        engine.trials.insert(
            trial,
            Trial {
                peer_id,
                peer: peer.clone(),
                original: original.clone(),
                started: now,
                phase: Phase::Measuring,
                conn: None,
                measurements: Measurements::default(),
                committed_since: None,
                last_control: now,
                return_id: None,
                return_retired: Vec::new(),
                return_started: None,
                next_return: now,
                direct_refreshed: None,
                requested: Some(RequestedCandidate {
                    peer_id,
                    request_id: 71,
                    identity: (np.wg_public_key.clone(), np.overlay_ip.clone()),
                    candidate: first.clone(),
                    at: now,
                }),
            },
        );
        engine
            .cancel(trial, &ctx, &mut wg, &peers, &mut installed, false)
            .await;
        assert_eq!(engine.failed_requests.len(), 1);
        engine
            .tick_enabled(
                &ctx,
                &mut wg,
                &peers,
                &mut installed,
                &mut discovery,
                false,
                false,
            )
            .await;
        assert!(engine.failed_requests.is_empty());
        assert_eq!(
            discovery
                .candidate_for(&peers, peer_id, now)
                .unwrap()
                .relay_node_id,
            second.relay_node_id
        );
        // Rotate around to prove the first candidate is excluded by actual
        // negative feedback, not merely skipped by the next-after cursor.
        discovery.note_attempt(&peers, peer_id, &second, now);
        assert_eq!(
            discovery
                .candidate_for(&peers, peer_id, now)
                .unwrap()
                .relay_node_id,
            second.relay_node_id
        );
        assert_eq!(wg.peer_count(), 0);
        assert!(installed[&peer_id].is_direct);
        assert!(rx.try_recv().is_err());
        // An unsolicited/responding trial does not possess a local correlation
        // and cannot poison a candidate inferred only from its relay node id.
        engine.trials.insert(
            ObjectId::new(),
            Trial {
                peer_id,
                peer,
                original,
                started: now,
                phase: Phase::Measuring,
                conn: None,
                measurements: Measurements::default(),
                committed_since: None,
                last_control: now,
                return_id: None,
                return_retired: Vec::new(),
                return_started: None,
                next_return: now,
                direct_refreshed: None,
                requested: None,
            },
        );
        let foreign = *engine.trials.keys().next().unwrap();
        engine
            .cancel(foreign, &ctx, &mut wg, &peers, &mut installed, false)
            .await;
        assert!(engine.failed_requests.is_empty());
    }
}

/// Thin test-only owner around the REAL Engine/WgDevice. No score injection,
/// time scaling, alternate protocol, OS TUN, or system-route installation.
#[cfg(feature = "path-trial-test-support")]
#[doc(hidden)]
pub mod test_support {
    use super::*;
    #[derive(Clone, Debug)]
    pub struct Snapshot {
        pub phase: &'static str,
        pub direct_sender: bool,
        pub direct_ready: bool,
        pub managed: bool,
        pub windows: Vec<(Option<f64>, Option<f64>, Instant)>,
    }
    pub struct Harness {
        engine: Engine,
        ctx: OverlayRuntime,
        wg: WgDevice,
        peers: HashMap<ObjectId, NetmapPeer>,
        installed: HashMap<ObjectId, Installed>,
        discovery: super::super::super::orgrelay::discovery::Discovery,
        disco: mpsc::Receiver<disco::DiscoInbound>,
        inbox: mpsc::Receiver<Vec<u8>>,
        peer_id: ObjectId,
        peer_key: [u8; 32],
        observation_rx: watch::Receiver<crate::localapi::OverlayView>,
    }
    /// Holds an ACTUAL successful bind completion before the Engine consumes
    /// it. This only controls asynchronous delivery in a race regression; no
    /// connection, authentication result, clock, or quality score is fabricated.
    pub struct HeldBind {
        done: Option<Bound>,
        conn: Arc<OrgRelayConn>,
    }
    impl HeldBind {
        pub fn trial_id(&self) -> ObjectId {
            self.done.as_ref().expect("not yet released").id
        }
        pub fn is_alive(&self) -> bool {
            self.conn.is_alive()
        }
    }
    impl Drop for HeldBind {
        fn drop(&mut self) {
            self.conn.close();
        }
    }
    impl Harness {
        pub async fn request_discovery(&mut self) {
            self.discovery
                .request(true, true, &self.peers, &self.ctx.outbound, Instant::now())
                .await;
        }
        pub fn receive_discovery(&mut self, msg: ServerMsg) -> usize {
            let ServerMsg::OverlayOrgRelayCandidates {
                peer_node_id,
                request_id,
                candidates,
                ttl_secs,
                next_cursor,
            } = msg
            else {
                panic!("expected actual server discovery metadata");
            };
            self.discovery.receive_page(
                &self.peers,
                peer_node_id,
                request_id,
                candidates,
                ttl_secs,
                next_cursor,
                Instant::now(),
            )
        }
        pub async fn hold_completed_bind(&mut self) -> HeldBind {
            let done = tokio::time::timeout(Duration::from_secs(4), self.engine.rx.recv())
                .await
                .expect("real local bind completion deadline")
                .expect("live completion receiver");
            let conn = done
                .conn
                .as_ref()
                .expect("must hold a real successful authenticated bind")
                .clone();
            HeldBind {
                done: Some(done),
                conn,
            }
        }
        pub async fn release_completed_bind(&self, held: &mut HeldBind) {
            self.engine
                .tx
                .send(held.done.take().expect("release once"))
                .await
                .unwrap_or_else(|_| panic!("live original Engine completion channel"));
        }
        /// Whitelisted diagnostic counters only; never peer IDs, keys, endpoints,
        /// secrets, packet contents, or protocol credentials.
        /// Real measurement/handshake predicates and aggregate RTTs only.
        /// Diagnostics cannot change samples, readiness, identity, or routing.
        pub fn diagnostic_quality(
            &self,
            id: ObjectId,
        ) -> (bool, bool, usize, usize, usize, Option<f64>, Option<f64>) {
            let Some(t) = self.engine.trials.get(&id) else {
                return (false, false, 0, 0, 0, None, None);
            };
            let median = |mut values: Vec<f64>| {
                values.sort_by(f64::total_cmp);
                (!values.is_empty()).then(|| values[values.len() / 2])
            };
            let d: Vec<_> = t.measurements.windows.iter().filter_map(|w| w.0).collect();
            let r: Vec<_> = t.measurements.windows.iter().filter_map(|w| w.1).collect();
            (
                t.measurements.ready(Instant::now()),
                self.wg.path_trial_handshake_done(id),
                t.measurements.windows.len(),
                d.len(),
                r.len(),
                median(d),
                median(r),
            )
        }
        pub fn diagnostic_counters(&self) -> (usize, bool, u64, bool, usize, usize) {
            let now = Instant::now();
            (
                self.engine.trials.len(),
                self.engine.pending_request.is_some(),
                self.engine
                    .next_request
                    .saturating_duration_since(now)
                    .as_millis()
                    .min(u64::MAX as u128) as u64,
                self.discovery
                    .candidate_for(&self.peers, self.peer_id, now)
                    .is_some(),
                self.engine.failed_requests.len(),
                self.engine
                    .trials
                    .values()
                    .filter(|t| Engine::current(t, &self.peers, &self.installed))
                    .count(),
            )
        }
        /// Same bounded production watch publisher, never a hand-built status.
        fn publish_local_observation(&self) {
            let before = self.observation_rx.borrow().clone();
            observation::publish_view(
                &self.ctx.peer_view,
                &self.engine,
                &self.peers,
                &self.installed,
                true,
            );
            let after = self.observation_rx.borrow();
            assert_eq!(
                after.peers, before.peers,
                "diagnostic publication cannot rewrite peer fields"
            );
            assert_eq!(after.self_ip, before.self_ip);
            assert_eq!(after.self_ip6, before.self_ip6);
        }
        pub fn local_observation(&self) -> crate::localapi::PathTrialStatus {
            self.observation_rx
                .borrow()
                .path_trials
                .clone()
                .expect("live actual Engine observation was published")
        }
        pub fn trial_count(&self) -> usize {
            self.engine.trials.len()
        }
        pub fn active_trial_observation(&self) -> Option<(ObjectId, Instant)> {
            self.engine
                .trials
                .iter()
                .next()
                .map(|(id, t)| (*id, t.started))
        }
        pub fn installed_identity(&self) -> Option<([u8; 32], Ipv4Addr, Instant)> {
            self.installed
                .get(&self.peer_id)
                .map(|p| (p.pubkey, p.overlay_ip, p.since))
        }
        pub async fn new(
            own: WgKeypair,
            peer: NetmapPeer,
            sock: Arc<tokio::net::UdpSocket>,
            dst: SocketAddr,
            initiator: bool,
        ) -> (Self, mpsc::Receiver<ClientMsg>) {
            let peer_id = peer.node_id;
            let config = peer_config_from_netmap(&peer).expect("valid authenticated fixture peer");
            let (out, rx) = mpsc::channel(128);
            let ctx = OverlayRuntime::new_relay(
                own.clone(),
                out,
                Box::new(|_, _, _| {
                    Err(std::io::Error::other(
                        "composite oracle must never open TUN",
                    ))
                }),
                1280,
            )
            .with_org_primary(true);
            let (mut wg, inbox) = WgDevice::new(own.secret.clone());
            let disco = wg.take_disco_events().unwrap();
            wg.ensure_direct_demux(sock.clone());
            wg.add_direct_peer(sock, config.public_key, config.overlay_ip, dst, initiator)
                .await;
            let installed = HashMap::from([(
                peer_id,
                Installed::base(
                    config.public_key,
                    config.overlay_ip,
                    DirectTier::Public,
                    Instant::now(),
                ),
            )]);
            let peers = HashMap::from([(peer_id, peer)]);
            let initial_view = build_overlay_view(
                "",
                &installed,
                &peers,
                &HashMap::new(),
                Instant::now(),
                0,
                &HashMap::new(),
            );
            let (view_tx, observation_rx) = watch::channel(initial_view);
            let ctx = ctx.with_peer_view(view_tx);
            (
                Self {
                    engine: Engine::new(),
                    ctx,
                    wg,
                    peers,
                    installed,
                    discovery: Default::default(),
                    disco,
                    inbox,
                    peer_id,
                    peer_key: config.public_key,
                    observation_rx,
                },
                rx,
            )
        }
        pub fn handshake_done(&self) -> bool {
            self.wg.peer_handshake_done(&self.peer_key) == Some(true)
        }
        pub async fn control(&mut self, msg: ServerMsg) {
            self.engine
                .control_enabled(
                    msg,
                    &self.ctx,
                    &mut self.wg,
                    &self.peers,
                    &mut self.installed,
                    true,
                    true,
                )
                .await;
            self.publish_local_observation();
        }
        pub async fn tick(&mut self) {
            while let Ok(p) = self.disco.try_recv() {
                self.engine.active_pong(&p);
            }
            self.engine
                .tick_enabled(
                    &self.ctx,
                    &mut self.wg,
                    &self.peers,
                    &mut self.installed,
                    &mut self.discovery,
                    true,
                    true,
                )
                .await;
            self.publish_local_observation();
        }
        pub fn snapshot(&self, id: ObjectId) -> Snapshot {
            let trial = self.engine.trials.get(&id);
            let phase = trial
                .map(|t| match t.phase {
                    Phase::Binding => "binding",
                    Phase::Measuring => "measuring",
                    Phase::Ready => "ready",
                    Phase::Committed => "committed",
                    Phase::Finalized => "finalized",
                    Phase::ReturnPreparing => "return_preparing",
                    Phase::ReturnReady => "return_ready",
                    Phase::Returned => "returned",
                })
                .unwrap_or("retired");
            Snapshot {
                phase,
                direct_sender: self.wg.direct_src_of(&self.peer_key).is_some(),
                direct_ready: self.wg.path_trial_direct_ready(id),
                managed: self
                    .ctx
                    .path_trial_managed
                    .lock()
                    .unwrap()
                    .contains(&self.peer_id),
                windows: trial
                    .map(|t| t.measurements.windows.clone())
                    .unwrap_or_default(),
            }
        }
        pub fn fail_retained_direct(&self, id: ObjectId) {
            assert!(self.wg.fail_retained_path_trial_direct(id));
            assert!(!self.wg.path_trial_direct_ready(id));
        }
        pub async fn send_packet(&self, packet: &[u8]) -> bool {
            self.wg.send_ip_packet(packet).await
        }
        pub async fn receive_packet(&mut self) -> Option<Vec<u8>> {
            tokio::time::timeout(Duration::from_secs(2), self.inbox.recv())
                .await
                .ok()
                .flatten()
        }
    }
}

#[cfg(test)]
mod retained_repair_pacing {
    use super::*;
    #[tokio::test]
    async fn path_trial_failed_retained_repair_is_paced_and_identity_loss_cancels() {
        let own = WgKeypair::generate();
        let remote = WgKeypair::generate();
        let peer_id = ObjectId::new();
        let id = ObjectId::new();
        let np: NetmapPeer = serde_json::from_value(serde_json::json!({
            "node_id":peer_id.to_hex(),"overlay_ip":"100.64.0.2",
            "wg_public_key":remote.public_base64(),"reachable":true
        }))
        .unwrap();
        let peer = peer_config_from_netmap(&np).unwrap();
        let now = Instant::now();
        let original = Installed::base(peer.public_key, peer.overlay_ip, DirectTier::Public, now);
        let (out, mut rx) = mpsc::channel(16);
        let ctx = OverlayRuntime::new_relay(
            own.clone(),
            out,
            Box::new(|_, _, _| Err(std::io::Error::other("never open TUN"))),
            1280,
        )
        .with_org_primary(true);
        ctx.path_trial_managed.lock().unwrap().insert(peer_id);
        let mut installed = HashMap::from([(peer_id, original.clone())]);
        let mut peers = HashMap::from([(peer_id, np)]);
        let mut engine = Engine::new();
        engine.trials.insert(
            id,
            Trial {
                peer_id,
                peer,
                original,
                started: now,
                phase: Phase::Finalized,
                conn: None,
                measurements: Measurements::default(),
                committed_since: Some(now),
                last_control: now,
                return_id: None,
                return_retired: Vec::new(),
                return_started: None,
                next_return: now,
                direct_refreshed: None,
                requested: None,
            },
        );
        let (mut wg, _) = WgDevice::new(own.secret.clone());
        let mut discovery = super::super::super::orgrelay::discovery::Discovery::default();
        // No owned native trial to rebuild: failure must still be paced by
        // the existing Public-tier deadline instead of retried every tick.
        engine
            .tick_enabled(
                &ctx,
                &mut wg,
                &peers,
                &mut installed,
                &mut discovery,
                true,
                true,
            )
            .await;
        let first = engine.trials[&id].direct_refreshed.unwrap();
        for _ in 0..8 {
            engine
                .tick_enabled(
                    &ctx,
                    &mut wg,
                    &peers,
                    &mut installed,
                    &mut discovery,
                    true,
                    true,
                )
                .await;
            assert_eq!(engine.trials[&id].direct_refreshed, Some(first));
        }
        assert!(rx.try_recv().is_err());
        // Removed/rekeyed identity is checked BEFORE any repair, even with
        // newer repair metadata present; it cannot reinsert managed ownership.
        peers.clear();
        engine
            .tick_enabled(
                &ctx,
                &mut wg,
                &peers,
                &mut installed,
                &mut discovery,
                true,
                true,
            )
            .await;
        assert!(!engine.trials.contains_key(&id));
        assert!(!ctx.path_trial_managed.lock().unwrap().contains(&peer_id));
        assert_eq!(wg.peer_count(), 0);
    }
}

#[cfg(test)]
mod reset_gate_cause_tests {
    use super::*;
    #[tokio::test]
    async fn path_trial_reset_unavailable_handle_and_tick_account_exact_gate_without_protocol() {
        use crate::localapi::PathTrialResetReason as R;
        // The all-false case verifies fixed local -> server -> primary priority.
        for (local, supported, primary, handle_reason, tick_reason) in [
            (
                false,
                false,
                false,
                R::HandleLocalDisabled,
                R::TickLocalDisabled,
            ),
            (
                true,
                false,
                false,
                R::HandleServerUnsupported,
                R::TickServerUnsupported,
            ),
            (true, true, false, R::HandleNonPrimary, R::TickNonPrimary),
        ] {
            let key = WgKeypair::generate();
            let (out, mut rx) = mpsc::channel(4);
            let ctx = OverlayRuntime::new_relay(
                key.clone(),
                out,
                Box::new(|_, _, _| Err(std::io::Error::other("TUN must not open"))),
                1280,
            )
            .with_org_primary(primary);
            let (mut wg, _) = WgDevice::new(key.secret.clone());
            let peers = HashMap::new();
            let mut installed = HashMap::new();
            let mut engine = Engine::new();
            engine
                .control_enabled(
                    ServerMsg::OverlayPathTrialAbort {
                        trial_id: ObjectId::new(),
                    },
                    &ctx,
                    &mut wg,
                    &peers,
                    &mut installed,
                    supported,
                    local,
                )
                .await;
            assert_eq!(
                engine
                    .observation(&peers, &installed, true)
                    .unwrap()
                    .reset_diagnostics
                    .unwrap()
                    .last_reason,
                Some(handle_reason)
            );
            engine
                .tick_enabled(
                    &ctx,
                    &mut wg,
                    &peers,
                    &mut installed,
                    &mut super::super::super::orgrelay::discovery::Discovery::default(),
                    supported,
                    local,
                )
                .await;
            let d = engine
                .observation(&peers, &installed, true)
                .unwrap()
                .reset_diagnostics
                .unwrap();
            assert_eq!(d.last_reason, Some(tick_reason));
            let encoded = serde_json::to_value(d).unwrap();
            let total: u64 = encoded
                .as_object()
                .unwrap()
                .iter()
                .filter(|(key, _)| key.as_str() != "last_reason")
                .map(|(_, value)| value.as_u64().unwrap())
                .sum();
            assert_eq!(total, 2);
            assert_eq!(wg.peer_count(), 0);
            assert!(installed.is_empty() && engine.trials.is_empty());
            assert!(
                rx.try_recv().is_err(),
                "unavailable diagnostic must emit no control traffic"
            );
        }
    }
}
