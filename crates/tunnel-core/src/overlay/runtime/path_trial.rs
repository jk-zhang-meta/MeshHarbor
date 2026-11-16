// SPDX-License-Identifier: MPL-2.0
//! Bilateral path trials: identical authenticated echo metrics on the incumbent
//! and shadow; the server's two-member Commit is the only promotion authority.
use super::*;
use crate::overlay::{
    disco,
    orgrelay::{client::OrgRelayConn, member::OrgSession},
};
use crate::transport::relay::RelayConn;
use meshharbor_remote_control::signaling::{OrgRelayCandidateWire, ServerMsg};

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
    /// Median RTT (ms) of the direct and relay echoes over the open windows,
    /// for the trial's log lines.
    fn medians(&self) -> (Option<f64>, Option<f64>) {
        let med = |mut v: Vec<f64>| {
            v.sort_by(f64::total_cmp);
            v.get(v.len() / 2).copied()
        };
        (
            med(self.windows.iter().filter_map(|w| w.0).collect()),
            med(self.windows.iter().filter_map(|w| w.1).collect()),
        )
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
    /// True when the trial started over a bound OrgRelay incumbent rather than direct.
    incumbent_is_relay: bool,
    /// True once `backbone_only` (or a relay incumbent) retired the retained shadow:
    /// no direct rebuild, post-commit direct probe, or return-to-direct may run.
    direct_shadow_retired: bool,
    requested: Option<RequestedCandidate>,
}
pub(super) struct Bound {
    id: ObjectId,
    conn: Option<Arc<OrgRelayConn>>,
}
struct PromotedCarrier {
    conn: Arc<OrgRelayConn>,
    pubkey: [u8; 32],
    overlay_ip: Ipv4Addr,
    since: Instant,
}

pub(super) struct Engine {
    observation: observation::Observation,
    trials: HashMap<ObjectId, Trial>,
    /// Active relay connections promoted out of superseded `Phase::Finalized`
    /// trials while a newer `R1 -> R2` upgrade trial is evaluated. Kept alive
    /// if the new trial aborts before commit; closed once a replacement trial
    /// finalizes or the peer's trial-managed carrier is torn down.
    promoted_conns: HashMap<ObjectId, PromotedCarrier>,
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
            promoted_conns: HashMap::new(),
            retired: Vec::new(),
            tx,
            rx,
            serial: rand::random::<u64>() / 2,
            next_request: Instant::now(),
            pending_request: None,
            failed_requests: Vec::new(),
        }
    }
    fn peer_is_backbone_only(peer_id: ObjectId, peers: &HashMap<ObjectId, NetmapPeer>) -> bool {
        peers.get(&peer_id).is_some_and(|p| p.backbone_only)
    }

    fn promoted_current(
        peer_id: ObjectId,
        pc: &PromotedCarrier,
        peers: &HashMap<ObjectId, NetmapPeer>,
        installed: &HashMap<ObjectId, Installed>,
    ) -> bool {
        peers
            .get(&peer_id)
            .and_then(peer_config_from_netmap)
            .is_some_and(|p| p.public_key == pc.pubkey && p.overlay_ip == pc.overlay_ip)
            && installed.get(&peer_id).is_some_and(|p| {
                !p.is_direct
                    && p.pubkey == pc.pubkey
                    && p.overlay_ip == pc.overlay_ip
                    && p.since == pc.since
            })
    }

    /// Release any promoted connection and orphaned `path_trial_managed`
    /// ownership immediately when `peer_id` is evicted from the netmap.
    pub(super) fn on_peer_evicted(&mut self, peer_id: ObjectId, ctx: &OverlayRuntime) {
        if self
            .pending_request
            .as_ref()
            .is_some_and(|r| r.peer_id == peer_id)
        {
            self.pending_request = None;
        }
        if let Some(pc) = self.promoted_conns.remove(&peer_id) {
            pc.conn.close();
        }
        if !self
            .trials
            .values()
            .any(|t| t.peer_id == peer_id && t.committed_since.is_some())
        {
            ctx.path_trial_managed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&peer_id);
        }
    }

    fn current(
        t: &Trial,
        peers: &HashMap<ObjectId, NetmapPeer>,
        installed: &HashMap<ObjectId, Installed>,
    ) -> bool {
        let backbone_only = Self::peer_is_backbone_only(t.peer_id, peers);
        if backbone_only
            && (!t.incumbent_is_relay
                && matches!(t.phase, Phase::Binding | Phase::Measuring | Phase::Ready)
                || t.phase == Phase::Returned)
        {
            return false;
        }
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

    /// Immediately retire any trial-held direct state for peers that flipped to
    /// `backbone_only = true`, without restoring the direct shadow.
    pub(super) async fn retire_forbidden_direct_shadows(
        &mut self,
        ctx: &OverlayRuntime,
        wg: &mut WgDevice,
        peers: &HashMap<ObjectId, NetmapPeer>,
        installed: &mut HashMap<ObjectId, Installed>,
    ) {
        if let Some(pending) = &self.pending_request
            && Self::peer_is_backbone_only(pending.peer_id, peers)
        {
            self.pending_request = None;
        }
        let ids: Vec<ObjectId> = self
            .trials
            .iter()
            .filter(|(_, t)| !t.incumbent_is_relay && Self::peer_is_backbone_only(t.peer_id, peers))
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            let phase = self.trials.get(&id).map(|t| t.phase);
            match phase {
                Some(Phase::Binding | Phase::Measuring | Phase::Ready | Phase::Returned) => {
                    self.cancel(id, ctx, wg, peers, installed, true).await;
                }
                Some(
                    Phase::Committed
                    | Phase::Finalized
                    | Phase::ReturnPreparing
                    | Phase::ReturnReady,
                ) => {
                    let abort_return = {
                        let t = self.trials.get_mut(&id).unwrap();
                        let abort_id = matches!(
                            t.phase,
                            Phase::ReturnPreparing | Phase::ReturnReady
                        )
                        .then_some(t.return_id)
                        .flatten();
                        if let Some(rid) = t.return_id.take() {
                            t.return_retired.push(rid);
                            if t.return_retired.len() > 64 {
                                t.return_retired.remove(0);
                            }
                        }
                        t.return_started = None;
                        if matches!(t.phase, Phase::ReturnPreparing | Phase::ReturnReady) {
                            t.phase = Phase::Finalized;
                        }
                        t.direct_shadow_retired = true;
                        t.measurements = Measurements {
                            seq: rand::random::<u64>() / 2,
                            ..Default::default()
                        };
                        abort_id
                    };
                    wg.retire_path_trial_direct_shadow(id).await;
                    if let Some(return_id) = abort_return
                        && enabled()
                        && ctx.org_primary
                    {
                        Self::send(
                            &ctx.outbound,
                            ClientMsg::OverlayPathTrialReturnAbort {
                                trial_id: id,
                                return_id,
                            },
                        )
                        .await;
                    }
                }
                None => {}
            }
        }
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
        info!(trial = %id, peer = %t.peer_id, notify, "overlay path-trial: cancelled");
        if matches!(t.phase, Phase::Binding | Phase::Measuring | Phase::Ready)
            && let Some(requested) = t.requested.clone()
        {
            if self.failed_requests.len() >= MAX_TRIALS {
                self.failed_requests.remove(0);
            }
            self.failed_requests.push(requested);
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
        let preserve_promoted = current
            && !removed_active
            && self
                .promoted_conns
                .get(&t.peer_id)
                .is_some_and(|pc| Self::promoted_current(t.peer_id, pc, peers, installed));
        if !preserve_promoted {
            if let Some(pc) = self.promoted_conns.remove(&t.peer_id) {
                pc.conn.close();
            }
            ctx.path_trial_managed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&t.peer_id);
        }
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
    #[allow(clippy::too_many_arguments)] // Preserve the runtime owners and explicit local gate.
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
    #[allow(clippy::too_many_arguments)] // Same runtime-owner seam as control_enabled.
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
                path,
                requester_at_exit,
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
                info!(trial = %trial_id, peer = %peer_node_id, relay = %relay_node_id,
                    "overlay path-trial: started by the server — binding the relay, then measuring it against direct");
                let config = peers.get(&peer_node_id).and_then(peer_config_from_netmap);
                let backbone_only = Self::peer_is_backbone_only(peer_node_id, peers);
                let original = installed
                    .get(&peer_node_id)
                    .filter(|p| {
                        !p.stalled
                            && ((p.is_direct && !backbone_only)
                                || (!p.is_direct && p.relay_kind == Some(RelayKind::Org)))
                    })
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
                let incumbent_is_relay = !original.is_direct;
                let superseded_ids: Vec<ObjectId> = self
                    .trials
                    .iter()
                    .filter(|(_, t)| t.peer_id == peer_node_id)
                    .map(|(id, _)| *id)
                    .collect();
                let peer_slot_free = if superseded_ids.is_empty() {
                    true
                } else {
                    incumbent_is_relay
                        && superseded_ids.iter().all(|id| {
                            self.trials.get(id).is_some_and(|t| {
                                t.phase == Phase::Finalized
                                    && t.return_started.is_none()
                                    && Self::current(t, peers, installed)
                            })
                        })
                };
                let allowed = local_enabled
                    && ctx.org_primary
                    && supported
                    && self.trials.len().saturating_sub(superseded_ids.len()) < MAX_TRIALS
                    && peer_slot_free;
                let path_nodes = path.relay_node_ids();
                if !allowed
                    || (path_nodes.len() == 1 && requester_at_exit)
                    || (relay_node_id != path_nodes[0]
                        && relay_node_id != path_nodes[path_nodes.len() - 1])
                    || super::super::decode_public(&peer_wg_public_key) != Some(peer.public_key)
                    || original.pubkey != peer.public_key
                    || original.overlay_ip != peer.overlay_ip
                {
                    Self::send(&ctx.outbound, ClientMsg::OverlayPathTrialAbort { trial_id }).await;
                    return;
                }
                let now = Instant::now();
                let pending = self
                    .pending_request
                    .as_ref()
                    .filter(|r| r.request_id == request_id && r.peer_id == peer_node_id);
                if pending.is_some_and(|r| {
                    r.candidate.path != path
                        || r.candidate.requester_at_exit != requester_at_exit
                        || r.candidate.requester_relay_node_id() != relay_node_id
                }) {
                    Self::send(&ctx.outbound, ClientMsg::OverlayPathTrialAbort { trial_id }).await;
                    return;
                }
                let requested = pending
                    .filter(|r| {
                        now.saturating_duration_since(r.at) < PREPARE_TIMEOUT
                            && peers.get(&peer_node_id).is_some_and(|p| {
                                (p.wg_public_key.clone(), p.overlay_ip.clone()) == r.identity
                            })
                    })
                    .cloned();
                if requested.is_some() {
                    self.pending_request = None;
                }
                for old_id in superseded_ids {
                    if let Some(mut old_t) = self.trials.remove(&old_id) {
                        if let Some(conn) = old_t.conn.take() {
                            let promoted = PromotedCarrier {
                                conn,
                                pubkey: old_t.peer.public_key,
                                overlay_ip: old_t.peer.overlay_ip,
                                since: old_t.committed_since.unwrap_or(old_t.original.since),
                            };
                            if let Some(prev) = self.promoted_conns.insert(peer_node_id, promoted) {
                                prev.conn.close();
                            }
                        }
                        let _ = wg.promote_finalized_path_trial(old_id).await;
                        self.retired(old_id);
                    }
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
                        incumbent_is_relay,
                        direct_shadow_retired: incumbent_is_relay,
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
                        Ok((sock, relay, _)) => Some(Arc::new(
                            OrgRelayConn::new(
                                Arc::new(sock),
                                relay,
                                session.vni,
                                "path-trial".into(),
                            )
                            .with_rebind(session.generation, session.secret.clone()),
                        )),
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
                    if let Err(e) = tx.send(Bound { id: trial_id, conn }).await
                        && let Some(c) = e.0.conn
                    {
                        c.close();
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
                let (d, r) = t.measurements.medians();
                info!(trial = %trial_id, peer = %t.peer_id, direct_ms = ?d, relay_ms = ?r,
                    "overlay path-trial: committed — the pair rides the org relay, direct kept warm to return to");
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
                let mut finalized_peer = None;
                let retire_shadow = if let Some(t) = self.trials.get_mut(&trial_id)
                    && t.phase == Phase::Committed
                    && Self::current(t, peers, installed)
                    && wg.finalize_path_trial(trial_id)
                {
                    t.phase = Phase::Finalized;
                    finalized_peer = Some(t.peer_id);
                    if Self::peer_is_backbone_only(t.peer_id, peers) || t.direct_shadow_retired {
                        t.direct_shadow_retired = true;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };
                if retire_shadow {
                    wg.retire_path_trial_direct_shadow(trial_id).await;
                }
                if let Some(peer_id) = finalized_peer
                    && let Some(prev) = self.promoted_conns.remove(&peer_id)
                {
                    prev.conn.close();
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
                if Self::peer_is_backbone_only(t.peer_id, peers) || t.direct_shadow_retired {
                    t.direct_shadow_retired = true;
                    wg.retire_path_trial_direct_shadow(trial_id).await;
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
                if Self::peer_is_backbone_only(t.peer_id, peers) || t.direct_shadow_retired {
                    t.direct_shadow_retired = true;
                    wg.retire_path_trial_direct_shadow(trial_id).await;
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
                    let (d, r) = t.measurements.medians();
                    info!(trial = %trial_id, peer = %t.peer_id, direct_ms = ?d, relay_ms = ?r,
                        "overlay path-trial: returned to direct — it is no slower than the relay again");
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
                        && !t.direct_shadow_retired
                        && !Self::peer_is_backbone_only(t.peer_id, peers)
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
                if Self::peer_is_backbone_only(t.peer_id, peers) || t.direct_shadow_retired {
                    if t.phase == Phase::Returned {
                        if wg.abort_path_trial_return(trial_id) {
                            let now = Instant::now();
                            installed.insert(
                                t.peer_id,
                                Installed {
                                    hs_done: true,
                                    initiated: true,
                                    relay_kind: Some(RelayKind::Org),
                                    carrier_local: t
                                        .conn
                                        .as_ref()
                                        .and_then(|c| c.local_addr().ok()),
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
                        } else {
                            self.cancel(trial_id, ctx, wg, peers, installed, false)
                                .await;
                            return;
                        }
                    }
                    t.direct_shadow_retired = true;
                    wg.retire_path_trial_direct_shadow(trial_id).await;
                    t.return_retired.push(return_id);
                    if t.return_retired.len() > 64 {
                        t.return_retired.remove(0);
                    }
                    t.return_id = None;
                    t.return_started = None;
                    if matches!(
                        t.phase,
                        Phase::ReturnPreparing | Phase::ReturnReady | Phase::Returned
                    ) {
                        t.phase = Phase::Finalized;
                    }
                    return;
                }
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
    #[allow(clippy::too_many_arguments)] // Runtime owners and explicit gate are independently borrowed.
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
    #[allow(clippy::too_many_arguments)] // Same runtime-owner seam as tick_enabled.
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
        let mut released_promoted = Vec::new();
        self.promoted_conns.retain(|peer_id, pc| {
            let keep = Self::promoted_current(*peer_id, pc, peers, installed);
            if !keep {
                pc.conn.close();
                released_promoted.push(*peer_id);
            }
            keep
        });
        if !released_promoted.is_empty() {
            let mut managed = ctx
                .path_trial_managed
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for peer_id in released_promoted {
                if !self
                    .trials
                    .values()
                    .any(|t| t.peer_id == peer_id && t.committed_since.is_some())
                {
                    managed.remove(&peer_id);
                }
            }
        }
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
            let direct_forbidden =
                Self::peer_is_backbone_only(self.trials[&id].peer_id, peers)
                    || self.trials[&id].direct_shadow_retired;
            if direct_forbidden {
                self.trials.get_mut(&id).unwrap().direct_shadow_retired = true;
                wg.retire_path_trial_direct_shadow(id).await;
            }
            let t = self.trials.get_mut(&id).unwrap();
            // A dead retained Tunn cannot be resurrected by stateless echo.
            // Repair only the non-active shadow and only before a Ready vote;
            // Returned/Committed decisions must keep both receivers unchanged.
            if !direct_forbidden
                && matches!(t.phase, Phase::Finalized | Phase::ReturnPreparing)
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
                        let (d, r) = t.measurements.medians();
                        info!(trial = %id, peer = %t.peer_id, direct_ms = ?d, relay_ms = ?r,
                            "overlay path-trial: the relay measured faster than direct — ready to commit");
                    }
                } else if t.phase == Phase::Ready {
                    self.cancel(id, ctx, wg, peers, installed, true).await;
                    continue;
                }
            } else if !direct_forbidden
                && t.phase == Phase::Finalized
                && now >= t.next_return
                && t.measurements.return_ready(now)
                && wg.path_trial_direct_ready(id)
            {
                let return_id = t.return_id.unwrap_or_default();
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
                    if (t.phase != Phase::ReturnReady
                        || now.duration_since(t.last_control) >= Duration::from_secs(5))
                        && Self::send(
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
            } else if t.phase == Phase::Returned
                && now.duration_since(t.last_control) >= Duration::from_secs(5)
            {
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
            let t = self.trials.get_mut(&id).unwrap();
            let measure_allowed = !direct_forbidden
                || (t.incumbent_is_relay
                    && matches!(t.phase, Phase::Measuring | Phase::Ready));
            if measure_allowed
                && t.measurements.round.is_none()
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
            if candidate.path.relay_node_ids().len() > 1
                && !(crate::overlay::orgrelay::backbone::path_enabled() || ctx.backbone_enabled)
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
                    request_id: serial,
                    path: candidate.path.clone(),
                    requester_at_exit: candidate.requester_at_exit,
                },
            )
            .await
            {
                discovery.note_attempt(peers, peer, &candidate, now);
                info!(%peer, path = ?candidate.path.relay_node_ids(), requester_at_exit = candidate.requester_at_exit,
                    "overlay path-trial: requested a relay trial for a direct peer");
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
                    incumbent_is_relay: false,
                    direct_shadow_retired: false,
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
                    incumbent_is_relay: false,
                    direct_shadow_retired: false,
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
            path: meshharbor_remote_control::signaling::RelayPathWire::new(vec![
                ObjectId::new(),
                ObjectId::new(),
            ])
            .unwrap(),
            requester_at_exit: false,
            endpoints: vec!["8.8.8.8:3478".into()],
        };
        let second = OrgRelayCandidateWire {
            path: meshharbor_remote_control::signaling::RelayPathWire::new(vec![ObjectId::new()])
                .unwrap(),
            requester_at_exit: false,
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
                incumbent_is_relay: false,
                direct_shadow_retired: false,
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
                .requester_relay_node_id(),
            second.requester_relay_node_id()
        );
        // Rotate around to prove the first candidate is excluded by actual
        // negative feedback, not merely skipped by the next-after cursor.
        discovery.note_attempt(&peers, peer_id, &second, now);
        assert_eq!(
            discovery
                .candidate_for(&peers, peer_id, now)
                .unwrap()
                .requester_relay_node_id(),
            second.requester_relay_node_id()
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
                incumbent_is_relay: false,
                direct_shadow_retired: false,
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
        /// Drive the production limiter with an explicit monotonic test clock.
        pub async fn request_discovery_at(&mut self, now: Instant) {
            self.discovery
                .request(true, true, &self.peers, &self.ctx.outbound, now)
                .await;
        }
        pub fn receive_discovery(&mut self, msg: ServerMsg) -> usize {
            let ServerMsg::OverlayOrgRelayCandidates {
                peer_node_id,
                request_id,
                candidates,
                ttl_secs,
                next_cursor,
                scan,
            } = msg
            else {
                panic!("expected actual server discovery metadata");
            };
            self.discovery.receive_wire_page(
                &self.peers,
                peer_node_id,
                request_id,
                candidates,
                ttl_secs,
                next_cursor,
                scan,
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
        pub fn with_backbone_enabled(mut self, enabled: bool) -> Self {
            self.ctx = self.ctx.with_backbone_enabled(enabled);
            self
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
                incumbent_is_relay: false,
                direct_shadow_retired: false,
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

#[cfg(test)]
mod sequential_relay_upgrade_tests {
    use super::*;
    use crate::overlay::orgrelay::bind::{BindSecret, CookieKey};
    use crate::overlay::orgrelay::client::bind_any;
    use crate::overlay::orgrelay::server::{RelayServer, RelayStats};
    use crate::overlay::orgrelay::session::{Member, Session};
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use meshharbor_remote_control::signaling::RelayPathWire;

    fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total = (20 + payload.len()) as u16;
        let mut p = Vec::with_capacity(total as usize);
        p.push(0x45);
        p.push(0);
        p.extend_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }

    async fn spawn_relay_session(
        vni: u32,
        generation: u64,
        pub_a: [u8; 32],
        pub_b: [u8; 32],
        sec_a: [u8; 32],
        sec_b: [u8; 32],
    ) -> (SocketAddr, Arc<RelayStats>, tokio::task::JoinHandle<()>) {
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        let stats = Arc::new(RelayStats::default());
        let (server, handle) =
            RelayServer::new(CookieKey::from_bytes([0x42; 32]), stats.clone());
        let now = Instant::now();
        assert!(handle.install(Session {
            vni,
            generation,
            members: [
                Member {
                    wg_public: pub_a,
                    secret: BindSecret::from_bytes(sec_a),
                },
                Member {
                    wg_public: pub_b,
                    secret: BindSecret::from_bytes(sec_b),
                },
            ],
            bound: [None, None],
            max_lifetime: now + Duration::from_secs(120),
            idle_deadline: now + Duration::from_secs(120),
            bind_deadline: now + Duration::from_secs(60),
        }));
        let task = tokio::spawn(async move {
            let _keep_handle = handle;
            server.serve(sock).await;
        });
        (addr, stats, task)
    }

    fn seed_ready_windows(t: &mut Trial, now: Instant, inc_ms: f64, cand_ms: f64) {
        for i in 0..9 {
            let at = now - Duration::from_millis((9 - i) * 100);
            let a = |result| Attempt {
                nonce: [0; 8],
                at,
                dst: None,
                result: Some(result),
            };
            t.measurements.round = Some(Round {
                direct: a(Some(inc_ms)),
                relay: a(Some(cand_ms)),
            });
            t.measurements.finish(at);
        }
    }

    #[tokio::test]
    async fn sequential_relay_upgrade_r0_to_r1_to_r2_preserves_r1_on_abort_and_switches_to_r2_on_commit()
    {
        let (kp_a, kp_b) = (WgKeypair::generate(), WgKeypair::generate());
        let (id_a, id_b) = (ObjectId::new(), ObjectId::new());
        let (ip_a, ip_b) = (Ipv4Addr::new(100, 64, 0, 10), Ipv4Addr::new(100, 64, 0, 11));
        let (_r0_id, r1_id, r2_id) = (ObjectId::new(), ObjectId::new(), ObjectId::new());

        let np_b: NetmapPeer = serde_json::from_value(serde_json::json!({
            "node_id": id_b.to_hex(),
            "overlay_ip": ip_b.to_string(),
            "wg_public_key": kp_b.public_base64(),
            "reachable": true,
        }))
        .unwrap();
        let np_a: NetmapPeer = serde_json::from_value(serde_json::json!({
            "node_id": id_a.to_hex(),
            "overlay_ip": ip_a.to_string(),
            "wg_public_key": kp_a.public_base64(),
            "reachable": true,
        }))
        .unwrap();

        // Start with an active bound OrgRelay R0 carrier between A and B.
        let (s0_a, s0_b) = ([0x10; 32], [0x11; 32]);
        let (r0_addr, _, r0_task) = spawn_relay_session(
            100,
            1,
            kp_a.public.to_bytes(),
            kp_b.public.to_bytes(),
            s0_a,
            s0_b,
        )
        .await;
        let (sock0_a, _, _) =
            bind_any(&[r0_addr], 100, 1, &BindSecret::from_bytes(s0_a), Duration::from_secs(2))
                .await
                .unwrap();
        let (sock0_b, _, _) =
            bind_any(&[r0_addr], 100, 1, &BindSecret::from_bytes(s0_b), Duration::from_secs(2))
                .await
                .unwrap();
        let conn0_a = Arc::new(OrgRelayConn::new(Arc::new(sock0_a), r0_addr, 100, "r0".into()));
        let conn0_b = Arc::new(OrgRelayConn::new(Arc::new(sock0_b), r0_addr, 100, "r0".into()));

        let (out_a, mut rx_a) = mpsc::channel(64);
        let (out_b, mut rx_b) = mpsc::channel(64);
        let ctx_a = OverlayRuntime::new_relay(
            kp_a.clone(),
            out_a,
            Box::new(|_, _, _| Err(std::io::Error::other("no TUN"))),
            1280,
        )
        .with_org_primary(true);
        let ctx_b = OverlayRuntime::new_relay(
            kp_b.clone(),
            out_b,
            Box::new(|_, _, _| Err(std::io::Error::other("no TUN"))),
            1280,
        )
        .with_org_primary(true);

        let (mut wg_a, mut inbox_a) = WgDevice::new(kp_a.secret.clone());
        let (mut wg_b, mut inbox_b) = WgDevice::new(kp_b.secret.clone());
        wg_a.add_peer(
            kp_b.public.to_bytes(),
            ip_b,
            Carrier::relay(conn0_a.clone(), conn0_a.synth_peer()),
            true,
        );
        wg_b.add_peer(
            kp_a.public.to_bytes(),
            ip_a,
            Carrier::relay(conn0_b.clone(), conn0_b.synth_peer()),
            false,
        );
        let pkt0 = ipv4_packet(ip_a, ip_b, b"over-r0");
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                wg_a.send_ip_packet(&pkt0).await;
                if let Ok(Some(got)) =
                    tokio::time::timeout(Duration::from_millis(80), inbox_b.recv()).await
                {
                    assert_eq!(got, pkt0);
                    break;
                }
            }
        })
        .await
        .expect("initial R0 carrier delivers traffic");

        let now0 = Instant::now();
        let mut installed_a = HashMap::from([(
            id_b,
            Installed {
                hs_done: true,
                initiated: true,
                relay_kind: Some(RelayKind::Org),
                carrier_dst: Some(conn0_a.synth_peer()),
                ..Installed::base(kp_b.public.to_bytes(), ip_b, DirectTier::Relay, now0)
            },
        )]);
        let mut installed_b = HashMap::from([(
            id_a,
            Installed {
                hs_done: true,
                initiated: false,
                relay_kind: Some(RelayKind::Org),
                carrier_dst: Some(conn0_b.synth_peer()),
                ..Installed::base(kp_a.public.to_bytes(), ip_a, DirectTier::Relay, now0)
            },
        )]);
        let peers_a = HashMap::from([(id_b, np_b)]);
        let peers_b = HashMap::from([(id_a, np_a)]);
        let mut eng_a = Engine::new();
        let mut eng_b = Engine::new();
        let mut disc_a = super::super::super::orgrelay::discovery::Discovery::default();
        let mut disc_b = super::super::super::orgrelay::discovery::Discovery::default();

        // ---- Phase 1: R0 -> R1 upgrade trial commits and finalizes ----
        let t1 = ObjectId::new();
        let (s1_a, s1_b) = ([0x20; 32], [0x21; 32]);
        let (r1_addr, r1_stats, r1_task) = spawn_relay_session(
            101,
            2,
            kp_a.public.to_bytes(),
            kp_b.public.to_bytes(),
            s1_a,
            s1_b,
        )
        .await;
        eng_a
            .control_enabled(
                ServerMsg::OverlayPathTrialStart {
                    trial_id: t1,
                    request_id: 1,
                    path: RelayPathWire::new(vec![r1_id]).unwrap(),
                    requester_at_exit: false,
                    peer_node_id: id_b,
                    peer_wg_public_key: kp_b.public_base64(),
                    vni: 101,
                    generation: 2,
                    relay_node_id: r1_id,
                    relay_endpoints: vec![r1_addr.to_string()],
                    bind_secret: BASE64.encode(s1_a),
                    bind_secs: 30,
                    max_lifetime_secs: 120,
                },
                &ctx_a,
                &mut wg_a,
                &peers_a,
                &mut installed_a,
                true,
                true,
            )
            .await;
        eng_b
            .control_enabled(
                ServerMsg::OverlayPathTrialStart {
                    trial_id: t1,
                    request_id: 1,
                    path: RelayPathWire::new(vec![r1_id]).unwrap(),
                    requester_at_exit: false,
                    peer_node_id: id_a,
                    peer_wg_public_key: kp_a.public_base64(),
                    vni: 101,
                    generation: 2,
                    relay_node_id: r1_id,
                    relay_endpoints: vec![r1_addr.to_string()],
                    bind_secret: BASE64.encode(s1_b),
                    bind_secs: 30,
                    max_lifetime_secs: 120,
                },
                &ctx_b,
                &mut wg_b,
                &peers_b,
                &mut installed_b,
                true,
                true,
            )
            .await;

        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                eng_a
                    .tick_enabled(&ctx_a, &mut wg_a, &peers_a, &mut installed_a, &mut disc_a, true, true)
                    .await;
                eng_b
                    .tick_enabled(&ctx_b, &mut wg_b, &peers_b, &mut installed_b, &mut disc_b, true, true)
                    .await;
                if wg_a.path_trial_handshake_done(t1) && wg_b.path_trial_handshake_done(t1) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("R1 trial handshake completes");

        let now1 = Instant::now();
        seed_ready_windows(eng_a.trials.get_mut(&t1).unwrap(), now1, 120.0, 60.0);
        seed_ready_windows(eng_b.trials.get_mut(&t1).unwrap(), now1, 120.0, 60.0);
        eng_a.trials.get_mut(&t1).unwrap().phase = Phase::Ready;
        eng_b.trials.get_mut(&t1).unwrap().phase = Phase::Ready;
        let conn1_a = eng_a.trials[&t1].conn.clone().unwrap();

        for msg in [
            ServerMsg::OverlayPathTrialCommit { trial_id: t1 },
            ServerMsg::OverlayPathTrialFinalize { trial_id: t1 },
        ] {
            eng_a
                .control_enabled(msg.clone(), &ctx_a, &mut wg_a, &peers_a, &mut installed_a, true, true)
                .await;
            eng_b
                .control_enabled(msg, &ctx_b, &mut wg_b, &peers_b, &mut installed_b, true, true)
                .await;
        }
        while rx_a.try_recv().is_ok() {}
        while rx_b.try_recv().is_ok() {}
        assert!(eng_a.trials[&t1].phase == Phase::Finalized);
        assert!(eng_b.trials[&t1].phase == Phase::Finalized);
        conn0_a.close();
        conn0_b.close();

        // ---- Phase 2: R1 -> R2_bad starts over Finalized R1, then aborts -> R1 preserved! ----
        let t2_bad = ObjectId::new();
        eng_a
            .control_enabled(
                ServerMsg::OverlayPathTrialStart {
                    trial_id: t2_bad,
                    request_id: 2,
                    path: RelayPathWire::new(vec![r2_id]).unwrap(),
                    requester_at_exit: false,
                    peer_node_id: id_b,
                    peer_wg_public_key: kp_b.public_base64(),
                    vni: 102,
                    generation: 3,
                    relay_node_id: r2_id,
                    relay_endpoints: vec!["127.0.0.1:9".into()],
                    bind_secret: BASE64.encode([0x30; 32]),
                    bind_secs: 30,
                    max_lifetime_secs: 120,
                },
                &ctx_a,
                &mut wg_a,
                &peers_a,
                &mut installed_a,
                true,
                true,
            )
            .await;
        assert!(
            eng_a.trials.contains_key(&t2_bad),
            "client must admit second upgrade trial R1->R2 after R0->R1 finalized"
        );
        assert!(!eng_a.trials.contains_key(&t1));
        assert!(eng_a.retired.contains(&t1));

        // Abort t2_bad before commit: R1 must stay installed, managed, and carrying traffic!
        eng_a
            .control_enabled(
                ServerMsg::OverlayPathTrialAbort { trial_id: t2_bad },
                &ctx_a,
                &mut wg_a,
                &peers_a,
                &mut installed_a,
                true,
                true,
            )
            .await;
        assert!(installed_a.contains_key(&id_b));
        assert!(conn1_a.is_alive(), "R1 connection must stay alive when R1->R2 aborts");
        assert!(ctx_a.path_trial_managed.lock().unwrap().contains(&id_b));
        let r1_fwd_before = r1_stats.snapshot().forwarded;
        let pkt1 = ipv4_packet(ip_a, ip_b, b"still-on-r1");
        wg_a.send_ip_packet(&pkt1).await;
        let got1 = tokio::time::timeout(Duration::from_secs(2), inbox_b.recv())
            .await
            .expect("R1 still delivers after R1->R2 abort")
            .unwrap();
        assert_eq!(got1, pkt1);
        assert!(r1_stats.snapshot().forwarded > r1_fwd_before);

        // ---- Phase 3: R1 -> R2_good commits & finalizes -> switches to R2 & ignores late Abort(t1) ----
        let t2_good = ObjectId::new();
        let (s2_a, s2_b) = ([0x40; 32], [0x41; 32]);
        let (r2_addr, r2_stats, r2_task) = spawn_relay_session(
            103,
            4,
            kp_a.public.to_bytes(),
            kp_b.public.to_bytes(),
            s2_a,
            s2_b,
        )
        .await;
        eng_a
            .control_enabled(
                ServerMsg::OverlayPathTrialStart {
                    trial_id: t2_good,
                    request_id: 3,
                    path: RelayPathWire::new(vec![r2_id]).unwrap(),
                    requester_at_exit: false,
                    peer_node_id: id_b,
                    peer_wg_public_key: kp_b.public_base64(),
                    vni: 103,
                    generation: 4,
                    relay_node_id: r2_id,
                    relay_endpoints: vec![r2_addr.to_string()],
                    bind_secret: BASE64.encode(s2_a),
                    bind_secs: 30,
                    max_lifetime_secs: 120,
                },
                &ctx_a,
                &mut wg_a,
                &peers_a,
                &mut installed_a,
                true,
                true,
            )
            .await;
        eng_b
            .control_enabled(
                ServerMsg::OverlayPathTrialStart {
                    trial_id: t2_good,
                    request_id: 3,
                    path: RelayPathWire::new(vec![r2_id]).unwrap(),
                    requester_at_exit: false,
                    peer_node_id: id_a,
                    peer_wg_public_key: kp_a.public_base64(),
                    vni: 103,
                    generation: 4,
                    relay_node_id: r2_id,
                    relay_endpoints: vec![r2_addr.to_string()],
                    bind_secret: BASE64.encode(s2_b),
                    bind_secs: 30,
                    max_lifetime_secs: 120,
                },
                &ctx_b,
                &mut wg_b,
                &peers_b,
                &mut installed_b,
                true,
                true,
            )
            .await;

        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                eng_a
                    .tick_enabled(&ctx_a, &mut wg_a, &peers_a, &mut installed_a, &mut disc_a, true, true)
                    .await;
                eng_b
                    .tick_enabled(&ctx_b, &mut wg_b, &peers_b, &mut installed_b, &mut disc_b, true, true)
                    .await;
                if wg_a.path_trial_handshake_done(t2_good) && wg_b.path_trial_handshake_done(t2_good) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("R2 trial handshake completes");

        let now2 = Instant::now();
        seed_ready_windows(eng_a.trials.get_mut(&t2_good).unwrap(), now2, 60.0, 25.0);
        seed_ready_windows(eng_b.trials.get_mut(&t2_good).unwrap(), now2, 60.0, 25.0);
        eng_a.trials.get_mut(&t2_good).unwrap().phase = Phase::Ready;
        eng_b.trials.get_mut(&t2_good).unwrap().phase = Phase::Ready;

        for msg in [
            ServerMsg::OverlayPathTrialCommit { trial_id: t2_good },
            ServerMsg::OverlayPathTrialFinalize { trial_id: t2_good },
            // Server retires superseded t1 upon finalizing t2_good by pushing Abort(t1).
            ServerMsg::OverlayPathTrialAbort { trial_id: t1 },
        ] {
            eng_a
                .control_enabled(msg.clone(), &ctx_a, &mut wg_a, &peers_a, &mut installed_a, true, true)
                .await;
            eng_b
                .control_enabled(msg, &ctx_b, &mut wg_b, &peers_b, &mut installed_b, true, true)
                .await;
        }

        assert!(eng_a.trials[&t2_good].phase == Phase::Finalized);
        assert!(eng_b.trials[&t2_good].phase == Phase::Finalized);
        assert!(
            !conn1_a.is_alive(),
            "superseded R1 carrier must be closed once R2 finalizes"
        );
        let r2_fwd_before = r2_stats.snapshot().forwarded;
        let pkt2 = ipv4_packet(ip_a, ip_b, b"switched-to-r2");
        wg_a.send_ip_packet(&pkt2).await;
        let got2 = tokio::time::timeout(Duration::from_secs(2), inbox_b.recv())
            .await
            .expect("R2 delivers traffic after R1->R2 finalization and Abort(t1)")
            .unwrap();
        assert_eq!(got2, pkt2);
        assert!(r2_stats.snapshot().forwarded > r2_fwd_before);
        let pkt2_rev = ipv4_packet(ip_b, ip_a, b"reply-over-r2");
        wg_b.send_ip_packet(&pkt2_rev).await;
        let got2_rev = tokio::time::timeout(Duration::from_secs(2), inbox_a.recv())
            .await
            .expect("B->A traffic also rides R2")
            .unwrap();
        assert_eq!(got2_rev, pkt2_rev);

        let conn2_a = eng_a.trials[&t2_good].conn.clone().unwrap();
        assert!(conn2_a.is_alive());

        // ---- Phase 4: Follow-up R2 -> R3_bad aborts before commit, then peer is removed and re-added ----
        let t3_bad = ObjectId::new();
        let (s3_a, _s3_b) = ([0x50; 32], [0x51; 32]);
        eng_a
            .control_enabled(
                ServerMsg::OverlayPathTrialStart {
                    trial_id: t3_bad,
                    request_id: 4,
                    path: RelayPathWire::new(vec![r1_id]).unwrap(),
                    requester_at_exit: false,
                    peer_node_id: id_b,
                    peer_wg_public_key: kp_b.public_base64(),
                    vni: 104,
                    generation: 5,
                    relay_node_id: r1_id,
                    relay_endpoints: vec![r1_addr.to_string()],
                    bind_secret: BASE64.encode(s3_a),
                    bind_secs: 30,
                    max_lifetime_secs: 120,
                },
                &ctx_a,
                &mut wg_a,
                &peers_a,
                &mut installed_a,
                true,
                true,
            )
            .await;
        eng_a
            .control_enabled(
                ServerMsg::OverlayPathTrialAbort { trial_id: t3_bad },
                &ctx_a,
                &mut wg_a,
                &peers_a,
                &mut installed_a,
                true,
                true,
            )
            .await;
        assert!(eng_a.trials.is_empty());
        assert!(eng_a.promoted_conns.contains_key(&id_b));
        assert!(ctx_a.path_trial_managed.lock().unwrap().contains(&id_b));

        // Evict peer B (netmap ACL/removal): tick pruning & explicit eviction must BOTH release
        // promoted_conns AND clear path_trial_managed so B can receive a fresh relay session on return!
        let mut peers_a_evicted = peers_a.clone();
        let saved_np_b = peers_a_evicted.remove(&id_b).unwrap();
        installed_a.remove(&id_b);
        wg_a.remove_peer(&kp_b.public.to_bytes()).await;
        eng_a
            .tick_enabled(
                &ctx_a,
                &mut wg_a,
                &peers_a_evicted,
                &mut installed_a,
                &mut disc_a,
                true,
                true,
            )
            .await;
        assert!(
            !conn2_a.is_alive(),
            "promoted R2 carrier must close on peer eviction"
        );
        assert!(
            !eng_a.promoted_conns.contains_key(&id_b),
            "promoted_conns must be pruned on peer removal"
        );
        assert!(
            !ctx_a.path_trial_managed.lock().unwrap().contains(&id_b),
            "path_trial_managed must be cleared when promoted peer is removed so rejoin relay grants are accepted"
        );

        // Re-add peer B on a fresh org-relay session R_rejoin and prove packet delivery succeeds!
        let (sr_a, sr_b) = ([0x60; 32], [0x61; 32]);
        let (rejoin_addr, rejoin_stats, rejoin_task) = spawn_relay_session(
            105,
            6,
            kp_a.public.to_bytes(),
            kp_b.public.to_bytes(),
            sr_a,
            sr_b,
        )
        .await;
        let (sockr_a, _, _) = bind_any(
            &[rejoin_addr],
            105,
            6,
            &BindSecret::from_bytes(sr_a),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let (sockr_b, _, _) = bind_any(
            &[rejoin_addr],
            105,
            6,
            &BindSecret::from_bytes(sr_b),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let conn_rejoin_a = Arc::new(OrgRelayConn::new(
            Arc::new(sockr_a),
            rejoin_addr,
            105,
            "rejoin".into(),
        ));
        let conn_rejoin_b = Arc::new(OrgRelayConn::new(
            Arc::new(sockr_b),
            rejoin_addr,
            105,
            "rejoin".into(),
        ));
        peers_a_evicted.insert(id_b, saved_np_b);
        wg_b.remove_peer(&kp_a.public.to_bytes()).await;
        wg_a.add_peer(
            kp_b.public.to_bytes(),
            ip_b,
            Carrier::relay(conn_rejoin_a.clone(), conn_rejoin_a.synth_peer()),
            true,
        );
        wg_b.add_peer(
            kp_a.public.to_bytes(),
            ip_a,
            Carrier::relay(conn_rejoin_b.clone(), conn_rejoin_b.synth_peer()),
            false,
        );
        installed_a.insert(
            id_b,
            Installed {
                hs_done: true,
                initiated: true,
                relay_kind: Some(RelayKind::Org),
                carrier_dst: Some(conn_rejoin_a.synth_peer()),
                ..Installed::base(kp_b.public.to_bytes(), ip_b, DirectTier::Relay, Instant::now())
            },
        );
        assert!(
            !ctx_a.path_trial_managed.lock().unwrap().contains(&id_b),
            "re-added peer remains eligible for ordinary org-relay sessions"
        );
        let pkt_rejoin = ipv4_packet(ip_a, ip_b, b"rejoined-after-eviction");
        let got_rejoin = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                wg_a.send_ip_packet(&pkt_rejoin).await;
                if let Ok(Some(got)) =
                    tokio::time::timeout(Duration::from_millis(80), inbox_b.recv()).await
                {
                    break got;
                }
            }
        })
        .await
        .expect("re-added peer delivers over new relay session");
        assert_eq!(got_rejoin, pkt_rejoin);
        assert!(rejoin_stats.snapshot().forwarded > 0);

        r0_task.abort();
        r1_task.abort();
        r2_task.abort();
        rejoin_task.abort();
    }
}
