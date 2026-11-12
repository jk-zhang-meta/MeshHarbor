// SPDX-License-Identifier: MPL-2.0
//! The runtime half of path quality: it sends the echo probes
//! [`path_quality`](crate::overlay::path_quality) asks for, answers the
//! peers' probes, reports each window, and honors the server's prefer-relay
//! verdict (`NetmapPeer::prefer_relay_ms`).
//!
//! Who decides what:
//!
//! * **This member measures.** Direct-path probes ride the direct carrier, or
//!   the peer's direct candidates while the pair is on the relay. Relay-path
//!   probes ride the relay carrier, or, while the pair is on a direct
//!   carrier, the `/derp` mux as standby payloads (`DerpMux::set_echo_sink`).
//! * **The server decides**, from both members' reports, and stamps a
//!   time-limited verdict on both ends' netmap rows.
//! * **This member obeys, within bounds.** Under a verdict it moves the pair
//!   to the relay and holds every direct tier down
//!   ([`path::PathMonitor::on_prefer_relay`]). It keeps measuring both paths,
//!   so the server can take the verdict back when the direct path heals. The
//!   hold only ever runs out: it is capped at
//!   [`path::PREFER_RELAY_MAX`] per row, and this member voids it at once if
//!   the relay itself stops carrying.
//!
//! `MESHHARBORD_OVERLAY_PREFER_RELAY=0` switches all of it off: no probe, no
//! report, no echo answered, and a verdict row is ignored, so the pair
//! behaves as it did before this module existed.

use super::*;
use crate::overlay::disco;
use crate::overlay::path_quality::{Action, Engine, Leg, PeerNow};
use crate::transport::derp::PathEcho;

/// Business traffic within this long makes a pair "active": watched with a
/// direct probe a second instead of by the 5 s disco table.
const ACTIVE_FOR: Duration = Duration::from_secs(15);
/// How often a held pair still on a direct carrier is moved again (the relay
/// may have been unbuildable the first time).
const DEMOTE_RETRY: Duration = Duration::from_secs(5);
/// Echo frames the mux may queue for the responder.
const ECHO_QUEUE: usize = 256;
/// At most one echo answered per peer per this long: a prober sends one a
/// second, and an answer is a frame through the relay.
const ECHO_ANSWER_SPACING: Duration = Duration::from_millis(200);
/// What a relay echo reports as its observed source: nothing. The pong's
/// observed-address field is a direct-path (srflx) reading.
const NO_SOURCE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// How long the walk runs every tick after the server withdrew a verdict, so
/// the direct probe starts at once even where a spacing pin held the first
/// walk back.
pub(super) const WITHDRAWN_WALK: Duration = Duration::from_secs(30);

/// `MESHHARBORD_OVERLAY_PREFER_RELAY`: measure path quality, report it, and
/// honor the server's prefer-relay verdict. `0|false|no|off` restores the
/// behavior before this module.
fn enabled() -> bool {
    crate::env::flag("OVERLAY_PREFER_RELAY", true)
}

/// What one tick changed, for the loop's usual tails.
#[derive(Default)]
pub(super) struct Outcome {
    /// A carrier was replaced: reconcile exit routing and republish the view.
    pub(super) changed: bool,
    /// A hold was voided here: walk now, so the direct path is probed at once.
    pub(super) walk: bool,
}

struct TrafficSeen {
    counters: (u64, u64),
    moved_at: Option<Instant>,
    relay_rx_at: Option<Instant>,
}

/// The loop-side state of path quality.
pub(super) struct PreferRelay {
    /// The kill switch, read once ([`enabled`]). Off: nothing here acts.
    on: bool,
    engine: Engine,
    /// The server's `OverlayNetworkInfo::path_quality_v1`: it takes the
    /// reports. Without it nothing is measured and nothing is sent.
    pub(super) server_wants: bool,
    /// The mux whose path echoes the responder task serves, and the task.
    echo: Option<(std::sync::Weak<DerpMux>, tokio::task::JoinHandle<()>)>,
    /// Relay-path answers the responder task saw: `(peer, nonce, arrival)`.
    pongs_tx: mpsc::Sender<([u8; 32], [u8; 8], Instant)>,
    pongs_rx: mpsc::Receiver<([u8; 32], [u8; 8], Instant)>,
    /// Each peer's last business counters and when they last moved.
    traffic: HashMap<ObjectId, TrafficSeen>,
    /// When a held peer's move to the relay was last tried.
    demote_tried: HashMap<ObjectId, Instant>,
    /// Static-static secrets, per peer key: one X25519 instead of one a probe.
    shared: HashMap<[u8; 32], [u8; 32]>,
    /// Peers whose pending-verdict wait has been logged.
    pending_logged: HashSet<ObjectId>,
}

impl PreferRelay {
    pub(super) fn new() -> Self {
        Self::with(enabled())
    }

    /// With the kill switch as given, whatever the environment says.
    pub(super) fn with(on: bool) -> Self {
        let (pongs_tx, pongs_rx) = mpsc::channel(ECHO_QUEUE);
        Self {
            on,
            engine: Engine::new(),
            server_wants: false,
            echo: None,
            pongs_tx,
            pongs_rx,
            traffic: HashMap::new(),
            demote_tried: HashMap::new(),
            shared: HashMap::new(),
            pending_logged: HashSet::new(),
        }
    }

    /// Is the feature on (the kill switch not thrown)?
    pub(super) fn on(&self) -> bool {
        self.on
    }

    /// An echo answer the WG receive seams authenticated (direct path, or a
    /// relay carrier). Unknown nonces belong to the other probers.
    pub(super) fn on_pong(
        &mut self,
        p: &disco::DiscoInbound,
        by_node: &HashMap<ObjectId, Installed>,
    ) {
        if let Some(id) = node_of(by_node, &p.sender) {
            self.engine.on_pong(&id, p.nonce, p.at);
        }
    }

    /// Serve `mux`'s path echoes: answer the peers' pings at once, and pass
    /// their pongs on with the instant they arrived. A task of its own,
    /// because an answer that waited for the next tick would add up to a
    /// second to the round trip the peer measures.
    fn arm_echo(
        &mut self,
        mux: &Arc<DerpMux>,
        keypair: &WgKeypair,
        sender: crate::overlay::wg::WgSender,
    ) {
        if self.echo.as_ref().is_some_and(|(served, task)| {
            !task.is_finished() && served.upgrade().is_some_and(|m| Arc::ptr_eq(&m, mux))
        }) {
            return;
        }
        if let Some((_, task)) = self.echo.take() {
            task.abort();
        }
        let (tx, mut rx) = mpsc::channel::<PathEcho>(ECHO_QUEUE);
        mux.set_echo_sink(Some(tx));
        let (secret, public) = (keypair.secret.clone(), keypair.public);
        let pongs = self.pongs_tx.clone();
        let served = Arc::downgrade(mux);
        let weak = served.clone();
        let task = tokio::spawn(async move {
            let mut answered: HashMap<[u8; 32], Instant> = HashMap::new();
            while let Some(echo) = rx.recv().await {
                // The relay stamped `src` from the sender's registration; the
                // frame must claim that same key, and it must be a peer.
                let verdict = disco::classify(&echo.frame, NO_SOURCE, &secret, &public, |pk| {
                    *pk == echo.src && sender.has_peer(pk)
                });
                match verdict {
                    disco::Verdict::Answer(pong) => {
                        if answered.get(&echo.src).is_some_and(|t| {
                            echo.at.saturating_duration_since(*t) < ECHO_ANSWER_SPACING
                        }) {
                            continue;
                        }
                        if answered.len() >= 4096 {
                            answered.clear();
                        }
                        answered.insert(echo.src, echo.at);
                        let Some(mux) = weak.upgrade() else { break };
                        mux.send_standby(&echo.src, &pong);
                    }
                    disco::Verdict::Pong(p) => {
                        let _ = pongs.try_send((p.sender, p.nonce, echo.at));
                    }
                    disco::Verdict::Ignore => {}
                }
            }
        });
        self.echo = Some((served, task));
    }

    /// Stop serving echoes (the switch went off, or the runtime is ending).
    fn disarm_echo(&mut self) {
        if let Some((served, task)) = self.echo.take() {
            task.abort();
            if let Some(mux) = served.upgrade() {
                mux.set_echo_sink(None);
            }
        }
    }
}

impl Drop for PreferRelay {
    fn drop(&mut self) {
        self.disarm_echo();
    }
}

fn node_of(by_node: &HashMap<ObjectId, Installed>, pubkey: &[u8; 32]) -> Option<ObjectId> {
    by_node
        .iter()
        .find(|(_, e)| &e.pubkey == pubkey)
        .map(|(id, _)| *id)
}

impl OverlayRuntime {
    /// Read the server's prefer-relay verdict off netmap rows it just sent
    /// (a full netmap's peers or a delta's upserts). Call BEFORE the walk
    /// over those rows: a withdrawn verdict then lets that very walk probe
    /// the direct path, and a new one keeps it from starting a probe.
    ///
    /// A row's lifetime counts from now, so this must run once per received
    /// row and never over stored rows. `true` when a standing verdict was
    /// withdrawn: the caller then keeps walking for [`WITHDRAWN_WALK`].
    pub(super) fn note_prefer_relay_rows(&self, st: &PreferRelay, rows: &[NetmapPeer]) -> bool {
        let mut withdrawn = false;
        if !st.on {
            return withdrawn;
        }
        let now = Instant::now();
        for p in rows {
            match p.prefer_relay_ms {
                None => {}
                Some(0) => {
                    let stood = self.shadow(|s| s.mon.clear_prefer_relay(&p.node_id, true, now));
                    if stood == Some(true) {
                        withdrawn = true;
                        info!(
                            peer = %p.node_id,
                            "overlay path quality: the server withdrew its prefer-relay verdict (the direct path measures healthy again) — probing direct now; the relay carries until the probe handshakes"
                        );
                    }
                }
                Some(ms) => {
                    let ttl = Duration::from_millis(u64::from(ms));
                    let stood = self.shadow(|s| {
                        let stood = s.mon.prefer_relay_active(&p.node_id, now);
                        s.mon.on_prefer_relay(&p.node_id, ttl, now);
                        stood
                    });
                    if stood == Some(false) {
                        info!(
                            peer = %p.node_id,
                            ttl_s = ttl.min(path::PREFER_RELAY_MAX).as_secs(),
                            "overlay path quality: the server prefers the relay for this pair (its relay path measured clearly better than its direct path) — holding direct until the verdict is withdrawn or runs out"
                        );
                    }
                }
            }
        }
        withdrawn
    }

    /// Make the carriers match the standing verdicts: a held pair rides the
    /// relay, and no upgrade probe of it is left to latch. `true` when a
    /// carrier was replaced.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn enforce_prefer_relay(
        &self,
        st: &mut PreferRelay,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        relay: &mut Option<RelayCoordinator>,
        tun: &Arc<dyn TunIo>,
        current_peers: &HashMap<ObjectId, NetmapPeer>,
        relay_bq: &mut RelayBuildQueue,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
    ) -> bool {
        if !st.on {
            return false;
        }
        let now = Instant::now();
        let held: Vec<ObjectId> = current_peers
            .keys()
            .filter(|id| self.shadow(|s| s.mon.prefer_relay_active(id, now)) == Some(true))
            .copied()
            .collect();
        st.demote_tried.retain(|id, _| held.contains(id));
        let mut changed = false;
        for nid in held {
            // A negotiated path trial owns this pair's carriers.
            if self
                .path_trial_managed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&nid)
            {
                continue;
            }
            // A probe already in flight would latch and promote the very
            // path the verdict holds down. No verdict is booked on its tier:
            // nothing about the path was measured by dropping it.
            if let Some(p) = upgrade_probes.remove(&nid) {
                wg.drop_direct_probe(&p.pubkey).await;
                self.shadow(|s| s.mon.on_probe_aborted(&nid));
                debug!(peer = %nid, tier = ?p.tier, "overlay path quality: dropped the in-flight direct probe of a pair the server holds on the relay");
            }
            let Some((was, pubkey)) = by_node
                .get(&nid)
                .filter(|e| e.is_direct)
                .map(|e| (e.tier, e.pubkey))
            else {
                continue;
            };
            if st
                .demote_tried
                .get(&nid)
                .is_some_and(|t| now.saturating_duration_since(*t) < DEMOTE_RETRY)
            {
                continue;
            }
            st.demote_tried.insert(nid, now);
            let Some(cfg) = current_peers
                .get(&nid)
                .and_then(peer_config_from_netmap)
                .filter(|c| c.public_key == pubkey)
            else {
                continue;
            };
            let Some(coord) = relay.as_mut() else {
                continue;
            };
            match coord.follow_peer_to_derp(nid, cfg) {
                Some(link) => {
                    info!(
                        peer = %nid, ?was,
                        "overlay path quality: prefer-relay verdict — moving this pair from its direct carrier to the relay"
                    );
                    self.install_ready(wg, by_node, tun, link, relay_bq).await;
                    changed = true;
                }
                // Never self-wedge: with no relay to move to, the direct
                // carrier keeps carrying, and this is tried again.
                None => debug!(
                    peer = %nid,
                    "overlay path quality: prefer-relay verdict, but no relay can be built now (no /derp mux, mux down, or the peer cannot ride DERP) — staying on the direct carrier"
                ),
            }
        }
        changed
    }

    /// One pass, every [`path_quality::PROBE_EVERY`](crate::overlay::path_quality::PROBE_EVERY):
    /// send the probes that are due, report the windows that closed, void a
    /// hold whose relay stopped carrying, and enforce the holds that stand.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn prefer_relay_tick(
        &self,
        st: &mut PreferRelay,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        relay: &mut Option<RelayCoordinator>,
        tun: &Arc<dyn TunIo>,
        current_peers: &HashMap<ObjectId, NetmapPeer>,
        direct_ctx: Option<&DirectCtx>,
        relay_bq: &mut RelayBuildQueue,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
    ) -> Outcome {
        let mut out = Outcome::default();
        if !st.on {
            return out;
        }
        let now = Instant::now();
        let mux = relay.as_ref().and_then(|r| r.derp_mux_handle());
        if let Some(mux) = &mux {
            st.arm_echo(mux, &self.keypair, wg.sender());
        }
        while let Ok((sender, nonce, at)) = st.pongs_rx.try_recv() {
            if let Some(id) = node_of(by_node, &sender) {
                st.engine.on_pong(&id, nonce, at);
            }
        }

        // -- who is measured ---------------------------------------------------
        let mut peers: Vec<PeerNow> = Vec::new();
        if st.server_wants {
            let table = self
                .disco_paths
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();
            let managed = self
                .path_trial_managed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            for (nid, e) in by_node.iter() {
                let Some(np) = current_peers.get(nid) else {
                    continue;
                };
                // The relay path measured and moved to is `/derp`: a pair
                // that cannot ride it has nothing to prefer.
                if np.backbone_only || !np.supports_derp || managed.contains(nid) {
                    continue;
                }
                let holding = self.shadow(|s| s.mon.prefer_relay_active(nid, now)) == Some(true);
                if !holding
                    && (wg.peer_is_dormant(&e.pubkey) == Some(true)
                        || (!e.hs_done && !st.engine.comparing(nid)))
                {
                    continue;
                }
                let counters = wg.peer_business_traffic(&e.pubkey).unwrap_or((0, 0));
                let seen = st.traffic.entry(*nid).or_insert(TrafficSeen {
                    counters,
                    moved_at: None,
                    relay_rx_at: None,
                });
                if !e.is_direct && counters.1 > seen.counters.1 {
                    seen.relay_rx_at = Some(now);
                } else if e.is_direct {
                    seen.relay_rx_at = None;
                }
                if seen.counters != counters {
                    seen.counters = counters;
                    seen.moved_at = Some(now);
                }
                let active = seen
                    .moved_at
                    .is_some_and(|t| now.saturating_duration_since(t) < ACTIVE_FOR);
                let relay_rx_recent = !e.is_direct
                    && seen
                        .relay_rx_at
                        .is_some_and(|t| now.saturating_duration_since(t) < Duration::from_secs(2));
                let slow_direct = e
                    .carrier_dst
                    .filter(|_| e.is_direct)
                    .and_then(|dst| table.iter().find(|s| s.peer == e.pubkey && s.dst == dst))
                    .map(|s| (s.rtt_ms, s.loss));
                peers.push(PeerNow {
                    id: *nid,
                    on_direct: e.is_direct,
                    holding,
                    active,
                    relay_rx_recent,
                    slow_direct,
                });
            }
        }
        st.traffic.retain(|id, _| by_node.contains_key(id));

        // -- probes, reports, a dead relay --------------------------------------
        for action in st.engine.tick(now, &peers) {
            match action {
                Action::Probe { peer, leg, nonce } => {
                    let Some(e) = by_node.get(&peer) else {
                        continue;
                    };
                    let shared = *st.shared.entry(e.pubkey).or_insert_with(|| {
                        disco::shared_secret(
                            &self.keypair.secret,
                            &boringtun::x25519::PublicKey::from(e.pubkey),
                        )
                    });
                    let frame = disco::build(
                        disco::KIND_PING,
                        nonce,
                        self.keypair.public.as_bytes(),
                        None,
                        &shared,
                    );
                    // Stamped before the write, so egress queueing counts.
                    let at = Instant::now();
                    let went = match (leg, e.is_direct) {
                        // The path the carrier itself rides.
                        (Leg::Direct, true) | (Leg::Relay, false) => wg
                            .sender()
                            .send_disco_raw(&e.pubkey, &frame)
                            .await
                            .is_some(),
                        // The relay path of a pair on a direct carrier: a
                        // standby payload, to a peer that takes them.
                        (Leg::Relay, true) => mux.as_ref().is_some_and(|m| {
                            m.is_alive()
                                && disco::standby_capable(&e.pubkey, at)
                                && m.send_standby(&e.pubkey, &frame)
                        }),
                        // The direct path of a pair on the relay: the peer's
                        // direct candidates. An echo is stateless and is
                        // answered to its observed source, so this neither
                        // dials nor disturbs the carrier in use.
                        (Leg::Direct, false) => match current_peers.get(&peer) {
                            Some(np) => self.echo_direct_candidates(direct_ctx, np, &frame).await,
                            None => false,
                        },
                    };
                    if went {
                        st.engine.sent(peer, leg, nonce, at);
                    }
                }
                Action::Report(r) => {
                    debug!(
                        peer = %r.peer, on_relay = r.on_relay, window_ms = r.window_ms,
                        direct = ?r.direct, relay = ?r.relay,
                        "overlay path quality: reporting this window to the server"
                    );
                    let _ = tokio::time::timeout(
                        Duration::from_millis(10),
                        self.outbound.send(ClientMsg::OverlayPathQuality {
                            peer_node_id: r.peer,
                            window_ms: r.window_ms,
                            direct_sent: r.direct.sent,
                            direct_lost: r.direct.lost,
                            direct_rtt_ms: r.direct.rtt_ms,
                            relay_sent: r.relay.sent,
                            relay_lost: r.relay.lost,
                            relay_rtt_ms: r.relay.rtt_ms,
                            on_relay: r.on_relay,
                        }),
                    )
                    .await;
                }
                Action::LossyDirect { peer } => {
                    // Good for a little over two ticks: a carrier that dies
                    // after the probes stopped saying so is not held.
                    let until = now + crate::overlay::path_quality::PROBE_EVERY * 3;
                    self.shadow(|s| s.mon.note_lossy_direct(&peer, until));
                }
                Action::RelayDown { peer } => {
                    let stood = self.shadow(|s| s.mon.clear_prefer_relay(&peer, false, now));
                    if stood == Some(true) {
                        warn!(
                            %peer,
                            "overlay path quality: the relay stopped answering while the direct path still does — voiding the server's prefer-relay hold so direct can carry again"
                        );
                        out.walk = true;
                    }
                }
            }
        }
        let live: HashSet<[u8; 32]> = by_node.values().map(|e| e.pubkey).collect();
        st.shared.retain(|pk, _| live.contains(pk));
        // Say once when the monitor took its own short wait for a verdict
        // (a lossy direct carrier died): otherwise a pair that sits on the
        // relay for ten seconds with no verdict in the log is a mystery.
        st.pending_logged
            .retain(|id| self.shadow(|s| s.mon.prefer_relay_pending(id, now)) == Some(true));
        for p in &peers {
            if self.shadow(|s| s.mon.prefer_relay_pending(&p.id, now)) == Some(true)
                && st.pending_logged.insert(p.id)
            {
                info!(
                    peer = %p.id,
                    hold_s = path::PENDING_VERDICT_HOLD.as_secs(),
                    "overlay path quality: a direct carrier died on a path measured lossy but alive — holding direct while the server judges the report (the relay carries)"
                );
            }
        }

        out.changed = self
            .enforce_prefer_relay(
                st,
                wg,
                by_node,
                relay,
                tun,
                current_peers,
                relay_bq,
                upgrade_probes,
            )
            .await;
        out
    }

    /// Send one echo frame to each direct candidate of a peer that rides the
    /// relay (the candidates the 5 s disco round probes). One nonce for all:
    /// the first answer is the sample, so the reading is the best direct
    /// path the pair has.
    async fn echo_direct_candidates(
        &self,
        direct_ctx: Option<&DirectCtx>,
        np: &NetmapPeer,
        frame: &[u8],
    ) -> bool {
        let Some(ctx) = direct_ctx else {
            return false;
        };
        let Some(cfg) = peer_config_from_netmap(np) else {
            return false;
        };
        let cands = resolve_direct_candidates(direct_ctx, &cfg, Default::default());
        let lan = match cands.lan {
            Some((local_ip, dst)) => lan_egress_socket(ctx, local_ip, dst)
                .await
                .map(|s| (dst, s)),
            None => None,
        };
        let mut went = false;
        for pair in [
            lan,
            cands.public.zip(ctx.public_sock.clone()),
            cands.srflx.and_then(|d| ctx.srflx_sock(d).map(|s| (d, s))),
        ] {
            let Some((dst, sock)) = pair else { continue };
            went |= sock.send_to(frame, dst).await.is_ok();
        }
        went
    }
}
