// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Peer-establishment half of [`OverlayRuntime`] — split out of `runtime.rs`
//! (rc.284, pure move): the direct-tier LAN context, the netmap
//! install/evict pipeline, make-before-break upgrade probes, the
//! direct/public/srflx installers, and the carrier-health sweep. A child
//! module of `runtime`, so the moved code keeps private-field access and
//! `use super::*` inherits the parent's import block unchanged.

use super::*;

/// #22 — the re-init-pressure window and threshold. A healthy peer
/// initiates a rekey about once per ~120 s (plus a stray retry on a lossy
/// hop: ≤2 initiations per window); a peer that cannot hear our responses
/// retries every ~5 s (boringtun's rekey timeout), i.e. ≥12 per window —
/// the two populations never overlap at 5. The 08-18 zombie-leg wedge's
/// rebirthing floor (fresh init burst every ~70 s carrier life) also
/// clears 5 comfortably.
const REINIT_WINDOW: Duration = Duration::from_secs(60);
const REINIT_PRESSURE_MIN: u32 = 5;

/// rc.131/132/143 — direct LAN carrier context: one UDP socket per LAN
/// interface (each bound to that interface IP — rc.143), this node's LAN IPs
/// across ALL interfaces (for the same-subnet test), and the `IP:port`
/// endpoints we advertise (one per interface socket) so a multi-homed peer can
/// reach us on whichever subnet it shares with us.
pub(super) struct DirectCtx {
    /// One UDP socket bound to EACH usable LAN interface IP (rc.143 — NOT
    /// `0.0.0.0`). Binding to the specific address forces egress out that NIC,
    /// so a same-subnet peer is reached over the LAN even when a full-tunnel VPN
    /// has hijacked the default route (a `0.0.0.0` socket sent the reply out the
    /// VPN and the peer never got it). A peer is served by the socket whose
    /// interface IP shares its /24.
    pub(super) socks: Vec<(Ipv4Addr, Arc<UdpSocket>)>,
    pub(super) my_ips: Vec<Ipv4Addr>,
    pub(super) endpoints: Vec<String>,
    /// Phase A (`public_direct_enabled`) — a single `0.0.0.0:0` socket used to
    /// DIAL a peer's public endpoint. Unbound to any interface so the OS routing
    /// table picks the egress NIC for each public destination (a per-interface
    /// socket bound to a private LAN IP would need us to know which NIC holds
    /// the default route on a multi-homed host). Its demux loop catches the
    /// exit's replies (keyed by the exit's public source). `None` when the
    /// public-direct tier is off. We do NOT advertise this socket's address (a
    /// peer reaches US on our per-interface PUBLIC socket, already advertised in
    /// `endpoints` since a public NIC IP passes `is_usable_lan_ipv4`).
    pub(super) public_sock: Option<Arc<UdpSocket>>,
    /// Phase C — the interface socket that owns our FIRST advertised srflx
    /// candidate (`srflx_endpoints[0]`), paired with that candidate string. To
    /// hole-punch a NAT'd peer we must dial its srflx from THIS socket, so our
    /// outbound WG INITs ride the same NAT mapping we advertised (opening our
    /// filter toward the peer). Distinct from `public_sock` (the Phase A
    /// public-NIC dialer, an unbound `0.0.0.0` socket): a punch requires the
    /// mapping-owning socket, not an arbitrary egress one. `None` when the srflx
    /// tier is off or no public srflx was gathered. Set after the startup
    /// srflx gather (which returns each candidate with its socket).
    pub(super) punch: Option<(String, Arc<UdpSocket>)>,
    /// Phase C — OUR probed NAT mapping type (`"cone"` / `"symmetric"`), or
    /// `None` when unknown. Set at the startup gather (probing the punch socket
    /// against two STUN targets). `install_peers` reads it to skip a srflx punch
    /// only when BOTH ends are symmetric.
    pub(super) my_nat: Option<String>,
}

/// rc.225 — did a netmap upsert change the peer's DIRECT-dial endpoints (its
/// LAN addresses or srflx mappings)? Deliberately ignores `endpoints` (the
/// relay-advert bucket — it churns on every re-allocation and says nothing
/// about direct reachability). A `true` here resets the peer's monitor state
/// (`PathMonitor::on_endpoint_change` — penalties, strikes AND quality): new
/// ports/addresses = new dial conditions, so the old evidence is stale. Pure.
pub(super) fn direct_endpoints_changed(old: &NetmapPeer, new: &NetmapPeer) -> bool {
    old.lan_endpoints != new.lan_endpoints || old.srflx_endpoints != new.srflx_endpoints
}

/// P3 PR-B — one peer's direct-tier candidates (extracted verbatim from
/// `install_peers`, where PR-A computed them inline). PR-E: these ARE the
/// dial targets now — the monitor's `decide()` is the only selection filter
/// on top. Endpoint / feature-flag / hairpin checks are availability, never
/// score. Pure reads.
pub(super) struct DirectCandidates {
    /// Same-subnet LAN endpoint (highest-priority tier): (our matching
    /// interface IP, the peer's dst). rc.204 — scans the provenance-pure
    /// `lan_endpoints` bucket (the peer's join-time NIC sockets), NOT the
    /// `endpoints` union: the union also carries the peer's trickled
    /// coturn-RELAYED addresses, and on this fleet the coturn workers ride
    /// the hosts' own public IPs, so a fleet host same-/24-matched a peer's
    /// *relay allocation* and "LAN"-dialed coturn forever (field-observed
    /// 2026-07-21: buildhost dialing DEVBOX's relayed 94.130.141.74:* as a LAN
    /// endpoint).
    pub(super) lan: Option<(Ipv4Addr, std::net::SocketAddr)>,
    /// Phase A — the peer's PUBLIC NIC endpoint (its join-time bucket),
    /// dialable WITHOUT STUN because the peer's NIC holds a public IP.
    /// Dialed over the shared `public_sock` (arbitrary egress is fine — the
    /// peer has no NAT filter). Gated by the feature flag + the egress
    /// socket's existence.
    pub(super) public: Option<std::net::SocketAddr>,
    /// Phase C — the peer's srflx (its STUN-learned public NAT mapping),
    /// dialed over the PUNCH socket (the one that owns OUR advertised srflx)
    /// so our INITs ride our advertised mapping and open our NAT's filter
    /// toward the peer — the mutual hole-punch. Skipped when BOTH ends are
    /// symmetric (a punch can't work — save the futile 12 s attempt + the
    /// strike) and for the P8 same-NAT hairpin with a LAN candidate present.
    /// Lowest direct tier.
    pub(super) srflx: Option<std::net::SocketAddr>,
}

/// How many consecutive failed LAN probes disprove the "the peer's LAN
/// candidate actually works" premise of the P8 hairpin gate. 2026-08-15
/// field (home mesh with client isolation): same-subnet client↔client
/// traffic was DEAD at the AP — raw UDP and ICMP both directions — while
/// the candidates stayed advertised, and mesh-node roaming made it FLAP
/// (a 03:17 LAN handshake worked; by 07:10 the same path was black). With
/// presence treated as usability, the gate suppressed the srflx hairpin —
/// the only direct tier a same-NAT pair has there — so pairs demoted
/// during a VPN window stayed relay-locked until a daemon restart.
pub(super) const LAN_DEAD_STRIKES: u32 = 3;

/// F2 — the tee decision: copy a peer's data onto `/derp` only while a
/// business or Major proof for it has gone unanswered past
/// [`STANDBY_ARM_AFTER`], and only to a peer that takes copies. A healthy
/// path answers within one RTT, so the recurring proofs of a healthy one-way
/// stream never copy anything.
pub(super) fn standby_tee_wanted(
    poke: Option<PokeArm>,
    answered: bool,
    capable: bool,
    now: Instant,
) -> bool {
    capable
        && !answered
        && poke.is_some_and(|p| {
            (p.from_business || p.from_major)
                && now.saturating_duration_since(p.at) >= STANDBY_ARM_AFTER
        })
}

pub(super) fn resolve_direct_candidates(
    direct_ctx: Option<&DirectCtx>,
    cfg: &PeerConfig,
    rot: CandidateRotation,
) -> DirectCandidates {
    let lan = direct_ctx
        .and_then(|ctx| direct::pick_same_subnet_endpoint(&ctx.my_ips, &cfg.lan_endpoints));
    let public = direct_ctx.and_then(|ctx| {
        (direct::public_direct_enabled() && ctx.public_sock.is_some())
            .then(|| {
                direct::pick_public_endpoint_rotated(&ctx.my_ips, &cfg.lan_endpoints, rot.public)
            })
            .flatten()
    });
    // The hairpin gate takes LAN health, not LAN presence: a candidate that
    // keeps failing its probes ([`LAN_DEAD_STRIKES`]) no longer counts as
    // "the tier that actually works", and the hairpin punch unlocks. The
    // LAN candidate itself keeps being dialed — if the AP starts forwarding
    // again (mesh roam), its strikes clear and the premise is restored.
    let lan_usable = lan.is_some() && rot.lan < LAN_DEAD_STRIKES;
    let srflx = direct_ctx.and_then(|ctx| {
        (direct::srflx_enabled()
            && ctx.punch.is_some()
            && direct::srflx_punch_worth_trying(ctx.my_nat.as_deref(), cfg.srflx_nat.as_deref())
            && !direct::srflx_hairpin_pointless(
                ctx.punch.as_ref().map(|(s, _)| s.as_str()),
                &cfg.srflx_endpoints,
                lan_usable,
            ))
        .then(|| direct::pick_public_endpoint_rotated(&ctx.my_ips, &cfg.srflx_endpoints, rot.srflx))
        .flatten()
    });
    DirectCandidates { lan, public, srflx }
}

/// A2 — per-tier dial-attempt offsets for multi-candidate rotation: the
/// PathMonitor's strike count per (peer, tier), so each failed probe advances
/// [`direct::pick_public_endpoint_rotated`] to the peer's next advertised
/// candidate and a success (strikes reset) returns to the primary. Default
/// (zeros) = today's first-candidate behavior.
#[derive(Default, Clone, Copy)]
pub(super) struct CandidateRotation {
    pub public: u32,
    pub srflx: u32,
    /// LAN-tier strike count — not a rotation offset (the LAN pick is the
    /// single same-subnet match): [`resolve_direct_candidates`] reads it as
    /// the LAN-health input to the P8 hairpin gate ([`LAN_DEAD_STRIKES`]).
    pub lan: u32,
}

// The stable-port binder MOVED to `direct::bind_direct_socket` (multi-org v2:
// the shared carrier plane binds the same way, and `direct` is the module both
// can reach). Re-exported so the call sites here and the band-walk lock test
// in `runtime::tests` keep their `bind_direct_socket` /
// `establish::bind_direct_socket` paths.
pub(super) use crate::overlay::direct::bind_direct_socket;

/// bind-to-interface-by-route (Phase 1, `OVERLAY_BIND_BY_ROUTE`) — pick the
/// egress socket for a LAN direct carrier/probe to `dst`. Tailscale's
/// `net/netns` `bindToInterfaceByRoute` adapted to roomler's per-interface
/// sockets: when the gate is on, the OS route table is consulted via the
/// `connect()`-trick ([`direct::os_src_ip_for`]) + [`direct::classify_egress`]
/// so the chosen socket matches the interface that actually reaches `dst` (an
/// on-link `/24` beats a full-tunnel VPN's `/1` split-default), and it is
/// re-pinned to its CURRENT ifindex (fresh — a VPN connect since startup can't
/// leave a stale `IP_UNICAST_IF` pin). Falls back to the same-subnet pick
/// (today's behaviour) when the gate is off, the query is inconclusive, or the
/// OS routes `dst` off our interfaces; the working relay + the MBB probe
/// machinery catch a one-way path from there, so this never skips direct.
/// `None` only when no socket is bound for the subnet at all.
pub(super) async fn lan_egress_socket(
    ctx: &DirectCtx,
    local_ip: Ipv4Addr,
    dst: std::net::SocketAddr,
) -> Option<Arc<UdpSocket>> {
    let pick = |ip: Ipv4Addr| {
        ctx.socks
            .iter()
            .find(|(i, _)| *i == ip)
            .map(|(_, s)| s.clone())
    };
    let same_subnet = pick(local_ip);
    if !direct::bind_by_route_enabled() {
        return same_subnet;
    }
    let socket_ips: Vec<Ipv4Addr> = ctx.socks.iter().map(|(ip, _)| *ip).collect();
    let chosen_ip = match direct::classify_egress(direct::os_src_ip_for(dst).await, &socket_ips) {
        direct::Egress::Use(ip) => {
            if ip != local_ip {
                info!(%local_ip, chosen = %ip, %dst, "overlay: bind-by-route picked the OS-routed egress interface (≠ the same-subnet pick)");
            }
            ip
        }
        direct::Egress::Foreign => {
            info!(%local_ip, %dst, "overlay: bind-by-route — OS routes this LAN dst off our interfaces (VPN-captured?); keeping same-subnet socket (relay/MBB catches a one-way path)");
            local_ip
        }
        direct::Egress::Loop => {
            info!(%local_ip, %dst, "overlay: bind-by-route — route resolves into our own overlay TUN; keeping same-subnet socket");
            local_ip
        }
        direct::Egress::Unknown => local_ip,
    };
    let sock = pick(chosen_ip).or(same_subnet)?;
    // Re-pin egress to the CURRENT ifindex of the chosen interface (freshly
    // read — the pin computed at `setup_direct` can go stale after a VPN
    // connect). No-op off Windows / when `if-addrs` supplies no index.
    if let Some(ix) = direct::ifindex_for(chosen_ip) {
        direct::force_egress_interface(&sock, ix);
    }
    Some(sock)
}

/// rc.208 — an in-flight make-before-break upgrade probe. The candidate direct
/// carrier lives as a shadow `Tunn` in [`WgDevice::probes`] (keyed by `pubkey`);
/// THIS is the runtime-side metadata the promote/expire sweep needs. While it is
/// present, `by_node[node]` still points at the peer's ACTIVE (relay) carrier —
/// routing is untouched — and [`OverlayRuntime::sweep_upgrade_probes`] either
/// promotes it (handshake latched → cut over to direct) or drops it (past the
/// tier's [`DirectTier::handshake_deadline`] → keep relay). See
/// [`crate::overlay::direct::make_before_break_enabled`].
pub(super) struct UpgradeProbe {
    pub(super) pubkey: [u8; 32],
    pub(super) overlay_ip: Ipv4Addr,
    /// The direct endpoint the probe dials (the promoted carrier's off-link
    /// exit-exemption dst for `Public`/`Srflx`).
    pub(super) dst: std::net::SocketAddr,
    /// Which direct tier is being probed — drives the deadline + CC1 cooldown.
    pub(super) tier: DirectTier,
    /// When the probe was started — for the tier handshake deadline.
    pub(super) since: Instant,
    /// rc.276 diagnostics — `true` for an outbound MBB upgrade probe (we
    /// dialed), `false` for an accepted inbound dial held as a probe. Carried
    /// into `Installed.initiated` on promote.
    pub(super) initiated: bool,
    /// rc.276 diagnostics — the probe socket's local address, carried into
    /// `Installed.carrier_local` on promote.
    pub(super) local: Option<std::net::SocketAddr>,
}

impl OverlayRuntime {
    /// rc.137/139 — find carriers that are one-way / dead and repair them.
    /// Health is LOCK-FREE: each sweep snapshots `(tx, rx)` (atomic reads — no
    /// `Tunn` lock, so it can't stall the packet path like the rc.136
    /// handshake-age check did); a carrier where **tx climbed but rx stayed
    /// flat** for [`BAD_SWEEPS_TO_FALLBACK`] consecutive sweeps is dead (we're
    /// sending, nothing comes back). The repair depends on the carrier kind:
    /// - **direct** → fall back to relay (the LAN path only LOOKED viable —
    ///   corp VPN route hijack, Wi-Fi AP/client isolation, asymmetric firewall);
    ///   the monitor's suppression penalty keeps the next netmap from
    ///   re-upgrading it (PR-E: `PathMonitor::on_death` is the bookkeeping).
    /// - **relay** (rc.139) → refresh it: the peer almost certainly
    ///   re-allocated its coturn port (restart/churn) and we're dialing a stale
    ///   one. Re-request so we re-allocate + re-dial the peer's CURRENT address
    ///   ([`RELAY_REFRESH_COOLDOWN`] bounds two ends ping-ponging).
    /// Run the fallback health pass and immediately repair a real removal.
    /// The establish walk supplies the existing DERP floor and coordinates
    /// better tiers; a healthy pass does not add any walk or retry work.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn sweep_and_repair_carriers(
        &self,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        relay: &mut Option<RelayCoordinator>,
        tun: &Arc<dyn TunIo>,
        relay_refresh_cooldown: &mut HashMap<ObjectId, Instant>,
        current_peers: &HashMap<ObjectId, NetmapPeer>,
        force_poke: ForcedPoke,
        direct_ctx: Option<&DirectCtx>,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
        relay_bq: &mut RelayBuildQueue,
    ) -> bool {
        let carrier_lost = self.sweep_carrier_health(
            wg, by_node, relay, tun, relay_refresh_cooldown, current_peers, force_poke,
        ).await;
        if carrier_lost {
            let peers: Vec<NetmapPeer> = current_peers.values().cloned().collect();
            self.install_peers(wg, by_node, relay, tun, &peers, direct_ctx,
                upgrade_probes, relay_bq, "carrier-loss").await;
        }
        carrier_lost
    }

    /// Sample business traffic independently of the five-second health bucket.
    /// This lane may start proof, but never settles proof or judges a carrier.
    pub(super) fn scout_business_traffic(
        &self,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        samples: &mut HashMap<ObjectId, BusinessTrafficSample>,
    ) {
        samples.retain(|nid, _| by_node.contains_key(nid));
        let now = Instant::now();
        for (nid, e) in by_node.iter_mut() {
            if !e.is_direct || !wg.peer_handshake_done(&e.pubkey).unwrap_or(false)
                || now.saturating_duration_since(e.since) < crate::overlay::lifecycle::DIRECT_GRACE
            {
                samples.remove(nid);
                continue;
            }
            let Some(traffic) = wg.peer_business_traffic(&e.pubkey) else {
                samples.remove(nid);
                continue;
            };
            let retapped = samples.get(nid).and_then(|s| s.retapped);
            let Some(previous) = samples.insert(*nid, BusinessTrafficSample {
                installed_at: e.since, traffic, retapped,
            }) else {
                continue;
            };
            if previous.installed_at != e.since
                || traffic.0 <= previous.traffic.0 || traffic.1 != previous.traffic.1
            {
                continue;
            }
            // Do not settle answered proofs here: the normal sweep remains
            // their only consumer. In particular, a healthy one-way stream
            // cannot turn this faster sampler into a per-second rekey loop.
            if let Some(p) = e.poke.filter(|p| p.from_major || p.from_business) {
                // §6.3 F1 — the one exception: a business proof still
                // unanswered after BUSINESS_POKE_RETAP_AFTER gets ONE fresh
                // initiation, so its 2 s window judges two attempts. Once per
                // proof (keyed by its arm instant), never for a Major poke.
                if p.from_business && !p.from_major && super::business_poke_fast()
                    && retapped != Some(p.at)
                    && now.saturating_duration_since(p.at)
                        >= crate::overlay::lifecycle::BUSINESS_POKE_RETAP_AFTER
                    && !wg.peer_initiator_hs_answered(&e.pubkey, p.at)
                    && wg.poke_handshake(&e.pubkey)
                {
                    if let Some(s) = samples.get_mut(nid) {
                        s.retapped = Some(p.at);
                    }
                    info!(peer = %nid, tier = ?e.tier,
                        "overlay: business proof still unanswered — second initiation");
                }
                continue;
            }
            if wg.poke_handshake(&e.pubkey) {
                e.poke = Some(PokeArm {
                    at: now,
                    from_major: false,
                    from_business: true,
                });
                info!(peer = %nid, tier = ?e.tier,
                    "overlay: unanswered business traffic — fast validation of the direct carrier");
            }
        }
    }

    /// F2 — standby upkeep, once per scout tick. Every peer on a direct
    /// carrier keeps a standby sink (a rebuilt peer gets a new one) and hears
    /// our `STANDBY_HELLO` every [`STANDBY_HELLO_EVERY`], sent only while that
    /// carrier is direct so an older receiver never sees it on `/derp`. A
    /// peer that left its direct carrier has its standby route retired. The
    /// tees themselves are [`Self::arm_standby_tees`].
    pub(super) async fn sweep_standby(
        &self,
        wg: &mut WgDevice,
        by_node: &HashMap<ObjectId, Installed>,
        mux: &Arc<crate::transport::derp::DerpMux>,
        standby: &mut HashMap<[u8; 32], Option<Instant>>,
    ) {
        let now = Instant::now();
        let direct: std::collections::HashSet<[u8; 32]> =
            by_node.values().filter(|e| e.is_direct).map(|e| e.pubkey).collect();
        standby.retain(|pk, _| {
            let keep = direct.contains(pk);
            if !keep {
                mux.clear_standby(pk);
            }
            keep
        });
        for e in by_node.values().filter(|e| e.is_direct) {
            if !wg.has_standby_sink(&e.pubkey) {
                wg.attach_standby_sink(&e.pubkey, mux.standby_route(e.pubkey));
            }
            let last = standby.entry(e.pubkey).or_insert(None);
            if last.is_none_or(|t| now.saturating_duration_since(t) >= STANDBY_HELLO_EVERY) {
                let frame = crate::overlay::disco::standby_hello(
                    &e.pubkey,
                    &self.keypair.secret,
                    &self.keypair.public,
                );
                if wg.sender().send_disco_raw(&e.pubkey, &frame).await.is_some() {
                    *last = Some(now);
                }
            }
        }
        self.arm_standby_tees(wg, by_node, mux);
    }

    /// F2 — the tee of each direct peer, on the scout tick and every
    /// [`STANDBY_WATCH_TICK`] while a proof is pending: copies flow while a
    /// proof stays unanswered past [`STANDBY_ARM_AFTER`], to a peer whose
    /// hello is fresh, and stop the moment it is answered.
    pub(super) fn arm_standby_tees(
        &self,
        wg: &WgDevice,
        by_node: &HashMap<ObjectId, Installed>,
        mux: &Arc<crate::transport::derp::DerpMux>,
    ) {
        let now = Instant::now();
        for e in by_node.values().filter(|e| e.is_direct) {
            let answered = e
                .poke
                .is_some_and(|p| wg.peer_initiator_hs_answered(&e.pubkey, p.at));
            let capable = crate::overlay::disco::standby_capable(&e.pubkey, now);
            let tee = standby_tee_wanted(e.poke, answered, capable, now);
            wg.set_standby_tee(&e.pubkey, tee.then(|| mux.clone()));
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn sweep_carrier_health(
        &self,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        relay: &mut Option<RelayCoordinator>,
        tun: &Arc<dyn TunIo>,
        relay_refresh_cooldown: &mut HashMap<ObjectId, Instant>,
        current_peers: &HashMap<ObjectId, NetmapPeer>,
        force_poke: ForcedPoke,
    ) -> bool {
        let now = Instant::now();
        let mut carrier_lost = false;
        // P3 PR-A — the shadow monitor consumes the same env read the legacy
        // escalation table does, at the same moment.
        let mbb = crate::overlay::direct::make_before_break_enabled();
        let mut dead: Vec<(ObjectId, DirectTier, DeathReason)> = Vec::new();
        for (nid, e) in by_node.iter_mut() {
            let Some((tx, rx)) = wg.peer_traffic(&e.pubkey) else {
                continue;
            };
            let (last_tx, last_rx) = e.last_traffic;
            e.last_traffic = (tx, rx);
            // P3b-3 / rc.206 — "last heard from this peer" advances on ANY
            // authenticated inbound packet, INCLUDING content-free WG keepalives.
            // The IP-data `rx` counter alone froze on a mostly-idle-but-alive
            // carrier (its only inbound is keepalives → `TunnResult::Done`, which
            // never touches `rx`), so the rx-staleness rule would have reaped a
            // healthy idle link. `peer_take_rx_any` drains the
            // keepalive-inclusive liveness counter (single-consumer; the sweep is
            // the only reader). Advance BEFORE building the tick inputs so a
            // freshly installed peer's first inbound already registers.
            let heard = wg.peer_take_rx_any(&e.pubkey) > 0;
            if heard {
                e.last_rx_at = now;
            }
            // #22 — re-init pressure: accumulate the peer's authenticated
            // handshake INITIATIONS in a rolling window. Judged below when
            // arming revalidation; drained here so the counter can't grow
            // unread.
            let reinits = wg.peer_take_reinits(&e.pubkey) as u32;
            if now.saturating_duration_since(e.reinit_window_from) > REINIT_WINDOW {
                e.reinit_window_from = now;
                e.reinit_recent = 0;
            }
            e.reinit_recent = e.reinit_recent.saturating_add(reinits);
            // P4 — snapshot the ingress-ACL denial counter for the LocalAPI
            // view. Monotonic, so a plain read (not a drain like `rx_any`).
            e.rx_denied = wg.peer_rx_denied(&e.pubkey);
            e.rx_denied_noroute = wg.peer_rx_denied_noroute(&e.pubkey);
            // The peer exists (peer_traffic answered just above, no await in
            // between), so the latch read always answers too — the `else` is
            // unreachable belt-and-braces.
            let Some(handshake_done) = wg.peer_handshake_done(&e.pubkey) else {
                continue;
            };
            // Stage 2 — settle any pending active-revalidation poke: answered
            // iff an INITIATOR-role handshake completed at-or-after the poke
            // instant (the only signal that proves OUR outbound works — see
            // `PeerStats::hs_response_at`). An answered poke clears, re-arming
            // the triggers; an unanswered one rides into the tick, which
            // kills it once the tier's handshake-deadline window closes.
            let poke = e.poke.map(|p| PokeState {
                since_poke: now.saturating_duration_since(p.at),
                answered: wg.peer_initiator_hs_answered(&e.pubkey, p.at),
                from_major: p.from_major,
                from_business: p.from_business,
            });
            // Diagnostic — capture poke state before `poke` moves into
            // `carrier_tick` (see `OVERLAY_SESSION_TRACE`).
            let trace_poke = poke
                .as_ref()
                .map(|p| (p.since_poke, p.answered, p.from_major));
            if poke.as_ref().is_some_and(|p| p.answered) {
                e.poke = None;
            }
            // P2 — every rule that can kill this carrier lives in ONE pure
            // transition (`lifecycle::carrier_tick`): the per-tier handshake
            // deadline (Phase C / rc.204 / rc.223), the rc.206 rx-staleness
            // backstop, the rc.137 one-way counter, the rc.181 hard-dead fast
            // path, the Stage 2 poke verdict, the warm-up grace, and the relay
            // refresh holdoff. This loop only gathers inputs and applies the
            // verdict.
            let since_last_rx = now.saturating_duration_since(e.last_rx_at);
            let v = carrier_tick(&HealthInputs {
                business_poke_window: super::business_poke_window(),
                tier: e.tier,
                is_direct: e.is_direct,
                hard_dead: wg.peer_carrier_dead(&e.pubkey).unwrap_or(false),
                handshake_done,
                since_install: e.since.elapsed(),
                since_last_rx,
                traffic: (tx, rx),
                last_traffic: (last_tx, last_rx),
                bad_sweeps: e.bad_sweeps,
                relay_refresh_held: relay_refresh_cooldown
                    .get(nid)
                    .is_some_and(|&until| until > now),
                poke,
            });
            // Diagnostic — per-carrier health/poke trace (see
            // `OVERLAY_SESSION_TRACE`). Shows why a uni-directional carrier
            // isn't being revalidated: proof_age vs POKE_PROOF, rx silence,
            // whether a poke is stuck pending, and the tick's death verdict.
            //
            // Covers RELAY carriers too. It was `&& e.is_direct` until
            // 2026-08-25, which made the one place this trace is most needed
            // the one place it could not fire: a VPN transition kills the
            // REMOTE end's relay carrier, and that end sees nothing at all for
            // the ~15 s (`BAD_SWEEPS_TO_FALLBACK` × the 5 s tick) it spends
            // accumulating one-way strikes — then emits a single conviction
            // line. Reading a real capture of that window, the strike
            // accumulation was simply invisible, so "was the carrier silent,
            // or was rx advancing on a carrier we weren't sending on?" could
            // not be answered from the log at all. It is off by default, so
            // widening it costs nothing until a lab run asks for it.
            if crate::overlay::direct::session_trace_enabled() {
                let proof_age = wg
                    .peer_initiator_hs_age(&e.pubkey)
                    .map_or(e.since.elapsed(), |a| a.min(e.since.elapsed()));
                tracing::info!(
                    peer = %nid,
                    overlay_ip = %e.overlay_ip,
                    tier = ?e.tier,
                    // Which plane this line is about. Without these two a
                    // relay line and a direct line are indistinguishable, and
                    // the poke/proof fields below mean different things on
                    // each — `tier` alone does not say it (`Relay` is a tier,
                    // but a DERP carrier and a TURN one are both `Relay`).
                    is_direct = e.is_direct,
                    relay_kind = ?e.relay_kind,
                    hs_done = handshake_done,
                    since_rx_s = since_last_rx.as_secs(),
                    proof_age_s = proof_age.as_secs(),
                    poke_pending = e.poke.is_some(),
                    poke_since_s = trace_poke.map(|(s, _, _)| s.as_secs()),
                    poke_answered = trace_poke.map(|(_, a, _)| a),
                    // #26 — which window this poke is judged on: a
                    // net-change-armed poke convicts at MAJOR_POKE_DEADLINE
                    // instead of the tier's establish-sized deadline.
                    poke_netchange = trace_poke.map(|(_, _, n)| n),
                    // A2 round-2 — the one-way inputs: does tx-DATA advance
                    // (tx>last_tx) while rx-DATA stays flat (rx==last_rx)?
                    // That's what must accumulate `bad_sweeps` → OneWay demote.
                    tx,
                    rx,
                    dtx = tx.saturating_sub(last_tx),
                    drx = rx.saturating_sub(last_rx),
                    bad_sweeps_in = e.bad_sweeps,
                    bad_sweeps_out = v.bad_sweeps,
                    death = ?v.death,
                    "overlay: session-trace (carrier health)"
                );
            }
            // P3 PR-A — feed the sweep's evidence to the shadow monitor:
            // heard-this-sweep (Q credit), a stored one-way strike (Q debit),
            // and the strike-clear (a direct carrier genuinely receiving also
            // grades any recent monitor refusal of this tier as harmful).
            {
                let tier = e.tier;
                let old_bad = e.bad_sweeps;
                self.shadow(|s| {
                    if heard {
                        s.mon.on_heard(nid, tier);
                    }
                    if v.bad_sweeps > old_bad {
                        s.mon.on_bad_sweep(nid, tier);
                    }
                    if v.clear_tier_strikes {
                        s.mon.on_healthy_rx(nid, tier);
                        s.establishment(nid, tier, now);
                    }
                });
            }
            e.bad_sweeps = v.bad_sweeps;
            // rc.275 honesty — stamp the display verdict (CLI `stalled`);
            // reap decisions stay with `carrier_tick` below.
            e.stalled = crate::overlay::lifecycle::carrier_stalled(
                e.since.elapsed(),
                handshake_done,
                v.bad_sweeps,
            );
            // rc.276 diagnostics — mirror the latch for the peers debug view.
            e.hs_done = handshake_done;
            // Unresponsive-peer backoff — a relay carrier that completed its
            // handshake proves the peer alive: forget its death streak so
            // future re-requests are immediate again.
            if !e.is_direct
                && handshake_done
                && let Some(c) = relay.as_mut()
            {
                c.clear_death_streak(nid);
            }
            // #22 — a peer we HEARD this sweep is not asleep: void any
            // active relay-death defer for it (the defer exists for silent
            // peers; an audible peer whose pair still churns will never
            // re-request from ITS side if its own leg round-trips — the
            // 08-18 mutual-defer wedge).
            if heard && let Some(c) = relay.as_mut() {
                c.note_peer_audible(nid);
            }
            // PR-E — the strike-clear (CC1: the carrier's OWN tier only)
            // lives in the monitor now (`on_healthy_rx`, fed just above).
            // Net-change acceleration — an OS addr/iface event this tick is
            // itself the suspicion: skip the silence/proof waits and
            // revalidate every established DIRECT carrier NOW. A healthy
            // carrier answers within a handshake round; a captured-route
            // casualty dies at `MAJOR_POKE_DEADLINE` instead of ~90 s
            // later (winhost-a CP-connect, 2026-08-15). Relay carriers are
            // exempt — they ride TCP/TLS and have their own refresh logic.
            //
            // #26 — this RE-ARMS over a poke already in flight, so it is
            // hoisted out of the `last_poke_at.is_none()` branch it used to
            // live in. Two reasons, both load-bearing: a poke armed by the
            // silence/proof triggers moments before a VPN connect otherwise
            // kept its 12–30 s tier deadline (a hole exactly one poke-window
            // wide, and the pre-#26 arming skipped it entirely), and the tight
            // window is only honest against a FRESH initiation — boringtun's
            // last re-send of an in-flight poke can already be ~5 s old.
            // An unanswered business packet is evidence to VERIFY the path
            // before TCP backs off and the next idle sweep clears its
            // one-way counter. Keep the normal handshake proof/deadline;
            // healthy one-way traffic can answer without a carrier switch.
            let unanswered_traffic = e.is_direct && handshake_done && v.bad_sweeps > 0;
            let forced = force_poke != ForcedPoke::No
                && e.is_direct
                && should_poke_on_netchange(handshake_done);
            let business_rearm = unanswered_traffic
                && e.poke.is_some_and(|p| !p.from_major && !p.from_business);
            if let Some(reason) = v.death {
                dead.push((*nid, e.tier, reason));
            } else if forced {
                if wg.poke_handshake(&e.pubkey) {
                    let rearmed = e.poke.is_some();
                    // Only a MAJOR earns the tight conviction window — see
                    // `ForcedPoke::AddrIface` for why the chatty cause must not.
                    let from_major = force_poke == ForcedPoke::Major;
                    e.poke = Some(PokeArm {
                        at: now,
                        from_major,
                        from_business: false,
                    });
                    // FR-68 — each poke re-keys a peer and can demote a healthy
                    // direct carrier, so this is what turns "the mesh feels
                    // unstable" into a number. ~100/min was #1237's signature.
                    crate::evidence::FORCED_REVALIDATIONS
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    info!(
                        peer = %nid, tier = ?e.tier,
                        silent_s = since_last_rx.as_secs(),
                        rearmed, from_major,
                        "overlay: net-change — revalidating direct carrier now (forced rekey poke)"
                    );
                }
            } else if business_rearm {
                if wg.poke_handshake(&e.pubkey) {
                    e.poke = Some(PokeArm {
                        at: now,
                        from_major: false,
                        from_business: true,
                    });
                    info!(peer = %nid, tier = ?e.tier,
                        "overlay: existing proof rearmed for unanswered business traffic");
                }
            } else if e.poke.is_none() {
                // Stage 2 — arm an active revalidation for a SURVIVOR when the
                // passive signals can't prove it either way: silent past
                // `POKE_SILENCE_AFTER`, or no initiator-role handshake within
                // `POKE_PROOF_AFTER` (`since_proof` counts from install for a
                // carrier we never initiated on). One in-flight poke per
                // carrier; boringtun retries the initiation every ~5 s on its
                // own.
                let since_proof = wg
                    .peer_initiator_hs_age(&e.pubkey)
                    .map_or(e.since.elapsed(), |age| age.min(e.since.elapsed()));
                // #22 — re-init pressure: the peer is retrying its handshake
                // at the ~5 s failure cadence against our ESTABLISHED
                // session, which means it cannot hear our responses on the
                // path it uses. Force the round-trip proof through OUR leg
                // now; if ours is the dead one the poke goes unanswered and
                // the tick's deadline convicts in seconds instead of the
                // ~30 min the proof-age trigger took on 08-18. rx-silence
                // can never catch this: the re-inits themselves keep
                // `last_rx_at` fresh.
                let pressured = handshake_done && e.reinit_recent >= REINIT_PRESSURE_MIN;
                if (pressured || unanswered_traffic
                    || should_poke(handshake_done, false, since_last_rx, since_proof))
                    && wg.poke_handshake(&e.pubkey)
                {
                    // Business data on an established direct path gets a
                    // liveness-sized window. Periodic/pressure-only pokes keep
                    // the original establishment deadline.
                    e.poke = Some(PokeArm {
                        at: now,
                        from_major: false,
                        from_business: unanswered_traffic,
                    });
                    if pressured {
                        info!(
                            peer = %nid, tier = ?e.tier,
                            reinits_in_window = e.reinit_recent,
                            "overlay: peer re-initiating rapidly against an established session — our outbound may be one-way; revalidating now (#22)"
                        );
                        e.reinit_recent = 0;
                        e.reinit_window_from = now;
                    } else if unanswered_traffic {
                        info!(
                            peer = %nid, tier = ?e.tier,
                            bad_sweeps = v.bad_sweeps,
                            "overlay: unanswered business traffic — verifying the direct carrier now"
                        );
                    } else {
                        debug!(
                            peer = %nid, tier = ?e.tier,
                            silent_s = since_last_rx.as_secs(), proof_age_s = since_proof.as_secs(),
                            "overlay: revalidating carrier (forced rekey poke)"
                        );
                    }
                }
            }
        }
        for (nid, tier, reason) in dead {
            let Some(e) = by_node.remove(&nid) else {
                continue;
            };
            carrier_lost = true;
            // P3 PR-A — a death is path-selection evidence: the monitor books
            // the strike + suppression penalty (≡ the cooldown insert below)
            // and slams the tier's quality. The tripwire then proves the
            // penalty math actually made the tier ineligible — the sweep-
            // surface half of the shadow comparison (a full decide() compare
            // happens at the next install_peers walk, which is where legacy
            // itself re-selects).
            self.shadow(|s| {
                s.mon.on_death(&nid, tier, reason, mbb, now);
                // Stage 2 — a RekeyUnanswered death deliberately books NO
                // penalty (see `PathMonitor::on_death`), so the tier is
                // legitimately still eligible and the tripwire would
                // false-fire its MODEL-BUG warning on every poke death.
                if tier.is_direct() && !matches!(reason, DeathReason::RekeyUnanswered) {
                    s.assert_ineligible(&nid, tier, now);
                }
            });
            wg.remove_peer(&e.pubkey).await;
            // A carrier REPAIR, not an eviction (the relay is re-requested
            // below), so it deliberately does NOT go through `evict_peer` —
            // forgetting the monitor evidence/probe here would undo proven behaviour.
            // It does need the recycled-address guard.
            del_peer_route_if_unowned(tun, by_node, e.overlay_ip).await;
            if tier.is_direct() {
                // PR-E — `PathMonitor::on_death` (fed above) IS the failure
                // bookkeeping now: strike + suppression penalty on the
                // carrier's OWN tier (CC1), escalating to the sticky regime
                // at the same thresholds the legacy maps used. Only the
                // operator-greppable log lines remain here, keyed off the
                // monitor's strike state — strings preserved verbatim.
                let tier_name = match tier {
                    DirectTier::Srflx => "srflx",
                    DirectTier::Public => "public",
                    _ => "LAN",
                };
                let (fails, sticky) = self
                    .shadow(|s| (s.mon.strikes(&nid, tier), s.mon.is_sticky(&nid, tier, mbb)))
                    .unwrap_or((0, false));
                if sticky {
                    warn!(
                        peer = %nid, tier = tier_name, fails,
                        "overlay: direct carrier failed repeatedly — pinning this peer to relay for the session"
                    );
                } else if reason == DeathReason::RekeyUnanswered {
                    // Stage 2 — active proof: 2–3 forced-rekey initiations
                    // went unanswered. No strike booked (the rebuild supplies
                    // fresh evidence itself), so a re-upgrade may re-attempt
                    // direct immediately — its failure is what books.
                    //
                    // #26 — `from_major` says WHICH window convicted: a
                    // Major-armed poke judges a SINGLE initiation over
                    // `MAJOR_POKE_DEADLINE`, every other poke judges 2–3 over
                    // the tier deadline. If the tight window ever proves too
                    // eager in the field, this is the line that shows it
                    // (Major convictions immediately followed by a successful
                    // direct re-upgrade of the same pair).
                    warn!(
                        peer = %nid, tier = tier_name,
                        from_major = e.poke.is_some_and(|p| p.from_major),
                        "overlay: established direct carrier failed active revalidation (forced rekey unanswered — path filtered / VPN / NAT rebind?) — rebuilding via relay"
                    );
                } else if reason == DeathReason::RxStale {
                    // rc.206 — an ESTABLISHED direct carrier that went silent
                    // (peer roamed / NAT rebind / path died mid-session), not a
                    // never-punched one. Distinct message so field logs separate
                    // "died" from "never established". A re-upgrade re-punches
                    // once the cooldown clears; the fail count usually clears on
                    // the first receiving sweep after that, so a one-off death
                    // doesn't march toward the sticky pin.
                    warn!(
                        peer = %nid, tier = tier_name,
                        "overlay: established direct carrier went silent (no keepalive within the rx-stale deadline — peer roamed / NAT rebind / path died) — rebuilding via relay"
                    );
                } else {
                    warn!(
                        peer = %nid, tier = tier_name,
                        "overlay: direct carrier didn't establish (firewall / VPN / AP-isolation / unpunchable NAT?) — falling back to relay"
                    );
                }
            } else {
                relay_refresh_cooldown.insert(nid, now + RELAY_REFRESH_COOLDOWN);
                // P2 — relay side: HardDead > RxStale > else ("one-way" covers
                // both OneWay and a relay HandshakeDeadline, as pre-P2).
                // The kind rides every conviction line (field 2026-08-16: a
                // dead DERP carrier convicted under "stale coturn port?" and
                // sent the diagnosis hunting through coturn for hours).
                //
                // #28 — and so does the SENTENCE. A DERP carrier is raw WG over
                // the pubkey-addressed `/derp` WS: it has no coturn allocation,
                // no relayed port, nothing to re-allocate. Adding `kind=` in
                // 2026-08-16 made the truth available; it did not stop the
                // message itself from asserting a TURN diagnosis, and the
                // message is what a human greps and reads first.
                let is_derp = e.relay_kind == Some(crate::overlay::relay_link::RelayKind::Derp);
                let rebuild = if is_derp {
                    "rebuilding the /derp carrier"
                } else {
                    "re-allocating"
                };
                if reason == DeathReason::HardDead {
                    let cause = if is_derp {
                        "/derp WS closed under it"
                    } else {
                        "TURNS/TCP reset / QUIC-over-TURN lost"
                    };
                    warn!(
                        peer = %nid, kind = ?e.relay_kind,
                        "overlay: relay carrier send hard-errored ({cause}) — {rebuild}"
                    );
                } else if reason == DeathReason::RekeyUnanswered {
                    // Stage 2 — the relay accepted our sends (no hard error)
                    // but repeated forced-rekey initiations never completed:
                    // the classic silently-dead allocation, now caught by
                    // active proof instead of the 90 s rx-stale wait — and
                    // caught EVEN when the peer's own inbound traffic keeps
                    // rx moving (the one-way class no passive rule can see;
                    // field 2026-08-08, winhost-a→devbox via a raw-dialed srflx).
                    let cause = if is_derp {
                        "one-way over /derp"
                    } else {
                        "one-way or dead allocation"
                    };
                    warn!(
                        peer = %nid, kind = ?e.relay_kind,
                        "overlay: relay carrier failed active revalidation (forced rekey unanswered — {cause}) — {rebuild}"
                    );
                } else if reason == DeathReason::RxStale {
                    // rc.206 — a relay carrier that stopped delivering with no
                    // send-error to trip `hard_dead` (silently-dropped coturn
                    // allocation / a dead worker the send path can't detect).
                    let cause = if is_derp {
                        "the relay is not delivering the peer's frames to us"
                    } else {
                        "coturn allocation dropped?"
                    };
                    warn!(
                        peer = %nid, kind = ?e.relay_kind,
                        "overlay: relay carrier went silent (no keepalive within the rx-stale deadline — {cause}) — {rebuild}"
                    );
                } else {
                    // #28 — the one-way class is where the wrong sentence hurt
                    // most, because on DERP it has a completely different
                    // cause: nothing of ours is coming BACK, which means the
                    // peer is not on `/derp` with us (its own WS down, or —
                    // pre-#27 — it simply never followed us here). Re-running a
                    // coturn hunt for that is wasted field time.
                    let cause = if is_derp {
                        "the peer is not reachable over /derp — its WS may be down, or it has not followed us onto DERP"
                    } else {
                        "stale coturn port?"
                    };
                    warn!(
                        peer = %nid, kind = ?e.relay_kind,
                        "overlay: relay carrier one-way ({cause}) — {rebuild}"
                    );
                }
            }
            // (Re)request the relay now (don't wait for the next netmap). For a
            // relay refresh we first forget the stale allocation so a fresh one
            // is made; a direct→relay fall has no prior allocation to forget.
            if let (Some(coord), Some(np)) = (relay.as_mut(), current_peers.get(&nid))
                && let Some(cfg) = peer_config_from_netmap(np)
            {
                // Dialer honesty — a NEVER-HANDSHOOK death of a TURN carrier
                // while WE were the raw-UDP DIALER is evidence about OUR
                // egress (the dial toward the anchor's relay-band port never
                // landed). ONLY that class books: a worked-then-died link
                // (RxStale/OneWay/RekeyUnanswered/HardDead) is the peer's or
                // the allocation's death — booking those latched half the
                // fleet during the rc.393 rolling update, when every restart
                // wave killed working links everywhere. Two distinct peers
                // latch not-dialer-capable (dialer.rs adds start-grace and
                // recency guards on top), the mirror sync below flips this
                // org's role inputs the same cycle, and the periodic srflx
                // advert carries the verdict to peers + server.
                if reason == DeathReason::HandshakeDeadline
                    && e.relay_kind == Some(crate::overlay::relay_link::RelayKind::Turn)
                    && coord.was_dialer_for(&nid)
                {
                    crate::overlay::dialer::note_dialer_conviction(nid);
                }
                coord.set_udp_dialer_ok(crate::overlay::dialer::udp_dialer_ok());
                coord.set_relay_band_udp(
                    crate::overlay::netcheck::current_fresh().and_then(|v| v.relay_band_udp),
                );
                // #24 — the carrier is gone either way, so the birth-floor
                // bookkeeping is stale NOW. `forget` (relay deaths only)
                // used to be the sole path that cleared it, which left a
                // floored→direct→dead peer permanently unable to re-floor:
                // the establish walk's `!is_floored()` gate saw a floor that
                // no longer existed and fell through to a ladder that, with
                // no srflx and no dialer role, could not build either.
                coord.clear_floor(&nid);
                if !tier.is_direct() {
                    coord.forget(&nid);
                }
                // U1 — ship the death as evidence with the re-request: the
                // dead carrier's relay flavour (None for a direct→relay fall)
                // + the typed reason, so the server's churn escalation can
                // log/act on WHAT died instead of inferring from timing.
                coord.note_refresh_context(nid, e.relay_kind, reason.as_str());
                coord.request(nid, cfg).await;
            }
        }
        // P3 PR-A — the 10-min shadow summary rides the 5 s sweep cadence.
        self.shadow(|s| s.maybe_summary(now));
        carrier_lost
    }

    /// rc.131 — bind the shared direct-carrier socket + discover our LAN
    /// endpoint. Only in Relay mode (Direct mode is the loopback test/helper
    /// path) and when `ROOMLERD_OVERLAY_DIRECT` isn't disabled. `None` if
    /// disabled, not relay mode, the bind fails, or there's no usable LAN IP
    /// (offline / CGNAT-only) — the node then stays relay-only as before.
    pub(super) async fn setup_direct(&self) -> Option<DirectCtx> {
        if !matches!(self.mode, CarrierMode::Relay) || !direct::direct_enabled() {
            return None;
        }
        // Multi-org v2 — plane mode: the process-wide socket set is bound
        // ONCE by the plane; this runtime consumes a view of it instead of
        // binding its own (the per-runtime band race this replaces). The
        // punch socket + NAT class are stamped by the plane-side gather.
        if let Some(plane) = &self.carrier_plane {
            let v = plane.ensure_bound().await?;
            return Some(DirectCtx {
                socks: v.socks,
                my_ips: v.my_ips,
                endpoints: v.endpoints,
                public_sock: v.public_sock,
                punch: None,
                my_nat: None,
            });
        }
        let ifaces = direct::gather_lan_interfaces();
        let my_ips: Vec<Ipv4Addr> = ifaces.iter().map(|(ip, _)| *ip).collect();
        if my_ips.is_empty() {
            info!("overlay: no usable LAN interface; direct path off (relay only)");
            return None;
        }
        // rc.143 — bind ONE socket per interface IP (to that IP, not 0.0.0.0);
        // rc.144 — ALSO pin egress to that NIC via IP_UNICAST_IF, because on
        // Windows a source-IP bind alone doesn't force the egress interface (the
        // route does), so a full-tunnel VPN's default route otherwise steals the
        // send and same-WiFi direct oscillates. Advertise each socket's own
        // `ip:port`; the peer dials whichever shares its subnet, and both sides
        // then send/receive over that interface's pinned socket.
        // Stable direct port (rc.307): bind every direct socket to the SAME
        // port across restarts/rebuilds so the carrier's UDP 5-tuple is
        // reproducible — stateful corp firewalls (Check Point) grandfather
        // flows that predate their VPN session table, and only a matching
        // 5-tuple keeps riding that grandfathered session after a rebuild.
        // 0 = ephemeral (pre-rc.307 behavior). See `direct::direct_port`.
        let stable_port = direct::direct_port();
        let mut socks: Vec<(Ipv4Addr, Arc<UdpSocket>)> = Vec::new();
        let mut endpoints: Vec<String> = Vec::new();
        for (ip, ifindex) in &ifaces {
            let Some(s) = bind_direct_socket(*ip, stable_port, "lan").await else {
                continue;
            };
            if let Some(idx) = ifindex {
                direct::force_egress_interface(&s, *idx);
            }
            match s.local_addr() {
                Ok(local) => {
                    endpoints.push(format!("{ip}:{}", local.port()));
                    socks.push((*ip, Arc::new(s)));
                }
                Err(e) => {
                    warn!(%ip, %e, "overlay: direct socket local_addr failed; skipping")
                }
            }
        }
        if socks.is_empty() {
            info!("overlay: no bindable LAN interface; direct path off (relay only)");
            return None;
        }
        info!(
            endpoints = ?endpoints,
            "overlay: advertising direct LAN endpoints (per-interface sockets; same-subnet peers dial direct)"
        );
        // Phase A/B — a single unbound socket to DIAL peers' public endpoints
        // (the OS picks egress per-destination). Shared by the public-direct
        // tier (peer's public NIC) AND the srflx tier (peer's NAT mapping), so
        // it's bound when EITHER is on. Best-effort: a bind failure just leaves
        // both public-dial tiers off (relay still works).
        let public_sock = if direct::public_direct_enabled() || direct::srflx_enabled() {
            // Stable-port twin on its OWN band: a wildcard bind collides with
            // the interface-specific LAN binds above on the same port (no
            // SO_REUSEADDR — unsafe double-delivery semantics on Windows
            // UDP), and the offset keeps a LAN band walk from ever running
            // into it. `direct_port` caps the base so this can't overflow.
            let public_port = if stable_port != 0 {
                stable_port + direct::PUBLIC_DIAL_PORT_OFFSET
            } else {
                0
            };
            match bind_direct_socket(Ipv4Addr::UNSPECIFIED, public_port, "public-dial").await {
                Some(s) => {
                    // VPN-bypass: pin this `0.0.0.0` public/srflx dialer's egress
                    // to the physical uplink so it leaves the real NIC instead
                    // of a full-tunnel corp VPN's captured default.
                    if let Some(ix) = direct::vpn_bypass_ifindex() {
                        direct::force_egress_interface(&s, ix);
                        info!(
                            ifindex = ix,
                            "overlay: VPN-bypass — public-dial egress pinned to the physical uplink"
                        );
                    }
                    info!(
                        public_direct = direct::public_direct_enabled(),
                        srflx = direct::srflx_enabled(),
                        "overlay: public-dial egress socket ON (NAT-traversal Phase A/B)"
                    );
                    Some(Arc::new(s))
                }
                None => {
                    warn!("overlay: public-dial egress socket bind failed; public/srflx tiers off");
                    None
                }
            }
        } else {
            None
        };
        Some(DirectCtx {
            socks,
            my_ips,
            endpoints,
            public_sock,
            // Set after the startup srflx gather (Phase C) once we know which
            // interface socket owns our first advertised srflx candidate + the
            // NAT-type probe on it.
            punch: None,
            my_nat: None,
        })
    }

    /// Tear one peer's carrier down: WG peer, crypto-routes, OS `/32`, relay
    /// coordination, queued builds/allocations and any in-flight upgrade probe.
    ///
    /// THE single teardown for every eviction path (delta `removes`, the
    /// full-netmap prune, resume-from-suspend) so the three can't drift apart.
    /// Returns the removed [`Installed`], if the peer was installed at all.
    ///
    /// `by_node.remove` happens FIRST so [`del_peer_route_if_unowned`] sees only
    /// survivors when it decides whether the OS route is still claimed.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn remove_peer_state(
        &self,
        node_id: ObjectId,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        tun: &Arc<dyn TunIo>,
        relay: &mut Option<RelayCoordinator>,
        relay_bq: &mut RelayBuildQueue,
        alloc_q: Option<&mut RelayAllocQueue>,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
        os_route: PeerRoute,
    ) -> Option<Installed> {
        let removed = by_node.remove(&node_id);
        if let Some(e) = &removed {
            wg.remove_peer(&e.pubkey).await;
            if os_route == PeerRoute::Drop {
                del_peer_route_if_unowned(tun, by_node, e.overlay_ip).await;
            }
        }
        if let Some(r) = relay.as_mut() {
            r.forget(&node_id);
        }
        // rc.211 — drop any in-flight off-loop relay build (stale on arrival).
        relay_bq.invalidate(&node_id);
        if let Some(q) = alloc_q {
            q.invalidate(&node_id);
        }
        // rc.208 — drop any in-flight make-before-break probe (its shadow
        // carrier + demux registration).
        if let Some(pr) = upgrade_probes.remove(&node_id) {
            wg.drop_direct_probe(&pr.pubkey).await;
        }
        removed
    }

    /// Re-establish a peer stuck on an **established DERP** carrier whose
    /// strategy inputs have since improved (the peer's — or our own — srflx
    /// arrived after the link was built), so the pair moves DERP → TURN.
    ///
    /// Called only from the installed-on-relay arm of [`Self::install_peers`],
    /// and only on the paths that would otherwise KEEP the relay: a direct tier
    /// beats every relay tier, so an available direct upgrade always wins and
    /// this never competes with it. `RelayCoordinator::derp_regrade_due` owns
    /// the decision (and its cooldown); this owns the mechanics, which mirror
    /// the P7 force-DERP teardown/rebuild in the other direction.
    ///
    /// Returns whether a regrade was performed.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn maybe_regrade_derp(
        &self,
        node_id: ObjectId,
        cfg: &PeerConfig,
        pk: &[u8; 32],
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        tun: &Arc<dyn TunIo>,
        relay: &mut Option<RelayCoordinator>,
        relay_bq: &mut RelayBuildQueue,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
        now: Instant,
    ) -> bool {
        // Only an installed DERP carrier is in scope, and never while a
        // make-before-break direct probe is in flight — that probe may be about
        // to retire the relay entirely, and tearing the peer down here would
        // drop its shadow carrier with it.
        if by_node.get(&node_id).and_then(|e| e.relay_kind)
            != Some(crate::overlay::relay_link::RelayKind::Derp)
            || wg.has_direct_probe(pk)
        {
            return false;
        }
        if !relay
            .as_mut()
            .is_some_and(|r| r.derp_regrade_due(&node_id, cfg, now))
        {
            return false;
        }
        info!(
            peer = %node_id,
            "overlay relay: DERP no longer the best tier for this pair (srflx settled since it was built) — re-establishing"
        );
        // `PeerRoute::Keep`: the peer's overlay IP is unchanged and we reinstall
        // immediately, so dropping and re-adding its OS route would only blip
        // the data path.
        self.remove_peer_state(
            node_id,
            wg,
            by_node,
            tun,
            relay,
            relay_bq,
            None,
            upgrade_probes,
            PeerRoute::Keep,
        )
        .await;
        if let Some(r) = relay.as_mut() {
            r.request(node_id, cfg.clone()).await;
            // A DERP→single-relay DIALER build can complete synchronously off
            // the netmap we already hold; an ANCHOR/both-allocate needs the
            // server's grant and lands later via the alloc queue.
            if let Some(link) = r.maybe_complete(node_id, cfg) {
                self.install_ready(wg, by_node, tun, link, relay_bq).await;
            }
        }
        true
    }

    /// A full EVICTION: [`Self::remove_peer_state`] plus the netmap/monitor
    /// bookkeeping that only makes sense when the peer is GONE (as opposed to
    /// being re-installed).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn evict_peer(
        &self,
        node_id: ObjectId,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        tun: &Arc<dyn TunIo>,
        relay: &mut Option<RelayCoordinator>,
        relay_bq: &mut RelayBuildQueue,
        alloc_q: &mut RelayAllocQueue,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
        current_peers: &mut HashMap<ObjectId, NetmapPeer>,
        relay_refresh_cooldown: &mut HashMap<ObjectId, Instant>,
    ) {
        current_peers.remove(&node_id);
        // P3 PR-A — drop the monitor's per-peer state.
        self.shadow(|s| s.mon.on_peer_removed(&node_id));
        let removed = self
            .remove_peer_state(
                node_id,
                wg,
                by_node,
                tun,
                relay,
                relay_bq,
                Some(alloc_q),
                upgrade_probes,
                PeerRoute::Drop,
            )
            .await;
        // Keyed by node id and never pruned otherwise, so a long-lived daemon
        // accumulated an entry per peer that ever churned (the monitor's
        // per-peer state is dropped by `on_peer_removed` above).
        relay_refresh_cooldown.remove(&node_id);
        if removed.is_some() {
            info!(peer = %node_id, "overlay: peer removed");
        }
    }

    /// Reconcile the netmap into installed peers. NOT-yet-installed: Direct
    /// mode → build the loopback/test carrier; Relay mode → a DIRECT LAN
    /// carrier when the peer advertises a same-subnet endpoint (rc.131/134 — N
    /// peers share one socket via the device's source-address demux), else the
    /// coturn relay coordination. ALREADY-installed on RELAY but a same-subnet
    /// endpoint has since appeared → UPGRADE to direct (rc.134 re-evaluation:
    /// a peer first seen before its endpoint arrived would otherwise stay on
    /// relay forever). A peer whose direct tier is monitor-suppressed (it just
    /// failed — rc.136) is kept on relay regardless of a same-subnet endpoint.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn install_peers(
        &self,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        relay: &mut Option<RelayCoordinator>,
        tun: &Arc<dyn TunIo>,
        peers: &[NetmapPeer],
        direct_ctx: Option<&DirectCtx>,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
        relay_bq: &mut RelayBuildQueue,
        trigger: &'static str,
    ) {
        let now = Instant::now();
        // rc.208 — make-before-break: probe a relay→direct upgrade instead of
        // tearing the relay down speculatively. Read once per call.
        let make_before_break = crate::overlay::direct::make_before_break_enabled();
        // FR-33 P2 — the host's captured LAN prefixes, read once per walk: a
        // peer whose LAN candidate lies in one is reported to the monitor
        // below, which refuses the LAN tier outright (`on_lan_capture`). No
        // handle (monitor off / platform without one) = no captures = no gate.
        let lan_captures: Vec<crate::overlay::netstate::LanCapture> =
            crate::overlay::netstate::handle()
                .map(|h| h.snapshot().lan_captures.clone())
                .unwrap_or_default();
        for np in peers {
            // P9 — presence: never dial / probe / relay-request a peer the
            // server marked unreachable (ghost enrollment, stale heartbeat,
            // clean leave). An already-installed carrier is left alone — the
            // data plane outlives a control-plane hiccup and the health sweep
            // owns its lifecycle; removal still arrives via the leave delta.
            if !np.reachable {
                continue;
            }
            let Some(cfg) = peer_config_from_netmap(np) else {
                continue;
            };
            // PR-E — the candidates ARE the dial targets: tier suppression
            // (rc.136 + CC1 in monitor form — per-tier penalties that never
            // cross-poison, escalating at the same thresholds) lives entirely
            // in `decide()`'s eligibility plane, applied via the action
            // gating below. This also closes the soak-#2 residual coupling
            // (a legacy cooldown withholding a dst the monitor held
            // eligible).
            // A2 — rotate multi-candidate dials by the monitor's strike
            // count: each failed probe advances to the peer's next advertised
            // public/srflx candidate (success resets strikes → primary).
            let rot = self
                .shadow(|s| CandidateRotation {
                    public: s.mon.strikes(&np.node_id, DirectTier::Public),
                    srflx: s.mon.strikes(&np.node_id, DirectTier::Srflx),
                    lan: s.mon.strikes(&np.node_id, DirectTier::Lan),
                })
                .unwrap_or_default();
            let cands = resolve_direct_candidates(direct_ctx, &cfg, rot);
            // FR-33 P2 — a LAN candidate inside a captured prefix is a dial
            // the OS has already said it will misroute; hand the verdict to
            // the monitor so `decide` never proposes it and `why` names it.
            let lan_captured = cands.lan.is_some_and(|(_, dst)| match dst {
                std::net::SocketAddr::V4(sa) => {
                    lan_captures.iter().any(|c| c.contains_v4(*sa.ip()))
                }
                std::net::SocketAddr::V6(_) => false,
            });
            self.shadow(|s| s.mon.on_lan_capture(&np.node_id, lan_captured));
            let direct_dst = cands.lan;
            let phase_a_dst = cands.public;
            let srflx_dst = cands.srflx;

            // Multi-org P2a: the peer's OVERLAY IP changed under a stable
            // node_id — the tenant-block renumber (P2b) re-IPs nodes, and
            // everything we hold (crypto-route, peer /32, defended route) is
            // keyed to the OLD address. Pre-P2a this upsert was a silent
            // no-op: the already-installed short-circuits below kept the
            // stale /32 + router entry alive and the new IP was never
            // installed. Tear down FIRST (so the copy-out below reads None →
            // clean install); `PeerRoute::Drop` (vs the key-rotation arm's
            // `Keep`) because the OLD address's route must go — install
            // re-adds the new one, and Drop's other-claimant guard protects a
            // recycled address already owned by a different live peer.
            if let Some(old_ip) = by_node.get(&np.node_id).map(|e| e.overlay_ip)
                && old_ip != cfg.overlay_ip
            {
                warn!(peer = %np.node_id, old_ip = %old_ip, new_ip = %cfg.overlay_ip,
                    "overlay: peer's overlay IP changed (renumber) — reinstalling its carrier");
                self.remove_peer_state(
                    np.node_id,
                    wg,
                    by_node,
                    tun,
                    relay,
                    relay_bq,
                    None,
                    upgrade_probes,
                    PeerRoute::Drop,
                )
                .await;
            }
            // Copy-out the installed carrier's shape (all Copy), so the by_node
            // borrow ends before any mutation below.
            let installed = by_node
                .get(&np.node_id)
                .map(|e| (e.is_direct, e.pubkey, e.tier, e.public_direct_dst));
            // The node's WG identity CHANGED under a stable node_id: the daemon
            // rotated its key, or the netmap row is the stale remains of a
            // different machine. Either way everything we hold — Tunn,
            // crypto-route, demux registration, relay coordination, in-flight
            // probe — is keyed to the OLD key and is dead. Tear it down and fall
            // through to a clean install; without this the already-installed
            // short-circuits below kept the orphaned peer alive AND kept the old
            // key accepted inbound forever.
            let installed = match installed {
                Some((_, pk, _, _)) if pk != cfg.public_key => {
                    warn!(peer = %np.node_id, overlay_ip = %cfg.overlay_ip,
                        "overlay: peer's WG public key changed — reinstalling its carrier");
                    // No alloc_q here (install_peers doesn't take one) and none
                    // needed: `relay.forget` inside makes a landing `AllocDone`
                    // a no-op for this node.
                    self.remove_peer_state(
                        np.node_id,
                        wg,
                        by_node,
                        tun,
                        relay,
                        relay_bq,
                        None,
                        upgrade_probes,
                        PeerRoute::Keep,
                    )
                    .await;
                    None
                }
                other => other,
            };
            // The negotiated bilateral trial owns carrier selection, but only
            // AFTER authoritative key/IP reconciliation above. Never allow the
            // legacy relay-to-direct upgrader to split the two-member decision.
            if installed.is_some()
                && self
                    .path_trial_managed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(&np.node_id)
            {
                continue;
            }
            // P3 PR-A — the shadow monitor's answer to the SAME question this
            // walk is about to answer, computed up-front; every decision exit
            // below records the legacy outcome against it (`record`). Legacy
            // stays authoritative — this is instrumentation only. Inert in
            // Direct/test carrier mode and when the monitor is off.
            let avail = path::TierAvailability {
                lan: cands.lan.is_some(),
                public: cands.public.is_some(),
                srflx: cands.srflx.is_some(),
            };
            let incumbent = match installed {
                Some((true, _, tier, _)) => path::Incumbent::Direct(tier),
                Some((false, _, _, _)) => path::Incumbent::Relay,
                None => path::Incumbent::None,
            };
            let monitor_action = matches!(self.mode, CarrierMode::Relay)
                .then(|| {
                    self.shadow(|s| {
                        // B2 — demotion executes only in `on` mode; shadow
                        // counts separately below.
                        let demote_on = s.demote == path::DemoteMode::On;
                        s.mon.decide(
                            &np.node_id,
                            incumbent,
                            avail,
                            make_before_break,
                            now,
                            demote_on,
                        )
                    })
                })
                .flatten();
            let record = |surface: &'static str, legacy: path::PathAction| {
                if let Some(m) = monitor_action {
                    self.shadow(|s| {
                        s.compare(surface, trigger, &np.node_id, Some(legacy), Some(m), now)
                    });
                }
            };
            // P3 PR-C — ON mode: the monitor's decision is AUTHORITATIVE. It
            // gates the legacy walk below instead of duplicating it: for a
            // committed single-tier action only that tier stays dialable, so
            // the same install/probe machinery executes exactly the monitor's
            // choice; Keep/Relay clear every direct tier (fall through to
            // relay / no-op). Two deliberate exemptions:
            // * already-direct incumbents keep their dsts — the D10 re-dial
            //   is execution-layer (dial-target freshness, not selection);
            // * P9 probe-first fresh-LAN keeps ALL dsts — the walk needs the
            //   LAN candidate for the probe AND the fallback tiers for the
            //   working carrier, exactly like legacy.
            // The legacy cooldown state keeps being written throughout (the
            // shadow-revert safety rail); `record` still runs, so pilot
            // volume shows in the summaries (compares are monitor-vs-monitor
            // there — the fleet's shadow mode carries the real divergence
            // telemetry until PR-D).
            // PR-E — the monitor's decision gates the walk UNCONDITIONALLY
            // (there is no legacy selector any more; `PathMonMode` is
            // telemetry-only).
            let (direct_dst, phase_a_dst, srflx_dst) = if monitor_action.is_some() {
                match (incumbent, monitor_action) {
                    (path::Incumbent::Direct(_), _) => (direct_dst, phase_a_dst, srflx_dst),
                    (path::Incumbent::None, Some(path::PathAction::Probe(DirectTier::Lan))) => {
                        (direct_dst, phase_a_dst, srflx_dst)
                    }
                    (_, Some(path::PathAction::Probe(DirectTier::Lan)))
                    | (_, Some(path::PathAction::Install(DirectTier::Lan))) => {
                        (direct_dst, None, None)
                    }
                    (_, Some(path::PathAction::Probe(DirectTier::Public)))
                    | (_, Some(path::PathAction::Install(DirectTier::Public))) => {
                        (None, phase_a_dst, None)
                    }
                    (_, Some(path::PathAction::Probe(DirectTier::Srflx)))
                    | (_, Some(path::PathAction::Install(DirectTier::Srflx))) => {
                        (None, None, srflx_dst)
                    }
                    _ => (None, None, None),
                }
            } else {
                (direct_dst, phase_a_dst, srflx_dst)
            };
            match installed {
                Some((true, pk, tier, inst_dst)) => {
                    // D10 — a zombie srflx punch (installed but never handshook)
                    // whose advertised srflx has since CHANGED: re-dial the fresh
                    // mapping NOW, without booking a strike (the old dst is
                    // known-stale — not evidence the pair can't punch). Otherwise
                    // a srflx re-trickle sits ignored on an already-direct peer
                    // until the handshake deadline tears it down (~100 s later),
                    // and books a bogus strike doing so.
                    if tier == DirectTier::Srflx
                        && !wg.peer_handshake_done(&pk).unwrap_or(true)
                        && let (Some(ctx), Some(fresh)) = (direct_ctx, srflx_dst)
                        && inst_dst != Some(fresh)
                    {
                        // P3 PR-C (soak #1 finding) — a D10 re-dial refreshes
                        // the DIAL TARGET of the current tier (Srflx→Srflx),
                        // so it is NOT a tier-selection event: counted, never
                        // compared (PR-A's compare here produced 50+/host/45 h
                        // of false "divergence"). Permanently execution-layer.
                        self.shadow(|s| s.stats.d10_redials += 1);
                        info!(peer = %np.node_id, old = ?inst_dst, new = %fresh, "overlay: srflx changed under a pending punch — re-dialing fresh mapping");
                        wg.remove_peer(&pk).await;
                        self.install_srflx_direct(wg, by_node, tun, ctx, np.node_id, &cfg, fresh)
                            .await;
                    } else if let Some(path::PathAction::Probe(target)) = monitor_action
                        && target != tier
                        && !wg.has_direct_probe(&pk)
                    {
                        // B2 (on) — voluntary demotion: the monitor found a
                        // sustained margin-sized score deficit against an
                        // eligible alternative. MBB-probe it — the incumbent
                        // keeps carrying traffic until the probe latches
                        // (`sweep_upgrade_probes` promotes tier-agnostically).
                        let probe_target = match target {
                            DirectTier::Lan => {
                                if let (Some(ctx), Some((local_ip, dst))) = (direct_ctx, direct_dst)
                                {
                                    lan_egress_socket(ctx, local_ip, dst)
                                        .await
                                        .map(|s| (s, dst))
                                } else {
                                    None
                                }
                            }
                            DirectTier::Public => {
                                if let (Some(ctx), Some(dst)) = (direct_ctx, phase_a_dst) {
                                    ctx.public_sock.clone().map(|s| (s, dst))
                                } else {
                                    None
                                }
                            }
                            DirectTier::Srflx => {
                                if let (Some(ctx), Some(dst)) = (direct_ctx, srflx_dst) {
                                    ctx.punch.clone().map(|(_, s)| (s, dst))
                                } else {
                                    None
                                }
                            }
                            DirectTier::Relay => None,
                        };
                        if let Some((sock, dst)) = probe_target {
                            record("install_peers:demote", path::PathAction::Probe(target));
                            info!(
                                peer = %np.node_id, from = ?tier, to = ?target,
                                "overlay pathmon[demote]: sustained score deficit — probing better tier (incumbent held until latch)"
                            );
                            self.start_upgrade_probe(
                                wg,
                                upgrade_probes,
                                np.node_id,
                                &cfg,
                                sock,
                                dst,
                                target,
                                now,
                            )
                            .await;
                        } else {
                            record("install_peers:keep_direct", path::PathAction::Keep);
                        }
                    } else {
                        // B2 shadow — count the would-be demotion without
                        // acting (its own by_class lane + rate-limited log).
                        // The Relay class stays advisory even in `on` mode
                        // (decide returns it, but execution is deferred —
                        // the death path owns actual direct→relay moves).
                        if let path::Incumbent::Direct(cur) = incumbent {
                            self.shadow(|s| {
                                let advisory_relay =
                                    matches!(monitor_action, Some(path::PathAction::Relay));
                                if (s.demote == path::DemoteMode::Shadow || advisory_relay)
                                    && let Some(would) =
                                        s.mon.demote_candidate(&np.node_id, cur, avail, now)
                                {
                                    s.note_shadow_demote(&np.node_id, would, now);
                                }
                            });
                        }
                        // B3 — mid-tier upward probing: a HEALTHY established
                        // srflx/public incumbent probes an eligible HIGHER
                        // tier at most once per 120 s (the monitor books the
                        // spacing at candidate time). Same MBB execution as
                        // the demote branch above; mutually exclusive with it
                        // by construction (a demote Probe took the branch
                        // above; here decide said Keep).
                        let upward_target: Option<DirectTier> = if wg.has_direct_probe(&pk) {
                            None
                        } else {
                            self.shadow(|s| {
                                if !s.upward {
                                    return None;
                                }
                                let path::Incumbent::Direct(cur) = incumbent else {
                                    return None;
                                };
                                s.mon.upward_candidate(&np.node_id, cur, avail, now)
                            })
                            .flatten()
                        };
                        if let Some(target) = upward_target {
                            let probe_target = match target {
                                DirectTier::Lan => {
                                    if let (Some(ctx), Some((local_ip, dst))) =
                                        (direct_ctx, direct_dst)
                                    {
                                        lan_egress_socket(ctx, local_ip, dst)
                                            .await
                                            .map(|s| (s, dst))
                                    } else {
                                        None
                                    }
                                }
                                DirectTier::Public => {
                                    if let (Some(ctx), Some(dst)) = (direct_ctx, phase_a_dst) {
                                        ctx.public_sock.clone().map(|s| (s, dst))
                                    } else {
                                        None
                                    }
                                }
                                DirectTier::Srflx => {
                                    if let (Some(ctx), Some(dst)) = (direct_ctx, srflx_dst) {
                                        ctx.punch.clone().map(|(_, s)| (s, dst))
                                    } else {
                                        None
                                    }
                                }
                                DirectTier::Relay => None,
                            };
                            if let Some((sock, dst)) = probe_target {
                                self.shadow(|s| {
                                    let c =
                                        s.stats.by_class.entry("midtier_upward").or_insert((0, 0));
                                    c.0 += 1;
                                });
                                info!(
                                    peer = %np.node_id, from = ?tier, to = ?target,
                                    "overlay pathmon[upward]: higher tier eligible — probing (incumbent held until latch)"
                                );
                                self.start_upgrade_probe(
                                    wg,
                                    upgrade_probes,
                                    np.node_id,
                                    &cfg,
                                    sock,
                                    dst,
                                    target,
                                    now,
                                )
                                .await;
                                continue; // counted as midtier_upward, not keep
                            }
                        }
                        // P3 PR-A (F14) — the already-direct fall-through IS a
                        // decision (keep the incumbent); record it so the
                        // shadow compare covers this arm too.
                        record("install_peers:keep_direct", path::PathAction::Keep);
                    }
                    continue; // already direct (LAN / public / srflx)
                }
                Some((false, pk, _, _)) => {
                    // Installed on RELAY — upgrade to the best available direct
                    // tier now that an endpoint has appeared: LAN > public-NIC >
                    // srflx punch.
                    //
                    // rc.208 make-before-break: when enabled, install the
                    // candidate direct carrier as a SHADOW PROBE (keyed by the
                    // same pubkey; its own `Tunn` in `WgDevice::probes`) while the
                    // working relay keeps routing. `sweep_upgrade_probes` cuts
                    // over only once the probe's handshake latches (proof the path
                    // works both ways), and drops it — leaving the relay
                    // untouched — if it never does. This kills the ~15-38 s
                    // per-upgrade freeze the destructive path below caused on a
                    // peer that can only relay (same-NAT AP-isolation / no
                    // hairpin). Skip if a probe for this peer is already in flight.
                    if make_before_break {
                        // Resolve the best available direct tier's (socket, dst):
                        // LAN > public-NIC > srflx punch — same precedence as the
                        // destructive path. Skip if a probe is already in flight.
                        let probe_target = if wg.has_direct_probe(&pk) {
                            None
                        } else if let (Some(ctx), Some((local_ip, dst))) = (direct_ctx, direct_dst)
                        {
                            // LAN tier — bind-by-route egress selection (Phase 1).
                            lan_egress_socket(ctx, local_ip, dst)
                                .await
                                .map(|s| (s, dst, DirectTier::Lan))
                        } else if let (Some(ctx), Some(dst)) = (direct_ctx, phase_a_dst) {
                            ctx.public_sock
                                .clone()
                                .map(|s| (s, dst, DirectTier::Public))
                        } else if let (Some(ctx), Some(dst)) = (direct_ctx, srflx_dst) {
                            ctx.punch.clone().map(|(_, s)| (s, dst, DirectTier::Srflx))
                        } else {
                            None
                        };
                        if let Some((sock, dst, tier)) = probe_target {
                            record("install_peers:upgrade", path::PathAction::Probe(tier));
                            self.start_upgrade_probe(
                                wg,
                                upgrade_probes,
                                np.node_id,
                                &cfg,
                                sock,
                                dst,
                                tier,
                                now,
                            )
                            .await;
                        } else {
                            // P3 PR-A — no probe target (all tiers cooling /
                            // unavailable, or one already in flight) = keep
                            // the relay; record the decision.
                            record("install_peers:upgrade", path::PathAction::Keep);
                            // …but "keep the relay" must not mean "keep the
                            // WRONG relay tier": a DERP carrier built while the
                            // pair looked both-UDP-blocked is re-graded here
                            // once srflx says otherwise.
                            self.maybe_regrade_derp(
                                np.node_id,
                                &cfg,
                                &pk,
                                wg,
                                by_node,
                                tun,
                                relay,
                                relay_bq,
                                upgrade_probes,
                                now,
                            )
                            .await;
                        }
                        continue;
                    }
                    // Pre-rc.208 destructive upgrade (break-before-make): tears the
                    // relay down first, then handshakes over the (unproven) direct
                    // path. Kept as the default until make-before-break is
                    // field-proven per-host.
                    if let (Some(ctx), Some((local_ip, dst))) = (direct_ctx, direct_dst) {
                        record(
                            "install_peers:upgrade",
                            path::PathAction::Install(DirectTier::Lan),
                        );
                        info!(peer = %np.node_id, %dst, "overlay: upgrading relay peer to direct LAN carrier");
                        wg.remove_peer(&pk).await;
                        if let Some(r) = relay.as_mut() {
                            r.forget(&np.node_id);
                        }
                        // rc.211 — a direct carrier supersedes any relay build
                        // still in flight for this peer; drop it on arrival.
                        relay_bq.invalidate(&np.node_id);
                        self.install_direct(wg, by_node, tun, ctx, np.node_id, &cfg, local_ip, dst)
                            .await;
                    } else if let (Some(ctx), Some(dst)) = (direct_ctx, phase_a_dst) {
                        record(
                            "install_peers:upgrade",
                            path::PathAction::Install(DirectTier::Public),
                        );
                        info!(peer = %np.node_id, %dst, "overlay: upgrading relay peer to direct-to-public carrier");
                        wg.remove_peer(&pk).await;
                        if let Some(r) = relay.as_mut() {
                            r.forget(&np.node_id);
                        }
                        // rc.211 — a direct carrier supersedes any relay build
                        // still in flight for this peer; drop it on arrival.
                        relay_bq.invalidate(&np.node_id);
                        self.install_public_direct(wg, by_node, tun, ctx, np.node_id, &cfg, dst)
                            .await;
                    } else if let (Some(ctx), Some(dst)) = (direct_ctx, srflx_dst) {
                        record(
                            "install_peers:upgrade",
                            path::PathAction::Install(DirectTier::Srflx),
                        );
                        info!(peer = %np.node_id, %dst, "overlay: upgrading relay peer to srflx hole-punch carrier");
                        wg.remove_peer(&pk).await;
                        if let Some(r) = relay.as_mut() {
                            r.forget(&np.node_id);
                        }
                        // rc.211 — a direct carrier supersedes any relay build
                        // still in flight for this peer; drop it on arrival.
                        relay_bq.invalidate(&np.node_id);
                        self.install_srflx_direct(wg, by_node, tun, ctx, np.node_id, &cfg, dst)
                            .await;
                    } else {
                        // P3 PR-A — nothing dialable: the relay stays. Same as
                        // the make-before-break arm above — the relay staying
                        // still leaves the DERP-vs-TURN question to re-ask.
                        record("install_peers:upgrade", path::PathAction::Keep);
                        self.maybe_regrade_derp(
                            np.node_id,
                            &cfg,
                            &pk,
                            wg,
                            by_node,
                            tun,
                            relay,
                            relay_bq,
                            upgrade_probes,
                            now,
                        )
                        .await;
                    }
                    continue;
                }
                None => {}
            }

            match &self.mode {
                CarrierMode::Direct(links) => {
                    let Some(carrier) = links.build_carrier(&cfg).await else {
                        debug!(peer = %np.node_id, "overlay: no carrier built; retry next netmap");
                        continue;
                    };
                    self.install_ready(
                        wg,
                        by_node,
                        tun,
                        ReadyLink {
                            node_id: np.node_id,
                            public_key: cfg.public_key,
                            overlay_ip: cfg.overlay_ip,
                            carrier,
                            relay_parts: None,
                            extra_permission_targets: Vec::new(),
                            supports_quic: cfg.supports_quic,
                            single_relay: None,
                            relay_kind: RelayKind::Turn,
                            subnets: cfg.subnets.clone(),
                        },
                        relay_bq,
                    )
                    .await;
                }
                CarrierMode::Relay => {
                    // Phase A2 (overlay v3) — DERP floor at birth, BEFORE any
                    // direct-tier pick: a fresh pair with nothing installed
                    // gets the derp carrier IMMEDIATELY (both ends
                    // floor-capable, mux alive), the better-tier coordination
                    // fires in the SAME pass, and the direct tiers arrive as
                    // MBB upgrade probes OVER the floor on the next walks
                    // (the relay-installed arm never inspects relay_kind).
                    // Placement is load-bearing: the fresh walk short-circuits
                    // at the first dialable direct tier — field 2026-08-17,
                    // rc.398: corplap's dead srflx punch looped 12 s deadlines
                    // forever, the relay arm was never reached, and the pair
                    // sat carrier-less. The floor must come FIRST so a wrong
                    // direct guess costs an upgrade-probe, never the carrier.
                    // A withheld floor (mux down / peer not capable) falls
                    // through to the whole ladder unchanged; DERP-strategy
                    // pairs skip the redundant TURN request.
                    // rc.412 (#24) — the gate is `is_derping`, NOT
                    // `is_tracking`. This walk only sees peers with NO
                    // installed carrier, and "carrier-less while a better
                    // tier coordinates" is the exact state the floor exists
                    // to cover — the block itself fires `coord.request(...)`
                    // right below, so floor-plus-in-flight-request is the
                    // designed combination, not a conflict. Gating on
                    // `is_tracking` instead starved the pairs that need it
                    // most: `request` for a `SingleRelay(false)` dialer just
                    // inserts into `dialing` and returns — no allocation, no
                    // wire message, nothing that can time out — so a peer
                    // whose anchor never advertises `R` stayed tracked, and
                    // therefore floor-less, forever (winhost-a's secondary org
                    // under corp VPN, 2026-08-19: four peers blocked from the
                    // moment the VPN killed their direct carriers, while the
                    // one peer on a Derp strategy stayed healthy). A DERPING
                    // peer is still excluded — its link is the same carrier
                    // over the same mux, arriving via `maybe_complete`.
                    // rc.414 (#25) — REPAIR stale floor bookkeeping instead of
                    // obeying it. `floored` asserts "the birth floor IS this
                    // peer's installed carrier", and this block is reached
                    // ONLY when nothing is installed (the `match installed`
                    // above `continue`s for every installed shape). So a
                    // `floored` entry seen HERE is stale by construction —
                    // whatever dropped the carrier failed to clear it (an
                    // `install_ready` that did not take, a teardown path that
                    // bypassed `forget`/`clear_floor`, …). Treating it as
                    // authoritative is what stranded peers permanently:
                    // rc.413's field probe on winhost-a found peers `blocked`
                    // with ZERO "floor WITHHELD" lines and 111 successful
                    // floor installs, i.e. `build_floor` was never even
                    // CALLED for them — they were skipped by this gate.
                    // Clearing lets the floor rebuild, and a rebuild that
                    // keeps failing simply retries next walk instead of
                    // giving up for the process's life.
                    if let Some(coord) = relay.as_mut()
                        && coord.clear_floor(&np.node_id)
                    {
                        warn!(
                            peer = %np.node_id,
                            "overlay relay: repaired STALE floor bookkeeping — the peer was \
                             marked floored with no installed carrier, which blocked its \
                             floor from ever rebuilding; rebuilding now"
                        );
                    }
                    // rc.415 (#25) — an in-flight TURN grant no longer blocks
                    // the floor. This was the LAST gate standing between a
                    // carrier-less peer and its floor, and the field convicted
                    // it directly: rc.414 on winhost-a + winhost-b logged
                    // `repairs=0` (so stale bookkeeping was NOT the cause) and
                    // every single withhold line read "a TURN grant is already
                    // in flight for it".
                    //
                    // Under a corp VPN that grant CHURNS — UDP allocations to
                    // the relay band time out and retry for tens of seconds at
                    // a time (winhost-a: repeated "pinned UDP TURN allocate timed
                    // out" against :3478 AND :443 before TLS:443 finally took)
                    // — so `in_flight` is occupied on essentially every walk
                    // and the peer waits out the entire churn with NO carrier.
                    // That is precisely the outage the floor exists to prevent,
                    // and precisely the pairs that need it most.
                    //
                    // Safe by the same argument as the tracking gate: this walk
                    // only ever sees carrier-less peers, and the block already
                    // fires `coord.request(...)` right below, so floor-plus-
                    // in-flight-grant is the DESIGNED combination. When the
                    // grant lands, `install_ready` replaces the floor
                    // MBB-style and the TURN link clears the floor bookkeeping.
                    // rc.416 (#25) — and NOT gated on `is_derping` either.
                    // That exclusion (rc.412) rested on "a derping peer's link
                    // is the same carrier over the same mux, arriving via
                    // `maybe_complete`, so flooring it is pure duplication" —
                    // true ONLY if the coordination actually completes. It has
                    // the identical flaw as the `is_tracking` gate it replaced:
                    // `derping` has NO timeout. `request` for a Derp strategy
                    // just does `derping.insert(...)` and returns, and the
                    // entry is cleared only by `maybe_complete`/`forget`. When
                    // the trickle that would drive `maybe_complete` never
                    // arrives, the peer starves — field: winhost-a → devbox sat
                    // blocked for 70+ min on rc.415 while this very branch
                    // logged "coordinating a DERP link of its own" every 5 min.
                    //
                    // Since the floor IS that DERP link, building it directly
                    // is not duplication — it is the same carrier, delivered
                    // now instead of never. `build_floor` clears the `derping`
                    // entry it satisfies.
                    if let Some(coord) = relay.as_mut()
                        && let Some(link) = coord.build_floor(np.node_id, &cfg)
                    {
                        let t0 = Instant::now();
                        self.install_ready(wg, by_node, tun, link, relay_bq).await;
                        warn_if_slow("install_ready(floor)", t0);
                        if !coord.strategy_is_derp(&np.node_id, &cfg) {
                            coord.request(np.node_id, cfg.clone()).await;
                        }
                        // Birth probe — the `continue` below skips the fresh
                        // path's LAN probe-first, which left a LAN pair on the
                        // floor until the next re-upgrade walk (~30 s, F0).
                        // Probe off the floor now: make-before-break, so a
                        // dead LAN candidate costs only the probe deadline. A
                        // server DERP pin still wins, as it does on the walk.
                        if make_before_break
                            && crate::overlay::direct::birth_lan_probe_enabled()
                            && !wg.has_direct_probe(&cfg.public_key)
                            && !self
                                .shadow(|s| s.mon.forced_derp_active(&np.node_id, now))
                                .unwrap_or(false)
                            && let (Some(ctx), Some((local_ip, dst))) = (direct_ctx, direct_dst)
                            && let Some(sock) = lan_egress_socket(ctx, local_ip, dst).await
                        {
                            record("install_peers:birth", path::PathAction::Probe(DirectTier::Lan));
                            self.start_upgrade_probe(
                                wg,
                                upgrade_probes,
                                np.node_id,
                                &cfg,
                                sock,
                                dst,
                                DirectTier::Lan,
                                now,
                            )
                            .await;
                        }
                        continue;
                    }
                    // rc.416 (#25) — reaching here means `build_floor` itself
                    // refused, and it reports its own reason (rc.413). Both
                    // pre-gates are gone now: the in-flight TURN grant
                    // (rc.415) and the derping exclusion (rc.416), each
                    // convicted in the field by the line it was made to emit.
                    // P9 — fresh-install LAN is PROBE-FIRST under make-before-
                    // break: a same-/24 match is only a HINT the peer is on
                    // this LAN. Two sites on a vendor-default subnet
                    // (192.168.68.0/24 Deco, 192.168.1.0/24 …) false-match, and
                    // the "same subnet" dial is then dead air — field
                    // 2026-07-28: corp peers advertised another city's
                    // 192.168.68.x and every fresh install burned the 12 s LAN
                    // deadline with NO carrier, repeatedly. So: shadow-probe
                    // the LAN candidate and keep walking the fallback chain
                    // (public → srflx → relay) for the working carrier in the
                    // SAME pass; `sweep_upgrade_probes` cuts over the moment
                    // the probe latches (ms on a genuine LAN) and books CC1 if
                    // it never does. The destructive install remains when
                    // nothing else is dialable (airgapped pure-LAN mesh — a
                    // wrong guess costs nothing there) and when MBB is
                    // env-disabled.
                    let lan_probe_first = make_before_break
                        && direct_dst.is_some()
                        && (phase_a_dst.is_some() || srflx_dst.is_some() || relay.is_some());
                    let mut lan_probing = false;
                    if lan_probe_first {
                        if wg.has_direct_probe(&cfg.public_key) {
                            // In flight from an earlier pass — walk the
                            // fallback chain quietly (the monitor holds Keep
                            // while a probe runs; no compare on this pass).
                            lan_probing = true;
                        } else if let (Some(ctx), Some((local_ip, dst))) = (direct_ctx, direct_dst)
                            && let Some(sock) = ctx
                                .socks
                                .iter()
                                .find(|(ip, _)| *ip == local_ip)
                                .map(|(_, s)| s.clone())
                        {
                            record(
                                "install_peers:fresh",
                                path::PathAction::Probe(DirectTier::Lan),
                            );
                            self.start_upgrade_probe(
                                wg,
                                upgrade_probes,
                                np.node_id,
                                &cfg,
                                sock,
                                dst,
                                DirectTier::Lan,
                                now,
                            )
                            .await;
                            lan_probing = true;
                        }
                    }
                    if !lan_probing
                        && let (Some(ctx), Some((local_ip, dst))) = (direct_ctx, direct_dst)
                    {
                        record(
                            "install_peers:fresh",
                            path::PathAction::Install(DirectTier::Lan),
                        );
                        // Same-subnet → LAN direct, skip the relay. Forget any
                        // pending relay request so a late grant can't later
                        // clobber the direct carrier.
                        if let Some(r) = relay.as_mut() {
                            r.forget(&np.node_id);
                        }
                        // rc.211 — a direct carrier supersedes any relay build
                        // still in flight for this peer; drop it on arrival.
                        relay_bq.invalidate(&np.node_id);
                        self.install_direct(wg, by_node, tun, ctx, np.node_id, &cfg, local_ip, dst)
                            .await;
                    } else if let (Some(ctx), Some(dst)) = (direct_ctx, phase_a_dst) {
                        if !lan_probing {
                            record(
                                "install_peers:fresh",
                                path::PathAction::Install(DirectTier::Public),
                            );
                        }
                        // Phase A — peer's NIC is public: dial it directly, skip
                        // the relay. Same forget-the-pending-relay guard.
                        if let Some(r) = relay.as_mut() {
                            r.forget(&np.node_id);
                        }
                        // rc.211 — a direct carrier supersedes any relay build
                        // still in flight for this peer; drop it on arrival.
                        relay_bq.invalidate(&np.node_id);
                        self.install_public_direct(wg, by_node, tun, ctx, np.node_id, &cfg, dst)
                            .await;
                    } else if let (Some(ctx), Some(dst)) = (direct_ctx, srflx_dst) {
                        if !lan_probing {
                            record(
                                "install_peers:fresh",
                                path::PathAction::Install(DirectTier::Srflx),
                            );
                        }
                        // Phase C — both NAT'd: hole-punch the peer's srflx from
                        // the punch socket, skip the relay.
                        if let Some(r) = relay.as_mut() {
                            r.forget(&np.node_id);
                        }
                        // rc.211 — a direct carrier supersedes any relay build
                        // still in flight for this peer; drop it on arrival.
                        relay_bq.invalidate(&np.node_id);
                        self.install_srflx_direct(wg, by_node, tun, ctx, np.node_id, &cfg, dst)
                            .await;
                    } else if let Some(coord) = relay.as_mut() {
                        // P3 PR-A — every sub-case below (mid-build, complete,
                        // request, tracking) is the same decision: the relay
                        // tier carries this peer.
                        if !lan_probing {
                            record("install_peers:fresh", path::PathAction::Relay);
                        }
                        // rc.211 — a carrier for this peer is mid-BUILD off-loop:
                        // post-`try_build` the coordinator no longer tracks it, so
                        // without this guard `!is_tracking` would re-`request` a
                        // DUPLICATE coordination during the 8 s QUIC window.
                        if relay_bq.in_flight.contains_key(&np.node_id) {
                            continue;
                        }
                        if let Some(link) = coord.maybe_complete(np.node_id, &cfg) {
                            let t0 = Instant::now();
                            self.install_ready(wg, by_node, tun, link, relay_bq).await;
                            warn_if_slow("install_ready(maybe_complete)", t0);
                        } else if !coord.is_tracking(&np.node_id) {
                            // Both ends pick the same coturn worker from the
                            // server's symmetric pair_key (in the grant), so no
                            // initiator/responder asymmetry is needed here — see
                            // relay_link.rs. The WG handshake still tie-breaks
                            // the dialer by pubkey in `install_ready`.
                            coord.request(np.node_id, cfg).await;
                        }
                    }
                }
            }
        }
    }

    /// rc.208 make-before-break — start a shadow direct-carrier PROBE for a peer
    /// currently on relay: register the demux + hand the candidate carrier to
    /// [`WgDevice::start_direct_probe`] (its own `Tunn`, NOT in the routing map),
    /// and record the [`UpgradeProbe`] metadata the promote/expire sweep reads.
    /// Does NOT touch `by_node` or the relay allocation — routing stays on relay
    /// until [`Self::sweep_upgrade_probes`] promotes this on a latched handshake.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn start_upgrade_probe(
        &self,
        wg: &mut WgDevice,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
        node_id: ObjectId,
        cfg: &PeerConfig,
        sock: Arc<UdpSocket>,
        dst: std::net::SocketAddr,
        tier: DirectTier,
        now: Instant,
    ) {
        // P3 PR-A — mirror the probe start (per-peer serialization + the
        // global cap + the F2 LAN attempt marker live in the monitor).
        self.shadow(|s| s.mon.on_probe_started(&node_id, tier, now));
        wg.ensure_direct_demux(sock.clone());
        // Outbound upgrade: WE dial the peer, so initiate the handshake.
        // rc.276 diagnostics — capture before `sock` moves into the device.
        let probe_local = sock.local_addr().ok();
        wg.start_direct_probe(sock, cfg.public_key, cfg.overlay_ip, dst, true)
            .await;
        upgrade_probes.insert(
            node_id,
            UpgradeProbe {
                pubkey: cfg.public_key,
                overlay_ip: cfg.overlay_ip,
                dst,
                tier,
                since: now,
                initiated: true,
                local: probe_local,
            },
        );
        info!(
            peer = %node_id, overlay_ip = %cfg.overlay_ip, %dst, ?tier,
            "overlay: make-before-break — probing direct upgrade (relay held; cuts over only if the probe handshakes)"
        );
    }

    /// rc.208 make-before-break — drive in-flight upgrade probes each fallback
    /// tick. For each probe: PROMOTE it (swap the direct carrier in, drop the
    /// relay, retag `by_node` as direct, clear the tier's strikes) the moment its
    /// handshake latches; or, past the tier's [`DirectTier::handshake_deadline`],
    /// DROP it (keep the relay, book a tier failure — CC1, like the health
    /// sweep's fallback). The active carrier never stalls either way. No-op when
    /// no probes are in flight.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn sweep_upgrade_probes(
        &self,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        relay: &mut Option<RelayCoordinator>,
        tun: &Arc<dyn TunIo>,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
        relay_bq: &mut RelayBuildQueue,
    ) {
        if upgrade_probes.is_empty() {
            return;
        }
        let now = Instant::now();
        // P3 PR-A — same env read the legacy escalation table uses.
        let mbb = crate::overlay::direct::make_before_break_enabled();
        let mut settled: Vec<ObjectId> = Vec::new();
        for (nid, p) in upgrade_probes.iter() {
            if self
                .path_trial_managed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(nid)
            {
                continue;
            }
            // P2 — the promote/expire/wait decision is the pure
            // `lifecycle::probe_tick`; this loop executes the disposition.
            let verdict = probe_tick(
                wg.probe_handshake_done(&p.pubkey) == Some(true),
                now.duration_since(p.since),
                p.tier,
                p.initiated,
            );
            if verdict == ProbeVerdict::Promote {
                // P3 PR-B — read the probe's REAL latch latency (recv-path
                // `handshake_at` stamp minus the probe start) BEFORE the
                // promote moves the probe out of the probes map.
                let latency_ms = wg
                    .probe_handshake_latency_ms(&p.pubkey, p.since)
                    .map(|ms| ms as f64);
                // Bidirectional direct proven → cut over. `promote_direct_probe`
                // drops the old relay carrier; forget its coturn allocation and
                // retag `by_node` as the direct tier.
                if wg.promote_direct_probe(&p.pubkey) {
                    // P3 PR-A — the latch is the tier's proof: Q credit +
                    // strike clear in the monitor (≡ the `*_fails.remove`
                    // below), and any recent monitor refusal of this tier
                    // grades as harmful.
                    self.shadow(|s| {
                        s.mon.on_probe_result(
                            nid,
                            p.tier,
                            path::ProbeOutcome::Latched { latency_ms },
                            mbb,
                            now,
                        );
                        s.establishment(nid, p.tier, now);
                    });
                    if let Some(r) = relay.as_mut() {
                        r.forget(nid);
                    }
                    // P9 — a fresh-install LAN probe can latch while the
                    // fallback relay build is still in flight; drop that build
                    // so its late completion can't clobber the direct carrier
                    // (same rc.211 rule as the destructive installs).
                    relay_bq.invalidate(nid);
                    let off_link = matches!(p.tier, DirectTier::Public | DirectTier::Srflx);
                    by_node.insert(
                        *nid,
                        Installed {
                            initiated: p.initiated,
                            hs_done: true, // promote fires on the latched handshake
                            carrier_local: p.local,
                            carrier_dst: Some(p.dst),
                            public_direct_dst: off_link.then_some(p.dst),
                            ..Installed::base(p.pubkey, p.overlay_ip, p.tier, now)
                        },
                    );
                    tun.add_peer_route(p.overlay_ip).await.ok();
                    // PR-E — the latch already cleared the tier's strikes in
                    // the monitor (`on_probe_result(Latched)`, fed above).
                    // `probe_ms` is how long THIS probe took to latch; paired
                    // with the `waited_ms` on each preceding failure it gives
                    // total time-to-converge without timestamp arithmetic —
                    // the metric any cadence tuning has to move.
                    info!(
                        peer = %nid, overlay_ip = %p.overlay_ip, tier = ?p.tier,
                        probe_ms = now.saturating_duration_since(p.since).as_millis() as u64,
                        "overlay: make-before-break — direct carrier promoted (relay held throughout; zero stall)"
                    );
                } else {
                    // P3 PR-A — probe slot vanished under us (abnormal): free
                    // the monitor's mirror without booking a verdict.
                    self.shadow(|s| s.mon.on_probe_aborted(nid));
                }
                settled.push(*nid);
            } else if verdict == ProbeVerdict::Expire {
                // Probe never latched within the deadline → direct unreachable.
                // Drop it, KEEP the relay, book the failure on the tier (CC1 —
                // mirrors `sweep_carrier_health`'s direct→relay bookkeeping so a
                // repeatedly-failing tier still escalates to its sticky deny and
                // stops re-probing).
                //
                // P3 PR-A — the expiry books the monitor's strike + penalty (≡
                // the cooldown insert below); F1: NO quality event (the
                // penalty already encodes the failure). Tripwire: the tier
                // must be ineligible immediately after.
                self.shadow(|s| {
                    s.mon
                        .on_probe_result(nid, p.tier, path::ProbeOutcome::Expired, mbb, now);
                    s.assert_ineligible(nid, p.tier, now);
                });
                // Read the probe's counters BEFORE dropping it: this is the
                // only moment the answer exists.
                //
                // `saw_inbound` splits a failure into the two cases that imply
                // DIFFERENT fixes, which the bare "did not handshake" line
                // could not distinguish:
                //   false ⇒ nothing came back at all — the two ends' probe
                //           windows are not aligned (a cadence/phase problem);
                //   true  ⇒ the far end answered but no session latched — the
                //           handshake deadline is too tight for this path.
                // Field 2026-08-13: winhost-a took 4 attempts / ~4.7 min to
                // promote a 4 ms LAN path and the log could not say which.
                let saw_inbound = wg.probe_saw_inbound(&p.pubkey);
                let waited_ms = now.saturating_duration_since(p.since).as_millis() as u64;
                wg.drop_direct_probe(&p.pubkey).await;
                let tier_name = match p.tier {
                    DirectTier::Srflx => "srflx",
                    DirectTier::Public => "public",
                    _ => "LAN",
                };
                info!(
                    peer = %nid, tier = tier_name, dst = %p.dst, waited_ms, saw_inbound,
                    "overlay: make-before-break — direct probe did not handshake within deadline; kept relay (no stall)"
                );
                settled.push(*nid);
            }
        }
        for nid in settled {
            upgrade_probes.remove(&nid);
        }
    }

    /// rc.134 — install a peer over the SHARED direct-LAN socket (demuxed by
    /// source address, so any number of same-subnet peers coexist — no more
    /// "one direct peer" cap). Both ends initiate (bilateral hole-punch,
    /// rc.133). Adds the `/32` route + records it as `direct` in `by_node`.
    #[allow(clippy::too_many_arguments)]
    /// rc.134 — install a peer over the shared, interface-bound direct-LAN
    /// socket (source-demuxed, so any number of same-subnet peers coexist).
    /// The egress socket is chosen by [`lan_egress_socket`] (bind-by-route when
    /// enabled). Both ends initiate (bilateral hole-punch); records the `/32`
    /// route + `by_node` as `direct` / `Lan`.
    pub(super) async fn install_direct(
        &self,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        tun: &Arc<dyn TunIo>,
        ctx: &DirectCtx,
        node_id: ObjectId,
        cfg: &PeerConfig,
        local_ip: Ipv4Addr,
        dst: std::net::SocketAddr,
    ) {
        // Use the socket bound to the interface that shares the peer's subnet
        // (rc.143) so send/receive stay on the right NIC past a full-tunnel VPN.
        // With `OVERLAY_BIND_BY_ROUTE` on, `lan_egress_socket` instead consults
        // the OS route table per-destination and re-pins the socket fresh.
        let Some(sock) = lan_egress_socket(ctx, local_ip, dst).await else {
            warn!(peer = %node_id, %local_ip, "overlay: no socket bound for the matching LAN interface; skipping direct");
            return;
        };
        // P3 PR-A — record the install (switch time + the F2 LAN marker).
        self.shadow(|s| {
            s.mon
                .on_installed(&node_id, DirectTier::Lan, Instant::now())
        });
        wg.ensure_direct_demux(sock.clone());
        wg.add_direct_peer(sock.clone(), cfg.public_key, cfg.overlay_ip, dst, true)
            .await;
        by_node.insert(
            node_id,
            Installed {
                initiated: true,
                carrier_local: sock.local_addr().ok(),
                carrier_dst: Some(dst),
                ..Installed::base(
                    cfg.public_key,
                    cfg.overlay_ip,
                    DirectTier::Lan,
                    Instant::now(),
                )
            },
        );
        if let Err(e) = tun.add_peer_route(cfg.overlay_ip).await {
            debug!(peer = %node_id, %e, "overlay: /32 peer route not installed (ok on clean hosts)");
        }
        // Phase 1 — if this peer is an approved subnet router, route its CIDRs
        // to it (router allowed_ips + OS route).
        self.install_subnets(wg, tun, node_id, cfg.public_key, &cfg.subnets)
            .await;
        info!(peer = %node_id, overlay_ip = %cfg.overlay_ip, %dst, "overlay: direct LAN carrier (same subnet) — skipping relay");
    }

    /// Phase A — install a peer over the **direct-to-public** carrier: dial its
    /// public NIC endpoint over the shared `public_sock` (a `0.0.0.0` socket, so
    /// the OS picks the egress NIC per-destination), demuxed by source like any
    /// direct peer. Bilateral init (a direct carrier initiates on both ends,
    /// `install_ready` semantics — the peer either dials us back symmetrically
    /// or, if NAT'd, accepts our dial and replies over the mapping our INIT
    /// opened). Records `public_direct_dst` so the health sweep tiers it and the
    /// exit-node exemption pins its IP (never self-wedge).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn install_public_direct(
        &self,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        tun: &Arc<dyn TunIo>,
        ctx: &DirectCtx,
        node_id: ObjectId,
        cfg: &PeerConfig,
        dst: std::net::SocketAddr,
    ) {
        let Some(sock) = ctx.public_sock.clone() else {
            warn!(peer = %node_id, "overlay: public-direct requested but no egress socket; skipping");
            return;
        };
        // P3 PR-A — record the install (switch time).
        self.shadow(|s| {
            s.mon
                .on_installed(&node_id, DirectTier::Public, Instant::now())
        });
        wg.ensure_direct_demux(sock.clone());
        // rc.276 diagnostics — capture before `sock` moves into the device.
        let carrier_local = sock.local_addr().ok();
        wg.add_direct_peer(sock, cfg.public_key, cfg.overlay_ip, dst, true)
            .await;
        by_node.insert(
            node_id,
            Installed {
                initiated: true,
                carrier_local,
                carrier_dst: Some(dst),
                public_direct_dst: Some(dst),
                ..Installed::base(
                    cfg.public_key,
                    cfg.overlay_ip,
                    DirectTier::Public,
                    Instant::now(),
                )
            },
        );
        if let Err(e) = tun.add_peer_route(cfg.overlay_ip).await {
            debug!(peer = %node_id, %e, "overlay: /32 peer route not installed (ok on clean hosts)");
        }
        self.install_subnets(wg, tun, node_id, cfg.public_key, &cfg.subnets)
            .await;
        info!(peer = %node_id, overlay_ip = %cfg.overlay_ip, %dst, "overlay: direct-to-public carrier (NAT-traversal Phase A) — skipping relay");
    }

    /// Phase C — install a peer over the **srflx hole-punch** carrier: dial its
    /// STUN-learned public mapping from the PUNCH socket (`ctx.punch`, the
    /// interface socket that owns our own first advertised srflx), so our
    /// outbound WG INITs ride the same NAT mapping we advertised — opening our
    /// NAT's filter toward the peer's srflx while the peer's bilateral INITs open
    /// theirs toward ours (the mutual hole-punch). This is the crux difference
    /// from [`install_public_direct`], which dials via the arbitrary-egress
    /// `public_sock`: a punch REQUIRES the mapping-owning socket. Records
    /// `public_direct_dst` (off-link ⇒ exit-node exemption) and `tier = Srflx`
    /// (its own cooldown + the tight handshake deadline). No punch socket (srflx
    /// off / none gathered) ⇒ skip, and the caller falls through to relay.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn install_srflx_direct(
        &self,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        tun: &Arc<dyn TunIo>,
        ctx: &DirectCtx,
        node_id: ObjectId,
        cfg: &PeerConfig,
        dst: std::net::SocketAddr,
    ) {
        let Some((_, sock)) = ctx.punch.clone() else {
            warn!(peer = %node_id, "overlay: srflx punch requested but no punch socket; skipping");
            return;
        };
        // P3 PR-A — record the install (switch time).
        self.shadow(|s| {
            s.mon
                .on_installed(&node_id, DirectTier::Srflx, Instant::now())
        });
        wg.ensure_direct_demux(sock.clone());
        // rc.276 diagnostics — capture before `sock` moves into the device.
        let carrier_local = sock.local_addr().ok();
        wg.add_direct_peer(sock, cfg.public_key, cfg.overlay_ip, dst, true)
            .await;
        by_node.insert(
            node_id,
            Installed {
                initiated: true,
                carrier_local,
                carrier_dst: Some(dst),
                public_direct_dst: Some(dst),
                ..Installed::base(
                    cfg.public_key,
                    cfg.overlay_ip,
                    DirectTier::Srflx,
                    Instant::now(),
                )
            },
        );
        if let Err(e) = tun.add_peer_route(cfg.overlay_ip).await {
            debug!(peer = %node_id, %e, "overlay: /32 peer route not installed (ok on clean hosts)");
        }
        self.install_subnets(wg, tun, node_id, cfg.public_key, &cfg.subnets)
            .await;
        info!(peer = %node_id, overlay_ip = %cfg.overlay_ip, %dst, "overlay: srflx hole-punch carrier (NAT-traversal Phase C) — skipping relay");
    }
    /// Install a ready carrier as a WG peer, add its `/32` route, and record
    /// it (pubkey + IP) for later removal.
    pub(super) async fn install_ready(
        &self,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        tun: &Arc<dyn TunIo>,
        link: ReadyLink,
        relay_bq: &mut RelayBuildQueue,
    ) {
        // P3 PR-A — a relay install is a switch too (production mode only:
        // the Direct/test carrier mode funnels loopback links through here,
        // which aren't relay-tier decisions).
        if matches!(self.mode, CarrierMode::Relay) {
            self.shadow(|s| {
                s.mon
                    .on_installed(&link.node_id, DirectTier::Relay, Instant::now())
            });
        }
        // Handshake direction. RELAY carriers use a deterministic single
        // initiator (the lexicographically smaller pubkey dials; both ends
        // compute it identically) — fine because the relay forwards both ways.
        //
        // rc.133 — DIRECT carriers need BOTH ends to initiate (bilateral
        // hole-punch). A direct WG init is an UNSOLICITED inbound UDP on the
        // responder's PHYSICAL interface, which default Windows Firewall drops
        // (field: two same-LAN hosts, direct carrier built but
        // HANDSHAKE(REKEY_TIMEOUT) forever). When both ends initiate, each
        // side's outbound init opens a stateful firewall hole for the other's
        // inbound, so the handshake completes. The relay path never hit this
        // because its ciphertext rides the agent's OWN outbound TURN
        // connection (already a stateful hole).
        // Optional QUIC-over-TURN upgrade of a relay carrier (opt-in, default
        // OFF via `overlay_quic_enabled`). QUIC's congestion control smooths the
        // relay's buffer-bloat latency spikes and its keepalive holds the TURN
        // permission fresh. On ANY handshake failure/timeout we fall back to the
        // already-built raw relay carrier, so the upgrade can only improve —
        // never break — the link.
        //
        // rc.199 — mutual coturn permission bootstrap for EVERY relay carrier
        // (raw, QUIC, or QUIC-fallback-to-raw). coturn only relays a peer's
        // datagrams to this allocation once it holds a *permission* for that
        // peer's relayed address, and a permission is opened by SENDING to it
        // (the webrtc-rs `turn` client lazily CreatePermission's the dst on the
        // first `send_to`). The relay carrier uses a single WG initiator (the
        // lexicographically-smaller pubkey), so without this the RESPONDER never
        // sends first → its allocation never opens a permission for the initiator
        // → coturn silently drops the WG handshake INIT → HANDSHAKE(REKEY_TIMEOUT)
        // forever. This is exactly why the cross-NAT relay never completed in the
        // field (P5 exit-node bring-up 2026-07-19: relay LINK ready + peer
        // installed, yet the handshake timed out for every peer); the DIRECT path
        // always worked precisely because it needs no coturn permission. Both
        // ends build a carrier and send this stray `\x00`, so BOTH permissions are
        // open before the handshake. `quic_relay` already does its own `\x00`
        // internally (wg.rs); this covers the raw + QUIC-fallback paths, which
        // previously shipped WITHOUT it (the wg.rs relay tests only passed because
        // they do the bootstrap by hand). The 1-byte datagram is below WG's
        // minimum message size, so boringtun ignores it.
        if let Some((conn, dst)) = &link.relay_parts {
            // W6 phase-2 — visible + measured (was `let _ =`): the send blocks
            // on CreatePermission, so its latency is the permission RTT and
            // its error means coturn drops this peer's inbound wholesale.
            let _ = crate::overlay::wg::assert_relay_permission(conn, *dst, "install").await;
        }
        // Phase D — a single-relay link FORCES the QUIC carrier, ignoring the
        // `OVERLAY_QUIC` opt-in: a raw `Carrier::Relay` discards the recv source
        // (wg.rs recv), so the anchor would reply to the dialer's ADVERTISED
        // srflx port — wrong under a symmetric NAT (per-destination mapping) —
        // and the handshake dies. Only quinn's server consumes the observed
        // path. Symmetric on both ends: any build that advertises
        // `supports_relay_single` carries this rule, so the pair can't split
        // QUIC/raw (see `ReadyLink::single_relay`).
        //
        // A DERP link (`relay_kind == Derp`) is explicitly EXCLUDED from QUIC:
        // it's raw WG over the pubkey-addressed WS relay, and the pubkey pinning
        // makes the raw recv-source discard correct. QUIC-over-DERP would be
        // QUIC-over-TCP (double-reliable, HOL-on-HOL) and is untested — v1 stays
        // raw (A2). The gate below is belt-and-suspenders: a DERP link already
        // sets `single_relay: None` + `supports_quic: false`, but the explicit
        // `Turn` check keeps a future field-add from silently upgrading it.
        let want_quic = link.relay_parts.is_some()
            && link.relay_kind == RelayKind::Turn
            && (link.single_relay.is_some() || (overlay_quic_enabled() && link.supports_quic));
        if want_quic {
            // rc.211 — the QUIC-over-TURN rendezvous (up to QUIC_BUILD_TIMEOUT
            // = 8 s) runs OFF-LOOP: awaiting it here head-of-line-blocked the
            // `tun.read_packet()` arm for its full duration — the field-proven
            // 1–2 s overlay RTT plateaus (S1 watchdog: five 8.06 s stalls named
            // `install_ready(quic-build)` in one 150 s run on a churny host).
            // The spawned build sends its result to the `built_rx` select! arm,
            // which commits via `install_built` (µs). `quic_relay` sends the
            // `\x00` permission bootstrap itself; on failure the builder sends
            // one for the raw fallback (mirrors the pre-split inline probe).
            //
            // QUIC role. For a SINGLE-RELAY link the ANCHOR must serve — its
            // allocation is the rendezvous, and only the server-on-the-
            // allocation replies to coturn's observed sources. With UDP-aware
            // anchor selection the anchor may hold the LARGER pubkey, so the
            // pubkey rule would invert the roles and deadlock (the anchor
            // would QUIC-connect toward the dialer's srflx, which that
            // socket's NAT filter drops). Both-allocate keeps the pubkey rule
            // (deterministic, both ends agree; either allocation can serve).
            let (conn, dst) = link.relay_parts.clone().unwrap();
            let am_server = match link.single_relay {
                Some(anchor) => anchor,
                None => self.keypair.public.to_bytes() < link.public_key,
            };
            let min_datagram = self.mtu as usize + WG_OVERHEAD;
            let epoch = relay_bq.stamp(link.node_id);
            let tx = relay_bq.tx.clone();
            // W6 phase 3 — RAW-FIRST (default): commit the already-built raw
            // carrier NOW and run the rendezvous in the background with the
            // 90 s window. Field 2026-08-15 (winhost-a on VPN): health-sweep
            // REBUILDS are not netmap-synchronized, so two independent 8 s
            // windows on ~60 s retry clocks overlapped ~11% of the time
            // (22/201 carrier-ups) — and the pair sat DARK for the whole
            // window on every dead-carrier rebuild. Raw-first removes the
            // dark window; the upgrade commits through the normal BuiltRelay
            // path, whose epoch guard drops it if a direct promotion (or any
            // newer build) landed meanwhile.
            let raw_first = super::super::direct::quic_async_enabled();
            let bg_link = link.clone();
            if raw_first {
                self.install_built(wg, by_node, tun, link, None).await;
            }
            tokio::spawn(async move {
                let link = bg_link;
                // W6 phase-2 — the ANCHOR permits EVERY distinct public srflx
                // IP the dialer advertises (permissions are IP-scoped): a
                // multi-homed dialer's raw dial socket picks its source by
                // route, and a permission for only the FIRST advertised IP
                // silently drops the whole dial at coturn. Off-loop by
                // construction (this spawn), so the permission RTTs cannot
                // stall the runtime.
                for t in &link.extra_permission_targets {
                    let _ = crate::overlay::wg::assert_relay_permission(&conn, *t, "anchor-extra")
                        .await;
                }
                let quic = if raw_first {
                    // The SERVER holds one continuous accept for the whole
                    // window; the CLIENT retries connect attempts inside it,
                    // so any single overlap suffices.
                    let deadline = tokio::time::Instant::now() + QUIC_UPGRADE_DEADLINE;
                    let mut last_err: Option<anyhow::Error> = None;
                    loop {
                        let window = if am_server {
                            deadline.saturating_duration_since(tokio::time::Instant::now())
                        } else {
                            QUIC_BUILD_TIMEOUT
                        };
                        if window.is_zero() {
                            break None;
                        }
                        match Carrier::quic_relay(
                            conn.clone(),
                            dst,
                            am_server,
                            min_datagram,
                            window,
                        )
                        .await
                        {
                            Ok(q) => {
                                info!(peer = %link.node_id, %dst, am_server,
                                      "overlay: QUIC-over-TURN carrier up (background upgrade)");
                                break Some(q);
                            }
                            Err(e) => last_err = Some(e),
                        }
                        if tokio::time::Instant::now() + QUIC_BUILD_TIMEOUT + QUIC_UPGRADE_RETRY_GAP
                            > deadline
                        {
                            break None;
                        }
                        tokio::time::sleep(QUIC_UPGRADE_RETRY_GAP).await;
                    }
                    .or_else(|| {
                        // Raw is ALREADY live — this is a missed upgrade, not
                        // a fallback: one line at the end of the window, with
                        // the last attempt's rendezvous diagnostics.
                        info!(peer = %link.node_id, single_relay = ?link.single_relay, am_server,
                              e = %last_err.map(|e| e.to_string()).unwrap_or_default(),
                              "overlay: QUIC upgrade did not rendezvous within the window — staying on raw relay");
                        None
                    })
                } else {
                    // Legacy (OVERLAY_QUIC_ASYNC=off): one blocking-window
                    // attempt, raw committed only afterwards.
                    match Carrier::quic_relay(
                        conn.clone(),
                        dst,
                        am_server,
                        min_datagram,
                        QUIC_BUILD_TIMEOUT,
                    )
                    .await
                    {
                        Ok(q) => {
                            info!(peer = %link.node_id, %dst, am_server, "overlay: QUIC-over-TURN carrier up");
                            Some(q)
                        }
                        Err(e) => {
                            // For a single-relay link the raw fallback only carries
                            // for cone-ish dialers (port-preserving mapping); a
                            // symmetric dialer stays dark until the health sweep
                            // re-coordinates.
                            warn!(peer = %link.node_id, %e, single_relay = ?link.single_relay, am_server,
                                  "overlay: QUIC carrier build failed; using raw relay");
                            // Permission bootstrap for the raw fallback (the QUIC
                            // attempt sent its own, but re-assert — it's 1 byte).
                            // W6 phase-2: measured — if THIS one succeeds after the
                            // build's failed, the failed permission explains rx=0.
                            let _ = crate::overlay::wg::assert_relay_permission(
                                &conn,
                                dst,
                                "raw-fallback",
                            )
                            .await;
                            None
                        }
                    }
                };
                // Raw-first: only a SUCCESSFUL upgrade needs a commit — the
                // raw carrier is already installed, and re-sending it would
                // re-install (re-handshake) the peer for nothing.
                if raw_first && quic.is_none() {
                    return;
                }
                // Receiver dropped ⇒ runtime exited; the build is moot.
                let _ = tx.send(BuiltRelay { epoch, link, quic }).await;
            });
            return;
        }
        self.install_built(wg, by_node, tun, link, None).await;
    }

    /// #27 — act on one unroutable inbound `/derp` frame: FOLLOW that peer onto
    /// DERP, because a peer only relays to us once it has demoted, so we are
    /// holding a carrier it has abandoned. Returns `true` when a carrier was
    /// actually installed (the caller then re-reconciles + republishes).
    ///
    /// Extracted from the select arm so the decision is testable: the arm is
    /// glue, and every gate below is a rule.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn demote_follow(
        &self,
        pk: [u8; 32],
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        relay: &mut Option<RelayCoordinator>,
        tun: &Arc<dyn TunIo>,
        current_peers: &HashMap<ObjectId, NetmapPeer>,
        relay_bq: &mut RelayBuildQueue,
        cooldown: &mut HashMap<ObjectId, Instant>,
    ) -> bool {
        // Resolve against the CURRENT netmap. An unknown pubkey is ignored
        // outright, so this can never act on a node we don't already carry —
        // the first and cheapest bound on the signal.
        let Some((nid, cfg)) = current_peers.iter().find_map(|(nid, np)| {
            peer_config_from_netmap(np)
                .filter(|c| c.public_key == pk)
                .map(|c| (*nid, c))
        }) else {
            debug!(
                "overlay relay: unroutable /derp frame from a pubkey not in our netmap — ignored"
            );
            return false;
        };
        // ORG has an explicit fresh active-floor protocol. A pk-only mux
        // notice cannot distinguish old ciphertext from current peer intent.
        if by_node.get(&nid).is_some_and(|e| e.relay_kind == Some(RelayKind::Org)) { return false; }
        // #34 — a carrier we JUST promoted is not evidence of disagreement.
        //
        // The peer has to complete its own probe → latch → cutover, which was
        // measured at 4.2-7.4 s on a healthy LAN. Until it does, it is still
        // sending over the relay, and those frames are exactly what this
        // handler reads as "the peer relays instead". Caught live 2026-08-26:
        //
        //   22:59:01  accepted inbound direct handshake as a PROBE
        //   22:59:06  direct carrier PROMOTED (relay held throughout)
        //   22:59:06  peer is relaying to us over /derp — following it (demote-follow)
        //
        // Promote and follow in the SAME SECOND, on a pair whose peer had just
        // INITIATED the direct handshake — i.e. a peer that demonstrably wanted
        // direct. Every such round also books a `relayed_instead` strike, and
        // #31 escalates the hold-down 3→6→12→15 min, so the pair ends up
        // pinned to a relay for a quarter of an hour by its own convergence.
        //
        // A promotion is therefore given a grace period: comfortably longer
        // than the observed latch, short enough that a peer which genuinely
        // stays on the relay is still followed within a sweep or two.
        if by_node
            .get(&nid)
            .is_some_and(|e| e.is_direct && e.since.elapsed() < PROMOTE_FOLLOW_GRACE)
        {
            debug!(
                peer = %nid,
                "overlay relay: /derp frame within the promote grace — the peer is still \
                 cutting over, not disagreeing"
            );
            return false;
        }
        // Already on DERP ⇒ nothing to follow. This is the ordinary shape of a
        // repeat notice: the peer keeps relaying until we converge, and frames
        // already in flight when we flipped still arrive.
        if by_node
            .get(&nid)
            .is_some_and(|e| e.relay_kind == Some(crate::overlay::relay_link::RelayKind::Derp))
        {
            return false;
        }
        let now = Instant::now();
        if cooldown.get(&nid).is_some_and(|&t| now < t) {
            return false;
        }
        let Some(coord) = relay.as_mut() else {
            return false;
        };
        cooldown.insert(nid, now + DERP_FOLLOW_COOLDOWN);
        let was = by_node.get(&nid).map(|e| e.tier);
        match coord.follow_peer_to_derp(nid, cfg) {
            Some(link) => {
                warn!(
                    peer = %nid, ?was,
                    "overlay relay: peer is relaying to us over /derp while we hold another carrier — following it onto DERP now (demote-follow)"
                );
                // #29 — and SUPPRESS the tier we are leaving. Otherwise
                // make-before-break re-promotes it the moment its probe
                // latches, the peer keeps relaying, and the two mechanisms flap
                // the pair on MBB's cadence (field 2026-08-25: every 60 s for
                // hours, from the minute #27 shipped). A latched probe proves
                // the path CARRIES; it says nothing about whether the peer
                // intends to use it, and the peer's own frames are the better
                // evidence. Decaying, so direct returns on its own.
                if let Some(t) = was.filter(|t| t.is_direct()) {
                    let mbb = crate::overlay::direct::make_before_break_enabled();
                    self.shadow(|s| s.mon.on_peer_relayed_instead(&nid, t, mbb, Instant::now()));
                }
                self.install_ready(wg, by_node, tun, link, relay_bq).await;
                true
            }
            None => {
                debug!(
                    peer = %nid,
                    "overlay relay: demote-follow declined (no mux / mux down / peer lacks derp) — the walk retries"
                );
                false
            }
        }
    }

    /// rc.211 — commit an already-BUILT relay/test carrier as a WG peer: the
    /// µs-fast install half of the old `install_ready` (`wg.add_peer` + `/32`
    /// route + subnets + bookkeeping). `quic: Some` = the off-loop QUIC build
    /// succeeded; `None` = raw carrier (no-QUIC link, or QUIC fallback).
    pub(super) async fn install_built(
        &self,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        tun: &Arc<dyn TunIo>,
        link: ReadyLink,
        quic: Option<Arc<Carrier>>,
    ) {
        if link.relay_kind == RelayKind::Org && wg.org_recovery_held(&link.public_key) { return; }
        let (relay_local, relay_dst) = match &link.relay_parts {
            Some((conn, dst)) => (conn.local_addr().ok(), Some(*dst)),
            None => (None, None),
        };
        let carrier = quic.unwrap_or_else(|| link.carrier.clone());
        if link.relay_kind == RelayKind::Org
            && by_node.get(&link.node_id).is_some_and(|e| {
                e.pubkey == link.public_key && e.overlay_ip == link.overlay_ip
                    && e.relay_kind == Some(RelayKind::Derp)
            })
        {
            if wg.start_org_upgrade(link.public_key, link.overlay_ip, carrier) {
                let node_id = link.node_id;
                by_node.get_mut(&node_id).expect("incumbent checked").org_upgrade =
                    Some((link, Instant::now()));
            }
            return;
        }
        let initiate = carrier.is_direct() || self.keypair.public.to_bytes() < link.public_key;
        let is_direct = carrier.is_direct();
        wg.add_peer(link.public_key, link.overlay_ip, carrier, initiate);
        wg.set_peer_relay_role(&link.public_key, link.relay_kind == RelayKind::Derp, link.relay_kind == RelayKind::Org);
        by_node.insert(
            link.node_id,
            Installed {
                // rc.276 — every install_ready carrier is a flow WE built
                // (our allocation / dialer socket / DERP WS / loopback).
                initiated: true,
                carrier_local: relay_local,
                carrier_dst: relay_dst,
                relay_kind: (!is_direct).then_some(link.relay_kind),
                relay_local,
                relay_dst,
                // A relay carrier, or the loopback carrier used in Direct/test
                // mode. Test loopback carriers are direct → Lan (no off-link
                // handshake deadline); coturn carriers → Relay.
                ..Installed::base(
                    link.public_key,
                    link.overlay_ip,
                    if is_direct {
                        DirectTier::Lan
                    } else {
                        DirectTier::Relay
                    },
                    Instant::now(),
                )
            },
        );
        // Host `/32` so overlay traffic to this peer beats any colliding
        // less-specific route on the uplink (e.g. a carrier CGNAT /10).
        // Best-effort — clean hosts route fine via the connected /10.
        if let Err(e) = tun.add_peer_route(link.overlay_ip).await {
            debug!(peer = %link.node_id, %e, "overlay: /32 peer route not installed (ok on clean hosts)");
        }
        // Phase 1 — subnet-router peer: route its approved CIDRs to it.
        self.install_subnets(wg, tun, link.node_id, link.public_key, &link.subnets)
            .await;
        info!(peer = %link.node_id, overlay_ip = %link.overlay_ip, initiate, "overlay: peer installed");
    }

    pub(super) fn sweep_authenticated_derp_follow(
        &self, wg: &mut WgDevice, by_node: &mut HashMap<ObjectId, Installed>,
        relay: &mut Option<RelayCoordinator>, current_peers: &HashMap<ObjectId, NetmapPeer>,
    ) -> bool {
        let mut changed = false;
        for (nid, e) in by_node.iter_mut() {
            if e.relay_kind != Some(RelayKind::Org) { continue; }
            if !current_peers.get(nid).and_then(peer_config_from_netmap)
                .is_some_and(|p| p.public_key == e.pubkey && p.overlay_ip == e.overlay_ip)
            {
                wg.cancel_derp_follow(&e.pubkey);
                continue;
            }
            if !wg.poll_derp_follow(&e.pubkey) { continue; }
            let (local, dst) = wg.peer_relay_addrs(&e.pubkey);
            let traffic = wg.peer_traffic(&e.pubkey).unwrap_or((0,0));
            *e = Installed {
                hs_done: wg.peer_handshake_done(&e.pubkey) == Some(true),
                initiated: true, relay_kind: Some(RelayKind::Derp),
                last_traffic: traffic, relay_local: local, relay_dst: dst,
                carrier_local: local, carrier_dst: dst,
                org_recovery_until: wg.org_recovery_until(&e.pubkey),
                org_recovery_needs_query: true,
                ..Installed::base(e.pubkey, e.overlay_ip, DirectTier::Relay, Instant::now())
            };
            if let Some(r) = relay.as_mut() { r.org_bind_failed(nid); }
            info!(peer = %nid, "overlay relay: authenticated fresh active-DERP proof — restored retained floor");
            changed = true;
        }
        changed
    }

    /// Settle only an authorized candidate tied to the current key/IP and
    /// incumbent. A failed or revoked candidate never withdraws the floor.
    pub(super) fn sweep_org_upgrades(
        &self, wg: &mut WgDevice, by_node: &mut HashMap<ObjectId, Installed>,
        relay: &mut Option<RelayCoordinator>, current_peers: &HashMap<ObjectId, NetmapPeer>,
    ) -> bool {
        let mut changed = false;
        for (nid, e) in by_node.iter_mut() {
            let Some((link, since)) = e.org_upgrade.as_ref() else { continue; };
            let current = current_peers.get(nid).and_then(peer_config_from_netmap)
                .is_some_and(|p| p.public_key == link.public_key && p.overlay_ip == link.overlay_ip);
            if !current || wg.org_recovery_held(&e.pubkey) || e.org_recovery_needs_query
                || since.elapsed() >= DirectTier::Relay.handshake_deadline() {
                wg.cancel_org_upgrade(&e.pubkey);
                e.org_upgrade = None;
                if let Some(r) = relay.as_mut() { r.org_bind_failed(nid); }
                info!(peer = %nid, "overlay relay: ORG candidate did not settle; DERP retained");
                continue;
            }
            if !wg.promote_org_upgrade(&e.pubkey) { continue; }
            let (link, _) = e.org_upgrade.take().expect("candidate checked");
            let (local, dst) = link.relay_parts.as_ref()
                .map(|(c, d)| (c.local_addr().ok(), Some(*d))).unwrap_or((None, None));
            *e = Installed {
                hs_done: true,
                initiated: true,
                relay_kind: Some(RelayKind::Org),
                relay_local: local, relay_dst: dst,
                carrier_local: local, carrier_dst: dst,
                ..Installed::base(link.public_key, link.overlay_ip, DirectTier::Relay, Instant::now())
            };
            info!(peer = %nid, "overlay relay: ORG carrier promoted after authenticated WG response (DERP receive retained)");
            changed = true;
        }
        changed
    }

    /// R3 — the socket half of a direct-plane rebuild: tear down everything
    /// referencing the old sockets, retire their demux slots (freeing the
    /// stable-port band — the ports only close when the LAST Arc drops, and
    /// carriers, the pump mirror, probes and the demux all hold clones),
    /// mint a fresh stun-events channel, bind the new plane, and register
    /// its demux loops. Returns the new keepalive event receiver.
    ///
    /// The caller owns the rest of the ordered sequence (join → gather →
    /// coordinator swap → keepalive respawn → `install_peers`) because those
    /// touch `run()`'s loop locals. The caller must ALSO abort the srflx
    /// keepalive BEFORE calling (it owns a punch-socket Arc by value).
    #[allow(clippy::too_many_arguments)]
    /// Steps 1-2 of the R3 rebuild, shared with the carrier-plane Teardown
    /// step (P1-d): every direct carrier and in-flight upgrade probe dies —
    /// their `Carrier`/pump/timer-task Arcs pin the old sockets, and the
    /// plane may only re-bind once every engine has released them.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn teardown_direct_carriers(
        &self,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
        relay: &mut Option<RelayCoordinator>,
        relay_bq: &mut RelayBuildQueue,
        alloc_q: &mut RelayAllocQueue,
        tun: &Arc<dyn TunIo>,
    ) {
        // 1. Direct carriers die first — the shared teardown also drops each
        //    peer's in-flight probe.
        let direct_nids: Vec<ObjectId> = by_node
            .iter()
            .filter(|(_, e)| e.is_direct)
            .map(|(n, _)| *n)
            .collect();
        for nid in direct_nids {
            self.remove_peer_state(
                nid,
                wg,
                by_node,
                tun,
                relay,
                relay_bq,
                Some(alloc_q),
                upgrade_probes,
                PeerRoute::Drop,
            )
            .await;
        }
        // 2. Probes on RELAY peers also ride the old sockets — drop them
        //    without a verdict (the plane vanished under them; that says
        //    nothing about the tier).
        let probe_nids: Vec<ObjectId> = upgrade_probes.keys().copied().collect();
        for nid in probe_nids {
            if let Some(p) = upgrade_probes.remove(&nid) {
                wg.drop_direct_probe(&p.pubkey).await;
                self.shadow(|s| s.mon.on_probe_aborted(&nid));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn rebuild_direct_plane_sockets(
        &self,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
        relay: &mut Option<RelayCoordinator>,
        relay_bq: &mut RelayBuildQueue,
        alloc_q: &mut RelayAllocQueue,
        tun: &Arc<dyn TunIo>,
        direct_ctx: &mut Option<DirectCtx>,
    ) -> Option<mpsc::Receiver<crate::transport::stun::StunInbound>> {
        // 1+2 — every direct carrier and in-flight probe dies first (their
        //    Arcs pin the old sockets).
        self.teardown_direct_carriers(wg, by_node, upgrade_probes, relay, relay_bq, alloc_q, tun)
            .await;
        // 3. Retire the old demux slots (aborts their recv loops) and drop
        //    the plane's own Arcs — with 1+2 done, the ports actually free.
        if let Some(old) = direct_ctx.take() {
            for (_ip, s) in &old.socks {
                if let Ok(a) = s.local_addr() {
                    wg.retire_direct_socket(a);
                }
            }
            if let Some(ps) = &old.public_sock
                && let Ok(a) = ps.local_addr()
            {
                wg.retire_direct_socket(a);
            }
        }
        // 4. Fresh stun-events channel: the old receiver died with the
        //    keepalive task; retired loops keep the dead sender, and every
        //    loop registered below clones the new one.
        let stun_rx = wg.replace_stun_events();
        // 5. Bind the new plane (the stable-port binder tolerates the old
        //    binds' lingering close with its ~900 ms retry window) and wire
        //    its demux loops eagerly, exactly like startup.
        *direct_ctx = self.setup_direct().await;
        if let Some(ctx) = direct_ctx.as_ref()
            && (direct::public_direct_enabled() || direct::srflx_enabled())
        {
            for (_ip, s) in &ctx.socks {
                wg.ensure_direct_demux(s.clone());
            }
            if let Some(ps) = &ctx.public_sock {
                wg.ensure_direct_demux(ps.clone());
            }
        }
        // 6. Every direct-tier measurement was made through sockets that no
        //    longer exist — reset that evidence (relay evidence survives).
        self.shadow(|s| s.mon.on_local_rebuild());
        Some(stun_rx)
    }

    /// R1 — one srflx gather + advertise pass, extracted VERBATIM from
    /// `run()`'s startup inline block so the direct-plane rebuild (R3) can
    /// re-run it mid-session; [`setup_direct`](Self::setup_direct) is the
    /// bind half of the same split. Behaviour is identical to the inline
    /// original: gate on `srflx_gather_active`, resolve a STUN server
    /// excluding our own IPs, gather within [`SRFLX_GATHER_BUDGET`], pick the
    /// FIRST pair as the punch socket, probe our NAT type on it, stamp
    /// `ctx.punch`/`ctx.my_nat`, publish `srflx_status`, and advertise via
    /// `ClientMsg::OverlaySrflx`.
    ///
    /// Ordering contracts (both load-bearing):
    /// * call AFTER the join for this plane — the server's (re-)join handler
    ///   CLEARS `srflx_endpoints`, so a gather advertised before the join is
    ///   erased by it;
    /// * call BEFORE the demux loops start reading these sockets — the STUN
    ///   replies ride the very sockets the overlay will use (the mapping has
    ///   to match), and a recv loop would steal them.
    pub(super) async fn gather_and_advertise_srflx(
        &mut self,
        direct_ctx: &mut Option<DirectCtx>,
        stun_urls: &[String],
    ) -> SrflxGather {
        let mut out = SrflxGather {
            stun_server: None,
            advertised: Vec::new(),
            my_nat: None,
        };
        // Multi-org v2 — plane mode: ONE gather + NAT probe for the whole
        // process (the plane's recv loops own the sockets, so per-runtime
        // raw-socket STUN would be stolen anyway). Each runtime still
        // advertises on ITS OWN control WS, after ITS OWN join — preserving
        // the server-side join-clears-srflx ordering contract per org.
        if let Some(plane) = self.carrier_plane.clone() {
            let shared = plane.ensure_srflx(stun_urls).await;
            if let Some(ctx) = direct_ctx.as_mut() {
                ctx.punch = shared.punch.clone();
                ctx.my_nat = shared.my_nat.clone();
            }
            self.srflx_status = Some(crate::localapi::SrflxStatus {
                candidates: shared.candidates.clone(),
                stun_server: shared.stun_server.map(|s| s.to_string()),
                nat: shared.my_nat.clone(),
                via_public_dial: shared.via_public_dial,
                error: shared.error.clone(),
            });
            if !shared.candidates.is_empty() {
                let _ = self
                    .outbound
                    .send(ClientMsg::OverlaySrflx {
                        candidates: shared.candidates.clone(),
                        nat: shared.my_nat.clone(),
                        udp_dialer_ok: Some(crate::overlay::dialer::udp_dialer_ok()),
                    })
                    .await;
            }
            out.stun_server = shared.stun_server;
            out.advertised = shared.candidates;
            out.my_nat = shared.my_nat;
            return out;
        }
        if !direct::srflx_gather_active() {
            return out;
        }
        let socks = direct_ctx
            .as_ref()
            .map(|c| c.socks.clone())
            .unwrap_or_default();
        // Our own interface IPs — excluded as STUN targets so a fleet host
        // co-located with a coturn worker doesn't STUN itself (→ hairpin →
        // false UDP-blocked). See `direct::resolve_stun_server`.
        let own_ips: Vec<Ipv4Addr> = socks.iter().map(|(ip, _)| *ip).collect();
        if socks.is_empty() || stun_urls.is_empty() {
            return out;
        }
        match direct::resolve_stun_server(stun_urls, &own_ips).await {
            Some(stun_server) => {
                out.stun_server = Some(stun_server);
                let pairs = tokio::time::timeout(
                    SRFLX_GATHER_BUDGET,
                    direct::gather_srflx(&socks, stun_server, SRFLX_ATTEMPT_TIMEOUT),
                )
                .await
                .unwrap_or_default();
                if pairs.is_empty() {
                    // WARN, not debug. This exact line was `debug!` when the
                    // srflx tier died fleet-wide on 2026-08-06 (coturn
                    // replying with TTL=1, so every forwarded reply was
                    // dropped before FORWARD) — and nothing above DEBUG said
                    // a word while every pair in the mesh silently degraded
                    // to the DERP carrier. Once per gather pass, so it can't
                    // become log spam.
                    warn!(
                        %stun_server,
                        sockets = socks.len(),
                        "overlay: srflx gather yielded NO public candidate — this node \
                         cannot hole-punch and every peer will read it as UDP-blocked \
                         (pairs fall back to the relay/DERP tier). Check that the STUN \
                         server answers UDP from the internet."
                    );
                    self.srflx_status = Some(crate::localapi::SrflxStatus {
                        candidates: Vec::new(),
                        stun_server: Some(stun_server.to_string()),
                        nat: None,
                        via_public_dial: false,
                        error: Some(format!(
                            "STUN yielded no public candidate from {stun_server} \
                             ({} socket(s) probed)",
                            socks.len()
                        )),
                    });
                } else {
                    // The FIRST pair is the punch socket: its candidate is
                    // advertised at index 0, which the peer's dial-side
                    // (`pick_public_endpoint`) picks first — so both ends
                    // agree on the mapping to punch.
                    let punch = pairs.first().cloned();
                    // Phase C — probe OUR NAT type on the punch socket (two
                    // distinct STUN targets), BEFORE its demux loop starts
                    // (same socket-read race as the gather). A peer skips the
                    // punch only when BOTH ends are symmetric; `None`
                    // (unknown) stays optimistic.
                    let my_nat = if let Some((_, ps)) = &punch {
                        let targets = direct::resolve_stun_targets(stun_urls, &own_ips).await;
                        direct::probe_nat_type(ps, &targets, SRFLX_ATTEMPT_TIMEOUT)
                            .await
                            .map(str::to_string)
                    } else {
                        None
                    };
                    out.my_nat = my_nat.clone();
                    if let (Some(ctx), Some(first)) = (direct_ctx.as_mut(), punch) {
                        ctx.punch = Some(first);
                        ctx.my_nat = my_nat.clone();
                    }
                    let candidates: Vec<String> = pairs.into_iter().map(|(c, _)| c).collect();
                    out.advertised = candidates.clone();
                    self.srflx_status = Some(crate::localapi::SrflxStatus {
                        candidates: candidates.clone(),
                        stun_server: Some(stun_server.to_string()),
                        nat: my_nat.clone(),
                        via_public_dial: false,
                        error: None,
                    });
                    info!(?candidates, ?my_nat, %stun_server, "overlay: advertising srflx candidates (NAT-traversal Phase B/C)");
                    let _ = self
                        .outbound
                        .send(ClientMsg::OverlaySrflx {
                            candidates,
                            nat: my_nat,
                            udp_dialer_ok: Some(crate::overlay::dialer::udp_dialer_ok()),
                        })
                        .await;
                }
            }
            None => {
                // Also promoted from debug! — same reasoning as the
                // no-candidate arm: with no STUN server the entire srflx tier
                // is off for this pass, which is a fleet-level fact, not a
                // detail.
                warn!(
                    urls = ?stun_urls,
                    "overlay: no resolvable STUN server — srflx tier OFF this run; \
                     this node will read as UDP-blocked to every peer"
                );
                self.srflx_status = Some(crate::localapi::SrflxStatus {
                    candidates: Vec::new(),
                    stun_server: None,
                    nat: None,
                    via_public_dial: false,
                    error: Some(format!("no resolvable STUN server among {stun_urls:?}")),
                });
            }
        }
        out
    }
}

/// R1 — outcome of one [`gather_and_advertise_srflx`] pass: the pinned STUN
/// server, the advertised candidates, and the probed NAT class — exactly the
/// three loop locals `run()` used to fill inline. The keepalive task and the
/// reattach restore read these.
///
/// [`gather_and_advertise_srflx`]: OverlayRuntime::gather_and_advertise_srflx
pub(super) struct SrflxGather {
    pub(super) stun_server: Option<SocketAddr>,
    pub(super) advertised: Vec<String>,
    pub(super) my_nat: Option<String>,
}

#[cfg(test)]
mod tests {
    //! First tests in this file (2026-08-14 debt audit: 2,378 prod LOC,
    //! zero tests) — seeded at the decision helper the W5 srflx work edits
    //! next: `resolve_direct_candidates` gates which direct tiers get
    //! dialed at all, and each case below encodes a shipped field lesson.

    use super::*;

    fn peer(lan: &[&str], srflx: &[&str], nat: Option<&str>) -> PeerConfig {
        PeerConfig {
            public_key: [7u8; 32],
            overlay_ip: Ipv4Addr::new(100, 65, 4, 9),
            name: "t".into(),
            subnets: vec![],
            endpoints: vec![],
            lan_endpoints: lan.iter().map(|s| s.to_string()).collect(),
            srflx_endpoints: srflx.iter().map(|s| s.to_string()).collect(),
            srflx_nat: nat.map(|s| s.to_string()),
            udp_dialer_ok: None,
            relay_band_udp: None,
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
            supports_forced_derp: false,
            supports_derp_floor: false,
            supports_overlay_echo: false,
            relay_strategy: None,
            relay_home: None,
            warm_relay_endpoint: None,
        }
    }

    async fn ctx(punch_candidate: Option<&str>, my_nat: Option<&str>) -> DirectCtx {
        let punch = match punch_candidate {
            Some(c) => {
                let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                Some((c.to_string(), s))
            }
            None => None,
        };
        DirectCtx {
            socks: vec![],
            my_ips: vec![Ipv4Addr::new(192, 168, 68, 126)],
            endpoints: vec![],
            public_sock: None,
            punch,
            my_nat: my_nat.map(|s| s.to_string()),
        }
    }

    #[tokio::test]
    async fn srflx_tier_needs_a_punch_socket() {
        let p = peer(&[], &["37.63.112.129:43649"], Some("cone"));
        let none = resolve_direct_candidates(
            Some(&ctx(None, Some("cone")).await),
            &p,
            CandidateRotation::default(),
        );
        assert!(
            none.srflx.is_none(),
            "no punch socket -> no srflx dial (the srflx-NONE victim state)"
        );
        let some = resolve_direct_candidates(
            Some(&ctx(Some("5.5.5.5:1"), Some("cone")).await),
            &p,
            CandidateRotation::default(),
        );
        assert_eq!(some.srflx, Some("37.63.112.129:43649".parse().unwrap()));
    }

    #[tokio::test]
    async fn srflx_skipped_only_when_both_ends_are_symmetric() {
        let c = ctx(Some("5.5.5.5:1"), Some("symmetric")).await;
        let both = resolve_direct_candidates(
            Some(&c),
            &peer(&[], &["37.63.112.129:43649"], Some("symmetric")),
            CandidateRotation::default(),
        );
        assert!(both.srflx.is_none(), "symmetric<->symmetric cannot punch");
        let one_cone = resolve_direct_candidates(
            Some(&c),
            &peer(&[], &["37.63.112.129:43649"], Some("cone")),
            CandidateRotation::default(),
        );
        assert!(one_cone.srflx.is_some(), "one cone end keeps the punch");
    }

    #[tokio::test]
    async fn same_nat_hairpin_suppresses_srflx_only_when_a_lan_path_exists() {
        // The peer's srflx shares OUR public IP (same NAT). With a
        // same-subnet LAN candidate the punch is pointless; WITHOUT one it
        // must stay — the #436 lesson: a phantom LAN candidate wrongly
        // suppressed srflx and the pair was left with no direct tier at all.
        let c = ctx(Some("37.63.112.129:43649"), Some("cone")).await;
        let with_lan = resolve_direct_candidates(
            Some(&c),
            &peer(
                &["192.168.68.4:43648"],
                &["37.63.112.129:43610"],
                Some("cone"),
            ),
            CandidateRotation::default(),
        );
        assert!(with_lan.lan.is_some());
        assert!(
            with_lan.srflx.is_none(),
            "hairpin + LAN present -> srflx suppressed"
        );
        let without_lan = resolve_direct_candidates(
            Some(&c),
            &peer(&[], &["37.63.112.129:43610"], Some("cone")),
            CandidateRotation::default(),
        );
        assert!(
            without_lan.srflx.is_some(),
            "hairpin WITHOUT a LAN candidate keeps srflx"
        );
    }

    #[tokio::test]
    async fn dead_lan_strikes_unlock_the_hairpin_punch() {
        // 2026-08-15 field: an AP with client isolation (or cross-node mesh
        // roaming) leaves the peer's LAN candidate advertised but DEAD —
        // every tier=Lan probe reads saw_inbound=false while raw same-subnet
        // UDP + ICMP measure dead both directions. Presence-as-usability
        // suppressed the hairpin srflx dial, so same-NAT pairs demoted
        // during a VPN window sat relay-locked forever (a restart's fresh
        // punch matrix was the only way out). After LAN_DEAD_STRIKES failed
        // LAN probes the hairpin must unlock — while the LAN candidate
        // keeps being dialed so a recovered AP path clears the strikes.
        let c = ctx(Some("37.63.112.129:43650"), Some("cone")).await;
        let p = peer(
            &["192.168.68.106:43650"],
            &["37.63.112.129:43721"],
            Some("cone"),
        );
        let below = resolve_direct_candidates(
            Some(&c),
            &p,
            CandidateRotation {
                lan: LAN_DEAD_STRIKES - 1,
                ..Default::default()
            },
        );
        assert!(
            below.srflx.is_none(),
            "below the threshold the LAN premise still holds"
        );
        let dead = resolve_direct_candidates(
            Some(&c),
            &p,
            CandidateRotation {
                lan: LAN_DEAD_STRIKES,
                ..Default::default()
            },
        );
        assert!(dead.lan.is_some(), "the LAN candidate keeps being probed");
        assert_eq!(
            dead.srflx,
            Some("37.63.112.129:43721".parse().unwrap()),
            "a dead LAN unlocks the hairpin srflx dial"
        );
    }

    #[tokio::test]
    async fn public_tier_stays_off_under_the_default_flag() {
        let mut c = ctx(None, None).await;
        c.public_sock = Some(Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()));
        let got = resolve_direct_candidates(
            Some(&c),
            &peer(&["5.9.157.221:43648"], &[], None),
            CandidateRotation::default(),
        );
        assert!(got.public.is_none(), "OVERLAY_PUBLIC_DIRECT is default-OFF");
    }

    #[test]
    fn standby_copies_wait_for_an_unanswered_proof() {
        // F2 — `standby_tee_wanted`: nothing without a pending proof, nothing
        // for a young one, copies for one unanswered past STANDBY_ARM_AFTER,
        // none once answered, none to a peer that takes no copies, none for
        // a proof that is neither business nor Major.
        let now = Instant::now();
        let old = now - STANDBY_ARM_AFTER - Duration::from_millis(1);
        let business = |at| Some(PokeArm { at, from_major: false, from_business: true });
        assert!(!standby_tee_wanted(None, false, true, now));
        assert!(!standby_tee_wanted(business(now), false, true, now));
        assert!(standby_tee_wanted(business(old), false, true, now));
        assert!(!standby_tee_wanted(business(old), true, true, now));
        assert!(!standby_tee_wanted(business(old), false, false, now));
        let major = Some(PokeArm { at: old, from_major: true, from_business: false });
        assert!(standby_tee_wanted(major, false, true, now));
        let other = Some(PokeArm { at: old, from_major: false, from_business: false });
        assert!(!standby_tee_wanted(other, false, true, now));
    }

    #[tokio::test]
    async fn lan_candidate_comes_from_the_shared_slash24_only() {
        let c = ctx(None, None).await;
        let on_link = resolve_direct_candidates(
            Some(&c),
            &peer(&["192.168.68.4:43648"], &[], None),
            CandidateRotation::default(),
        );
        assert_eq!(
            on_link.lan,
            Some((
                Ipv4Addr::new(192, 168, 68, 126),
                "192.168.68.4:43648".parse().unwrap()
            ))
        );
        let off_link = resolve_direct_candidates(
            Some(&c),
            &peer(&["10.0.0.4:43648"], &[], None),
            CandidateRotation::default(),
        );
        assert!(off_link.lan.is_none());
    }
}
