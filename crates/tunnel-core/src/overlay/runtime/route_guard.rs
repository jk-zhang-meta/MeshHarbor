// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Route ownership + defense — split out of `runtime.rs` (rc.284, pure move):
//! the 2 s route-guard cadence, the peer `/32` drop helper, subnet-route
//! install, and the P5 exit-node split-default state machine (reconcile /
//! teardown / readiness). The route-war doctrine (re-assert peer `/32`s and
//! defend our own `/32` against a full-tunnel VPN) is anchored here.

use super::*;

/// The route-guard blind-tick cadence WITHOUT a live route-event
/// subscription (rc.146; sole cadence until the P4 demotion). A full-tunnel
/// VPN (Check Point) keeps re-installing a competing `/32` for each overlay
/// IP via its own NIC that swallows overlay traffic; the route table flaps
/// between it and ours. Re-asserting UNCONDITIONALLY on a tight cadence —
/// not gated on the carrier's traffic counters, because a captured route
/// means our packets never reach the WG device so `tx` stays flat and a
/// traffic-gated check would never fire — keeps the overlay winning the
/// route war. Cheap (a couple of route commands per peer) and 2 s bounds the
/// capture window to a couple of dropped pings. This cadence also RETURNS
/// mid-session if the subscription dies (see the route-event arm's `None`
/// leg), so the demoted heartbeat below never runs uncovered.
pub(super) const ROUTE_GUARD_TICK: Duration = Duration::from_secs(2);

/// P4 demotion (gated on the fleet soak: subscriptions alive 36 h+ on every
/// host, zero watch deaths, zero uncaught erasures): with a LIVE
/// route-event subscription the blind tick is belt-and-braces only — an
/// erase is re-asserted by the event arm within milliseconds (or by its
/// trailing-edge pull within `ROUTE_WAVE_MIN_INTERVAL` when it lands inside
/// a rate-limit quiet window), so the tick drops to a 30 s heartbeat.
pub(super) const ROUTE_GUARD_HEARTBEAT: Duration = Duration::from_secs(30);

/// Effective route-guard cadence. No live subscription (env-disabled,
/// platform-unavailable, or died) ⇒ [`ROUTE_GUARD_TICK`] — pre-P4 behaviour
/// exactly. With one ⇒ [`ROUTE_GUARD_HEARTBEAT`], overridable via
/// `ROOMLERD_OVERLAY_ROUTE_TICK_SECS` (2–300 s; `2` is the operator
/// revert to the old cadence; garbage/out-of-range falls back to the
/// default so a typo can never disable the guard).
pub(super) fn route_guard_cadence(watch_live: bool, env: Option<String>) -> Duration {
    if !watch_live {
        return ROUTE_GUARD_TICK;
    }
    match env.and_then(|v| v.trim().parse::<u64>().ok()) {
        Some(s) if (2..=300).contains(&s) => Duration::from_secs(s),
        _ => ROUTE_GUARD_HEARTBEAT,
    }
}

/// rc.285 — one entry of the DEFENDED SET: a prefix the overlay owns and
/// keeps re-asserting against a competing full-tunnel VPN. The set is
/// composed ONLY by [`defended_routes`] and executed ONLY by
/// [`run_defense_wave`]; every route-guard trigger (the 2 s tick, a
/// RouteWatch event) runs exactly that list, so a new defended class is
/// added in one place or not at all. Grew ad hoc before this: peer `/32`s
/// (rc.208) → own `/32` (rc.278) → own v6 `/128` + `/96` (rc.281), each
/// spliced into both select-loop arms by hand.
///
/// Deliberately NOT in the set: the P5 exit split-default `/1`s. Their
/// re-assert must stay INLINE on the select! loop — this wave runs DETACHED,
/// and a detached task with a stale snapshot could re-install a `/1` that
/// `teardown_exit_routing` (on that same loop) had just purged, black-holing
/// the host's whole egress (the self-wedge the P5 design forbids).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Defend {
    /// An installed peer's `/32`: evict foreign competitors, then (re-)add
    /// ours at metric 1 via the overlay NIC ([`TunIo::add_peer_route`]).
    AssertPeer(Ipv4Addr),
    /// Our OWN addresses — the self `/32` plus (on Windows) the derived v6
    /// `/128` and the connected ULA `/96`: EVICTION-ONLY
    /// ([`TunIo::defend_self_route`]). Re-adding our own address via the TUN
    /// risks a forwarding loop; Windows' on-link route serves local delivery
    /// the moment the competitor is gone (field-proven on winhost-a).
    EvictSelf(Ipv4Addr),
    /// Change B — the block-floor maintenance step
    /// ([`TunIo::defend_block_floor`]): assert the four `plen+2` sub-prefixes
    /// of the connected overlay block (a corp VPN's `/11` out-specifics both
    /// the connected `/10` and the rc.288 metric-0 defense, so absent-`/32`
    /// traffic leaked to the CORP GATEWAY — field 2026-08-08, winhost-a), or
    /// actively retract them when the host's own uplink sits inside the block
    /// (the ISP-CGNAT self-wedge gate — decided per wave, inside the detached
    /// task, off the select loop).
    BlockFloor,
}

/// Compose the defended set from the live peer table + our own address.
/// Peers first, self next, the block floor LAST — the peer/self shape the
/// arms have used since rc.278, locked by
/// `route_reassert_covers_self_and_peers`. The floor entry is unconditional
/// here: its per-wave assert-vs-retract decision (the ISP-CGNAT gate) lives
/// in [`TunIo::defend_block_floor`] so it runs inside the DETACHED wave, not
/// on the select loop.
pub(super) fn defended_routes(
    by_node: &HashMap<ObjectId, Installed>,
    self_v4: Ipv4Addr,
) -> Vec<Defend> {
    by_node
        .values()
        .map(|e| Defend::AssertPeer(e.overlay_ip))
        .chain([Defend::EvictSelf(self_v4), Defend::BlockFloor])
        .collect()
}

/// Execute one defense wave — the ONLY consumer of [`defended_routes`].
/// Runs detached from the select! loop under the caller's owned re-assert
/// lock (rc.206: a slow Windows route batch must never stack concurrent
/// delete-then-add on the same prefix, and awaiting it inline would stall
/// the outbound TUN arm).
pub(super) async fn run_defense_wave(tun: Arc<dyn TunIo>, set: Vec<Defend>) {
    // FR-68 — the wave is the unit of work a route war multiplies: every
    // eviction is a FIB change, which feeds our own route-change subscription,
    // which arms the next wave. Waves/min far above the 30 s heartbeat means
    // the guard is driving itself rather than reacting to the network.
    crate::evidence::ROUTE_WAVES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // v3 (#23) — the peer list doubles as the reclaim step's target set.
    let peers: Vec<Ipv4Addr> = set
        .iter()
        .filter_map(|e| match e {
            Defend::AssertPeer(ip) => Some(*ip),
            _ => None,
        })
        .collect();
    for entry in set {
        match entry {
            Defend::AssertPeer(ip) => {
                tun.add_peer_route(ip).await.ok();
            }
            Defend::EvictSelf(ip) => tun.defend_self_route(ip).await,
            Defend::BlockFloor => tun.defend_block_floor().await,
        }
    }
    // v3 (#23) — the ownership CHECK runs last, against the freshest
    // possible table: with the interface metric pinned to 0 our rows win
    // every tie outright, so this only has work to do when the pin was
    // reverted (adapter reset / profile change) or a third product outranks
    // us — both of which it reports rather than fights.
    if !peers.is_empty() {
        tun.verify_peer_path_ownership(&peers).await;
    }
}

/// Whether a teardown should also drop the peer's OS `/32`. `Keep` is for a
/// RE-INSTALL of the SAME node (a WG key rotation): the route is about to be
/// re-added for the same address, so dropping it only flaps the host route —
/// and on Windows every add/del is a slow IP-Helper round-trip.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum PeerRoute {
    Drop,
    Keep,
}

/// Drop a peer's OS `/32` — UNLESS the address is still claimed by ANOTHER
/// installed peer.
///
/// Overlay addresses are RECYCLED: the server returns a removed device's host
/// number to the tenant's pool, so by the time we reap a stale peer its address
/// may already belong to a live one. Deleting the route unconditionally would
/// blackhole the new owner with nothing to re-install it (`install_peers` skips
/// a node that is already in `by_node`).
///
/// Call AFTER the removed peer is out of `by_node`, so the scan sees only
/// survivors.
pub(super) async fn del_peer_route_if_unowned(
    tun: &Arc<dyn TunIo>,
    by_node: &HashMap<ObjectId, Installed>,
    ip: Ipv4Addr,
) {
    if by_node.values().any(|e| e.overlay_ip == ip) {
        debug!(%ip, "overlay: keeping the OS route — the address was recycled to a live peer");
        return;
    }
    tun.del_peer_route(ip).await;
}

/// P5 exit-node — the two IPv4 split-default halves. Installing these (as OS
/// routes via the overlay NIC + as the exit peer's WG `allowed_ips`) beats the
/// host's `0.0.0.0/0` default by longest-prefix WITHOUT deleting it, so the OS
/// default self-heals the instant the overlay routes go away (a crash / kill
/// can't strand the host offline — see A2/D3 in the P5 plan). `pub(crate)` so the
/// crash-safety purge ([`crate::overlay::tun::purge_split_default`]) removes EXACTLY what
/// the installer installs — one source of truth, symmetric by construction.
pub(crate) const SPLIT_DEFAULT_V4: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];
/// P5 exit-node — the two IPv6 halves, installed via the overlay NIC as a
/// FAIL-CLOSED measure: the crypto-router drops any non-derived-ULA v6
/// destination, so routing `::/1` + `8000::/1` into the overlay blackholes ALL
/// v6 internet egress. Without this a dual-stack host would send v4 through the
/// exit but leak v6 straight out its uplink (silent AAAA deanonymisation). Full
/// v6 exit egress is a follow-up (S3b); this is the minimum-safe stance (A5).
pub(crate) const SPLIT_DEFAULT_V6: [&str; 2] = ["::/1", "8000::/1"];

/// P5 — resolve the operator's chosen exit-node selector (a [`NetmapPeer`]'s
/// `name` or a node-id hex string) to a concrete node in the current netmap.
/// Pure, so the name-vs-hex match is unit-tested directly. `None` when no peer
/// matches (the chosen exit isn't in the mesh yet — reconcile defers rather than
/// blackholing egress waiting for it).
pub(super) fn resolve_exit_peer(
    selector: &str,
    peers: &HashMap<ObjectId, NetmapPeer>,
) -> Option<ObjectId> {
    let selector = selector.trim();
    peers
        .values()
        .find(|np| np.name == selector || np.node_id.to_hex() == selector)
        .map(|np| np.node_id)
}

/// P5 — did a NAME selector drift to a DIFFERENT machine than the one it first
/// resolved to?
///
/// A name is not a stable identity: removing a device releases its MagicDNS name
/// back to the network, so the same label can later belong to another machine.
/// Following it would silently redirect this host's ENTIRE internet egress. Once
/// we have captured the default route through a named peer we refuse to follow
/// the label elsewhere without operator action; a node-id hex selector is
/// unambiguous by construction and never drifts. Pure.
pub(super) fn exit_selector_drifted(
    pinned: Option<ObjectId>,
    selector: &str,
    resolved: ObjectId,
) -> bool {
    selector.trim() != resolved.to_hex() && pinned.is_some_and(|p| p != resolved)
}

/// P5 — is `peer` an admin-APPROVED exit node? The client only routes its
/// default egress through a peer whose netmap `routes` carry a default route
/// (`0.0.0.0/0`); the server only ever puts one there via the dedicated
/// exit-node approval (A6), so this is the client-side half of the admin gate —
/// naming a peer that wasn't approved as an exit node stays inert. Pure.
pub(super) fn peer_is_approved_exit(peer: &NetmapPeer) -> bool {
    peer.routes
        .iter()
        .filter_map(|r| crate::overlay::router::Cidr::parse(r))
        .any(|c| c.is_default_route())
}

/// P5 — the carrier-critical endpoint IPs that MUST bypass the split-default
/// (pinned via the ORIGINAL gateway) for the mesh to survive exit routing: the
/// coordination server's resolved IPs, every live RELAY carrier's coturn worker
/// IPs (both our own allocation `relay_local` and the peer's `relay_dst`), AND
/// (Phase A) every PUBLIC-DIRECT carrier's peer address. A SAME-LAN direct
/// carrier is on-link (a connected route more specific than a `/1`), so it needs
/// no exemption — but a public-direct carrier crosses the internet via the
/// default route, so without pinning its dst the split-default would swallow the
/// path to the exit itself and self-wedge. Pure, so the set arithmetic is
/// unit-tested against synthetic carriers.
pub(super) fn exit_exemption_set(
    server_ips: &[IpAddr],
    by_node: &HashMap<ObjectId, Installed>,
) -> HashSet<IpAddr> {
    let mut set: HashSet<IpAddr> = server_ips.iter().copied().collect();
    for inst in by_node.values() {
        if let Some(a) = inst.relay_local {
            set.insert(a.ip());
        }
        if let Some(a) = inst.relay_dst {
            set.insert(a.ip());
        }
        if let Some(a) = inst.public_direct_dst {
            set.insert(a.ip());
        }
    }
    // P7 — a DERP carrier's `relay_parts` hold SYNTHETIC `127.x.y.z`
    // placeholder addresses (pubkey-derived, non-routable); they must never
    // become exemption routes via the physical gateway. DERP's real transport
    // is the server WS, whose IPs are already in `server_ips`.
    set.retain(|ip| !ip.is_loopback());
    set
}

/// P5 — the exit peer's WG `allowed_ips` while it carries this node's default
/// egress: its own real (non-default) advertised subnets UNIONed with the two
/// v4 split-default halves, so packets to any non-overlay v4 destination
/// encapsulate to it (the `/1`s) while its `/32` host route + any real subnets
/// keep winning by longest-prefix for their own ranges. A peer that advertised
/// only `0.0.0.0/0` yields exactly the two `/1`s. Pure.
pub(super) fn exit_peer_allowed_ips(exit: &NetmapPeer) -> Vec<crate::overlay::router::Cidr> {
    let mut cidrs: Vec<crate::overlay::router::Cidr> = peer_config_from_netmap(exit)
        .map(|c| c.subnets)
        .unwrap_or_default()
        .into_iter()
        .filter(|c| !c.is_default_route())
        .collect();
    // unwrap: both are valid /1 CIDR literals (const-correct, covered by tests).
    cidrs.push(crate::overlay::router::Cidr::parse(SPLIT_DEFAULT_V4[0]).unwrap());
    cidrs.push(crate::overlay::router::Cidr::parse(SPLIT_DEFAULT_V4[1]).unwrap());
    cidrs
}

/// FR-97 — does a peer's current allowed-IPs set lack either v4
/// split-default half? Pure.
pub(super) fn split_default_missing(current: &[crate::overlay::router::Cidr]) -> bool {
    SPLIT_DEFAULT_V4.iter().any(|half| {
        // unwrap: both are valid /1 CIDR literals (const-correct, covered by tests).
        let half = crate::overlay::router::Cidr::parse(half).unwrap();
        !current.contains(&half)
    })
}

/// P5 — is the chosen exit peer ready to carry this node's default egress?
/// `Ok((id, np, pubkey))` when it is present in the netmap, admin-APPROVED
/// (`peer_is_approved_exit`), AND has a live carrier; else `Err(reason)` — the
/// operator-facing split-tunnel reason surfaced in [`ExitNodeStatus`] (S4). Pure,
/// so the reason mapping is unit-tested directly.
pub(super) fn exit_readiness(
    selector: &str,
    current_peers: &HashMap<ObjectId, NetmapPeer>,
    by_node: &HashMap<ObjectId, Installed>,
) -> Result<(ObjectId, NetmapPeer, [u8; 32]), &'static str> {
    let id = resolve_exit_peer(selector, current_peers)
        .ok_or("exit node not visible in the mesh yet")?;
    let np = current_peers
        .get(&id)
        .ok_or("exit node not visible in the mesh yet")?;
    if !peer_is_approved_exit(np) {
        return Err("not an admin-approved exit node (no 0.0.0.0/0 approved)");
    }
    let inst = by_node
        .get(&id)
        .ok_or("exit node has no live carrier yet")?;
    Ok((id, np.clone(), inst.pubkey))
}

/// P5 — the LocalAPI [`ExitNodeStatus`] for the daemon view (S4), or `None` when
/// this node isn't an exit-node client. `active` mirrors the installed
/// split-default; `withheld_reason` is surfaced only while inactive (a stale
/// reason left on the state is suppressed once routing is active). Pure.
pub(super) fn exit_node_status(
    selector: Option<&str>,
    state: &ExitRoutingState,
) -> Option<ExitNodeStatus> {
    let selector = selector?.to_string();
    Some(ExitNodeStatus {
        selector,
        active: state.split_default_installed,
        withheld_reason: if state.split_default_installed {
            None
        } else {
            state.withheld_reason.clone()
        },
        // S3b — global IPv6 also routes through the exit only when v4 is active
        // AND v6 egress was enabled (v6 exemptions pinned). Otherwise v6 is
        // fail-closed even while v4 egress is active.
        // FR-97 P0c-3 — and never from a netstack node: its SOCKS5 front
        // refuses every IPv6 destination that is not an overlay address, so
        // no global v6 packet leaves it for the exit, whatever the router holds.
        v6_active: state.split_default_installed
            && state.v6_active == Some(true)
            && state.socks5_port.is_none(),
        // S4b — DNS steered through the exit only while v4 egress is active.
        dns_steered: state.split_default_installed && state.dns_steered,
        socks5_port: state.socks5_port,
    })
}

/// S4b — whether the exit's DNS steer may run now: only beside an installed
/// split-default, once, and with MagicDNS on only at a live local resolver.
///
/// FR-97 P0c-3 — never from a netstack node. Its OS routes nothing through the
/// exit, so a steer would only move every app on the host to the public
/// upstream over the uplink: the Windows NRPT rule and the macOS resolver entry
/// are host-wide, and on a managed laptop they would cut off its internal
/// names. Only the SOCKS5 front's dials use the exit. Pure, so the gate is
/// tested on every OS.
pub(super) fn dns_steer_allowed(state: &ExitRoutingState) -> bool {
    state.split_default_installed
        && !state.dns_steered
        && state.socks5_port.is_none()
        && (state.dns_magic_domain.is_none() || state.dns_bound)
        && state.dns_target.is_some()
}

/// S4 — record the split-tunnel WITHHELD reason on the state and log it ONCE per
/// reason change (dedup on `state.withheld_reason`), so a persistently-withheld
/// exit config doesn't spam the log every reconcile while still surfacing each
/// distinct cause. The live reason is also exposed via [`ExitNodeStatus`] for
/// `meshharbor status`.
pub(super) fn note_withheld(state: &mut ExitRoutingState, selector: &str, reason: &str) {
    if state.withheld_reason.as_deref() != Some(reason) {
        warn!(
            exit = %selector, reason,
            "overlay exit-node: default routing WITHHELD (split-tunnel safety) — egress stays on the local uplink"
        );
        state.withheld_reason = Some(reason.to_string());
    }
}

/// FR-97 P1a — how often, at most, the pinned exemptions are re-checked
/// against the uplink ([`TunIo::stale_host_exemptions`]). The sweep reconciles
/// every few seconds and every carrier event reconciles too; a re-check costs
/// a table read per family (a `netstat` on macOS, an `ip route show` on Linux,
/// an in-memory FIB snapshot on Windows), so a burst of carrier events at
/// startup must not multiply it. A moved uplink is still noticed within a
/// sweep.
pub(super) const EXEMPTION_RECHECK_EVERY: Duration = Duration::from_secs(3);

/// FR-97 P1a — is a re-check of the pinned exemptions due? Pure.
pub(super) fn exemption_recheck_due(last: Option<Instant>, now: Instant) -> bool {
    last.is_none_or(|t| now.saturating_duration_since(t) >= EXEMPTION_RECHECK_EVERY)
}

/// FR-97 P1a — record that pinning `ip` failed with `err`. `true` when that
/// is news worth a WARN: the first failure for `ip`, or a different cause.
/// The gate retries on every reconcile, which is every few seconds, and the
/// field Mac on 0.4.132 logged the same failure every ~5 s for as long as it
/// was up.
pub(super) fn note_exemption_failure(state: &mut ExitRoutingState, ip: IpAddr, err: &str) -> bool {
    if state.exemption_failures.get(&ip).map(String::as_str) == Some(err) {
        return false;
    }
    state.exemption_failures.insert(ip, err.to_string());
    true
}

/// FR-97 P1a — the withheld reason when a v4 exemption cannot be pinned: the
/// device's own cause for the lowest such address. Lowest, so the reason (the
/// withhold WARN's dedup key, and what `meshharbor status` prints) is the same on
/// every reconcile rather than following a hash set's order. Pure.
pub(super) fn exemption_withheld_reason(
    want: &HashSet<IpAddr>,
    state: &ExitRoutingState,
) -> String {
    let lowest = want
        .iter()
        .filter(|ip| ip.is_ipv4() && !state.exemptions.contains(ip))
        .min();
    match lowest {
        Some(ip) => match state.exemption_failures.get(ip) {
            Some(err) => format!("carrier-endpoint exemption for {ip} unavailable: {err}"),
            None => format!("carrier-endpoint exemption for {ip} unavailable"),
        },
        None => "carrier-endpoint exemption unavailable".to_string(),
    }
}

/// P5 exit-node — live state of default-route capture, owned by [`run`]'s loop.
#[derive(Default)]
pub(super) struct ExitRoutingState {
    /// The exit peer currently carrying our egress, once chosen + reachable +
    /// carriered + approved. `None` when inactive.
    pub(super) active_peer: Option<ObjectId>,
    /// `/32` (host) exemptions currently pinned via the original gateway — so we
    /// add only NEW ones per reconcile and revert exactly on teardown.
    pub(super) exemptions: HashSet<IpAddr>,
    /// FR-97 P1a — the cause last logged per endpoint that would not pin, so
    /// the WARN fires once per cause ([`note_exemption_failure`]) and the
    /// withheld reason can name it. Cleared for an endpoint when it pins;
    /// pruned to the endpoints still wanted.
    pub(super) exemption_failures: HashMap<IpAddr, String>,
    /// FR-97 P1a — when the pins were last re-checked against the uplink; see
    /// [`EXEMPTION_RECHECK_EVERY`].
    pub(super) exemptions_checked_at: Option<Instant>,
    /// Whether the v4 split-default (`0.0.0.0/1`+`128.0.0.0/1`) is installed.
    pub(super) split_default_installed: bool,
    /// S4 — why default routing is currently WITHHELD (the split-tunnel signal),
    /// surfaced in [`ExitNodeStatus`]. `None` when active or not configured. Also
    /// the dedup key for the withhold WARN (log only on a reason change).
    pub(super) withheld_reason: Option<String>,
    /// S3b — global IPv6 egress state: `None` = undecided; `Some(true)` = v6
    /// routes through the exit; `Some(false)` = v6 fail-closed (no v6 uplink to
    /// exempt the coordination server, or a Windows exit). Reset to `None` on
    /// teardown. Independent of `split_default_installed` (v4) per BLOCKER-1 — v6
    /// never gates v4. Also the transition-log dedup key.
    pub(super) v6_active: Option<bool>,
    /// S4b — exit-node DNS steering context + state. `dns_magic_domain`: `Some` =
    /// MagicDNS on (steer "." at the local resolver `dns_target` == self_v4, which
    /// forwards to the network upstream via the exit); `None` = MagicDNS off (steer
    /// "." at `dns_target` == the public upstream directly). `dns_bound`: the local
    /// resolver bound :53 (only gates the MagicDNS-on steer — steering at a dead
    /// resolver would blackhole ALL DNS). `dns_steered`: the "." catch-all steer is
    /// currently installed (⇒ `split_default_installed`, locked by a debug-assert).
    pub(super) dns_magic_domain: Option<String>,
    pub(super) dns_target: Option<Ipv4Addr>,
    pub(super) dns_bound: bool,
    pub(super) dns_steered: bool,
    /// The node a NAME selector first resolved to, this process lifetime.
    /// Overlay names are RELEASED when a device is removed and can be taken by a
    /// different machine, so once we have routed our whole egress through one we
    /// refuse to follow the same label elsewhere — see
    /// [`exit_selector_drifted`]. `None` for a hex selector (unambiguous) or
    /// before the first successful resolution.
    pub(super) pinned_exit: Option<ObjectId>,
    /// FR-97 P0c-3 — the netstack SOCKS5 front's port, when that is this
    /// node's device. Fixed for the runtime's life: a netstack node installs
    /// no OS routes, so the split-default lives only in the userspace router
    /// and the exit carries only what the front dials. Reported in
    /// [`ExitNodeStatus::socks5_port`].
    pub(super) socks5_port: Option<u16>,
}

/// Surface a duplicate subnet claim — NEVER silently. Two live routers approved
/// for the same CIDR is an admin error the data plane can only expose: the
/// crypto-router keeps both claims and tie-breaks deterministically (higher
/// pubkey wins), so the losing claimant's replies are RPF-denied — the field
/// 2026-08-25 signature (`rx_denied` climbing on the honest router while corp
/// egress looped through a claimant with no working uplink). The server refuses
/// NEW duplicate approvals; this catches rows that pre-date the guard.
pub(super) fn warn_subnet_conflicts(
    node_id: ObjectId,
    conflicts: &[(crate::overlay::router::Cidr, [u8; 32])],
) {
    for (cidr, other) in conflicts {
        warn!(
            peer = %node_id,
            %cidr,
            other_claimant = %crate::overlay::wg::short_key(other),
            "overlay: TWO subnet routers claim this CIDR — the deterministic \
             tie-break picks one carrier and the loser's replies RPF-deny; \
             revoke the stale approval (one live router per CIDR)"
        );
    }
}

/// The subnet routes a peer offers that this host may install, and why each
/// other one may not: a default route (exit-node routing is opt-in — a /0 is
/// never auto-installed), one overlapping a network this host is directly
/// connected to (the local network always wins: an equal or more specific
/// route would cut the host off from it), or one overlapping the overlay's own
/// `100.64.0.0/10` (it would capture traffic to peers).
pub(super) fn screen_subnets(
    subnets: &[crate::overlay::router::Cidr],
    local: &[crate::overlay::router::Cidr],
) -> (
    Vec<crate::overlay::router::Cidr>,
    Vec<(crate::overlay::router::Cidr, &'static str)>,
) {
    use crate::overlay::router::Cidr;
    let overlay = Cidr::parse("100.64.0.0/10").expect("a CIDR");
    let mut keep = Vec::new();
    let mut dropped = Vec::new();
    for &c in subnets {
        let why = if c.is_default_route() {
            Some("a default route (exit-node routing is opt-in)")
        } else if c.overlaps(&overlay) {
            Some("overlaps the overlay range 100.64.0.0/10")
        } else if local.iter().any(|l| l.overlaps(&c)) {
            Some("overlaps a network this host is connected to; the local network wins")
        } else {
            None
        };
        match why {
            Some(w) => dropped.push((c, w)),
            None => keep.push(c),
        }
    }
    (keep, dropped)
}

impl OverlayRuntime {
    /// Phase 1 — register a peer's approved subnet routes in the crypto-router
    /// (so packets to those CIDRs encapsulate to it) and install the matching OS
    /// routes via the overlay NIC. No-op when the peer advertised none.
    pub(super) async fn install_subnets(
        &self,
        wg: &mut WgDevice,
        tun: &Arc<dyn TunIo>,
        node_id: ObjectId,
        pubkey: [u8; 32],
        subnets: &[crate::overlay::router::Cidr],
    ) {
        // P5/A1 — the generic subnet-install path NEVER installs a default route.
        // Approving `0.0.0.0/0` on an exit node fans it into every peer's netmap
        // `routes`; without this filter each client would install it here
        // unconditionally — into the crypto-router's allowed_ips AND an OS default
        // route — hijacking the whole fleet's egress with zero opt-in. Default
        // routing toward a CHOSEN exit node is a separate, opt-in path
        // (split-default `/1`s + carrier-endpoint exemptions) that never flows
        // through this generic installer.
        let (filtered, dropped) = screen_subnets(subnets, &super::super::direct::local_lan_cidrs());
        for (cidr, why) in dropped {
            warn!(peer = %node_id, %cidr, why, "overlay: a peer's subnet route was not installed");
        }
        let conflicts = wg.set_peer_subnets(pubkey, &filtered);
        warn_subnet_conflicts(node_id, &conflicts);
        for c in &filtered {
            let cidr = c.to_string();
            if let Err(e) = tun.add_cidr_route(&cidr).await {
                debug!(peer = %node_id, %cidr, %e, "overlay: subnet route not installed");
            } else {
                info!(peer = %node_id, %cidr, "overlay: subnet route installed (router peer)");
            }
        }
    }

    /// P5 exit-node — reconcile default-route capture toward the chosen exit
    /// peer. No-op unless `exit_node` is configured. Idempotent + safe to call
    /// after every carrier change: it pins any newly-needed carrier exemptions
    /// FIRST, and only once EVERY required endpoint is exempted does it install
    /// the split-default — so a missing exemption can never sever the very tunnel
    /// that carries the mesh + coordination path (the load-bearing bootstrap
    /// safety, R1/D3). Withdraws the capture (egress reverts to the never-deleted
    /// OS default) if the chosen peer leaves, loses its carrier/approval, or an
    /// exemption can't be pinned.
    pub(super) async fn reconcile_exit_routing(
        &self,
        wg: &mut WgDevice,
        tun: &Arc<dyn TunIo>,
        by_node: &HashMap<ObjectId, Installed>,
        current_peers: &HashMap<ObjectId, NetmapPeer>,
        state: &mut ExitRoutingState,
    ) {
        let Some(selector) = self.exit_node.as_deref() else {
            return; // not an exit-node client — inert
        };

        // The chosen exit must be present, reachable-with-a-live-carrier, AND an
        // admin-approved exit node. Any miss → withdraw the capture, record the
        // (distinct) split-tunnel reason for `meshharbor status`, and wait.
        let (exit_id, exit_np, exit_pubkey) = match exit_readiness(selector, current_peers, by_node)
        {
            Ok(v) => v,
            Err(reason) => {
                if state.split_default_installed {
                    self.teardown_exit_routing(wg, tun, by_node, current_peers, state)
                        .await;
                }
                note_withheld(state, selector, reason);
                return;
            }
        };

        // A NAME selector that now resolves somewhere else. Overlay names are
        // released on device removal and reusable, so following the label would
        // hand this host's whole internet egress to a machine the operator never
        // chose. Fail closed and say what to do about it.
        if exit_selector_drifted(state.pinned_exit, selector, exit_id) {
            if state.split_default_installed {
                self.teardown_exit_routing(wg, tun, by_node, current_peers, state)
                    .await;
            }
            note_withheld(
                state,
                selector,
                "exit-node name now resolves to a DIFFERENT machine — set overlay_exit_node to the node-id hex to pin it",
            );
            return;
        }
        state.pinned_exit = Some(exit_id);

        // FR-97 P1a — a pin holds only while the uplink it was made through
        // does. A device that re-reads its uplink (macOS since P1a, Linux and
        // Windows since P0e) names the pins that no longer hold, through the
        // old uplink or gone from the table; each is re-pinned through the
        // current one, and one
        // that cannot be is DELETED before it is forgotten. A host route left
        // on a next hop that no longer answers black-holes the very endpoint
        // it was pinned for, the coordination server included, and once
        // untracked no teardown would ever remove it.
        let now = Instant::now();
        if !state.exemptions.is_empty() && exemption_recheck_due(state.exemptions_checked_at, now) {
            state.exemptions_checked_at = Some(now);
            let pinned: Vec<IpAddr> = state.exemptions.iter().copied().collect();
            for ip in tun.stale_host_exemptions(&pinned).await {
                match tun.add_host_exemption(ip).await {
                    Ok(()) => {
                        state.exemption_failures.remove(&ip);
                        info!(%ip, "overlay exit-node: re-pinned a carrier exemption through the current uplink");
                    }
                    Err(e) => {
                        tun.del_host_exemption(ip).await;
                        state.exemptions.remove(&ip);
                        let err = e.to_string();
                        if note_exemption_failure(state, ip, &err) {
                            warn!(%ip, %err, "overlay exit-node: a carrier exemption stopped holding and cannot be re-pinned — removed it; that family's exit egress is withheld (v6: fail-closed) until it pins again");
                        }
                    }
                }
            }
        }

        // Pin any exemptions we don't yet hold, BEFORE (re)installing the /1s —
        // the coturn set grows as relay carriers appear, so re-run on churn.
        let want = exit_exemption_set(&self.exit_server_ips, by_node);
        state.exemption_failures.retain(|ip, _| want.contains(ip));
        for ip in &want {
            if state.exemptions.contains(ip) {
                continue;
            }
            match tun.add_host_exemption(*ip).await {
                Ok(()) => {
                    state.exemptions.insert(*ip);
                    state.exemption_failures.remove(ip);
                    info!(%ip, "overlay exit-node: pinned carrier-endpoint exemption via the current uplink");
                }
                Err(e) => {
                    // FR-97 P1a — once per cause, not once per reconcile.
                    let err = e.to_string();
                    if note_exemption_failure(state, *ip, &err) {
                        warn!(%ip, %err, "overlay exit-node: FAILED to pin a carrier exemption — withholding default routing to avoid a self-wedge");
                    }
                }
            }
        }

        // BLOCKER-1 safety gate — the v4 split-default gates ONLY on the v4
        // exemptions (server A-records + coturn workers). A v6-exemption failure
        // (e.g. roomler.ai has an AAAA but this host has no v6 default route, so
        // its `/128` can't pin) must NEVER withhold v4 exit — v6 is handled
        // separately below and simply stays fail-closed. Without this split, a
        // pure-v6 feature would regress shipped v4 the moment roomler.ai gained
        // an AAAA.
        let v4_ok = want
            .iter()
            .filter(|ip| ip.is_ipv4())
            .all(|ip| state.exemptions.contains(ip));
        if !v4_ok {
            if state.split_default_installed {
                self.teardown_exit_routing(wg, tun, by_node, current_peers, state)
                    .await;
            }
            // FR-97 P1a — the device's own cause, not a guess at one.
            let reason = exemption_withheld_reason(&want, state);
            note_withheld(state, selector, &reason);
            return;
        }

        // Install (or move) the split-default toward the exit peer (idempotent):
        // the two v4 /1 halves into its WG allowed_ips + as OS routes, plus the
        // two v6 /1 halves as OS routes into the overlay NIC. The v6 halves either
        // FORWARD (v6 egress) or blackhole (fail-closed) depending on `v6_exit`,
        // set below — the routes themselves are identical either way.
        if !(state.split_default_installed && state.active_peer == Some(exit_id)) {
            let allowed = exit_peer_allowed_ips(&exit_np);
            warn_subnet_conflicts(exit_id, &wg.set_peer_subnets(exit_pubkey, &allowed));
            for cidr in SPLIT_DEFAULT_V4.iter().chain(SPLIT_DEFAULT_V6.iter()) {
                if let Err(e) = tun.add_cidr_route(cidr).await {
                    warn!(%cidr, %e, "overlay exit-node: split-default route not installed");
                }
            }
            state.split_default_installed = true;
            state.active_peer = Some(exit_id);
            state.withheld_reason = None;
            info!(peer = %exit_id, exit = %selector, "overlay exit-node: v4 default egress now routes through the exit peer");
        } else if split_default_missing(&wg.peer_subnets(&exit_pubkey)) {
            // FR-97 — a re-install of the exit peer (a carrier rebuilt, a
            // netmap update) runs the generic `install_subnets`, which REPLACES
            // its allowed-IPs with its real subnets: the `/1` halves are gone
            // while `split_default_installed` still says they are in. The OS
            // `/1`s keep routing into the TUN, every packet finds no peer, and
            // all v4 egress is black-holed until a restart. Field (tart Mac
            // exit clients, 0.4.134 and a candidate): twice, each right after
            // `dropped advertised default route(s) … peer=<the exit>`, with
            // `meshharbor status` still saying `active`. Re-asserted on every
            // reconcile, as `v6_exit` is below (MAJOR-3).
            let allowed = exit_peer_allowed_ips(&exit_np);
            warn_subnet_conflicts(exit_id, &wg.set_peer_subnets(exit_pubkey, &allowed));
            warn!(peer = %exit_id, exit = %selector, "overlay exit-node: a re-install of the exit peer had dropped its split-default — re-asserted (v4 egress was black-holed since)");
        }

        // S3b — global IPv6 egress, INDEPENDENT of v4 and re-asserted every
        // reconcile so a `remove_peer`-clear during a relay↔direct carrier
        // reinstall self-repairs (MAJOR-3). Enable only when EVERY v6 exemption
        // (the coordination server's AAAA) is pinned, so the WS-over-v6 control
        // channel stays direct (MAJOR-1). Otherwise `v6_exit=None` keeps the `::/1`
        // routes as a fail-closed blackhole — v6 never leaks, and v4 is unaffected.
        let v6_ok = want
            .iter()
            .filter(|ip| ip.is_ipv6())
            .all(|ip| state.exemptions.contains(ip));
        if v6_ok {
            wg.set_v6_exit(Some(exit_pubkey));
            if state.v6_active != Some(true) {
                state.v6_active = Some(true);
                info!(peer = %exit_id, "overlay exit-node: global IPv6 egress now routes through the exit peer");
            }
        } else {
            wg.set_v6_exit(None);
            if state.v6_active != Some(false) {
                state.v6_active = Some(false);
                warn!(exit = %selector, "overlay exit-node: IPv6 egress WITHHELD (no v6 uplink to exempt the coordination server) — v6 stays fail-closed while v4 routes through the exit");
            }
        }

        // S4b — exit-node DNS steering, coupled to the v4 split-default so DNS can
        // never route to the exit while egress doesn't. Idempotent (`!dns_steered`).
        // When MagicDNS is on, gated on a live local resolver (`dns_bound`, known
        // before the first reconcile) — steering "." at a dead :53 would blackhole
        // ALL DNS. A not-bound resolver is left unsteered (working local DNS beats a
        // blackhole) and surfaced via `dns_steered=false` in `meshharbor status`.
        // FR-97 P0c-3 — and never from a netstack node ([`dns_steer_allowed`]).
        if dns_steer_allowed(state)
            && let Some(target) = state.dns_target
        {
            if dns::steer_default_dns(target, state.dns_magic_domain.as_deref()).await {
                state.dns_steered = true;
                info!(exit = %selector, "overlay exit-node: DNS now steers all queries through the exit (no DNS leak)");
            } else {
                debug!(exit = %selector, "overlay exit-node: DNS steer command failed (resolvectl/NRPT unavailable?) — DNS NOT steered");
            }
        }
        debug_assert!(
            !state.dns_steered
                || (state.split_default_installed
                    && (state.dns_magic_domain.is_none() || state.dns_bound)),
            "exit-node DNS steered without an active split-default + a live local resolver"
        );
    }

    /// P5 exit-node — revert everything [`reconcile_exit_routing`] installed:
    /// drop the split-default OS routes, reset the (former) exit peer's WG
    /// `allowed_ips` back to its real subnets (so it keeps working as a normal /
    /// subnet-router peer), and remove the carrier exemptions. Idempotent. NB:
    /// `process::exit` paths (watchdog stall, self-update) bypass this — a
    /// synchronous pre-exit cleanup + a boot-time stale-route reconciler are the
    /// A2 follow-up (S3.5); the split-default self-heals regardless (the OS
    /// default was never deleted).
    pub(super) async fn teardown_exit_routing(
        &self,
        wg: &mut WgDevice,
        tun: &Arc<dyn TunIo>,
        by_node: &HashMap<ObjectId, Installed>,
        current_peers: &HashMap<ObjectId, NetmapPeer>,
        state: &mut ExitRoutingState,
    ) {
        if !state.split_default_installed
            && state.exemptions.is_empty()
            && state.active_peer.is_none()
            && !state.dns_steered
        {
            return;
        }
        for cidr in SPLIT_DEFAULT_V4.iter().chain(SPLIT_DEFAULT_V6.iter()) {
            tun.del_cidr_route(cidr).await;
        }
        // Reset the former exit peer's allowed_ips to its real subnets, if it's
        // still installed + in the netmap (else its Tunn is already gone).
        if let Some(id) = state.active_peer
            && let (Some(inst), Some(np)) = (by_node.get(&id), current_peers.get(&id))
        {
            let real: Vec<crate::overlay::router::Cidr> = peer_config_from_netmap(np)
                .map(|c| c.subnets)
                .unwrap_or_default()
                .into_iter()
                .filter(|c| !c.is_default_route())
                .collect();
            warn_subnet_conflicts(id, &wg.set_peer_subnets(inst.pubkey, &real));
        }
        for ip in state.exemptions.drain() {
            tun.del_host_exemption(ip).await;
        }
        // S3b — stop routing global v6 to the (now former) exit; global v6 reverts
        // to the physical uplink once the `::/1` routes above are removed.
        wg.set_v6_exit(None);
        // S4b — revert DNS steering (drop the "." catch-all). With MagicDNS on the
        // P2 suffix rule stays, so overlay names keep resolving; otherwise the
        // physical resolver is restored.
        if state.dns_steered {
            dns::unsteer_default_dns(state.dns_magic_domain.as_deref()).await;
            state.dns_steered = false;
        }
        state.split_default_installed = false;
        state.active_peer = None;
        state.v6_active = None;
        info!("overlay exit-node: default routing torn down; egress reverted to the local uplink");
    }
}

#[cfg(test)]
mod cadence_tests {
    use super::*;

    #[test]
    fn no_watch_is_always_the_2s_tick() {
        // Pre-P4 behaviour exactly — env is irrelevant without a subscription.
        assert_eq!(route_guard_cadence(false, None), ROUTE_GUARD_TICK);
        assert_eq!(
            route_guard_cadence(false, Some("300".into())),
            ROUTE_GUARD_TICK
        );
    }

    #[test]
    fn live_watch_demotes_to_heartbeat_with_env_override() {
        assert_eq!(route_guard_cadence(true, None), ROUTE_GUARD_HEARTBEAT);
        assert_eq!(
            route_guard_cadence(true, Some("2".into())),
            ROUTE_GUARD_TICK,
            "the documented operator revert to the old cadence"
        );
        assert_eq!(
            route_guard_cadence(true, Some(" 120 ".into())),
            Duration::from_secs(120)
        );
    }

    #[test]
    fn garbage_or_out_of_range_env_falls_back_to_heartbeat() {
        for bad in ["0", "1", "301", "fast", "", "-5"] {
            assert_eq!(
                route_guard_cadence(true, Some(bad.into())),
                ROUTE_GUARD_HEARTBEAT,
                "input {bad:?} must fall back, never disable the guard"
            );
        }
    }
}

#[cfg(test)]
mod subnet_screen_tests {
    use super::*;
    use crate::overlay::router::Cidr;

    #[test]
    fn a_peer_subnet_never_shadows_a_local_network_or_the_overlay() {
        let c = |s: &str| Cidr::parse(s).unwrap();
        let local = [c("192.168.1.0/24"), c("10.20.0.0/16")];
        let offered = [
            c("10.0.0.0/24"),      // a remote site: kept
            c("192.168.1.0/24"),   // the host's own LAN
            c("192.168.1.128/25"), // more specific than the LAN
            c("192.168.0.0/16"),   // covers the LAN
            c("10.20.5.0/24"),     // inside the other local network
            c("100.65.0.0/24"),    // the overlay's own space
            c("0.0.0.0/0"),        // a default route
            c("172.16.0.0/12"),    // kept
        ];
        let (keep, dropped) = screen_subnets(&offered, &local);
        assert_eq!(keep, vec![c("10.0.0.0/24"), c("172.16.0.0/12")]);
        assert_eq!(dropped.len(), 6, "{dropped:?}");
    }
}
