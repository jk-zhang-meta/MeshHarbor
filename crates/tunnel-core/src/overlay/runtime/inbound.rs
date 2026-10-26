// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Inbound direct-handshake adoption (Phase A) — split out of `runtime.rs`
//! (rc.284, pure move). An authenticated unknown-source WG init forwarded by
//! a demux loop either re-points a known peer (restart/roam), installs the
//! exit-side accept, or is held as an inbound upgrade probe; see
//! [`OverlayRuntime::handle_direct_inbound`].

use super::*;

/// Classify an authenticated inbound init's SOURCE into a direct tier: a
/// public source matching the peer's advertised srflx is a hole-punch
/// (Phase C), any other public source is a direct-to-public dial (Phase A),
/// a private source is a same-LAN roam. A global IPv6 source is public
/// (§6 item 5: an IPv6 srflx candidate or dial). Returns `(tier,
/// is_public_src)` — the bool also gates the exit-exemption dst on install. Pure.
pub(super) fn classify_inbound_src(src: SocketAddr, peer_srflx: &[String]) -> (DirectTier, bool) {
    let is_public = match src {
        SocketAddr::V4(v4) => direct::is_public_v4(*v4.ip()),
        SocketAddr::V6(v6) => direct::is_public_v6(*v6.ip()),
    };
    let src_str = src.to_string();
    let tier = if is_public && peer_srflx.iter().any(|e| e.trim() == src_str) {
        DirectTier::Srflx
    } else if is_public {
        DirectTier::Public
    } else {
        DirectTier::Lan
    };
    (tier, is_public)
}

impl OverlayRuntime {
    /// Phase A — act on an AUTHENTICATED inbound direct handshake initiation
    /// forwarded by a demux loop ([`crate::overlay::wg::DirectInbound`]): a NAT'd client
    /// dialing our advertised public endpoint (the exit-side accept — we can't
    /// know its NAT'd source ahead of time), or a known peer that restarted /
    /// roamed onto a new ephemeral port. Installs (or re-points) that peer onto
    /// a direct carrier bound to the arriving socket + source, then feeds the
    /// very init back in so the response goes out immediately (no ~5 s wait for
    /// the initiator's retransmit).
    ///
    /// Safety: `wg.authenticate_init` cryptographically proves the sender holds
    /// the claimed key's private half (a forger copying a public key fails), so
    /// this can't be used to hijack a healthy peer's route. Only a pubkey that
    /// maps to a CURRENT netmap peer (server-ACL-authorised) is acted on. A peer
    /// suppressed on the matching tier (monitor penalty) is left on relay
    /// (anti-thrash).
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn handle_direct_inbound(
        &self,
        wg: &mut WgDevice,
        by_node: &mut HashMap<ObjectId, Installed>,
        relay: &mut Option<RelayCoordinator>,
        tun: &Arc<dyn TunIo>,
        current_peers: &HashMap<ObjectId, NetmapPeer>,
        upgrade_probes: &mut HashMap<ObjectId, UpgradeProbe>,
        relay_bq: &mut RelayBuildQueue,
        inb: crate::overlay::wg::DirectInbound,
    ) {
        let Some(pubkey) = wg.authenticate_init(&inb.packet) else {
            return; // unparseable / forged — drop
        };
        // Map the authenticated key to a current, ACL-authorised netmap peer.
        let Some(np) = current_peers
            .values()
            .find(|p| crate::overlay::decode_public(&p.wg_public_key).is_some_and(|k| k == pubkey))
        else {
            debug!(src = %inb.src, "overlay: authenticated inbound init from a non-netmap peer — dropping");
            return;
        };
        let Some(cfg) = peer_config_from_netmap(np) else {
            return;
        };
        let node_id = np.node_id;
        // MeshHarbor #21 — a cross-border peer rides its line alone: a direct
        // init from it is never answered, so no direct carrier can form.
        if cfg.backbone_only {
            debug!(peer = %node_id, src = %inb.src,
                "overlay: direct init from a backbone-only peer refused (cross-border line only)");
            return;
        }

        // Already direct on THIS exact source → nothing to change; just answer
        // the init (it may be a keepalive-driven rehandshake). Re-assert the
        // plane's reverse entry FIRST: this init reached us via ForwardInit,
        // which for a live session at this source means its `(engine, src)`
        // entry is missing (clobbered by a replacement's register+unregister,
        // or moved by a roam `direct_src` never learned about). Without the
        // re-assert, `feed_direct` routes the packet straight back through the
        // same auth → Drop → ForwardInit path — a livelock burning a DH per
        // cycle and never answering the peer.
        if wg.direct_src_of(&pubkey) == Some(inb.src) {
            wg.reassert_plane_src(&pubkey, inb.src);
            wg.feed_direct(inb.src, inb.sock.clone(), &inb.packet).await;
            return;
        }

        // A bilateral trial owns the sender. An unsolicited direct init may
        // not unilaterally overwrite its decision; existing direct receiver
        // routes above remain usable throughout make-before-break.
        if by_node
            .get(&node_id)
            .is_some_and(|p| p.pubkey == cfg.public_key && p.overlay_ip == cfg.overlay_ip)
            && self
                .path_trial_managed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .contains(&node_id)
        {
            return;
        }
        // Classify the arriving source into a tier (pure helper below).
        let now = Instant::now();
        let make_before_break = crate::overlay::direct::make_before_break_enabled();
        let (tier, is_public_src) = classify_inbound_src(inb.src, &np.srflx_endpoints);

        // P3 PR-A — the monitor's inbound decision (evidence feed + its own
        // D9 clear + eligibility gate), against the PRE-mutation incumbent.
        // Every legacy exit below records its outcome against it; legacy
        // stays authoritative.
        let incumbent = match by_node.get(&node_id) {
            Some(e) if e.is_direct => path::Incumbent::Direct(e.tier),
            Some(_) => path::Incumbent::Relay,
            None => path::Incumbent::None,
        };
        let monitor_inbound = self.shadow(|s| {
            s.mon
                .inbound_init(&node_id, tier, incumbent, make_before_break, now)
        });
        let record_inbound = |legacy: Option<path::PathAction>| {
            if let Some(m) = monitor_inbound {
                self.shadow(|s| s.compare("inbound", "inbound", &node_id, legacy, m, now));
            }
        };

        // PR-E — the monitor's inbound verdict IS the gate (anti-thrash via
        // its penalty plane; the D9 srflx override — an authenticated init
        // that traversed BOTH NATs proves the pair can punch right now — and
        // the Q evidence were already applied inside `inbound_init`).
        let refuse = monitor_inbound.map(|v| v.is_none()).unwrap_or(false);
        if refuse {
            record_inbound(None);
            return;
        }

        // rc.208 make-before-break (inbound): when enabled and the peer is
        // currently on RELAY, accept the peer's direct init as a SHADOW PROBE
        // (its own `Tunn` in `WgDevice::probes`) and answer the init on it via
        // `feed_direct`, WITHOUT tearing down the relay. `sweep_upgrade_probes`
        // cuts over only once the probe's handshake latches (proof our response
        // reached the peer AND its follow-up reached us — the reverse direction
        // works). If it never latches, the probe is dropped and the relay is
        // untouched — so a peer whose direct init reaches us over a path that
        // can't carry OUR reply (one-way) doesn't cost us the relay.
        if make_before_break {
            // A retransmitted init while we're already probing this src → just
            // answer it and let the in-flight probe keep converging.
            if wg.has_direct_probe(&pubkey) {
                record_inbound(Some(path::PathAction::Keep));
                wg.feed_direct(inb.src, inb.sock.clone(), &inb.packet).await;
                return;
            }
            // Only probe when there's a working relay to protect. A fresh peer
            // (nothing installed) or one already on direct-via-another-src falls
            // through to the destructive re-point — no relay is at risk there.
            if by_node.get(&node_id).is_some_and(|e| !e.is_direct) {
                record_inbound(Some(path::PathAction::Probe(tier)));
                self.shadow(|s| s.mon.on_probe_started(&node_id, tier, now));
                wg.ensure_direct_demux(inb.sock.clone());
                // Inbound: DON'T initiate — the peer already sent the init; we
                // answer it on the probe via `feed_direct` below.
                wg.start_direct_probe(inb.sock.clone(), pubkey, cfg.overlay_ip, inb.src, false)
                    .await;
                wg.feed_direct(inb.src, inb.sock.clone(), &inb.packet).await;
                upgrade_probes.insert(
                    node_id,
                    UpgradeProbe {
                        pubkey,
                        overlay_ip: cfg.overlay_ip,
                        dst: inb.src,
                        tier,
                        since: now,
                        // rc.276 — an ACCEPTED inbound dial held as a probe:
                        // the peer initiated the flow.
                        initiated: false,
                        local: inb.sock.local_addr().ok(),
                    },
                );
                info!(
                    peer = %node_id, src = %inb.src, ?tier,
                    "overlay: make-before-break — accepted inbound direct handshake as a PROBE (relay held)"
                );
                return;
            }
        }

        // Re-point: drop any existing carrier (relay or direct-on-another-src)
        // and any pending relay request, then install direct on the arriving
        // socket keyed by the init's source. `initiate = false` — the peer
        // already initiated; we only need to respond.
        record_inbound(Some(path::PathAction::Install(tier)));
        self.shadow(|s| s.mon.on_installed(&node_id, tier, now));
        if let Some(old) = by_node.remove(&node_id) {
            wg.remove_peer(&old.pubkey).await;
        }
        if let Some(r) = relay.as_mut() {
            r.forget(&node_id);
        }
        // rc.211 — the direct carrier installed below supersedes any relay
        // build still in flight for this peer; drop it on arrival.
        relay_bq.invalidate(&node_id);
        // rc.208 — if a stale probe lingers for this peer (feature toggled off
        // mid-session, or a direct-on-another-src re-point), discard it so it
        // can't later promote over the carrier we install here.
        if upgrade_probes.remove(&node_id).is_some() {
            // P3 PR-A — free the monitor's probe mirror without a verdict.
            self.shadow(|s| s.mon.on_probe_aborted(&node_id));
            wg.drop_direct_probe(&pubkey).await;
        }
        wg.ensure_direct_demux(inb.sock.clone());
        wg.add_direct_peer(inb.sock.clone(), pubkey, cfg.overlay_ip, inb.src, false)
            .await;
        by_node.insert(
            node_id,
            Installed {
                // rc.276 — adopted from an authenticated INBOUND dial: the
                // flow was initiated by the peer (the winhost-a-class rescue
                // path a stateful corp firewall permits); `initiated: false`
                // is base's default.
                hs_done: true, // authenticate_init proved the session
                carrier_local: inb.sock.local_addr().ok(),
                carrier_dst: Some(inb.src),
                // Any OFF-LINK public inbound source is an exit-exemption; a
                // private source is an on-link LAN roam (no exemption). The tier
                // (Srflx punch vs Public dial vs Lan roam) drives cooldown +
                // deadline.
                public_direct_dst: is_public_src.then_some(inb.src),
                ..Installed::base(pubkey, cfg.overlay_ip, tier, Instant::now())
            },
        );
        if let Err(e) = tun.add_peer_route(cfg.overlay_ip).await {
            debug!(peer = %node_id, %e, "overlay: /32 peer route not installed (ok on clean hosts)");
        }
        self.install_subnets(wg, tun, node_id, pubkey, &cfg.subnets)
            .await;
        // Answer the init that triggered this, immediately.
        wg.feed_direct(inb.src, inb.sock.clone(), &inb.packet).await;
        info!(peer = %node_id, src = %inb.src, ?tier, "overlay: accepted authenticated inbound direct handshake");
    }
}

#[cfg(test)]
mod tests {
    //! First tests in this module (2026-08-14 debt audit: 219 LOC, zero
    //! tests). The full `handle_direct_inbound` needs a live WgDevice +
    //! runtime; the extracted pure classifier is the decision logic worth
    //! locking first — a mis-tiered inbound picks the wrong deadline,
    //! cooldown, and exit-exemption.

    use super::*;

    fn srflx(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn private_source_is_a_lan_roam() {
        let (tier, public) =
            classify_inbound_src("192.168.68.4:43648".parse().unwrap(), &srflx(&[]));
        assert_eq!(tier, DirectTier::Lan);
        assert!(!public);
    }

    #[test]
    fn public_source_matching_the_peers_srflx_is_a_punch() {
        let (tier, public) = classify_inbound_src(
            "37.63.112.129:43649".parse().unwrap(),
            &srflx(&["37.63.112.129:43649", "5.9.157.221:43648"]),
        );
        assert_eq!(tier, DirectTier::Srflx);
        assert!(public);
    }

    #[test]
    fn srflx_match_tolerates_whitespace_in_the_advert() {
        let (tier, _) = classify_inbound_src(
            "37.63.112.129:43649".parse().unwrap(),
            &srflx(&[" 37.63.112.129:43649 "]),
        );
        assert_eq!(tier, DirectTier::Srflx);
    }

    #[test]
    fn a_global_ipv6_source_is_public_and_a_punch_when_advertised() {
        let src = "[2001:db8:7::5]:43648".parse().unwrap();
        assert_eq!(
            classify_inbound_src(src, &srflx(&["37.63.112.129:43649", "[2001:db8:7::5]:43648"])),
            (DirectTier::Srflx, true)
        );
        assert_eq!(classify_inbound_src(src, &srflx(&[])), (DirectTier::Public, true));
        let ula = "[fd7a:115c:a1e0::5]:43648".parse().unwrap();
        assert_eq!(classify_inbound_src(ula, &srflx(&[])).0, DirectTier::Lan, "ULA is not public");
    }

    #[test]
    fn public_source_not_in_the_advert_is_a_public_dial() {
        let (tier, public) = classify_inbound_src(
            "94.130.141.98:43648".parse().unwrap(),
            &srflx(&["37.63.112.129:43649"]),
        );
        assert_eq!(tier, DirectTier::Public);
        assert!(public);
    }
}
