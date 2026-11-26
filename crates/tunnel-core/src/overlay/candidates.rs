// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — Disco-validated candidate planner for topology-aware direct paths.
//!
//! Pure state machine (no sockets, no async, no ambient clocks — every method
//! takes `now: Instant`). Replaces single-endpoint blind guessing with a
//! per-peer candidate table ordered by topology preference:
//!
//!   `Loopback` < `Subnet` < `Routed`
//!
//! Load-bearing invariants:
//!
//! 1. **Disco first, WireGuard second.** Candidates marked `requires_disco`
//!    (routed RFC 1918 LANs, same-host loopback, learned inbound hints) MUST
//!    earn a fresh source-matched authenticated Disco pong (`sender == peer`
//!    AND `src == probed_dst`) before [`CandidatePlanner::best_lan`] will hand
//!    them to WireGuard.
//! 2. **Silence is never negative evidence.** Mixed fleets include `0.4.217`
//!    nodes that do not answer cold Disco pings. When no candidate has a fresh
//!    pong yet, [`CandidatePlanner::best_lan`] falls back to the first
//!    unverified `!requires_disco` advertised candidate — byte-for-byte
//!    preserving legacy same-subnet behavior.
//! 3. **Inbound hints never auto-promote.** An authenticated inbound Disco ping
//!    from a new source address records a bounded hint only; promotion happens
//!    only after a fresh outbound ping→pong succeeds (or WireGuard itself
//!    completes a handshake).
//! 4. **Bounded probe budget.** Across all peers combined, candidate probing
//!    never exceeds [`MAX_CANDIDATE_PINGS_PER_SEC`] (50 pings/s).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use super::disco::DiscoInbound;

/// `MESHHARBORD_OVERLAY_CANDIDATE_DISCO` — default ON. Set `0`/`false`/`off`
/// to fall back strictly to legacy first-match advertised subnet selection.
pub fn candidate_disco_enabled() -> bool {
    crate::env::flag("OVERLAY_CANDIDATE_DISCO", true)
}

/// Global outbound candidate-Disco cap across all peers combined (pings/sec).
pub(crate) const MAX_CANDIDATE_PINGS_PER_SEC: usize = 50;

/// How long a source-matched Disco pong keeps a candidate freshly verified.
pub(crate) const VERIFIED_PATH_TTL: Duration = Duration::from_secs(90);

/// How long an inbound-ping / cache-seeded candidate hint stays eligible to be
/// probed before eviction.
pub(crate) const LEARNED_HINT_TTL: Duration = Duration::from_secs(300);

/// Minimum interval between consecutive candidate Disco pings to the exact same
/// `(peer, dst)` tuple.
pub(crate) const CANDIDATE_PROBE_MIN_SPACING: Duration = Duration::from_secs(4);

/// Maximum unverified inbound hints retained per peer.
const MAX_HINTS_PER_PEER: usize = 8;

/// Maximum outstanding candidate nonces tracked globally.
const MAX_PENDING_PROBES: usize = 512;

/// Expiry for unmatched pending candidate nonces.
const PENDING_PROBE_TTL: Duration = Duration::from_secs(30);

/// Diagnostic sub-kind of a `DirectTier::Lan` path.
///
/// Ordered from most-preferred to least-preferred (`Loopback < Subnet < Routed`).
/// Intentionally NOT a new `DirectTier` variant: all three share on-link
/// `DirectTier::Lan` semantics in `PathMonitor` and exit-route exemption logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum LanPathKind {
    Loopback,
    Subnet,
    Routed,
}

impl LanPathKind {
    #[allow(dead_code)] // Surfaced on PeerCarrierDebug in Commit 6.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            LanPathKind::Loopback => "loopback",
            LanPathKind::Subnet => "subnet",
            LanPathKind::Routed => "routed",
        }
    }
}

/// Which local socket carries a `DirectTier::Lan` candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum LanEgress {
    /// Per-interface socket bound to `local_ip` (`DirectCtx::socks`).
    Owned(Ipv4Addr),
    /// Shared wildcard `0.0.0.0` dialer (`DirectCtx::public_sock`), used for
    /// Mirrored WSL2 outbound LAN dialing and same-host loopback probing.
    Wildcard,
}

/// One candidate endpoint for `DirectTier::Lan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct LanCandidate {
    pub dst: SocketAddr,
    pub egress: LanEgress,
    pub kind: LanPathKind,
    /// When `true`, this candidate MUST earn a fresh source-matched Disco pong
    /// before WireGuard will dial it. When `false` (direct same-subnet
    /// advertised endpoint), silence falls back cleanly to legacy probing.
    pub requires_disco: bool,
    /// `true` when learned from an inbound authenticated Disco ping or local
    /// cache rather than the current netmap's `lan_endpoints`.
    pub learned: bool,
}

impl LanCandidate {
    pub(crate) fn subnet(local_ip: Ipv4Addr, dst: SocketAddr) -> Self {
        Self {
            dst,
            egress: LanEgress::Owned(local_ip),
            kind: LanPathKind::Subnet,
            requires_disco: false,
            learned: false,
        }
    }

    pub(crate) fn wildcard_subnet(dst: SocketAddr) -> Self {
        Self {
            dst,
            egress: LanEgress::Wildcard,
            kind: LanPathKind::Subnet,
            requires_disco: false,
            learned: false,
        }
    }

    pub(crate) fn routed(egress: LanEgress, dst: SocketAddr) -> Self {
        Self {
            dst,
            egress,
            kind: LanPathKind::Routed,
            requires_disco: true,
            learned: false,
        }
    }

    #[allow(dead_code)] // Used by same-host loopback discovery (Commit 6).
    pub(crate) fn loopback(dst: SocketAddr) -> Self {
        Self {
            dst,
            egress: LanEgress::Wildcard,
            kind: LanPathKind::Loopback,
            requires_disco: true,
            learned: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct HintEntry {
    seen_at: Instant,
    egress: LanEgress,
    kind: LanPathKind,
}

#[derive(Debug, Clone, Copy)]
struct VerifiedPath {
    rtt_ms: f64,
    last_pong: Instant,
    egress: LanEgress,
    kind: LanPathKind,
    learned: bool,
    #[allow(dead_code)] // Preserved for future observed-endpoint diagnostics.
    observed: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy)]
struct PendingProbe {
    peer: [u8; 32],
    cand: LanCandidate,
    sent_at: Instant,
}

#[derive(Debug, Default)]
struct PeerCandidates {
    hints: HashMap<SocketAddr, HintEntry>,
    verified: HashMap<SocketAddr, VerifiedPath>,
}

/// Outcome returned when a source-matched Disco pong verifies a candidate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct VerifiedHit {
    pub peer: [u8; 32],
    pub dst: SocketAddr,
    pub kind: LanPathKind,
    /// `true` if this candidate had no fresh verification before this pong.
    pub newly_verified: bool,
    pub rtt_ms: f64,
    pub observed: Option<SocketAddr>,
}

/// Pure per-peer candidate planner driven by `OverlayRuntime::disco_round` and
/// consulted by `resolve_direct_candidates_with`.
#[derive(Debug, Default)]
pub(crate) struct CandidatePlanner {
    peers: HashMap<[u8; 32], PeerCandidates>,
    pending: HashMap<[u8; 8], PendingProbe>,
    last_sent: HashMap<([u8; 32], SocketAddr), Instant>,
    budget_window_start: Option<Instant>,
    budget_used: usize,
}

impl CandidatePlanner {
    /// Record an authenticated inbound Disco ping's source address as a
    /// candidate hint ONLY. Never marks the path verified or promotable on its
    /// own — an outbound ping→pong (or WG handshake) must still prove it.
    pub(crate) fn on_inbound_ping(
        &mut self,
        peer: [u8; 32],
        src: SocketAddr,
        egress: LanEgress,
        kind: LanPathKind,
        now: Instant,
    ) {
        let entry = self.peers.entry(peer).or_default();
        entry
            .hints
            .retain(|_, h| now.saturating_duration_since(h.seen_at) <= LEARNED_HINT_TTL);
        if !entry.hints.contains_key(&src)
            && entry.hints.len() >= MAX_HINTS_PER_PEER
            && let Some(oldest) = entry
                .hints
                .iter()
                .min_by_key(|(_, h)| h.seen_at)
                .map(|(k, _)| *k)
        {
            entry.hints.remove(&oldest);
        }
        entry.hints.insert(
            src,
            HintEntry {
                seen_at: now,
                egress,
                kind,
            },
        );
    }

    /// Seed previously learned endpoints (e.g., from the signed offline netmap
    /// cache) as candidate hints requiring fresh proof before promotion.
    #[allow(dead_code)] // Consumed by netmap cache replay (Commit 8).
    pub(crate) fn seed_learned(
        &mut self,
        peer: [u8; 32],
        endpoints: &[SocketAddr],
        classify: impl Fn(SocketAddr) -> Option<(LanEgress, LanPathKind)>,
        now: Instant,
    ) {
        for &ep in endpoints {
            if let Some((egress, kind)) = classify(ep) {
                self.on_inbound_ping(peer, ep, egress, kind, now);
            }
        }
    }

    /// Consume a verified Disco pong. Matches nonce, sender pubkey, AND exact
    /// source socket address before crediting the candidate path.
    pub(crate) fn on_pong(&mut self, pong: &DiscoInbound) -> Option<VerifiedHit> {
        let pending = self.pending.remove(&pong.nonce)?;
        if pong.sender != pending.peer || pong.src != pending.cand.dst {
            // Re-insert so a spoofed/unrelated packet cannot consume the nonce.
            self.pending.insert(pong.nonce, pending);
            return None;
        }
        let rtt_ms = pong
            .at
            .saturating_duration_since(pending.sent_at)
            .as_secs_f64()
            * 1000.0;
        let peer_state = self.peers.entry(pending.peer).or_default();
        let prev = peer_state.verified.get(&pending.cand.dst).copied();
        let newly_verified = prev.is_none_or(|v| {
            pong.at.saturating_duration_since(v.last_pong) > VERIFIED_PATH_TTL
        });
        let ewma_rtt = match prev {
            Some(v) if !newly_verified => v.rtt_ms * 0.7 + rtt_ms * 0.3,
            _ => rtt_ms,
        };
        peer_state.verified.insert(
            pending.cand.dst,
            VerifiedPath {
                rtt_ms: ewma_rtt,
                last_pong: pong.at,
                egress: pending.cand.egress,
                kind: pending.cand.kind,
                learned: pending.cand.learned,
                observed: pong.observed,
            },
        );
        Some(VerifiedHit {
            peer: pending.peer,
            dst: pending.cand.dst,
            kind: pending.cand.kind,
            newly_verified,
            rtt_ms: ewma_rtt,
            observed: pong.observed,
        })
    }

    /// Select the best candidate probes to transmit for `peer` in this round,
    /// combining advertised candidates, unexpired inbound hints, and previously
    /// verified paths while enforcing per-candidate pacing and the global
    /// [`MAX_CANDIDATE_PINGS_PER_SEC`] budget.
    pub(crate) fn plan_probes(
        &mut self,
        peer: [u8; 32],
        advertised: &[LanCandidate],
        now: Instant,
    ) -> Vec<LanCandidate> {
        self.prune_budget(now);
        let remaining = MAX_CANDIDATE_PINGS_PER_SEC.saturating_sub(self.budget_used);
        if remaining == 0 {
            return Vec::new();
        }

        // Merge advertised + hints + verified, deduped by dst.
        // Lower `(kind, requires_disco)` wins on duplicate dst.
        let mut merged: HashMap<SocketAddr, (LanCandidate, bool)> = HashMap::new();
        for &c in advertised {
            merged
                .entry(c.dst)
                .and_modify(|(existing, _)| {
                    if (c.kind, c.requires_disco) < (existing.kind, existing.requires_disco) {
                        *existing = c;
                    }
                })
                .or_insert((c, false));
        }

        if let Some(p) = self.peers.get_mut(&peer) {
            p.hints
                .retain(|_, h| now.saturating_duration_since(h.seen_at) <= LEARNED_HINT_TTL);
            for (&dst, h) in &p.hints {
                let hint_cand = LanCandidate {
                    dst,
                    egress: h.egress,
                    kind: h.kind,
                    requires_disco: true,
                    learned: true,
                };
                merged.entry(dst).or_insert((hint_cand, false));
            }
            for (&dst, v) in &p.verified {
                let fresh = now.saturating_duration_since(v.last_pong) <= VERIFIED_PATH_TTL;
                let ver_cand = LanCandidate {
                    dst,
                    egress: v.egress,
                    kind: v.kind,
                    requires_disco: v.learned || v.kind != LanPathKind::Subnet,
                    learned: v.learned,
                };
                merged
                    .entry(dst)
                    .and_modify(|(_, was_ver)| {
                        if fresh {
                            *was_ver = true;
                        }
                    })
                    .or_insert((ver_cand, fresh));
            }
        }

        let mut list: Vec<(LanCandidate, bool)> = merged
            .into_values()
            .filter(|(c, _)| {
                self.last_sent.get(&(peer, c.dst)).is_none_or(|&t| {
                    now.saturating_duration_since(t) >= CANDIDATE_PROBE_MIN_SPACING
                })
            })
            .collect();

        // Priority: topology kind (Loopback < Subnet < Routed), then previously
        // verified paths, then advertised ahead of hints, then deterministic dst.
        list.sort_by(|(a, a_ver), (b, b_ver)| {
            a.kind
                .cmp(&b.kind)
                .then_with(|| b_ver.cmp(a_ver))
                .then_with(|| a.learned.cmp(&b.learned))
                .then_with(|| a.dst.cmp(&b.dst))
        });

        let chosen: Vec<LanCandidate> = list.into_iter().take(remaining).map(|(c, _)| c).collect();
        self.budget_used += chosen.len();
        chosen
    }

    /// Record that a candidate Disco ping with `nonce` was transmitted at `at`.
    pub(crate) fn record_sent(
        &mut self,
        nonce: [u8; 8],
        peer: [u8; 32],
        cand: LanCandidate,
        at: Instant,
    ) {
        self.last_sent.insert((peer, cand.dst), at);
        self.pending.insert(
            nonce,
            PendingProbe {
                peer,
                cand,
                sent_at: at,
            },
        );
        if self.pending.len() > MAX_PENDING_PROBES {
            self.pending
                .retain(|_, p| at.saturating_duration_since(p.sent_at) <= PENDING_PROBE_TTL);
        }
    }

    /// Pick the single best `DirectTier::Lan` candidate for `peer`.
    ///
    /// * When `candidate_disco_enabled()` is on and at least one egress-valid
    ///   candidate has a fresh source-matched Disco pong, pick the winner by
    ///   `(LanPathKind, ewma_rtt_ms)` (`Loopback < Subnet < Routed`, then lowest
    ///   RTT).
    /// * Otherwise (silence is never negative evidence): fall back to the first
    ///   `!requires_disco` candidate in `advertised`.
    pub(crate) fn best_lan(
        &self,
        peer: &[u8; 32],
        advertised: &[LanCandidate],
        owned_ips: &[Ipv4Addr],
        has_wildcard: bool,
        now: Instant,
    ) -> Option<LanCandidate> {
        let egress_ok = |e: LanEgress| match e {
            LanEgress::Owned(ip) => owned_ips.contains(&ip),
            LanEgress::Wildcard => has_wildcard,
        };

        if candidate_disco_enabled()
            && let Some(p) = self.peers.get(peer)
        {
            let mut best: Option<(LanCandidate, f64)> = None;
            for (&dst, v) in &p.verified {
                if now.saturating_duration_since(v.last_pong) > VERIFIED_PATH_TTL {
                    continue;
                }
                if !egress_ok(v.egress) {
                    continue;
                }
                let cand = LanCandidate {
                    dst,
                    egress: v.egress,
                    kind: v.kind,
                    requires_disco: v.learned || v.kind != LanPathKind::Subnet,
                    learned: v.learned,
                };
                let better = match best {
                    None => true,
                    Some((cur, cur_rtt)) => {
                        cand.kind < cur.kind
                            || (cand.kind == cur.kind && v.rtt_ms < cur_rtt)
                    }
                };
                if better {
                    best = Some((cand, v.rtt_ms));
                }
            }
            if let Some((cand, _)) = best {
                return Some(cand);
            }
        }

        // Fallback on silence / switch-off: first unverified same-subnet
        // advertised candidate whose egress socket exists.
        advertised
            .iter()
            .copied()
            .find(|c| !c.requires_disco && egress_ok(c.egress))
    }

    /// All currently verified LAN endpoints for `peer`, ordered best-first, for
    /// persisting into the local offline netmap cache.
    #[allow(dead_code)] // Consumed by netmap cache persistence (Commit 8).
    pub(crate) fn verified_endpoints(&self, peer: &[u8; 32], now: Instant) -> Vec<SocketAddr> {
        let Some(p) = self.peers.get(peer) else {
            return Vec::new();
        };
        let mut rows: Vec<(LanPathKind, f64, SocketAddr)> = p
            .verified
            .iter()
            .filter(|(_, v)| now.saturating_duration_since(v.last_pong) <= VERIFIED_PATH_TTL)
            .map(|(&dst, v)| (v.kind, v.rtt_ms, dst))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.total_cmp(&b.1)));
        rows.into_iter().map(|(_, _, dst)| dst).collect()
    }

    /// Local sockets were rebuilt (roam / interface change): drop all verified
    /// records and in-flight nonces measured on the retired sockets, and drop
    /// hints tied to retired owned interface IPs.
    pub(crate) fn on_local_rebuild(&mut self) {
        self.pending.clear();
        self.last_sent.clear();
        for p in self.peers.values_mut() {
            p.verified.clear();
            p.hints
                .retain(|_, h| matches!(h.egress, LanEgress::Wildcard));
        }
    }

    /// Peer left the netmap or became `backbone_only`.
    pub(crate) fn forget_peer(&mut self, peer: &[u8; 32]) {
        self.peers.remove(peer);
        self.pending.retain(|_, p| &p.peer != peer);
        self.last_sent.retain(|(pk, _), _| pk != peer);
    }

    fn prune_budget(&mut self, now: Instant) {
        match self.budget_window_start {
            Some(start) if now.saturating_duration_since(start) < Duration::from_secs(1) => {}
            _ => {
                self.budget_window_start = Some(now);
                self.budget_used = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn pong(sender: [u8; 32], nonce: [u8; 8], src: SocketAddr, at: Instant) -> DiscoInbound {
        DiscoInbound {
            sender,
            nonce,
            src,
            observed: Some(sa("192.0.2.10:43648")),
            at,
        }
    }

    #[test]
    fn answered_candidate_beats_first_match_and_ranks_by_kind_then_rtt() {
        let mut planner = CandidatePlanner::default();
        let peer = [7u8; 32];
        let t0 = Instant::now();
        let nic1 = Ipv4Addr::new(192, 168, 10, 2);
        let nic2 = Ipv4Addr::new(192, 168, 20, 2);

        let c_first = LanCandidate::subnet(nic1, sa("192.168.10.9:43648"));
        let c_second = LanCandidate::subnet(nic2, sa("192.168.20.9:43648"));
        let c_loop = LanCandidate::loopback(sa("127.0.0.1:43904"));
        let adv = vec![c_first, c_second, c_loop];

        // Before any pong, silence falls back to first !requires_disco match.
        assert_eq!(
            planner.best_lan(&peer, &adv, &[nic1, nic2], true, t0),
            Some(c_first)
        );

        // Probe all three; second subnet answers faster than first.
        planner.record_sent([1; 8], peer, c_first, t0);
        planner.record_sent([2; 8], peer, c_second, t0);
        planner.record_sent([3; 8], peer, c_loop, t0);

        planner.on_pong(&pong(
            peer,
            [1; 8],
            c_first.dst,
            t0 + Duration::from_millis(12),
        ));
        planner.on_pong(&pong(
            peer,
            [2; 8],
            c_second.dst,
            t0 + Duration::from_millis(2),
        ));
        assert_eq!(
            planner.best_lan(&peer, &adv, &[nic1, nic2], true, t0 + Duration::from_millis(20)),
            Some(c_second),
            "faster verified subnet must beat slower first-listed subnet"
        );

        // Loopback pong arrives (even with slightly higher synthetic RTT):
        // topology preference Loopback < Subnet wins.
        planner.on_pong(&pong(
            peer,
            [3; 8],
            c_loop.dst,
            t0 + Duration::from_millis(5),
        ));
        assert_eq!(
            planner.best_lan(&peer, &adv, &[nic1, nic2], true, t0 + Duration::from_millis(20)),
            Some(c_loop),
            "verified loopback beats verified subnet"
        );
    }

    #[test]
    fn silence_falls_back_to_first_unverified_subnet_and_never_selects_requires_disco() {
        let planner = CandidatePlanner::default();
        let peer = [3u8; 32];
        let t0 = Instant::now();
        let nic = Ipv4Addr::new(192, 168, 10, 2);

        let routed_only = vec![
            LanCandidate::loopback(sa("127.0.0.1:43904")),
            LanCandidate::routed(LanEgress::Owned(nic), sa("10.20.30.4:43648")),
        ];
        assert_eq!(
            planner.best_lan(&peer, &routed_only, &[nic], true, t0),
            None,
            "requires_disco candidates must never be dialed on silence"
        );

        let mixed = vec![
            LanCandidate::loopback(sa("127.0.0.1:43904")),
            LanCandidate::subnet(nic, sa("192.168.10.5:43648")),
        ];
        assert_eq!(
            planner.best_lan(&peer, &mixed, &[nic], true, t0),
            Some(mixed[1]),
            "silence falls back cleanly to legacy same-subnet candidate"
        );
    }

    #[test]
    fn inbound_ping_records_hint_only_and_never_promotes_without_source_matched_pong() {
        let mut planner = CandidatePlanner::default();
        let peer = [9u8; 32];
        let t0 = Instant::now();
        let nic = Ipv4Addr::new(192, 168, 10, 2);
        let hint_dst = sa("192.168.10.77:43648");

        planner.on_inbound_ping(peer, hint_dst, LanEgress::Owned(nic), LanPathKind::Subnet, t0);
        // Hint alone must NOT make the path selectable.
        assert_eq!(planner.best_lan(&peer, &[], &[nic], true, t0), None);

        // Planning probes DOES schedule the hint.
        let planned = planner.plan_probes(peer, &[], t0);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].dst, hint_dst);
        assert!(planned[0].requires_disco);
        assert!(planned[0].learned);

        // Sending and getting a source-matched pong verifies it.
        planner.record_sent([42; 8], peer, planned[0], t0);
        let hit = planner
            .on_pong(&pong(peer, [42; 8], hint_dst, t0 + Duration::from_millis(1)))
            .expect("source-matched pong verifies hint");
        assert!(hit.newly_verified);
        assert_eq!(
            planner.best_lan(&peer, &[], &[nic], true, t0 + Duration::from_millis(2)),
            Some(planned[0])
        );
    }

    #[test]
    fn wrong_source_or_wrong_sender_pong_is_rejected() {
        let mut planner = CandidatePlanner::default();
        let peer_a = [1u8; 32];
        let peer_b = [2u8; 32];
        let t0 = Instant::now();
        let nic = Ipv4Addr::new(192, 168, 10, 2);
        let cand = LanCandidate::routed(LanEgress::Owned(nic), sa("10.0.0.8:43648"));

        planner.record_sent([9; 8], peer_a, cand, t0);
        // Wrong source IP/port must be rejected without consuming the nonce.
        assert!(
            planner
                .on_pong(&pong(peer_a, [9; 8], sa("10.0.0.9:43648"), t0))
                .is_none()
        );
        // Wrong sender pubkey must be rejected without consuming the nonce.
        assert!(
            planner
                .on_pong(&pong(peer_b, [9; 8], cand.dst, t0))
                .is_none()
        );
        // Genuine source-matched pong still succeeds.
        assert!(
            planner
                .on_pong(&pong(peer_a, [9; 8], cand.dst, t0 + Duration::from_millis(3)))
                .is_some()
        );
    }

    #[test]
    fn global_budget_caps_probes_at_fifty_per_second() {
        let mut planner = CandidatePlanner::default();
        let t0 = Instant::now();
        let nic = Ipv4Addr::new(192, 168, 10, 2);
        let mut total = 0usize;
        for i in 0u8..20 {
            let peer = [i; 32];
            let cands: Vec<LanCandidate> = (0u16..5)
                .map(|j| {
                    LanCandidate::subnet(
                        nic,
                        SocketAddr::from(([192, 168, 10, 10 + i], 43648 + j)),
                    )
                })
                .collect();
            let planned = planner.plan_probes(peer, &cands, t0);
            for (k, c) in planned.iter().enumerate() {
                planner.record_sent([i, k as u8, 0, 0, 0, 0, 0, 0], peer, *c, t0);
            }
            total += planned.len();
        }
        assert_eq!(total, MAX_CANDIDATE_PINGS_PER_SEC);
        // Next second refills the budget.
        let refilled = planner.plan_probes(
            [99; 32],
            &[LanCandidate::subnet(nic, sa("192.168.10.200:43648"))],
            t0 + Duration::from_secs(1),
        );
        assert_eq!(refilled.len(), 1);
    }

    #[test]
    fn stale_verified_path_expires_and_owned_ip_filter_drops_retired_nic() {
        let mut planner = CandidatePlanner::default();
        let peer = [5u8; 32];
        let t0 = Instant::now();
        let old_nic = Ipv4Addr::new(192, 168, 10, 2);
        let new_nic = Ipv4Addr::new(192, 168, 20, 2);
        let cand = LanCandidate::subnet(old_nic, sa("192.168.10.9:43648"));

        planner.record_sent([7; 8], peer, cand, t0);
        planner.on_pong(&pong(peer, [7; 8], cand.dst, t0 + Duration::from_millis(1)));

        // Still fresh on old_nic, filtered out if old_nic disappeared.
        assert_eq!(
            planner.best_lan(&peer, &[], &[old_nic], true, t0 + Duration::from_secs(10)),
            Some(cand)
        );
        assert_eq!(
            planner.best_lan(&peer, &[], &[new_nic], true, t0 + Duration::from_secs(10)),
            None
        );
        // Past VERIFIED_PATH_TTL, no longer selected.
        assert_eq!(
            planner.best_lan(
                &peer,
                &[],
                &[old_nic],
                true,
                t0 + VERIFIED_PATH_TTL + Duration::from_secs(1),
            ),
            None
        );
    }
}
