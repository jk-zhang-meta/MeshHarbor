// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Disco — the out-of-tunnel carrier echo (C1: responder only).
//!
//! # Why this exists, and why it is NOT the rc.346 data-probe
//!
//! Measuring whether a *path* delivers data is the one thing the liveness
//! stack could never do honestly. Every passive signal is indirect: WG
//! handshakes are small and retried, so they complete over a path that drops
//! most bulk data (field 2026-08-11: `tx=122 rx=58`, `ping` 100 % loss, and
//! the carrier still looked healthy to every reaper).
//!
//! rc.346 tried to fix that with an **in-tunnel** probe — an inner ICMP /
//! marked IP packet that the PEER'S OS or overlay engine had to answer. That
//! made the measurement depend on the peer's operating system, its firewall,
//! and a capability negotiation, and it shipped default-ON in the same release
//! that introduced the responder, so nothing in the fleet could answer yet: it
//! demoted healthy 0 ms carriers within minutes.
//!
//! Disco is the Tailscale-shaped correction. It rides **outside** the WG
//! tunnel, as its own datagram shape on the carrier socket the two daemons
//! already share, and it is answered **unconditionally by the daemon** — no
//! OS, no firewall rule, no tunnel session, no capability bit. It measures the
//! PATH, not the peer's host stack.
//!
//! # Deployment rule this module encodes
//!
//! **A prober that punishes non-answer must ship at least one release AFTER
//! the responder is fleet-wide.** C1 therefore ships the responder ONLY —
//! this node answers pings, and asks nothing. Nothing reads the answers yet.
//! The prober (C2) and scoring (C3) come later, once every peer can reply.
//!
//! # Frame
//!
//! ```text
//!  0   magic[8]      "RMDISCO1"
//!  8   kind[1]       1 = ping, 2 = pong
//!  9   reserved[1]   0
//! 10   nonce[8]      echoed verbatim in the pong
//! 18   sender_pub[32] the sender's WG static public key
//! 50   observed[19]  the source the RESPONDER saw (family|16-byte addr|port);
//!                    all-zero in a ping. A free srflx observation for C2.
//! 69   mac[16]       HMAC-SHA256(X25519(self_secret, peer_public), bytes[0..69])[..16]
//! ```
//! Total 85 bytes, fixed.
//!
//! **Shape disjointness (load-bearing — a false match steals a live datagram
//! and blacks out the mesh):** WireGuard is `pkt[0] ∈ 1..=4 && pkt[1..4] ==
//! [0,0,0]` ([`super::wg::is_wg_shaped`]) and STUN is `len ≥ 20 && pkt[4..8]
//! == 0x2112A442` ([`crate::transport::stun::has_stun_cookie`]). `"RMDISCO1"`
//! starts with `0x52` (∉ 1..=4) and carries `"SCO1"` at bytes 4..8 (≠ the STUN
//! cookie), so the three shapes are pairwise disjoint by construction. Locked
//! by [`tests::disco_shape_is_disjoint_from_wg_and_stun`].

use std::net::{IpAddr, SocketAddr};

use boringtun::x25519::{PublicKey, StaticSecret};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub(crate) const MAGIC: &[u8; 8] = b"RMDISCO1";
pub(crate) const KIND_PING: u8 = 1;
pub(crate) const KIND_PONG: u8 = 2;
/// F2 — "I take standby copies" (`derp::STANDBY_MAGIC`), sent on a direct
/// carrier. Kind 0x10 stays clear of the follow-control kinds 3–6. A receiver
/// older than F2 drops it as an unknown kind, so it is safe to send to anyone.
pub(crate) const KIND_STANDBY_HELLO: u8 = 0x10;
/// F2 — how long a peer's `STANDBY_HELLO` counts (it re-sends every 20 s).
pub(crate) const STANDBY_HELLO_TTL: std::time::Duration = std::time::Duration::from_secs(90);

/// F2 — peers whose AUTHENTICATED `STANDBY_HELLO` arrived, by static key,
/// with when. Process-wide because every recv seam verifies through
/// [`classify`], and a static key names one peer in one org.
static STANDBY_PEERS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<[u8; 32], std::time::Instant>>,
> = std::sync::LazyLock::new(Default::default);

/// F2 — does `peer` take standby copies (a fresh authenticated hello)?
pub(crate) fn standby_capable(peer: &[u8; 32], now: std::time::Instant) -> bool {
    STANDBY_PEERS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(peer)
        .is_some_and(|at| now.saturating_duration_since(*at) < STANDBY_HELLO_TTL)
}

/// F2 — our `STANDBY_HELLO` to `peer`.
pub(crate) fn standby_hello(peer: &[u8; 32], secret: &StaticSecret, public: &PublicKey) -> Vec<u8> {
    let shared = shared_secret(secret, &PublicKey::from(*peer));
    build(KIND_STANDBY_HELLO, [0; 8], public.as_bytes(), None, &shared)
}

const OFF_KIND: usize = 8;
const OFF_NONCE: usize = 10;
const OFF_SENDER: usize = 18;
const OFF_OBSERVED: usize = 50;
const OFF_MAC: usize = 69;
/// Fixed frame length. A reply is exactly this long too, so the responder can
/// never amplify (reply bytes == request bytes).
pub(crate) const FRAME_LEN: usize = 85;

/// A parsed, MAC-verified disco frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Disco {
    pub kind: u8,
    pub nonce: [u8; 8],
    pub sender: [u8; 32],
    /// The source the responder observed, `None` in a ping (all-zero).
    pub observed: Option<SocketAddr>,
}

/// Cheap pre-filter: does this datagram even look like disco? Checked before
/// any crypto so a junk flood costs a memcmp, not a DH.
pub(crate) fn is_disco_shaped(pkt: &[u8]) -> bool {
    pkt.len() == FRAME_LEN && &pkt[..8] == MAGIC.as_slice()
}

/// The sender's claimed static public key, readable WITHOUT verifying the MAC.
/// The caller uses it to decide whether this is a peer it knows (a cheap map
/// lookup) before spending an X25519 — an unknown key is dropped for free, so
/// a flood of forged frames can't burn CPU.
pub(crate) fn claimed_sender(pkt: &[u8]) -> Option<[u8; 32]> {
    if !is_disco_shaped(pkt) {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&pkt[OFF_SENDER..OFF_SENDER + 32]);
    Some(k)
}

/// Verify + parse. `shared` is the X25519 static-static DH with the claimed
/// sender (the caller resolves and caches it). Returns `None` on any shape or
/// MAC failure — this is the authentication boundary.
pub(crate) fn parse(pkt: &[u8], shared: &[u8; 32]) -> Option<Disco> {
    if !is_disco_shaped(pkt) {
        return None;
    }
    let kind = pkt[OFF_KIND];
    if kind != KIND_PING && kind != KIND_PONG && kind != KIND_STANDBY_HELLO {
        return None;
    }
    if !mac_ok(pkt, shared) {
        return None;
    }
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&pkt[OFF_NONCE..OFF_NONCE + 8]);
    let mut sender = [0u8; 32];
    sender.copy_from_slice(&pkt[OFF_SENDER..OFF_SENDER + 32]);
    Some(Disco {
        kind,
        nonce,
        sender,
        observed: decode_observed(&pkt[OFF_OBSERVED..OFF_OBSERVED + 19]),
    })
}

/// Build a frame. `observed` is `Some` only in a pong.
pub(crate) fn build(
    kind: u8,
    nonce: [u8; 8],
    sender_pub: &[u8; 32],
    observed: Option<SocketAddr>,
    shared: &[u8; 32],
) -> Vec<u8> {
    let mut p = vec![0u8; FRAME_LEN];
    p[..8].copy_from_slice(MAGIC.as_slice());
    p[OFF_KIND] = kind;
    p[OFF_NONCE..OFF_NONCE + 8].copy_from_slice(&nonce);
    p[OFF_SENDER..OFF_SENDER + 32].copy_from_slice(sender_pub);
    if let Some(sa) = observed {
        encode_observed(&mut p[OFF_OBSERVED..OFF_OBSERVED + 19], sa);
    }
    let tag = mac(&p[..OFF_MAC], shared);
    p[OFF_MAC..].copy_from_slice(&tag);
    p
}

/// The static-static X25519 shared secret with `peer_public`. Deterministic,
/// so the caller may cache it per peer.
pub(crate) fn shared_secret(secret: &StaticSecret, peer_public: &PublicKey) -> [u8; 32] {
    secret.diffie_hellman(peer_public).to_bytes()
}

// A ping-only `respond()` helper used to live here, wrapping `classify` and
// discarding everything that was not an Answer. It has been DELETED rather
// than kept for convenience: the device-demux seam switched on it, so every
// PONG that arrived there was silently dropped, and any path served by that
// socket measured `loss=100%` while carrying WG data perfectly (fleet-host-2→fleet-host-1
// on grox, 0 % by ping, 2026-08-12). A helper that answers half the protocol
// is a trap for the next seam; with it gone, a caller must handle the whole
// [`Verdict`] and the two seams cannot drift apart again.

/// What a recv loop should do with a disco datagram.
pub(crate) enum Verdict {
    /// A verified PING — send these bytes back to the source.
    Answer(Vec<u8>),
    /// A verified PONG — hand it to the prober's sink (C2).
    Pong(DiscoInbound),
    /// Not ours / unknown sender / bad MAC ⇒ drop silently.
    Ignore,
}

/// Verify a disco datagram once and say what to do with it. Both recv seams
/// (device demux + carrier plane) call exactly this, so ping-answering and
/// pong-routing can never diverge between them.
pub(crate) fn classify(
    pkt: &[u8],
    src: SocketAddr,
    secret: &StaticSecret,
    public: &PublicKey,
    known_peer: impl Fn(&[u8; 32]) -> bool,
) -> Verdict {
    let Some(sender) = claimed_sender(pkt) else {
        return Verdict::Ignore;
    };
    // Known-peer check BEFORE any crypto: a forged flood costs a map lookup.
    if !known_peer(&sender) {
        return Verdict::Ignore;
    }
    let shared = shared_secret(secret, &PublicKey::from(sender));
    let Some(d) = parse(pkt, &shared) else {
        return Verdict::Ignore;
    };
    match d.kind {
        KIND_PING => Verdict::Answer(build(
            KIND_PONG,
            d.nonce,
            public.as_bytes(),
            Some(src),
            &shared,
        )),
        KIND_PONG => Verdict::Pong(DiscoInbound {
            sender: d.sender,
            nonce: d.nonce,
            src,
            // Stamp on the receive path, while we are still holding the
            // packet — see `DiscoInbound::at`.
            at: std::time::Instant::now(),
        }),
        KIND_STANDBY_HELLO => {
            let mut peers = STANDBY_PEERS.lock().unwrap_or_else(|e| e.into_inner());
            peers.insert(d.sender, std::time::Instant::now());
            Verdict::Ignore
        }
        _ => Verdict::Ignore,
    }
}

fn mac(body: &[u8], shared: &[u8; 32]) -> [u8; 16] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(shared).expect("hmac accepts any key length");
    m.update(body);
    let out = m.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&out[..16]);
    tag
}

/// Constant-time-ish compare via the MAC crate's own verifier.
fn mac_ok(pkt: &[u8], shared: &[u8; 32]) -> bool {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(shared).expect("hmac accepts any key length");
    m.update(&pkt[..OFF_MAC]);
    let out = m.finalize().into_bytes();
    out[..16] == pkt[OFF_MAC..]
}

fn encode_observed(dst: &mut [u8], sa: SocketAddr) {
    match sa.ip() {
        IpAddr::V4(v4) => {
            dst[0] = 4;
            dst[1..5].copy_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            dst[0] = 6;
            dst[1..17].copy_from_slice(&v6.octets());
        }
    }
    dst[17..19].copy_from_slice(&sa.port().to_be_bytes());
}

fn decode_observed(src: &[u8]) -> Option<SocketAddr> {
    let port = u16::from_be_bytes([src[17], src[18]]);
    match src[0] {
        4 => {
            let mut o = [0u8; 4];
            o.copy_from_slice(&src[1..5]);
            Some(SocketAddr::from((o, port)))
        }
        6 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&src[1..17]);
            Some(SocketAddr::from((o, port)))
        }
        _ => None,
    }
}

/// C2 — a verified PONG handed from a recv loop to the prober. Carries the
/// path it arrived on so the prober can attribute the sample to the exact
/// (local socket, remote endpoint) pair it probed.
#[derive(Debug, Clone)]
pub struct DiscoInbound {
    /// The peer that answered (its WG static public key).
    pub sender: [u8; 32],
    /// The nonce being answered — matched against the outstanding round.
    pub nonce: [u8; 8],
    /// Where the pong came FROM (the remote end of the measured path).
    pub src: SocketAddr,
    /// When the pong was AUTHENTICATED on the carrier socket — not when the
    /// prober got round to reading it.
    ///
    /// The prober drains this channel once per 5 s round, so measuring RTT at
    /// drain time charges every sample the full distance to the next tick.
    /// Field 2026-08-12: every path reported `rtt=5000ms` — exactly one tick —
    /// including paths answering every single probe at `loss=0%`. Loss was
    /// unaffected (the pong is still credited to its nonce), which is what
    /// made the RTT obviously wrong rather than plausibly bad.
    pub at: std::time::Instant,
}

// ───────────────────────────── C2: the path table ─────────────────────────
//
// The measurement C1 made possible. Keyed by (peer, local socket, remote
// endpoint) — the granularity the tier model structurally lacks, where every
// advertised endpoint of a peer collapses into ONE `TierState` and is
// disambiguated only by a strike-count rotation.
//
// Two rules are load-bearing, both paid for in the field:
//
// 1. **Silence is never negative evidence.** A missing pong lowers nothing.
//    A path loses only by DECAYING while rivals accumulate fresh pongs. This
//    is what makes a mixed fleet safe with no capability bit: a peer that
//    cannot answer simply never wins that path, instead of being punished.
// 2. **Loss is a WINDOWED RATE, never a consecutive-miss count.** rc.346's
//    reaper counted consecutive misses and could therefore only catch a
//    FULLY dead path: on the live grox carrier (~20 % delivery, `tx=17..22
//    rx=3..4`) roughly one probe in five got through and reset the counter,
//    so it demoted nothing. A rate sees 80 % loss for what it is.

/// How many recent rounds the loss rate is computed over. At the steady 30 s
/// cadence that is ~8 minutes of history; at the 5 s discovery cadence, ~80 s.
pub(crate) const LOSS_WINDOW: u32 = 16;

/// One measured path to one peer.
///
/// `allow(dead_code)`: the prober that drives this lands in the NEXT commit
/// (C2b). Same convention as the repo's defensive-enum rule — the allow is
/// temporary and must be removed when the consumer lands. Shipping the table
/// first keeps the measurement primitives reviewable on their own, and they
/// are already locked by `loss_is_a_rate_so_a_lossy_path_cannot_hide`.
#[derive(Debug, Clone, Default)]
pub(crate) struct PathStats {
    /// Rounds issued into the window (saturating at [`LOSS_WINDOW`]).
    sent: u32,
    /// Rounds answered within the window.
    answered: u32,
    /// Smoothed round-trip, `None` until the first pong.
    pub rtt_ms: Option<f64>,
    /// W6 — the last [`LOSS_WINDOW`] raw RTT samples, oldest first. The
    /// EWMA above hides spikes by design; judging "large ping variability"
    /// (field 2026-08-14: winhost-a→fleet-host-2 42 ms baseline, 374 ms spikes on a
    /// TCP relay) needs the tail of the distribution, not the mean.
    recent_rtts: std::collections::VecDeque<f64>,
    /// The nonce of the round currently outstanding, if any.
    pending: Option<[u8; 8]>,
}

impl PathStats {
    /// Record that a round was issued with `nonce`. A still-outstanding
    /// previous round counts as unanswered — that is the ONLY way `sent`
    /// outpaces `answered`, and it is a rate input, never a death.
    pub(crate) fn on_sent(&mut self, nonce: [u8; 8]) {
        self.sent = (self.sent + 1).min(LOSS_WINDOW);
        if self.sent >= LOSS_WINDOW {
            // Slide: keep the ratio, halve both so recent rounds dominate.
            self.sent = self.sent.div_ceil(2);
            self.answered = self.answered.div_ceil(2);
        }
        self.pending = Some(nonce);
    }

    /// Record a pong. Only a MATCHING nonce counts — a late pong from an
    /// earlier round is ignored rather than credited to the current one.
    pub(crate) fn on_pong(&mut self, nonce: [u8; 8], rtt_ms: f64) {
        if self.pending != Some(nonce) {
            return;
        }
        self.pending = None;
        self.answered = (self.answered + 1).min(self.sent);
        // EWMA, α = 0.3 — fast enough to track a real path change, slow
        // enough that one scheduling hiccup doesn't dominate.
        self.rtt_ms = Some(match self.rtt_ms {
            Some(prev) => prev * 0.7 + rtt_ms * 0.3,
            None => rtt_ms,
        });
        self.recent_rtts.push_back(rtt_ms);
        if self.recent_rtts.len() > LOSS_WINDOW as usize {
            self.recent_rtts.pop_front();
        }
    }

    /// W6 — the tail of the windowed RTT distribution: `(p95, max)` over
    /// the last [`LOSS_WINDOW`] answered rounds. `None` until 4 samples —
    /// an unmeasured path must never read as a spiky one.
    pub(crate) fn rtt_tail(&self) -> Option<(f64, f64)> {
        if self.recent_rtts.len() < 4 {
            return None;
        }
        let mut v: Vec<f64> = self.recent_rtts.iter().copied().collect();
        v.sort_by(f64::total_cmp);
        let idx = ((v.len() as f64 * 0.95).ceil() as usize).saturating_sub(1);
        Some((v[idx.min(v.len() - 1)], v[v.len() - 1]))
    }

    /// Fraction of windowed rounds that went unanswered, 0.0..=1.0. `None`
    /// until the window has enough rounds to mean anything — an unmeasured
    /// path must never look like a bad one.
    pub(crate) fn loss(&self) -> Option<f64> {
        if self.sent < 4 {
            return None;
        }
        Some(1.0 - (self.answered as f64 / self.sent as f64))
    }
}

/// One measured path, as reported out of the [`Prober`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct PathSample {
    pub peer: [u8; 32],
    pub dst: SocketAddr,
    /// Windowed loss 0.0..=1.0; `None` until enough rounds to judge — an
    /// unmeasured path must never read as a bad one.
    pub loss: Option<f64>,
    pub rtt_ms: Option<f64>,
    /// W6 — 95th percentile of the raw RTT window (spike visibility; the
    /// EWMA `rtt_ms` smooths spikes away by design).
    pub rtt_p95_ms: Option<f64>,
    /// W6 — worst raw RTT in the window.
    pub rtt_max_ms: Option<f64>,
}

/// C2 — the prober: one round per peer per tick over that peer's CURRENT
/// direct-carrier path, plus the windowed table of what came back.
///
/// Deliberately measurement-only. Nothing here demotes, penalises, or ranks —
/// `paths()` is read by the LocalAPI and the summary log, and by nothing that
/// makes a routing decision. Scoring (C3) and authority (C6) are separate
/// stages behind their own flags, precisely so a bug here cannot move traffic.
#[derive(Default)]
pub(crate) struct Prober {
    /// (peer pubkey, remote endpoint) → windowed stats.
    table: std::collections::HashMap<([u8; 32], SocketAddr), PathStats>,
    /// Outstanding rounds: nonce → (peer, path, sent-at).
    pending: std::collections::HashMap<[u8; 8], ([u8; 32], SocketAddr, std::time::Instant)>,
    /// Nonce source. Seeded RANDOMLY per prober, not from zero: two org
    /// engines on one host both mint rounds, and when they share a peer at
    /// the SAME endpoint (the multi-org norm — e.g. one relay in both orgs)
    /// a from-zero counter makes their nonces collide, so a pong for one
    /// engine.s round validates against the other.s pending entry and yields
    /// a garbage RTT. Field 2026-08-12: `rtt=5000ms` on a 40 ms path.
    seq: u64,
}

impl Prober {
    /// A prober with a randomly-seeded nonce space (see `seq`).
    pub(crate) fn new() -> Self {
        use rand::RngCore;
        Self {
            seq: rand::rng().next_u64(),
            ..Default::default()
        }
    }

    /// Build the next ping for `peer` and remember the round. The caller
    /// sends the bytes over that peer's carrier and reports the dst back via
    /// [`Self::sent`].
    pub(crate) fn next_ping(
        &mut self,
        peer: &[u8; 32],
        secret: &StaticSecret,
        public: &PublicKey,
    ) -> ([u8; 8], Vec<u8>) {
        self.seq = self.seq.wrapping_add(1);
        let nonce = self.seq.to_be_bytes();
        let shared = shared_secret(secret, &PublicKey::from(*peer));
        (
            nonce,
            build(KIND_PING, nonce, public.as_bytes(), None, &shared),
        )
    }

    /// Record that the round actually went out to `dst`.
    pub(crate) fn sent(&mut self, peer: [u8; 32], dst: SocketAddr, nonce: [u8; 8]) {
        self.sent_at(peer, dst, nonce, std::time::Instant::now());
    }

    /// Timestamp BEFORE the actual carrier write, so relay egress queueing
    /// is measured just like direct egress queueing, rather than discounted.
    pub(crate) fn sent_at(
        &mut self,
        peer: [u8; 32],
        dst: SocketAddr,
        nonce: [u8; 8],
        at: std::time::Instant,
    ) {
        self.table.entry((peer, dst)).or_default().on_sent(nonce);
        self.pending.insert(nonce, (peer, dst, at));
        // Bound the pending map: a path that never answers would otherwise
        // accumulate one entry per round forever.
        if self.pending.len() > 512 {
            let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(120);
            self.pending.retain(|_, (_, _, at)| *at > cutoff);
        }
    }

    /// Record a verified pong. Unmatched nonces (a late reply, or a path we
    /// never probed) are ignored rather than credited.
    pub(crate) fn on_pong(&mut self, p: &DiscoInbound) {
        let Some((peer, dst, at)) = self.pending.remove(&p.nonce) else {
            return;
        };
        // The nonce alone is not enough: a pong must come from the PEER and
        // the PATH we probed, or the sample would be attributed to the wrong
        // path (and a peer could credit a path it does not actually serve).
        if p.sender != peer || p.src != dst {
            return;
        }
        // Measure to when the pong ARRIVED, not to now: this channel is
        // drained once per round, so `at.elapsed()` would charge every sample
        // the full distance to the next tick. See `DiscoInbound::at`.
        let rtt = p.at.saturating_duration_since(at).as_secs_f64() * 1000.0;
        if let Some(s) = self.table.get_mut(&(peer, dst)) {
            s.on_pong(p.nonce, rtt);
        }
    }

    /// Every measured path.
    pub(crate) fn paths(&self) -> Vec<PathSample> {
        self.table
            .iter()
            .map(|((peer, dst), s)| {
                let tail = s.rtt_tail();
                PathSample {
                    peer: *peer,
                    dst: *dst,
                    loss: s.loss(),
                    rtt_ms: s.rtt_ms,
                    rtt_p95_ms: tail.map(|t| t.0),
                    rtt_max_ms: tail.map(|t| t.1),
                }
            })
            .collect()
    }

    /// A compact, operator-readable digest of what the paths measure right
    /// now: how many are measured, and the WORST few by loss. This is C2's
    /// entire observable — the stage deliberately produces a log line and a
    /// LocalAPI field, and no behaviour.
    ///
    /// `None` until at least one path has enough rounds to judge, so a
    /// freshly-started prober says nothing rather than something misleading.
    /// `label` names the peer behind a path — pass the overlay IP. Without it
    /// the digest is endpoint-only, and attributing a loss figure to a named
    /// host means reverse-engineering public IPs by hand (2026-08-12: working
    /// out which of four Hetzner addresses was buildhost took longer than reading
    /// the number). The overlay IP also discriminates the ORG for free, since
    /// each org engine logs its own line with no other marker: `100.65.4.x`
    /// is one org's block, `100.65.0.x` the other's.
    pub(crate) fn summary(
        &self,
        label: impl Fn(&[u8; 32]) -> Option<std::net::Ipv4Addr>,
    ) -> Option<String> {
        let mut worst: Vec<(f64, PathSample)> = self
            .paths()
            .into_iter()
            .filter_map(|p| p.loss.map(|l| (l, p)))
            .collect();
        if worst.is_empty() {
            return None;
        }
        let measured = worst.len();
        worst.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        let lossy = worst.iter().filter(|(l, _)| *l > 0.1).count();
        let top: Vec<String> = worst
            .iter()
            .take(3)
            .map(|(l, p)| {
                let who = match label(&p.peer) {
                    Some(ip) => format!("{ip}@{}", p.dst),
                    None => format!("{}", p.dst),
                };
                let rtt = match p.rtt_ms {
                    Some(r) => format!("{r:.0}"),
                    None => "—".to_string(),
                };
                // W6 — the p95/max tail names the spiky-but-low-mean path
                // (TCP-relay head-of-line stalls) that the EWMA alone hides.
                match (p.rtt_p95_ms, p.rtt_max_ms) {
                    (Some(p95), Some(max)) => format!(
                        "{who} loss={:.0}% rtt={rtt}ms p95={p95:.0} max={max:.0}",
                        l * 100.0
                    ),
                    _ => format!("{who} loss={:.0}% rtt={rtt}ms", l * 100.0),
                }
            })
            .collect();
        Some(format!(
            "paths={} lossy={lossy} worst=[{}]",
            measured,
            top.join(", ")
        ))
    }

    /// Keep only the paths we are STILL probing for `peer`.
    ///
    /// A2 generalised this from a single `keep` to a set: a peer parked on
    /// relay is probed on several CANDIDATE endpoints at once (lan / public /
    /// srflx), and pruning to one would throw away all but the last every
    /// round, so no candidate would ever accumulate enough rounds to earn a
    /// loss figure. An installed direct carrier simply passes a one-element
    /// set, which is the old behaviour exactly.
    pub(crate) fn retain_paths(&mut self, peer: &[u8; 32], keep: &[SocketAddr]) {
        self.table.retain(|(p, d), _| p != peer || keep.contains(d));
        self.pending
            .retain(|_, (p, d, _)| p != peer || keep.contains(d));
    }

    /// Drop state for a peer that left the mesh.
    pub(crate) fn forget(&mut self, peer: &[u8; 32]) {
        self.table.retain(|(p, _), _| p != peer);
        self.pending.retain(|_, (p, _, _)| p != peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::stun::has_stun_cookie;

    fn kp() -> (StaticSecret, PublicKey) {
        let kp = super::super::WgKeypair::generate();
        (kp.secret, kp.public)
    }

    /// THE load-bearing invariant: a disco frame must never be mistaken for
    /// WireGuard or STUN (a false match steals a live datagram and blacks out
    /// the mesh), and neither may be mistaken for disco.
    #[test]
    fn disco_shape_is_disjoint_from_wg_and_stun() {
        let (a_s, a_p) = kp();
        let (_b_s, b_p) = kp();
        let sh = shared_secret(&a_s, &b_p);
        let f = build(KIND_PING, [7u8; 8], a_p.as_bytes(), None, &sh);

        assert_eq!(f.len(), FRAME_LEN);
        assert!(is_disco_shaped(&f));
        assert!(
            !super::super::wg::is_wg_shaped(&f),
            "disco must never look like WireGuard"
        );
        assert!(
            !has_stun_cookie(&f),
            "disco must never look like STUN (bytes 4..8 != magic cookie)"
        );

        // …and every WG message type must not look like disco. WG is
        // type byte 1..=4 followed by three zero bytes.
        for t in 1u8..=4 {
            let mut wg = vec![0u8; FRAME_LEN];
            wg[0] = t;
            assert!(super::super::wg::is_wg_shaped(&wg));
            assert!(!is_disco_shaped(&wg), "WG type {t} must not parse as disco");
        }
        // A STUN Binding response shape must not look like disco either.
        let mut stun = vec![0u8; FRAME_LEN];
        stun[0] = 0x01;
        stun[4..8].copy_from_slice(&0x2112_A442u32.to_be_bytes());
        assert!(has_stun_cookie(&stun));
        assert!(!is_disco_shaped(&stun));
    }

    #[test]
    fn ping_pong_roundtrip_and_mac_rejects_forgery() {
        let (a_s, a_p) = kp();
        let (b_s, b_p) = kp();
        // A→B share == B→A share (static-static DH is symmetric).
        let ab = shared_secret(&a_s, &b_p);
        let ba = shared_secret(&b_s, &a_p);
        assert_eq!(ab, ba);

        let ping = build(KIND_PING, [9u8; 8], a_p.as_bytes(), None, &ab);
        let got = parse(&ping, &ba).expect("B verifies A's ping");
        assert_eq!(got.kind, KIND_PING);
        assert_eq!(got.nonce, [9u8; 8]);
        assert_eq!(&got.sender, a_p.as_bytes());
        assert_eq!(got.observed, None, "a ping carries no observation");
        assert_eq!(claimed_sender(&ping).unwrap(), *a_p.as_bytes());

        // The pong echoes the nonce and reports the observed source.
        let obs: SocketAddr = "203.0.113.9:41000".parse().unwrap();
        let pong = build(KIND_PONG, got.nonce, b_p.as_bytes(), Some(obs), &ba);
        assert_eq!(pong.len(), ping.len(), "a pong must never amplify");
        let back = parse(&pong, &ab).expect("A verifies B's pong");
        assert_eq!(back.kind, KIND_PONG);
        assert_eq!(back.nonce, [9u8; 8]);
        assert_eq!(back.observed, Some(obs));

        // Forgery: a third party's DH does not verify.
        let (c_s, _c_p) = kp();
        let ca = shared_secret(&c_s, &a_p);
        assert!(parse(&ping, &ca).is_none(), "wrong key must not verify");

        // Any bit flip in the body invalidates the MAC.
        let mut tampered = ping.clone();
        tampered[OFF_NONCE] ^= 0x01;
        assert!(parse(&tampered, &ba).is_none(), "tamper must not verify");

        // Wrong length / wrong magic / unknown kind are rejected pre-crypto.
        assert!(!is_disco_shaped(&ping[..FRAME_LEN - 1]));
        let mut bad_kind = ping.clone();
        bad_kind[OFF_KIND] = 9;
        assert!(parse(&bad_kind, &ba).is_none());
    }

    /// A2 — a peer parked on relay is probed on SEVERAL candidate endpoints at
    /// once, so the prune must keep a set. The failure mode this guards is
    /// silent and total: pruning to one dst per peer (the pre-A2 behaviour)
    /// throws away all but the last candidate every round, so no candidate
    /// ever accumulates enough rounds to earn a loss figure and every one of
    /// them reads `None` — indistinguishable from "not probed yet" forever.
    #[test]
    fn retain_paths_keeps_every_candidate_still_being_probed() {
        let mut p = Prober::new();
        let peer = [7u8; 32];
        let other = [9u8; 32];
        let lan: SocketAddr = "192.168.68.129:43881".parse().unwrap();
        let public: SocketAddr = "37.63.112.129:43881".parse().unwrap();
        let srflx: SocketAddr = "37.63.112.129:51000".parse().unwrap();
        let gone: SocketAddr = "10.0.0.9:1234".parse().unwrap();

        for (i, dst) in [lan, public, srflx, gone].into_iter().enumerate() {
            p.sent(peer, dst, [i as u8; 8]);
        }
        p.sent(other, lan, [99u8; 8]);

        // Still probing three of the four.
        p.retain_paths(&peer, &[lan, public, srflx]);

        let dsts: Vec<SocketAddr> = p
            .paths()
            .iter()
            .filter(|s| s.peer == peer)
            .map(|s| s.dst)
            .collect();
        assert_eq!(
            dsts.len(),
            3,
            "all three live candidates must survive: {dsts:?}"
        );
        for d in [lan, public, srflx] {
            assert!(dsts.contains(&d), "{d} was pruned while still being probed");
        }
        assert!(
            !dsts.contains(&gone),
            "a candidate we stopped probing must go"
        );

        // Pruning one peer must never touch another's table.
        assert!(
            p.paths().iter().any(|s| s.peer == other && s.dst == lan),
            "another peer's path on the same endpoint was collaterally pruned"
        );

        // The one-element case is the installed-direct carrier, unchanged.
        p.retain_paths(&peer, &[public]);
        let dsts: Vec<SocketAddr> = p
            .paths()
            .iter()
            .filter(|s| s.peer == peer)
            .map(|s| s.dst)
            .collect();
        assert_eq!(dsts, vec![public]);
    }
    /// THE regression lock. rc.346 counted CONSECUTIVE misses, so a path that
    /// delivered ~20 % (the real grox carrier: `tx=17..22 rx=3..4`) reset the
    /// counter roughly every fifth round and was never detected. A windowed
    /// RATE must see that same path as ~80 % lossy — while a healthy path
    /// reads ~0 and an unmeasured one reads `None`, never "bad".
    #[test]
    fn loss_is_a_rate_so_a_lossy_path_cannot_hide() {
        // ~20 % delivery: 1 pong per 5 rounds — the shape that defeated the
        // consecutive-miss reaper.
        let mut lossy = PathStats::default();
        for i in 0..10u32 {
            let n = [i as u8; 8];
            lossy.on_sent(n);
            if i % 5 == 0 {
                lossy.on_pong(n, 40.0);
            }
        }
        let l = lossy.loss().expect("enough rounds to judge");
        assert!(
            l > 0.6,
            "a ~20% delivery path must read as heavily lossy, got {l}"
        );

        // A healthy path reads ~0 loss.
        let mut good = PathStats::default();
        for i in 0..10u32 {
            let n = [i as u8; 8];
            good.on_sent(n);
            good.on_pong(n, 10.0);
        }
        assert_eq!(good.loss(), Some(0.0));
        assert!(good.rtt_ms.unwrap() > 0.0);

        // An UNMEASURED path is `None` — never mistaken for a bad one. This
        // is the "silence is not negative evidence" rule in code.
        let mut fresh = PathStats::default();
        fresh.on_sent([1u8; 8]);
        assert_eq!(fresh.loss(), None, "too few rounds must not read as loss");

        // A stale pong (wrong nonce) credits nothing.
        let mut stale = PathStats::default();
        stale.on_sent([1u8; 8]);
        stale.on_pong([9u8; 8], 5.0);
        assert_eq!(stale.rtt_ms, None);
    }

    /// W6 — the rtt tail reports the spike the EWMA hides: the field shape
    /// (42 ms baseline, one 374 ms head-of-line stall on a TCP relay) must
    /// surface in p95/max while the smoothed mean stays low.
    #[test]
    fn rtt_tail_reports_the_spike_the_ewma_hides() {
        let mut s = PathStats::default();
        for i in 0..12u32 {
            let n = [i as u8; 8];
            s.on_sent(n);
            s.on_pong(n, if i == 7 { 374.0 } else { 42.0 });
        }
        let ewma = s.rtt_ms.expect("answered rounds");
        assert!(ewma < 120.0, "the EWMA smooths the spike away: {ewma}");
        let (p95, max) = s.rtt_tail().expect("enough samples");
        assert_eq!(max, 374.0);
        // 12 samples: p95 index = ceil(11.4) - 1 = 11 → the max itself.
        assert_eq!(p95, 374.0);

        // Too few samples → None, never a verdict.
        let mut fresh = PathStats::default();
        for i in 0..3u32 {
            let n = [i as u8; 8];
            fresh.on_sent(n);
            fresh.on_pong(n, 10.0);
        }
        assert_eq!(fresh.rtt_tail(), None);

        // The window slides: more than LOSS_WINDOW pongs keep only the
        // last LOSS_WINDOW samples, so an old spike eventually ages out.
        let mut slide = PathStats::default();
        let mut i = 0u32;
        let mut nonce = move || {
            i += 1;
            [i as u8; 8]
        };
        let n0 = nonce();
        slide.on_sent(n0);
        slide.on_pong(n0, 900.0); // the old spike
        for _ in 0..LOSS_WINDOW {
            let n = nonce();
            slide.on_sent(n);
            slide.on_pong(n, 20.0);
        }
        let (_, max) = slide.rtt_tail().expect("full window");
        assert_eq!(max, 20.0, "the 900 ms sample must have aged out");
    }

    /// A recv seam must handle BOTH directions of the protocol.
    ///
    /// The device demux used to switch on a ping-only `respond()` helper, so
    /// every PONG that landed on that socket was dropped: the peer answered,
    /// the reply arrived, the prober never saw it, and a healthy carrier read
    /// `loss=100%` (fleet-host-2→fleet-host-1 on grox, 0 % by ping, 2026-08-12). The helper
    /// is gone; this pins what replaced it — ONE entry point that surfaces a
    /// ping and a pong distinguishably, so a seam cannot silently serve half.
    #[test]
    fn classify_surfaces_both_directions_so_no_seam_can_serve_half() {
        let (a_s, a_p) = kp();
        let (b_s, b_p) = kp();
        let src: SocketAddr = "203.0.113.20:41000".parse().unwrap();

        // A ping from B lands on A's seam ⇒ answerable.
        let ping = build(
            KIND_PING,
            [3u8; 8],
            b_p.as_bytes(),
            None,
            &shared_secret(&b_s, &a_p),
        );
        match classify(&ping, src, &a_s, &a_p, |_| true) {
            Verdict::Answer(pong) => assert_eq!(pong.len(), FRAME_LEN, "reply never amplifies"),
            _ => panic!("a verified ping must be answerable"),
        }

        // B's pong to A's round lands on the SAME seam ⇒ routable, not dropped.
        let pong = build(
            KIND_PONG,
            [7u8; 8],
            b_p.as_bytes(),
            Some(src),
            &shared_secret(&b_s, &a_p),
        );
        match classify(&pong, src, &a_s, &a_p, |_| true) {
            Verdict::Pong(p) => {
                assert_eq!(p.sender, *b_p.as_bytes());
                assert_eq!(p.nonce, [7u8; 8]);
                assert_eq!(p.src, src);
            }
            _ => panic!("a verified pong must be surfaced for routing"),
        }
    }

    /// A carrier that MOVES must not leave its old endpoint in the table
    /// reading as a live lossy path.
    ///
    /// Field 2026-08-12: winhost-a rebound from `:62349` to `:59669`; fleet-host-2 kept
    /// reporting `100.65.0.5@…:62349 loss=47%` for 25 minutes afterwards.
    /// `forget` only prunes peers that LEFT the mesh — a peer that stays and
    /// moves accumulates a permanent dead row, which is indistinguishable in
    /// the digest from a real black-hole and would feed C3 a phantom.
    #[test]
    fn a_moved_carrier_drops_its_old_endpoint_row() {
        let (a_s, a_p) = kp();
        let (_b_s, b_p) = kp();
        let peer = *b_p.as_bytes();
        let old: SocketAddr = "203.0.113.7:62349".parse().unwrap();
        let new: SocketAddr = "203.0.113.7:59669".parse().unwrap();
        let mut pr = Prober::default();

        // Six unanswered rounds on the old endpoint ⇒ it reads lossy.
        for _ in 0..6 {
            let (nonce, _f) = pr.next_ping(&peer, &a_s, &a_p);
            pr.sent(peer, old, nonce);
        }
        assert_eq!(pr.paths().len(), 1);

        // The carrier moves; the next round goes to the new endpoint.
        let (nonce, _f) = pr.next_ping(&peer, &a_s, &a_p);
        pr.sent(peer, new, nonce);
        pr.retain_paths(&peer, &[new]);

        let p = pr.paths();
        assert_eq!(p.len(), 1, "the dead endpoint must not linger");
        assert_eq!(p[0].dst, new);
    }

    /// RTT is measured to when the pong ARRIVED, not to when the prober got
    /// round to reading it.
    ///
    /// Locks the 2026-08-12 field reading: the prober drains its pong channel
    /// once per 5 s round, so charging `at.elapsed()` at drain time reported
    /// `rtt=5000ms` — exactly one tick — on EVERY path, including ones
    /// answering every probe at `loss=0%`. Loss was right and RTT was garbage,
    /// which is the only reason it was obviously a bug rather than a bad peer.
    #[test]
    fn rtt_measures_arrival_not_drain_time() {
        let (a_s, a_p) = kp();
        let (_b_s, b_p) = kp();
        let peer = *b_p.as_bytes();
        let dst: SocketAddr = "203.0.113.11:41000".parse().unwrap();
        let mut pr = Prober::default();

        let (nonce, _frame) = pr.next_ping(&peer, &a_s, &a_p);
        pr.sent(peer, dst, nonce);
        // The pong comes back promptly...
        let arrived = std::time::Instant::now();
        // ...but sits in the channel until the next round.
        std::thread::sleep(std::time::Duration::from_millis(40));
        pr.on_pong(&DiscoInbound {
            sender: peer,
            nonce,
            src: dst,
            at: arrived,
        });

        let rtt = pr.paths()[0].rtt_ms.expect("an RTT was measured");
        assert!(
            rtt < 20.0,
            "RTT must reflect arrival, not the {}ms spent queued; got {rtt}ms",
            40
        );
    }

    /// The prober's round accounting: a path that answers reads healthy, a
    /// path that goes silent accrues LOSS (never a death), and an unmatched
    /// or late pong credits nothing.
    #[test]
    fn prober_rounds_measure_loss_without_punishing_silence() {
        let (a_s, a_p) = kp();
        let (_b_s, b_p) = kp();
        let peer = *b_p.as_bytes();
        let dst: SocketAddr = "203.0.113.9:41000".parse().unwrap();
        let mut pr = Prober::default();

        // Six answered rounds ⇒ zero loss, an RTT is known.
        for _ in 0..6 {
            let (nonce, frame) = pr.next_ping(&peer, &a_s, &a_p);
            assert!(is_disco_shaped(&frame));
            pr.sent(peer, dst, nonce);
            pr.on_pong(&DiscoInbound {
                sender: peer,
                nonce,
                src: dst,
                at: std::time::Instant::now(),
            });
        }
        let p = pr.paths();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].loss, Some(0.0), "answered rounds ⇒ no loss");
        assert!(p[0].rtt_ms.is_some(), "an RTT was measured");

        // Six silent rounds ⇒ the loss RATE climbs. Nothing else happens:
        // there is no death, no penalty, no ranking — measurement only.
        for _ in 0..6 {
            let (nonce, _f) = pr.next_ping(&peer, &a_s, &a_p);
            pr.sent(peer, dst, nonce);
        }
        let loss = pr.paths()[0].loss.expect("measured");
        assert!(loss > 0.0, "silence must show as loss, got {loss}");

        // An unknown nonce credits nothing.
        let before = pr.paths()[0].loss;
        pr.on_pong(&DiscoInbound {
            sender: peer,
            nonce: [0xEE; 8],
            src: dst,
            at: std::time::Instant::now(),
        });
        assert_eq!(
            pr.paths()[0].loss,
            before,
            "an unmatched pong must not credit"
        );

        // Forgetting a departed peer clears its paths.
        pr.forget(&peer);
        assert!(pr.paths().is_empty());
    }

    #[test]
    fn observed_encodes_v4_and_v6() {
        let (a_s, a_p) = kp();
        let (_b_s, b_p) = kp();
        let sh = shared_secret(&a_s, &b_p);
        for s in ["198.51.100.5:65535", "[2001:db8::1]:443"] {
            let sa: SocketAddr = s.parse().unwrap();
            let f = build(KIND_PONG, [0u8; 8], a_p.as_bytes(), Some(sa), &sh);
            assert_eq!(parse(&f, &sh).unwrap().observed, Some(sa));
        }
    }
}


/// Fresh carrier-intent proof. The existing disco prefix keeps regional and
/// central DERP demux compatibility; the longer fixed frame and new kinds are
/// ignored by old WG receivers. HELLO is sent on ORG first, never on DERP.
pub(crate) mod derp_follow {
    use super::*;
    use sha2::Digest;

    const LEN: usize = 160;
    const MAC_OFFSET: usize = 128;
    const DOMAIN: &[u8] = b"meshharbor/derp-follow/v1";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    pub(crate) enum Kind { Hello = 3, HelloAck = 4, Challenge = 5, Proof = 6 }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct Frame {
        pub kind: Kind,
        pub nonce: [u8; 16],
        pub init: [u8; 32],
    }

    pub(crate) fn shaped(bytes: &[u8]) -> bool {
        bytes.len() == LEN && bytes.starts_with(MAGIC)
    }

    fn key(shared: &[u8; 32]) -> Option<[u8; 32]> {
        if shared == &[0; 32] { return None; }
        let mut h = <Hmac<Sha256> as Mac>::new_from_slice(shared).ok()?;
        h.update(DOMAIN);
        Some(h.finalize().into_bytes().into())
    }

    pub(crate) fn encode(
        frame: &Frame, sender: &[u8; 32], recipient: &[u8; 32], shared: &[u8; 32],
    ) -> Option<Vec<u8>> {
        let key = key(shared)?;
        let mut bytes = vec![0u8; LEN];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = frame.kind as u8;
        bytes[16..48].copy_from_slice(sender);
        bytes[48..80].copy_from_slice(recipient);
        bytes[80..96].copy_from_slice(&frame.nonce);
        bytes[96..128].copy_from_slice(&frame.init);
        let mut h = <Hmac<Sha256> as Mac>::new_from_slice(&key).ok()?;
        h.update(&bytes[..MAC_OFFSET]);
        bytes[MAC_OFFSET..].copy_from_slice(&h.finalize().into_bytes());
        Some(bytes)
    }

    pub(crate) fn decode(
        bytes: &[u8], sender: &[u8; 32], recipient: &[u8; 32], shared: &[u8; 32],
    ) -> Option<Frame> {
        if !shaped(bytes) || bytes[9..16] != [0; 7]
            || bytes[16..48] != *sender || bytes[48..80] != *recipient
        { return None; }
        let kind = match bytes[8] {
            3 => Kind::Hello, 4 => Kind::HelloAck, 5 => Kind::Challenge, 6 => Kind::Proof,
            _ => return None,
        };
        let key = key(shared)?;
        let mut h = <Hmac<Sha256> as Mac>::new_from_slice(&key).ok()?;
        h.update(&bytes[..MAC_OFFSET]);
        h.verify_slice(&bytes[MAC_OFFSET..]).ok()?;
        let frame = Frame {
            kind, nonce: bytes[80..96].try_into().ok()?, init: bytes[96..128].try_into().ok()?,
        };
        if frame.nonce == [0; 16]
            || matches!(kind, Kind::Hello | Kind::HelloAck) && frame.init != [0; 32]
        { return None; }
        Some(frame)
    }

    pub(crate) fn init_digest(bytes: &[u8]) -> Option<[u8; 32]> {
        (bytes.len() == 148 && bytes[..4] == [1, 0, 0, 0])
            .then(|| Sha256::digest(bytes).into())
    }

    pub(crate) fn nonce() -> [u8; 16] {
        use rand::RngCore;
        loop {
            let mut value = [0u8; 16];
            rand::rng().fill_bytes(&mut value);
            if value != [0; 16] { return value; }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn sample() -> Frame { Frame { kind: Kind::Challenge, nonce: [3; 16], init: [7; 32] } }
        #[test]
        fn follow_wire_binds_direction_kind_nonce_digest_and_domain() {
            let f = sample(); let a = [1; 32]; let b = [2; 32]; let shared = [9; 32];
            let p = encode(&f, &a, &b, &shared).unwrap();
            assert_eq!(decode(&p, &a, &b, &shared), Some(f));
            assert!(decode(&p, &b, &a, &shared).is_none(), "reflection");
            assert!(decode(&p, &a, &[4; 32], &shared).is_none(), "cross peer");
            assert!(decode(&p, &a, &b, &[8; 32]).is_none(), "wrong DH");
            for offset in [8, 9, 16, 48, 80, 96, 128, 159] {
                let mut bad = p.clone(); bad[offset] ^= 1;
                assert!(decode(&bad, &a, &b, &shared).is_none(), "tamper {offset}");
            }
            assert!(encode(&sample(), &a, &b, &[0; 32]).is_none());
        }
        #[test]
        fn follow_wire_keeps_legacy_classifier_and_shape_disjointness() {
            let p = encode(&sample(), &[1; 32], &[2; 32], &[9; 32]).unwrap();
            assert!(roomler_ai_remote_control::derp_frame::payload_is_wg_or_disco(&p));
            assert!(!super::super::is_disco_shaped(&p), "old receiver ignores the longer kind");
            assert!(!crate::overlay::wg::is_wg_shaped(&p));
            assert!(!crate::transport::stun::has_stun_cookie(&p));
            assert!(decode(&p[..159], &[1; 32], &[2; 32], &[9; 32]).is_none());
        }
    }
}
