// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-19 P1 — the bind-only reachability responder.
//!
//! Answers org-relay **probe** frames and forwards nothing. There is no session
//! table, no peer state and no data path: this exists so a node can be *asked*
//! whether it is reachable on a given UDP port, which is the question E2E-3
//! showed cannot be answered any other way — `relay_band_udp` is not a port
//! test, it dials a live coturn allocation and coturn is the responder
//! (`overlay::netcheck::probe_relay_band`).
//!
//! # What this is, security-wise
//!
//! It is a **reflector, deliberately bounded**, and it is worth being precise
//! rather than reassuring:
//!
//! * **It cannot amplify.** A reply is the *same frame* that arrived, so reply
//!   bytes == request bytes exactly. That is the rule this codebase already
//!   applies to disco (`disco::FRAME_LEN`), and it matters more here because
//!   the port is chosen precisely because corporate egresses permit it.
//! * **It can still reflect 1:1** — a spoofed source gets one 64-byte datagram
//!   per 64-byte datagram sent. The per-source gate bounds that, and P2's
//!   minted token removes it entirely by making an unsolicited probe
//!   unanswerable. Until then this is the same posture as disco answering a
//!   ping, and it is not more.
//! * **Per-attempt state is bounded, not zero.** The gate keeps at most
//!   [`MAX_SOURCES`] entries and *refuses* rather than growing — the shape of
//!   `unknown_init_fresh` in [`super::super::carrier_plane`]. "Stateless" would
//!   be the wrong claim; "cannot be made to allocate without bound" is the true
//!   one, and it is what the tests assert.
//!
//! # Why classification is a pure function
//!
//! [`ProbeGate::classify`] takes `now` and returns a verdict, so every property
//! below — including rate limiting and table bounding — is tested without a
//! socket and without sleeping. [`ProbeResponder`] is the thin shell that owns
//! the socket and calls it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::wire::{is_org_relay_shaped, parse_probe};

/// Probes admitted per source per window. Low on purpose: a reachability probe
/// is a once-per-measurement question, not a stream.
pub const PER_SOURCE_PER_WINDOW: u32 = 4;

/// The rate-limit window, mirroring `UNKNOWN_INIT_MIN_INTERVAL`.
pub const WINDOW: Duration = Duration::from_secs(2);

/// Hard ceiling on tracked sources, mirroring `UNKNOWN_INIT_MAX_SOURCES`. Once
/// reached, unknown sources are refused rather than admitted — the table is a
/// bound, so it must not be growable by the party it is bounding.
///
/// 512, not 64: on a serving relay this one table also admits every fresh
/// session's first binds, and a mint burst (a daemon or server restart, a
/// zone change re-minting a node's lines) brings two new member sockets per
/// session at once. 64 was measured too small on a ~200-socket relay
/// (2026-11-17). 512 entries is tens of KiB, still a fixed bound.
pub const MAX_SOURCES: usize = 512;

/// What the responder decided about one datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeVerdict {
    /// Echo these bytes back. Always exactly the bytes that arrived.
    Answer(Vec<u8>),
    /// Not an org-relay frame at all (wrong shape).
    RefusedNotShaped,
    /// Org-relay shaped, but not a probe (wrong length, or a data frame).
    RefusedNotProbe,
    /// This source has had its allowance for the current window.
    RefusedRateLimited,
}

/// Per-refusal-reason counters. One counter per cause, because during a flood
/// "refused" alone cannot tell an attack from a misconfiguration — the
/// distinction FR-19 requires of every counter it ships.
#[derive(Debug, Default)]
pub struct ResponderStats {
    answered: AtomicU64,
    refused_not_shaped: AtomicU64,
    refused_not_probe: AtomicU64,
    refused_rate_limited: AtomicU64,
}

/// A plain snapshot — the *reader* every counter here ships with, so no
/// counter can end up like FR-18's `dropped_stale`, which was added without one
/// and left its acceptance criterion unevaluable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResponderCounts {
    pub answered: u64,
    pub refused_not_shaped: u64,
    pub refused_not_probe: u64,
    pub refused_rate_limited: u64,
}

impl ResponderStats {
    pub fn snapshot(&self) -> ResponderCounts {
        ResponderCounts {
            answered: self.answered.load(Ordering::Relaxed),
            refused_not_shaped: self.refused_not_shaped.load(Ordering::Relaxed),
            refused_not_probe: self.refused_not_probe.load(Ordering::Relaxed),
            refused_rate_limited: self.refused_rate_limited.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn record(&self, v: &ProbeVerdict) {
        let c = match v {
            ProbeVerdict::Answer(_) => &self.answered,
            ProbeVerdict::RefusedNotShaped => &self.refused_not_shaped,
            ProbeVerdict::RefusedNotProbe => &self.refused_not_probe,
            ProbeVerdict::RefusedRateLimited => &self.refused_rate_limited,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }
}

/// The classification + rate-limit state. Bounded by construction.
#[derive(Debug, Default)]
pub struct ProbeGate {
    recent: HashMap<SocketAddr, (Instant, u32)>,
}

impl ProbeGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of sources currently tracked. Exposed so the bound is assertable
    /// rather than merely intended.
    pub fn tracked_sources(&self) -> usize {
        self.recent.len()
    }

    /// Classify one datagram.
    ///
    /// Order matters and is deliberate: **shape first, rate limit last**. A
    /// malformed flood must not be able to evict a legitimate peer's rate-limit
    /// entry, and refusing on shape costs no table space at all.
    pub fn classify(&mut self, src: SocketAddr, pkt: &[u8], now: Instant) -> ProbeVerdict {
        if !is_org_relay_shaped(pkt) {
            return ProbeVerdict::RefusedNotShaped;
        }
        if parse_probe(pkt).is_none() {
            return ProbeVerdict::RefusedNotProbe;
        }
        // Rate limit LAST, and mutation-verified: moving it ahead of the shape
        // check makes a malformed flood consume table entries and evict
        // legitimate peers, which `non_org_relay_shapes_are_refused_without_
        // touching_the_table` fails on.
        if !self.admit(src, now) {
            return ProbeVerdict::RefusedRateLimited;
        }
        // The echo IS the request. Constructing a fresh frame here would be the
        // bug: any divergence in length becomes an amplification factor.
        ProbeVerdict::Answer(pkt.to_vec())
    }

    /// The per-source budget, shared by EVERY unauthenticated control frame —
    /// probe, bind and answer draw from the same allowance, because to a
    /// flooder they are all just "a packet that makes the relay do work".
    /// Public so the relay server can gate binds through the same table
    /// rather than keeping a second one an attacker could fill separately.
    pub fn admit(&mut self, src: SocketAddr, now: Instant) -> bool {
        if self.recent.len() >= MAX_SOURCES {
            self.recent
                .retain(|_, (t, _)| now.duration_since(*t) < WINDOW);
        }
        match self.recent.get_mut(&src) {
            Some((t, count)) if now.duration_since(*t) < WINDOW => {
                if *count < PER_SOURCE_PER_WINDOW {
                    *count += 1;
                    true
                } else {
                    false
                }
            }
            Some(entry) => {
                *entry = (now, 1);
                true
            }
            None => {
                if self.recent.len() < MAX_SOURCES {
                    self.recent.insert(src, (now, 1));
                    true
                } else {
                    // Full of live entries: refuse rather than grow. A new
                    // source is turned away for at most one window.
                    false
                }
            }
        }
    }
}

/// The socket-owning shell for a **probe-only** node. Holds no session state.
///
/// Superseded on a serving relay by [`super::server::RelayServer`], which
/// answers probes through the same [`ProbeGate`] and additionally binds and
/// forwards. Retained as the minimal P1 surface and for its socket-loop tests,
/// which are the regression tests for the oversized-datagram DoS.
pub struct ProbeResponder {
    gate: ProbeGate,
    stats: Arc<ResponderStats>,
}

impl ProbeResponder {
    pub fn new(stats: Arc<ResponderStats>) -> Self {
        Self {
            gate: ProbeGate::new(),
            stats,
        }
    }

    /// Handle one received datagram, returning the bytes to send back (if any).
    /// Kept synchronous and I/O-free so the socket loop stays a thin wrapper.
    pub fn handle(&mut self, src: SocketAddr, pkt: &[u8], now: Instant) -> Option<Vec<u8>> {
        let verdict = self.gate.classify(src, pkt, now);
        self.stats.record(&verdict);
        match verdict {
            ProbeVerdict::Answer(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn stats(&self) -> ResponderCounts {
        self.stats.snapshot()
    }

    pub fn tracked_sources(&self) -> usize {
        self.gate.tracked_sources()
    }

    /// Own `sock` and answer probes until the socket dies.
    ///
    /// ⚠️ **A successful bind does not prove reachability, and the log line
    /// says so on purpose.** On a host with a coturn DNAT the port can be
    /// consumed in `PREROUTING` while `ss -ulnp` shows it free and this loop
    /// receives nothing — measured on mars during E2E-3, where exactly that
    /// confound nearly inverted the result. The probe exists because binding
    /// is not evidence.
    pub async fn serve(mut self, sock: Arc<tokio::net::UdpSocket>) {
        let local = sock.local_addr().ok();
        tracing::info!(
            ?local,
            "org-relay probe responder listening (answers probes, forwards nothing; \
             a successful bind does NOT prove reachability -- a DNAT can eat this port \
             upstream of the socket)"
        );
        // ⚠️ Sized well above a probe frame ON PURPOSE, and a recv error is
        // NOT fatal. Both halves were bugs, caught by
        // `serve_answers_a_real_probe_and_stays_silent_otherwise`:
        //
        // A datagram larger than the buffer does not truncate everywhere. On
        // Windows `recvfrom` fails with `WSAEMSGSIZE` instead, so a one-frame
        // buffer plus "any error ends the loop" meant **one oversized packet
        // from anyone on the internet permanently killed the responder** — a
        // remote DoS on an unauthenticated port, which is precisely what this
        // module claims to be hardened against.
        //
        // So: read generously and refuse on length in `classify` (portable, no
        // error path for the common case), and treat errors as transient up to
        // a bound — a genuinely dead socket still terminates instead of
        // spinning, but no single datagram can end the service.
        const READ_BUF: usize = 2048;
        const MAX_CONSECUTIVE_ERRORS: u32 = 64;
        let mut buf = [0u8; READ_BUF];
        let mut consecutive_errors: u32 = 0;
        loop {
            let (n, src) = match sock.recv_from(&mut buf).await {
                Ok(v) => {
                    consecutive_errors = 0;
                    v
                }
                Err(e) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                        tracing::warn!(
                            ?local,
                            error = %e,
                            consecutive_errors,
                            "org-relay responder giving up: the socket keeps failing"
                        );
                        return;
                    }
                    tracing::debug!(?local, error = %e, "org-relay responder recv error (transient)");
                    continue;
                }
            };
            if let Some(reply) = self.handle(src, &buf[..n], Instant::now())
                && let Err(e) = sock.send_to(&reply, src).await
            {
                tracing::debug!(%src, error = %e, "org-relay probe reply failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::orgrelay::{PROBE_FRAME_LEN, PROBE_TOKEN_LEN, build_probe};

    fn src(n: u16) -> SocketAddr {
        format!("198.51.100.{}:{}", n % 250 + 1, 40000 + n)
            .parse()
            .unwrap()
    }

    fn probe() -> [u8; PROBE_FRAME_LEN] {
        build_probe(7, &[0x11; PROBE_TOKEN_LEN])
    }

    #[test]
    fn a_valid_probe_is_echoed_byte_for_byte() {
        let mut g = ProbeGate::new();
        let p = probe();
        match g.classify(src(1), &p, Instant::now()) {
            ProbeVerdict::Answer(bytes) => {
                assert_eq!(bytes, p.to_vec(), "the echo must BE the request");
                assert_eq!(
                    bytes.len(),
                    p.len(),
                    "reply bytes must equal request bytes -- any divergence is an \
                     amplification factor"
                );
            }
            other => panic!("expected Answer, got {other:?}"),
        }
    }

    #[test]
    fn non_org_relay_shapes_are_refused_without_touching_the_table() {
        let mut g = ProbeGate::new();
        let now = Instant::now();
        // WireGuard handshake initiation, STUN binding request, and junk.
        let mut wg = vec![0u8; 148];
        wg[0] = 1;
        let mut stun = vec![0u8; 20];
        stun[1] = 0x01;
        stun[4..8].copy_from_slice(&0x2112_A442u32.to_be_bytes());
        for pkt in [wg, stun, vec![0xFF; 64], vec![]] {
            assert_eq!(
                g.classify(src(2), &pkt, now),
                ProbeVerdict::RefusedNotShaped
            );
        }
        assert_eq!(
            g.tracked_sources(),
            0,
            "a malformed flood must cost no table space, or it could evict \
             legitimate peers' entries"
        );
    }

    #[test]
    fn shaped_but_not_a_probe_is_refused() {
        let mut g = ProbeGate::new();
        let now = Instant::now();

        // Right shape, wrong length.
        let short = &probe()[..PROBE_FRAME_LEN - 1];
        assert_eq!(
            g.classify(src(3), short, now),
            ProbeVerdict::RefusedNotProbe
        );

        // Right shape and length, but a DATA frame (control bit clear).
        let mut data = probe();
        data[1] = 0x00;
        assert!(is_org_relay_shaped(&data));
        assert_eq!(
            g.classify(src(3), &data, now),
            ProbeVerdict::RefusedNotProbe
        );
    }

    #[test]
    fn a_source_is_rate_limited_within_the_window_and_recovers_after_it() {
        let mut g = ProbeGate::new();
        let t0 = Instant::now();
        let p = probe();
        let s = src(4);

        for i in 0..PER_SOURCE_PER_WINDOW {
            assert!(
                matches!(g.classify(s, &p, t0), ProbeVerdict::Answer(_)),
                "probe {i} within the allowance must be answered"
            );
        }
        assert_eq!(g.classify(s, &p, t0), ProbeVerdict::RefusedRateLimited);

        // A fresh window admits it again.
        let t1 = t0 + WINDOW + Duration::from_millis(1);
        assert!(matches!(g.classify(s, &p, t1), ProbeVerdict::Answer(_)));
    }

    /// The bound is the point of the table, so it must hold against the party
    /// it is bounding: a flood from thousands of distinct sources must not grow
    /// it past the cap.
    #[test]
    fn a_flood_from_many_sources_cannot_grow_the_table_past_the_cap() {
        let mut g = ProbeGate::new();
        let now = Instant::now();
        let p = probe();
        for n in 0..5000u16 {
            let _ = g.classify(
                format!("203.0.113.{}:{}", n % 254 + 1, 1024 + n)
                    .parse()
                    .unwrap(),
                &p,
                now,
            );
            assert!(
                g.tracked_sources() <= MAX_SOURCES,
                "table grew to {} at n={n}",
                g.tracked_sources()
            );
        }
    }

    /// Entries older than the window are reclaimed, so a burst of one-shot
    /// sources cannot lock the table out forever.
    #[test]
    fn stale_sources_are_reclaimed_so_the_table_does_not_wedge() {
        let mut g = ProbeGate::new();
        let t0 = Instant::now();
        let p = probe();
        for n in 0..MAX_SOURCES as u16 {
            let _ = g.classify(src(n), &p, t0);
        }
        assert_eq!(g.tracked_sources(), MAX_SOURCES);

        // A brand-new source now, while the table is full of LIVE entries, is
        // refused -- the bound holds.
        assert_eq!(
            g.classify(src(9999), &p, t0),
            ProbeVerdict::RefusedRateLimited
        );

        // After the window, the same source is admitted.
        let t1 = t0 + WINDOW + Duration::from_millis(1);
        assert!(matches!(
            g.classify(src(9999), &p, t1),
            ProbeVerdict::Answer(_)
        ));
    }

    #[test]
    fn every_verdict_increments_its_own_counter_and_the_snapshot_reads_it() {
        let stats = Arc::new(ResponderStats::default());
        let mut r = ProbeResponder::new(stats.clone());
        let now = Instant::now();
        let p = probe();

        assert!(r.handle(src(5), &p, now).is_some());
        assert!(r.handle(src(5), &[0xFF; 32], now).is_none());
        assert!(r.handle(src(5), &p[..10], now).is_none());
        for _ in 0..PER_SOURCE_PER_WINDOW {
            let _ = r.handle(src(5), &p, now);
        }

        let c = r.stats();
        assert_eq!(c.answered, PER_SOURCE_PER_WINDOW as u64);
        assert_eq!(c.refused_not_shaped, 1);
        assert_eq!(c.refused_not_probe, 1);
        assert_eq!(c.refused_rate_limited, 1);
        // The snapshot is the reader; the Arc sees the same numbers.
        assert_eq!(stats.snapshot(), c);
    }

    /// The socket loop itself, over a real loopback UDP socket. `classify` is
    /// covered exhaustively above, but that leaves the parts only `serve` has:
    /// the one-frame read buffer, the reply going back to the right peer, and
    /// the fact that a refused datagram produces **no** datagram at all rather
    /// than an error reply.
    #[tokio::test]
    async fn serve_answers_a_real_probe_and_stays_silent_otherwise() {
        use tokio::net::UdpSocket;
        use tokio::time::{Duration as TDuration, timeout};

        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let stats = Arc::new(ResponderStats::default());
        tokio::spawn(ProbeResponder::new(stats.clone()).serve(server.clone()));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sent = probe();
        client.send_to(&sent, server_addr).await.unwrap();

        let mut buf = [0u8; 256];
        let n = timeout(TDuration::from_secs(5), client.recv(&mut buf))
            .await
            .expect("responder did not reply within 5s")
            .unwrap();
        assert_eq!(
            &buf[..n],
            &sent[..],
            "the reply must be the request, byte for byte"
        );
        assert_eq!(
            n,
            sent.len(),
            "reply bytes must equal request bytes over a real socket too"
        );

        // A datagram that is not a probe must produce NO reply at all --
        // silence, not an error frame, which would be a second reflection
        // surface and a way to probe for our presence.
        client.send_to(&[0xFFu8; 40], server_addr).await.unwrap();
        assert!(
            timeout(TDuration::from_millis(400), client.recv(&mut buf))
                .await
                .is_err(),
            "a refused datagram must draw no response"
        );

        // An OVERSIZED datagram whose first 64 bytes ARE a valid probe. It is
        // org-relay *shaped* (the header is in bytes 0..8) but it is not a
        // probe, because a probe is exactly 64 bytes -- so it draws no reply.
        //
        // ⚠️ This case found two real bugs, and the second only because the
        // first was fixed:
        //
        // 1. With a one-frame read buffer, Windows `recvfrom` returns
        //    WSAEMSGSIZE rather than truncating, and the loop treated every
        //    error as fatal -- so ONE oversized datagram from anyone on the
        //    internet permanently killed the responder.
        // 2. Once the buffer was sized up, the honest behaviour appeared:
        //    refuse on length. The tempting alternative -- truncate to 64 and
        //    answer -- would mean a 512-byte request drew a 64-byte reply,
        //    which is de-amplifying and therefore *looks* safe, but it also
        //    means the frame we answer is not the frame that was sent. Exact
        //    match or nothing.
        // (a) Oversized but still UNDER the read buffer: read in full on every
        // platform, then refused on length. Deterministic, so the counter is
        // safe to assert.
        let mut big = vec![0u8; 512];
        big[..PROBE_FRAME_LEN].copy_from_slice(&sent);
        client.send_to(&big, server_addr).await.unwrap();
        assert!(
            timeout(TDuration::from_millis(400), client.recv(&mut buf))
                .await
                .is_err(),
            "an oversized datagram must draw no reply -- not a truncated one"
        );

        // (b) LARGER than the read buffer: this is where the platforms differ.
        // Linux truncates and classifies; Windows fails the recv outright with
        // WSAEMSGSIZE. So assert only the property that must hold on BOTH --
        // the responder is still alive -- and deliberately assert nothing
        // about the counters here, because a portable-looking counter
        // assertion would be a lie on one of the two.
        let mut huge = vec![0u8; 4096];
        huge[..PROBE_FRAME_LEN].copy_from_slice(&sent);
        client.send_to(&huge, server_addr).await.unwrap();
        let _ = timeout(TDuration::from_millis(400), client.recv(&mut buf)).await;

        client.send_to(&sent, server_addr).await.unwrap();
        let n3 = timeout(TDuration::from_secs(5), client.recv(&mut buf))
            .await
            .expect("responder died after an oversized datagram -- remote DoS")
            .unwrap();
        assert_eq!(&buf[..n3], &sent[..]);

        let c = stats.snapshot();
        assert_eq!(c.answered, 2, "two well-formed probes were answered");
        assert_eq!(c.refused_not_shaped, 1, "the junk datagram");
        assert!(
            c.refused_not_probe >= 1,
            "case (a) must have been classified and refused on length; \
             case (b) may or may not reach the classifier depending on platform"
        );
    }

    /// Runs on an unauthenticated public UDP port inside a SYSTEM/root daemon:
    /// a panic here is a remote daemon kill.
    #[test]
    fn arbitrary_input_never_panics_and_never_answers_more_than_it_received() {
        let mut g = ProbeGate::new();
        let now = Instant::now();
        let mut seed = 0x9E37_79B9u32;
        for len in 0usize..80 {
            for _ in 0..32 {
                let mut buf = vec![0u8; len];
                for b in buf.iter_mut() {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    *b = seed as u8;
                }
                if let ProbeVerdict::Answer(reply) = g.classify(src(6), &buf, now) {
                    assert!(
                        reply.len() <= buf.len(),
                        "a {len}-byte input produced a {}-byte reply",
                        reply.len()
                    );
                }
            }
        }
    }
}
