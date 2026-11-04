// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! C4 — the warm TURN allocation: loop-side state + pure helpers.
//! Stage 1 made the leg's survival across a VPN transition READABLE
//! (probes over the grandfathered flow). Stage 2 PR-A adds the flavor
//! ladder ([`WarmFlavor`]: UDP where it can work, TURNS/TCP:443 on
//! strict-corp hosts where fresh UDP is provably dead — a leg that
//! SURVIVES a capture) and advertises the live relayed address to the
//! server pair-less, so PR-B's peers can dial it the moment their pair
//! dies without a coordination round-trip through the captured host's
//! control WS. Nothing routes over the leg until PR-B.
//! Design: `docs/overlay-warm-relay.md`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::transport::relay::RelayConn;

/// Minimum spacing between credential requests — a host whose allocate
/// keeps failing (or whose grants go unanswered) must not hammer the
/// control WS.
pub(crate) const REQUEST_SPACING: Duration = Duration::from_secs(300);

/// Liveness-probe cadence. Doubles as the flow keepalive on the client
/// leg (the turn client's own refreshes also traffic the 5-tuple, but the
/// probe is the one we MEASURE) — comfortably inside the ~20-25 s-per-30 s
/// conntrack-assurance window is unnecessary here because the allocation
/// refresh traffic already keeps the flow assured; the probe only has to
/// notice death promptly.
pub(crate) const PROBE_SPACING: Duration = Duration::from_secs(60);

/// Which transport the warm leg rides. Stage 2 (PR-A): UDP is still
/// preferred — the corp-VPN flow-grandfathering measurement (stage 1's
/// whole point) only exists on a UDP leg — but a strict-corp host whose
/// fresh UDP is dead on every path (field winhost-a: CP desktop policy
/// blocks ALL fresh outbound UDP incl. 443) gets a TURNS/TCP:443 leg
/// instead: it rides the same middlebox TLS path the control WS does and
/// SURVIVES a VPN capture, which is exactly what a standing failover leg
/// is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WarmFlavor {
    Udp,
    Tls,
}

/// Consecutive UDP establish failures before the ladder falls back to the
/// TLS flavor.
pub(crate) const UDP_FLAVOR_STRIKES: u8 = 2;

/// Once on TLS, every Nth establishment attempt re-tries UDP so a network
/// that regains UDP upgrades back to the measurable flavor.
pub(crate) const RETRY_UDP_EVERY: u8 = 4;

/// Async outcomes flowing back into the runtime loop from spawned work.
pub(crate) enum WarmMsg {
    Established {
        conn: Arc<dyn RelayConn>,
        /// The allocation's relayed transport address (`worker-ip:port`).
        relayed: SocketAddr,
        /// From the ephemeral username's timestamp prefix, when parseable.
        cred_expiry_epoch_s: Option<u64>,
        flavor: WarmFlavor,
    },
    EstablishFailed {
        flavor: WarmFlavor,
        error: String,
    },
    ProbeOk,
    ProbeFailed(String),
}

/// What `apply` observed — the runtime turns these into log lines (state
/// mutation and narration are separated so the transitions are testable).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WarmTransition {
    Established,
    EstablishFailed,
    ProbeOk,
    /// One probe failed but the 2-strike rule is tolerating it (field
    /// 2026-08-15, winhost-b on VPN: a single lost CreatePermission round
    /// trip cycled a healthy allocation at 09:52Z).
    ProbeMissed,
    Lost,
}

#[derive(Default)]
pub(crate) struct WarmRelay {
    conn: Option<Arc<dyn RelayConn>>,
    relayed: Option<SocketAddr>,
    established: Option<Instant>,
    cred_expiry_epoch_s: Option<u64>,
    /// Rotates the probe's permission target (see [`Self::probe_parts`]).
    probe_seq: u8,
    last_probe_ok: Option<Instant>,
    probe_in_flight: bool,
    /// Consecutive failed probes; LOST only at 2 (one lost round trip on
    /// a corp path must not cycle a healthy allocation).
    probe_fail_streak: u8,
    last_request: Option<Instant>,
    detail: Option<String>,
    lost: bool,
    /// Flavor of the live (or last-established) leg.
    flavor: Option<WarmFlavor>,
    /// Consecutive UDP establish failures — the flavor-ladder input.
    udp_establish_failures: u8,
    /// Total establishment attempts, for the periodic UDP re-try cadence.
    establish_attempts: u8,
    /// One INFO per grandfather episode (probe OK while srflx is NONE) —
    /// reset when the allocation is re-established.
    pub(crate) grandfather_logged: bool,
}

impl WarmRelay {
    pub(crate) fn is_live(&self) -> bool {
        self.conn.is_some() && !self.lost
    }

    /// Time to (re)request creds? Only when nothing is live and the last
    /// request is old enough. (Stage 2: the caller no longer gates on
    /// srflx — a strict-corp host with srflx permanently empty is exactly
    /// the host that needs the TLS-flavored leg; the srflx evidence feeds
    /// [`Self::next_flavor`] instead.)
    pub(crate) fn request_due(&self, now: Instant) -> bool {
        !self.is_live()
            && self
                .last_request
                .is_none_or(|t| now.duration_since(t) >= REQUEST_SPACING)
    }

    pub(crate) fn note_requested(&mut self, now: Instant) {
        self.last_request = Some(now);
    }

    pub(crate) fn probe_due(&self, now: Instant) -> bool {
        self.is_live()
            && !self.probe_in_flight
            && self
                .last_probe_ok
                .is_none_or(|t| now.duration_since(t) >= PROBE_SPACING)
    }

    /// The handles a spawned probe needs; `None` when not live.
    ///
    /// The probe target ROTATES through TEST-NET-3 (`203.0.113.1..=254`,
    /// never routed — the 1-byte stray goes to a blackhole): a permission
    /// the client has ALREADY established is cached, so `send_to` toward a
    /// repeated address is enqueue-only on a UDP leg and its `Ok` proves
    /// nothing about the allocation. A NEW address per probe forces a
    /// fresh authenticated CreatePermission round trip — coturn answering
    /// it IS the liveness proof (field 2026-08-15: `creds -180s` with
    /// `probe ok` — the fixed-target probe kept "succeeding" against an
    /// allocation whose credentials had already lapsed).
    pub(crate) fn probe_parts(&mut self) -> Option<(Arc<dyn RelayConn>, SocketAddr)> {
        let conn = self.conn.clone()?;
        self.probe_seq = self.probe_seq.wrapping_add(1);
        let last_octet = 1 + (self.probe_seq % 254);
        let dst = SocketAddr::from(([203, 0, 113, last_octet], 9));
        Some((conn, dst))
    }

    pub(crate) fn note_probe_started(&mut self) {
        self.probe_in_flight = true;
    }

    /// Which flavor the NEXT establishment attempt should use.
    ///
    /// `udp_provably_dead` = the caller's live evidence that fresh UDP
    /// cannot work right now (srflx currently empty — every vantage
    /// including the public-dial fallback timed out). With it true there
    /// is no point burning an attempt on a UDP allocate; the TLS leg is
    /// the one that can exist. Otherwise UDP leads until
    /// [`UDP_FLAVOR_STRIKES`] consecutive failures, after which TLS takes
    /// over with a UDP re-try every [`RETRY_UDP_EVERY`]th attempt (a
    /// network that regains UDP upgrades back to the measurable flavor).
    pub(crate) fn next_flavor(&self, udp_provably_dead: bool) -> WarmFlavor {
        if udp_provably_dead {
            return WarmFlavor::Tls;
        }
        if self.udp_establish_failures < UDP_FLAVOR_STRIKES {
            return WarmFlavor::Udp;
        }
        if self
            .establish_attempts
            .wrapping_add(1)
            .is_multiple_of(RETRY_UDP_EVERY)
        {
            WarmFlavor::Udp
        } else {
            WarmFlavor::Tls
        }
    }

    pub(crate) fn apply(&mut self, msg: WarmMsg, now: Instant) -> WarmTransition {
        match msg {
            WarmMsg::Established {
                conn,
                relayed,
                cred_expiry_epoch_s,
                flavor,
            } => {
                self.conn = Some(conn);
                self.relayed = Some(relayed);
                self.established = Some(now);
                self.cred_expiry_epoch_s = cred_expiry_epoch_s;
                self.last_probe_ok = None;
                self.probe_in_flight = false;
                self.detail = None;
                self.lost = false;
                self.grandfather_logged = false;
                self.flavor = Some(flavor);
                self.establish_attempts = self.establish_attempts.wrapping_add(1);
                if flavor == WarmFlavor::Udp {
                    // A working UDP leg resets the ladder — UDP leads again.
                    self.udp_establish_failures = 0;
                }
                WarmTransition::Established
            }
            WarmMsg::EstablishFailed { flavor, error } => {
                self.detail = Some(error);
                self.establish_attempts = self.establish_attempts.wrapping_add(1);
                if flavor == WarmFlavor::Udp {
                    self.udp_establish_failures = self.udp_establish_failures.saturating_add(1);
                }
                WarmTransition::EstablishFailed
            }
            WarmMsg::ProbeOk => {
                self.probe_in_flight = false;
                self.last_probe_ok = Some(now);
                self.probe_fail_streak = 0;
                WarmTransition::ProbeOk
            }
            WarmMsg::ProbeFailed(e) => {
                self.probe_in_flight = false;
                self.probe_fail_streak = self.probe_fail_streak.saturating_add(1);
                if self.probe_fail_streak < 2 {
                    // 2-strike rule: one lost round trip on a corp path is
                    // not death; the next probe (≤ PROBE_SPACING away)
                    // decides. `last_probe_ok` is NOT advanced, so the
                    // retry is due on the next tick.
                    self.detail = Some(e);
                    return WarmTransition::ProbeMissed;
                }
                // Two consecutive failed permission asserts: coturn no
                // longer honours the allocation (expiry, worker restart, or
                // the client leg's flow died). Drop the conn — holding it
                // would keep `is_live` true and starve re-establishment.
                self.conn = None;
                self.lost = true;
                self.detail = Some(e);
                WarmTransition::Lost
            }
        }
    }

    pub(crate) fn status(&self, now: Instant) -> crate::localapi::WarmRelayStatus {
        let epoch_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        crate::localapi::WarmRelayStatus {
            state: if self.is_live() {
                "live"
            } else if self.lost {
                "lost"
            } else {
                "none"
            }
            .to_string(),
            relayed: self.relayed.map(|r| r.to_string()),
            flavor: self.flavor.filter(|_| self.is_live()).map(|f| {
                match f {
                    WarmFlavor::Udp => "udp",
                    WarmFlavor::Tls => "tls",
                }
                .to_string()
            }),
            age_s: self
                .established
                .filter(|_| self.is_live())
                .map(|t| now.duration_since(t).as_secs()),
            cred_expiry_in_s: self
                .cred_expiry_epoch_s
                .filter(|_| self.is_live())
                .map(|e| e as i64 - epoch_now as i64),
            last_probe_ok_s: self
                .last_probe_ok
                .filter(|_| self.is_live())
                .map(|t| now.duration_since(t).as_secs()),
            detail: self.detail.clone(),
        }
    }
}

/// The expiry baked into a coturn ephemeral username (`"<epoch>:<label>"`).
pub(crate) fn ephemeral_cred_expiry_s(username: &str) -> Option<u64> {
    username.split(':').next()?.parse().ok()
}

/// The UDP-capable TURN urls out of a grant — the warm allocation is
/// UDP-or-nothing (a TCP "warm" allocation would just be today's TURNS
/// fallback with extra steps).
pub(crate) fn udp_turn_urls(urls: &[String]) -> Vec<String> {
    urls.iter()
        .filter(|u| {
            let l = u.to_ascii_lowercase();
            l.starts_with("turn:") && !l.contains("transport=tcp")
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    /// C4 stage 2 — the flavor ladder: UDP leads (the grandfather-
    /// measurable leg), live srflx-emptiness short-circuits to TLS, two
    /// consecutive UDP establish failures fall back to TLS with a UDP
    /// re-try every [`RETRY_UDP_EVERY`]th attempt, and a UDP success
    /// resets the ladder.
    #[test]
    fn flavor_ladder_udp_first_tls_fallback_periodic_retry() {
        let now = Instant::now();
        let mut w = WarmRelay::default();
        assert_eq!(
            w.next_flavor(false),
            WarmFlavor::Udp,
            "fresh state leads UDP"
        );
        assert_eq!(
            w.next_flavor(true),
            WarmFlavor::Tls,
            "srflx empty right now: no point burning a UDP attempt"
        );
        w.apply(
            WarmMsg::EstablishFailed {
                flavor: WarmFlavor::Udp,
                error: "t".into(),
            },
            now,
        );
        assert_eq!(
            w.next_flavor(false),
            WarmFlavor::Udp,
            "one strike still leads UDP"
        );
        w.apply(
            WarmMsg::EstablishFailed {
                flavor: WarmFlavor::Udp,
                error: "t".into(),
            },
            now,
        );
        assert_eq!(
            w.next_flavor(false),
            WarmFlavor::Tls,
            "two strikes fall back to TLS"
        );
        w.apply(
            WarmMsg::EstablishFailed {
                flavor: WarmFlavor::Tls,
                error: "t".into(),
            },
            now,
        );
        assert_eq!(
            w.next_flavor(false),
            WarmFlavor::Udp,
            "every 4th attempt re-tries UDP"
        );
        let t = w.apply(
            WarmMsg::Established {
                conn: Arc::new(NopConn),
                relayed: "5.9.157.221:12795".parse().unwrap(),
                cred_expiry_epoch_s: None,
                flavor: WarmFlavor::Udp,
            },
            now,
        );
        assert_eq!(t, WarmTransition::Established);
        assert_eq!(
            w.next_flavor(false),
            WarmFlavor::Udp,
            "a UDP success resets the ladder"
        );
        assert_eq!(
            w.status(now).flavor.as_deref(),
            Some("udp"),
            "the live flavor is surfaced"
        );
    }

    struct NopConn;
    #[async_trait::async_trait]
    impl RelayConn for NopConn {
        async fn send_to(&self, buf: &[u8], _dst: SocketAddr) -> io::Result<usize> {
            Ok(buf.len())
        }
        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("5.9.157.221:12795".parse().unwrap())
        }
    }

    fn established(now: Instant) -> WarmRelay {
        let mut w = WarmRelay::default();
        let t = w.apply(
            WarmMsg::Established {
                conn: Arc::new(NopConn),
                relayed: "5.9.157.221:12795".parse().unwrap(),
                cred_expiry_epoch_s: Some(u64::MAX / 2),
                flavor: WarmFlavor::Udp,
            },
            now,
        );
        assert_eq!(t, WarmTransition::Established);
        w
    }

    /// The lifecycle the Monday VPN event must be readable through:
    /// establish → probes OK (live) → probe fails (LOST, conn dropped so
    /// re-establishment isn't starved) → status says why.
    #[test]
    fn lifecycle_establish_probe_lose() {
        let now = Instant::now();
        let mut w = established(now);
        assert!(w.is_live());
        assert!(w.probe_due(now), "first probe fires immediately");
        assert!(w.probe_parts().is_some());
        w.note_probe_started();
        assert!(!w.probe_due(now), "no overlapping probes");
        assert_eq!(w.apply(WarmMsg::ProbeOk, now), WarmTransition::ProbeOk);
        assert!(!w.probe_due(now), "just probed — not due again yet");
        assert!(w.probe_due(now + PROBE_SPACING));

        w.note_probe_started();
        assert_eq!(
            w.apply(WarmMsg::ProbeFailed("transient".into()), now),
            WarmTransition::ProbeMissed,
            "one failed probe is tolerated (2-strike rule)"
        );
        assert!(w.is_live(), "still live after a single miss");
        assert!(
            w.probe_due(now + PROBE_SPACING),
            "the retry stays scheduled — a miss never advances last_probe_ok"
        );
        // An OK in between resets the streak: the next single failure is
        // again only a miss.
        w.note_probe_started();
        assert_eq!(w.apply(WarmMsg::ProbeOk, now), WarmTransition::ProbeOk);
        w.note_probe_started();
        assert_eq!(
            w.apply(WarmMsg::ProbeFailed("transient".into()), now),
            WarmTransition::ProbeMissed
        );
        // Second consecutive failure ⇒ LOST.
        w.note_probe_started();
        assert_eq!(
            w.apply(WarmMsg::ProbeFailed("437 allocation gone".into()), now),
            WarmTransition::Lost
        );
        assert!(!w.is_live());
        let s = w.status(now);
        assert_eq!(s.state, "lost");
        assert_eq!(s.detail.as_deref(), Some("437 allocation gone"));
        assert_eq!(s.age_s, None, "a lost allocation has no age");
        // Lost ⇒ requesting again becomes due (spacing permitting).
        assert!(w.request_due(now + REQUEST_SPACING));
    }

    /// Request throttling: never hammer the control WS.
    #[test]
    fn requests_are_spaced() {
        let now = Instant::now();
        let mut w = WarmRelay::default();
        assert!(w.request_due(now));
        w.note_requested(now);
        assert!(!w.request_due(now + Duration::from_secs(1)));
        assert!(w.request_due(now + REQUEST_SPACING));
        // A live allocation never requests.
        let w = established(now);
        assert!(!w.request_due(now + REQUEST_SPACING * 10));
    }

    #[test]
    fn cred_expiry_parses_the_ephemeral_username_prefix() {
        assert_eq!(
            ephemeral_cred_expiry_s("1786831244:coturntest"),
            Some(1786831244)
        );
        assert_eq!(ephemeral_cred_expiry_s("not-a-number:x"), None);
        assert_eq!(ephemeral_cred_expiry_s(""), None);
    }

    #[test]
    fn udp_url_filter_drops_tcp_and_turns() {
        let urls = vec![
            "turn:coturn.meshharbor.itachi.fans:3478?transport=udp".to_string(),
            "turn:coturn.meshharbor.itachi.fans:3478".to_string(),
            "turn:coturn.meshharbor.itachi.fans:443?transport=tcp".to_string(),
            "turns:coturn.meshharbor.itachi.fans:443".to_string(),
        ];
        assert_eq!(
            udp_turn_urls(&urls),
            vec![
                "turn:coturn.meshharbor.itachi.fans:3478?transport=udp".to_string(),
                "turn:coturn.meshharbor.itachi.fans:3478".to_string(),
            ]
        );
    }
}
