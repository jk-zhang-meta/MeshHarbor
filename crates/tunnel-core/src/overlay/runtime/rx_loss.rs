//! Passive loss of the WG stream each peer sends us, per health sweep, from
//! the counters the data plane books ([`WgDevice::peer_rx_loss`]). Two
//! outputs: a 10-minute "loss by carrier" summary line, and a shadow verdict
//! when an ORG carrier loses heavily. Measurement only: nothing here moves a
//! carrier.
//!
//! Why: on the field's org-relay leg (2026-10-26, HK↔Tokyo through the Isvoro
//! relay) 7–10% of the packets were lost on the way into the relay and the pair
//! carried ~2 Mbit/s, while DERP through the same host carried 23–33. Nothing
//! measured a carrier's loss, so nothing could tell the two apart.
//!
//! A peer's packets are bucketed by what carries OUR side of the pair; the
//! peer may send over another (an ORG pair keeps receiving on DERP), so a
//! bucket is the loss of the peer's stream while we rode that carrier.
use super::*;

/// Health sweeps per ORG verdict window (the sweep runs every 5 s).
const WINDOW_SWEEPS: u8 = 6;
/// Packets the peer must have sent in a window before its loss is judged.
const MIN_PACKETS: u64 = 1000;
/// The loss at which an ORG window counts as lossy. Loss-based TCP over a
/// 50 ms path is held near 1.4 Mbit/s at 3% and 0.7 Mbit/s at 8% (Mathis;
/// `netstack_tcp_lossy_rto_matrix`), so 5% is already a crippled carrier.
const LOSSY_PCT: f64 = 5.0;
/// Per-peer spacing of the shadow verdict's log line.
const LOG_EVERY: Duration = Duration::from_secs(60);
/// A peer not read for this long is forgotten.
const FORGET_AFTER: Duration = Duration::from_secs(600);

/// What carries our side of a pair, for the summary's buckets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Via {
    Direct,
    Turn,
    Org,
    Derp,
}

impl Via {
    const ALL: [Via; 4] = [Via::Direct, Via::Turn, Via::Org, Via::Derp];

    pub(super) fn of(is_direct: bool, relay: Option<RelayKind>) -> Self {
        match (is_direct, relay) {
            (true, _) => Via::Direct,
            (false, Some(RelayKind::Org)) => Via::Org,
            (false, Some(RelayKind::Derp)) => Via::Derp,
            (false, _) => Via::Turn,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Via::Direct => "direct",
            Via::Turn => "turn",
            Via::Org => "org",
            Via::Derp => "derp",
        }
    }
}

/// The share of `span` packets that never arrived, once `span` is big enough
/// to judge. A window can read slightly negative (a late packet of the last
/// one); that is no loss.
pub(super) fn loss_pct(span: u64, accepted: u64) -> Option<f64> {
    (span >= MIN_PACKETS).then(|| span.saturating_sub(accepted) as f64 * 100.0 / span as f64)
}

#[derive(Default)]
pub(super) struct RxLoss {
    /// Each peer's last cumulative `(span, accepted)` and when it was read.
    prev: HashMap<ObjectId, (u64, u64, Instant)>,
    /// The open ORG verdict window per peer: `(span, accepted, sweeps)`.
    win: HashMap<ObjectId, (u64, u64, u8)>,
    /// `(span, accepted)` per [`Via`] since the last summary.
    by: [(u64, u64); 4],
    /// ORG windows judged lossy since the last summary.
    lossy: u64,
    last_log: HashMap<ObjectId, Instant>,
}

impl RxLoss {
    /// One sweep's reading for `peer`: its cumulative counters and what our
    /// side rides. Returns the loss of an ORG window that just closed lossy.
    pub(super) fn note(
        &mut self,
        peer: ObjectId,
        via: Via,
        (span, accepted): (u64, u64),
        now: Instant,
    ) -> Option<f64> {
        let (ps, pa, _) = self.prev.insert(peer, (span, accepted, now))?;
        // A reinstalled peer's counters start over: nothing to compare yet.
        if span < ps || accepted < pa {
            self.win.remove(&peer);
            return None;
        }
        let (ds, da) = (span - ps, accepted - pa);
        let bucket = &mut self.by[via as usize];
        bucket.0 += ds;
        bucket.1 += da;
        if via != Via::Org {
            self.win.remove(&peer);
            return None;
        }
        let w = self.win.entry(peer).or_default();
        w.0 += ds;
        w.1 += da;
        w.2 += 1;
        if w.2 < WINDOW_SWEEPS {
            return None;
        }
        let (ws, wa, _) = std::mem::take(w);
        let pct = loss_pct(ws, wa).filter(|p| *p >= LOSSY_PCT)?;
        self.lossy += 1;
        if self
            .last_log
            .get(&peer)
            .is_none_or(|&t| now.duration_since(t) >= LOG_EVERY)
        {
            self.last_log.insert(peer, now);
            info!(
                peer = %peer, loss_pct = format!("{pct:.1}"), packets = ws,
                "overlay relay[loss-shadow]: the ORG carrier lost this share of the peer's \
                 packets over ~30 s, a lossy relay path where DERP may carry the pair better \
                 (measurement only; rate-limited 1/min/peer)"
            );
        }
        Some(pct)
    }

    /// The period's summary, `direct 0.10% of 52000, org 7.40% of 31000
    /// (lossy org windows: 4)`, and a fresh period. Peers no longer read are
    /// forgotten.
    pub(super) fn summary(&mut self, now: Instant) -> String {
        let buckets = Via::ALL
            .iter()
            .filter_map(|&v| {
                let (s, a) = self.by[v as usize];
                (s > 0).then(|| {
                    let lost = s.saturating_sub(a) as f64 * 100.0 / s as f64;
                    format!("{} {lost:.2}% of {s}", v.as_str())
                })
            })
            .collect::<Vec<_>>();
        self.by = [(0, 0); 4];
        let lossy = std::mem::take(&mut self.lossy);
        self.prev
            .retain(|_, (_, _, at)| now.duration_since(*at) < FORGET_AFTER);
        self.win.retain(|p, _| self.prev.contains_key(p));
        self.last_log.retain(|p, _| self.prev.contains_key(p));
        let buckets = if buckets.is_empty() {
            "no traffic".to_string()
        } else {
            buckets.join(", ")
        };
        format!("{buckets} (lossy org windows: {lossy})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> ObjectId {
        ObjectId::parse_str("6ade3631cd0b6f647805e07c").unwrap()
    }

    /// Feed `sweeps` readings that each add `sent` packets of which `got`
    /// arrived; returns the last verdict.
    fn feed(l: &mut RxLoss, via: Via, sweeps: u8, sent: u64, got: u64, t0: Instant) -> Option<f64> {
        let mut v = None;
        let (mut s, mut a) = (10, 10);
        l.note(peer(), via, (s, a), t0);
        for i in 1..=sweeps {
            s += sent;
            a += got;
            v = l.note(
                peer(),
                via,
                (s, a),
                t0 + Duration::from_secs(5 * u64::from(i)),
            );
        }
        v
    }

    #[test]
    fn a_lossy_org_window_is_judged_after_six_sweeps() {
        let t0 = Instant::now();
        let mut l = RxLoss::default();
        let pct = feed(&mut l, Via::Org, 6, 500, 460, t0).expect("8% over 3000 packets");
        assert!((pct - 8.0).abs() < 1e-9, "{pct}");
        assert!(
            l.summary(t0)
                .contains("org 8.00% of 3000 (lossy org windows: 1)")
        );
        assert_eq!(
            l.summary(t0),
            "no traffic (lossy org windows: 0)",
            "a fresh period"
        );
    }

    #[test]
    fn small_clean_or_non_org_windows_raise_no_verdict() {
        let t0 = Instant::now();
        let mut l = RxLoss::default();
        assert_eq!(
            feed(&mut l, Via::Org, 5, 500, 400, t0),
            None,
            "the window is still open"
        );
        let mut l = RxLoss::default();
        assert_eq!(
            feed(&mut l, Via::Org, 6, 100, 50, t0),
            None,
            "600 packets: too few to judge"
        );
        let mut l = RxLoss::default();
        assert_eq!(
            feed(&mut l, Via::Org, 6, 500, 490, t0),
            None,
            "2% is not lossy"
        );
        let mut l = RxLoss::default();
        assert_eq!(
            feed(&mut l, Via::Derp, 6, 500, 400, t0),
            None,
            "only ORG gets a verdict"
        );
        assert!(l.summary(t0).starts_with("derp 20.00% of 3000"));
    }

    #[test]
    fn a_reinstalled_peer_books_no_loss() {
        let t0 = Instant::now();
        let mut l = RxLoss::default();
        l.note(peer(), Via::Direct, (5000, 5000), t0);
        // Fresh `PeerStats` after a reinstall: the counters went backwards.
        assert_eq!(l.note(peer(), Via::Direct, (100, 100), t0), None);
        l.note(peer(), Via::Direct, (1100, 1100), t0);
        assert_eq!(l.summary(t0), "direct 0.00% of 1000 (lossy org windows: 0)");
    }

    #[test]
    fn via_buckets_our_side_of_the_pair() {
        assert_eq!(Via::of(true, Some(RelayKind::Org)), Via::Direct);
        assert_eq!(Via::of(false, Some(RelayKind::Org)), Via::Org);
        assert_eq!(Via::of(false, Some(RelayKind::Derp)), Via::Derp);
        assert_eq!(Via::of(false, Some(RelayKind::Turn)), Via::Turn);
        assert_eq!(Via::of(false, None), Via::Turn);
    }
}
