//! ROOMLER PATCH: a NewReno-lite controller (RFC 5681, RFC 6928 IW10, RFC 3465
//! byte counting) in place of upstream's Reno, which started at 2 KiB, never
//! cut cwnd on duplicate ACKs, and fell back to one MSS on every ACK once in
//! congestion avoidance. It is only useful with the `tcp.rs` patch that makes
//! cwnd bound the bytes in flight.
//!
//! smoltcp recovers loss go-back-N and calls `on_retransmit` for both a fast
//! retransmit and a timeout, so the controller tells them apart by the
//! duplicate ACKs it has counted since the last new ACK.

use crate::{
    socket::tcp::RttEstimator,
    time::{Duration, Instant},
};

use super::Controller;

/// RFC 3465 `L`: slow start grows by at most this many MSS per ACK, so a large
/// cumulative ACK (after recovery) cannot burst.
const ABC_LIMIT_MSS: usize = 2;
/// Duplicate ACKs that make a retransmit a fast retransmit (RFC 5681 §3.2).
const DUP_ACK_THRESHOLD: u8 = 3;
/// Spacing between multiplicative decreases until an RTT is measured.
const DEFAULT_SRTT: Duration = Duration::from_millis(100);
/// The MSS assumed before the handshake sets one (RFC 9293 default).
const DEFAULT_MSS: usize = 536;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Reno {
    cwnd: usize,
    ssthresh: usize,
    mss: usize,
    /// The largest window the peer has offered; cwnd never grows past it.
    rwnd: usize,
    /// Bytes acknowledged toward the next congestion-avoidance increase.
    acked: usize,
    dup_acks: u8,
    srtt: Duration,
    last_decrease: Option<Instant>,
    /// No data acknowledged yet: a new MSS re-derives the initial window.
    initial: bool,
}

/// RFC 6928: `min(10 * MSS, max(2 * MSS, 14600))`.
fn initial_window(mss: usize) -> usize {
    (10 * mss).min((2 * mss).max(14600))
}

impl Reno {
    pub fn new() -> Self {
        Reno {
            cwnd: initial_window(DEFAULT_MSS),
            ssthresh: usize::MAX,
            mss: DEFAULT_MSS,
            rwnd: 64 * 1024,
            acked: 0,
            dup_acks: 0,
            srtt: DEFAULT_SRTT,
            last_decrease: None,
            initial: true,
        }
    }

    /// One multiplicative decrease per round trip: the losses of one window
    /// are one congestion event (RFC 5681 §3.2; RFC 6582's intent), and
    /// go-back-N resends draw duplicate ACKs that would otherwise cut again.
    fn decrease_due(&mut self, now: Instant) -> bool {
        let due = self.last_decrease.map_or(true, |t| now >= t + self.srtt);
        if due {
            self.last_decrease = Some(now);
        }
        due
    }
}

impl Controller for Reno {
    fn window(&self) -> usize {
        self.cwnd
    }

    fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    fn on_ack(&mut self, _now: Instant, len: usize, rtt: &RttEstimator) {
        if rtt.have_measurement {
            self.srtt = Duration::from_millis(rtt.srtt.into());
        }
        // A duplicate ACK or a pure window update acknowledges nothing.
        if len == 0 {
            return;
        }
        self.initial = false;
        self.dup_acks = 0;
        if self.cwnd < self.ssthresh {
            self.cwnd += len.min(ABC_LIMIT_MSS * self.mss);
        } else {
            // +1 MSS per cwnd of bytes acknowledged, i.e. MSS²/cwnd per MSS.
            self.acked += len;
            if self.acked >= self.cwnd {
                self.acked -= self.cwnd;
                self.cwnd += self.mss;
            }
        }
        self.cwnd = self.cwnd.min(self.rwnd.max(initial_window(self.mss)));
    }

    fn on_duplicate_ack(&mut self, _now: Instant) {
        self.dup_acks = self.dup_acks.saturating_add(1);
    }

    fn on_retransmit(&mut self, now: Instant) {
        let fast = self.dup_acks >= DUP_ACK_THRESHOLD;
        self.dup_acks = 0;
        self.acked = 0;
        if fast {
            // Resume at half the window; a second fast retransmit inside the
            // same round trip is the same event and changes nothing.
            if self.decrease_due(now) {
                self.ssthresh = (self.cwnd / 2).max(2 * self.mss);
                self.cwnd = self.ssthresh;
            }
        } else {
            // A timeout: the ACK clock is gone, restart from one segment
            // (RFC 5681 §3.1 LW). A repeated timeout of the same data leaves
            // ssthresh where the first one put it.
            if self.cwnd > self.mss && self.decrease_due(now) {
                self.ssthresh = (self.cwnd / 2).max(2 * self.mss);
            }
            self.cwnd = self.mss;
        }
    }

    fn set_mss(&mut self, mss: usize) {
        self.mss = mss.max(1);
        if self.initial {
            self.cwnd = initial_window(self.mss);
        }
    }

    fn set_remote_window(&mut self, remote_window: usize) {
        if self.rwnd < remote_window {
            self.rwnd = remote_window;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const MSS: usize = 1460;

    fn reno() -> Reno {
        let mut r = Reno::new();
        r.set_mss(MSS);
        r.set_remote_window(16 * 1024 * 1024);
        r
    }

    fn rtt() -> RttEstimator {
        RttEstimator::default()
    }

    #[test]
    fn the_initial_window_is_rfc_6928() {
        assert_eq!(reno().window(), 14600);
        let mut r = Reno::new();
        r.set_mss(1200);
        assert_eq!(r.window(), 12000);
        r.set_mss(536);
        assert_eq!(r.window(), 5360, "an MSS before any ACK re-derives it");
    }

    #[test]
    fn slow_start_grows_by_at_most_two_segments_per_ack() {
        let mut r = reno();
        let now = Instant::from_millis(0);
        r.on_ack(now, MSS, &rtt());
        assert_eq!(r.window(), 14600 + MSS);
        r.on_ack(now, 64 * 1024, &rtt());
        assert_eq!(r.window(), 14600 + 3 * MSS, "a cumulative ACK cannot burst");
        r.on_ack(now, 0, &rtt());
        assert_eq!(
            r.window(),
            14600 + 3 * MSS,
            "a zero-length ACK grows nothing"
        );
    }

    #[test]
    fn congestion_avoidance_adds_one_segment_per_window() {
        let mut r = reno();
        let now = Instant::from_millis(0);
        for _ in 0..3 {
            r.on_duplicate_ack(now);
        }
        r.on_retransmit(now);
        let w = r.window();
        assert_eq!(w, 7300, "fast retransmit halves the window");
        r.on_ack(now, w - 1, &rtt());
        assert_eq!(r.window(), w);
        r.on_ack(now, 1, &rtt());
        assert_eq!(r.window(), w + MSS);
    }

    #[test]
    fn fast_retransmit_cuts_once_per_round_trip() {
        let mut r = reno();
        let t0 = Instant::from_millis(0);
        for _ in 0..3 {
            r.on_duplicate_ack(t0);
        }
        r.on_retransmit(t0);
        assert_eq!(r.window(), 7300);
        for _ in 0..3 {
            r.on_duplicate_ack(t0);
        }
        r.on_retransmit(Instant::from_millis(50));
        assert_eq!(r.window(), 7300, "the same loss event inside one srtt");
        for _ in 0..3 {
            r.on_duplicate_ack(t0);
        }
        r.on_retransmit(Instant::from_millis(150));
        assert_eq!(r.window(), 3650, "a later event cuts again");
        for _ in 0..3 {
            r.on_duplicate_ack(t0);
        }
        r.on_retransmit(Instant::from_millis(300));
        assert_eq!(r.window(), 2 * MSS, "never below two segments");
    }

    #[test]
    fn a_new_ack_resets_the_duplicate_count() {
        let mut r = reno();
        let now = Instant::from_millis(0);
        r.on_duplicate_ack(now);
        r.on_duplicate_ack(now);
        r.on_ack(now, MSS, &rtt());
        r.on_duplicate_ack(now);
        r.on_retransmit(now);
        assert_eq!(
            r.window(),
            MSS,
            "two then one duplicate is a timeout, not fast"
        );
    }

    #[test]
    fn a_timeout_restarts_from_one_segment_and_keeps_ssthresh_on_repeat() {
        let mut r = reno();
        let now = Instant::from_millis(0);
        r.on_retransmit(now);
        assert_eq!(r.window(), MSS);
        assert_eq!(r.ssthresh, 7300);
        r.on_retransmit(Instant::from_millis(1_000));
        assert_eq!(r.ssthresh, 7300, "a repeated timeout of the same data");
        // Slow start back up to ssthresh, then linear.
        while r.window() < r.ssthresh {
            r.on_ack(now, MSS, &rtt());
        }
        assert!(r.window() <= 7300 + 2 * MSS);
    }

    #[test]
    fn the_window_never_outgrows_the_largest_remote_window() {
        let mut r = Reno::new();
        r.set_mss(MSS);
        r.set_remote_window(32 * 1024);
        let now = Instant::from_millis(0);
        for _ in 0..100 {
            r.on_ack(now, MSS, &rtt());
        }
        assert_eq!(
            r.window(),
            64 * 1024,
            "the larger of the default and the offer"
        );
    }
}
