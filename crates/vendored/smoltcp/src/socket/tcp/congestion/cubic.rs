//! ROOMLER PATCH: CUBIC per RFC 9438 in place of upstream's, which worked in
//! bytes from a 2 KiB `w_max`, never left slow start's own ssthresh logic and
//! ran its cubic curve from `pre_transmit` on a 100 ms timer. Like the
//! NewReno-lite in `reno.rs` it is only useful with the `tcp.rs` patch that
//! makes cwnd bound the bytes in flight.
//!
//! - The window is kept in segments for the curve: `W_cubic(t) = C (t - K)^3
//!   + W_max`, `K = cbrt(W_max (1 - beta) / C)`, beta 0.7, C 0.4, with fast
//!   convergence (§4.7) and the Reno-friendly estimate `W_est` (§4.3).
//! - In congestion avoidance cwnd moves toward `W_cubic(t + RTT)`, at most
//!   1.5 × cwnd (§4.4), per byte acknowledged.
//! - Slow start, IW10 and one decrease per smoothed RTT match `reno.rs`; a
//!   timeout restarts from one segment (§4.8).

use crate::{
    socket::tcp::RttEstimator,
    time::{Duration, Instant},
};

use super::Controller;

const BETA: f64 = 0.7;
const C: f64 = 0.4;
/// RFC 9438 §4.3: the Reno-friendly additive increase, per round trip.
const ALPHA: f64 = 3.0 * (1.0 - BETA) / (1.0 + BETA);
/// RFC 3465 `L`, as in `reno.rs`.
const ABC_LIMIT_MSS: usize = 2;
const DUP_ACK_THRESHOLD: u8 = 3;
const DEFAULT_SRTT: Duration = Duration::from_millis(100);
const DEFAULT_MSS: usize = 536;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Cubic {
    cwnd: usize,
    ssthresh: usize,
    mss: usize,
    rwnd: usize,
    /// Segments: the window at the last congestion event, and the one before
    /// it (fast convergence).
    w_max: f64,
    w_last_max: f64,
    /// Seconds from the epoch start until the curve is back at `w_max`.
    k: f64,
    /// Start of the current congestion-avoidance epoch.
    epoch: Option<Instant>,
    /// Segments: the window standard Reno would have now.
    w_est: f64,
    dup_acks: u8,
    srtt: Duration,
    last_decrease: Option<Instant>,
    initial: bool,
}

/// RFC 6928: `min(10 * MSS, max(2 * MSS, 14600))`.
fn initial_window(mss: usize) -> usize {
    (10 * mss).min((2 * mss).max(14600))
}

/// Cube root by Newton's method (`core` has no `cbrt`).
fn cbrt(a: f64) -> f64 {
    if a <= 0.0 {
        return 0.0;
    }
    let mut x = if a > 1.0 { a / 3.0 } else { 1.0 };
    for _ in 0..64 {
        let next = (2.0 * x + a / (x * x)) / 3.0;
        let step = if next > x { next - x } else { x - next };
        if step <= 1e-9 * next {
            return next;
        }
        x = next;
    }
    x
}

impl Cubic {
    pub fn new() -> Self {
        Cubic {
            cwnd: initial_window(DEFAULT_MSS),
            ssthresh: usize::MAX,
            mss: DEFAULT_MSS,
            rwnd: 64 * 1024,
            w_max: 0.0,
            w_last_max: 0.0,
            k: 0.0,
            epoch: None,
            w_est: 0.0,
            dup_acks: 0,
            srtt: DEFAULT_SRTT,
            last_decrease: None,
            initial: true,
        }
    }

    fn segments(&self) -> f64 {
        self.cwnd as f64 / self.mss as f64
    }

    fn decrease_due(&mut self, now: Instant) -> bool {
        let due = self.last_decrease.map_or(true, |t| now >= t + self.srtt);
        if due {
            self.last_decrease = Some(now);
        }
        due
    }

    /// RFC 9438 §4.6–4.7: remember the window, cut to beta of it.
    fn congestion_event(&mut self) {
        let w = self.segments();
        self.w_max = if w < self.w_last_max {
            w * (1.0 + BETA) / 2.0
        } else {
            w
        };
        self.w_last_max = w;
        self.ssthresh = ((self.cwnd as f64 * BETA) as usize).max(2 * self.mss);
        self.epoch = None;
    }

    fn w_cubic(&self, t: f64) -> f64 {
        let d = t - self.k;
        C * d * d * d + self.w_max
    }
}

impl Controller for Cubic {
    fn window(&self) -> usize {
        self.cwnd
    }

    fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    fn on_ack(&mut self, now: Instant, len: usize, rtt: &RttEstimator) {
        if rtt.have_measurement {
            self.srtt = Duration::from_millis(rtt.srtt.into());
        }
        if len == 0 {
            return;
        }
        self.initial = false;
        self.dup_acks = 0;
        if self.cwnd < self.ssthresh {
            self.cwnd += len.min(ABC_LIMIT_MSS * self.mss);
        } else {
            let w = self.segments();
            let epoch = match self.epoch {
                Some(epoch) => epoch,
                None => {
                    // §4.2: a new epoch starts from the current window.
                    self.epoch = Some(now);
                    self.w_est = w;
                    self.k = if self.w_max > w {
                        cbrt((self.w_max - w) / C)
                    } else {
                        self.w_max = w;
                        0.0
                    };
                    now
                }
            };
            let t = (now - epoch).total_micros() as f64 / 1e6;
            let rtt_s = self.srtt.total_micros() as f64 / 1e6;
            let acked = len as f64 / self.mss as f64;
            self.w_est += ALPHA * acked / w;
            let target = self.w_cubic(t + rtt_s).clamp(w, 1.5 * w);
            let next = if self.w_cubic(t) < self.w_est {
                // §4.3: the Reno-friendly region.
                self.w_est
            } else {
                w + (target - w) / w * acked
            };
            self.cwnd = ((next * self.mss as f64) as usize).max(self.cwnd);
        }
        self.cwnd = self.cwnd.min(self.rwnd.max(initial_window(self.mss)));
    }

    fn on_duplicate_ack(&mut self, _now: Instant) {
        self.dup_acks = self.dup_acks.saturating_add(1);
    }

    fn on_retransmit(&mut self, now: Instant) {
        let fast = self.dup_acks >= DUP_ACK_THRESHOLD;
        self.dup_acks = 0;
        if fast {
            if self.decrease_due(now) {
                self.congestion_event();
                self.cwnd = self.ssthresh;
            }
        } else {
            // §4.8: a timeout. A repeated one leaves ssthresh and W_max alone.
            if self.cwnd > self.mss && self.decrease_due(now) {
                self.congestion_event();
            }
            self.epoch = None;
            self.cwnd = self.mss;
        }
    }

    fn on_fast_retransmit(&mut self, now: Instant) {
        self.dup_acks = self.dup_acks.max(DUP_ACK_THRESHOLD);
        self.on_retransmit(now);
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

    fn cubic() -> Cubic {
        let mut c = Cubic::new();
        c.set_mss(MSS);
        c.set_remote_window(64 * 1024 * 1024);
        c
    }

    fn rtt() -> RttEstimator {
        RttEstimator::default()
    }

    #[test]
    fn cbrt_is_a_cube_root() {
        for a in [0.001, 1.0, 27.0, 1000.0, 123_456.0] {
            let r = cbrt(a);
            let err = r * r * r - a;
            assert!(
                err * err <= (1e-6 * a.max(1.0)) * (1e-6 * a.max(1.0)),
                "{a}: {r}"
            );
        }
        assert_eq!(cbrt(0.0), 0.0);
    }

    #[test]
    fn slow_start_matches_reno() {
        let mut c = cubic();
        assert_eq!(c.window(), 14600);
        c.on_ack(Instant::from_millis(0), 64 * 1024, &rtt());
        assert_eq!(
            c.window(),
            14600 + 2 * MSS,
            "byte counting, at most 2 MSS per ACK"
        );
        assert!(c.in_slow_start());
    }

    #[test]
    fn a_loss_cuts_to_beta_and_the_curve_returns_to_w_max_after_k() {
        let mut c = cubic();
        c.cwnd = 100 * MSS;
        let t0 = Instant::from_millis(1000);
        for _ in 0..3 {
            c.on_duplicate_ack(t0);
        }
        c.on_retransmit(t0);
        assert_eq!(c.window(), 70 * MSS, "beta 0.7");
        assert!(!c.in_slow_start());
        // K = cbrt(100 * 0.3 / 0.4) ≈ 4.22 s: about there the window is back
        // near W_max, well before Reno's 30 round trips at +1 MSS each.
        let mut now = t0;
        for _ in 0..4300 {
            now += Duration::from_millis(1);
            c.on_ack(now, MSS, &rtt());
        }
        let w = c.window() as f64 / MSS as f64;
        assert!((90.0..=110.0).contains(&w), "near W_max at K: {w:.1}");
        // A second loss inside the same round trip changes nothing.
        let before = c.window();
        for _ in 0..3 {
            c.on_duplicate_ack(now);
        }
        c.on_retransmit(now);
        let after_one = c.window();
        c.on_fast_retransmit(now);
        assert_eq!(c.window(), after_one, "one decrease per round trip");
        assert!(after_one < before);
    }

    #[test]
    fn fast_convergence_lowers_w_max_when_the_window_shrinks() {
        let mut c = cubic();
        c.cwnd = 100 * MSS;
        c.on_fast_retransmit(Instant::from_millis(0));
        assert_eq!(c.w_max, 100.0);
        c.on_fast_retransmit(Instant::from_millis(10_000));
        let d = c.w_max - 70.0 * 1.7 / 2.0;
        assert!(d * d < 1e-12, "{}", c.w_max);
    }

    #[test]
    fn a_timeout_restarts_from_one_segment() {
        let mut c = cubic();
        c.cwnd = 50 * MSS;
        c.on_retransmit(Instant::from_millis(0));
        assert_eq!(c.window(), MSS);
        assert_eq!(c.ssthresh, 35 * MSS);
        assert!(c.in_slow_start());
    }
}
