// SPDX-License-Identifier: MPL-2.0
//! Path quality: this member's own measurement of a pair's two paths.
//!
//! The goal is to ride the relay only when it is clearly better than the
//! direct path, and never to flap between them. Before this, a pair stayed on
//! a direct path however slow it was (lab, 2026-11-11: direct at 960 ms
//! round trip against about 620 ms over the relay, for ten minutes), and
//! under heavy loss it fell to the relay and climbed straight back onto the
//! lossy direct path.
//!
//! The decision is the server's. This module is the member's half, and it
//! only measures: authenticated echo probes ([`super::disco`]) on the direct
//! path and on the relay path, kept in a sliding window per path and turned
//! into a report ([`Report`]) of counts and a median. Whether a report means
//! "prefer the relay" is judged by the server, over both members' reports,
//! and comes back as a time-limited `prefer_relay_ms` on the peer's netmap
//! row. Nothing here moves a carrier.
//!
//! # What is probed, and when
//!
//! Probing every pair on both paths all the time would put two frames a
//! second per pair through the relay, so a pair is measured only as far as
//! it needs to be ([`Mode`]):
//!
//! * **Watch.** The direct path looks fine. While the pair carries traffic
//!   it gets one direct probe per [`PROBE_EVERY`]; an idle pair gets none,
//!   and the 5 s disco table's reading stands in for it. Two bad probes of
//!   the last three start a comparison.
//! * **Compare.** Both paths are probed every [`PROBE_EVERY`] and a report
//!   goes out every [`REPORT_EVERY`]. A pair the server holds on the relay
//!   stays here for as long as the verdict stands, so the direct path keeps
//!   being measured and the pair can go back.
//! * **Settled.** The comparison found the relay no better. The pair is
//!   watched again, against the direct round trip it had then, and compared
//!   again when that gets worse or after a growing pause.
//!
//! # Loss
//!
//! A probe is a round trip, so loss in either direction counts. A probe is
//! lost once [`PROBE_TIMEOUT`] has passed without its answer, and a window
//! only ever holds probes that old, so every probe in a report is resolved.
//!
//! No sockets, no async and no clock reads: every method takes `now`.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use bson::oid::ObjectId;

/// How often a measured path gets a probe.
pub(crate) const PROBE_EVERY: Duration = Duration::from_secs(1);
/// A probe unanswered for this long is lost. Above any round trip a usable
/// path has; an answer that arrives later still counts as lost.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// The span of resolved probes a report covers.
pub(crate) const WINDOW: Duration = Duration::from_secs(10);
/// How often a compared pair is reported.
pub(crate) const REPORT_EVERY: Duration = Duration::from_secs(5);
/// A direct round trip at or above this starts a comparison. A relay has two
/// legs of its own, so below this it cannot be clearly better.
pub(crate) const SUSPECT_RTT_MS: f64 = 100.0;
/// Reports in a row with a direct path that is no longer suspect before a
/// comparison ends.
const CALM_REPORTS: u8 = 3;
/// Reports in a row in which the relay is no better (or cannot be measured)
/// before the pair settles.
const SETTLE_REPORTS: u8 = 6;
/// "No better": the direct median is within this of the relay's.
const EVEN_RATIO: f64 = 1.1;
const EVEN_SLACK_MS: f64 = 20.0;
/// A settled pair is compared again once its direct round trip is this much
/// worse than when it settled.
const WORSE_RATIO: f64 = 1.25;
/// The first pause before a settled pair is compared again, doubled each
/// time it settles again, up to [`RECHECK_MAX`].
const RECHECK_BASE: Duration = Duration::from_secs(120);
const RECHECK_MAX: Duration = Duration::from_secs(900);
/// The fewest resolved direct probes a report is worth sending for.
const MIN_REPORT_PROBES: u32 = 5;
/// While a verdict holds, a relay path that answers nothing for this long
/// (or cannot be probed at all) is reported as down.
const RELAY_DOWN_AFTER: Duration = Duration::from_secs(6);
/// Slack on periodic probe and report slots: the runtime drives [`Engine::tick`]
/// from a 1 s `tokio::time::interval`, whose wakeups jitter around each grid
/// deadline. Without slack, a tick that wakes tens of microseconds earlier
/// than the previous one misses `now >= next` and skips an entire 1 s slot.
const SLOT_SLACK: Duration = Duration::from_millis(50);

/// Which of the pair's two paths.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Leg {
    Direct,
    Relay,
}

/// One window's reading of one path.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) struct Stats {
    pub sent: u32,
    pub lost: u32,
    /// Median round trip of the answered probes.
    pub rtt_ms: Option<u32>,
}

/// One closed window of both paths, for `rc:overlay.path_quality`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Report {
    pub peer: ObjectId,
    pub window_ms: u32,
    pub direct: Stats,
    pub relay: Stats,
    pub on_relay: bool,
}

/// What the runtime knows about one peer this tick.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PeerNow {
    pub id: ObjectId,
    /// Our side of the pair rides a direct carrier.
    pub on_direct: bool,
    /// The server's prefer-relay verdict stands for this peer.
    pub holding: bool,
    /// Business traffic moved on the pair lately.
    pub active: bool,
    /// Authenticated inbound WG traffic arrived over the relay carrier this tick.
    pub relay_rx_recent: bool,
    /// The 5 s disco table's reading of the direct carrier, `(rtt_ms, loss)`
    /// with loss in `0.0..=1.0`: what an idle pair is watched by.
    pub slow_direct: Option<(Option<f64>, Option<f64>)>,
}

/// What the engine asks of the runtime.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Action {
    /// Send one echo probe with this nonce on this path, and call
    /// [`Engine::sent`] if it went out.
    Probe {
        peer: ObjectId,
        leg: Leg,
        nonce: [u8; 8],
    },
    Report(Report),
    /// The verdict holds but the relay path carries nothing: the hold must
    /// not outlive the relay.
    RelayDown {
        peer: ObjectId,
    },
    /// This member's probes read the direct path the pair rides as lossy but
    /// alive, right now. Raised every tick while it holds; the runtime tells
    /// the path monitor, which then waits for the server's verdict if that
    /// carrier dies instead of climbing straight back onto the path.
    LossyDirect {
        peer: ObjectId,
    },
}

#[derive(Clone, Copy)]
struct Probe {
    nonce: [u8; 8],
    sent: Instant,
    rtt_ms: Option<f64>,
}

/// One path's recent probes, oldest first.
#[derive(Default)]
struct Track {
    probes: VecDeque<Probe>,
    /// When the next probe is due; `None` = now.
    next: Option<Instant>,
}

fn slot_due(slot: Option<Instant>, now: Instant) -> bool {
    slot.is_none_or(|t| now + SLOT_SLACK >= t)
}

fn advance_slot(slot: &mut Option<Instant>, now: Instant, period: Duration) {
    *slot = Some(match *slot {
        Some(t) if now.saturating_duration_since(t) < period => t + period,
        _ => now + period,
    });
}

impl Track {
    fn due(&self, now: Instant) -> bool {
        slot_due(self.next, now)
    }

    fn push(&mut self, nonce: [u8; 8], now: Instant) {
        self.probes.push_back(Probe {
            nonce,
            sent: now,
            rtt_ms: None,
        });
    }

    /// Drop what no window can reach any more; returns the dropped nonces.
    fn trim(&mut self, now: Instant) -> Vec<[u8; 8]> {
        let keep = WINDOW + PROBE_TIMEOUT + PROBE_EVERY;
        let mut gone = Vec::new();
        while let Some(p) = self.probes.front() {
            if now.saturating_duration_since(p.sent) <= keep {
                break;
            }
            gone.push(p.nonce);
            self.probes.pop_front();
        }
        gone
    }

    fn clear(&mut self) -> Vec<[u8; 8]> {
        self.next = None;
        self.probes.drain(..).map(|p| p.nonce).collect()
    }

    /// The resolved window ending [`PROBE_TIMEOUT`] ago, and its span.
    fn stats(&self, now: Instant) -> (Stats, Duration) {
        let mut rtts: Vec<f64> = Vec::new();
        let (mut sent, mut first, mut last) = (0u32, None, None);
        for p in &self.probes {
            let age = now.saturating_duration_since(p.sent);
            if age < PROBE_TIMEOUT || age > PROBE_TIMEOUT + WINDOW {
                continue;
            }
            sent += 1;
            first.get_or_insert(p.sent);
            last = Some(p.sent);
            if let Some(r) = p.rtt_ms {
                rtts.push(r);
            }
        }
        rtts.sort_by(f64::total_cmp);
        let stats = Stats {
            sent,
            lost: sent - rtts.len() as u32,
            rtt_ms: rtts.get(rtts.len() / 2).map(|r| r.round() as u32),
        };
        let span = match (first, last) {
            (Some(a), Some(b)) => (b.saturating_duration_since(a) + PROBE_EVERY).min(WINDOW),
            _ => Duration::ZERO,
        };
        (stats, span)
    }

    /// Of the last `of` probes that can be judged (answered, or past the
    /// timeout), are at least `need` bad: lost, or at or above `rtt_ms`?
    fn recently_bad(&self, now: Instant, rtt_ms: f64, need: usize, of: usize) -> bool {
        self.probes
            .iter()
            .rev()
            .filter(|p| {
                p.rtt_ms.is_some() || now.saturating_duration_since(p.sent) >= PROBE_TIMEOUT
            })
            .take(of)
            .filter(|p| p.rtt_ms.is_none_or(|r| r >= rtt_ms))
            .count()
            >= need
    }

    /// Lossy but alive: of the last six probes that can be judged, at least
    /// two were lost and at least one was answered. A dead path (nothing
    /// answered) is not this: its failover and its return are the carrier
    /// lifecycle's business.
    fn lossy_but_alive(&self, now: Instant) -> bool {
        let (mut lost, mut answered) = (0, 0);
        for p in self
            .probes
            .iter()
            .rev()
            .filter(|p| {
                p.rtt_ms.is_some() || now.saturating_duration_since(p.sent) >= PROBE_TIMEOUT
            })
            .take(6)
        {
            if p.rtt_ms.is_some() {
                answered += 1;
            } else {
                lost += 1;
            }
        }
        lost >= 2 && answered >= 1
    }

    /// When a probe of this track was last answered.
    fn last_answer(&self) -> Option<Instant> {
        self.probes
            .iter()
            .rev()
            .find(|p| p.rtt_ms.is_some())
            .map(|p| p.sent)
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Mode {
    Watch,
    Compare {
        /// Reports in a row with an unsuspicious direct path.
        calm: u8,
        /// Reports in a row in which the relay was no better.
        even: u8,
    },
    Settled {
        /// The direct median when the comparison ended.
        baseline_ms: f64,
        recheck: Instant,
        /// The relay could not be measured at all (an older peer, no relay
        /// to probe through). Until `recheck`, nothing the direct path does
        /// can make a comparison worth its probes.
        relay_blind: bool,
    },
}

struct Pair {
    direct: Track,
    relay: Track,
    mode: Mode,
    next_report: Option<Instant>,
    /// How many times in a row the pair has settled (the recheck backoff).
    settles: u32,
    /// What our side rode at the last tick; a change starts the relay track
    /// over, because the two sides of it measure different relay paths.
    was_direct: Option<bool>,
    /// Since when, under a hold, the relay path has carried no answer.
    relay_silent_since: Option<Instant>,
    /// Last authenticated inbound activity on the active relay path (either a
    /// relay pong arrival, even past [`PROBE_TIMEOUT`], or inbound WG traffic).
    last_relay_rx: Option<Instant>,
}

impl Default for Pair {
    fn default() -> Self {
        Self {
            direct: Track::default(),
            relay: Track::default(),
            mode: Mode::Watch,
            next_report: None,
            settles: 0,
            was_direct: None,
            relay_silent_since: None,
            last_relay_rx: None,
        }
    }
}

/// The measurement engine: per-peer windows and the schedule that fills them.
pub(crate) struct Engine {
    pairs: HashMap<ObjectId, Pair>,
    /// Outstanding probes by nonce.
    pending: HashMap<[u8; 8], (ObjectId, Leg)>,
    /// Nonce source, seeded at random: several probers share the one pong
    /// channel and each must ignore the others' answers.
    seq: u64,
}

impl Engine {
    pub(crate) fn new() -> Self {
        Self::with_seed(rand::random::<u64>())
    }

    fn with_seed(seq: u64) -> Self {
        Self {
            pairs: HashMap::new(),
            pending: HashMap::new(),
            seq,
        }
    }

    fn nonce(&mut self) -> [u8; 8] {
        self.seq = self.seq.wrapping_add(1);
        self.seq.to_be_bytes()
    }

    /// A probe [`Action::Probe`] asked for actually went out at `now`.
    pub(crate) fn sent(&mut self, peer: ObjectId, leg: Leg, nonce: [u8; 8], now: Instant) {
        let Some(pair) = self.pairs.get_mut(&peer) else {
            return;
        };
        match leg {
            Leg::Direct => pair.direct.push(nonce, now),
            Leg::Relay => pair.relay.push(nonce, now),
        }
        self.pending.insert(nonce, (peer, leg));
    }

    /// `peer`'s authenticated echo answer with this nonce arrived at `at`.
    /// `true` if it answers one of our probes to that peer, in time.
    pub(crate) fn on_pong(&mut self, peer: &ObjectId, nonce: [u8; 8], at: Instant) -> bool {
        // Another prober's nonce, or ours answered by the wrong peer.
        if self.pending.get(&nonce).is_none_or(|(p, _)| p != peer) {
            return false;
        }
        let Some((_, leg)) = self.pending.remove(&nonce) else {
            return false;
        };
        let Some(pair) = self.pairs.get_mut(peer) else {
            return false;
        };
        if matches!(leg, Leg::Relay) {
            pair.last_relay_rx = Some(at);
        }
        let track = match leg {
            Leg::Direct => &mut pair.direct,
            Leg::Relay => &mut pair.relay,
        };
        let Some(p) = track.probes.iter_mut().find(|p| p.nonce == nonce) else {
            return false;
        };
        let rtt = at.saturating_duration_since(p.sent);
        if rtt > PROBE_TIMEOUT {
            return false; // already counted lost; a window never changes its mind
        }
        p.rtt_ms = Some(rtt.as_secs_f64() * 1000.0);
        true
    }

    /// Is this peer being compared (both paths probed, reports going out)?
    pub(crate) fn comparing(&self, peer: &ObjectId) -> bool {
        self.pairs
            .get(peer)
            .is_some_and(|p| matches!(p.mode, Mode::Compare { .. }))
    }

    /// One pass over the peers the runtime holds. Peers not listed are
    /// forgotten.
    pub(crate) fn tick(&mut self, now: Instant, peers: &[PeerNow]) -> Vec<Action> {
        let mut out = Vec::new();
        let gone: Vec<ObjectId> = self
            .pairs
            .keys()
            .filter(|id| !peers.iter().any(|p| p.id == **id))
            .copied()
            .collect();
        for id in gone {
            self.forget(&id);
        }
        for p in peers {
            self.tick_peer(now, p, &mut out);
        }
        out
    }

    fn forget(&mut self, peer: &ObjectId) {
        self.pairs.remove(peer);
        self.pending.retain(|_, (p, _)| p != peer);
    }

    fn tick_peer(&mut self, now: Instant, p: &PeerNow, out: &mut Vec<Action>) {
        let pair = self.pairs.entry(p.id).or_default();
        // A pair the death path left on the relay is none of this engine's
        // business until it is back on direct or the server holds it.
        if !p.on_direct && !p.holding && !matches!(pair.mode, Mode::Compare { .. }) {
            for n in pair.direct.clear().into_iter().chain(pair.relay.clear()) {
                self.pending.remove(&n);
            }
            pair.was_direct = Some(false);
            pair.relay_silent_since = None;
            pair.last_relay_rx = None;
            return;
        }
        for n in pair
            .direct
            .trim(now)
            .into_iter()
            .chain(pair.relay.trim(now))
        {
            self.pending.remove(&n);
        }
        if pair.was_direct.is_some_and(|w| w != p.on_direct) {
            for n in pair.relay.clear() {
                self.pending.remove(&n);
            }
            pair.relay_silent_since = None;
            pair.last_relay_rx = None;
            // A compared pair just left its direct carrier: the server
            // hears why now, not at the next report slot.
            if !p.on_direct && matches!(pair.mode, Mode::Compare { .. }) {
                pair.next_report = Some(now);
            }
        }
        pair.was_direct = Some(p.on_direct);

        // -- which mode ------------------------------------------------------
        if p.holding && !matches!(pair.mode, Mode::Compare { .. }) {
            pair.mode = Mode::Compare { calm: 0, even: 0 };
            pair.next_report = Some(now + REPORT_EVERY);
        }
        let start_comparing = match pair.mode {
            Mode::Watch => {
                pair.direct.recently_bad(now, SUSPECT_RTT_MS, 2, 3)
                    || (!p.active && slow_suspect(p.slow_direct, SUSPECT_RTT_MS))
            }
            // A settled pair needs a clearer signal than a watched one: its
            // direct path is known to be imperfect and was compared already.
            Mode::Settled {
                baseline_ms,
                recheck,
                relay_blind,
            } => {
                let worse = (baseline_ms * WORSE_RATIO).max(SUSPECT_RTT_MS);
                now >= recheck
                    || (!relay_blind
                        && (pair.direct.recently_bad(now, worse, 3, 5)
                            || (!p.active && slow_suspect(p.slow_direct, worse))))
            }
            Mode::Compare { .. } => false,
        };
        if start_comparing {
            pair.mode = Mode::Compare { calm: 0, even: 0 };
            pair.next_report = Some(now + REPORT_EVERY);
        }

        // -- probes ----------------------------------------------------------
        let comparing = matches!(pair.mode, Mode::Compare { .. });
        let mut want = Vec::new();
        if (comparing || p.active) && pair.direct.due(now) {
            advance_slot(&mut pair.direct.next, now, PROBE_EVERY);
            want.push(Leg::Direct);
        }
        if comparing && pair.relay.due(now) {
            advance_slot(&mut pair.relay.next, now, PROBE_EVERY);
            want.push(Leg::Relay);
        }

        // -- report ----------------------------------------------------------
        let mut report = None;
        if comparing && slot_due(pair.next_report, now) {
            advance_slot(&mut pair.next_report, now, REPORT_EVERY);
            let (direct, span) = pair.direct.stats(now);
            let (relay, _) = pair.relay.stats(now);
            if direct.sent >= MIN_REPORT_PROBES {
                report = Some(Report {
                    peer: p.id,
                    window_ms: span.as_millis() as u32,
                    direct,
                    relay,
                    on_relay: !p.on_direct,
                });
                if !p.holding {
                    Self::grade_comparison(pair, direct, relay, now);
                }
            }
        }

        // -- a hold must not outlive the relay --------------------------------
        let mut relay_down = false;
        if p.holding && !p.on_direct {
            if p.relay_rx_recent {
                pair.last_relay_rx = Some(now);
            }
            let heard = pair
                .last_relay_rx
                .or_else(|| pair.relay.last_answer())
                .is_some_and(|t| now.saturating_duration_since(t) < RELAY_DOWN_AFTER);
            if heard {
                pair.relay_silent_since = None;
            } else {
                let since = *pair.relay_silent_since.get_or_insert(now);
                // Only against a direct path that does answer: with both
                // dark there is nothing better to go back to.
                relay_down = now.saturating_duration_since(since) >= RELAY_DOWN_AFTER
                    && pair
                        .direct
                        .last_answer()
                        .is_some_and(|t| now.saturating_duration_since(t) < RELAY_DOWN_AFTER);
            }
        } else {
            pair.relay_silent_since = None;
        }

        let lossy_direct =
            comparing && p.on_direct && !p.holding && pair.direct.lossy_but_alive(now);
        for leg in want {
            let nonce = self.nonce();
            out.push(Action::Probe {
                peer: p.id,
                leg,
                nonce,
            });
        }
        if lossy_direct {
            out.push(Action::LossyDirect { peer: p.id });
        }
        if let Some(r) = report {
            out.push(Action::Report(r));
        }
        if relay_down {
            out.push(Action::RelayDown { peer: p.id });
        }
    }

    /// A report went out for a pair no verdict holds: does the comparison
    /// still earn its probes?
    fn grade_comparison(pair: &mut Pair, direct: Stats, relay: Stats, now: Instant) {
        let Mode::Compare { calm, even } = pair.mode else {
            return;
        };
        let d = direct.rtt_ms.map(f64::from);
        let is_calm = direct.lost == 0 && d.is_some_and(|d| d < SUSPECT_RTT_MS);
        // "No better" covers a relay that cannot be measured: with nothing
        // to compare against, the probes buy nothing.
        let relay_blind = relay.rtt_ms.is_none();
        let low_loss = direct.lost * 10 <= direct.sent;
        let is_even = relay_blind
            || (low_loss
                && match (d, relay.rtt_ms.map(f64::from)) {
                    (Some(d), Some(r)) => d <= (r * EVEN_RATIO).max(r + EVEN_SLACK_MS),
                    _ => false,
                });
        let calm = if is_calm { calm + 1 } else { 0 };
        let even = if is_even { even + 1 } else { 0 };
        pair.mode = if calm >= CALM_REPORTS {
            pair.settles = 0;
            Mode::Watch
        } else if even >= SETTLE_REPORTS {
            let pause = RECHECK_BASE
                .saturating_mul(1u32 << pair.settles.min(8))
                .min(RECHECK_MAX);
            pair.settles = pair.settles.saturating_add(1);
            Mode::Settled {
                baseline_ms: d.unwrap_or(SUSPECT_RTT_MS),
                recheck: now + pause,
                relay_blind,
            }
        } else {
            Mode::Compare { calm, even }
        };
        if !matches!(pair.mode, Mode::Compare { .. }) {
            pair.next_report = None;
        }
    }
}

/// Does the slow table's reading make the direct path suspect?
fn slow_suspect(slow: Option<(Option<f64>, Option<f64>)>, rtt_ms: f64) -> bool {
    slow.is_some_and(|(rtt, loss)| {
        rtt.is_some_and(|r| r >= rtt_ms) || loss.is_some_and(|l| l >= 0.2)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> ObjectId {
        ObjectId::parse_str("6ade3631cd0b6f647805e07c").unwrap()
    }

    fn now_peer(on_direct: bool, holding: bool, active: bool) -> PeerNow {
        PeerNow {
            id: peer(),
            on_direct,
            holding,
            active,
            relay_rx_recent: false,
            slow_direct: None,
        }
    }

    /// Drive `secs` one-second ticks from `t0 + from`. Each probe goes out
    /// and is answered after `direct`/`relay` ms; `None` loses it.
    #[allow(clippy::too_many_arguments)]
    fn run(
        e: &mut Engine,
        t0: Instant,
        from: u64,
        secs: u64,
        p: PeerNow,
        direct: impl Fn(u64) -> Option<u64>,
        relay: impl Fn(u64) -> Option<u64>,
    ) -> Vec<Action> {
        let mut all = Vec::new();
        for s in from..from + secs {
            let now = t0 + Duration::from_secs(s);
            let acts = e.tick(now, &[p]);
            for a in &acts {
                if let Action::Probe { peer, leg, nonce } = *a {
                    e.sent(peer, leg, nonce, now);
                    let rtt = match leg {
                        Leg::Direct => direct(s),
                        Leg::Relay => relay(s),
                    };
                    if let Some(ms) = rtt {
                        e.on_pong(&peer, nonce, now + Duration::from_millis(ms));
                    }
                }
            }
            all.extend(acts);
        }
        all
    }

    fn reports(acts: &[Action]) -> Vec<Report> {
        acts.iter()
            .filter_map(|a| match a {
                Action::Report(r) => Some(*r),
                _ => None,
            })
            .collect()
    }

    fn probes(acts: &[Action], leg: Leg) -> usize {
        acts.iter()
            .filter(|a| matches!(a, Action::Probe { leg: l, .. } if *l == leg))
            .count()
    }

    #[test]
    fn a_healthy_active_pair_gets_direct_probes_only_and_no_report() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        let acts = run(
            &mut e,
            t0,
            0,
            60,
            now_peer(true, false, true),
            |_| Some(1),
            |_| Some(600),
        );
        assert_eq!(probes(&acts, Leg::Direct), 60);
        assert_eq!(
            probes(&acts, Leg::Relay),
            0,
            "a healthy pair costs the relay nothing"
        );
        assert!(reports(&acts).is_empty());
        assert!(!e.comparing(&peer()));
    }

    #[test]
    fn an_idle_healthy_pair_is_not_probed_at_all() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        let acts = run(
            &mut e,
            t0,
            0,
            60,
            now_peer(true, false, false),
            |_| Some(1),
            |_| Some(600),
        );
        assert!(acts.is_empty(), "{acts:?}");
    }

    #[test]
    fn an_idle_pair_is_compared_once_the_slow_table_reads_it_suspect() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        let mut p = now_peer(true, false, false);
        p.slow_direct = Some((Some(960.0), Some(0.0)));
        let acts = run(&mut e, t0, 0, 3, p, |_| Some(960), |_| Some(620));
        assert!(e.comparing(&peer()));
        assert!(probes(&acts, Leg::Relay) >= 2);
        let mut lossy = now_peer(true, false, false);
        lossy.slow_direct = Some((Some(1.0), Some(0.25)));
        let mut e = Engine::with_seed(7);
        run(&mut e, t0, 0, 1, lossy, |_| Some(1), |_| Some(620));
        assert!(e.comparing(&peer()), "loss alone is suspect too");
    }

    #[test]
    fn a_slow_direct_path_starts_the_comparison_within_three_probes() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        let p = now_peer(true, false, true);
        run(&mut e, t0, 0, 20, p, |_| Some(1), |_| Some(620));
        assert!(!e.comparing(&peer()));
        // The direct path turns slow at t0+20.
        let acts = run(&mut e, t0, 20, 3, p, |_| Some(960), |_| Some(620));
        assert!(e.comparing(&peer()), "two slow probes of three are enough");
        assert!(
            probes(&acts, Leg::Relay) >= 1,
            "the relay is measured from here on"
        );
    }

    #[test]
    fn a_lossy_direct_path_starts_the_comparison_once_its_probes_time_out() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        let p = now_peer(true, false, true);
        run(&mut e, t0, 0, 10, p, |_| Some(1), |_| Some(620));
        // From t0+10 every direct probe is lost.
        run(&mut e, t0, 10, 3, p, |_| None, |_| Some(620));
        assert!(
            !e.comparing(&peer()),
            "unanswered for under the timeout is not loss yet"
        );
        run(&mut e, t0, 13, 2, p, |_| None, |_| Some(620));
        assert!(e.comparing(&peer()));
    }

    #[test]
    fn a_report_carries_the_resolved_window_of_both_paths() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        let p = now_peer(true, false, true);
        // Slow from the start; every fourth direct probe is lost.
        let acts = run(
            &mut e,
            t0,
            0,
            30,
            p,
            |s| (s % 4 != 0).then_some(960),
            |_| Some(620),
        );
        let last = *reports(&acts).last().expect("a compared pair reports");
        assert_eq!(last.peer, peer());
        assert!(!last.on_relay);
        assert_eq!(last.window_ms, 10_000);
        // The window holds the probes sent 2..=12 s before the report.
        assert_eq!(last.direct.sent, 11);
        assert_eq!(last.direct.lost, 3);
        assert_eq!(last.direct.rtt_ms, Some(960));
        assert_eq!(last.relay.lost, 0);
        assert_eq!(last.relay.rtt_ms, Some(620));
        assert!(last.relay.sent >= 10);
    }

    #[test]
    fn reports_come_every_five_seconds_while_the_relay_is_clearly_better() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        let p = now_peer(true, false, true);
        let acts = run(&mut e, t0, 0, 120, p, |_| Some(960), |_| Some(620));
        let n = reports(&acts).len();
        assert!((20..=24).contains(&n), "{n} reports in 120 s");
        assert!(
            e.comparing(&peer()),
            "a clearly worse direct path never settles"
        );
    }

    #[test]
    fn a_late_or_foreign_answer_is_no_sample() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        let p = now_peer(true, false, true);
        let acts = e.tick(t0, &[p]);
        let Action::Probe { peer, leg, nonce } = acts[0] else {
            panic!("{acts:?}")
        };
        e.sent(peer, leg, nonce, t0);
        assert!(!e.on_pong(&peer, [9; 8], t0), "not ours");
        let other = ObjectId::parse_str("6ade3631cd0b6f647805e07d").unwrap();
        assert!(
            !e.on_pong(&other, nonce, t0),
            "ours, but another peer answered"
        );
        assert!(
            !e.on_pong(&peer, nonce, t0 + PROBE_TIMEOUT + Duration::from_millis(1)),
            "past the timeout"
        );
        assert!(
            !e.on_pong(&peer, nonce, t0),
            "and it cannot be answered twice"
        );
    }

    #[test]
    fn a_pair_whose_relay_is_no_better_settles_and_is_compared_again_when_direct_worsens() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        let p = now_peer(true, false, true);
        // Direct 672 ms against a 620 ms relay: suspect, but no better.
        let acts = run(&mut e, t0, 0, 70, p, |_| Some(672), |_| Some(620));
        assert!(
            !e.comparing(&peer()),
            "settled after {SETTLE_REPORTS} even reports"
        );
        assert!(!reports(&acts).is_empty());
        // Settled: the relay is left alone.
        let quiet = run(&mut e, t0, 70, 30, p, |_| Some(672), |_| Some(620));
        assert_eq!(probes(&quiet, Leg::Relay), 0);
        assert!(reports(&quiet).is_empty());
        assert_eq!(
            probes(&quiet, Leg::Direct),
            30,
            "still watched while it carries traffic"
        );
        // Direct climbs to 960 ms: compared again after three slow probes.
        run(&mut e, t0, 100, 3, p, |_| Some(960), |_| Some(620));
        assert!(
            !e.comparing(&peer()),
            "two are not enough for a settled pair"
        );
        run(&mut e, t0, 103, 1, p, |_| Some(960), |_| Some(620));
        assert!(e.comparing(&peer()));
    }

    #[test]
    fn a_settled_pair_is_rechecked_after_its_pause_which_grows() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        let p = now_peer(true, false, true);
        run(&mut e, t0, 0, 70, p, |_| Some(672), |_| Some(620));
        assert!(!e.comparing(&peer()));
        // Nothing changes; the first recheck comes RECHECK_BASE after settling.
        let acts = run(&mut e, t0, 70, 200, p, |_| Some(672), |_| Some(620));
        assert!(probes(&acts, Leg::Relay) > 0, "rechecked");
        assert!(!e.comparing(&peer()), "and settled again");
        // The second pause is twice the first.
        let acts = run(&mut e, t0, 270, 150, p, |_| Some(672), |_| Some(620));
        assert_eq!(probes(&acts, Leg::Relay), 0, "{acts:?}");
    }

    #[test]
    fn a_comparison_ends_once_the_direct_path_is_healthy_again() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        let p = now_peer(true, false, true);
        run(&mut e, t0, 0, 30, p, |_| Some(960), |_| Some(620));
        assert!(e.comparing(&peer()));
        run(&mut e, t0, 30, 40, p, |_| Some(1), |_| Some(620));
        assert!(!e.comparing(&peer()));
        let acts = run(&mut e, t0, 70, 20, p, |_| Some(1), |_| Some(620));
        assert_eq!(probes(&acts, Leg::Relay), 0);
    }

    #[test]
    fn a_pair_with_no_measurable_relay_stops_probing_it() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        let p = now_peer(true, false, true);
        // The peer never answers a relay probe (an older build).
        run(&mut e, t0, 0, 70, p, |_| Some(960), |_| None);
        assert!(!e.comparing(&peer()), "nothing to compare against");
        // And however bad the direct path then gets, the relay is left alone
        // until the recheck.
        let acts = run(&mut e, t0, 70, 60, p, |_| None, |_| None);
        assert_eq!(probes(&acts, Leg::Relay), 0, "{acts:?}");
        assert!(reports(&acts).is_empty());
    }

    #[test]
    fn a_hold_keeps_both_paths_measured_however_good_direct_looks() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        // On the relay under the server's verdict; direct has recovered.
        let p = now_peer(false, true, false);
        let acts = run(&mut e, t0, 0, 300, p, |_| Some(1), |_| Some(620));
        assert!(
            e.comparing(&peer()),
            "the pair is measured for as long as it is held"
        );
        assert_eq!(probes(&acts, Leg::Direct), 300);
        assert_eq!(probes(&acts, Leg::Relay), 300);
        let r = reports(&acts);
        assert!(r.len() >= 55, "{} reports", r.len());
        let last = r.last().unwrap();
        assert!(last.on_relay);
        assert_eq!((last.direct.lost, last.direct.rtt_ms), (0, Some(1)));
    }

    #[test]
    fn a_relay_that_stops_answering_under_a_hold_is_reported_down() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        let p = now_peer(false, true, true);
        let acts = run(&mut e, t0, 0, 20, p, |_| Some(960), |_| Some(620));
        assert!(!acts.iter().any(|a| matches!(a, Action::RelayDown { .. })));
        // The relay goes dark at t0+20; direct still answers.
        let acts = run(&mut e, t0, 20, 14, p, |_| Some(960), |_| None);
        let first = acts
            .iter()
            .position(|a| matches!(a, Action::RelayDown { .. }))
            .expect("a dead relay is reported");
        assert!(first > 0);
        // With the direct path dark as well, there is nothing to go back to.
        let mut e = Engine::with_seed(7);
        run(&mut e, t0, 0, 20, p, |_| Some(960), |_| Some(620));
        let acts = run(&mut e, t0, 20, 30, p, |_| None, |_| None);
        assert!(!acts.iter().any(|a| matches!(a, Action::RelayDown { .. })));
    }

    #[test]
    fn a_pair_that_fell_to_the_relay_on_its_own_is_left_alone() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        // Direct died and the death path moved the pair; no verdict stands.
        let acts = run(
            &mut e,
            t0,
            0,
            30,
            now_peer(false, false, true),
            |_| Some(1),
            |_| Some(620),
        );
        assert!(acts.is_empty(), "{acts:?}");
    }

    #[test]
    fn a_comparison_survives_the_pair_falling_to_the_relay() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        run(
            &mut e,
            t0,
            0,
            10,
            now_peer(true, false, true),
            |_| None,
            |_| Some(620),
        );
        assert!(e.comparing(&peer()));
        // The lossy direct carrier dies; the comparison carries on, so the
        // server still learns why.
        let acts = run(
            &mut e,
            t0,
            10,
            20,
            now_peer(false, false, true),
            |_| None,
            |_| Some(620),
        );
        let r = reports(&acts);
        assert!(!r.is_empty());
        assert!(r.last().unwrap().on_relay);
        assert_eq!(r.last().unwrap().direct.rtt_ms, None);
    }

    /// The direct path a pair rides is flagged lossy only while it both
    /// loses probes and answers some. A dead path is never flagged (its
    /// failover and fast return are not this module's to slow), and neither
    /// is a slow but lossless one.
    #[test]
    fn a_lossy_direct_path_is_flagged_while_it_still_answers() {
        let flagged = |acts: &[Action]| {
            acts.iter()
                .filter(|a| matches!(a, Action::LossyDirect { .. }))
                .count()
        };
        let (t0, p) = (Instant::now(), now_peer(true, false, true));
        // Two probes of three lost.
        let mut e = Engine::with_seed(7);
        let acts = run(
            &mut e,
            t0,
            0,
            30,
            p,
            |s| (s % 3 == 0).then_some(2),
            |_| Some(620),
        );
        assert!(e.comparing(&peer()));
        assert!(
            flagged(&acts) >= 20,
            "every tick once compared: {}",
            flagged(&acts)
        );
        // Dead: compared, never flagged.
        let mut e = Engine::with_seed(7);
        let acts = run(&mut e, t0, 0, 30, p, |_| None, |_| Some(620));
        assert!(e.comparing(&peer()));
        assert_eq!(flagged(&acts), 0);
        // Slow and lossless: compared, never flagged.
        let mut e = Engine::with_seed(7);
        let acts = run(&mut e, t0, 0, 30, p, |_| Some(960), |_| Some(620));
        assert_eq!(flagged(&acts), 0);
        // And not once the pair has left the direct carrier.
        let mut e = Engine::with_seed(7);
        run(
            &mut e,
            t0,
            0,
            15,
            p,
            |s| (s % 3 == 0).then_some(2),
            |_| Some(620),
        );
        let acts = run(
            &mut e,
            t0,
            15,
            10,
            now_peer(false, false, true),
            |s| (s % 3 == 0).then_some(2),
            |_| Some(620),
        );
        assert_eq!(flagged(&acts), 0);
    }

    /// The tick a compared pair's direct carrier is gone, its report goes
    /// out: the server's verdict has to beat the probe that would climb back.
    #[test]
    fn a_compared_pair_reports_the_moment_it_falls_to_the_relay() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        let lossy = |s: u64| s.is_multiple_of(3).then_some(2);
        let acts = run(
            &mut e,
            t0,
            0,
            13,
            now_peer(true, false, true),
            lossy,
            |_| Some(620),
        );
        let last_on_direct = acts
            .iter()
            .rposition(|a| matches!(a, Action::Report(_)))
            .expect("compared and reported");
        assert!(last_on_direct < acts.len());
        // The carrier dies between two report slots.
        let acts = run(
            &mut e,
            t0,
            13,
            1,
            now_peer(false, false, true),
            lossy,
            |_| Some(620),
        );
        let r = reports(&acts);
        assert_eq!(r.len(), 1, "{acts:?}");
        assert!(r[0].on_relay);
        assert!(
            r[0].direct.lost >= 3 && r[0].direct.rtt_ms == Some(2),
            "{:?}",
            r[0]
        );
    }

    #[test]
    fn a_peer_that_left_is_forgotten() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        run(
            &mut e,
            t0,
            0,
            5,
            now_peer(true, false, true),
            |_| None,
            |_| None,
        );
        assert!(!e.pending.is_empty());
        e.tick(t0 + Duration::from_secs(5), &[]);
        assert!(e.pairs.is_empty() && e.pending.is_empty());
    }

    #[test]
    fn the_relay_window_starts_over_when_the_carrier_changes() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        run(
            &mut e,
            t0,
            0,
            20,
            now_peer(true, false, true),
            |_| Some(960),
            |_| Some(620),
        );
        // Demoted: the relay probes now ride the carrier itself.
        let acts = run(
            &mut e,
            t0,
            20,
            6,
            now_peer(false, true, true),
            |_| Some(960),
            |_| Some(300),
        );
        let r = *reports(&acts).last().expect("still reporting");
        assert!(r.relay.sent <= 4, "{r:?}");
        assert_eq!(
            r.relay.rtt_ms,
            Some(300),
            "no sample of the old relay path is mixed in"
        );
    }

    #[test]
    fn jittered_one_second_ticks_still_fill_every_ten_second_window() {
        let (t0, mut e) = (Instant::now(), Engine::with_seed(7));
        let p = now_peer(true, false, true);
        let mut all = Vec::new();
        // Simulate real OS interval wakeups: odd ticks wake 1 ms after the
        // 1 s grid, even ticks wake 4 ms after, so every odd tick is 3 ms
        // less than 1.000 s after the previous tick.
        for s in 0..60u64 {
            let jitter = Duration::from_millis(if s.is_multiple_of(2) { 4 } else { 1 });
            let now = t0 + Duration::from_secs(s) + jitter;
            let acts = e.tick(now, &[p]);
            for a in &acts {
                if let Action::Probe { peer, leg, nonce } = *a {
                    e.sent(peer, leg, nonce, now);
                    let rtt = match leg {
                        Leg::Direct => 960,
                        Leg::Relay => 390,
                    };
                    e.on_pong(&peer, nonce, now + Duration::from_millis(rtt));
                }
            }
            all.extend(acts);
        }
        let r = reports(&all);
        assert!(r.len() >= 9, "expected 5 s report cadence, got {}", r.len());
        // After the comparison warms up, every full 10 s window must carry >= 9
        // resolved probes so the server's MIN_DIRECT_PROBES (8) never grades Thin.
        for w in r.iter().skip(2) {
            assert!(w.direct.sent >= 9, "thin direct window under jitter: {w:?}");
            assert!(w.relay.sent >= 9, "thin relay window under jitter: {w:?}");
        }
    }

    #[test]
    fn a_relay_carrying_traffic_or_late_pongs_is_not_reported_down() {
        let t0 = Instant::now();
        // Case 1: relay disco probes are shed/lost under DERP queue-age cap,
        // while inbound WG traffic keeps arriving over the relay carrier.
        let mut e = Engine::with_seed(7);
        let mut live_rx = now_peer(false, true, true);
        live_rx.relay_rx_recent = true;
        run(&mut e, t0, 0, 10, live_rx, |_| Some(960), |_| Some(540));
        let acts = run(&mut e, t0, 10, 20, live_rx, |_| Some(960), |_| None);
        assert!(
            !acts.iter().any(|a| matches!(a, Action::RelayDown { .. })),
            "inbound WG relay traffic proves the relay is alive: {acts:?}"
        );

        // Case 2: idle pair whose relay pongs arrive at 2200 ms (> PROBE_TIMEOUT),
        // so they count as lost for quality, yet prove the relay still answers.
        let mut e = Engine::with_seed(7);
        let idle = now_peer(false, true, false);
        let mut acts = Vec::new();
        for s in 0..25u64 {
            let now = t0 + Duration::from_secs(s);
            let step = e.tick(now, &[idle]);
            for a in &step {
                if let Action::Probe { peer, leg, nonce } = *a {
                    e.sent(peer, leg, nonce, now);
                    let rtt = match leg {
                        Leg::Direct => 960,
                        Leg::Relay => 2200,
                    };
                    e.on_pong(&peer, nonce, now + Duration::from_millis(rtt));
                }
            }
            acts.extend(step);
        }
        assert!(
            !acts.iter().any(|a| matches!(a, Action::RelayDown { .. })),
            "late relay pongs still prove relay reachability: {acts:?}"
        );
    }
}
