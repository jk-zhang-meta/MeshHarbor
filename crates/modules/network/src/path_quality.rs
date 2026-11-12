//! Path quality: the server's prefer-relay verdict.
//!
//! A pair's direct path can be far worse than its relay path and still pass
//! every liveness check. Field, 2026-11-11 (lab): a direct path at 960 ms
//! round trip stayed in use for ten minutes while the relay measured about
//! 620 ms, and a direct path losing a quarter of its packets was left and
//! re-entered every few seconds. A member cannot settle this alone: each end
//! sees one side, and two ends deciding separately is how a pair flaps.
//!
//! So the members only measure. Each reports closed windows of its own echo
//! probes over both paths (`rc:overlay.path_quality`), and this module judges
//! them:
//!
//! * **Enter** when both members measured, over a full window each, a direct
//!   path clearly worse than a healthy relay path ([`grade`]). One member is
//!   enough once its side has already fallen to the relay, because the
//!   verdict then moves nothing and only stops the climb back. A direct path
//!   that answers nothing at all starts no verdict: a dead path already
//!   fails over, and its quick return when it comes back must stay quick.
//! * **Renew** while fresh reports keep coming and the direct path has not
//!   healed. The verdict is a lifetime ([`VERDICT_TTL`]) on both ends'
//!   netmap rows (`NetmapPeer::prefer_relay_ms`), pushed again well before it
//!   runs out. Reports stopping is enough to end it: it is never renewed
//!   from anything but a measurement.
//! * **Withdraw** when every reporting member has measured the direct path
//!   healthy for long enough ([`EXIT_SUSTAIN`], doubled for a pair that came
//!   straight back), or at once when the relay itself stops answering.
//!
//! Thresholds are deliberately apart: 35% and 100 ms worse to enter, within
//! 15% or 30 ms to leave, 20% probe loss to enter, 5% to leave. Between them
//! a pair stays where it is.
//!
//! `MESHHARBOR__OVERLAY__PREFER_RELAY_MODE` = `off` | `shadow` | `on`
//! ([`Mode`]), read when the module's state is built. State is pod-local, like `relay_pair_churn` and for the same
//! reason: tenant affinity puts a pair's two members on one pod. A restarted
//! pod has no verdicts; the members' holds run out and fresh reports rebuild
//! whatever still applies.

use std::time::{Duration, Instant};

use bson::oid::ObjectId;
use dashmap::DashMap;
use meshharbor_remote_control::models::OverlayNode;
use tracing::{debug, info};

use crate::NetworkState;
use crate::overlay::{self, NodeIdentity};

/// How far the verdict is engaged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Mode {
    /// No reports asked for, none judged, no row stamped.
    Off = 0,
    /// Reports are asked for and judged, and each would-be verdict is
    /// logged, but no row is stamped: nothing moves.
    Shadow = 1,
    /// Verdicts are stamped on both ends' netmap rows.
    On = 2,
}

impl Mode {
    /// `off|0|false|no` → Off, `shadow` → Shadow, anything else (unset
    /// included) → On.
    pub fn parse(v: Option<&str>) -> Self {
        match v.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            Some("off") | Some("0") | Some("false") | Some("no") => Mode::Off,
            Some("shadow") => Mode::Shadow,
            _ => Mode::On,
        }
    }
}

impl Mode {
    /// The mode `MESHHARBOR__OVERLAY__PREFER_RELAY_MODE` asks for.
    pub fn from_env() -> Self {
        Mode::parse(
            std::env::var("MESHHARBOR__OVERLAY__PREFER_RELAY_MODE")
                .ok()
                .as_deref(),
        )
    }

    fn from_u8(v: u8) -> Self {
        match v {
            0 => Mode::Off,
            1 => Mode::Shadow,
            _ => Mode::On,
        }
    }
}

/// How long one verdict lasts on a member unless renewed. A member honors at
/// most twice this from one row (`PREFER_RELAY_MAX` on the agent).
pub const VERDICT_TTL: Duration = Duration::from_secs(60);
/// A standing verdict is pushed again once its last push is this old, so a
/// member's remaining lifetime stays above half of [`VERDICT_TTL`].
const REPUSH_AFTER: Duration = Duration::from_secs(20);
/// A member that says it still rides a direct carrier under a standing
/// verdict gets the row again after this long: its push was lost.
const REPUSH_STRAGGLER_AFTER: Duration = Duration::from_secs(5);
/// How long a member's last report speaks for it.
const FRESH: Duration = Duration::from_secs(15);
/// Reports from one member about one pair closer together than this are
/// dropped (a member sends one per 5 s).
const MIN_REPORT_GAP: Duration = Duration::from_secs(1);
/// What a window must hold before it is judged.
const MIN_WINDOW_MS: u32 = 8_000;
const MIN_DIRECT_PROBES: u32 = 8;
const MIN_RELAY_PROBES: u32 = 3;
/// Enter: the direct median is at least this share of the relay's AND at
/// least this many ms above it.
const ENTER_RATIO_PCT: u64 = 135;
const ENTER_GAP_MS: u64 = 100;
/// Leave: the direct median is within this share of the relay's OR within
/// this many ms of it.
const EXIT_RATIO_PCT: u64 = 115;
const EXIT_GAP_MS: u64 = 30;
/// Enter at this share of direct probes lost (a probe is a round trip, so
/// 20% is about 11% each way); leave at or under [`EXIT_LOSS_PCT`].
const ENTER_LOSS_PCT: u64 = 20;
const EXIT_LOSS_PCT: u64 = 5;
/// A relay path losing more than this is not preferred or renewed; at
/// [`RELAY_DOWN_PCT`] a standing verdict is withdrawn at once.
const RELAY_MAX_LOSS_PCT: u64 = 10;
const RELAY_DOWN_PCT: u64 = 50;
/// A verdict stands at least this long before it can be withdrawn as healed.
const MIN_HOLD: Duration = Duration::from_secs(20);
/// How long every fresh report must read healthy before a verdict is
/// withdrawn. Doubled per re-entry within [`REENTRY_MEMORY`], up to
/// [`MAX_EXIT_DOUBLINGS`] times, so a pair whose direct path keeps relapsing
/// goes back to it more and more reluctantly.
const EXIT_SUSTAIN: Duration = Duration::from_secs(10);
const REENTRY_MEMORY: Duration = Duration::from_secs(30 * 60);
const MAX_EXIT_DOUBLINGS: u32 = 4;
/// Tracked pairs before stale ones are swept.
const PAIR_CAP: usize = 10_000;
/// How long a connection's resolved node is trusted without a re-read.
const REPORTER_TTL: Duration = Duration::from_secs(60);

/// One member's closed window (`ClientMsg::OverlayPathQuality`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Report {
    pub window_ms: u32,
    pub direct_sent: u32,
    pub direct_lost: u32,
    pub direct_rtt_ms: Option<u32>,
    pub relay_sent: u32,
    pub relay_lost: u32,
    pub relay_rtt_ms: Option<u32>,
    pub on_relay: bool,
}

/// Why the direct path is clearly worse.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Worse {
    Latency,
    Loss,
}

/// What one window says about the pair.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Grade {
    /// Too little measured to say anything.
    Thin,
    /// The relay path answers almost nothing: it cannot be preferred.
    RelayDown,
    /// The relay path loses too much to be preferred, but it does carry.
    RelayPoor,
    /// Nothing on the direct path answered. A dead path is the carrier
    /// lifecycle's business (failover, then the fast return when it comes
    /// back), so it starts no verdict; it does keep a standing one.
    Dead,
    /// The direct path is clearly worse than a healthy relay path.
    Worse(Worse),
    /// Neither clearly worse nor healthy: the pair stays where it is.
    Between,
    /// The direct path is as good as the relay or better, and loses nothing
    /// to speak of.
    Healthy,
}

/// Pure: grade one window. Integer arithmetic throughout; a lost count above
/// the sent count is clamped.
pub fn grade(r: &Report) -> Grade {
    if r.window_ms < MIN_WINDOW_MS
        || r.direct_sent < MIN_DIRECT_PROBES
        || r.relay_sent < MIN_RELAY_PROBES
    {
        return Grade::Thin;
    }
    let (d_sent, r_sent) = (u64::from(r.direct_sent), u64::from(r.relay_sent));
    let d_lost = u64::from(r.direct_lost).min(d_sent);
    let r_lost = u64::from(r.relay_lost).min(r_sent);
    let Some(relay_ms) = r.relay_rtt_ms.map(u64::from) else {
        return Grade::RelayDown;
    };
    if r_lost * 100 >= r_sent * RELAY_DOWN_PCT {
        return Grade::RelayDown;
    }
    if r_lost * 100 > r_sent * RELAY_MAX_LOSS_PCT {
        return Grade::RelayPoor;
    }
    let Some(direct_ms) = r.direct_rtt_ms.map(u64::from).filter(|_| d_lost < d_sent) else {
        return Grade::Dead;
    };
    if d_lost * 100 >= d_sent * ENTER_LOSS_PCT {
        return Grade::Worse(Worse::Loss);
    }
    if direct_ms * 100 >= relay_ms * ENTER_RATIO_PCT && direct_ms >= relay_ms + ENTER_GAP_MS {
        return Grade::Worse(Worse::Latency);
    }
    if d_lost * 100 <= d_sent * EXIT_LOSS_PCT
        && (direct_ms * 100 <= relay_ms * EXIT_RATIO_PCT || direct_ms <= relay_ms + EXIT_GAP_MS)
    {
        return Grade::Healthy;
    }
    Grade::Between
}

/// Whether `r`'s direct window reads healed on its own, even when the relay
/// leg in the same window is congested or down (`RelayPoor` / `RelayDown`).
fn direct_healed(r: &Report) -> bool {
    if r.window_ms < MIN_WINDOW_MS || r.direct_sent < MIN_DIRECT_PROBES {
        return false;
    }
    let d_sent = u64::from(r.direct_sent);
    let d_lost = u64::from(r.direct_lost).min(d_sent);
    let Some(direct_ms) = r.direct_rtt_ms.map(u64::from).filter(|_| d_lost < d_sent) else {
        return false;
    };
    d_lost * 100 <= d_sent * EXIT_LOSS_PCT
        && match r.relay_rtt_ms.map(u64::from) {
            Some(relay_ms) => {
                direct_ms * 100 <= relay_ms * EXIT_RATIO_PCT || direct_ms <= relay_ms + EXIT_GAP_MS
            }
            None => direct_ms < ENTER_GAP_MS,
        }
}

/// One member's latest word on the pair.
#[derive(Clone, Copy, Debug)]
struct Seen {
    at: Instant,
    grade: Grade,
    healed: bool,
}

/// Why a standing verdict ends before its lifetime.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Withdrawn {
    /// The direct path measured healthy for long enough.
    Healed,
    /// The relay path stopped answering.
    RelayDown,
}

/// What a report changes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    Nothing,
    /// A verdict begins: stamp both ends.
    Enter(Worse),
    /// The standing verdict was renewed and its rows are due again.
    Push,
    /// The standing verdict ends now: tell both ends.
    Withdraw(Withdrawn),
}

/// One pair's verdict state.
#[derive(Debug, Default)]
pub struct Pair {
    /// The latest report of each member, lower node id first.
    last: [Option<Seen>; 2],
    /// While unexpired, the verdict stands.
    until: Option<Instant>,
    entered: Option<Instant>,
    last_push: Option<Instant>,
    /// Since when every fresh report has read healthy, and how many did.
    healthy_since: Option<Instant>,
    healthy_reports: u32,
    /// Re-entries in a row within [`REENTRY_MEMORY`], and the last withdrawal.
    reentries: u32,
    last_exit: Option<Instant>,
}

impl Pair {
    /// The verdict's remaining lifetime, if it stands.
    pub fn remaining(&self, now: Instant) -> Option<Duration> {
        self.until
            .and_then(|until| until.checked_duration_since(now))
            .filter(|d| !d.is_zero())
    }

    fn exit_sustain(&self) -> Duration {
        EXIT_SUSTAIN.saturating_mul(1u32 << self.reentries.min(MAX_EXIT_DOUBLINGS))
    }

    /// Nothing about this pair is worth keeping any more.
    fn stale(&self, now: Instant) -> bool {
        self.remaining(now).is_none()
            && self
                .last
                .iter()
                .flatten()
                .all(|s| now.saturating_duration_since(s.at) > FRESH)
            && self
                .last_exit
                .is_none_or(|t| now.saturating_duration_since(t) > REENTRY_MEMORY)
    }
}

/// Pure: take one member's report at `now` and say what it changes.
/// `from_low` = the reporter is the pair's lower node id.
pub fn note(pair: &mut Pair, from_low: bool, r: &Report, now: Instant) -> Step {
    let g = grade(r);
    let healed = g == Grade::Healthy
        || (matches!(g, Grade::RelayPoor | Grade::RelayDown) && direct_healed(r));
    let (me, peer) = if from_low { (0, 1) } else { (1, 0) };
    pair.last[me] = Some(Seen {
        at: now,
        grade: g,
        healed,
    });
    let other = pair.last[peer].filter(|s| now.saturating_duration_since(s.at) <= FRESH);

    if pair.remaining(now).is_none() {
        // No verdict, or one that ran out unrenewed.
        pair.until = None;
        pair.entered = None;
        pair.healthy_since = None;
        pair.healthy_reports = 0;
        let Grade::Worse(why) = g else {
            return Step::Nothing;
        };
        // Both members measured it; or this one has already fallen to the
        // relay, the other is taking part, and it does not read healthy.
        let both = other.is_some_and(|o| matches!(o.grade, Grade::Worse(_)));
        let fell = r.on_relay && other.is_some_and(|o| o.grade != Grade::Healthy);
        if !(both || fell) {
            return Step::Nothing;
        }
        pair.reentries = match pair.last_exit {
            Some(t) if now.saturating_duration_since(t) <= REENTRY_MEMORY => {
                pair.reentries.saturating_add(1)
            }
            _ => 0,
        };
        pair.until = Some(now + VERDICT_TTL);
        pair.entered = Some(now);
        pair.last_push = Some(now);
        return Step::Enter(why);
    }

    // A verdict stands.
    match g {
        // Too little to renew on, too little to end on.
        Grade::Thin => return Step::Nothing,
        Grade::RelayDown => {
            // Withdraw at once only when a full relay window answered nothing
            // at all AND the direct path is usable (answering, below severe
            // loss). A partial WAN TCP head-of-line stall (`Some(ms)`), a
            // post-switch stub window (`relay_sent < MIN_DIRECT_PROBES`), or a
            // severely lossy/dead direct path must not yank the pair back onto
            // a broken direct link; instead it withholds renewal like RelayPoor.
            let d_sent = u64::from(r.direct_sent);
            let d_lost = u64::from(r.direct_lost).min(d_sent);
            let direct_usable = r.direct_rtt_ms.is_some()
                && d_lost < d_sent
                && d_lost * 100 < d_sent * ENTER_LOSS_PCT;
            if r.relay_rtt_ms.is_none() && r.relay_sent >= MIN_DIRECT_PROBES && direct_usable {
                end(pair, now);
                return Step::Withdraw(Withdrawn::RelayDown);
            }
            if check_healed_exit(pair, other, healed, now) {
                end(pair, now);
                return Step::Withdraw(Withdrawn::Healed);
            }
            return Step::Nothing;
        }
        // Not renewed: a relay this lossy runs the verdict out, while still
        // letting a healed direct path complete its sustained exit.
        Grade::RelayPoor => {
            if check_healed_exit(pair, other, healed, now) {
                end(pair, now);
                return Step::Withdraw(Withdrawn::Healed);
            }
            return Step::Nothing;
        }
        Grade::Healthy => {
            if check_healed_exit(pair, other, true, now) {
                end(pair, now);
                return Step::Withdraw(Withdrawn::Healed);
            }
        }
        Grade::Worse(_) | Grade::Between | Grade::Dead => {
            pair.healthy_since = None;
            pair.healthy_reports = 0;
        }
    }
    // Every usable report short of a withdrawal renews: the pair is still
    // being measured and has not earned its way back.
    pair.until = Some(now + VERDICT_TTL);
    let pushed = pair
        .last_push
        .map(|t| now.saturating_duration_since(t))
        .unwrap_or(Duration::MAX);
    if pushed >= REPUSH_AFTER || (!r.on_relay && pushed >= REPUSH_STRAGGLER_AFTER) {
        pair.last_push = Some(now);
        return Step::Push;
    }
    Step::Nothing
}

fn check_healed_exit(pair: &mut Pair, other: Option<Seen>, healed: bool, now: Instant) -> bool {
    if !healed {
        pair.healthy_since = None;
        pair.healthy_reports = 0;
        return false;
    }
    let since = *pair.healthy_since.get_or_insert(now);
    pair.healthy_reports += 1;
    let held = pair
        .entered
        .is_some_and(|t| now.saturating_duration_since(t) >= MIN_HOLD);
    held && pair.healthy_reports >= 2
        && now.saturating_duration_since(since) >= pair.exit_sustain()
        && other.is_none_or(|o| o.healed)
}

fn end(pair: &mut Pair, now: Instant) {
    pair.until = None;
    pair.entered = None;
    pair.last_push = None;
    pair.healthy_since = None;
    pair.healthy_reports = 0;
    pair.last_exit = Some(now);
}

/// A connection's resolved overlay node, so a report costs no database read.
#[derive(Clone, Copy)]
struct Reporter {
    node_id: ObjectId,
    at: Instant,
}

/// The module's pod-local state (`NetworkState::path_quality`).
pub struct PathQualityState {
    /// The [`Mode`], as its discriminant.
    mode: std::sync::atomic::AtomicU8,
    /// Keyed by the symmetric `pair_key`.
    pairs: DashMap<String, Pair>,
    /// Keyed by the connection key (agent or tunnel-client id).
    reporters: DashMap<ObjectId, Reporter>,
}

impl Default for PathQualityState {
    /// The mode the environment asks for.
    fn default() -> Self {
        let mode = Mode::from_env();
        info!(?mode, "overlay path quality: prefer-relay mode");
        Self::new(mode)
    }
}

impl PathQualityState {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode: std::sync::atomic::AtomicU8::new(mode as u8),
            pairs: DashMap::new(),
            reporters: DashMap::new(),
        }
    }

    pub fn mode(&self) -> Mode {
        Mode::from_u8(self.mode.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Change the mode of a running server. Standing verdicts stop being
    /// stamped at once when it leaves `on`; the members' holds then run out.
    /// A netmap already sent keeps the capability it said, until the
    /// member's next full netmap.
    pub fn set_mode(&self, mode: Mode) {
        self.mode
            .store(mode as u8, std::sync::atomic::Ordering::Relaxed);
    }

    /// The standing verdict's remaining lifetime for a pair, in ms, when the
    /// mode stamps rows.
    pub fn standing_ms(&self, a: ObjectId, b: ObjectId) -> Option<u32> {
        self.standing_ms_in(self.mode(), a, b, Instant::now())
    }

    fn standing_ms_in(&self, mode: Mode, a: ObjectId, b: ObjectId, now: Instant) -> Option<u32> {
        if mode != Mode::On {
            return None;
        }
        self.pairs
            .get(&overlay::pair_key(a, b))
            .and_then(|p| p.remaining(now))
            .map(|d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX).max(1))
    }

    /// Forget a node that left: its pairs' verdicts and the connections
    /// resolved to it.
    pub fn forget_node(&self, node_id: ObjectId) {
        self.reporters.retain(|_, r| r.node_id != node_id);
        let hex = node_id.to_hex();
        self.pairs
            .retain(|k, _| !k.split(':').any(|side| side == hex));
    }

    /// Is a verdict standing for the pair right now (whatever the mode
    /// does with it)?
    pub fn is_standing(&self, a: ObjectId, b: ObjectId) -> bool {
        self.pairs
            .get(&overlay::pair_key(a, b))
            .is_some_and(|p| p.remaining(Instant::now()).is_some())
    }

    /// Test seam: make the pair's standing verdict, its healthy run and its
    /// members' last reports `by` older than they are, as if that long had
    /// passed without a report. The verdict's end is left where it is.
    pub fn age_verdict(&self, a: ObjectId, b: ObjectId, by: Duration) {
        if let Some(mut p) = self.pairs.get_mut(&overlay::pair_key(a, b)) {
            let back = |t: &mut Option<Instant>| {
                *t = t.and_then(|at| at.checked_sub(by));
            };
            back(&mut p.entered);
            back(&mut p.healthy_since);
            back(&mut p.last_push);
            for seen in p.last.iter_mut().flatten() {
                seen.at = seen.at.checked_sub(by).unwrap_or(seen.at);
            }
        }
    }
}

/// A member's path quality report. Judged in memory; the database is read
/// only when the verdict changes or a row is pushed.
pub async fn handle(state: &NetworkState, ident: NodeIdentity, peer_node_id: ObjectId, r: Report) {
    let pq = &state.path_quality;
    let mode = pq.mode();
    if mode == Mode::Off {
        return;
    }
    let now = Instant::now();
    let conn = ident.connection_key();
    let cached = pq
        .reporters
        .get(&conn)
        .map(|c| *c)
        .filter(|c| now.saturating_duration_since(c.at) <= REPORTER_TTL);
    let reporter_id = match cached {
        Some(c) => c.node_id,
        None => {
            let Some(id) = overlay::current_node(state, ident).await.and_then(|n| n.id) else {
                debug!(?ident, "overlay path quality: report before join; dropped");
                return;
            };
            pq.reporters.insert(
                conn,
                Reporter {
                    node_id: id,
                    at: now,
                },
            );
            id
        }
    };
    if reporter_id == peer_node_id {
        return;
    }
    let pk = overlay::pair_key(reporter_id, peer_node_id);
    if pq.pairs.len() > PAIR_CAP {
        pq.pairs.retain(|_, p| !p.stale(now));
    }
    let from_low = reporter_id.to_hex() <= peer_node_id.to_hex();
    let (step, graded) = {
        let mut pair = pq.pairs.entry(pk.clone()).or_default();
        let mine = pair.last[usize::from(!from_low)];
        if mine.is_some_and(|s| now.saturating_duration_since(s.at) < MIN_REPORT_GAP) {
            return;
        }
        let step = note(pair.value_mut(), from_low, &r, now);
        (step, grade(&r))
    };
    debug!(
        %pk, reporter = %reporter_id, ?graded, ?step, on_relay = r.on_relay,
        window_ms = r.window_ms,
        direct = %format_args!("{}/{} {:?}ms", r.direct_lost, r.direct_sent, r.direct_rtt_ms),
        relay = %format_args!("{}/{} {:?}ms", r.relay_lost, r.relay_sent, r.relay_rtt_ms),
        "overlay path quality: report"
    );
    if step == Step::Nothing {
        return;
    }
    // The verdict changes or is pushed: both rows are read fresh, and a pair
    // that may not have one loses its state.
    let Some((reporter, peer)) = pair_rows(state, ident, reporter_id, peer_node_id).await else {
        pq.pairs.remove(&pk);
        debug!(%pk, "overlay path quality: the pair is no longer two live, DERP-capable nodes of one network; verdict dropped");
        return;
    };
    let numbers = format!(
        "direct {}/{} lost, {} ms; relay {}/{} lost, {} ms",
        r.direct_lost,
        r.direct_sent,
        r.direct_rtt_ms
            .map_or_else(|| "-".to_string(), |v| v.to_string()),
        r.relay_lost,
        r.relay_sent,
        r.relay_rtt_ms
            .map_or_else(|| "-".to_string(), |v| v.to_string()),
    );
    let acting = if mode == Mode::On {
        ""
    } else {
        " [shadow: not acting]"
    };
    match step {
        Step::Nothing => return,
        Step::Enter(why) => info!(
            %pk, reporter = %reporter.name, peer = %peer.name, ?why, %numbers,
            "overlay path quality: the relay is clearly better than this pair's direct path — preferring the relay for {}s, renewed while reports support it{acting}",
            VERDICT_TTL.as_secs()
        ),
        Step::Withdraw(why) => info!(
            %pk, reporter = %reporter.name, peer = %peer.name, ?why, %numbers,
            "overlay path quality: prefer-relay verdict withdrawn — the pair goes back to its direct path{acting}"
        ),
        Step::Push => {
            debug!(%pk, %numbers, "overlay path quality: prefer-relay verdict renewed; pushing its rows again")
        }
    }
    if mode != Mode::On {
        return;
    }
    overlay::fan_pair_prefer_relay(state, &reporter, &peer, matches!(step, Step::Withdraw(_)))
        .await;
}

/// Both nodes of a pair, read fresh, if they may hold a verdict: live rows
/// of one tenant and one network, keys authorized, both able to ride DERP
/// (the relay path the members measure and move to).
async fn pair_rows(
    state: &NetworkState,
    ident: NodeIdentity,
    reporter_id: ObjectId,
    peer_node_id: ObjectId,
) -> Option<(OverlayNode, OverlayNode)> {
    let reporter = overlay::current_node(state, ident)
        .await
        .filter(|n| n.id == Some(reporter_id))?;
    let peer = state
        .overlay_nodes
        .base
        .find_by_id(peer_node_id)
        .await
        .ok()?;
    (peer.tenant_id == reporter.tenant_id
        && peer.network_id == reporter.network_id
        && peer.deleted_at.is_none()
        && peer.is_key_authorized_at(bson::DateTime::now())
        && reporter.supports_derp
        && peer.supports_derp)
        .then_some((reporter, peer))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A full window: `direct` and `relay` as `(lost of 11, median ms)`.
    fn rep(direct: (u32, Option<u32>), relay: (u32, Option<u32>), on_relay: bool) -> Report {
        Report {
            window_ms: 10_000,
            direct_sent: 11,
            direct_lost: direct.0,
            direct_rtt_ms: direct.1,
            relay_sent: 11,
            relay_lost: relay.0,
            relay_rtt_ms: relay.1,
            on_relay,
        }
    }

    fn slow(direct_ms: u32, relay_ms: u32) -> Report {
        rep((0, Some(direct_ms)), (0, Some(relay_ms)), false)
    }

    #[test]
    fn the_mode_parses_with_on_as_the_default() {
        assert_eq!(Mode::parse(None), Mode::On);
        assert_eq!(Mode::parse(Some("on")), Mode::On);
        assert_eq!(Mode::parse(Some(" Shadow ")), Mode::Shadow);
        for off in ["off", "0", "false", "no", "OFF"] {
            assert_eq!(Mode::parse(Some(off)), Mode::Off, "{off}");
        }
    }

    /// The field's four phases, graded: only the clearly worse ones are.
    #[test]
    fn grades_follow_the_measured_field_cases() {
        // Stable: direct 0.3 ms against a 620 ms relay.
        assert_eq!(grade(&slow(0, 620)), Grade::Healthy);
        // Mild: 672 ms (8% worse) and 744 ms (20% worse) both stay put.
        assert_eq!(grade(&slow(672, 620)), Grade::Healthy);
        assert_eq!(grade(&slow(744, 620)), Grade::Between);
        // Severe latency: 960 ms against 620 ms (and against 560 ms).
        assert_eq!(grade(&slow(960, 620)), Grade::Worse(Worse::Latency));
        assert_eq!(grade(&slow(960, 560)), Grade::Worse(Worse::Latency));
        // Heavy loss: 25% each way is about 44% of round trips.
        assert_eq!(
            grade(&rep((5, Some(2)), (0, Some(620)), false)),
            Grade::Worse(Worse::Loss)
        );
        // Nothing answered at all: dead, not lossy.
        assert_eq!(grade(&rep((11, None), (0, Some(620)), true)), Grade::Dead);
        assert_eq!(
            grade(&rep((10, Some(2)), (0, Some(620)), true)),
            Grade::Worse(Worse::Loss),
            "one answer in eleven is a lossy path"
        );
    }

    #[test]
    fn the_thresholds_sit_apart_on_both_axes() {
        // Latency: 35% AND 100 ms to enter.
        assert_eq!(grade(&slow(836, 620)), Grade::Between, "34.8% worse");
        assert_eq!(grade(&slow(837, 620)), Grade::Worse(Worse::Latency));
        assert_eq!(
            grade(&slow(140, 50)),
            Grade::Between,
            "nearly three times the relay's, but only 90 ms: not worth a move"
        );
        assert_eq!(grade(&slow(150, 50)), Grade::Worse(Worse::Latency));
        // Latency: within 15% OR 30 ms to leave.
        assert_eq!(grade(&slow(713, 620)), Grade::Healthy);
        assert_eq!(grade(&slow(714, 620)), Grade::Between);
        assert_eq!(grade(&slow(80, 50)), Grade::Healthy, "within 30 ms");
        // Loss: 2 of 11 (18%) is between, 3 of 11 (27%) enters, 1 of 11 (9%)
        // does not yet read healthy, none does.
        assert_eq!(
            grade(&rep((2, Some(2)), (0, Some(620)), false)),
            Grade::Between
        );
        assert_eq!(
            grade(&rep((3, Some(2)), (0, Some(620)), false)),
            Grade::Worse(Worse::Loss)
        );
        assert_eq!(
            grade(&rep((1, Some(2)), (0, Some(620)), false)),
            Grade::Between
        );
        assert_eq!(
            grade(&rep((0, Some(2)), (0, Some(620)), false)),
            Grade::Healthy
        );
    }

    #[test]
    fn a_thin_window_or_a_bad_relay_is_never_a_reason_to_prefer_it() {
        let mut thin = slow(960, 620);
        thin.window_ms = 7_999;
        assert_eq!(grade(&thin), Grade::Thin);
        let mut thin = slow(960, 620);
        thin.direct_sent = 7;
        assert_eq!(grade(&thin), Grade::Thin);
        let mut thin = slow(960, 620);
        thin.relay_sent = 2;
        assert_eq!(grade(&thin), Grade::Thin, "the relay was barely measured");
        // The relay answered nothing, or half of nothing.
        assert_eq!(
            grade(&rep((0, Some(960)), (11, None), false)),
            Grade::RelayDown
        );
        assert_eq!(
            grade(&rep((0, Some(960)), (6, Some(620)), false)),
            Grade::RelayDown
        );
        // 2 of 11 lost on the relay: it carries, but is not preferred.
        assert_eq!(
            grade(&rep((0, Some(960)), (2, Some(620)), false)),
            Grade::RelayPoor
        );
        assert_eq!(
            grade(&rep((0, Some(960)), (1, Some(620)), false)),
            Grade::Worse(Worse::Latency),
            "1 of 11 is within the relay's allowance"
        );
        // A lost count above the sent count is clamped, not trusted.
        let mut odd = slow(1, 620);
        odd.direct_lost = 99;
        assert_eq!(grade(&odd), Grade::Dead);
    }

    #[test]
    fn a_verdict_needs_both_members_to_measure_the_direct_path_worse() {
        let t0 = Instant::now();
        let mut p = Pair::default();
        let bad = slow(960, 620);
        // One member alone is never enough, however often it reports.
        for s in [0, 5, 10, 15, 20] {
            assert_eq!(
                note(&mut p, true, &bad, t0 + Duration::from_secs(s)),
                Step::Nothing
            );
        }
        // The other member reports the same: the verdict begins.
        assert_eq!(
            note(&mut p, false, &bad, t0 + Duration::from_secs(22)),
            Step::Enter(Worse::Latency)
        );
        assert_eq!(p.remaining(t0 + Duration::from_secs(22)), Some(VERDICT_TTL));
    }

    #[test]
    fn a_stale_or_disagreeing_second_member_does_not_count() {
        let t0 = Instant::now();
        let bad = slow(960, 620);
        // The other member's bad report is older than FRESH.
        let mut p = Pair::default();
        note(&mut p, false, &bad, t0);
        assert_eq!(
            note(&mut p, true, &bad, t0 + FRESH + Duration::from_secs(1)),
            Step::Nothing
        );
        // The other member measures the direct path healthy.
        let mut p = Pair::default();
        note(&mut p, false, &slow(1, 620), t0);
        assert_eq!(
            note(&mut p, true, &bad, t0 + Duration::from_secs(2)),
            Step::Nothing
        );
        // A thin or in-between report from the other is no agreement either.
        let mut p = Pair::default();
        note(&mut p, false, &slow(744, 620), t0);
        assert_eq!(
            note(&mut p, true, &bad, t0 + Duration::from_secs(2)),
            Step::Nothing
        );
    }

    /// A member whose side already fell to the relay (the lossy direct
    /// carrier died) is enough on its own, as long as the other member is
    /// taking part and does not read the path healthy: the verdict then
    /// moves nothing, it only stops the climb back onto the lossy path.
    #[test]
    fn a_member_already_on_the_relay_needs_only_a_participating_peer() {
        let t0 = Instant::now();
        let lossy_on_relay = rep((5, Some(2)), (0, Some(620)), true);
        let mut p = Pair::default();
        assert_eq!(
            note(&mut p, true, &lossy_on_relay, t0),
            Step::Nothing,
            "no peer yet"
        );
        // The peer's window is still thin: it takes part, and says nothing.
        let mut thin = slow(2, 620);
        thin.direct_sent = 4;
        note(&mut p, false, &thin, t0 + Duration::from_secs(1));
        assert_eq!(
            note(&mut p, true, &lossy_on_relay, t0 + Duration::from_secs(5)),
            Step::Enter(Worse::Loss)
        );
        // But not against a peer that measures the path healthy.
        let mut p = Pair::default();
        note(&mut p, false, &slow(2, 620), t0);
        assert_eq!(
            note(&mut p, true, &lossy_on_relay, t0 + Duration::from_secs(1)),
            Step::Nothing
        );
    }

    /// Drive both members' reports every 5 s (the low id at `t`, the high id
    /// 2 s later) from `from` for `secs`, and return the steps taken.
    fn drive(p: &mut Pair, t0: Instant, from: u64, secs: u64, r: Report) -> Vec<(u64, Step)> {
        let mut steps = Vec::new();
        let mut s = from;
        while s < from + secs {
            for (low, at) in [(true, s), (false, s + 2)] {
                let step = note(p, low, &r, t0 + Duration::from_secs(at));
                if step != Step::Nothing {
                    steps.push((at, step));
                }
            }
            s += 5;
        }
        steps
    }

    #[test]
    fn a_standing_verdict_is_renewed_and_pushed_again_before_it_runs_out() {
        let t0 = Instant::now();
        let mut p = Pair::default();
        let mut held = slow(960, 620);
        let steps = drive(&mut p, t0, 0, 5, held);
        assert_eq!(steps, vec![(2, Step::Enter(Worse::Latency))]);
        // Both members now ride the relay and keep measuring the same.
        held.on_relay = true;
        let steps = drive(&mut p, t0, 5, 600, held);
        assert!(steps.iter().all(|(_, s)| *s == Step::Push), "{steps:?}");
        let gaps: Vec<u64> = std::iter::once(2)
            .chain(steps.iter().map(|(at, _)| *at))
            .collect::<Vec<_>>()
            .windows(2)
            .map(|w| w[1] - w[0])
            .collect();
        assert!(
            gaps.iter().all(|g| (20..=25).contains(g)),
            "a row every 20-25 s keeps a member's lifetime above half: {gaps:?}"
        );
        assert!(p.remaining(t0 + Duration::from_secs(605)).is_some());
    }

    /// Never ratchet: with no report to renew it the verdict simply ends,
    /// and a verdict that ran out needs both members again to restart.
    #[test]
    fn a_verdict_nobody_renews_runs_out() {
        let t0 = Instant::now();
        let mut p = Pair::default();
        drive(&mut p, t0, 0, 5, slow(960, 620));
        assert!(p.remaining(t0 + Duration::from_secs(61)).is_some());
        assert!(p.remaining(t0 + Duration::from_secs(63)).is_none());
        assert_eq!(
            note(&mut p, true, &slow(960, 620), t0 + Duration::from_secs(120)),
            Step::Nothing,
            "one member, and the other's word is stale"
        );
    }

    #[test]
    fn a_member_still_on_direct_under_a_verdict_gets_its_row_again_soon() {
        let t0 = Instant::now();
        let mut p = Pair::default();
        drive(&mut p, t0, 0, 5, slow(960, 620));
        // 3 s after the push: too soon. 6 s after: its push was lost.
        assert_eq!(
            note(&mut p, true, &slow(960, 620), t0 + Duration::from_secs(5)),
            Step::Nothing
        );
        assert_eq!(
            note(&mut p, false, &slow(960, 620), t0 + Duration::from_secs(8)),
            Step::Push
        );
    }

    #[test]
    fn a_verdict_is_withdrawn_once_the_direct_path_has_measured_healthy_long_enough() {
        let t0 = Instant::now();
        let mut p = Pair::default();
        drive(&mut p, t0, 0, 5, slow(960, 620));
        let mut bad = slow(960, 620);
        bad.on_relay = true;
        drive(&mut p, t0, 5, 55, bad);
        // The direct path heals at +60 s.
        let mut good = slow(1, 620);
        good.on_relay = true;
        let steps = drive(&mut p, t0, 60, 60, good);
        let (at, step) = steps
            .iter()
            .find(|(_, s)| matches!(s, Step::Withdraw(_)))
            .copied()
            .expect("healed");
        assert_eq!(step, Step::Withdraw(Withdrawn::Healed));
        assert!(
            (70..=75).contains(&at),
            "10 s of healthy reports from both, at +{at}s"
        );
        assert!(p.remaining(t0 + Duration::from_secs(at)).is_none());
    }

    #[test]
    fn a_verdict_is_not_withdrawn_while_one_member_still_measures_it_worse() {
        let t0 = Instant::now();
        let mut p = Pair::default();
        drive(&mut p, t0, 0, 5, slow(960, 620));
        let (mut good, mut bad) = (slow(1, 620), slow(960, 620));
        (good.on_relay, bad.on_relay) = (true, true);
        for s in (5..120).step_by(5) {
            let a = note(&mut p, true, &good, t0 + Duration::from_secs(s));
            let b = note(&mut p, false, &bad, t0 + Duration::from_secs(s + 2));
            assert!(
                !matches!(a, Step::Withdraw(_)) && !matches!(b, Step::Withdraw(_)),
                "+{s}s"
            );
        }
        assert!(p.remaining(t0 + Duration::from_secs(120)).is_some());
    }

    /// A verdict stands for MIN_HOLD whatever is reported, so a path that
    /// reads healthy the moment the pair leaves it does not bounce it back.
    #[test]
    fn a_fresh_verdict_holds_for_its_minimum() {
        let t0 = Instant::now();
        let mut p = Pair::default();
        drive(&mut p, t0, 0, 5, slow(960, 620));
        let mut good = slow(1, 620);
        good.on_relay = true;
        let steps = drive(&mut p, t0, 5, 30, good);
        let (at, _) = steps
            .iter()
            .find(|(_, s)| matches!(s, Step::Withdraw(_)))
            .copied()
            .expect("healed");
        assert!(at >= 2 + MIN_HOLD.as_secs(), "withdrawn at +{at}s");
    }

    #[test]
    fn a_dead_relay_ends_the_verdict_at_once_and_a_poor_one_lets_it_run_out() {
        let t0 = Instant::now();
        let mut p = Pair::default();
        drive(&mut p, t0, 0, 5, slow(960, 620));
        assert_eq!(
            note(
                &mut p,
                true,
                &rep((0, Some(960)), (11, None), true),
                t0 + Duration::from_secs(5)
            ),
            Step::Withdraw(Withdrawn::RelayDown)
        );
        // A relay losing 2 of 11: never renewed, so it ends by itself.
        let mut p = Pair::default();
        drive(&mut p, t0, 0, 5, slow(960, 620));
        let poor = rep((0, Some(960)), (2, Some(620)), true);
        let steps = drive(&mut p, t0, 5, 70, poor);
        assert!(steps.is_empty(), "{steps:?}");
        assert!(p.remaining(t0 + Duration::from_secs(63)).is_none());
    }

    /// Trans-oceanic WAN `/derp` regression (lab, 2026-11-12):
    /// 1) A TCP head-of-line stall on `/derp` where 6/10 probes exceed 2 s
    ///    while 4 still answer (`Some(536)`), or a 3-probe post-transition
    ///    stub window (`3/3 None`), or a stall while `direct` itself is
    ///    severely lossy (`4/10` lost), must NOT yank the pair back onto the
    ///    broken direct path; instead it withholds renewal like `RelayPoor`.
    /// 2) Conversely, if `direct` has healed (`0/10, 0 ms`) while `/derp` is
    ///    congested (`4/10` or `6/10`), the pair still heals cleanly after
    ///    `MIN_HOLD` + `EXIT_SUSTAIN`.
    #[test]
    fn a_wan_tcp_relay_stall_never_bounces_into_lossy_direct_yet_allows_healed_exit() {
        let t0 = Instant::now();
        let mut p = Pair::default();
        let lossy = rep((4, Some(2)), (0, Some(600)), false);
        assert_eq!(
            drive(&mut p, t0, 0, 5, lossy),
            vec![(2, Step::Enter(Worse::Loss))]
        );
        // Post-switch 3-probe relay window (`3/3 None`) while direct loses 3/9:
        let post_switch = Report {
            window_ms: 9_000,
            direct_sent: 9,
            direct_lost: 3,
            direct_rtt_ms: Some(2),
            relay_sent: 3,
            relay_lost: 3,
            relay_rtt_ms: None,
            on_relay: true,
        };
        assert_eq!(
            note(&mut p, true, &post_switch, t0 + Duration::from_secs(7)),
            Step::Nothing,
            "3-probe post-switch window must not withdraw"
        );
        // Partial WAN TCP HoL stall (`6/10 Some(536)`) while direct loses 4/10:
        assert_eq!(
            note(
                &mut p,
                false,
                &rep((4, Some(2)), (6, Some(536)), true),
                t0 + Duration::from_secs(12)
            ),
            Step::Nothing,
            "partial TCP HoL stall with Some(536)ms must not bounce onto 40%-loss direct"
        );
        // Even a full `11/11 None` relay window while direct loses 4/11 does
        // not force immediate switch onto a 36%-loss direct path, nor renew:
        assert_eq!(
            note(
                &mut p,
                true,
                &rep((4, Some(2)), (11, None), true),
                t0 + Duration::from_secs(17)
            ),
            Step::Nothing
        );
        assert!(
            p.remaining(t0 + Duration::from_secs(61)).is_some()
                && p.remaining(t0 + Duration::from_secs(63)).is_none(),
            "unrenewed stall still expires cleanly at VERDICT_TTL without ratcheting"
        );

        // Now verify that when direct heals (`0/11, 0 ms`), `/derp` congestion
        // (`RelayPoor` 3/11 or `RelayDown` 6/11 with `Some(578)`) never blocks
        // `Withdraw(Healed)`.
        let mut p = Pair::default();
        drive(&mut p, t0, 0, 5, lossy);
        let mut held = lossy;
        held.on_relay = true;
        drive(&mut p, t0, 5, 25, held);
        let healed_under_poor_relay = rep((0, Some(0)), (6, Some(578)), true);
        let steps = drive(&mut p, t0, 30, 20, healed_under_poor_relay);
        assert!(
            steps.contains(&(40, Step::Withdraw(Withdrawn::Healed)))
                || steps
                    .iter()
                    .any(|(_, s)| *s == Step::Withdraw(Withdrawn::Healed)),
            "healed direct exits cleanly despite congested relay: {steps:?}"
        );
    }

    /// A pair whose direct path relapses right after each return is let back
    /// more and more reluctantly: the healthy stretch it must show doubles.
    #[test]
    fn a_pair_that_comes_straight_back_must_stay_healthy_twice_as_long() {
        let t0 = Instant::now();
        let mut p = Pair::default();
        let (mut bad, mut good) = (slow(960, 620), slow(1, 620));
        let mut clock = 0u64;
        let mut sustained = Vec::new();
        for _ in 0..4 {
            (bad.on_relay, good.on_relay) = (false, true);
            drive(&mut p, t0, clock, 5, bad);
            assert!(p.remaining(t0 + Duration::from_secs(clock + 3)).is_some());
            bad.on_relay = true;
            drive(&mut p, t0, clock + 5, 25, bad);
            let healed_from = clock + 30;
            let steps = drive(&mut p, t0, healed_from, 400, good);
            let (at, _) = steps
                .iter()
                .find(|(_, s)| matches!(s, Step::Withdraw(_)))
                .copied()
                .expect("healed");
            sustained.push(at - healed_from);
            clock = at + 5;
        }
        assert!(
            sustained.windows(2).all(|w| w[1] >= w[0] + 5),
            "each return takes longer: {sustained:?}"
        );
        assert!(sustained[0] <= 15 && sustained[3] >= 80, "{sustained:?}");
    }

    #[test]
    fn rows_are_stamped_only_in_on_mode_and_only_while_the_verdict_stands() {
        let st = PathQualityState::new(Mode::On);
        let (a, b) = (ObjectId::new(), ObjectId::new());
        let now = Instant::now();
        assert_eq!(st.standing_ms_in(Mode::On, a, b, now), None);
        st.pairs.insert(
            overlay::pair_key(a, b),
            Pair {
                until: Some(now + Duration::from_secs(42)),
                ..Default::default()
            },
        );
        assert_eq!(st.standing_ms_in(Mode::On, a, b, now), Some(42_000));
        assert_eq!(
            st.standing_ms_in(Mode::On, b, a, now),
            Some(42_000),
            "symmetric"
        );
        assert_eq!(st.standing_ms_in(Mode::Shadow, a, b, now), None);
        assert_eq!(st.standing_ms_in(Mode::Off, a, b, now), None);
        assert_eq!(
            st.standing_ms_in(Mode::On, a, b, now + Duration::from_secs(42)),
            None,
            "run out"
        );
        st.forget_node(a);
        assert_eq!(st.standing_ms_in(Mode::On, a, b, now), None);
    }
}
