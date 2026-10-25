// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! netstate — the process-wide network-state subsystem.
//!
//! ONE owner of the OS network-change signal, typed state, and non-blocking
//! fan-out; everything else is a subscriber that reconciles against
//! snapshots. Replaces the per-runtime string-typed `route_events`
//! subscription (which registered the OS callbacks once PER ORG and told its
//! consumer nothing beyond `starts_with("addr")`).
//!
//! Design (docs/… "netstate", 2026-08-16):
//! * **Backend** (per OS) pushes raw `(RawSignal, detail)` pairs from the OS
//!   callbacks into an unbounded channel — never blocks, never allocates
//!   beyond the tiny detail string, exactly the discipline `route_events`
//!   established. Windows = the three IP-Helper registrations
//!   (`NotifyRouteChange2` / `NotifyUnicastIpAddressChange` /
//!   `NotifyIpInterfaceChange`), registered ONCE per process. Linux =
//!   `ip -o monitor route addr link` (all three classes); macOS =
//!   `route -n monitor` (the PF_ROUTE socket's line-per-message view).
//! * **Monitor** debounces bursts (a Check Point connect injects dozens of
//!   routes in one gulp), samples a [`NetSnapshot`], diffs it against the
//!   previous one, and publishes a [`NetDelta`] with a severity verdict.
//! * **Fan-out**: `watch<Arc<NetSnapshot>>` (latest state — always readable)
//!   plus `broadcast<NetDelta>` (wake-ups). A lagged subscriber loses only
//!   wake-ups, never state: on `Lagged` it reconciles from the watch. The
//!   monitor never waits on any subscriber.
//!
//! The subsystem is spawned lazily on first [`handle`] call and lives for
//! the process (the OS registration is cancelled at process exit, not per
//! overlay-runtime rebuild — subscribers come and go via handles).
//!
//! Config: `overlay_netmon` (default ON) + `overlay_netmon_debounce_ms`
//! (default 750, clamped 100–5000) via the standard env bridge
//! (`ROOMLERD_OVERLAY_NETMON*`).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, info, warn};

/// Master switch (`ROOMLERD_OVERLAY_NETMON`, default ON).
pub(crate) fn netmon_enabled() -> bool {
    crate::env::flag("OVERLAY_NETMON", true)
}

/// Minimum spacing between event-driven route re-assert waves (consumed by
/// the runtime's net-change arm; formerly `route_events`').
pub(crate) const ROUTE_WAVE_MIN_INTERVAL: Duration = Duration::from_secs(3);

/// `ROOMLERD_OVERLAY_ROUTE_EVENTS` — the legacy per-runtime consumer
/// kill-switch, still honored (default ON; `0`/`false`/`off` = the runtime
/// ignores net deltas and keeps the 2 s tick-only route guard, the pre-P4
/// behaviour). The subsystem-wide switch is [`netmon_enabled`].
pub(crate) fn route_events_enabled() -> bool {
    !matches!(
        crate::env::node_env("OVERLAY_ROUTE_EVENTS")
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref(),
        Some("0") | Some("false") | Some("off")
    )
}

/// Debounce window: further raw signals inside this quiet period are
/// absorbed into one delta (`ROOMLERD_OVERLAY_NETMON_DEBOUNCE_MS`).
fn debounce() -> Duration {
    let ms = crate::env::node_env("OVERLAY_NETMON_DEBOUNCE_MS")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(750)
        .clamp(100, 5000);
    Duration::from_millis(ms)
}

/// A continuous signal storm must still emit periodically — cap the absorb
/// window so a delta lands at least this often while churn is ongoing.
const DEBOUNCE_CAP: Duration = Duration::from_secs(3);

/// Flap damping (field 2026-08-16 19:00Z, winhost-a IN-VPN): Check Point and
/// our own route-guard waves fight over the routing table, so the effective
/// default-route identity FLAPS (ifindex 26↔17, 134 raw signals in one
/// burst) — and every flip published a fresh MAJOR. Each Major fires the
/// heavy lanes (WS probe, path-evidence reset, forced sweep), so the flap
/// became a WS-cycling storm: reattach every 1-3 min, netmap/grant
/// starvation, every pair "blocked". At most one material MAJOR is
/// published per this window; flips inside it are demoted to Minor —
/// subscribers still get the wake-up (route wave, snapshot refresh), but
/// the heavy lanes fire once per real transition, not once per flap.
const MAJOR_PUBLISH_COOLDOWN: Duration = Duration::from_secs(120);

/// Pure decision for the demotion above (unit-tested).
fn major_cooldown_active(since_last_major: Option<Duration>) -> bool {
    since_last_major.is_some_and(|d| d < MAJOR_PUBLISH_COOLDOWN)
}

/// Raw change classes from the OS backend. Deliberately coarse — the
/// snapshot diff carries the real information; these only (a) label the
/// burst and (b) preserve the legacy `route_events` string classes for the
/// compat shim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawSignal {
    Route,
    Addr,
    Iface,
}

/// One interface's addresses, keyed by name in [`NetSnapshot::ifaces`].
/// `vpn_class` is the NAME-based deny-list verdict
/// ([`super::direct::lan_iface_denied`]) — a LABEL, not the Major-severity
/// input: the Check Point adapter is named just "Ethernet" and evades
/// name-only classification, which is exactly why severity keys on
/// default-route movement instead.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IfaceSnap {
    pub v4: Vec<std::net::Ipv4Addr>,
    pub v6_count: usize,
    pub vpn_class: bool,
}

/// The effective default route per family: where a packet to a far
/// destination actually leaves. Sampled via a route LOOKUP (`GetBestRoute2`
/// / `ip route get`), not a `/0`-table scan — a corp capture rarely touches
/// `/0` (Check Point injects `/1`s and supernets; our exits install `/1`s),
/// but the lookup sees through all of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    /// Interface identity: ifindex (Windows) or device name (Unix) as text.
    pub ifref: String,
    pub gateway: Option<IpAddr>,
}

/// FR-33 — a LAN prefix this host owns an address in, whose traffic the OS
/// routes through a DIFFERENT interface than the one that owns the address.
/// That is the corp-VPN split-prefix capture (Check Point installs
/// `192.168.68.0/25` + `.128/25` via its adapter at metric 1; AnyConnect
/// re-routes the whole prefix): LAN handshakes still ARRIVE on the owning
/// socket, our replies leave through the VPN and die, and every surface used
/// to say only `upgrading` / `relay` / `penalty`. Detected by a route
/// LOOKUP of a neighbour address inside the prefix — the same instrument as
/// [`DefaultRoute`], for the same reason (a capture rarely touches the
/// prefix's own route entry). Detect and report only: routing around it is
/// VPN policy evasion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanCapture {
    /// The captured prefix, `a.b.c.d/n`.
    pub prefix: String,
    /// The interface that owns the address (name).
    pub owner: String,
    /// The interface the lookup selected: ifindex on Windows, device name on
    /// Unix — the same identity space as [`DefaultRoute::ifref`].
    pub via_ifref: String,
    /// The selected interface's name when the identity maps to one.
    pub via_name: Option<String>,
}

impl LanCapture {
    /// Does `ip` fall inside the captured prefix? The runtime asks this per
    /// peer LAN candidate to feed the path monitor's FR-33 P2 gate; the
    /// prefix is kept as the string `status` prints, so parse here. An
    /// unparseable prefix (impossible from `detect_lan_captures`, but this is
    /// a public struct) reads as "not captured" — the gate fails OPEN, the
    /// direction in which a wrong answer only costs a futile probe.
    pub fn contains_v4(&self, ip: std::net::Ipv4Addr) -> bool {
        let Some((net, plen)) = self.prefix.split_once('/') else {
            return false;
        };
        let (Ok(net), Ok(plen)) = (net.parse::<std::net::Ipv4Addr>(), plen.parse::<u8>()) else {
            return false;
        };
        plen <= 32 && network_of(ip, plen) == network_of(net, plen)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetSnapshot {
    pub ifaces: BTreeMap<String, IfaceSnap>,
    pub default_v4: Option<DefaultRoute>,
    pub default_v6: Option<DefaultRoute>,
    /// FR-97 N14 — per family, the uplink BENEATH our own adapter: the route
    /// the exit's carrier pins go through. It differs from the default only
    /// while the lookup lands on one of our adapters, which is what an exit's
    /// split-default `/1`s make every far lookup do. Without it, an uplink
    /// move under an active exit (a NIC down, Wi-Fi to Ethernet, a metric
    /// change) read as `default_moved=false`, no Major consumer ran, and the
    /// control WS sat dead until its keepalive's second strike: 56 s on the
    /// field's Linux client. Otherwise a copy of the default, so a host with
    /// no exit sees exactly what it saw before.
    pub uplink_v4: Option<DefaultRoute>,
    pub uplink_v6: Option<DefaultRoute>,
    /// FR-33 — captured LAN prefixes, empty when none (or the probe is off).
    pub lan_captures: Vec<LanCapture>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The network materially moved: the effective default route changed
    /// identity, or addresses vanished (a socket bound to one is now dead).
    Major,
    /// Something changed but nothing our sockets/strategies key on.
    Minor,
}

/// One published change, derived purely from two snapshots + the burst's
/// raw-signal classes. `summary` is the one-line INFO evidence.
///
/// `material == false` = the burst changed NOTHING the snapshot models (no
/// default-route move, no address delta) — typically our own route re-assert
/// waves or a corp client rewriting specific routes. Still published as a
/// WAKE-UP: the route guard's whole P4 contract is re-asserting within
/// milliseconds of an erase, and an erased peer `/32` is exactly a
/// snapshot-invisible change. Severity-driven subscribers (PR-2) filter on
/// `material`/`severity`; churn-driven ones (route guard) act on every delta.
#[derive(Debug, Clone)]
pub struct NetDelta {
    #[allow(dead_code)] // consumed by the PR-2 severity-driven subscribers
    pub severity: Severity,
    #[allow(dead_code)] // consumed by the PR-2 severity-driven subscribers
    pub material: bool,
    #[allow(dead_code)] // consumed by the PR-2 severity-driven subscribers
    pub default_route_moved: bool,
    #[allow(dead_code)] // consumed by the PR-2 severity-driven subscribers
    pub addrs_added: usize,
    #[allow(dead_code)] // consumed by the PR-2 severity-driven subscribers
    pub addrs_removed: usize,
    pub saw_addr_signal: bool,
    pub saw_iface_signal: bool,
    /// FR-97 N14 — the only movement was our own exit's capture coming or
    /// going: the lookup moved onto or off our adapter while the uplink beneath
    /// it stayed put, and no address was lost. Still a Major, as it always was,
    /// but one that must not spend the flap cooldown a real move after it
    /// needs ([`major_demoted`]).
    pub own_capture_only: bool,
    pub summary: String,
}

/// Pure diff: `None` when nothing material changed (a burst of self-inflicted
/// route churn — our own re-assert waves — lands here).
pub(crate) fn diff(
    prev: &NetSnapshot,
    next: &NetSnapshot,
    saw_addr: bool,
    saw_iface: bool,
) -> Option<NetDelta> {
    // FR-97 N14 — the uplink beneath an active exit moving is the network
    // moving, though the lookup still answers with our own TUN.
    let uplink_moved = prev.uplink_v4 != next.uplink_v4 || prev.uplink_v6 != next.uplink_v6;
    let default_route_moved =
        prev.default_v4 != next.default_v4 || prev.default_v6 != next.default_v6 || uplink_moved;
    // FR-33 — a capture appearing or clearing is MATERIAL (it decides whether
    // the LAN tier can ever work) but keys no socket, so it never lifts the
    // severity on its own; it is named in the summary either way, which is
    // the one onset / one clear line the operator gets.
    let captures_changed = prev.lan_captures != next.lan_captures;
    let count =
        |s: &NetSnapshot| -> usize { s.ifaces.values().map(|i| i.v4.len() + i.v6_count).sum() };
    let (mut added, mut removed) = (0usize, 0usize);
    for (name, ni) in &next.ifaces {
        match prev.ifaces.get(name) {
            Some(pi) => {
                added += ni.v4.iter().filter(|a| !pi.v4.contains(a)).count();
                removed += pi.v4.iter().filter(|a| !ni.v4.contains(a)).count();
                added += ni.v6_count.saturating_sub(pi.v6_count);
                removed += pi.v6_count.saturating_sub(ni.v6_count);
            }
            None => added += ni.v4.len() + ni.v6_count,
        }
    }
    for (name, pi) in &prev.ifaces {
        if !next.ifaces.contains_key(name) {
            removed += pi.v4.len() + pi.v6_count;
        }
    }
    if !default_route_moved && added == 0 && removed == 0 && !captures_changed {
        return None;
    }
    let severity = if default_route_moved || removed > 0 {
        Severity::Major
    } else {
        Severity::Minor
    };
    let material = true;
    let capture_note = if captures_changed {
        match next.lan_captures.first() {
            Some(c) => format!(
                " lan_capture={} via {}",
                c.prefix,
                c.via_name.as_deref().unwrap_or(c.via_ifref.as_str())
            ),
            None => " lan_capture=clear".to_string(),
        }
    } else {
        String::new()
    };
    // Named only while it differs from the default (an exit is active), so a
    // host without one logs exactly what it logged before.
    let uplink_note = if next.uplink_v4 == next.default_v4 {
        String::new()
    } else {
        format!(
            " uplink={}",
            next.uplink_v4
                .as_ref()
                .map(|d| d.ifref.as_str())
                .unwrap_or("-")
        )
    };
    let summary = format!(
        "default_moved={default_route_moved} v4_default={}{uplink_note} addrs +{added}/-{removed} ifaces={} (was {}, addrs {}→{}){capture_note}",
        next.default_v4
            .as_ref()
            .map(|d| d.ifref.as_str())
            .unwrap_or("-"),
        next.ifaces.len(),
        prev.ifaces.len(),
        count(prev),
        count(next),
    );
    Some(NetDelta {
        severity,
        material,
        default_route_moved,
        addrs_added: added,
        addrs_removed: removed,
        saw_addr_signal: saw_addr,
        saw_iface_signal: saw_iface,
        own_capture_only: default_route_moved && !uplink_moved && removed == 0,
        summary,
    })
}

/// FR-97 N14 — does the flap cooldown demote this Major? Our own exit's
/// capture coming or going is damped by ANY recent Major, so an exit whose
/// carrier flaps cannot fire the heavy lanes every few seconds. Any other
/// Major is damped only by a recent Major that was not one. Before this, the
/// exit's own activation spent the window: on the field's Linux client an
/// uplink move 13 s later was demoted, and the control WS waited 59 s for its
/// keepalive instead of being probed at once.
fn major_demoted(
    own_capture_only: bool,
    since_any: Option<Duration>,
    since_network: Option<Duration>,
) -> bool {
    major_cooldown_active(if own_capture_only {
        since_any
    } else {
        since_network
    })
}

/// Millis-since-[`mono_base`] of the last MATERIAL+MAJOR delta; 0 = never.
/// A plain atomic (not part of the handle) so non-subscribers — the
/// self-updater's defer gate — can ask "did the network just move?" without
/// holding a broadcast receiver.
static LAST_MAJOR_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn mono_base() -> std::time::Instant {
    static BASE: OnceLock<std::time::Instant> = OnceLock::new();
    *BASE.get_or_init(std::time::Instant::now)
}

fn stamp_major() {
    let ms = mono_base().elapsed().as_millis() as u64;
    // ms == 0 only within the first millisecond of process life; saturate to
    // 1 so "never" (0) stays unambiguous.
    LAST_MAJOR_MS.store(ms.max(1), std::sync::atomic::Ordering::Relaxed);
}

/// `true` when a material MAJOR network change was published within
/// `window`. R5b consumer: the self-updater defers a daemon restart while a
/// transition is fresh — a restart there forfeits every ESTABLISHED
/// (grandfathered) flow and, on a corp path that blackholes fresh TLS, locks
/// the machine out until the next transition (field 2026-08-16). `false`
/// when netstate is off or no Major was ever seen.
pub fn last_major_within(window: Duration) -> bool {
    let ms = LAST_MAJOR_MS.load(std::sync::atomic::Ordering::Relaxed);
    if ms == 0 {
        return false;
    }
    mono_base()
        .elapsed()
        .saturating_sub(Duration::from_millis(ms))
        < window
}

/// A subscriber's view: the latest snapshot (always readable) + the delta
/// wake-up stream. On `broadcast::error::RecvError::Lagged`, reconcile from
/// [`Self::snapshot`] — state is never lost, only wake-ups.
pub struct NetstateHandle {
    snap_rx: watch::Receiver<Arc<NetSnapshot>>,
    deltas: broadcast::Sender<NetDelta>,
}

impl NetstateHandle {
    pub fn subscribe(&self) -> broadcast::Receiver<NetDelta> {
        self.deltas.subscribe()
    }
    #[allow(dead_code)] // consumed by the PR-2 subscribers
    pub fn snapshot(&self) -> Arc<NetSnapshot> {
        self.snap_rx.borrow().clone()
    }
}

/// Yield the summary of the next MATERIAL+MAJOR delta on `rx`; pend forever
/// when there is no subscription (or after the monitor closes — `rx` is set
/// to `None` so callers stop polling a dead channel). Minor/immaterial
/// deltas are absorbed. `Lagged` is treated AS a Major ("we may have missed
/// one" — the conservative read for consumers that use this to react
/// FASTER; a spurious early retry costs one attempt, a missed transition
/// costs the whole backoff). Cancel-safe (broadcast `recv` is cancel-safe),
/// so it can sit in a `tokio::select!` arm against a backoff sleep — the
/// tunnel flow supervisor + route reconciler pattern (R1, 2026-08-25).
pub async fn next_major(rx: &mut Option<broadcast::Receiver<NetDelta>>) -> String {
    use tokio::sync::broadcast::error::RecvError;
    while let Some(r) = rx.as_mut() {
        match r.recv().await {
            Ok(d) if d.material && d.severity == Severity::Major => return d.summary,
            Ok(_) => continue,
            Err(RecvError::Lagged(_)) => {
                return "netstate deltas lagged — assuming a Major happened".to_string();
            }
            Err(RecvError::Closed) => {
                *rx = None;
                break;
            }
        }
    }
    std::future::pending().await
}

/// The process-wide instance, spawned lazily on first call (needs a tokio
/// context). `None` = disabled by config or the OS backend failed to
/// register — subscribers keep their timer fallbacks.
pub fn handle() -> Option<&'static NetstateHandle> {
    static INSTANCE: OnceLock<Option<NetstateHandle>> = OnceLock::new();
    INSTANCE.get_or_init(spawn).as_ref()
}

fn spawn() -> Option<NetstateHandle> {
    if !netmon_enabled() {
        debug!("netstate: disabled (ROOMLERD_OVERLAY_NETMON=0)");
        return None;
    }
    let (raw_tx, raw_rx) = mpsc::unbounded_channel();
    let _guard = backend::spawn(raw_tx)?;
    let initial = Arc::new(sample_snapshot());
    let (snap_tx, snap_rx) = watch::channel(initial.clone());
    let (delta_tx, _keepalive_rx) = broadcast::channel(16);
    info!(
        ifaces = initial.ifaces.len(),
        v4_default = initial
            .default_v4
            .as_ref()
            .map(|d| d.ifref.as_str())
            .unwrap_or("-"),
        "netstate: network monitor up (one OS registration, process-wide)"
    );
    tokio::spawn(monitor(raw_rx, snap_tx, delta_tx.clone(), _guard, initial));
    Some(NetstateHandle {
        snap_rx,
        deltas: delta_tx,
    })
}

async fn monitor(
    mut raw_rx: mpsc::UnboundedReceiver<(RawSignal, String)>,
    snap_tx: watch::Sender<Arc<NetSnapshot>>,
    delta_tx: broadcast::Sender<NetDelta>,
    _guard: backend::BackendGuard,
    mut prev: Arc<NetSnapshot>,
) {
    let quiet = debounce();
    let mut last_major_pub: Option<tokio::time::Instant> = None;
    // FR-97 N14 — the last Major that was not our own exit's capture.
    let mut last_network_major_pub: Option<tokio::time::Instant> = None;
    loop {
        let Some((first, _detail)) = raw_rx.recv().await else {
            warn!(
                "netstate: OS backend channel closed — monitor stopping (subscribers degrade to timers)"
            );
            return;
        };
        let mut saw_addr = first == RawSignal::Addr;
        let mut saw_iface = first == RawSignal::Iface;
        let mut absorbed = 0usize;
        let cap = tokio::time::Instant::now() + DEBOUNCE_CAP;
        loop {
            match tokio::time::timeout(quiet, raw_rx.recv()).await {
                Ok(Some((sig, _))) => {
                    saw_addr |= sig == RawSignal::Addr;
                    saw_iface |= sig == RawSignal::Iface;
                    absorbed += 1;
                    if tokio::time::Instant::now() >= cap {
                        break;
                    }
                }
                Ok(None) => {
                    warn!("netstate: OS backend channel closed mid-burst — monitor stopping");
                    return;
                }
                Err(_) => break, // quiet period elapsed
            }
        }
        let next = Arc::new(sample_snapshot());
        match diff(&prev, &next, saw_addr, saw_iface) {
            Some(mut delta) => {
                // Flap damping — see MAJOR_PUBLISH_COOLDOWN. Demotion keeps
                // the wake-up flowing; only the heavy lanes are spared.
                if delta.material
                    && delta.severity == Severity::Major
                    && major_demoted(
                        delta.own_capture_only,
                        last_major_pub.map(|t| t.elapsed()),
                        last_network_major_pub.map(|t| t.elapsed()),
                    )
                {
                    delta.severity = Severity::Minor;
                    delta.summary = format!("{} [major demoted: flap cooldown]", delta.summary);
                }
                info!(
                    severity = ?delta.severity,
                    absorbed,
                    %delta.summary,
                    "netstate: network changed"
                );
                if delta.material && delta.severity == Severity::Major {
                    let now = tokio::time::Instant::now();
                    last_major_pub = Some(now);
                    if !delta.own_capture_only {
                        last_network_major_pub = Some(now);
                    }
                    stamp_major();
                }
                let _ = snap_tx.send(next.clone());
                let _ = delta_tx.send(delta); // no receivers = fine
            }
            None => {
                // Snapshot-invisible churn (an erased peer /32, our own
                // re-assert wave) — still a wake-up, flagged immaterial.
                debug!(
                    absorbed,
                    "netstate: signal burst with no snapshot-visible change"
                );
                let _ = delta_tx.send(NetDelta {
                    severity: Severity::Minor,
                    material: false,
                    default_route_moved: false,
                    addrs_added: 0,
                    addrs_removed: 0,
                    saw_addr_signal: saw_addr,
                    saw_iface_signal: saw_iface,
                    own_capture_only: false,
                    summary: format!("route churn, no snapshot delta ({} signals)", absorbed + 1),
                });
            }
        }
        prev = next;
    }
}

/// Sample the CURRENT network state. Interfaces via `if_addrs` (portable);
/// effective default routes via a route lookup per family.
pub fn sample_snapshot() -> NetSnapshot {
    let mut ifaces: BTreeMap<String, IfaceSnap> = BTreeMap::new();
    // FR-33 — (name, ifindex, address, prefix length) per LAN v4 address, for
    // the capture probe below.
    let mut lan_v4: Vec<(String, Option<u32>, std::net::Ipv4Addr, u8)> = Vec::new();
    if let Ok(addrs) = if_addrs::get_if_addrs() {
        for a in addrs {
            let slot = ifaces.entry(a.name.clone()).or_default();
            slot.vpn_class = super::direct::lan_iface_denied(&a.name, "");
            match a.addr {
                if_addrs::IfAddr::V4(v4) => {
                    if !v4.ip.is_loopback() {
                        slot.v4.push(v4.ip);
                        lan_v4.push((a.name.clone(), a.index, v4.ip, v4.prefixlen));
                    }
                }
                if_addrs::IfAddr::V6(v6) => {
                    if !v6.ip.is_loopback() {
                        slot.v6_count += 1;
                    }
                }
            }
        }
        for s in ifaces.values_mut() {
            s.v4.sort_unstable();
        }
    }
    // A LAN interface whose OWN prefix route is dead (its next hop is not on
    // that LAN) is repaired first, so the capture probe below sees the table
    // as it now is. Narrow by construction: it never routes around another
    // interface's capture (`lan_repair` module docs).
    #[cfg(windows)]
    {
        let lan_only: Vec<_> = lan_v4
            .iter()
            .filter(|(name, ..)| !ifaces.get(name).is_some_and(|i| i.vpn_class))
            .cloned()
            .collect();
        super::lan_repair::reconcile(&lan_only);
    }
    let lan_captures = if crate::env::flag("OVERLAY_LAN_CAPTURE_PROBE", true) {
        detect_lan_captures(&lan_v4, &ifaces)
    } else {
        Vec::new()
    };
    let default_v4 = default_route(false);
    let default_v6 = default_route(true);
    NetSnapshot {
        ifaces,
        uplink_v4: uplink_beneath_own(default_v4.as_ref(), false),
        uplink_v6: uplink_beneath_own(default_v6.as_ref(), true),
        default_v4,
        default_v6,
        lan_captures,
    }
}

/// FR-97 N14 — the route beneath our own adapter when the default lookup
/// lands on one ([`NetSnapshot::uplink_v4`]), else the default itself. Read
/// by the code the exemption pins use (`tun::uplink_beneath`), so the
/// network monitor and the pins agree on what the uplink is.
/// `ROOMLERD_OVERLAY_NETMON_UPLINK=0` puts netstate back to the lookup alone.
fn uplink_beneath_own(default: Option<&DefaultRoute>, v6: bool) -> Option<DefaultRoute> {
    #[cfg(feature = "overlay-l3")]
    if let Some(d) = default
        && crate::env::flag("OVERLAY_NETMON_UPLINK", true)
        && super::tun::is_own_ifref(&d.ifref)
    {
        return super::tun::uplink_beneath(v6)
            .map(|(ifref, gateway)| DefaultRoute { ifref, gateway });
    }
    #[cfg(not(feature = "overlay-l3"))]
    let _ = v6;
    default.cloned()
}

/// FR-33 — one route lookup per LAN v4 address: does a packet to a neighbour
/// inside our own prefix leave through the interface that owns the address?
/// Link-local, loopback, point-to-point (/31, /32) and name-classified VPN
/// adapters are skipped: none of them is a LAN a peer could be on.
fn detect_lan_captures(
    lan_v4: &[(String, Option<u32>, std::net::Ipv4Addr, u8)],
    ifaces: &BTreeMap<String, IfaceSnap>,
) -> Vec<LanCapture> {
    let mut out: Vec<LanCapture> = Vec::new();
    for (name, index, ip, plen) in lan_v4 {
        if *plen == 0 || *plen >= 31 || ip.is_link_local() || ip.is_loopback() {
            continue;
        }
        if ifaces.get(name).is_some_and(|i| i.vpn_class) {
            continue;
        }
        let Some(hit) = route_lookup(IpAddr::V4(neighbour_in_prefix(*ip, *plen))) else {
            continue;
        };
        let owner_ref = owner_ifref(name, *index);
        if hit.ifref == owner_ref {
            continue;
        }
        // A SIBLING is not a capture: a docked laptop with Wi-Fi and Ethernet
        // on the same LAN routes the neighbour through whichever the OS
        // prefers, and that interface reaches the LAN just as well. What
        // makes a capture is the selected interface holding NO address in
        // the prefix — a VPN adapter's tunnel address never does. Load-
        // bearing since P2 turned the verdict into an eligibility gate.
        if selected_holds_prefix(&hit.ifref, *ip, *plen, lan_v4) {
            continue;
        }
        let prefix = format!("{}/{}", network_of(*ip, *plen), plen);
        if out.iter().any(|c| c.prefix == prefix && &c.owner == name) {
            continue;
        }
        let via_name = name_for_ifref(&hit.ifref, lan_v4);
        out.push(LanCapture {
            prefix,
            owner: name.clone(),
            via_ifref: hit.ifref,
            via_name,
        });
    }
    out
}

/// Does the interface [`route_lookup`] selected (`ifref`) itself hold an
/// address inside `ip/plen`? True for a same-LAN sibling (Wi-Fi + Ethernet on
/// one switch); false for a VPN adapter, whose address lives in the corporate
/// pool — the discriminator between "the OS prefers the other NIC" and "the
/// tunnel swallowed the LAN".
fn selected_holds_prefix(
    ifref: &str,
    ip: std::net::Ipv4Addr,
    plen: u8,
    lan_v4: &[(String, Option<u32>, std::net::Ipv4Addr, u8)],
) -> bool {
    let net = network_of(ip, plen);
    lan_v4
        .iter()
        .any(|(n, i, a, _)| owner_ifref(n, *i) == ifref && network_of(*a, plen) == net)
}

/// The identity [`route_lookup`] reports for an interface: ifindex on Windows
/// (falling back to the name when `if_addrs` has none), the name elsewhere.
#[cfg(windows)]
fn owner_ifref(name: &str, index: Option<u32>) -> String {
    index
        .map(|i| i.to_string())
        .unwrap_or_else(|| name.to_string())
}
#[cfg(not(windows))]
fn owner_ifref(name: &str, _index: Option<u32>) -> String {
    name.to_string()
}

/// Map a lookup's `ifref` back to an interface name where the identity is an
/// index (Windows); on Unix the ref already IS the name.
#[cfg(windows)]
fn name_for_ifref(
    ifref: &str,
    lan_v4: &[(String, Option<u32>, std::net::Ipv4Addr, u8)],
) -> Option<String> {
    let idx: u32 = ifref.parse().ok()?;
    lan_v4
        .iter()
        .find(|(_, i, _, _)| *i == Some(idx))
        .map(|(n, _, _, _)| n.clone())
}
#[cfg(not(windows))]
fn name_for_ifref(
    ifref: &str,
    _lan_v4: &[(String, Option<u32>, std::net::Ipv4Addr, u8)],
) -> Option<String> {
    Some(ifref.to_string())
}

/// The network address of `ip/plen`.
fn network_of(ip: std::net::Ipv4Addr, plen: u8) -> std::net::Ipv4Addr {
    let mask: u32 = if plen == 0 {
        0
    } else {
        u32::MAX << (32 - plen as u32)
    };
    std::net::Ipv4Addr::from(u32::from(ip) & mask)
}

/// A host address inside our own prefix that is neither us, the network nor
/// the broadcast: flip the lowest bit, and if that lands on the network or
/// broadcast address, flip the second bit instead. A fixed target inside the
/// prefix is what makes the lookup answer "where would a LAN peer's packet
/// go" without depending on any peer actually existing.
fn neighbour_in_prefix(ip: std::net::Ipv4Addr, plen: u8) -> std::net::Ipv4Addr {
    let net = u32::from(network_of(ip, plen));
    let bcast = net | (u32::MAX >> plen as u32);
    let a = u32::from(ip) ^ 1;
    let pick = if a == net || a == bcast {
        u32::from(ip) ^ 2
    } else {
        a
    };
    std::net::Ipv4Addr::from(pick)
}

/// The fixed public destination the default-route sample looks up.
fn far_destination(v6: bool) -> IpAddr {
    if v6 {
        IpAddr::V6("2001:4860:4860::8888".parse().expect("literal"))
    } else {
        IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))
    }
}

fn default_route(v6: bool) -> Option<DefaultRoute> {
    route_lookup(far_destination(v6))
}

/// The IPv4 next hop toward the internet, for port mapping
/// ([`super::portmap`]). `None` on an on-link default route, a v6 next hop,
/// or a default route through a tunnel. Blocking (it may run `ip route get`).
pub(crate) fn default_gateway_v4() -> Option<std::net::Ipv4Addr> {
    match default_route(false)?.gateway? {
        IpAddr::V4(g) => Some(g),
        IpAddr::V6(_) => None,
    }
}

/// Where a packet to `dest` would leave: a route LOOKUP (never a send), the
/// instrument behind both the default-route sample and the FR-33 capture probe.
#[cfg(windows)]
fn route_lookup(dest_ip: IpAddr) -> Option<DefaultRoute> {
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET};
    // SAFETY: zeroed in/out structs + the documented GetBestRoute2 call
    // shape; the row is only read on NO_ERROR. The lookup never sends a
    // packet.
    unsafe {
        let mut dest: SOCKADDR_INET = core::mem::zeroed();
        match dest_ip {
            IpAddr::V6(v6) => {
                dest.Ipv6.sin6_family = AF_INET6;
                dest.Ipv6.sin6_addr.u.Byte = v6.octets();
            }
            IpAddr::V4(v4) => {
                dest.Ipv4.sin_family = AF_INET;
                dest.Ipv4.sin_addr.S_un.S_addr = u32::from(v4).to_be();
            }
        }
        let mut row: MIB_IPFORWARD_ROW2 = core::mem::zeroed();
        let mut src: SOCKADDR_INET = core::mem::zeroed();
        if GetBestRoute2(
            core::ptr::null_mut(),
            0,
            core::ptr::null(),
            &dest,
            0,
            &mut row,
            &mut src,
        ) != NO_ERROR
        {
            return None;
        }
        let gw = match row.NextHop.si_family {
            f if f == AF_INET => {
                let o = row.NextHop.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
                let ip = std::net::Ipv4Addr::new(o[0], o[1], o[2], o[3]);
                (!ip.is_unspecified()).then_some(IpAddr::V4(ip))
            }
            f if f == AF_INET6 => {
                let ip = std::net::Ipv6Addr::from(row.NextHop.Ipv6.sin6_addr.u.Byte);
                (!ip.is_unspecified()).then_some(IpAddr::V6(ip))
            }
            _ => None,
        };
        Some(DefaultRoute {
            ifref: row.InterfaceIndex.to_string(),
            gateway: gw,
        })
    }
}

#[cfg(target_os = "linux")]
fn route_lookup(dest_ip: IpAddr) -> Option<DefaultRoute> {
    // One-shot lookup, matching the existing shelled-`ip` style: cheap,
    // dependency-free, and correct through policy routing.
    let mut cmd = std::process::Command::new("ip");
    let dest = dest_ip.to_string();
    if dest_ip.is_ipv6() {
        cmd.args(["-6", "-o", "route", "get", dest.as_str()]);
    } else {
        cmd.args(["-o", "route", "get", dest.as_str()]);
    }
    let out = cmd.output().ok()?;
    let line = String::from_utf8_lossy(&out.stdout);
    let mut toks = line.split_whitespace().peekable();
    let (mut dev, mut via) = (None, None);
    while let Some(t) = toks.next() {
        match t {
            "dev" => dev = toks.peek().map(|s| s.to_string()),
            "via" => via = toks.peek().and_then(|s| s.parse::<IpAddr>().ok()),
            _ => {}
        }
    }
    dev.map(|d| DefaultRoute {
        ifref: d,
        gateway: via,
    })
}

#[cfg(target_os = "macos")]
fn route_lookup(dest_ip: IpAddr) -> Option<DefaultRoute> {
    // `route -n get` — the BSD twin of `ip route get`; multi-line
    // `key: value` output ("interface: en0" / "gateway: 192.168.68.1").
    let mut cmd = std::process::Command::new("route");
    let dest = dest_ip.to_string();
    if dest_ip.is_ipv6() {
        cmd.args(["-n", "get", "-inet6", dest.as_str()]);
    } else {
        cmd.args(["-n", "get", dest.as_str()]);
    }
    let out = cmd.output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let (mut ifname, mut gw) = (None, None);
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("interface:") {
            ifname = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("gateway:") {
            gw = v.trim().parse::<IpAddr>().ok();
        }
    }
    ifname.map(|d| DefaultRoute {
        ifref: d,
        gateway: gw,
    })
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn route_lookup(_dest_ip: IpAddr) -> Option<DefaultRoute> {
    None
}

/// macOS — classify one line of `route -n monitor`; `None` for every line that
/// is not a routing-table CHANGE (#1856).
///
/// `route -n monitor` prints a six-line block per routing message: a blank, a
/// `got message of size … on <date>` banner, the `RTM_…:` header, then
/// `locks:`, `sockaddrs:` and the addresses. Every line used to count as a
/// signal, `RTM_GET` included, and an `RTM_GET` is only somebody's LOOKUP:
/// ours too. `sample_snapshot` runs `route -n get` after every burst, and the
/// route guard re-asserts after every delta, so on macOS the monitor fed
/// itself. The field MacBook ran a route wave every 3 s for as long as it was
/// up (tick 22512 / event 8 over 18 h), each one a delete-then-add of every
/// peer `/32`.
#[cfg(any(target_os = "macos", test))]
fn classify_bsd_monitor_line(line: &str) -> Option<RawSignal> {
    let kind = line.split(':').next()?.trim();
    if !kind.starts_with("RTM_") {
        return None;
    }
    match kind {
        // A lookup's answer, a failed lookup, and TCP's "this route may be
        // failing" advisory: none of them changes the table.
        "RTM_GET" | "RTM_GET2" | "RTM_GET_SILENT" | "RTM_GET_EXT" | "RTM_MISS" | "RTM_LOSING" => {
            None
        }
        "RTM_NEWADDR" | "RTM_DELADDR" => Some(RawSignal::Addr),
        "RTM_IFINFO" | "RTM_IFINFO2" | "RTM_IFANNOUNCE" => Some(RawSignal::Iface),
        _ => Some(RawSignal::Route),
    }
}

/// The OS raw-signal backends — the `route_events` registrations, moved here
/// verbatim with the sender retyped to `(RawSignal, detail)`.
mod backend {
    use super::RawSignal;

    #[cfg(windows)]
    pub(super) use win::{BackendGuard, spawn};

    #[cfg(not(windows))]
    pub(super) use unix::{BackendGuard, spawn};

    #[cfg(all(test, not(windows)))]
    pub(super) use unix::supervise;

    #[cfg(windows)]
    mod win {
        use super::RawSignal;
        use core::ffi::c_void;
        use tokio::sync::mpsc::UnboundedSender;
        use windows_sys::Win32::Foundation::{HANDLE, NO_ERROR};
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            CancelMibChangeNotify2, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
            MIB_UNICASTIPADDRESS_ROW, NotifyIpInterfaceChange, NotifyRouteChange2,
            NotifyUnicastIpAddressChange,
        };
        use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

        struct Ctx {
            tx: UnboundedSender<(RawSignal, String)>,
        }

        pub(in super::super) struct BackendGuard {
            handle: HANDLE,
            addr_handle: HANDLE,
            iface_handle: HANDLE,
            ctx: *mut Ctx,
        }
        // Raw pointers are only touched in Drop, after CancelMibChangeNotify2
        // guarantees no callback is running.
        unsafe impl Send for BackendGuard {}

        unsafe extern "system" fn on_route_change(
            caller_context: *const c_void,
            _row: *const MIB_IPFORWARD_ROW2,
            notification_type: MIB_NOTIFICATION_TYPE,
        ) {
            if caller_context.is_null() {
                return;
            }
            let ctx = unsafe { &*(caller_context as *const Ctx) };
            let _ = ctx
                .tx
                .send((RawSignal::Route, format!("type={notification_type}")));
        }

        unsafe extern "system" fn on_addr_change(
            caller_context: *const c_void,
            _row: *const MIB_UNICASTIPADDRESS_ROW,
            notification_type: MIB_NOTIFICATION_TYPE,
        ) {
            if caller_context.is_null() {
                return;
            }
            let ctx = unsafe { &*(caller_context as *const Ctx) };
            let _ = ctx
                .tx
                .send((RawSignal::Addr, format!("type={notification_type}")));
        }

        unsafe extern "system" fn on_iface_change(
            caller_context: *const c_void,
            _row: *const MIB_IPINTERFACE_ROW,
            notification_type: MIB_NOTIFICATION_TYPE,
        ) {
            if caller_context.is_null() {
                return;
            }
            let ctx = unsafe { &*(caller_context as *const Ctx) };
            let _ = ctx
                .tx
                .send((RawSignal::Iface, format!("type={notification_type}")));
        }

        pub(in super::super) fn spawn(
            tx: UnboundedSender<(RawSignal, String)>,
        ) -> Option<BackendGuard> {
            let ctx = Box::into_raw(Box::new(Ctx { tx }));
            let mut handle: HANDLE = core::ptr::null_mut();
            let rc = unsafe {
                NotifyRouteChange2(
                    AF_UNSPEC,
                    Some(on_route_change),
                    ctx as *const c_void,
                    false,
                    &mut handle,
                )
            };
            if rc != NO_ERROR {
                tracing::warn!(rc, "netstate: NotifyRouteChange2 registration failed");
                drop(unsafe { Box::from_raw(ctx) });
                return None;
            }
            let mut addr_handle: HANDLE = core::ptr::null_mut();
            let rc = unsafe {
                NotifyUnicastIpAddressChange(
                    AF_UNSPEC,
                    Some(on_addr_change),
                    ctx as *const c_void,
                    false,
                    &mut addr_handle,
                )
            };
            if rc != NO_ERROR {
                tracing::warn!(
                    rc,
                    "netstate: NotifyUnicastIpAddressChange registration failed"
                );
                addr_handle = core::ptr::null_mut();
            }
            let mut iface_handle: HANDLE = core::ptr::null_mut();
            let rc = unsafe {
                NotifyIpInterfaceChange(
                    AF_UNSPEC,
                    Some(on_iface_change),
                    ctx as *const c_void,
                    false,
                    &mut iface_handle,
                )
            };
            if rc != NO_ERROR {
                tracing::warn!(rc, "netstate: NotifyIpInterfaceChange registration failed");
                iface_handle = core::ptr::null_mut();
            }
            Some(BackendGuard {
                handle,
                addr_handle,
                iface_handle,
                ctx,
            })
        }

        impl Drop for BackendGuard {
            fn drop(&mut self) {
                unsafe {
                    CancelMibChangeNotify2(self.handle);
                    if !self.addr_handle.is_null() {
                        CancelMibChangeNotify2(self.addr_handle);
                    }
                    if !self.iface_handle.is_null() {
                        CancelMibChangeNotify2(self.iface_handle);
                    }
                    drop(Box::from_raw(self.ctx));
                }
            }
        }
    }

    #[cfg(not(windows))]
    mod unix {
        use super::RawSignal;
        use std::process::Stdio;
        use std::time::Duration;
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::sync::mpsc::UnboundedSender;

        /// Owns the supervising reader task, which owns the monitor child.
        /// Dropping the guard aborts the task, and dropping the task's
        /// `Child` (`kill_on_drop`) kills the monitor.
        pub(in super::super) struct BackendGuard {
            reader: tokio::task::JoinHandle<()>,
        }

        /// PR-3 — classify a monitor line. Linux `ip -o monitor route addr
        /// link` prints ONE line per message and labels sections
        /// `[ROUTE]`/`[ADDR]`/`[LINK]` when watching multiple objects.
        /// Unrecognized ⇒ Route — the snapshot diff carries the real
        /// information either way. macOS has its own classifier
        /// (`classify_bsd_monitor_line`): its monitor prints several lines
        /// per message, and lookups among them.
        #[cfg(not(target_os = "macos"))]
        fn classify(line: &str) -> Option<RawSignal> {
            Some(if line.contains("[ADDR]") {
                RawSignal::Addr
            } else if line.contains("[LINK]") {
                RawSignal::Iface
            } else {
                RawSignal::Route
            })
        }

        #[cfg(target_os = "macos")]
        fn classify(line: &str) -> Option<RawSignal> {
            super::super::classify_bsd_monitor_line(line)
        }

        /// PR-3 — full class coverage: routes + addresses + links on Linux
        /// (`notify_regather` and the LAN-set rebuild key on the addr/iface
        /// classes, which the route-only child never fired); `route -n
        /// monitor` on macOS (PF_ROUTE's socket, one block per kernel routing
        /// message).
        fn monitor_command() -> tokio::process::Command {
            #[cfg(target_os = "macos")]
            {
                let mut c = tokio::process::Command::new("route");
                c.args(["-n", "monitor"]);
                c
            }
            #[cfg(not(target_os = "macos"))]
            {
                let mut c = tokio::process::Command::new("ip");
                c.args(["-o", "monitor", "route", "addr", "link"]);
                c
            }
        }

        pub(in super::super) fn spawn(
            tx: UnboundedSender<(RawSignal, String)>,
        ) -> Option<BackendGuard> {
            supervise(
                monitor_command,
                tx,
                Duration::from_millis(250),
                Duration::from_secs(30),
            )
        }

        fn start(make: fn() -> tokio::process::Command) -> Option<tokio::process::Child> {
            make()
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .ok()
        }

        /// #1867 — run the monitor child and RESPAWN it whenever it exits.
        ///
        /// It used to run once: when the child died (killed by an over-broad
        /// `pkill`, crashed, OOM-reaped) the reader hit EOF, the channel
        /// closed, and the monitor stopped for the life of the process. The
        /// broadcast sender lives on in the process-wide handle, so the
        /// runtime never even saw `Closed` and never fell back to its 2 s
        /// tick. It just ran without an OS change feed until the next restart
        /// (field: MacBook-1, 2026-10-08, 10:35Z until an update restarted it).
        ///
        /// The FIRST spawn must succeed. `None` tells the caller there is no
        /// subscription at all, which keeps the runtime on its blind tick.
        /// After that, a dead child is respawned with a capped backoff (reset
        /// after a long healthy run). Each respawn sends one synthetic Route
        /// signal, so the monitor re-samples whatever changed while nothing was
        /// watching and the route guard re-asserts against it.
        pub(in super::super) fn supervise(
            make: fn() -> tokio::process::Command,
            tx: UnboundedSender<(RawSignal, String)>,
            first: Duration,
            max: Duration,
        ) -> Option<BackendGuard> {
            let child = start(make)?;
            let reader = tokio::spawn(async move {
                let mut child = child;
                let mut backoff = first;
                loop {
                    let started = tokio::time::Instant::now();
                    if let Some(stdout) = child.stdout.take() {
                        let mut lines = BufReader::new(stdout).lines();
                        while let Ok(Some(line)) = lines.next_line().await {
                            let Some(signal) = classify(&line) else {
                                continue;
                            };
                            if tx.send((signal, line)).is_err() {
                                return; // the monitor is gone: nobody to feed
                            }
                        }
                    }
                    // EOF: the child is gone or going. Reap it, or kill one that
                    // closed its stdout without exiting.
                    let status =
                        match tokio::time::timeout(Duration::from_secs(2), child.wait()).await {
                            Ok(s) => s.ok(),
                            Err(_) => {
                                let _ = child.kill().await;
                                None
                            }
                        };
                    if started.elapsed() >= max {
                        backoff = first; // it ran for a while: a new failure, not a loop
                    }
                    tracing::warn!(
                        ?status,
                        retry_in_ms = backoff.as_millis() as u64,
                        "netstate: the OS route monitor exited — respawning it (#1867); until it \
                         is back the route guard runs on its heartbeat alone"
                    );
                    loop {
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(max);
                        if tx.is_closed() {
                            return;
                        }
                        if let Some(c) = start(make) {
                            child = c;
                            break;
                        }
                    }
                    if tx
                        .send((RawSignal::Route, "netstate: backend respawned".into()))
                        .is_err()
                    {
                        return;
                    }
                    tracing::info!("netstate: OS route monitor respawned");
                }
            });
            Some(BackendGuard { reader })
        }

        impl Drop for BackendGuard {
            fn drop(&mut self) {
                self.reader.abort();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn snap(ifaces: &[(&str, &[&str])], default_if: Option<&str>) -> NetSnapshot {
        let mut m = BTreeMap::new();
        for (name, addrs) in ifaces {
            m.insert(
                name.to_string(),
                IfaceSnap {
                    v4: addrs
                        .iter()
                        .map(|a| a.parse::<Ipv4Addr>().unwrap())
                        .collect(),
                    v6_count: 0,
                    vpn_class: super::super::direct::lan_iface_denied(name, ""),
                },
            );
        }
        let default_v4 = default_if.map(|i| DefaultRoute {
            ifref: i.to_string(),
            gateway: Some("192.168.68.1".parse().unwrap()),
        });
        NetSnapshot {
            ifaces: m,
            uplink_v4: default_v4.clone(),
            default_v4,
            default_v6: None,
            uplink_v6: None,
            lan_captures: vec![],
        }
    }

    /// `snap` with an exit active: the lookup lands on our TUN, and the
    /// uplink beneath it is `uplink_if` via `gateway`.
    fn under_exit(ifaces: &[(&str, &[&str])], uplink_if: &str, gateway: &str) -> NetSnapshot {
        let mut s = snap(ifaces, Some("roomler0"));
        s.uplink_v4 = Some(DefaultRoute {
            ifref: uplink_if.to_string(),
            gateway: Some(gateway.parse().unwrap()),
        });
        s
    }

    /// FR-97 N14 — the field case: an exit is active, the client's uplink
    /// moves to its second NIC, and nothing else netstate models changes (the
    /// downed NIC keeps its address; the lookup answers with our TUN before
    /// and after). That has to be a Major, or the control WS probe and the
    /// carrier revalidation never run. The exit coming up over an unchanged
    /// uplink stays exactly the Major it always was, and a host with no exit
    /// logs nothing new.
    #[test]
    fn an_uplink_move_beneath_an_active_exit_is_a_major() {
        let nics: &[(&str, &[&str])] = &[("eth0", &["172.31.10.2"]), ("eth1", &["172.31.11.2"])];
        let on_eth0 = under_exit(nics, "eth0", "172.31.10.1");
        let on_eth1 = under_exit(nics, "eth1", "172.31.11.1");

        let d = diff(&on_eth0, &on_eth1, false, true).expect("the uplink moved");
        assert_eq!(d.severity, Severity::Major);
        assert!(d.default_route_moved);
        assert!(
            d.summary.contains("v4_default=roomler0 uplink=eth1"),
            "the log names the uplink beneath the TUN: {}",
            d.summary
        );
        assert!(
            diff(&on_eth1, &on_eth1.clone(), false, false).is_none(),
            "an exit holding still is no change"
        );

        // The exit coming up over the same uplink: the default moves to our
        // TUN while the uplink beneath it does not — one Major, as before.
        let mut plain = snap(nics, Some("eth0"));
        plain.uplink_v4 = on_eth0.uplink_v4.clone();
        plain.default_v4 = on_eth0.uplink_v4.clone();
        let d = diff(&plain, &on_eth0, false, false).expect("the exit came up");
        assert_eq!(d.severity, Severity::Major);

        // No exit: the uplink is the default, and the summary says nothing new.
        let d = diff(&plain, &snap(nics, Some("eth1")), false, false).expect("default moved");
        assert!(!d.summary.contains("uplink="), "{}", d.summary);
    }

    /// FR-97 N14 — off our own adapter the uplink IS the default: no table
    /// read, nothing that could make a host without an exit see a move.
    #[test]
    fn the_uplink_is_the_default_unless_the_lookup_lands_on_our_adapter() {
        let d = DefaultRoute {
            ifref: "203".into(),
            gateway: Some("192.168.68.1".parse().unwrap()),
        };
        assert_eq!(uplink_beneath_own(Some(&d), false), Some(d.clone()));
        assert_eq!(uplink_beneath_own(None, true), None);
    }

    /// FR-97 N14 — our own exit coming or going stays a Major, but it does
    /// not spend the cooldown a real move after it needs. An exit whose
    /// carrier flaps is still damped.
    #[test]
    fn our_exits_capture_does_not_spend_the_cooldown_a_real_move_needs() {
        let s = |n| Some(Duration::from_secs(n));
        // The field case: the exit came up 13 s before the uplink moved.
        assert!(
            !major_demoted(false, s(13), None),
            "the real move publishes"
        );
        // A real move 30 s after another real move is damped, as ever.
        assert!(major_demoted(false, s(30), s(30)));
        // The exit's own capture flapping is damped by any recent Major.
        assert!(major_demoted(true, s(13), None));
        assert!(major_demoted(true, s(40), s(40)));
        // The first Major of either kind publishes.
        assert!(!major_demoted(true, None, None));
        assert!(!major_demoted(false, None, None));
    }

    /// FR-97 N14 — a delta says whether the only thing that moved was our
    /// own exit's capture.
    #[test]
    fn a_delta_says_whether_only_our_exits_capture_moved() {
        let nics: &[(&str, &[&str])] = &[("eth0", &["172.31.10.2"]), ("eth1", &["172.31.11.2"])];
        let on_eth0 = under_exit(nics, "eth0", "172.31.10.1");
        let mut plain = snap(nics, Some("eth0"));
        plain.default_v4 = on_eth0.uplink_v4.clone();
        plain.uplink_v4 = on_eth0.uplink_v4.clone();

        let up = diff(&plain, &on_eth0, false, false).expect("the exit came up");
        assert!(up.own_capture_only && up.severity == Severity::Major);
        let down = diff(&on_eth0, &plain, false, false).expect("the exit went");
        assert!(down.own_capture_only);

        let on_eth1 = under_exit(nics, "eth1", "172.31.11.1");
        assert!(
            !diff(&on_eth0, &on_eth1, false, true)
                .unwrap()
                .own_capture_only,
            "the uplink moving beneath the exit is the network moving"
        );
        assert!(
            !diff(
                &snap(nics, Some("eth0")),
                &snap(nics, Some("eth1")),
                false,
                false
            )
            .unwrap()
            .own_capture_only,
            "a default move on a host without an exit"
        );
        let lost = under_exit(&[("eth1", &["172.31.11.2"])], "eth0", "172.31.10.1");
        assert!(
            !diff(&plain, &lost, true, false).unwrap().own_capture_only,
            "the exit coming up while an address goes"
        );
    }

    /// FR-33 — a capture appearing or clearing is a material delta on its
    /// own (nothing else moved), stays Minor (no socket keys on it), and the
    /// summary names it both ways — the one onset / one clear line.
    #[test]
    fn lan_capture_change_is_material_minor_and_named() {
        let home = snap(&[("Wi-Fi", &["192.168.68.132"])], Some("Wi-Fi"));
        let mut captured = home.clone();
        captured.lan_captures.push(LanCapture {
            prefix: "192.168.68.128/25".into(),
            owner: "Wi-Fi".into(),
            via_ifref: "27".into(),
            via_name: Some("Ethernet 3".into()),
        });
        let d = diff(&home, &captured, false, false).expect("onset is material");
        assert!(d.material);
        assert_eq!(d.severity, Severity::Minor, "a capture keys no socket");
        assert!(!d.default_route_moved);
        assert!(
            d.summary
                .contains("lan_capture=192.168.68.128/25 via Ethernet 3"),
            "summary names the capture: {}",
            d.summary
        );
        let d = diff(&captured, &home, false, false).expect("clear is material");
        assert!(d.summary.contains("lan_capture=clear"), "{}", d.summary);
        assert!(
            diff(&captured, &captured, false, false).is_none(),
            "unchanged = no delta"
        );
    }

    /// FR-33 P2 — `contains_v4` is the gate's membership test; the prefix
    /// travels as the string `status` prints, so it must parse both the /24
    /// and the split-/25 shapes the two VPN vendors produce, and fail OPEN on
    /// anything else.
    #[test]
    fn lan_capture_contains_v4_matches_prefix_membership() {
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let cap = |prefix: &str| LanCapture {
            prefix: prefix.into(),
            owner: "WLAN".into(),
            via_ifref: "10".into(),
            via_name: Some("Ethernet 2".into()),
        };
        let c = cap("192.168.43.0/24");
        assert!(c.contains_v4(ip("192.168.43.221")));
        assert!(c.contains_v4(ip("192.168.43.1")));
        assert!(!c.contains_v4(ip("192.168.0.241")));
        let half = cap("192.168.68.128/25");
        assert!(half.contains_v4(ip("192.168.68.132")));
        assert!(
            !half.contains_v4(ip("192.168.68.126")),
            "the other half is a different capture"
        );
        assert!(
            !cap("garbage").contains_v4(ip("192.168.43.221")),
            "unparseable = fail OPEN"
        );
        assert!(!cap("192.168.43.0/33").contains_v4(ip("192.168.43.221")));
    }

    /// FR-33 P2 — a same-LAN SIBLING interface is not a capture: the selected
    /// interface holds an address in the prefix, so it reaches the LAN. A VPN
    /// adapter never does, so the capture verdict stands.
    #[test]
    fn selected_interface_holding_the_prefix_is_a_sibling_not_a_capture() {
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let lan_v4 = vec![
            ("WLAN".to_string(), Some(6), ip("192.168.0.24"), 24),
            ("Ethernet".to_string(), Some(5), ip("192.168.0.50"), 24),
            ("Ethernet 2".to_string(), Some(10), ip("10.138.80.59"), 20),
        ];
        let eth = owner_ifref("Ethernet", Some(5));
        let vpn = owner_ifref("Ethernet 2", Some(10));
        assert!(
            selected_holds_prefix(&eth, ip("192.168.0.24"), 24, &lan_v4),
            "docked laptop: Ethernet reaches the same LAN"
        );
        assert!(
            !selected_holds_prefix(&vpn, ip("192.168.0.24"), 24, &lan_v4),
            "AnyConnect miniport: its address is in the corporate pool"
        );
        assert!(!selected_holds_prefix(
            "nope",
            ip("192.168.0.24"),
            24,
            &lan_v4
        ));
    }

    /// FR-33 — the probe target is a host inside our own prefix that is
    /// neither us, the network nor the broadcast address.
    #[test]
    fn neighbour_in_prefix_stays_inside_and_off_the_edges() {
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        assert_eq!(
            neighbour_in_prefix(ip("192.168.68.126"), 24),
            ip("192.168.68.127")
        );
        assert_eq!(
            neighbour_in_prefix(ip("192.168.68.132"), 25),
            ip("192.168.68.133")
        );
        // ^1 would land on the broadcast → the second bit is flipped instead.
        assert_eq!(neighbour_in_prefix(ip("10.0.0.254"), 24), ip("10.0.0.252"));
        // ^1 would land on the network address.
        assert_eq!(neighbour_in_prefix(ip("10.0.0.1"), 24), ip("10.0.0.3"));
        assert_eq!(network_of(ip("192.168.68.132"), 25), ip("192.168.68.128"));
        assert_eq!(network_of(ip("10.20.30.40"), 8), ip("10.0.0.0"));
    }

    /// Flap damping — one material Major per cooldown window; inside it the
    /// heavy lanes must not refire (field: the CP route-flap probe storm).
    #[test]
    fn major_cooldown_demotes_flaps() {
        assert!(!major_cooldown_active(None), "first Major always publishes");
        assert!(major_cooldown_active(Some(Duration::from_secs(30))));
        assert!(
            !major_cooldown_active(Some(MAJOR_PUBLISH_COOLDOWN)),
            "cooldown elapsed — next Major publishes"
        );
    }

    /// The severity contract: default-route movement or vanished addresses
    /// ⇒ Major (a VPN capture is BOTH); additions alone ⇒ Minor; identical
    /// snapshots (a self-inflicted route-churn burst) ⇒ no delta at all.
    #[test]
    fn diff_severity_contract() {
        let home = snap(&[("Wi-Fi", &["192.168.68.106"])], Some("12"));
        // VPN connect: default route moves to a new interface, address set intact.
        let captured = snap(
            &[
                ("Wi-Fi", &["192.168.68.106"]),
                ("Ethernet 3", &["10.138.80.110"]),
            ],
            Some("47"),
        );
        let d = diff(&home, &captured, true, true).expect("material change");
        assert_eq!(d.severity, Severity::Major);
        assert!(d.default_route_moved);
        assert!(d.saw_addr_signal && d.saw_iface_signal);

        // VPN disconnect: the vpn address vanishes ⇒ Major even if the
        // default-route sample momentarily reads the same.
        let d = diff(&captured, &home, true, false).expect("material change");
        assert_eq!(d.severity, Severity::Major);
        assert_eq!(d.addrs_removed, 1);

        // A new address with nothing else ⇒ Minor.
        let extra = snap(
            &[("Wi-Fi", &["192.168.68.106", "192.168.68.107"])],
            Some("12"),
        );
        let d = diff(&home, &extra, true, false).expect("material change");
        assert_eq!(d.severity, Severity::Minor);
        assert_eq!(d.addrs_added, 1);

        // Identical ⇒ None (the burst was our own route re-asserts).
        assert!(diff(&home, &home.clone(), false, false).is_none());
    }

    /// #1856 — macOS `route -n monitor`, verbatim from the field MacBook (its
    /// en0 link-layer address replaced): two
    /// lookups (one of them is what `sample_snapshot` runs after every burst)
    /// and then a route guard re-assert of one peer. Only the re-assert's two
    /// headers are changes; the other ten lines must not signal at all.
    #[test]
    fn bsd_monitor_signals_only_on_change_headers() {
        let monitor = "
got message of size 164 on Thu Oct  8 13:48:53 2026
RTM_GET: Report Metrics: len 164, pid: 67311, seq 1, errno 0, flags:<UP,HOST,DONE,STATIC>
locks:  inits:
sockaddrs: <DST,GATEWAY,IFP,IFA>
 100.65.4.2 index: 24 utun0 index: 24 utun0 100.65.4.34

got message of size 164 on Thu Oct  8 13:48:53 2026
RTM_GET: Report Metrics: len 164, pid: 67312, seq 1, errno 0, flags:<UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
locks:  inits:
sockaddrs: <DST,GATEWAY,NETMASK,IFP,IFA>
 default 192.168.8.1 default index: 15 en0:2.0.0.0.0.1 192.168.8.108

got message of size 128 on Thu Oct  8 13:56:57 2026
RTM_DELETE: Delete Route: len 128, pid: 70821, seq 1, errno 0, flags:<HOST,DONE,STATIC,CONDEMNED>
locks:  inits:
sockaddrs: <DST,GATEWAY>
 100.65.4.14 index: 24 utun0

got message of size 128 on Thu Oct  8 13:56:57 2026
RTM_ADD: Add Route: len 128, pid: 70825, seq 1, errno 0, flags:<UP,HOST,DONE,STATIC>
locks:  inits:
sockaddrs: <DST,GATEWAY>
 100.65.4.14 index: 24 utun0
";
        let signals: Vec<RawSignal> = monitor
            .lines()
            .filter_map(classify_bsd_monitor_line)
            .collect();
        assert_eq!(signals, vec![RawSignal::Route, RawSignal::Route]);

        // The address/interface classes still reach the roam lanes.
        let hdr = |kind: &str| format!("{kind}: x: len 1, pid: 1, seq 1, errno 0, flags:<UP>");
        for (kind, want) in [
            ("RTM_NEWADDR", Some(RawSignal::Addr)),
            ("RTM_DELADDR", Some(RawSignal::Addr)),
            ("RTM_IFINFO", Some(RawSignal::Iface)),
            ("RTM_CHANGE", Some(RawSignal::Route)),
            ("RTM_REDIRECT", Some(RawSignal::Route)),
            ("RTM_MISS", None),
            ("RTM_LOSING", None),
        ] {
            assert_eq!(classify_bsd_monitor_line(&hdr(kind)), want, "{kind}");
        }
    }

    /// #1867 — a monitor child that dies is respawned, and every respawn wakes
    /// the monitor. The fake prints one line and exits at once, so the
    /// supervisor has to keep bringing it back.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn a_dead_monitor_child_is_respawned_and_wakes_the_monitor() {
        fn fake_monitor() -> tokio::process::Command {
            let mut c = tokio::process::Command::new("sh");
            // `RTM_ADD:` is a Route signal for both the Linux and BSD classifiers.
            c.args(["-c", "echo 'RTM_ADD: fake route'"]);
            c
        }
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let guard = backend::supervise(
            fake_monitor,
            tx,
            Duration::from_millis(5),
            Duration::from_millis(20),
        )
        .expect("the first spawn must succeed");
        let (mut lines, mut respawns) = (0, 0);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while (lines < 3 || respawns < 2) && tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
                Ok(Some((RawSignal::Route, d))) if d.contains("fake route") => lines += 1,
                Ok(Some((RawSignal::Route, d))) if d.contains("respawned") => respawns += 1,
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        assert!(
            lines >= 3 && respawns >= 2,
            "a dead monitor must be brought back, and each return must wake the monitor: \
             lines={lines} respawns={respawns}"
        );
        // Dropping the guard stops it: the channel drains, then closes.
        drop(guard);
        let closed = tokio::time::timeout(Duration::from_secs(2), async {
            while rx.recv().await.is_some() {}
        })
        .await;
        assert!(
            closed.is_ok(),
            "dropping the guard must stop the supervisor and close the feed"
        );
    }

    /// The sampler runs on the host without privileges and produces a
    /// consistent snapshot (smoke — content is host-specific).
    #[test]
    fn sample_snapshot_smoke() {
        let s = sample_snapshot();
        // At least a loopback-stripped view exists; both calls agree.
        assert_eq!(s.ifaces, sample_snapshot().ifaces);
    }
}
