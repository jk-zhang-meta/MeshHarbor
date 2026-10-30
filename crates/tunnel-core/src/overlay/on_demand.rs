// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! MeshHarbor B6 — On-demand pair tunneling (`按需pair隧道`).
//!
//! Classic WireGuard peers in an always-on mesh exchange a 148-byte handshake
//! initiation + 92-byte response on install, followed by a 32-byte persistent
//! keepalive every 25 seconds (`KEEPALIVE_SECS`) and a full Noise rekey every
//! ~120 seconds, even when two nodes never exchange a single byte of business
//! IP traffic. In an N-node full mesh, idle pair background traffic scales as
//! $O(N^2)$.
//!
//! This module implements per-peer on-demand dormancy and first-packet wakeup:
//! * **Background traffic baseline & wire accounting**: Every WireGuard frame
//!   sent or received on a peer's carrier is classified into business transport
//!   data vs. protocol background traffic (Type 1 Handshake Initiation, Type 2
//!   Handshake Response, Type 3 Cookie Reply, and Type 4 32-byte empty
//!   Persistent Keepalive).
//! * **Configurable idle threshold & global off**: Controlled by
//!   [`OnDemandConfig`] (`OVERLAY_ON_DEMAND`, `OVERLAY_ON_DEMAND_IDLE_SECS`,
//!   `OVERLAY_ON_DEMAND_DEFER_INITIAL`), defaulting to `enabled = false` so
//!   classic always-on behavior is preserved unless explicitly enabled.
//! * **In-place dormancy (`OnDemandPhase::Dormant`)**: When a peer has no
//!   business traffic (`tx_attempted` and decrypted `rx`) for `idle_timeout`
//!   and no active hold (no direct upgrade probe, bilateral path trial, ORG
//!   relay upgrade/floor/recovery, or standby tee/sink), its 250 ms timer loop
//!   suspends `Tunn::update_timers`, dropping background keepalive and rekey
//!   emissions to **zero packets / zero bytes** while keeping its cryptokey
//!   route (`Router`), `SendPeer` handle, `Carrier`, and `DirectDemux` /
//!   `CarrierPlane` receiver registrations intact (no `remove_peer` / `add_peer`
//!   teardown-rebuild churn).
//! * **Zero-loss first-packet wakeup (`Dormant -> Waking -> Active`)**: The
//!   first outbound IP packet (or packet batch) arriving for a `Dormant` peer
//!   transitions it to `Waking` under the per-peer `Tunn` lock, clears stale
//!   session keys via `Tunn::set_static_private` (preserving the 24-bit peer
//!   index, TAI64N replay watermark, and monotonic stamper), queues the
//!   triggering packet(s) inside `boringtun::noise::Tunn`, and immediately
//!   emits a 148-byte Handshake Initiation over the active carrier (direct UDP
//!   or relay). When the 92-byte Handshake Response arrives, `decap_inbound`
//!   flushes all queued packets in FIFO order with **zero packet loss**,
//!   transitions the peer to `Active`, and records the exact first-packet
//!   establishment latency (`last_wake_latency_ns`, `max_wake_latency_ns`).

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

/// Maximum number of packets `boringtun::noise::Tunn::queue_packet` buffers
/// while a handshake is in flight (`MAX_QUEUE_DEPTH = 256`).
const BORINGTUN_QUEUE_PACKET_CAP: usize = 256;

/// Default business-idle timeout before an `Active` peer transitions to
/// [`OnDemandPhase::Dormant`].
pub const DEFAULT_ON_DEMAND_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Minimum programmatic idle timeout (allows fast deterministic unit and
/// integration tests while preventing zero-duration oscillation).
pub const MIN_ON_DEMAND_IDLE_TIMEOUT: Duration = Duration::from_millis(10);

/// WireGuard message type constants (little-endian `u32` at bytes `0..4`).
const WG_TYPE_HANDSHAKE_INIT: [u8; 4] = [1, 0, 0, 0];
const WG_TYPE_HANDSHAKE_RESP: [u8; 4] = [2, 0, 0, 0];
const WG_TYPE_COOKIE_REPLY: [u8; 4] = [3, 0, 0, 0];
const WG_TYPE_TRANSPORT_DATA: [u8; 4] = [4, 0, 0, 0];

/// Exact WireGuard frame sizes for control and keepalive packets.
pub const WG_HANDSHAKE_INIT_BYTES: usize = 148;
pub const WG_HANDSHAKE_RESP_BYTES: usize = 92;
pub const WG_COOKIE_REPLY_BYTES: usize = 64;
pub const WG_KEEPALIVE_BYTES: usize = 32;

/// Configuration for per-peer on-demand tunneling on a [`super::wg::WgDevice`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnDemandConfig {
    /// Master switch. When `false` (the default), peers operate in classic
    /// always-on mode (`KEEPALIVE_SECS = 25` and immediate handshake on install).
    pub enabled: bool,
    /// Duration of zero business traffic (`tx_attempted` and decrypted `rx`)
    /// after which an `Active` (or unanswered `Waking`) peer transitions to
    /// [`OnDemandPhase::Dormant`], provided no upgrade probe, path trial, ORG
    /// transition, or standby hold is active for that peer.
    pub idle_timeout: Duration,
    /// When `true` (default when `enabled` is `true`), newly installed routed
    /// peers start in [`OnDemandPhase::Dormant`] without emitting an initial
    /// 148-byte Handshake Initiation until the first business packet arrives
    /// (or the remote peer initiates).
    pub defer_initial_handshake: bool,
}

impl Default for OnDemandConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

impl OnDemandConfig {
    /// Classic always-on mode (global off).
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            idle_timeout: DEFAULT_ON_DEMAND_IDLE_TIMEOUT,
            defer_initial_handshake: false,
        }
    }

    /// Enable on-demand pair tunneling with the specified `idle_timeout`
    /// (clamped to at least [`MIN_ON_DEMAND_IDLE_TIMEOUT`]) and deferred
    /// initial handshake enabled.
    pub fn enabled(idle_timeout: Duration) -> Self {
        let clamped = if idle_timeout < MIN_ON_DEMAND_IDLE_TIMEOUT {
            MIN_ON_DEMAND_IDLE_TIMEOUT
        } else {
            idle_timeout
        };
        Self {
            enabled: true,
            idle_timeout: clamped,
            defer_initial_handshake: true,
        }
    }

    /// Builder override for `defer_initial_handshake`.
    pub const fn with_defer_initial_handshake(mut self, defer: bool) -> Self {
        self.defer_initial_handshake = defer;
        self
    }

    /// Parse configuration from node environment variables:
    /// * `ROOMLERD_OVERLAY_ON_DEMAND` / `OVERLAY_ON_DEMAND`: `"1" | "true" | "on" | "yes"`
    /// * `ROOMLERD_OVERLAY_ON_DEMAND_IDLE_SECS` / `OVERLAY_ON_DEMAND_IDLE_SECS`: seconds (`u64`, min 1s)
    /// * `ROOMLERD_OVERLAY_ON_DEMAND_DEFER_INITIAL` / `OVERLAY_ON_DEMAND_DEFER_INITIAL`: `"0" | "false" | "off" | "no"` to disable initial deferral
    pub fn from_env() -> Self {
        let enabled = crate::env::node_env("OVERLAY_ON_DEMAND")
            .as_deref()
            .is_some_and(parse_bool_true);
        if !enabled {
            return Self::disabled();
        }
        let idle_timeout = crate::env::node_env("OVERLAY_ON_DEMAND_IDLE_SECS")
            .as_deref()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|secs| Duration::from_secs(secs.max(1)))
            .unwrap_or(DEFAULT_ON_DEMAND_IDLE_TIMEOUT);
        let defer_initial_handshake = crate::env::node_env("OVERLAY_ON_DEMAND_DEFER_INITIAL")
            .as_deref()
            .map(|s| !parse_bool_false(s))
            .unwrap_or(true);
        Self {
            enabled: true,
            idle_timeout,
            defer_initial_handshake,
        }
    }
}

fn parse_bool_true(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn parse_bool_false(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

/// Lifecycle phase of a peer's on-demand tunnel state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OnDemandPhase {
    /// On-demand is globally disabled (or disabled for this shadow/probe peer).
    Disabled = 0,
    /// Tunnel is dormant in-place: routes, carrier, and demux registrations stay
    /// installed, while periodic keepalives and handshake timers are suspended.
    Dormant = 1,
    /// Outbound business traffic triggered a wakeup; packets are queued in
    /// `Tunn` while the 148-byte Handshake Initiation is in flight.
    Waking = 2,
    /// Session is active; keepalives and rekeys run normally until
    /// `idle_timeout` elapses with no business traffic and no hold.
    Active = 3,
}

impl OnDemandPhase {
    #[inline]
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Dormant,
            2 => Self::Waking,
            3 => Self::Active,
            _ => Self::Disabled,
        }
    }
}

/// Returns `true` iff `frame` is a non-business WireGuard protocol/keepalive
/// datagram:
/// * Type 1 Handshake Initiation (148 bytes)
/// * Type 2 Handshake Response (92 bytes)
/// * Type 3 Cookie Reply (64 bytes)
/// * Type 4 Empty Transport Data = Persistent Keepalive (32 bytes: 16B header + 0B payload + 16B tag)
#[inline]
pub fn is_wg_background_frame(frame: &[u8]) -> bool {
    if frame.len() < 4 {
        return false;
    }
    let hdr = [frame[0], frame[1], frame[2], frame[3]];
    matches!(
        (hdr, frame.len()),
        (WG_TYPE_HANDSHAKE_INIT, WG_HANDSHAKE_INIT_BYTES)
            | (WG_TYPE_HANDSHAKE_RESP, WG_HANDSHAKE_RESP_BYTES)
            | (WG_TYPE_COOKIE_REPLY, WG_COOKIE_REPLY_BYTES)
            | (WG_TYPE_TRANSPORT_DATA, WG_KEEPALIVE_BYTES)
    )
}

/// Returns `true` iff `frame` is an encrypted WireGuard transport data frame
/// carrying a non-empty payload (`Type 4` and `frame.len() > 32`).
#[inline]
pub fn is_wg_transport_data_frame(frame: &[u8]) -> bool {
    frame.len() > WG_KEEPALIVE_BYTES && frame[..4] == WG_TYPE_TRANSPORT_DATA
}

/// Point-in-time snapshot of a peer's wire traffic and on-demand state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerOnDemandSnapshot {
    pub phase: OnDemandPhase,
    pub enabled: bool,
    pub held: bool,
    pub idle_timeout: Duration,
    /// Total WireGuard datagrams transmitted on the carrier (background + data).
    pub wire_tx_packets: u64,
    /// Total WireGuard bytes transmitted on the carrier (background + data).
    pub wire_tx_bytes: u64,
    /// Total authenticated WireGuard datagrams received on the carrier.
    pub wire_rx_packets: u64,
    /// Total authenticated WireGuard bytes received on the carrier.
    pub wire_rx_bytes: u64,
    /// Non-business WireGuard datagrams transmitted (Handshake Init/Resp/Cookie + 32B Keepalive).
    pub background_tx_packets: u64,
    /// Non-business WireGuard bytes transmitted.
    pub background_tx_bytes: u64,
    /// Non-business WireGuard datagrams received.
    pub background_rx_packets: u64,
    /// Non-business WireGuard bytes received.
    pub background_rx_bytes: u64,
    /// Number of transitions into `Dormant` after exceeding `idle_timeout`.
    pub dormant_transitions: u64,
    /// Number of completed wakeups (`Dormant/Waking -> Active`).
    pub wake_count: u64,
    /// Number of `Dormant -> Waking` transitions triggered by first outbound packet.
    pub outbound_wake_count: u64,
    /// Number of `Dormant -> Active` transitions triggered by inbound peer initiation/data.
    pub inbound_wake_count: u64,
    /// Number of business packets queued in `Tunn` while `Waking`.
    pub queued_on_wake_packets: u64,
    /// Number of queued business packets flushed immediately upon handshake completion.
    pub flushed_on_wake_packets: u64,
    /// Duration of the most recent `Dormant -> Waking -> Active` handshake establishment (`None` if none).
    pub last_wake_latency: Option<Duration>,
    /// Maximum `Dormant -> Waking -> Active` handshake establishment latency observed (`None` if none).
    pub max_wake_latency: Option<Duration>,
}

/// Outcome of encapsulating an outbound business packet on an on-demand peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutboundEncap {
    /// `out[..n]` contains a WireGuard frame (Type 4 transport data or Type 1
    /// Handshake Initiation) ready to transmit on the carrier.
    SendWire(usize),
    /// The packet was queued inside `boringtun::noise::Tunn::packet_queue`
    /// behind an already in-flight wakeup handshake and will be flushed by
    /// `decap_inbound` the instant the Handshake Response arrives.
    QueuedForWake,
    /// Encapsulation failed or produced nothing.
    Dropped,
}

/// Minimum grace period (`6 s`, covering one `5 s` WireGuard `REKEY_TIMEOUT`
/// plus jitter) during which an in-flight `OnDemandPhase::Waking` handshake is
/// never retired back to `Dormant`, even if `idle_timeout` is configured shorter
/// in tests.
pub const WAKING_HANDSHAKE_GRACE_NS: u64 = 6_000_000_000;

/// WireGuard `REJECT_AFTER_TIME` (`180 s`): a pre-dormancy session older than
/// this must never be used to encrypt or decrypt packets before `update_timers`
/// runs.
const WG_REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

/// Maximum duration (`90 s`, matching WireGuard `REKEY_ATTEMPT_TIME`) during
/// which a pre-dormancy timer crossing `ConnectionExpired` while `Waking` is
/// treated as a timer-epoch resync rather than a dead carrier.
pub const WAKING_CONNECTION_EXPIRED_GRACE_NS: u64 = 90_000_000_000;

/// Lock-free per-peer on-demand state and wire-traffic accounting embedded in
/// [`super::wg::PeerStats`].
pub(crate) struct PeerOnDemand {
    enabled: AtomicBool,
    phase: AtomicU8,
    idle_timeout_ns: AtomicU64,
    last_business_ns: AtomicU64,
    wake_started_ns: AtomicU64,
    last_wake_latency_ns: AtomicU64,
    max_wake_latency_ns: AtomicU64,
    dormant_transitions: AtomicU64,
    wake_count: AtomicU64,
    outbound_wake_count: AtomicU64,
    inbound_wake_count: AtomicU64,
    queued_on_wake_packets: AtomicU64,
    flushed_on_wake_packets: AtomicU64,
    /// Additional packets queued via `TunnResult::Done` while a wake handshake
    /// was already in flight (or whose initial `HandshakeInit` carrier send
    /// failed), so `decap_inbound` can credit `PeerStats::tx` when they are
    /// flushed to the wire.
    pending_flushed_tx_credit: AtomicU64,
    external_hold: AtomicBool,
    /// Set when the peer transitions out of `Dormant` via a hold or runtime
    /// config change (`set_external_hold`, `note_hold_active`, `configure`),
    /// consumed under the `Tunn` lock so `boringtun`'s internal `TimeCurrent`
    /// and expired sessions are synchronized before the next `encapsulate` or
    /// `update_timers`.
    needs_timer_sync: AtomicBool,
    /// Sticky flag set whenever the peer starts in or enters `Dormant`;
    /// consumed by `OverlayRuntime::sweep_carrier_health` so a peer that
    /// transitions `Dormant -> Waking -> Active` between two 5s sweeps still
    /// gets its `since` / `last_rx_at` liveness clocks refreshed.
    dormant_since_last_sweep: AtomicBool,
    wire_tx_packets: AtomicU64,
    wire_tx_bytes: AtomicU64,
    wire_rx_packets: AtomicU64,
    wire_rx_bytes: AtomicU64,
    background_tx_packets: AtomicU64,
    background_tx_bytes: AtomicU64,
    background_rx_packets: AtomicU64,
    background_rx_bytes: AtomicU64,
    /// Static keypair and peer identity `(local_secret, peer_public, index)`
    /// used to reconstruct `Tunn::new` in-place under the `Tunn` lock on
    /// `Dormant` transitions and wakeups, resetting `boringtun`'s internal
    /// `Timers` (`time_started = Instant::now()`), `HandshakeState::None`,
    /// `sessions`, and `packet_queue` while preserving the peer's 24-bit index
    /// in `PlaneHandle` and `DirectDemux`.
    static_keys: Mutex<Option<(StaticSecret, PublicKey)>>,
    peer_identity: Mutex<Option<(StaticSecret, PublicKey, u32)>>,
    /// Bounded shadow copy of outbound business packets queued while `Waking`
    /// (up to [`BORINGTUN_QUEUE_PACKET_CAP`]), used to re-queue packets with
    /// zero loss if `boringtun::Tunn::update_timers` resets its internal timer
    /// epoch (`clear_all`) during an in-flight wakeup.
    wake_queue: Mutex<Vec<Vec<u8>>>,
}

impl Default for PeerOnDemand {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            phase: AtomicU8::new(OnDemandPhase::Disabled as u8),
            idle_timeout_ns: AtomicU64::new(DEFAULT_ON_DEMAND_IDLE_TIMEOUT.as_nanos() as u64),
            last_business_ns: AtomicU64::new(0),
            wake_started_ns: AtomicU64::new(0),
            last_wake_latency_ns: AtomicU64::new(0),
            max_wake_latency_ns: AtomicU64::new(0),
            dormant_transitions: AtomicU64::new(0),
            wake_count: AtomicU64::new(0),
            outbound_wake_count: AtomicU64::new(0),
            inbound_wake_count: AtomicU64::new(0),
            queued_on_wake_packets: AtomicU64::new(0),
            flushed_on_wake_packets: AtomicU64::new(0),
            pending_flushed_tx_credit: AtomicU64::new(0),
            external_hold: AtomicBool::new(false),
            needs_timer_sync: AtomicBool::new(false),
            dormant_since_last_sweep: AtomicBool::new(false),
            wire_tx_packets: AtomicU64::new(0),
            wire_tx_bytes: AtomicU64::new(0),
            wire_rx_packets: AtomicU64::new(0),
            wire_rx_bytes: AtomicU64::new(0),
            background_tx_packets: AtomicU64::new(0),
            background_tx_bytes: AtomicU64::new(0),
            background_rx_packets: AtomicU64::new(0),
            background_rx_bytes: AtomicU64::new(0),
            static_keys: Mutex::new(None),
            peer_identity: Mutex::new(None),
            wake_queue: Mutex::new(Vec::new()),
        }
    }
}

impl PeerOnDemand {
    /// Record the peer's immutable cryptographic identity and 24-bit session
    /// index at `Peer` construction time (`make_carrier_peer` /
    /// `make_direct_peer`).
    pub(crate) fn set_peer_identity(
        &self,
        secret: StaticSecret,
        peer_public: [u8; 32],
        index: u32,
    ) {
        *self
            .peer_identity
            .lock()
            .unwrap_or_else(|e| e.into_inner()) =
            Some((secret, PublicKey::from(peer_public), index));
    }

    /// Reset `t` in-place under its `Mutex<Tunn>` lock, clearing all expired
    /// sessions, queued packets, `HandshakeState::InitSent` / `Expired` states,
    /// and resetting `boringtun`'s internal `Timers::time_started` to
    /// `Instant::now()` while preserving the peer's 24-bit `index` (so all
    /// `PlaneHandle`, `DirectDemux`, `SendPeer`, and `Carrier` registrations
    /// remain valid in place).
    pub(crate) fn reset_tunn_under_lock(&self, t: &mut Tunn) {
        if let Some((secret, peer_public, index)) = self
            .peer_identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            *t = Tunn::new(
                secret,
                peer_public,
                None,
                Some(super::wg::KEEPALIVE_SECS),
                index,
                None,
            );
        } else if let Some((secret, public)) = self
            .static_keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            t.set_static_private(secret, public, None);
        }
    }

    /// Synchronize `t`'s timers and evict any session older than
    /// `REJECT_AFTER_TIME` (`180 s`) if the peer exited `Dormant` via a hold
    /// or runtime config change.
    pub(crate) fn sync_tunn_if_needed_under_lock(&self, t: &mut Tunn) {
        if !self.needs_timer_sync.swap(false, Ordering::AcqRel) {
            return;
        }
        if t.time_since_last_handshake()
            .is_none_or(|d| d >= WG_REJECT_AFTER_TIME)
        {
            self.reset_tunn_under_lock(t);
        } else {
            let mut scratch = [0u8; WG_HANDSHAKE_INIT_BYTES + 32];
            if matches!(
                t.update_timers(&mut scratch),
                TunnResult::Err(boringtun::noise::errors::WireGuardError::ConnectionExpired)
            ) {
                self.reset_tunn_under_lock(t);
            }
        }
    }

    /// Synchronize `t` before processing an inbound packet while `Dormant`.
    ///
    /// * If no valid (`< 180 s`) session exists and `is_handshake_init` is
    ///   `true` (or an expired `>= 180 s` session is still in `t`), resets `t`
    ///   via [`Self::reset_tunn_under_lock`] so `timers.time_started` is
    ///   `Instant::now()` and `handshake.state` is `HandshakeState::None`.
    /// * Otherwise (a valid `< 180 s` session exists), advances `TimeCurrent`
    ///   via `t.update_timers` while keeping the valid session intact.
    pub(crate) fn prepare_inbound_while_dormant_under_lock(
        &self,
        t: &mut Tunn,
        is_handshake_init: bool,
    ) {
        if !self.is_dormant() {
            return;
        }
        let has_fresh_session = t
            .time_since_last_handshake()
            .is_some_and(|d| d < WG_REJECT_AFTER_TIME);
        if has_fresh_session {
            let mut scratch = [0u8; WG_HANDSHAKE_INIT_BYTES + 32];
            if matches!(
                t.update_timers(&mut scratch),
                TunnResult::Err(boringtun::noise::errors::WireGuardError::ConnectionExpired)
            ) {
                self.reset_tunn_under_lock(t);
            }
        } else if is_handshake_init || t.time_since_last_handshake().is_some() {
            self.reset_tunn_under_lock(t);
        }
    }

    /// Configure on-demand state for an installed peer. Returns `true` if the
    /// initial handshake on `add_peer` / `add_direct_peer` should be deferred
    /// (because the peer starts in [`OnDemandPhase::Dormant`]).
    pub(crate) fn configure(
        &self,
        cfg: OnDemandConfig,
        secret: StaticSecret,
        held: bool,
        now_ns: u64,
    ) -> bool {
        let public = PublicKey::from(&secret);
        *self.static_keys.lock().unwrap_or_else(|e| e.into_inner()) = Some((secret, public));
        self.external_hold.store(held, Ordering::Relaxed);
        let timeout_ns = (cfg.idle_timeout.as_nanos() as u64)
            .max(MIN_ON_DEMAND_IDLE_TIMEOUT.as_nanos() as u64);
        self.idle_timeout_ns.store(timeout_ns, Ordering::Relaxed);
        self.last_business_ns
            .store(now_ns.max(1), Ordering::Relaxed);
        self.wake_started_ns.store(0, Ordering::Relaxed);
        let was_dormant = self.phase() == OnDemandPhase::Dormant;
        if !cfg.enabled {
            self.enabled.store(false, Ordering::Relaxed);
            self.phase
                .store(OnDemandPhase::Disabled as u8, Ordering::Release);
            if was_dormant {
                self.needs_timer_sync.store(true, Ordering::Release);
            }
            return false;
        }
        self.enabled.store(true, Ordering::Relaxed);
        if cfg.defer_initial_handshake && !held {
            self.phase
                .store(OnDemandPhase::Dormant as u8, Ordering::Release);
            self.dormant_since_last_sweep.store(true, Ordering::Release);
            true
        } else {
            self.phase
                .store(OnDemandPhase::Active as u8, Ordering::Release);
            if was_dormant {
                self.needs_timer_sync.store(true, Ordering::Release);
            }
            false
        }
    }

    #[inline]
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    #[inline]
    pub(crate) fn phase(&self) -> OnDemandPhase {
        OnDemandPhase::from_u8(self.phase.load(Ordering::Acquire))
    }

    #[inline]
    pub(crate) fn is_dormant(&self) -> bool {
        self.phase() == OnDemandPhase::Dormant
    }

    #[inline]
    pub(crate) fn is_waking(&self) -> bool {
        self.phase() == OnDemandPhase::Waking
    }

    #[inline]
    pub(crate) fn is_dormant_or_waking(&self) -> bool {
        matches!(self.phase(), OnDemandPhase::Dormant | OnDemandPhase::Waking)
    }

    #[inline]
    pub(crate) fn take_dormant_since_last_sweep(&self) -> bool {
        self.dormant_since_last_sweep.swap(false, Ordering::AcqRel)
    }

    #[inline]
    pub(crate) fn waking_elapsed_ns(&self, now_ns: u64) -> u64 {
        let started = self.wake_started_ns.load(Ordering::Acquire);
        if started == 0 {
            0
        } else {
            now_ns.saturating_sub(started)
        }
    }

    #[inline]
    pub(crate) fn has_external_hold(&self) -> bool {
        self.external_hold.load(Ordering::Relaxed)
    }

    /// Update the external-hold flag (set when a direct probe, bilateral path
    /// trial, ORG relay upgrade, or unsettled DERP follow state exists for
    /// this peer). If a hold becomes active while `Dormant`, transitions the
    /// peer out of `Dormant` and refreshes its activity timestamp.
    pub(crate) fn set_external_hold(&self, held: bool, now_ns: u64) {
        self.external_hold.store(held, Ordering::Relaxed);
        if held {
            self.last_business_ns
                .store(now_ns.max(1), Ordering::Release);
            if self
                .phase
                .compare_exchange(
                    OnDemandPhase::Dormant as u8,
                    OnDemandPhase::Active as u8,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                self.needs_timer_sync.store(true, Ordering::Release);
            }
        }
    }

    /// Refresh business activity timestamp while a local hold (`StandbyTee` or
    /// `recovery_hold`) is armed.
    pub(crate) fn note_hold_active(&self, now_ns: u64) {
        self.last_business_ns
            .store(now_ns.max(1), Ordering::Release);
        if self
            .phase
            .compare_exchange(
                OnDemandPhase::Dormant as u8,
                OnDemandPhase::Active as u8,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            self.needs_timer_sync.store(true, Ordering::Release);
        }
    }

    /// Record one WireGuard frame transmitted on the carrier.
    #[inline]
    pub(crate) fn record_wire_tx(&self, frame: &[u8]) {
        let len = frame.len() as u64;
        self.wire_tx_packets.fetch_add(1, Ordering::Relaxed);
        self.wire_tx_bytes.fetch_add(len, Ordering::Relaxed);
        if is_wg_background_frame(frame) {
            self.background_tx_packets.fetch_add(1, Ordering::Relaxed);
            self.background_tx_bytes.fetch_add(len, Ordering::Relaxed);
        }
    }

    /// Record a GSO batch of WireGuard transport data frames transmitted on a
    /// direct socket.
    #[inline]
    pub(crate) fn record_wire_tx_data_batch(&self, packets: u64, bytes: u64) {
        self.wire_tx_packets.fetch_add(packets, Ordering::Relaxed);
        self.wire_tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record one authenticated WireGuard frame received on the carrier.
    #[inline]
    pub(crate) fn record_wire_rx(&self, frame: &[u8]) {
        let len = frame.len() as u64;
        self.wire_rx_packets.fetch_add(1, Ordering::Relaxed);
        self.wire_rx_bytes.fetch_add(len, Ordering::Relaxed);
        if is_wg_background_frame(frame) {
            self.background_rx_packets.fetch_add(1, Ordering::Relaxed);
            self.background_rx_bytes.fetch_add(len, Ordering::Relaxed);
        }
    }

    /// Called under the peer's `Tunn` lock right before encapsulating one or
    /// more outbound business IP packets.
    ///
    /// If the peer was [`OnDemandPhase::Dormant`], transitions it to
    /// [`OnDemandPhase::Waking`], records `wake_started_ns`, clears any stale
    /// `Tunn` sessions via `Tunn::set_static_private` (preserving `next_index`
    /// and TAI64N replay state), refreshes `boringtun`'s internal `TimeCurrent`
    /// timer, and returns `true` so the caller forces a fresh Handshake
    /// Initiation if needed.
    pub(crate) fn prepare_outbound_under_lock(&self, t: &mut Tunn, now_ns: u64) -> bool {
        let stamp = now_ns.max(1);
        self.last_business_ns.store(stamp, Ordering::Release);
        self.sync_tunn_if_needed_under_lock(t);
        if !self.is_enabled() {
            return false;
        }
        if self
            .phase
            .compare_exchange(
                OnDemandPhase::Dormant as u8,
                OnDemandPhase::Waking as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.needs_timer_sync.store(false, Ordering::Release);
            self.wake_started_ns.store(stamp, Ordering::Release);
            self.outbound_wake_count.fetch_add(1, Ordering::Relaxed);
            self.pending_flushed_tx_credit.store(0, Ordering::Release);
            self.wake_queue
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            self.reset_tunn_under_lock(t);
            return true;
        }
        false
    }

    fn push_wake_shadow_packet(&self, packet: &[u8]) {
        if packet.is_empty() {
            return;
        }
        let mut q = self.wake_queue.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() < BORINGTUN_QUEUE_PACKET_CAP {
            q.push(packet.to_vec());
        }
    }

    /// If the initial wakeup `HandshakeInit` carrier send failed (`Err`),
    /// record a pending TX credit for the business packet queued inside `Tunn`
    /// so when the timer task later retransmits `HandshakeInit` and flushes the
    /// packet in `decap_inbound`, `PeerStats::tx` is still credited.
    pub(crate) fn note_wake_init_send_failed(&self) {
        self.pending_flushed_tx_credit
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Re-queue buffered wake packets and emit a fresh `HandshakeInit` after
    /// `boringtun::Tunn::update_timers` returned `ConnectionExpired` (which
    /// called `clear_all()`, resetting all internal timers to `now` and
    /// clearing `t.packet_queue`) during an in-flight wakeup.
    pub(crate) fn requeue_wake_packets_after_timer_reset(
        &self,
        t: &mut Tunn,
        out: &mut [u8],
    ) -> Option<Vec<u8>> {
        let packets = self
            .wake_queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let base = out.as_ptr() as usize;
        let mut init_wire = None;
        for pkt in &packets {
            if let TunnResult::WriteToNetwork(b) = t.encapsulate(pkt, out)
                && init_wire.is_none()
            {
                let (off, n) = (b.as_ptr() as usize - base, b.len());
                init_wire = Some(out[off..off + n].to_vec());
            }
        }
        if init_wire.is_none()
            && let TunnResult::WriteToNetwork(b) = t.format_handshake_initiation(out, true)
        {
            let (off, n) = (b.as_ptr() as usize - base, b.len());
            init_wire = Some(out[off..off + n].to_vec());
        }
        init_wire
    }

    /// Encapsulate a single outbound IP packet under the `Tunn` lock, handling
    /// `Dormant -> Waking` initiation and packet queuing without loss.
    pub(crate) fn encapsulate_for_send(
        &self,
        t: &mut Tunn,
        packet: &[u8],
        out: &mut [u8],
        just_woke: bool,
    ) -> OutboundEncap {
        let base = out.as_ptr() as usize;
        match t.encapsulate(packet, out) {
            TunnResult::WriteToNetwork(b) => {
                let (off, n) = (b.as_ptr() as usize - base, b.len());
                if off != 0 {
                    out.copy_within(off..off + n, 0);
                }
                if out[0] == WG_TYPE_HANDSHAKE_INIT[0]
                    && self.is_enabled()
                    && (just_woke || self.is_waking())
                {
                    self.queued_on_wake_packets.fetch_add(1, Ordering::Relaxed);
                    self.push_wake_shadow_packet(packet);
                }
                OutboundEncap::SendWire(n)
            }
            TunnResult::Done => {
                // `boringtun::Tunn::encapsulate` returns `Done` only when there
                // is no current session, `packet` was pushed onto
                // `t.packet_queue`, and `t.handshake.is_in_progress()` was
                // already true.
                if just_woke {
                    // `refresh_tunn_timers_for_wake` (or a prior unanswered
                    // wake) left `handshake.is_in_progress()` set; emit a fresh
                    // initiation now while keeping `packet` at the head of
                    // `packet_queue`.
                    if let TunnResult::WriteToNetwork(b) = t.format_handshake_initiation(out, true)
                    {
                        let (off, n) = (b.as_ptr() as usize - base, b.len());
                        if off != 0 {
                            out.copy_within(off..off + n, 0);
                        }
                        self.queued_on_wake_packets.fetch_add(1, Ordering::Relaxed);
                        self.push_wake_shadow_packet(packet);
                        return OutboundEncap::SendWire(n);
                    }
                }
                if self.is_enabled() && self.is_waking() {
                    let queued_len = {
                        let mut q = self.wake_queue.lock().unwrap_or_else(|e| e.into_inner());
                        if q.len() < 256 {
                            q.push(packet.to_vec());
                            Some(q.len())
                        } else {
                            None
                        }
                    };
                    if queued_len.is_some() {
                        self.queued_on_wake_packets.fetch_add(1, Ordering::Relaxed);
                        self.pending_flushed_tx_credit
                            .fetch_add(1, Ordering::Relaxed);
                        OutboundEncap::QueuedForWake
                    } else {
                        OutboundEncap::Dropped
                    }
                } else {
                    OutboundEncap::Dropped
                }
            }
            TunnResult::Err(_) => OutboundEncap::Dropped,
            _ => OutboundEncap::Dropped,
        }
    }

    /// Called under the `Tunn` lock in `decap_inbound` when an authenticated
    /// Type 1 Handshake Initiation arrives from the peer.
    ///
    /// * If `Dormant`, transitions `Dormant -> Active`, refreshes
    ///   `last_business_ns`, and counts an inbound wake.
    /// * If `Waking` (simultaneous wake), keeps the peer in `Waking` (so
    ///   queued outbound packets remain tracked until flushed) and refreshes
    ///   `last_business_ns`.
    /// * If already `Active`, does **not** overwrite `last_business_ns` so
    ///   periodic background rekeys or 30s silence pokes never prevent idle
    ///   transition to `Dormant`.
    pub(crate) fn on_inbound_handshake_init(&self, now_ns: u64) {
        if !self.is_enabled() {
            return;
        }
        let stamp = now_ns.max(1);
        match self.phase.compare_exchange(
            OnDemandPhase::Dormant as u8,
            OnDemandPhase::Active as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                self.needs_timer_sync.store(false, Ordering::Release);
                self.last_business_ns.store(stamp, Ordering::Release);
                self.inbound_wake_count.fetch_add(1, Ordering::Relaxed);
                self.wake_count.fetch_add(1, Ordering::Relaxed);
                self.wake_started_ns.store(0, Ordering::Release);
            }
            Err(cur) if cur == OnDemandPhase::Waking as u8 => {
                self.last_business_ns.store(stamp, Ordering::Release);
            }
            _ => {}
        }
    }

    /// Called under the `Tunn` lock in `decap_inbound` when an authenticated
    /// Type 2 Handshake Response (or simultaneous-wake responder session
    /// activation) completes a handshake and flushes `flushed_data_packets`
    /// queued business IP packets.
    ///
    /// Returns how many additional `PeerStats::tx` credits should be added for
    /// packets that were queued with `TunnResult::Done` while `Waking`.
    pub(crate) fn on_inbound_handshake_response(
        &self,
        now_ns: u64,
        flushed_data_packets: u64,
    ) -> u64 {
        let mut consumed = 0u64;
        if flushed_data_packets > 0 {
            let _ = self.pending_flushed_tx_credit.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |pending| {
                    consumed = pending.min(flushed_data_packets);
                    Some(pending - consumed)
                },
            );
        }
        if !self.is_enabled() {
            return consumed;
        }
        let stamp = now_ns.max(1);
        if flushed_data_packets > 0 {
            self.flushed_on_wake_packets
                .fetch_add(flushed_data_packets, Ordering::Relaxed);
        }
        let prev = self
            .phase
            .swap(OnDemandPhase::Active as u8, Ordering::AcqRel);
        if prev == OnDemandPhase::Waking as u8
            || prev == OnDemandPhase::Dormant as u8
            || flushed_data_packets > 0
        {
            self.last_business_ns.store(stamp, Ordering::Release);
        }
        if prev == OnDemandPhase::Waking as u8 || prev == OnDemandPhase::Dormant as u8 {
            self.needs_timer_sync.store(false, Ordering::Release);
            self.pending_flushed_tx_credit.store(0, Ordering::Release);
            self.wake_queue
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            let started = self.wake_started_ns.swap(0, Ordering::AcqRel);
            if started != 0 {
                let lat = stamp.saturating_sub(started).max(1);
                self.last_wake_latency_ns.store(lat, Ordering::Relaxed);
                self.max_wake_latency_ns.fetch_max(lat, Ordering::Relaxed);
            }
            self.wake_count.fetch_add(1, Ordering::Relaxed);
        }
        consumed
    }

    /// Called under the `Tunn` lock in `decap_inbound` when a decrypted
    /// business IP packet (`WriteToTunnelV4` / `WriteToTunnelV6`) passes
    /// ingress checks.
    pub(crate) fn on_inbound_business_packet(&self, now_ns: u64) {
        let stamp = now_ns.max(1);
        self.last_business_ns.store(stamp, Ordering::Release);
        if !self.is_enabled() {
            return;
        }
        let prev = self
            .phase
            .swap(OnDemandPhase::Active as u8, Ordering::AcqRel);
        if prev == OnDemandPhase::Dormant as u8 {
            self.needs_timer_sync.store(false, Ordering::Release);
            self.inbound_wake_count.fetch_add(1, Ordering::Relaxed);
            self.wake_count.fetch_add(1, Ordering::Relaxed);
            self.wake_started_ns.store(0, Ordering::Release);
        } else if prev == OnDemandPhase::Waking as u8 {
            self.pending_flushed_tx_credit.store(0, Ordering::Release);
            self.wake_queue
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            let started = self.wake_started_ns.swap(0, Ordering::AcqRel);
            if started != 0 {
                let lat = stamp.saturating_sub(started).max(1);
                self.last_wake_latency_ns.store(lat, Ordering::Relaxed);
                self.max_wake_latency_ns.fetch_max(lat, Ordering::Relaxed);
            }
            self.wake_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Fast lock-free pre-check before acquiring the `Tunn` lock on the timer
    /// path: returns `true` if the peer is currently `Active` or `Waking`, has
    /// no hold, and its idle duration has reached `idle_timeout_ns` (or at
    /// least [`WAKING_HANDSHAKE_GRACE_NS`] while `Waking`).
    #[inline]
    pub(crate) fn is_idle_candidate(&self, local_hold: bool, now_ns: u64) -> bool {
        if !self.is_enabled() || local_hold || self.has_external_hold() {
            return false;
        }
        let phase = self.phase();
        let timeout = match phase {
            OnDemandPhase::Active => self.idle_timeout_ns.load(Ordering::Relaxed),
            OnDemandPhase::Waking => self
                .idle_timeout_ns
                .load(Ordering::Relaxed)
                .max(WAKING_HANDSHAKE_GRACE_NS),
            _ => return false,
        };
        let last = self.last_business_ns.load(Ordering::Acquire);
        last != 0 && now_ns.saturating_sub(last) >= timeout
    }

    /// Authoritative idle retirement executed under the peer's `Tunn` lock so
    /// it can never race with concurrent `prepare_outbound_under_lock` or
    /// `decap_inbound`.
    pub(crate) fn try_enter_dormant_under_lock(
        &self,
        local_hold: bool,
        t: &mut Tunn,
        now_ns: u64,
    ) -> bool {
        if !self.is_idle_candidate(local_hold, now_ns) {
            return false;
        }
        let cur = self.phase.load(Ordering::Acquire);
        if cur != OnDemandPhase::Active as u8 && cur != OnDemandPhase::Waking as u8 {
            return false;
        }
        if self
            .phase
            .compare_exchange(
                cur,
                OnDemandPhase::Dormant as u8,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            self.reset_tunn_under_lock(t);
            self.pending_flushed_tx_credit.store(0, Ordering::Release);
            self.wake_queue
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear();
            self.wake_started_ns.store(0, Ordering::Release);
            self.needs_timer_sync.store(true, Ordering::Release);
            self.dormant_since_last_sweep.store(true, Ordering::Release);
            self.dormant_transitions.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        false
    }

    /// Snapshot all on-demand and wire-traffic counters for this peer.
    pub(crate) fn snapshot(&self, local_hold: bool) -> PeerOnDemandSnapshot {
        let last_lat = self.last_wake_latency_ns.load(Ordering::Relaxed);
        let max_lat = self.max_wake_latency_ns.load(Ordering::Relaxed);
        PeerOnDemandSnapshot {
            phase: self.phase(),
            enabled: self.is_enabled(),
            held: local_hold || self.has_external_hold(),
            idle_timeout: Duration::from_nanos(self.idle_timeout_ns.load(Ordering::Relaxed)),
            wire_tx_packets: self.wire_tx_packets.load(Ordering::Relaxed),
            wire_tx_bytes: self.wire_tx_bytes.load(Ordering::Relaxed),
            wire_rx_packets: self.wire_rx_packets.load(Ordering::Relaxed),
            wire_rx_bytes: self.wire_rx_bytes.load(Ordering::Relaxed),
            background_tx_packets: self.background_tx_packets.load(Ordering::Relaxed),
            background_tx_bytes: self.background_tx_bytes.load(Ordering::Relaxed),
            background_rx_packets: self.background_rx_packets.load(Ordering::Relaxed),
            background_rx_bytes: self.background_rx_bytes.load(Ordering::Relaxed),
            dormant_transitions: self.dormant_transitions.load(Ordering::Relaxed),
            wake_count: self.wake_count.load(Ordering::Relaxed),
            outbound_wake_count: self.outbound_wake_count.load(Ordering::Relaxed),
            inbound_wake_count: self.inbound_wake_count.load(Ordering::Relaxed),
            queued_on_wake_packets: self.queued_on_wake_packets.load(Ordering::Relaxed),
            flushed_on_wake_packets: self.flushed_on_wake_packets.load(Ordering::Relaxed),
            last_wake_latency: (last_lat != 0).then(|| Duration::from_nanos(last_lat)),
            max_wake_latency: (max_lat != 0).then(|| Duration::from_nanos(max_lat)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_frame_classifier_distinguishes_control_and_keepalive_from_data() {
        let mut init = vec![0u8; WG_HANDSHAKE_INIT_BYTES];
        init[..4].copy_from_slice(&WG_TYPE_HANDSHAKE_INIT);
        assert!(is_wg_background_frame(&init));
        assert!(!is_wg_transport_data_frame(&init));

        let mut resp = vec![0u8; WG_HANDSHAKE_RESP_BYTES];
        resp[..4].copy_from_slice(&WG_TYPE_HANDSHAKE_RESP);
        assert!(is_wg_background_frame(&resp));
        assert!(!is_wg_transport_data_frame(&resp));

        let mut cookie = vec![0u8; WG_COOKIE_REPLY_BYTES];
        cookie[..4].copy_from_slice(&WG_TYPE_COOKIE_REPLY);
        assert!(is_wg_background_frame(&cookie));
        assert!(!is_wg_transport_data_frame(&cookie));

        let mut keepalive = vec![0u8; WG_KEEPALIVE_BYTES];
        keepalive[..4].copy_from_slice(&WG_TYPE_TRANSPORT_DATA);
        assert!(is_wg_background_frame(&keepalive));
        assert!(!is_wg_transport_data_frame(&keepalive));

        let mut data = vec![0u8; WG_KEEPALIVE_BYTES + 20];
        data[..4].copy_from_slice(&WG_TYPE_TRANSPORT_DATA);
        assert!(!is_wg_background_frame(&data));
        assert!(is_wg_transport_data_frame(&data));
    }

    #[test]
    fn config_clamps_minimum_idle_timeout_and_defaults_to_disabled() {
        let off = OnDemandConfig::default();
        assert!(!off.enabled);
        assert!(!off.defer_initial_handshake);

        let on = OnDemandConfig::enabled(Duration::from_millis(1));
        assert!(on.enabled);
        assert!(on.defer_initial_handshake);
        assert_eq!(on.idle_timeout, MIN_ON_DEMAND_IDLE_TIMEOUT);
    }
}
