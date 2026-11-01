// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! B8 — Multi-path & link aggregation data-plane foundation for the userspace
//! WireGuard overlay.
//!
//! Operates at the encrypted WireGuard Type-4 transport frame layer while
//! sharing a single per-peer [`boringtun::noise::Tunn`] cryptographic session.
//!
//! By default every peer starts in [`MultipathMode::Off`] with zero secondary
//! legs (`is_active() == false`), adding zero atomic writes, zero clock reads,
//! zero locks, and zero background tasks to the single-path hot path. Multipath
//! scheduling and receiver reassembly activate only when a non-`Off` mode is
//! explicitly configured **and** at least one healthy, live secondary leg is
//! attached:
//!
//! 1. [`MultipathMode::Off`] — single primary carrier, zero hot-path overhead.
//! 2. [`MultipathMode::ActiveStandby`] — primary/standby fast failover: sends
//!    on the primary carrier while healthy and alive, and switches in `O(1)` on
//!    the very next packet to the highest-priority healthy secondary leg when
//!    the primary carrier dies or is marked unhealthy, without resetting the
//!    WireGuard session or re-handshaking.
//! 3. [`MultipathMode::Redundant`] — `1+1` (or `1+N`) duplicate send for
//!    jitter/loss reduction: each encapsulated WireGuard datagram is
//!    transmitted over both the primary leg and the best healthy secondary
//!    leg(s). On the receiver, the first copy to authenticate via
//!    `Tunn::decapsulate` records its `(session, counter, len, poly1305_tag)`
//!    in a bounded [`MultipathDedupTable`]. When the slower leg's copy arrives,
//!    [`PeerMultipathState::pre_decap_check`] verifies the 16-byte Poly1305
//!    authentication tag in constant time before `boringtun`'s replay window
//!    would reject it, dropping the duplicate cleanly while crediting the
//!    slower leg's receive health at most once per leg (preventing replay
//!    liveness spoofing).
//! 4. [`MultipathMode::Aggregate`] — weighted round-robin bandwidth aggregation
//!    across all healthy legs paired with a bounded, counter-ordered receiver
//!    [`MultipathReorderBuffer`] that restores strict ascending WireGuard
//!    `counter` delivery order across asymmetric-RTT paths and flushes parked
//!    packets after `reorder_hold_timeout` when a packet is genuinely lost.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::wg::{Carrier, mono_ms_now};

/// Maximum number of secondary multipath legs per peer (in addition to the
/// primary carrier at `leg_id = 0`).
pub const MAX_MULTIPATH_LEGS: usize = 4;

/// Maximum number of simultaneous transmit targets (`1` primary +
/// [`MAX_MULTIPATH_LEGS`] secondaries).
pub const MAX_TX_TARGETS: usize = MAX_MULTIPATH_LEGS + 1;

/// Default maximum number of out-of-order packets held per peer in
/// [`MultipathMode::Aggregate`] before the oldest counter is force-flushed.
pub const DEFAULT_MAX_REORDER_DEPTH: usize = 64;

/// Default maximum hold time for an out-of-order packet waiting on a missing
/// earlier counter in [`MultipathMode::Aggregate`].
pub const DEFAULT_REORDER_HOLD_TIMEOUT: Duration = Duration::from_millis(25);

/// Default sliding deduplication table capacity per peer in
/// [`MultipathMode::Redundant`].
pub const DEFAULT_DEDUP_WINDOW_SIZE: usize = 512;

/// Minimum WireGuard Type-4 transport packet length:
/// `4B type + 4B receiver_idx + 8B counter + 16B Poly1305 tag = 32B`.
pub const WG_TYPE4_MIN_LEN: usize = 32;

/// Operating mode for B8 per-peer multipath / link aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum MultipathMode {
    /// Standard single-carrier transmission (default).
    #[default]
    Off = 0,
    /// Primary/standby fast failover: uses primary leg when healthy, otherwise
    /// fails over immediately to the highest-priority healthy secondary leg.
    ActiveStandby = 1,
    /// Duplicate send (`1+1` / `1+N`) across primary and healthy secondary
    /// leg(s) with cryptographic receiver-side deduplication.
    Redundant = 2,
    /// Weighted round-robin packet striping across all healthy legs with
    /// receiver-side counter-ordered reassembly buffer.
    Aggregate = 3,
}

impl MultipathMode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::ActiveStandby,
            2 => Self::Redundant,
            3 => Self::Aggregate,
            _ => Self::Off,
        }
    }

    pub fn parse_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "0" | "off" | "disabled" | "none" | "single" => Some(Self::Off),
            "1" | "active-standby" | "active_standby" | "standby" | "failover" => {
                Some(Self::ActiveStandby)
            }
            "2" | "redundant" | "duplicate" | "dup" | "1+1" => Some(Self::Redundant),
            "3" | "aggregate" | "bond" | "bonding" | "ecmp" | "wrr" => Some(Self::Aggregate),
            _ => None,
        }
    }
}

/// Configuration for a peer's multipath scheduler, deduplicator, and reorder
/// buffer.
#[derive(Debug, Clone)]
pub struct MultipathConfig {
    pub mode: MultipathMode,
    pub primary_weight: u16,
    pub max_redundant_secondary_legs: usize,
    pub max_reorder_depth: usize,
    pub reorder_hold_timeout: Duration,
    pub dedup_window_size: usize,
}

impl Default for MultipathConfig {
    fn default() -> Self {
        Self {
            mode: MultipathMode::Off,
            primary_weight: 1,
            max_redundant_secondary_legs: 1,
            max_reorder_depth: DEFAULT_MAX_REORDER_DEPTH,
            reorder_hold_timeout: DEFAULT_REORDER_HOLD_TIMEOUT,
            dedup_window_size: DEFAULT_DEDUP_WINDOW_SIZE,
        }
    }
}

impl MultipathConfig {
    pub fn new(mode: MultipathMode) -> Self {
        Self {
            mode,
            ..Self::default()
        }
    }

    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(raw) = std::env::var("OVERLAY_MULTIPATH_MODE")
            && let Some(mode) = MultipathMode::parse_str(&raw)
        {
            cfg.mode = mode;
        }
        if let Ok(raw) = std::env::var("OVERLAY_MULTIPATH_PRIMARY_WEIGHT")
            && let Ok(w) = raw.trim().parse::<u16>()
        {
            cfg.primary_weight = w.clamp(1, 256);
        }
        if let Ok(raw) = std::env::var("OVERLAY_MULTIPATH_MAX_REORDER_DEPTH")
            && let Ok(d) = raw.trim().parse::<usize>()
        {
            cfg.max_reorder_depth = d.clamp(1, 512);
        }
        if let Ok(raw) = std::env::var("OVERLAY_MULTIPATH_REORDER_HOLD_MS")
            && let Ok(ms) = raw.trim().parse::<u64>()
        {
            cfg.reorder_hold_timeout = Duration::from_millis(ms.clamp(1, 500));
        }
        cfg
    }

    pub fn with_primary_weight(mut self, weight: u16) -> Self {
        self.primary_weight = weight.clamp(1, 256);
        self
    }

    pub fn with_max_redundant_secondary_legs(mut self, count: usize) -> Self {
        self.max_redundant_secondary_legs = count.clamp(1, MAX_MULTIPATH_LEGS);
        self
    }

    pub fn with_max_reorder_depth(mut self, depth: usize) -> Self {
        self.max_reorder_depth = depth.clamp(1, 512);
        self
    }

    pub fn with_reorder_hold_timeout(mut self, timeout: Duration) -> Self {
        self.reorder_hold_timeout =
            timeout.clamp(Duration::from_millis(1), Duration::from_millis(500));
        self
    }

    pub fn with_dedup_window_size(mut self, size: usize) -> Self {
        self.dedup_window_size = size.clamp(32, 2048);
        self
    }
}

/// Telemetry and status snapshot for a single multipath leg (`leg_id == 0` for
/// the primary carrier, `leg_id > 0` for secondary legs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipathLegSnapshot {
    pub leg_id: u32,
    pub priority: u8,
    pub weight: u16,
    pub healthy: bool,
    pub carrier_dead: bool,
    pub effective_up: bool,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_errors: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_dedup_hits: u64,
    pub last_tx_ms: u64,
    pub last_rx_ms: u64,
    pub rtt_ewma_us: u64,
}

/// Telemetry and status snapshot for a peer's overall multipath state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipathPeerSnapshot {
    pub mode: MultipathMode,
    pub active_tx_leg_id: u32,
    pub failover_switches: u64,
    pub redundant_extra_tx_packets: u64,
    pub dedup_dropped: u64,
    pub reorder_buffered: u64,
    pub reorder_in_order_delivered: u64,
    pub reorder_reordered_delivered: u64,
    pub reorder_timeout_flushed: u64,
    pub reorder_capacity_flushed: u64,
    pub reorder_late_delivered: u64,
    pub reorder_current_depth: usize,
    pub legs: Vec<MultipathLegSnapshot>,
}

/// Lock-free atomic counters for a single leg (primary or secondary).
///
/// TX and RX atomic counters are separated across 64-byte cache-line boundaries
/// so concurrent outbound pump and inbound receive tasks never bounce the same
/// cache line when multipath is active.
#[repr(C, align(64))]
pub struct LegCounters {
    pub healthy: AtomicBool,
    pub priority: AtomicU8,
    pub weight: AtomicU16,
    pub rtt_ewma_us: AtomicU64,
    pub tx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub tx_errors: AtomicU64,
    pub last_tx_ms: AtomicU64,
    _tx_rx_pad: [u8; 64],
    pub rx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub rx_dedup_hits: AtomicU64,
    pub last_rx_ms: AtomicU64,
}

impl Default for LegCounters {
    fn default() -> Self {
        Self {
            healthy: AtomicBool::new(false),
            priority: AtomicU8::new(0),
            weight: AtomicU16::new(1),
            rtt_ewma_us: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
            last_tx_ms: AtomicU64::new(0),
            _tx_rx_pad: [0u8; 64],
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            rx_dedup_hits: AtomicU64::new(0),
            last_rx_ms: AtomicU64::new(0),
        }
    }
}

impl LegCounters {
    fn new(priority: u8, weight: u16, healthy: bool) -> Self {
        Self {
            healthy: AtomicBool::new(healthy),
            priority: AtomicU8::new(priority),
            weight: AtomicU16::new(weight.clamp(1, 256)),
            ..Self::default()
        }
    }

    pub fn record_tx(&self, bytes: usize) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.last_tx_ms
            .store(mono_ms_now().max(1), Ordering::Relaxed);
    }

    pub fn record_tx_error(&self) {
        self.tx_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_rx(&self, bytes: usize, is_dedup_hit: bool) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        if is_dedup_hit {
            self.rx_dedup_hits.fetch_add(1, Ordering::Relaxed);
        }
        self.last_rx_ms
            .store(mono_ms_now().max(1), Ordering::Relaxed);
    }

    pub fn record_rtt(&self, rtt: Duration) {
        let sample_us = (rtt.as_micros() as u64).max(1);
        let prev = self.rtt_ewma_us.load(Ordering::Relaxed);
        let next = if prev == 0 {
            sample_us
        } else {
            // 7/8 old + 1/8 new EWMA.
            ((prev * 7) + sample_us) / 8
        };
        self.rtt_ewma_us.store(next.max(1), Ordering::Relaxed);
    }

    fn snapshot(&self, leg_id: u32, carrier_dead: bool) -> MultipathLegSnapshot {
        let healthy = self.healthy.load(Ordering::Relaxed);
        MultipathLegSnapshot {
            leg_id,
            priority: self.priority.load(Ordering::Relaxed),
            weight: self.weight.load(Ordering::Relaxed).max(1),
            healthy,
            carrier_dead,
            effective_up: healthy && !carrier_dead,
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            tx_errors: self.tx_errors.load(Ordering::Relaxed),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            rx_dedup_hits: self.rx_dedup_hits.load(Ordering::Relaxed),
            last_tx_ms: self.last_tx_ms.load(Ordering::Relaxed),
            last_rx_ms: self.last_rx_ms.load(Ordering::Relaxed),
            rtt_ewma_us: self.rtt_ewma_us.load(Ordering::Relaxed),
        }
    }
}

/// A configured secondary carrier leg attached to a peer.
pub struct SecondaryLeg {
    pub leg_id: u32,
    pub slot_bit: u8,
    pub carrier: Arc<Carrier>,
    pub counters: Arc<LegCounters>,
    tasks: Vec<JoinHandle<()>>,
}

impl SecondaryLeg {
    pub(crate) fn take_tasks(&mut self) -> Vec<JoinHandle<()>> {
        std::mem::take(&mut self.tasks)
    }
    pub fn is_effective_up(&self) -> bool {
        self.counters.healthy.load(Ordering::Relaxed) && !self.carrier.is_dead()
    }
}

impl Drop for SecondaryLeg {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Stack-allocated transmit target list returned by [`PeerMultipathState::select_tx_targets`].
pub struct TxTargetList {
    items: [Option<(u32, Arc<Carrier>)>; MAX_TX_TARGETS],
    len: usize,
}

impl TxTargetList {
    fn empty() -> Self {
        Self {
            items: [None, None, None, None, None],
            len: 0,
        }
    }

    fn push(&mut self, leg_id: u32, carrier: Arc<Carrier>) {
        if self.len < MAX_TX_TARGETS {
            self.items[self.len] = Some((leg_id, carrier));
            self.len += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &(u32, Arc<Carrier>)> {
        self.items[..self.len].iter().flatten()
    }
}

/// Result of checking a Type-4 datagram against [`MultipathDedupTable`] before
/// `Tunn::decapsulate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreDecapVerdict {
    /// Not a known duplicate — proceed with `Tunn::decapsulate`.
    Proceed,
    /// Cryptographically verified duplicate of an already-decapsulated packet
    /// (constant-time Poly1305 tag AND full ciphertext SHA-256 match against
    /// a prior successful AEAD). `first_on_leg` is true iff
    /// this leg had not yet received a copy of this `(session, counter)`.
    AuthenticatedDuplicate { first_on_leg: bool },
}

#[derive(Clone, Copy)]
struct DedupEntry {
    session: u32,
    counter: u64,
    len: u16,
    tag: [u8; 16],
    digest: [u8; 32],
    seen_legs_mask: u64,
    recorded_at: Instant,
}

/// Maximum age after initial authentication during which a redundant copy on a
/// different leg may credit that leg's receive counters (`first_on_leg`).
const DEDUP_LIVENESS_MAX_AGE: Duration = Duration::from_secs(5);

/// Bounded ring buffer of recently authenticated Type-4 packets for
/// constant-time Poly1305-verified deduplication in [`MultipathMode::Redundant`].
struct MultipathDedupTable {
    entries: VecDeque<DedupEntry>,
    capacity: usize,
}

impl MultipathDedupTable {
    fn new(capacity: usize) -> Self {
        let cap = capacity.clamp(32, 2048);
        Self {
            entries: VecDeque::with_capacity(cap),
            capacity: cap,
        }
    }

    fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity.clamp(32, 2048);
        while self.entries.len() > self.capacity {
            self.entries.pop_front();
        }
    }

    /// Check whether `(session, counter, len, tag)` matches an already
    /// authenticated Type-4 packet. Never inserts a new entry.
    fn check_duplicate(
        &mut self,
        session: u32,
        counter: u64,
        len: usize,
        authenticated: (&[u8; 16], &[u8; 32]),
        leg_bit: u64,
        now: Instant,
    ) -> Option<bool> {
        let (tag, digest) = authenticated;
        let len_u16 = u16::try_from(len).ok()?;
        // Search from newest to oldest since duplicate copies arrive closely in time.
        for entry in self.entries.iter_mut().rev() {
            if entry.session == session && entry.counter == counter {
                if entry.len == len_u16
                    && bool::from(entry.tag.ct_eq(tag) & entry.digest.ct_eq(digest))
                {
                    let fresh =
                        now.saturating_duration_since(entry.recorded_at) <= DEDUP_LIVENESS_MAX_AGE;
                    let first_on_leg =
                        fresh && leg_bit != 0 && (entry.seen_legs_mask & leg_bit) == 0;
                    entry.seen_legs_mask |= leg_bit;
                    return Some(first_on_leg);
                }
                // Same (session, counter) but mismatched length, tag, or full ciphertext:
                // forged/corrupted packet — do not match!
                return None;
            }
        }
        None
    }

    /// Record a freshly authenticated Type-4 packet after `Tunn::decapsulate`
    /// succeeded.
    fn record_authenticated(
        &mut self,
        session: u32,
        counter: u64,
        len: usize,
        authenticated: ([u8; 16], [u8; 32]),
        leg_bit: u64,
        now: Instant,
    ) {
        let (tag, digest) = authenticated;
        let Ok(len_u16) = u16::try_from(len) else {
            return;
        };
        for entry in self.entries.iter_mut().rev() {
            if entry.session == session && entry.counter == counter {
                entry.len = len_u16;
                entry.tag = tag;
                entry.digest = digest;
                entry.seen_legs_mask = leg_bit;
                entry.recorded_at = now;
                return;
            }
        }
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(DedupEntry {
            session,
            counter,
            len: len_u16,
            tag,
            digest,
            seen_legs_mask: leg_bit,
            recorded_at: now,
        });
    }
}

struct BufferedPacket {
    /// `Some(pkt)` for an authenticated, ingress-permitted IP packet;
    /// `None` for an authenticated non-deliverable Type-4 frame (such as a
    /// content-free keepalive or an ingress-denied packet) that still occupies
    /// a WireGuard sequence counter.
    packet: Option<Vec<u8>>,
    queued_at: Instant,
}

/// Per-peer receiver-side reorder buffer for [`MultipathMode::Aggregate`].
///
/// Orders authenticated, ingress-permitted IP packets by their WireGuard
/// Type-4 `(receiver_index, counter)` within a bounded depth (`max_depth`) and
/// hold duration (`hold_timeout`).
struct MultipathReorderBuffer {
    current_session: Option<u32>,
    prev_session: Option<u32>,
    expected_next_counter: u64,
    last_observed_session: Option<u32>,
    last_observed_counter: u64,
    buffered: BTreeMap<u64, BufferedPacket>,
    ready_overflow: VecDeque<Vec<u8>>,
    max_depth: usize,
    hold_timeout: Duration,
}

struct ReorderStatsDelta {
    buffered_inc: u64,
    in_order_inc: u64,
    reordered_inc: u64,
    timeout_flushed_inc: u64,
    capacity_flushed_inc: u64,
    late_inc: u64,
}

impl MultipathReorderBuffer {
    fn new(max_depth: usize, hold_timeout: Duration) -> Self {
        Self {
            current_session: None,
            prev_session: None,
            expected_next_counter: 0,
            last_observed_session: None,
            last_observed_counter: 0,
            buffered: BTreeMap::new(),
            ready_overflow: VecDeque::new(),
            max_depth: max_depth.clamp(1, 512),
            hold_timeout: hold_timeout.clamp(Duration::from_millis(1), Duration::from_millis(500)),
        }
    }

    fn note_counter(&mut self, session: u32, counter: u64) {
        if self.last_observed_session != Some(session) || counter > self.last_observed_counter {
            self.last_observed_session = Some(session);
            self.last_observed_counter = counter;
        }
    }

    fn buffered_data_count(&self) -> usize {
        self.buffered
            .values()
            .filter(|e| e.packet.is_some())
            .count()
    }

    /// Flush all buffered packets unconditionally into `ready_overflow` (used on
    /// mode transition out of `Aggregate` or session rotation).
    fn flush_all(&mut self) -> usize {
        let mut count = 0;
        while let Some((ctr, entry)) = self.buffered.pop_first() {
            if let Some(pkt) = entry.packet {
                self.ready_overflow.push_back(pkt);
                count += 1;
            }
            self.expected_next_counter = ctr.saturating_add(1);
            if let Some(cur) = self.current_session {
                self.note_counter(cur, ctr);
            }
        }
        count
    }

    /// Drain contiguous entries starting at `expected_next_counter`.
    fn drain_contiguous(&mut self, delta: &mut ReorderStatsDelta) {
        while let Some(entry) = self.buffered.remove(&self.expected_next_counter) {
            let ctr = self.expected_next_counter;
            self.expected_next_counter = ctr.saturating_add(1);
            if let Some(cur) = self.current_session {
                self.note_counter(cur, ctr);
            }
            if let Some(pkt) = entry.packet {
                self.ready_overflow.push_back(pkt);
                delta.reordered_inc += 1;
            }
        }
    }

    /// Flush expired entries (whose `queued_at` is at or past `hold_timeout`)
    /// and any contiguous entries immediately following them.
    fn flush_expired(&mut self, now: Instant, delta: &mut ReorderStatsDelta) {
        loop {
            let expired_ctr = self.buffered.iter().find_map(|(&ctr, entry)| {
                (now.saturating_duration_since(entry.queued_at) >= self.hold_timeout).then_some(ctr)
            });
            let Some(target_ctr) = expired_ctr else {
                break;
            };
            while let Some((&first_ctr, _)) = self.buffered.first_key_value() {
                if first_ctr > target_ctr {
                    break;
                }
                let (ctr, entry) = self.buffered.pop_first().expect("checked non-empty");
                self.expected_next_counter = ctr.saturating_add(1);
                if let Some(cur) = self.current_session {
                    self.note_counter(cur, ctr);
                }
                if let Some(pkt) = entry.packet {
                    self.ready_overflow.push_back(pkt);
                    delta.timeout_flushed_inc += 1;
                }
            }
            while let Some(entry) = self.buffered.remove(&self.expected_next_counter) {
                let ctr = self.expected_next_counter;
                self.expected_next_counter = ctr.saturating_add(1);
                if let Some(cur) = self.current_session {
                    self.note_counter(cur, ctr);
                }
                if let Some(pkt) = entry.packet {
                    self.ready_overflow.push_back(pkt);
                    delta.timeout_flushed_inc += 1;
                }
            }
        }
    }

    /// Sequence an authenticated Type-4 frame (`packet == Some(ip_pkt)` for
    /// ingress-permitted data, `packet == None` for keepalives or ingress-denied
    /// frames that still advance the WireGuard counter).
    /// Returns the first packet to deliver (if any) while keeping any additional
    /// released packets in `self.ready_overflow`.
    fn on_authenticated_type4(
        &mut self,
        session: u32,
        counter: u64,
        packet: Option<Vec<u8>>,
        now: Instant,
    ) -> (Option<Vec<u8>>, ReorderStatsDelta) {
        let mut delta = ReorderStatsDelta {
            buffered_inc: 0,
            in_order_inc: 0,
            reordered_inc: 0,
            timeout_flushed_inc: 0,
            capacity_flushed_inc: 0,
            late_inc: 0,
        };

        // First flush any buffered packets that have already exceeded hold_timeout.
        self.flush_expired(now, &mut delta);

        match self.current_session {
            None => {
                self.current_session = Some(session);
                // If Aggregate mode was enabled mid-session or the session started
                // past max_depth, align expected_next_counter to the prior in-order
                // observed counter + 1 (or `counter` if beyond max_depth). Otherwise
                // start at 0 so a swapped packet #1 arriving before packet #0 is
                // properly reordered.
                self.expected_next_counter = if self.last_observed_session == Some(session) {
                    self.last_observed_counter.saturating_add(1)
                } else if counter > self.max_depth as u64 {
                    counter
                } else {
                    0
                };
            }
            Some(cur) if cur != session => {
                if self.prev_session == Some(session) {
                    // Late straggler from the immediately preceding WG session:
                    // deliver in-place without resetting the active session.
                    if let Some(pkt) = packet {
                        delta.late_inc += 1;
                        self.ready_overflow.push_back(pkt);
                    }
                    return (self.ready_overflow.pop_front(), delta);
                }
                // Genuine session rotation (rekey): flush any remaining packets from
                // the old session first so they are delivered before the new session.
                let flushed = self.flush_all();
                delta.timeout_flushed_inc += flushed as u64;
                self.prev_session = Some(cur);
                self.current_session = Some(session);
                self.expected_next_counter = if self.last_observed_session == Some(session) {
                    self.last_observed_counter.saturating_add(1)
                } else if counter > self.max_depth as u64 {
                    counter
                } else {
                    0
                };
            }
            Some(_) => {}
        }

        if counter == self.expected_next_counter {
            if let Some(pkt) = packet {
                self.ready_overflow.push_back(pkt);
                delta.in_order_inc += 1;
            }
            self.note_counter(session, counter);
            self.expected_next_counter = counter.saturating_add(1);
            self.drain_contiguous(&mut delta);
        } else if counter < self.expected_next_counter {
            // Arrived after a timeout/capacity flush already advanced past `counter`.
            // Deliver immediately (boringtun already authenticated and replay-checked it).
            if let Some(pkt) = packet {
                self.ready_overflow.push_back(pkt);
                delta.late_inc += 1;
            }
        } else {
            // Out-of-order future counter (`counter > expected_next_counter`):
            // If `counter - expected_next_counter` exceeds `max_depth * 4`, advance
            // the window so a burst loss larger than the window does not stall.
            let max_span = (self.max_depth as u64).saturating_mul(4).max(16);
            if counter.saturating_sub(self.expected_next_counter) > max_span {
                let flushed = self.flush_all();
                delta.capacity_flushed_inc += flushed as u64;
                self.expected_next_counter = counter;
                if let Some(pkt) = packet {
                    self.ready_overflow.push_back(pkt);
                    delta.in_order_inc += 1;
                }
                self.note_counter(session, counter);
                self.expected_next_counter = counter.saturating_add(1);
            } else {
                let is_data = packet.is_some();
                self.buffered.insert(
                    counter,
                    BufferedPacket {
                        packet,
                        queued_at: now,
                    },
                );
                if is_data {
                    delta.buffered_inc += 1;
                }
                while self.buffered_data_count() > self.max_depth
                    || self.buffered.len() > self.max_depth.saturating_mul(2)
                {
                    let (oldest_ctr, entry) = self.buffered.pop_first().expect("non-empty");
                    self.expected_next_counter = oldest_ctr.saturating_add(1);
                    self.note_counter(session, oldest_ctr);
                    if let Some(pkt) = entry.packet {
                        self.ready_overflow.push_back(pkt);
                        delta.capacity_flushed_inc += 1;
                    }
                    self.drain_contiguous(&mut delta);
                }
            }
        }

        (self.ready_overflow.pop_front(), delta)
    }

    /// Next instant at which the earliest buffered packet will expire.
    fn next_expiry(&self) -> Option<Instant> {
        self.buffered
            .values()
            .map(|e| e.queued_at + self.hold_timeout)
            .min()
    }
}

struct SchedulerState {
    config: MultipathConfig,
    legs: Vec<SecondaryLeg>,
    wrr_cursor: usize,
    wrr_quantum_remaining: u16,
    dedup: MultipathDedupTable,
    reorder: MultipathReorderBuffer,
    reorder_flush_task: Option<JoinHandle<()>>,
}

/// Per-peer multipath controller shared between `Peer`, `SendPeer`, and `Ingress`.
pub struct PeerMultipathState {
    mode: AtomicU8,
    active_flag: AtomicBool,
    has_legs_flag: AtomicBool,
    primary_counters: LegCounters,
    active_tx_leg_id: AtomicU32,
    failover_switches: AtomicU64,
    redundant_extra_tx_packets: AtomicU64,
    dedup_dropped: AtomicU64,
    reorder_buffered: AtomicU64,
    reorder_in_order_delivered: AtomicU64,
    reorder_reordered_delivered: AtomicU64,
    reorder_timeout_flushed: AtomicU64,
    reorder_capacity_flushed: AtomicU64,
    reorder_late_delivered: AtomicU64,
    reorder_notify: Arc<Notify>,
    inner: Mutex<SchedulerState>,
}

impl Default for PeerMultipathState {
    fn default() -> Self {
        Self::new(MultipathConfig::default())
    }
}

impl Drop for PeerMultipathState {
    fn drop(&mut self) {
        self.reorder_notify.notify_waiters();
        if let Ok(mut st) = self.inner.lock()
            && let Some(task) = st.reorder_flush_task.take()
        {
            task.abort();
        }
    }
}

impl PeerMultipathState {
    pub fn new(config: MultipathConfig) -> Self {
        let mode = config.mode;
        let primary_weight = config.primary_weight.clamp(1, 256);
        let dedup_cap = config.dedup_window_size;
        let max_depth = config.max_reorder_depth;
        let hold_timeout = config.reorder_hold_timeout;
        Self {
            mode: AtomicU8::new(mode as u8),
            // Starts inactive (`false`) until a non-Off mode AND at least one
            // healthy, live secondary leg are present.
            active_flag: AtomicBool::new(false),
            has_legs_flag: AtomicBool::new(false),
            primary_counters: LegCounters::new(0, primary_weight, true),
            active_tx_leg_id: AtomicU32::new(0),
            failover_switches: AtomicU64::new(0),
            redundant_extra_tx_packets: AtomicU64::new(0),
            dedup_dropped: AtomicU64::new(0),
            reorder_buffered: AtomicU64::new(0),
            reorder_in_order_delivered: AtomicU64::new(0),
            reorder_reordered_delivered: AtomicU64::new(0),
            reorder_timeout_flushed: AtomicU64::new(0),
            reorder_capacity_flushed: AtomicU64::new(0),
            reorder_late_delivered: AtomicU64::new(0),
            reorder_notify: Arc::new(Notify::new()),
            inner: Mutex::new(SchedulerState {
                config,
                legs: Vec::new(),
                wrr_cursor: 0,
                wrr_quantum_remaining: primary_weight,
                dedup: MultipathDedupTable::new(dedup_cap),
                reorder: MultipathReorderBuffer::new(max_depth, hold_timeout),
                reorder_flush_task: None,
            }),
        }
    }

    /// Seed the highest authenticated WireGuard Type-4 `(session, counter)` observed
    /// on the single-path fast path before multipath was activated, so a mid-session
    /// transition into [`MultipathMode::Aggregate`] starts `expected_next_counter`
    /// at `counter + 1`.
    pub fn seed_rx_counter(&self, session: u32, counter: u64) {
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        st.reorder.note_counter(session, counter);
    }

    /// Fast-path check: `true` only when a non-`Off` mode is configured with at
    /// least one healthy, live secondary leg (or while draining residual reorder
    /// buffer entries). Single `Relaxed` atomic load.
    #[inline]
    pub fn is_active(&self) -> bool {
        self.active_flag.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn mode(&self) -> MultipathMode {
        MultipathMode::from_u8(self.mode.load(Ordering::Relaxed))
    }

    fn refresh_active_flag(&self, st: &SchedulerState) {
        let has_effective_secondary = st.legs.iter().any(|l| l.is_effective_up());
        let active = (st.config.mode != MultipathMode::Off && has_effective_secondary)
            || !st.reorder.buffered.is_empty()
            || !st.reorder.ready_overflow.is_empty();
        self.active_flag.store(active, Ordering::Relaxed);
        self.has_legs_flag
            .store(!st.legs.is_empty(), Ordering::Relaxed);
    }

    fn flush_parked_reorder_locked(&self, st: &mut SchedulerState) {
        if !st.reorder.buffered.is_empty() {
            let flushed = st.reorder.flush_all();
            if flushed > 0 {
                self.reorder_timeout_flushed
                    .fetch_add(flushed as u64, Ordering::Relaxed);
            }
            if !st.reorder.ready_overflow.is_empty() {
                self.reorder_notify.notify_one();
            }
        }
    }

    /// Update the peer's multipath configuration in place. If switching away
    /// from [`MultipathMode::Aggregate`] (or when no healthy secondary leg is
    /// present), any packets currently parked in the reorder buffer are
    /// immediately flushed into the ready queue and woken.
    pub fn set_config(&self, config: MultipathConfig) {
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let old_mode = st.config.mode;
        let new_mode = config.mode;
        self.primary_counters
            .weight
            .store(config.primary_weight.clamp(1, 256), Ordering::Relaxed);
        st.dedup.set_capacity(config.dedup_window_size);
        st.reorder.max_depth = config.max_reorder_depth.clamp(1, 512);
        st.reorder.hold_timeout = config
            .reorder_hold_timeout
            .clamp(Duration::from_millis(1), Duration::from_millis(500));
        let has_effective_secondary = st.legs.iter().any(|l| l.is_effective_up());
        if (old_mode == MultipathMode::Aggregate && new_mode != MultipathMode::Aggregate)
            || !has_effective_secondary
        {
            self.flush_parked_reorder_locked(&mut st);
            if new_mode != MultipathMode::Aggregate {
                st.reorder.current_session = None;
                st.reorder.prev_session = None;
            }
        }
        st.config = config;
        st.wrr_cursor = 0;
        st.wrr_quantum_remaining = self.primary_counters.weight.load(Ordering::Relaxed).max(1);
        self.mode.store(new_mode as u8, Ordering::Relaxed);
        self.refresh_active_flag(&st);
    }

    /// Set the administrative / path-monitor health of a leg (`leg_id == 0` for
    /// primary, `leg_id > 0` for a secondary leg). Returns `true` if `leg_id`
    /// exists.
    pub fn set_leg_healthy(&self, leg_id: u32, healthy: bool) -> bool {
        if leg_id == 0 {
            self.primary_counters
                .healthy
                .store(healthy, Ordering::Relaxed);
            return true;
        }
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(leg) = st.legs.iter().find(|l| l.leg_id == leg_id) else {
            return false;
        };
        leg.counters.healthy.store(healthy, Ordering::Relaxed);
        if !st.legs.iter().any(|l| l.is_effective_up()) {
            self.flush_parked_reorder_locked(&mut st);
        }
        self.refresh_active_flag(&st);
        true
    }

    /// Update a leg's weight (`1..=256`) and priority (`0..=255`).
    pub fn set_leg_policy(&self, leg_id: u32, priority: u8, weight: u16) -> bool {
        let clamped_weight = weight.clamp(1, 256);
        if leg_id == 0 {
            self.primary_counters
                .priority
                .store(priority, Ordering::Relaxed);
            self.primary_counters
                .weight
                .store(clamped_weight, Ordering::Relaxed);
            return true;
        }
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(leg) = st.legs.iter().find(|l| l.leg_id == leg_id) else {
            return false;
        };
        leg.counters.priority.store(priority, Ordering::Relaxed);
        leg.counters.weight.store(clamped_weight, Ordering::Relaxed);
        st.legs.sort_by_key(|l| {
            (
                l.counters.priority.load(Ordering::Relaxed),
                std::cmp::Reverse(l.counters.weight.load(Ordering::Relaxed)),
                l.leg_id,
            )
        });
        true
    }

    /// Record an observed RTT sample for `leg_id` (`0` = primary, `> 0` = secondary).
    pub fn record_leg_rtt(&self, leg_id: u32, rtt: Duration) -> bool {
        if leg_id == 0 {
            self.primary_counters.record_rtt(rtt);
            return true;
        }
        let st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(leg) = st.legs.iter().find(|l| l.leg_id == leg_id) else {
            return false;
        };
        leg.counters.record_rtt(rtt);
        true
    }

    /// Attach or replace a secondary carrier leg (`leg_id > 0` and `leg_id < 64`).
    /// Returns `false` if `leg_id == 0`, `leg_id >= 64`, or if [`MAX_MULTIPATH_LEGS`]
    /// distinct secondary legs are already attached.
    pub fn upsert_secondary_leg(
        &self,
        leg_id: u32,
        carrier: Arc<Carrier>,
        priority: u8,
        weight: u16,
        tasks: Vec<JoinHandle<()>>,
    ) -> bool {
        self.upsert_secondary_leg_with_health(leg_id, carrier, priority, weight, tasks, true)
    }

    pub(crate) fn upsert_secondary_leg_with_health(
        &self,
        leg_id: u32,
        carrier: Arc<Carrier>,
        priority: u8,
        weight: u16,
        tasks: Vec<JoinHandle<()>>,
        healthy: bool,
    ) -> bool {
        if leg_id == 0 || leg_id >= 64 {
            for t in tasks {
                t.abort();
            }
            return false;
        }
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = st.legs.iter_mut().find(|l| l.leg_id == leg_id) {
            let slot_bit = existing.slot_bit;
            *existing = SecondaryLeg {
                leg_id,
                slot_bit,
                carrier,
                counters: Arc::new(LegCounters::new(priority, weight, healthy)),
                tasks,
            };
        } else {
            if st.legs.len() >= MAX_MULTIPATH_LEGS {
                for t in tasks {
                    t.abort();
                }
                return false;
            }
            let used_bits: u8 = st.legs.iter().fold(0u8, |acc, l| acc | (1u8 << l.slot_bit));
            let slot_bit = (1u8..=MAX_MULTIPATH_LEGS as u8)
                .find(|b| (used_bits & (1u8 << b)) == 0)
                .unwrap_or(1);
            st.legs.push(SecondaryLeg {
                leg_id,
                slot_bit,
                carrier,
                counters: Arc::new(LegCounters::new(priority, weight, healthy)),
                tasks,
            });
        }
        st.legs.sort_by_key(|l| {
            (
                l.counters.priority.load(Ordering::Relaxed),
                std::cmp::Reverse(l.counters.weight.load(Ordering::Relaxed)),
                l.leg_id,
            )
        });
        self.refresh_active_flag(&st);
        true
    }

    /// Remove a secondary leg by `leg_id` (aborts its tasks via `Drop`).
    pub fn remove_secondary_leg(&self, leg_id: u32) -> bool {
        if leg_id == 0 {
            return false;
        }
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let before = st.legs.len();
        st.legs.retain(|l| l.leg_id != leg_id);
        let removed = st.legs.len() != before;
        if removed {
            st.wrr_cursor = 0;
            if !st.legs.iter().any(|l| l.is_effective_up()) {
                self.flush_parked_reorder_locked(&mut st);
            }
            self.refresh_active_flag(&st);
        }
        removed
    }

    /// Transfer receiver ownership during an already-authorized primary role
    /// commit. Taking does not abort the leg; its new Peer owner takes tasks.
    pub(crate) fn take_secondary_leg(&self, leg_id: u32) -> Option<SecondaryLeg> {
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let i = st.legs.iter().position(|leg| leg.leg_id == leg_id)?;
        let leg = st.legs.remove(i);
        st.wrr_cursor = 0;
        self.refresh_active_flag(&st);
        Some(leg)
    }

    /// Remove all secondary legs (and abort any lazy reorder flush task once
    /// no parked/ready reorder packets remain).
    pub fn clear_secondary_legs(&self) {
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        st.legs.clear();
        st.wrr_cursor = 0;
        self.flush_parked_reorder_locked(&mut st);
        if st.reorder.buffered.is_empty()
            && st.reorder.ready_overflow.is_empty()
            && let Some(task) = st.reorder_flush_task.take()
        {
            task.abort();
        }
        self.refresh_active_flag(&st);
    }

    pub fn secondary_leg_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .legs
            .len()
    }

    /// A current-session/role transition cannot reuse old duplicate liveness
    /// evidence. Reordering delivery remains separately counter/session bound.
    pub(crate) fn clear_crypto_observations(&self) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .dedup
            .entries
            .clear();
    }

    /// Fast check whether any secondary legs are attached.
    #[inline]
    pub fn has_secondary_legs(&self) -> bool {
        self.has_legs_flag.load(Ordering::Relaxed)
    }

    /// Return the `leg_id` of a secondary direct leg whose remote `dst` matches
    /// `src`, if any. Used by shared direct demuxers (`CarrierPlane` /
    /// `DirectDemux`) so secondary-leg datagrams on a shared socket are
    /// attributed to their leg without triggering A3 endpoint roaming.
    pub fn leg_id_for_direct_src(&self, src: std::net::SocketAddr) -> Option<u32> {
        if !self.has_legs_flag.load(Ordering::Relaxed) {
            return None;
        }
        let st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        st.legs.iter().find_map(|leg| {
            leg.carrier
                .direct_parts()
                .and_then(|(_, dst)| (dst == src).then_some(leg.leg_id))
        })
    }

    fn note_active_tx_leg(&self, leg_id: u32) {
        let prev = self.active_tx_leg_id.swap(leg_id, Ordering::Relaxed);
        if prev != leg_id {
            self.failover_switches.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Choose the carrier leg(s) for an outbound encapsulated WireGuard frame.
    pub fn select_tx_targets(
        &self,
        primary_carrier: &Arc<Carrier>,
        wire_frame: &[u8],
    ) -> TxTargetList {
        let mut out = TxTargetList::empty();
        let primary_up =
            self.primary_counters.healthy.load(Ordering::Relaxed) && !primary_carrier.is_dead();
        // A content-free keepalive is exactly WG_TYPE4_MIN_LEN (32) bytes;
        // a Type-4 data frame carrying an encrypted IP packet is strictly > 32 bytes.
        let is_data_frame = wire_frame.len() > WG_TYPE4_MIN_LEN && wire_frame[..4] == [4, 0, 0, 0];

        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !st.legs.iter().any(|l| l.is_effective_up()) {
            self.flush_parked_reorder_locked(&mut st);
            self.refresh_active_flag(&st);
        }
        match st.config.mode {
            MultipathMode::Off => {
                self.active_tx_leg_id.store(0, Ordering::Relaxed);
                out.push(0, primary_carrier.clone());
            }
            MultipathMode::ActiveStandby => {
                if primary_up {
                    self.note_active_tx_leg(0);
                    out.push(0, primary_carrier.clone());
                    // Include the highest-priority healthy standby leg as an immediate
                    // fallback in case the primary leg fails synchronously on this send.
                    if let Some(best) = st.legs.iter().find(|l| l.is_effective_up()) {
                        out.push(best.leg_id, best.carrier.clone());
                    }
                } else if let Some(best) = st.legs.iter().find(|l| l.is_effective_up()) {
                    let leg_id = best.leg_id;
                    let carrier = best.carrier.clone();
                    self.note_active_tx_leg(leg_id);
                    out.push(leg_id, carrier);
                } else {
                    // Last resort when all legs are unhealthy/dead: attempt primary.
                    self.note_active_tx_leg(0);
                    out.push(0, primary_carrier.clone());
                }
            }
            MultipathMode::Redundant => {
                if primary_up {
                    out.push(0, primary_carrier.clone());
                }
                let max_sec = st
                    .config
                    .max_redundant_secondary_legs
                    .clamp(1, MAX_MULTIPATH_LEGS);
                for leg in st.legs.iter().filter(|l| l.is_effective_up()).take(max_sec) {
                    out.push(leg.leg_id, leg.carrier.clone());
                }
                if out.is_empty() {
                    out.push(0, primary_carrier.clone());
                }
                if let Some((first_id, _)) = out.iter().next() {
                    self.note_active_tx_leg(*first_id);
                }
            }
            MultipathMode::Aggregate => {
                // Control frames (handshake init/response/cookie) and keepalives
                // without payload go over primary (if up) + best secondary so
                // handshakes complete reliably even if one leg is impaired.
                if !is_data_frame {
                    if primary_up {
                        out.push(0, primary_carrier.clone());
                    }
                    if let Some(sec) = st.legs.iter().find(|l| l.is_effective_up()) {
                        out.push(sec.leg_id, sec.carrier.clone());
                    }
                    if out.is_empty() {
                        out.push(0, primary_carrier.clone());
                    }
                    return out;
                }

                // Collect healthy legs: slot 0 = primary (if up), slots 1..=N = healthy secondaries.
                let mut healthy_slots: [(u32, u16, Option<Arc<Carrier>>); MAX_TX_TARGETS] = [
                    (0, 1, None),
                    (0, 1, None),
                    (0, 1, None),
                    (0, 1, None),
                    (0, 1, None),
                ];
                let mut count = 0usize;
                if primary_up {
                    let w = self.primary_counters.weight.load(Ordering::Relaxed).max(1);
                    healthy_slots[count] = (0, w, Some(primary_carrier.clone()));
                    count += 1;
                }
                for leg in st.legs.iter().filter(|l| l.is_effective_up()) {
                    if count < MAX_TX_TARGETS {
                        let w = leg.counters.weight.load(Ordering::Relaxed).max(1);
                        healthy_slots[count] = (leg.leg_id, w, Some(leg.carrier.clone()));
                        count += 1;
                    }
                }

                if count == 0 {
                    self.note_active_tx_leg(0);
                    out.push(0, primary_carrier.clone());
                    return out;
                }
                if count == 1 {
                    let (id, _, ref c) = healthy_slots[0];
                    self.note_active_tx_leg(id);
                    out.push(id, c.clone().expect("populated above"));
                    return out;
                }

                // Weighted round-robin (WRR) across the `count` healthy legs.
                if st.wrr_cursor >= count {
                    st.wrr_cursor = 0;
                    st.wrr_quantum_remaining = healthy_slots[0].1;
                }
                if st.wrr_quantum_remaining == 0 {
                    st.wrr_cursor = (st.wrr_cursor + 1) % count;
                    st.wrr_quantum_remaining = healthy_slots[st.wrr_cursor].1;
                }
                let chosen_idx = st.wrr_cursor;
                st.wrr_quantum_remaining = st.wrr_quantum_remaining.saturating_sub(1);
                if st.wrr_quantum_remaining == 0 {
                    st.wrr_cursor = (st.wrr_cursor + 1) % count;
                    st.wrr_quantum_remaining = healthy_slots[st.wrr_cursor].1;
                }

                let (chosen_id, _, ref chosen_carrier) = healthy_slots[chosen_idx];
                self.note_active_tx_leg(chosen_id);
                out.push(chosen_id, chosen_carrier.clone().expect("populated above"));
                // Also include the next healthy leg as a fallback in case the chosen leg's
                // send call fails immediately on this packet.
                let backup_idx = (chosen_idx + 1) % count;
                if backup_idx != chosen_idx {
                    let (backup_id, _, ref backup_carrier) = healthy_slots[backup_idx];
                    out.push(backup_id, backup_carrier.clone().expect("populated above"));
                }
            }
        }
        out
    }

    /// Record the outcome of transmitting `bytes_len` on `leg_id`.
    pub fn record_leg_tx_outcome(
        &self,
        leg_id: u32,
        bytes_len: usize,
        ok: bool,
        is_extra_copy: bool,
    ) {
        if is_extra_copy && ok {
            self.redundant_extra_tx_packets
                .fetch_add(1, Ordering::Relaxed);
        }
        if leg_id == 0 {
            if ok {
                self.primary_counters.record_tx(bytes_len);
            } else {
                self.primary_counters.record_tx_error();
            }
            return;
        }
        let st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(leg) = st.legs.iter().find(|l| l.leg_id == leg_id) {
            if ok {
                leg.counters.record_tx(bytes_len);
            } else {
                leg.counters.record_tx_error();
            }
        }
    }

    fn leg_bit_locked(st: &SchedulerState, leg_id: u32) -> u64 {
        if leg_id == 0 {
            1u64
        } else if let Some(leg) = st.legs.iter().find(|l| l.leg_id == leg_id) {
            1u64.checked_shl(u32::from(leg.slot_bit)).unwrap_or(0)
        } else {
            1u64 << 63
        }
    }

    fn record_leg_rx_locked(
        &self,
        st: &SchedulerState,
        leg_id: u32,
        bytes: usize,
        is_dedup_hit: bool,
    ) {
        if leg_id == 0 {
            self.primary_counters.record_rx(bytes, is_dedup_hit);
        } else if let Some(leg) = st.legs.iter().find(|l| l.leg_id == leg_id) {
            leg.counters.record_rx(bytes, is_dedup_hit);
        }
    }

    /// Parse `(session_receiver_index, counter, poly1305_tag)` from a WireGuard
    /// Type-4 transport packet (`n >= 32 && datagram[..4] == [4, 0, 0, 0]`).
    pub fn parse_type4_header_and_tag(datagram: &[u8]) -> Option<(u32, u64, [u8; 16])> {
        if datagram.len() < WG_TYPE4_MIN_LEN || datagram[..4] != [4, 0, 0, 0] {
            return None;
        }
        let session = u32::from_le_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]);
        let counter = u64::from_le_bytes([
            datagram[8],
            datagram[9],
            datagram[10],
            datagram[11],
            datagram[12],
            datagram[13],
            datagram[14],
            datagram[15],
        ]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&datagram[datagram.len() - 16..]);
        Some((session, counter, tag))
    }

    /// Check before `Tunn::decapsulate` whether `datagram` is an authentic
    /// redundant copy of an already-decapsulated Type-4 packet.
    ///
    /// Security invariant: only matches entries that were previously inserted by
    /// [`Self::post_decap_record`] *after* `Tunn::decapsulate` succeeded, and
    /// requires a constant-time match of the full 16-byte Poly1305 AEAD tag and
    /// datagram length. Credits `leg_id`'s receive counters at most once per
    /// `(session, counter)` via `seen_legs_mask` and only within
    /// `DEDUP_LIVENESS_MAX_AGE`.
    pub fn pre_decap_check(&self, datagram: &[u8], leg_id: u32) -> PreDecapVerdict {
        if !self.is_active() {
            return PreDecapVerdict::Proceed;
        }
        let Some((session, counter, tag)) = Self::parse_type4_header_and_tag(datagram) else {
            return PreDecapVerdict::Proceed;
        };
        let now = Instant::now();
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let leg_bit = Self::leg_bit_locked(&st, leg_id);
        let digest: [u8; 32] = Sha256::digest(datagram).into();
        if let Some(first_on_leg) = st.dedup.check_duplicate(
            session,
            counter,
            datagram.len(),
            (&tag, &digest),
            leg_bit,
            now,
        ) {
            self.dedup_dropped.fetch_add(1, Ordering::Relaxed);
            if first_on_leg {
                self.record_leg_rx_locked(&st, leg_id, datagram.len(), true);
            }
            return PreDecapVerdict::AuthenticatedDuplicate { first_on_leg };
        }
        PreDecapVerdict::Proceed
    }

    /// Called inside `decap_inbound` AFTER `Tunn::decapsulate` authenticated
    /// `datagram` (and after `ingress.permits` approved any decrypted IP packet).
    ///
    /// - Records per-leg receive statistics when multipath is active.
    /// - Records the authenticated Type-4 `(session, counter, len, tag)` in
    ///   [`MultipathDedupTable`] so subsequent redundant copies on slower legs
    ///   are recognized.
    /// - In [`MultipathMode::Aggregate`] (with at least one healthy secondary leg),
    ///   routes decrypted IP packets (and keepalive counters) through
    ///   [`MultipathReorderBuffer`] so packets are released to `tun_tx` in
    ///   ascending WireGuard counter order.
    pub fn post_decap_record(
        &self,
        datagram: &[u8],
        leg_id: u32,
        delivered: Option<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        if !self.is_active() {
            return delivered;
        }
        self.post_decap_record_inner(datagram, Some(leg_id), delivered)
    }

    /// Called inside `decap_standby` (F2 DERP standby copy) when multipath is
    /// active: records the authenticated Type-4 packet in [`MultipathDedupTable`]
    /// and advances [`MultipathReorderBuffer`] without crediting any carrier
    /// leg's receive counters (preserving F2's no-rx-stat invariant while
    /// preventing 25 ms counter holes in [`MultipathMode::Aggregate`]).
    pub fn post_decap_standby_record(
        &self,
        datagram: &[u8],
        delivered: Option<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        if !self.is_active() {
            return delivered;
        }
        self.post_decap_record_inner(datagram, None, delivered)
    }

    fn post_decap_record_inner(
        &self,
        datagram: &[u8],
        leg_id: Option<u32>,
        delivered: Option<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        let type4 = Self::parse_type4_header_and_tag(datagram);
        let now = Instant::now();
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let leg_bit = match leg_id {
            Some(id) => {
                self.record_leg_rx_locked(&st, id, datagram.len(), false);
                Self::leg_bit_locked(&st, id)
            }
            None => 0,
        };

        let Some((session, counter, tag)) = type4 else {
            return delivered;
        };

        st.dedup.record_authenticated(
            session,
            counter,
            datagram.len(),
            (tag, Sha256::digest(datagram).into()),
            leg_bit,
            now,
        );

        let aggregate_with_secondary = st.config.mode == MultipathMode::Aggregate
            && st.legs.iter().any(|l| l.is_effective_up());
        if !aggregate_with_secondary {
            if !st.reorder.buffered.is_empty() {
                let flushed = st.reorder.flush_all();
                if flushed > 0 {
                    self.reorder_timeout_flushed
                        .fetch_add(flushed as u64, Ordering::Relaxed);
                }
            }
            st.reorder.note_counter(session, counter);
            if let Some(pkt) = delivered {
                st.reorder.ready_overflow.push_back(pkt);
            }
            let out = st.reorder.ready_overflow.pop_front();
            if !st.reorder.ready_overflow.is_empty() {
                self.reorder_notify.notify_one();
            }
            self.refresh_active_flag(&st);
            return out;
        }

        let (out_pkt, delta) = st
            .reorder
            .on_authenticated_type4(session, counter, delivered, now);
        let should_notify =
            !st.reorder.buffered.is_empty() || !st.reorder.ready_overflow.is_empty();
        self.refresh_active_flag(&st);
        drop(st);

        self.apply_reorder_delta(&delta);
        if should_notify {
            self.reorder_notify.notify_one();
        }
        out_pkt
    }

    fn apply_reorder_delta(&self, delta: &ReorderStatsDelta) {
        if delta.buffered_inc > 0 {
            self.reorder_buffered
                .fetch_add(delta.buffered_inc, Ordering::Relaxed);
        }
        if delta.in_order_inc > 0 {
            self.reorder_in_order_delivered
                .fetch_add(delta.in_order_inc, Ordering::Relaxed);
        }
        if delta.reordered_inc > 0 {
            self.reorder_reordered_delivered
                .fetch_add(delta.reordered_inc, Ordering::Relaxed);
        }
        if delta.timeout_flushed_inc > 0 {
            self.reorder_timeout_flushed
                .fetch_add(delta.timeout_flushed_inc, Ordering::Relaxed);
        }
        if delta.capacity_flushed_inc > 0 {
            self.reorder_capacity_flushed
                .fetch_add(delta.capacity_flushed_inc, Ordering::Relaxed);
        }
        if delta.late_inc > 0 {
            self.reorder_late_delivered
                .fetch_add(delta.late_inc, Ordering::Relaxed);
        }
    }

    /// Drain any additional in-order packets released by gap-filling or timeout
    /// flushes into `out`.
    pub fn drain_ready_into(&self, out: &mut Vec<Vec<u8>>) {
        if !self.is_active() {
            return;
        }
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(pkt) = st.reorder.ready_overflow.pop_front() {
            out.push(pkt);
        }
        self.refresh_active_flag(&st);
    }

    /// Drain any additional in-order packets released by gap-filling or timeout
    /// flushes.
    pub fn drain_ready_packets(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        self.drain_ready_into(&mut out);
        out
    }

    /// Flush any out-of-order packets in [`MultipathReorderBuffer`] whose hold
    /// timeout has elapsed at `now`, returning all newly ready packets in
    /// ascending counter order.
    pub fn flush_expired_reorder(&self, now: Instant) -> Vec<Vec<u8>> {
        if !self.is_active() {
            return Vec::new();
        }
        let mut delta = ReorderStatsDelta {
            buffered_inc: 0,
            in_order_inc: 0,
            reordered_inc: 0,
            timeout_flushed_inc: 0,
            capacity_flushed_inc: 0,
            late_inc: 0,
        };
        let mut out = Vec::new();
        {
            let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !st.reorder.buffered.is_empty() {
                st.reorder.flush_expired(now, &mut delta);
            }
            while let Some(pkt) = st.reorder.ready_overflow.pop_front() {
                out.push(pkt);
            }
            self.refresh_active_flag(&st);
        }
        self.apply_reorder_delta(&delta);
        out
    }

    /// Lazily spawn and retain the background reorder-flush task if not already
    /// running for this peer. Called only when multipath is configured or a
    /// secondary leg is attached, avoiding background task overhead for default
    /// single-path peers.
    pub fn ensure_reorder_flush_task(self: &Arc<Self>, tun_tx: tokio::sync::mpsc::Sender<Vec<u8>>) {
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if st
            .reorder_flush_task
            .as_ref()
            .is_none_or(|t| t.is_finished())
        {
            st.reorder_flush_task = Some(self.spawn_reorder_flush_task(tun_tx));
        }
    }

    /// Spawn a background task that wakes whenever a packet is parked in the
    /// reorder buffer (or flushed into `ready_overflow` on mode change) and
    /// flushes it to `tun_tx` as soon as `reorder_hold_timeout` expires (even if
    /// no subsequent packet arrives).
    ///
    /// Never holds a strong `Arc<PeerMultipathState>` across an `.await`, so
    /// dropping the last external `Arc<PeerMultipathState>` wakes `reorder_notify`
    /// and causes this task to exit immediately via `Weak::upgrade() == None`.
    pub fn spawn_reorder_flush_task(
        self: &Arc<Self>,
        tun_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    ) -> JoinHandle<()> {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let Some(mp) = weak.upgrade() else {
                    break;
                };
                let (has_overflow, next_deadline, notify) = {
                    let st = mp.inner.lock().unwrap_or_else(|e| e.into_inner());
                    (
                        !st.reorder.ready_overflow.is_empty(),
                        st.reorder.next_expiry(),
                        mp.reorder_notify.clone(),
                    )
                };
                if has_overflow {
                    let ready = mp.flush_expired_reorder(Instant::now());
                    drop(mp);
                    for pkt in ready {
                        if tun_tx.send(pkt).await.is_err() {
                            return;
                        }
                    }
                    continue;
                }
                match next_deadline {
                    Some(deadline) => {
                        let now = Instant::now();
                        drop(mp);
                        if deadline > now {
                            tokio::select! {
                                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {}
                                _ = notify.notified() => {}
                            }
                        }
                        let Some(mp) = weak.upgrade() else {
                            break;
                        };
                        let ready = mp.flush_expired_reorder(Instant::now());
                        drop(mp);
                        for pkt in ready {
                            if tun_tx.send(pkt).await.is_err() {
                                return;
                            }
                        }
                    }
                    None => {
                        drop(mp);
                        // Park with zero strong reference held until an out-of-order packet
                        // enters the buffer or PeerMultipathState is dropped.
                        notify.notified().await;
                    }
                }
            }
        })
    }

    /// Snapshot per-peer and per-leg multipath telemetry.
    pub fn snapshot(&self, primary_carrier: &Arc<Carrier>) -> MultipathPeerSnapshot {
        let st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut legs = Vec::with_capacity(1 + st.legs.len());
        legs.push(self.primary_counters.snapshot(0, primary_carrier.is_dead()));
        for leg in &st.legs {
            legs.push(leg.counters.snapshot(leg.leg_id, leg.carrier.is_dead()));
        }
        MultipathPeerSnapshot {
            mode: st.config.mode,
            active_tx_leg_id: self.active_tx_leg_id.load(Ordering::Relaxed),
            failover_switches: self.failover_switches.load(Ordering::Relaxed),
            redundant_extra_tx_packets: self.redundant_extra_tx_packets.load(Ordering::Relaxed),
            dedup_dropped: self.dedup_dropped.load(Ordering::Relaxed),
            reorder_buffered: self.reorder_buffered.load(Ordering::Relaxed),
            reorder_in_order_delivered: self.reorder_in_order_delivered.load(Ordering::Relaxed),
            reorder_reordered_delivered: self.reorder_reordered_delivered.load(Ordering::Relaxed),
            reorder_timeout_flushed: self.reorder_timeout_flushed.load(Ordering::Relaxed),
            reorder_capacity_flushed: self.reorder_capacity_flushed.load(Ordering::Relaxed),
            reorder_late_delivered: self.reorder_late_delivered.load(Ordering::Relaxed),
            reorder_current_depth: st.reorder.buffered_data_count(),
            legs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_type4_packet(session: u32, counter: u64, payload: &[u8], tag_seed: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + payload.len() + 16);
        out.extend_from_slice(&[4, 0, 0, 0]);
        out.extend_from_slice(&session.to_le_bytes());
        out.extend_from_slice(&counter.to_le_bytes());
        out.extend_from_slice(payload);
        let mut tag = [0u8; 16];
        for (i, b) in tag.iter_mut().enumerate() {
            *b = tag_seed.wrapping_add(i as u8).wrapping_mul(31) ^ (counter as u8);
        }
        out.extend_from_slice(&tag);
        out
    }

    #[tokio::test]
    async fn redundant_dedup_verifies_poly1305_tag_and_prevents_replay_amplification() {
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dst = sock.local_addr().unwrap();
        let primary = Carrier::direct(sock.clone(), dst);
        let sec = Carrier::direct(sock, dst);

        let mp = PeerMultipathState::new(MultipathConfig::new(MultipathMode::Redundant));
        assert!(mp.upsert_secondary_leg(1, sec, 10, 1, Vec::new()));

        let wire = make_type4_packet(7, 42, &[1, 2, 3, 4], 0x5a);

        // Before `post_decap_record`, `pre_decap_check` must return Proceed (never pre-populates).
        assert_eq!(mp.pre_decap_check(&wire, 0), PreDecapVerdict::Proceed);

        // Simulate `Tunn::decapsulate` succeeding on leg 0 (primary).
        let delivered = mp.post_decap_record(&wire, 0, Some(vec![0x45, 0x00, 0x01]));
        assert_eq!(delivered, Some(vec![0x45, 0x00, 0x01]));

        // A forged packet with the same (session=7, counter=42) and same length but a
        // different 16-byte Poly1305 tag on leg 1 must NOT be treated as an authentic
        // duplicate or credit leg 1's health!
        let mut forged = wire.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0x01;
        assert_eq!(mp.pre_decap_check(&forged, 1), PreDecapVerdict::Proceed);
        let snap_after_forged = mp.snapshot(&primary);
        assert_eq!(snap_after_forged.dedup_dropped, 0);
        assert_eq!(snap_after_forged.legs[1].rx_packets, 0);

        // DEFECT-B8-DEDUP-TAG-ONLY-01: a copied valid tag/header with a changed
        // ciphertext body is NOT an authenticated duplicate. It must fall
        // through to normal AEAD and cannot earn any leg receive accounting.
        let mut copied_tag_forgery = wire.clone();
        copied_tag_forgery[16] ^= 0x80;
        assert_eq!(
            mp.pre_decap_check(&copied_tag_forgery, 1),
            PreDecapVerdict::Proceed
        );
        let after_copied_tag = mp.snapshot(&primary);
        assert_eq!(after_copied_tag.dedup_dropped, 0);
        assert_eq!(after_copied_tag.legs[1].rx_packets, 0);
        assert_eq!(after_copied_tag.legs[1].rx_dedup_hits, 0);

        // Now the genuine redundant copy arrives on leg 1: tag matches in constant time,
        // packet is deduplicated, and leg 1 is credited once.
        assert_eq!(
            mp.pre_decap_check(&wire, 1),
            PreDecapVerdict::AuthenticatedDuplicate { first_on_leg: true }
        );
        let snap1 = mp.snapshot(&primary);
        assert_eq!(snap1.dedup_dropped, 1);
        assert_eq!(snap1.legs[1].rx_packets, 1);
        assert_eq!(snap1.legs[1].rx_dedup_hits, 1);

        // Replaying the exact same authentic packet again on leg 1 is still dropped,
        // but `first_on_leg` is false and leg 1's rx counter is NOT incremented again.
        assert_eq!(
            mp.pre_decap_check(&wire, 1),
            PreDecapVerdict::AuthenticatedDuplicate {
                first_on_leg: false
            }
        );
        let snap2 = mp.snapshot(&primary);
        assert_eq!(snap2.dedup_dropped, 2);
        assert_eq!(snap2.legs[1].rx_packets, 1);
        assert_eq!(snap2.legs[1].rx_dedup_hits, 1);
    }

    #[tokio::test]
    async fn aggregate_reorder_buffer_restores_counter_order_and_flushes_on_timeout() {
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dst = sock.local_addr().unwrap();
        let primary = Carrier::direct(sock.clone(), dst);
        let sec = Carrier::direct(sock, dst);

        let cfg = MultipathConfig::new(MultipathMode::Aggregate)
            .with_max_reorder_depth(8)
            .with_reorder_hold_timeout(Duration::from_millis(20));
        let mp = PeerMultipathState::new(cfg);
        assert!(mp.upsert_secondary_leg(1, sec, 10, 1, Vec::new()));

        let w0 = make_type4_packet(11, 0, &[0], 1);
        let w1 = make_type4_packet(11, 1, &[1], 2);
        let w2 = make_type4_packet(11, 2, &[2], 3);
        let w4 = make_type4_packet(11, 4, &[4], 5);

        // Counter 1 and Counter 2 arrive before Counter 0 (asymmetric leg RTT):
        assert_eq!(mp.post_decap_record(&w2, 0, Some(vec![2])), None);
        assert_eq!(mp.post_decap_record(&w1, 1, Some(vec![1])), None);
        assert_eq!(mp.snapshot(&primary).reorder_current_depth, 2);

        // Now Counter 0 arrives: releases [0, 1, 2] in strict ascending counter order!
        let first = mp.post_decap_record(&w0, 0, Some(vec![0]));
        let mut all = vec![first.expect("counter 0 ready")];
        all.extend(mp.drain_ready_packets());
        assert_eq!(all, vec![vec![0], vec![1], vec![2]]);
        assert_eq!(mp.snapshot(&primary).reorder_current_depth, 0);

        // Counter 3 is lost; Counter 4 arrives and is parked waiting for Counter 3.
        assert_eq!(mp.post_decap_record(&w4, 0, Some(vec![4])), None);
        assert_eq!(mp.snapshot(&primary).reorder_current_depth, 1);

        // After reorder_hold_timeout (20 ms), flush_expired_reorder releases Counter 4.
        tokio::time::sleep(Duration::from_millis(25)).await;
        let flushed = mp.flush_expired_reorder(Instant::now());
        assert_eq!(flushed, vec![vec![4]]);
        let snap = mp.snapshot(&primary);
        assert_eq!(snap.reorder_timeout_flushed, 1);
        assert_eq!(snap.reorder_current_depth, 0);
    }

    #[tokio::test]
    async fn aggregate_reorder_handles_out_of_order_keepalives_and_mode_switch_flush() {
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dst = sock.local_addr().unwrap();
        let primary = Carrier::direct(sock.clone(), dst);
        let sec = Carrier::direct(sock, dst);

        let cfg = MultipathConfig::new(MultipathMode::Aggregate)
            .with_max_reorder_depth(16)
            .with_reorder_hold_timeout(Duration::from_millis(100));
        let mp = Arc::new(PeerMultipathState::new(cfg));
        assert!(mp.upsert_secondary_leg(1, sec, 10, 1, Vec::new()));
        let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel(16);
        let flush_task = mp.spawn_reorder_flush_task(tun_tx);

        let w0 = make_type4_packet(21, 0, &[0], 1);
        let w1_ka = make_type4_packet(21, 1, &[], 2);
        let w2 = make_type4_packet(21, 2, &[2], 3);
        let w4 = make_type4_packet(21, 4, &[4], 5);

        // Out-of-order keepalive (#1) and data (#2) arrive BEFORE data (#0):
        assert_eq!(mp.post_decap_record(&w1_ka, 1, None), None);
        assert_eq!(mp.post_decap_record(&w2, 1, Some(vec![2])), None);
        // Only data packets count toward reorder_current_depth:
        assert_eq!(mp.snapshot(&primary).reorder_current_depth, 1);

        // When data (#0) arrives on slow leg 0, it must step across keepalive (#1)
        // and immediately release both [0] and [2] without waiting for hold_timeout!
        let first = mp.post_decap_record(&w0, 0, Some(vec![0]));
        let mut released = vec![first.expect("counter 0 ready")];
        released.extend(mp.drain_ready_packets());
        assert_eq!(released, vec![vec![0], vec![2]]);

        // Park packet #4 (gap at #3), then dynamically switch mode to Off:
        // set_config must flush #4 into ready_overflow and wake spawn_reorder_flush_task.
        assert_eq!(mp.post_decap_record(&w4, 1, Some(vec![4])), None);
        mp.set_config(MultipathConfig::new(MultipathMode::Off));
        let flushed_pkt = tokio::time::timeout(Duration::from_millis(200), tun_rx.recv())
            .await
            .expect(
                "mode switch away from Aggregate must wake flush task and deliver parked packet",
            )
            .unwrap();
        assert_eq!(flushed_pkt, vec![4]);
        flush_task.abort();
    }

    #[tokio::test]
    async fn single_path_without_healthy_secondary_leg_stays_inactive_and_never_buffers_loss_and_flush_task_exits_on_drop()
     {
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dst = sock.local_addr().unwrap();
        let primary = Carrier::direct(sock.clone(), dst);
        let sec = Carrier::direct(sock, dst);

        // 1. Default state is Off and inactive.
        let mp_default = PeerMultipathState::default();
        assert_eq!(mp_default.mode(), MultipathMode::Off);
        assert!(!mp_default.is_active());

        // 2. Configuring Aggregate without any secondary leg attached MUST stay inactive
        // (`!mp.is_active()`), so a lost counter (#0) on a single link never parks #1 in
        // `MultipathReorderBuffer` for 25 ms!
        let cfg = MultipathConfig::new(MultipathMode::Aggregate)
            .with_reorder_hold_timeout(Duration::from_millis(250));
        let mp = Arc::new(PeerMultipathState::new(cfg));
        assert!(!mp.is_active());
        let w1 = make_type4_packet(31, 1, &[1], 2);
        assert_eq!(
            mp.post_decap_record(&w1, 0, Some(vec![1])),
            Some(vec![1]),
            "Aggregate without a secondary leg must deliver packets immediately without reorder buffering"
        );
        assert_eq!(mp.snapshot(&primary).reorder_buffered, 0);

        // 3. Attaching a healthy secondary leg activates Aggregate mode; marking that
        // secondary leg unhealthy immediately flushes parked packets and deactivates!
        assert!(mp.upsert_secondary_leg(1, sec, 10, 1, Vec::new()));
        assert!(mp.is_active());
        let w3 = make_type4_packet(31, 3, &[3], 4);
        assert_eq!(mp.post_decap_record(&w3, 1, Some(vec![3])), None);
        assert_eq!(mp.snapshot(&primary).reorder_current_depth, 1);

        let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel(16);
        let flush_task = mp.spawn_reorder_flush_task(tun_tx);
        assert!(mp.set_leg_healthy(1, false));
        let flushed = tokio::time::timeout(Duration::from_millis(200), tun_rx.recv())
            .await
            .expect("marking sole secondary leg unhealthy must immediately flush parked packets")
            .unwrap();
        assert_eq!(flushed, vec![3]);
        assert!(
            !mp.is_active(),
            "must become inactive once sole secondary leg is unhealthy and overflow drains"
        );

        // 4. Dropping the last external `Arc<PeerMultipathState>` must wake `reorder_notify`
        // and cause `spawn_reorder_flush_task` to exit cleanly without `abort()`.
        drop(mp);
        tokio::time::timeout(Duration::from_millis(200), flush_task)
            .await
            .expect("spawn_reorder_flush_task must exit when last external Arc<PeerMultipathState> is dropped")
            .expect("task panicked");
    }

    #[tokio::test]
    async fn aggregate_weighted_round_robin_distributes_by_configured_weights() {
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dst = sock.local_addr().unwrap();
        let primary = Carrier::direct(sock.clone(), dst);
        let sec1 = Carrier::direct(sock.clone(), dst);
        let sec2 = Carrier::direct(sock, dst);

        // Primary weight = 3, Secondary leg 1 weight = 2, Secondary leg 2 weight = 1 (total = 6).
        let cfg = MultipathConfig::new(MultipathMode::Aggregate).with_primary_weight(3);
        let mp = PeerMultipathState::new(cfg);
        assert!(mp.upsert_secondary_leg(1, sec1, 10, 2, Vec::new()));
        assert!(mp.upsert_secondary_leg(2, sec2, 20, 1, Vec::new()));

        let wire = make_type4_packet(1, 1, &[0x45, 0x00], 9);
        let mut counts = [0usize; 3];
        for _ in 0..60 {
            let targets = mp.select_tx_targets(&primary, &wire);
            let (chosen_leg, _) = targets.iter().next().expect("non-empty targets");
            counts[*chosen_leg as usize] += 1;
        }
        assert_eq!(counts[0], 30);
        assert_eq!(counts[1], 20);
        assert_eq!(counts[2], 10);
    }
}
