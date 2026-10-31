// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Optional post-quantum pre-shared key (PQ-PSK) negotiation and rotation for
//! WireGuard peers (Rosenpass-style out-of-band ML-KEM-768 key agreement).
//!
//! # Overview
//!
//! By default (`PqPskMode::Off`), MeshHarbor constructs WireGuard [`Tunn`]
//! instances with `preshared_key = None` and emits no PQ control frames.
//!
//! When enabled (`PqPskMode::Optional` or `PqPskMode::Required`), each peer
//! pair runs a four-step authenticated ML-KEM-768 (NIST FIPS 203) key
//! encapsulation handshake over the peer's existing [`Carrier`] (direct UDP,
//! TURN relay, or DERP/ORG relay):
//!
//! 1. **`KIND_INIT` (Initiator → Responder, 1282 B):**
//!    Carries a freshly generated ML-KEM-768 encapsulation key (`ek`, 1184 B),
//!    a 16-byte CSPRNG `init_nonce`, the requested `epoch`, and a 32-byte
//!    `HMAC-SHA256` tag keyed by the domain-separated static X25519 shared
//!    secret `X25519(self_secret, peer_public)`.
//! 2. **`KIND_RESP` (Responder → Initiator, 1202 B):**
//!    Responder verifies the MAC, encapsulates a fresh 32-byte post-quantum
//!    shared secret `(ct, k_pq)` against `ek`, generates a 16-byte CSPRNG
//!    `resp_nonce`, selects `effective_epoch = max(local_epoch + 1, init.epoch)`
//!    so single-peer restarts never roll the epoch backward, derives the hybrid
//!    `candidate_psk`, stores a bounded pending responder slot without touching
//!    the active [`Tunn`], and replies with `ct` (1088 B) + `mac`.
//! 3. **`KIND_CONFIRM` (Initiator → Responder, 114 B):**
//!    Initiator verifies `init_nonce` and the response MAC (which binds
//!    `SHA-256(ek)`), decapsulates `ct` to recover `k_pq`, derives the same
//!    `candidate_psk`, and sends a confirmation MAC keyed by `candidate_psk`
//!    over `(epoch, init_nonce, resp_nonce, initiator_pub, responder_pub)`.
//! 4. **`KIND_ACK` (Responder → Initiator, 114 B):**
//!    Responder verifies `confirm_mac` in constant time against its pending
//!    `candidate_psk`, installs `Some(candidate_psk)` into its [`Tunn`] before
//!    sending `KIND_ACK`, and replies. Upon receiving `KIND_ACK`, Initiator
//!    installs `Some(candidate_psk)` into its [`Tunn`] and immediately emits a
//!    WireGuard handshake initiation.
//!
//! # Security Properties
//!
//! - **Shape disjointness:** `"RMPQPSK1"` starts with `0x52` (`!∈ 1..=4`,
//!   disjoint from WireGuard), has `"PSK1"` at bytes `4..8` (`≠ 0x2112A442`,
//!   disjoint from STUN), and differs from `"RMDISCO1"` and `"RMDFOLL1"`.
//! - **Replay resistance:** Responder never mutates its active [`Tunn`] on
//!   `KIND_INIT`; commitment requires `KIND_CONFIRM` over Responder's fresh
//!   `resp_nonce`. Initiator requires `KIND_RESP` and `KIND_ACK` to match its
//!   live `init_nonce` and `resp_nonce`.
//! - **Fail-closed in `Required` mode:** Until PQ agreement succeeds (or after
//!   key expiration / mismatch), `Tunn` holds a per-peer CSPRNG guard PSK so
//!   classical `PSK=None` handshakes cannot complete.
//! - **Zero plaintext secret logging:** All key material (`psk`, `dk`, `k_pq`,
//!   `configured_psk`, `guard_psk`) is redacted in `Debug` implementations and
//!   never written to logs or control-plane messages.

use std::collections::VecDeque;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use hmac::{Hmac, Mac};
use ml_kem::{B32, DecapsulationKey768, EncapsulationKey768, KeyExport, Seed, kem::Decapsulate};
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::wg::{Carrier, PeerStats, WG_BUF};

type HmacSha256 = Hmac<Sha256>;

/// Wire magic for PQ-PSK control frames.
pub(crate) const MAGIC: &[u8; 8] = b"RMPQPSK1";

const KIND_INIT: u8 = 1;
const KIND_RESP: u8 = 2;
const KIND_REJECT: u8 = 3;
const KIND_CONFIRM: u8 = 4;
const KIND_ACK: u8 = 5;
const KIND_FRAG: u8 = 6;

const REJECT_MODE_OFF: u8 = 1;
const REJECT_INVALID_KEY: u8 = 2;
const REJECT_PSK_MISMATCH: u8 = 3;

const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;
const NONCE_LEN: usize = 16;
const PUBKEY_LEN: usize = 32;
const MAC_LEN: usize = 32;

const INIT_HEADER_LEN: usize = 8 + 1 + 1 + 8 + NONCE_LEN + PUBKEY_LEN; // 66
pub(crate) const INIT_FRAME_LEN: usize = INIT_HEADER_LEN + MLKEM768_EK_LEN + MAC_LEN; // 1282

const RESP_HEADER_LEN: usize = 8 + 1 + 1 + 8 + NONCE_LEN + NONCE_LEN + PUBKEY_LEN; // 82
pub(crate) const RESP_FRAME_LEN: usize = RESP_HEADER_LEN + MLKEM768_CT_LEN + MAC_LEN; // 1202

const REJECT_HEADER_LEN: usize = 8 + 1 + 1 + 8 + NONCE_LEN + 1 + PUBKEY_LEN; // 67
pub(crate) const REJECT_FRAME_LEN: usize = REJECT_HEADER_LEN + MAC_LEN; // 99

const CONFIRM_HEADER_LEN: usize = 8 + 1 + 1 + 8 + NONCE_LEN + NONCE_LEN + PUBKEY_LEN; // 82
pub(crate) const CONFIRM_FRAME_LEN: usize = CONFIRM_HEADER_LEN + MAC_LEN; // 114

/// Header layout of a `KIND_FRAG` datagram:
/// `MAGIC (8) + KIND_FRAG (1) + inner_kind (1) + frag_idx (1) + frag_total (1) + epoch (8) + msg_nonce (16) + sender_pub (32) = 68 B`.
const FRAG_HEADER_LEN: usize = 8 + 1 + 1 + 1 + 1 + 8 + NONCE_LEN + PUBKEY_LEN; // 68
/// Maximum payload carried in a single `KIND_FRAG` datagram (`<= 580 B`),
/// keeping the entire wire datagram (`68 + 580 + 32 = 680 B`) strictly under
/// 700 B so `KIND_INIT` (1282 B) and `KIND_RESP` (1202 B) traverse 1280 B IPv6
/// minimum-MTU, PPPoE, and double-encapsulated tunnel/relay paths without IP
/// fragmentation or DF drops.
pub(crate) const MAX_FRAG_PAYLOAD: usize = 580;
pub(crate) const MAX_WIRE_CONTROL_FRAME_LEN: usize = FRAG_HEADER_LEN + MAX_FRAG_PAYLOAD + MAC_LEN; // 680
const MAX_FRAG_TOTAL: u8 = 4;
const MAX_REASSEMBLY_SLOTS: usize = 4;

const MAX_PENDING_RESP: usize = 4;
const DEFAULT_REKEY_INTERVAL: Duration = Duration::from_secs(120);
const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(300);
const DEFAULT_RETRY_INTERVAL: Duration = Duration::from_millis(500);
const DEFAULT_MAX_RETRIES: u32 = 6;
const NON_PRIMARY_INITIAL_STAGGER: Duration = Duration::from_millis(120);
/// Periodic rekey stagger for the non-primary peer (`self_public > peer_public`):
/// set to `1_000 ms` (`4 × 250 ms` carrier timer ticks) so the primary peer's
/// `tick_timer` initiates periodic rotation at least 2 full timer ticks ahead
/// of the non-primary peer despite independent peer installation timestamps.
pub(crate) const NON_PRIMARY_REKEY_STAGGER: Duration = Duration::from_millis(1_000);

/// Operating mode for optional post-quantum WireGuard pre-shared keys.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PqPskMode {
    /// Default off: `Tunn` uses `preshared_key = None`; no PQ frames are sent.
    #[default]
    Off,
    /// Negotiates ML-KEM-768 PSK when the peer supports it; downgrades cleanly
    /// to classical `PSK=None` only on an authenticated `REJECT_MODE_OFF`.
    Optional,
    /// Requires ML-KEM-768 PSK agreement; locks `Tunn` with a fail-closed
    /// CSPRNG guard PSK until agreement succeeds and on mismatch/expiry.
    Required,
}

impl PqPskMode {
    pub fn parse(raw: Option<&str>) -> Self {
        let Some(v) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
            return Self::Off;
        };
        if v.eq_ignore_ascii_case("0")
            || v.eq_ignore_ascii_case("false")
            || v.eq_ignore_ascii_case("off")
            || v.eq_ignore_ascii_case("no")
        {
            Self::Off
        } else if v.eq_ignore_ascii_case("optional")
            || v.eq_ignore_ascii_case("opt")
            || v.eq_ignore_ascii_case("preferred")
            || v.eq_ignore_ascii_case("prefer")
        {
            Self::Optional
        } else if v.eq_ignore_ascii_case("1")
            || v.eq_ignore_ascii_case("true")
            || v.eq_ignore_ascii_case("on")
            || v.eq_ignore_ascii_case("yes")
            || v.eq_ignore_ascii_case("required")
            || v.eq_ignore_ascii_case("strict")
        {
            Self::Required
        } else {
            Self::Off
        }
    }

    pub fn from_env() -> Self {
        Self::parse(crate::env::node_env("OVERLAY_PQ_PSK").as_deref())
    }

    fn wire_byte(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Optional => 1,
            Self::Required => 2,
        }
    }

    fn from_wire_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Off),
            1 => Some(Self::Optional),
            2 => Some(Self::Required),
            _ => None,
        }
    }
}

/// Configuration for per-peer post-quantum PSK agreement and rotation.
#[derive(Clone)]
pub struct PqPskConfig {
    pub mode: PqPskMode,
    /// Optional additional static PSK mixed into the HKDF derivation alongside
    /// the ML-KEM-768 and X25519 shared secrets. Redacted in `Debug`.
    pub configured_psk: Option<[u8; 32]>,
    pub rekey_interval: Duration,
    pub max_lifetime: Duration,
    pub retry_interval: Duration,
    pub max_retries: u32,
}

impl Default for PqPskConfig {
    fn default() -> Self {
        Self {
            mode: PqPskMode::from_env(),
            configured_psk: None,
            rekey_interval: DEFAULT_REKEY_INTERVAL,
            max_lifetime: DEFAULT_MAX_LIFETIME,
            retry_interval: DEFAULT_RETRY_INTERVAL,
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }
}

impl fmt::Debug for PqPskConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqPskConfig")
            .field("mode", &self.mode)
            .field(
                "configured_psk",
                &self.configured_psk.as_ref().map(|_| "[REDACTED]"),
            )
            .field("rekey_interval", &self.rekey_interval)
            .field("max_lifetime", &self.max_lifetime)
            .field("retry_interval", &self.retry_interval)
            .field("max_retries", &self.max_retries)
            .finish()
    }
}

/// Observable status of a peer's post-quantum PSK lifecycle (never exposes key bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqPeerStatus {
    Disabled,
    Negotiating { epoch: u64 },
    Established { epoch: u64 },
    DowngradedToClassical,
    PeerMismatch,
    Expired { last_epoch: u64 },
    ExchangeFailed,
}

/// Non-sensitive telemetry snapshot for tests and diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PqPeerSnapshot {
    pub mode: PqPskMode,
    pub status: PqPeerStatus,
    pub current_epoch: u64,
    pub rotations_completed: u64,
    pub mismatch_count: u64,
    pub downgraded_count: u64,
    pub expired_count: u64,
    pub failed_exchanges: u64,
    /// Short non-reversible fingerprint (`SHA-256("meshharbor-pqpsk-fp" || psk)[..8]`)
    /// for verifying in tests that two peers derived the same key and that
    /// rotations changed the key, without exposing the raw PSK.
    pub psk_fingerprint: Option<[u8; 8]>,
}

/// Cheap pre-filter for PQ-PSK control frames on a carrier or demux socket.
pub(crate) fn is_pq_psk_shaped(pkt: &[u8]) -> bool {
    if pkt.len() < 9 || &pkt[..8] != MAGIC.as_slice() {
        return false;
    }
    match pkt[8] {
        KIND_INIT => pkt.len() == INIT_FRAME_LEN,
        KIND_RESP => pkt.len() == RESP_FRAME_LEN,
        KIND_REJECT => pkt.len() == REJECT_FRAME_LEN,
        KIND_CONFIRM | KIND_ACK => pkt.len() == CONFIRM_FRAME_LEN,
        KIND_FRAG => {
            pkt.len() > FRAG_HEADER_LEN + MAC_LEN && pkt.len() <= MAX_WIRE_CONTROL_FRAME_LEN
        }
        _ => false,
    }
}

/// Extract the sender's claimed static public key before verifying the MAC.
pub(crate) fn claimed_sender(pkt: &[u8]) -> Option<[u8; 32]> {
    if !is_pq_psk_shaped(pkt) {
        return None;
    }
    let off = match pkt[8] {
        KIND_INIT => 8 + 1 + 1 + 8 + NONCE_LEN,
        KIND_RESP | KIND_CONFIRM | KIND_ACK => 8 + 1 + 1 + 8 + NONCE_LEN + NONCE_LEN,
        KIND_REJECT => 8 + 1 + 1 + 8 + NONCE_LEN + 1,
        KIND_FRAG => 8 + 1 + 1 + 1 + 1 + 8 + NONCE_LEN,
        _ => return None,
    };
    pkt.get(off..off + PUBKEY_LEN)?.try_into().ok()
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rng().fill_bytes(&mut out);
    out
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub(crate) fn psk_fingerprint(psk: &[u8; 32]) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(b"meshharbor-pqpsk-v1-fingerprint");
    h.update(psk);
    let digest = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// Domain-separated static X25519 authentication key for PQ-PSK control frames.
fn static_auth_key(
    self_secret: &StaticSecret,
    self_public: &[u8; 32],
    peer_public: &[u8; 32],
) -> [u8; 32] {
    let dh = self_secret.diffie_hellman(&PublicKey::from(*peer_public));
    let (min_pub, max_pub) = if self_public < peer_public {
        (self_public, peer_public)
    } else {
        (peer_public, self_public)
    };
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(b"meshharbor-pqpsk-v1-static-auth").expect("hmac key");
    mac.update(dh.as_bytes());
    mac.update(min_pub);
    mac.update(max_pub);
    mac.finalize().into_bytes().into()
}

fn compute_mac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

fn verify_mac(key: &[u8; 32], parts: &[&[u8]], expected: &[u8; 32]) -> bool {
    let actual = compute_mac(key, parts);
    actual.ct_eq(expected).into()
}

/// Derive the 32-byte hybrid post-quantum WireGuard PSK from ML-KEM-768 shared
/// secret `k_pq`, static X25519 shared secret, optional configured static PSK,
/// and the full handshake transcript.
#[allow(clippy::too_many_arguments)]
fn derive_hybrid_psk(
    k_pq: &[u8],
    auth_key: &[u8; 32],
    configured_psk: Option<&[u8; 32]>,
    initiator_pub: &[u8; 32],
    responder_pub: &[u8; 32],
    epoch: u64,
    init_nonce: &[u8; 16],
    resp_nonce: &[u8; 16],
    ek_hash: &[u8; 32],
    ct_hash: &[u8; 32],
) -> [u8; 32] {
    // HKDF-Extract equivalent with domain separation
    let mut extract =
        <HmacSha256 as Mac>::new_from_slice(b"meshharbor-pqpsk-v1-hkdf-extract").expect("hmac key");
    extract.update(k_pq);
    extract.update(auth_key);
    if let Some(cfg) = configured_psk {
        extract.update(&[1u8]);
        extract.update(cfg);
    } else {
        extract.update(&[0u8]);
    }
    let prk: [u8; 32] = extract.finalize().into_bytes().into();

    // HKDF-Expand with full transcript binding
    let mut expand = <HmacSha256 as Mac>::new_from_slice(&prk).expect("hmac key");
    expand.update(b"meshharbor-pqpsk-v1-wg-psk");
    expand.update(initiator_pub);
    expand.update(responder_pub);
    expand.update(&epoch.to_be_bytes());
    expand.update(init_nonce);
    expand.update(resp_nonce);
    expand.update(ek_hash);
    expand.update(ct_hash);
    expand.update(&[0x01]);
    expand.finalize().into_bytes().into()
}

fn confirm_tag(
    candidate_psk: &[u8; 32],
    kind: u8,
    epoch: u64,
    init_nonce: &[u8; 16],
    resp_nonce: &[u8; 16],
    initiator_pub: &[u8; 32],
    responder_pub: &[u8; 32],
) -> [u8; 32] {
    let label: &[u8] = if kind == KIND_CONFIRM {
        b"meshharbor-pqpsk-v1-confirm"
    } else {
        b"meshharbor-pqpsk-v1-ack"
    };
    compute_mac(
        candidate_psk,
        &[
            label,
            &[kind],
            &epoch.to_be_bytes(),
            init_nonce,
            resp_nonce,
            initiator_pub,
            responder_pub,
        ],
    )
}

struct PendingInit {
    epoch: u64,
    init_nonce: [u8; 16],
    dk: Box<DecapsulationKey768>,
    ek_hash: [u8; 32],
    frame: Vec<u8>,
    last_sent: Instant,
    retries: u32,
}

impl fmt::Debug for PendingInit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingInit")
            .field("epoch", &self.epoch)
            .field("dk", &"[REDACTED]")
            .field("retries", &self.retries)
            .finish()
    }
}

struct PendingResp {
    epoch: u64,
    init_nonce: [u8; 16],
    resp_nonce: [u8; 16],
    candidate_psk: [u8; 32],
    resp_frame: Vec<u8>,
    created_at: Instant,
}

impl fmt::Debug for PendingResp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingResp")
            .field("epoch", &self.epoch)
            .field("candidate_psk", &"[REDACTED]")
            .finish()
    }
}

struct PendingConfirm {
    epoch: u64,
    init_nonce: [u8; 16],
    resp_nonce: [u8; 16],
    candidate_psk: [u8; 32],
    confirm_frame: Vec<u8>,
    last_sent: Instant,
    retries: u32,
}

impl fmt::Debug for PendingConfirm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingConfirm")
            .field("epoch", &self.epoch)
            .field("candidate_psk", &"[REDACTED]")
            .finish()
    }
}

struct CommittedAckCache {
    epoch: u64,
    init_nonce: [u8; 16],
    resp_nonce: [u8; 16],
    ack_frame: Vec<u8>,
}

struct FragReassemblySlot {
    inner_kind: u8,
    epoch: u64,
    msg_nonce: [u8; 16],
    frag_total: u8,
    chunks: Vec<Option<Vec<u8>>>,
}

struct PqPeerInner {
    config: PqPskConfig,
    status: PqPeerStatus,
    current_epoch: u64,
    active_psk: Option<[u8; 32]>,
    established_at: Option<Instant>,
    created_at: Instant,
    pending_init: Option<PendingInit>,
    pending_resps: VecDeque<PendingResp>,
    pending_confirm: Option<PendingConfirm>,
    pending_packets: VecDeque<Vec<u8>>,
    committed_init_nonces: VecDeque<[u8; NONCE_LEN]>,
    committed_acks: VecDeque<CommittedAckCache>,
    frag_reassembly: VecDeque<FragReassemblySlot>,
    rotations_completed: u64,
    mismatch_count: u64,
    downgraded_count: u64,
    expired_count: u64,
    failed_exchanges: u64,
}

const MAX_COMMITTED_INIT_NONCES: usize = 32;

fn record_committed_nonce(ring: &mut VecDeque<[u8; NONCE_LEN]>, nonce: [u8; NONCE_LEN]) {
    if !ring.contains(&nonce) {
        if ring.len() >= MAX_COMMITTED_INIT_NONCES {
            ring.pop_front();
        }
        ring.push_back(nonce);
    }
}

fn record_committed_ack(ring: &mut VecDeque<CommittedAckCache>, entry: CommittedAckCache) {
    ring.retain(|e| {
        !(e.epoch == entry.epoch
            && e.init_nonce == entry.init_nonce
            && e.resp_nonce == entry.resp_nonce)
    });
    if ring.len() >= MAX_COMMITTED_INIT_NONCES {
        ring.pop_front();
    }
    ring.push_back(entry);
}

impl fmt::Debug for PqPeerInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqPeerInner")
            .field("config", &self.config)
            .field("status", &self.status)
            .field("current_epoch", &self.current_epoch)
            .field(
                "active_psk",
                &self.active_psk.as_ref().map(|_| "[REDACTED]"),
            )
            .field("rotations_completed", &self.rotations_completed)
            .field("mismatch_count", &self.mismatch_count)
            .field("downgraded_count", &self.downgraded_count)
            .field("expired_count", &self.expired_count)
            .field("failed_exchanges", &self.failed_exchanges)
            .finish()
    }
}

#[derive(Clone)]
struct PqPeerBinding {
    tunn_index: u32,
    tunn: std::sync::Weak<Mutex<Tunn>>,
    carrier: std::sync::Weak<Carrier>,
    stats: std::sync::Weak<PeerStats>,
    initiate_when_ready: bool,
}

struct PqPeerBindings {
    primary: PqPeerBinding,
    shadow: Option<PqPeerBinding>,
}

/// Shared handle for one peer's PQ-PSK state machine and [`Tunn`] binding.
///
/// Holds [`std::sync::Weak`] references to `Tunn`, `Carrier`, and `PeerStats`
/// so storing `Arc<PqPeerHandle>` inside `PeerStats::pq` never forms an `Arc`
/// reference cycle and dropping `Peer` immediately releases `Tunn`.
/// When a make-before-break shadow direct probe (`probing == true`) is active,
/// the probe shares this same `PqPeerHandle` via `bindings.shadow` so both
/// primary and shadow `Tunn` instances use the negotiated ML-KEM-768 PSK and
/// promoting the probe preserves the active `epoch` and rotation state.
pub(crate) struct PqPeerHandle {
    mode: PqPskMode,
    self_public: [u8; 32],
    peer_public: [u8; 32],
    auth_key: [u8; 32],
    bindings: std::sync::RwLock<PqPeerBindings>,
    inner: Mutex<PqPeerInner>,
    /// Lock-free mirror of the last PSK installed into `Tunn` so a synchronous
    /// primary carrier rebuild (`rebind_primary`) can install the active PSK
    /// without awaiting `inner`.
    cached_tunn_psk: std::sync::Mutex<Option<[u8; 32]>>,
    /// Lock-free mirror of whether PQ-PSK is currently blocking classical
    /// handshakes (`Required` mode before PQ establishment).
    guard_active: std::sync::atomic::AtomicBool,
    epoch_atomic: AtomicU64,
}

impl fmt::Debug for PqPeerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tunn_index = self
            .bindings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .primary
            .tunn_index;
        f.debug_struct("PqPeerHandle")
            .field("peer_public", &short_hex(&self.peer_public))
            .field("tunn_index", &tunn_index)
            .field("epoch", &self.epoch_atomic.load(Ordering::Relaxed))
            .finish()
    }
}

fn short_hex(pk: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}", pk[0], pk[1], pk[2], pk[3])
}

impl PqPeerHandle {
    /// Compute the initial `preshared_key` argument for `Tunn::new` when a peer
    /// is installed.
    ///
    /// - `PqPskMode::Off`: `None` (classical WireGuard).
    /// - `PqPskMode::Optional`: `config.configured_psk` (`None` unless a static
    ///   fallback PSK was explicitly configured).
    /// - `PqPskMode::Required`: a freshly generated 32-byte CSPRNG guard PSK so
    ///   no classical `PSK=None` handshake can complete before ML-KEM-768
    ///   agreement succeeds.
    pub(crate) fn initial_tunn_psk(config: &PqPskConfig) -> Option<[u8; 32]> {
        match config.mode {
            PqPskMode::Off => None,
            PqPskMode::Optional => config.configured_psk,
            PqPskMode::Required => Some(random_bytes::<32>()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: PqPskConfig,
        self_secret: StaticSecret,
        self_public: [u8; 32],
        peer_public: [u8; 32],
        tunn_index: u32,
        _keepalive_secs: Option<u16>,
        tunn: Arc<Mutex<Tunn>>,
        carrier: Arc<Carrier>,
        stats: Arc<PeerStats>,
    ) -> Arc<Self> {
        let auth_key = static_auth_key(&self_secret, &self_public, &peer_public);
        let status = match config.mode {
            PqPskMode::Off => PqPeerStatus::Disabled,
            PqPskMode::Optional | PqPskMode::Required => PqPeerStatus::Negotiating { epoch: 1 },
        };
        let mode = config.mode;
        let guard_active = mode == PqPskMode::Required;
        let initial_psk = Self::initial_tunn_psk(&config);
        stats.pq_guard_active.store(guard_active, Ordering::Release);
        Arc::new(Self {
            mode,
            self_public,
            peer_public,
            auth_key,
            bindings: std::sync::RwLock::new(PqPeerBindings {
                primary: PqPeerBinding {
                    tunn_index,
                    tunn: Arc::downgrade(&tunn),
                    carrier: Arc::downgrade(&carrier),
                    stats: Arc::downgrade(&stats),
                    initiate_when_ready: false,
                },
                shadow: None,
            }),
            inner: Mutex::new(PqPeerInner {
                config,
                status,
                current_epoch: 0,
                active_psk: None,
                established_at: None,
                created_at: Instant::now(),
                pending_init: None,
                pending_resps: VecDeque::new(),
                pending_confirm: None,
                pending_packets: VecDeque::new(),
                committed_init_nonces: VecDeque::new(),
                committed_acks: VecDeque::new(),
                frag_reassembly: VecDeque::new(),
                rotations_completed: 0,
                mismatch_count: 0,
                downgraded_count: 0,
                expired_count: 0,
                failed_exchanges: 0,
            }),
            cached_tunn_psk: std::sync::Mutex::new(initial_psk),
            guard_active: std::sync::atomic::AtomicBool::new(guard_active),
            epoch_atomic: AtomicU64::new(0),
        })
    }

    fn set_guard_active(&self, active: bool) {
        self.guard_active.store(active, Ordering::Release);
        let (primary_stats, shadow_stats) = {
            let b = self.bindings.read().unwrap_or_else(|e| e.into_inner());
            (
                b.primary.stats.upgrade(),
                b.shadow.as_ref().and_then(|s| s.stats.upgrade()),
            )
        };
        if let Some(stats) = primary_stats {
            stats.pq_guard_active.store(active, Ordering::Release);
        }
        if let Some(stats) = shadow_stats {
            stats.pq_guard_active.store(active, Ordering::Release);
        }
    }

    pub(crate) fn set_carrier(&self, carrier: &Arc<Carrier>) {
        self.bindings
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .primary
            .carrier = Arc::downgrade(carrier);
    }

    fn upgrade_carrier(&self) -> Option<Arc<Carrier>> {
        self.bindings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .primary
            .carrier
            .upgrade()
    }

    /// Returns `true` if `stats` belongs to the primary peer binding (so a
    /// shadow probe's carrier timer does not double-tick `tick_timer`).
    pub(crate) fn is_primary_stats(&self, stats: &Arc<PeerStats>) -> bool {
        let b = self.bindings.read().unwrap_or_else(|e| e.into_inner());
        b.primary.stats.as_ptr() == Arc::as_ptr(stats)
    }

    /// Rebind the primary peer binding when the active carrier (`Peer`) in
    /// `WgDevice::peers` is rebuilt in-place (`add_peer` / `add_direct_peer`),
    /// preserving the shared `PqPeerHandle`, negotiated `active_psk`, and any
    /// in-flight shadow probe binding (`bindings.shadow`).
    pub(crate) fn rebind_primary(
        &self,
        tunn_index: u32,
        tunn: &Arc<Mutex<Tunn>>,
        carrier: &Arc<Carrier>,
        stats: &Arc<PeerStats>,
    ) {
        {
            let mut b = self.bindings.write().unwrap_or_else(|e| e.into_inner());
            b.primary = PqPeerBinding {
                tunn_index,
                tunn: Arc::downgrade(tunn),
                carrier: Arc::downgrade(carrier),
                stats: Arc::downgrade(stats),
                initiate_when_ready: false,
            };
        }
        let guard_active = self.guard_active.load(Ordering::Acquire);
        let psk = *self
            .cached_tunn_psk
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        stats.pq_guard_active.store(guard_active, Ordering::Release);
        if let Ok(mut t) = tunn.try_lock() {
            t.set_preshared_key(psk);
        }
    }

    /// Attach a shadow direct probe (`probing == true`) to this `PqPeerHandle`,
    /// registering `bindings.shadow` first and then reading `active_psk` and
    /// installing it into `tunn` under the `inner` lock so no concurrent
    /// rotation can slip between reading `active_psk` and registering the probe.
    pub(crate) async fn attach_shadow_probe(
        &self,
        tunn_index: u32,
        tunn: &Arc<Mutex<Tunn>>,
        carrier: &Arc<Carrier>,
        stats: &Arc<PeerStats>,
        initiate_when_ready: bool,
    ) {
        {
            let mut b = self.bindings.write().unwrap_or_else(|e| e.into_inner());
            b.shadow = Some(PqPeerBinding {
                tunn_index,
                tunn: Arc::downgrade(tunn),
                carrier: Arc::downgrade(carrier),
                stats: Arc::downgrade(stats),
                initiate_when_ready,
            });
        }
        let g = self.inner.lock().await;
        let guard_active = self.guard_active.load(Ordering::Acquire);
        let target_psk = if guard_active {
            Some(random_bytes::<32>())
        } else if let Some(active) = g.active_psk {
            Some(active)
        } else if matches!(g.status, PqPeerStatus::DowngradedToClassical) {
            None
        } else {
            Self::initial_tunn_psk(&g.config)
        };
        stats.pq_guard_active.store(guard_active, Ordering::Release);
        let mut t = tunn.lock().await;
        t.set_preshared_key(target_psk);
    }

    /// Promote the shadow direct probe to the primary binding of this
    /// `PqPeerHandle` when [`WgDevice::promote_direct_probe`] promotes the
    /// probe into `self.peers`.
    pub(crate) fn promote_shadow_to_primary(
        &self,
        tunn_index: u32,
        tunn: &Arc<Mutex<Tunn>>,
        carrier: &Arc<Carrier>,
        stats: &Arc<PeerStats>,
    ) {
        let guard = self.guard_active.load(Ordering::Acquire);
        stats.pq_guard_active.store(guard, Ordering::Release);
        let mut b = self.bindings.write().unwrap_or_else(|e| e.into_inner());
        b.primary = PqPeerBinding {
            tunn_index,
            tunn: Arc::downgrade(tunn),
            carrier: Arc::downgrade(carrier),
            stats: Arc::downgrade(stats),
            initiate_when_ready: false,
        };
        b.shadow = None;
    }

    /// Detach a discarded shadow direct probe when [`WgDevice::drop_direct_probe`]
    /// removes it without promotion.
    pub(crate) fn clear_shadow_probe(&self, stats: &Arc<PeerStats>) {
        let mut b = self.bindings.write().unwrap_or_else(|e| e.into_inner());
        if b.shadow
            .as_ref()
            .is_some_and(|s| s.stats.as_ptr() == Arc::as_ptr(stats))
        {
            b.shadow = None;
        }
    }

    /// Buffer an outbound IP packet while initial `Required`-mode PQ negotiation
    /// is in progress; returns `false` if the peer is in `PeerMismatch`,
    /// `Expired`, or `ExchangeFailed`.
    pub(crate) async fn buffer_outbound_if_negotiating(&self, packet: &[u8]) -> bool {
        let mut g = self.inner.lock().await;
        if matches!(g.status, PqPeerStatus::Negotiating { .. }) {
            if g.pending_packets.len() < 32 {
                g.pending_packets.push_back(packet.to_vec());
            }
            true
        } else {
            false
        }
    }

    pub(crate) fn is_primary_initiator(&self) -> bool {
        self.self_public < self.peer_public
    }

    pub(crate) fn should_defer_initial_wg_handshake(&self) -> bool {
        self.guard_active.load(Ordering::Relaxed)
    }

    pub(crate) async fn snapshot(&self) -> PqPeerSnapshot {
        let g = self.inner.lock().await;
        PqPeerSnapshot {
            mode: g.config.mode,
            status: g.status,
            current_epoch: g.current_epoch,
            rotations_completed: g.rotations_completed,
            mismatch_count: g.mismatch_count,
            downgraded_count: g.downgraded_count,
            expired_count: g.expired_count,
            failed_exchanges: g.failed_exchanges,
            psk_fingerprint: g.active_psk.as_ref().map(psk_fingerprint),
        }
    }

    /// Start the initial `epoch = 1` PQ-PSK exchange only if no exchange has
    /// started or completed yet. Safe to call after a startup stagger delay
    /// without causing a spurious `epoch = 2` rotation if the peer already
    /// drove `epoch = 1` to completion.
    pub(crate) async fn start_initial(&self) -> bool {
        if self.mode == PqPskMode::Off {
            return false;
        }
        let frame = {
            let mut g = self.inner.lock().await;
            if g.config.mode == PqPskMode::Off
                || g.current_epoch > 0
                || g.pending_init.is_some()
                || g.pending_confirm.is_some()
                || !g.pending_resps.is_empty()
                || matches!(
                    g.status,
                    PqPeerStatus::DowngradedToClassical | PqPeerStatus::PeerMismatch
                )
            {
                None
            } else {
                Some(self.build_init_locked(&mut g, 1))
            }
        };
        if let Some(bytes) = frame
            && let Some(carrier) = self.upgrade_carrier()
        {
            self.send_control_frame(&carrier, &bytes).await;
            true
        } else {
            false
        }
    }

    /// Explicitly trigger an immediate post-quantum PSK exchange / rotation
    /// toward this peer. Returns `false` when PQ-PSK mode is `Off`.
    pub(crate) async fn start_or_rotate(&self) -> bool {
        if self.mode == PqPskMode::Off {
            return false;
        }
        let frame = {
            let mut g = self.inner.lock().await;
            if g.config.mode == PqPskMode::Off {
                return false;
            }
            g.pending_confirm = None;
            let next_epoch = g.current_epoch.saturating_add(1);
            Some(self.build_init_locked(&mut g, next_epoch))
        };
        if let Some(bytes) = frame
            && let Some(carrier) = self.upgrade_carrier()
        {
            self.send_control_frame(&carrier, &bytes).await;
            true
        } else {
            false
        }
    }

    /// Periodic timer hook driven by the peer's 250 ms timer task.
    pub(crate) async fn tick_timer(&self) {
        if self.mode == PqPskMode::Off {
            return;
        }
        let mut to_send: Option<Vec<u8>> = None;
        let mut lock_guard_psk: Option<[u8; 32]> = None;

        {
            let mut g = self.inner.lock().await;
            if g.config.mode == PqPskMode::Off {
                return;
            }

            // 1. Check key expiration (max_lifetime)
            if let Some(est_at) = g.established_at
                && est_at.elapsed() >= g.config.max_lifetime
            {
                let last_epoch = g.current_epoch;
                g.established_at = None;
                g.active_psk = None;
                g.pending_init = None;
                g.pending_confirm = None;
                g.expired_count = g.expired_count.saturating_add(1);
                g.status = PqPeerStatus::Expired { last_epoch };
                g.pending_packets.clear();
                self.set_guard_active(g.config.mode == PqPskMode::Required);
                if g.config.mode == PqPskMode::Required {
                    lock_guard_psk = Some(random_bytes::<32>());
                }
                warn!(
                    peer = %short_hex(&self.peer_public),
                    last_epoch,
                    "overlay pq-psk: key lifetime expired; rotating session"
                );
                let next_epoch = g.current_epoch.saturating_add(1);
                to_send = Some(self.build_init_locked(&mut g, next_epoch));
            } else if !matches!(
                g.status,
                PqPeerStatus::DowngradedToClassical | PqPeerStatus::PeerMismatch
            ) {
                // 2. Service in-flight retransmissions (both initial and rotation)
                let retry_interval = g.config.retry_interval;
                let max_retries = g.config.max_retries;
                let resp_ttl = retry_interval.saturating_mul(max_retries.saturating_add(1));
                g.pending_resps
                    .retain(|r| r.created_at.elapsed() < resp_ttl);

                if let Some(conf) = g.pending_confirm.as_mut() {
                    if conf.last_sent.elapsed() >= retry_interval {
                        if conf.retries < max_retries {
                            conf.retries += 1;
                            conf.last_sent = Instant::now();
                            to_send = Some(conf.confirm_frame.clone());
                        } else {
                            let failed_epoch = conf.epoch;
                            g.pending_confirm = None;
                            g.failed_exchanges = g.failed_exchanges.saturating_add(1);
                            if g.established_at.is_none() {
                                g.status = PqPeerStatus::ExchangeFailed;
                            }
                            warn!(
                                peer = %short_hex(&self.peer_public),
                                epoch = failed_epoch,
                                stage = "confirm",
                                failed_exchanges = g.failed_exchanges,
                                "overlay pq-psk: exchange confirmation timed out after max retries"
                            );
                            if g.established_at.is_some() {
                                let next_epoch = g.current_epoch.saturating_add(1);
                                to_send = Some(self.build_init_locked(&mut g, next_epoch));
                            }
                        }
                    }
                } else if let Some(init) = g.pending_init.as_mut() {
                    if init.last_sent.elapsed() >= retry_interval {
                        if init.retries < max_retries {
                            init.retries += 1;
                            init.last_sent = Instant::now();
                            to_send = Some(init.frame.clone());
                        } else {
                            let failed_epoch = init.epoch;
                            g.pending_init = None;
                            g.failed_exchanges = g.failed_exchanges.saturating_add(1);
                            if g.established_at.is_none() {
                                g.status = PqPeerStatus::ExchangeFailed;
                            }
                            warn!(
                                peer = %short_hex(&self.peer_public),
                                epoch = failed_epoch,
                                stage = "init",
                                failed_exchanges = g.failed_exchanges,
                                "overlay pq-psk: exchange initiation timed out after max retries"
                            );
                            if g.established_at.is_some() {
                                let next_epoch = g.current_epoch.saturating_add(1);
                                to_send = Some(self.build_init_locked(&mut g, next_epoch));
                            }
                        }
                    }
                } else if let Some(est_at) = g.established_at {
                    // 3. Check periodic rekey / rotation (rekey_interval)
                    // Do not start a competing periodic rotation while an inbound
                    // responder exchange (`pending_resps`) is already in flight.
                    if g.pending_resps.is_empty() {
                        let stagger = if self.is_primary_initiator() {
                            Duration::ZERO
                        } else {
                            NON_PRIMARY_REKEY_STAGGER
                        };
                        if est_at.elapsed() >= g.config.rekey_interval.saturating_add(stagger) {
                            let next_epoch = g.current_epoch.saturating_add(1);
                            to_send = Some(self.build_init_locked(&mut g, next_epoch));
                        }
                    }
                } else {
                    // 4. Initial negotiation
                    let ready = self.is_primary_initiator()
                        || g.created_at.elapsed() >= NON_PRIMARY_INITIAL_STAGGER;
                    if ready {
                        let next_epoch = g.current_epoch.saturating_add(1);
                        to_send = Some(self.build_init_locked(&mut g, next_epoch));
                    }
                }
            }
        }

        if let Some(guard_psk) = lock_guard_psk {
            self.reinstall_tunn_psk(Some(guard_psk), true, false, Vec::new(), None)
                .await;
        }
        if let Some(bytes) = to_send
            && let Some(carrier) = self.upgrade_carrier()
        {
            self.send_control_frame(&carrier, &bytes).await;
        }
    }

    /// Split any oversized `RMPQPSK1` frame (`KIND_INIT` 1282 B, `KIND_RESP` 1202 B)
    /// into authenticated `KIND_FRAG` datagrams (`<= 680 B` each) so every wire
    /// packet fits comfortably inside a 1280 B IPv6/tunnel MTU even with UDP,
    /// IPv6, TURN, or DERP headers. Small control frames (`KIND_CONFIRM`,
    /// `KIND_ACK`, `KIND_REJECT`, all `<= 114 B`) are returned as a single frame.
    pub(crate) fn fragment_control_frame(&self, frame: &[u8]) -> Vec<Vec<u8>> {
        if frame.len() <= MAX_WIRE_CONTROL_FRAME_LEN {
            return vec![frame.to_vec()];
        }
        let inner_kind = frame[8];
        let epoch_bytes = &frame[10..18];
        let msg_nonce = match inner_kind {
            KIND_INIT => &frame[18..34],
            KIND_RESP => &frame[34..50],
            _ => return vec![frame.to_vec()],
        };
        let chunks: Vec<&[u8]> = frame.chunks(MAX_FRAG_PAYLOAD).collect();
        let frag_total = chunks.len() as u8;
        debug_assert!((2..=MAX_FRAG_TOTAL).contains(&frag_total));

        let mut out = Vec::with_capacity(chunks.len());
        for (idx, chunk) in chunks.into_iter().enumerate() {
            let mut pkt = Vec::with_capacity(FRAG_HEADER_LEN + chunk.len() + MAC_LEN);
            pkt.extend_from_slice(MAGIC);
            pkt.push(KIND_FRAG);
            pkt.push(inner_kind);
            pkt.push(idx as u8);
            pkt.push(frag_total);
            pkt.extend_from_slice(epoch_bytes);
            pkt.extend_from_slice(msg_nonce);
            pkt.extend_from_slice(&self.self_public);
            pkt.extend_from_slice(chunk);
            let mac = compute_mac(
                &self.auth_key,
                &[b"meshharbor-pqpsk-v1-frag", pkt.as_slice()],
            );
            pkt.extend_from_slice(&mac);
            debug_assert!(pkt.len() <= MAX_WIRE_CONTROL_FRAME_LEN);
            out.push(pkt);
        }
        out
    }

    async fn send_control_frame(&self, carrier: &Arc<Carrier>, frame: &[u8]) {
        for pkt in self.fragment_control_frame(frame) {
            let _ = carrier.send_disco(&pkt).await;
        }
    }

    fn build_init_locked(&self, g: &mut PqPeerInner, epoch: u64) -> Vec<u8> {
        let seed_bytes = random_bytes::<64>();
        let dk = Box::new(DecapsulationKey768::from_seed(Seed::from(seed_bytes)));
        let ek_bytes = dk.encapsulation_key().to_bytes();
        let ek_slice: &[u8] = ek_bytes.as_slice();
        let ek_hash = sha256_bytes(ek_slice);
        let init_nonce = random_bytes::<NONCE_LEN>();
        let mode_byte = g.config.mode.wire_byte();

        let mut frame = Vec::with_capacity(INIT_FRAME_LEN);
        frame.extend_from_slice(MAGIC);
        frame.push(KIND_INIT);
        frame.push(mode_byte);
        frame.extend_from_slice(&epoch.to_be_bytes());
        frame.extend_from_slice(&init_nonce);
        frame.extend_from_slice(&self.self_public);
        frame.extend_from_slice(ek_slice);
        let mac = compute_mac(&self.auth_key, &[&frame]);
        frame.extend_from_slice(&mac);
        debug_assert_eq!(frame.len(), INIT_FRAME_LEN);

        if g.current_epoch == 0 {
            g.status = PqPeerStatus::Negotiating { epoch };
        }
        g.pending_init = Some(PendingInit {
            epoch,
            init_nonce,
            dk,
            ek_hash,
            frame: frame.clone(),
            last_sent: Instant::now(),
            retries: 0,
        });
        frame
    }

    fn build_reject_frame(
        &self,
        mode: PqPskMode,
        epoch: u64,
        init_nonce: &[u8; 16],
        reason: u8,
    ) -> Vec<u8> {
        let mut frame = Vec::with_capacity(REJECT_FRAME_LEN);
        frame.extend_from_slice(MAGIC);
        frame.push(KIND_REJECT);
        frame.push(mode.wire_byte());
        frame.extend_from_slice(&epoch.to_be_bytes());
        frame.extend_from_slice(init_nonce);
        frame.push(reason);
        frame.extend_from_slice(&self.self_public);
        let mac = compute_mac(&self.auth_key, &[&frame]);
        frame.extend_from_slice(&mac);
        debug_assert_eq!(frame.len(), REJECT_FRAME_LEN);
        frame
    }

    /// Process an inbound `RMPQPSK1` frame on this peer's state machine and
    /// send any response over `reply_carrier`.
    pub(crate) async fn handle_inbound(&self, pkt: &[u8], reply_carrier: &Arc<Carrier>) {
        if !is_pq_psk_shaped(pkt) {
            return;
        }
        if claimed_sender(pkt).as_ref() != Some(&self.peer_public) {
            return;
        }
        match pkt[8] {
            KIND_INIT => self.on_init(pkt, reply_carrier).await,
            KIND_RESP => self.on_resp(pkt, reply_carrier).await,
            KIND_REJECT => self.on_reject(pkt, reply_carrier).await,
            KIND_CONFIRM => self.on_confirm(pkt, reply_carrier).await,
            KIND_ACK => self.on_ack(pkt, reply_carrier).await,
            KIND_FRAG => self.on_frag(pkt, reply_carrier).await,
            _ => {}
        }
    }

    async fn on_frag(&self, pkt: &[u8], reply_carrier: &Arc<Carrier>) {
        if pkt.len() <= FRAG_HEADER_LEN + MAC_LEN || pkt.len() > MAX_WIRE_CONTROL_FRAME_LEN {
            return;
        }
        let inner_kind = pkt[9];
        let frag_idx = pkt[10];
        let frag_total = pkt[11];
        if !matches!(inner_kind, KIND_INIT | KIND_RESP)
            || !(2..=MAX_FRAG_TOTAL).contains(&frag_total)
            || frag_idx >= frag_total
        {
            return;
        }
        let epoch = u64::from_be_bytes(pkt[12..20].try_into().expect("len"));
        if epoch == 0 {
            return;
        }
        let msg_nonce: [u8; 16] = pkt[20..36].try_into().expect("len");
        let body = &pkt[..pkt.len() - MAC_LEN];
        let mac_bytes: [u8; 32] = pkt[pkt.len() - MAC_LEN..].try_into().expect("len");
        // Authenticate the individual fragment before locking or allocating in
        // `frag_reassembly` so unauthenticated packets cannot consume memory.
        if !verify_mac(
            &self.auth_key,
            &[b"meshharbor-pqpsk-v1-frag", body],
            &mac_bytes,
        ) {
            return;
        }
        let chunk = &pkt[FRAG_HEADER_LEN..pkt.len() - MAC_LEN];

        let reassembled = {
            let mut g = self.inner.lock().await;
            if g.config.mode == PqPskMode::Off && inner_kind != KIND_INIT {
                return;
            }
            if inner_kind == KIND_INIT {
                if (epoch < g.current_epoch && epoch != 1)
                    || g.committed_init_nonces.contains(&msg_nonce)
                {
                    return;
                }
            } else if inner_kind == KIND_RESP {
                let matches_pending_init =
                    g.pending_init.as_ref().is_some_and(|p| epoch >= p.epoch);
                let matches_pending_confirm = g
                    .pending_confirm
                    .as_ref()
                    .is_some_and(|c| c.epoch == epoch && c.resp_nonce == msg_nonce);
                if epoch <= g.current_epoch || (!matches_pending_init && !matches_pending_confirm) {
                    return;
                }
            }
            let pos = g.frag_reassembly.iter().position(|s| {
                s.inner_kind == inner_kind
                    && s.epoch == epoch
                    && s.msg_nonce == msg_nonce
                    && s.frag_total == frag_total
            });
            let idx = if let Some(p) = pos {
                p
            } else {
                if g.frag_reassembly.len() >= MAX_REASSEMBLY_SLOTS {
                    g.frag_reassembly.pop_front();
                }
                g.frag_reassembly.push_back(FragReassemblySlot {
                    inner_kind,
                    epoch,
                    msg_nonce,
                    frag_total,
                    chunks: vec![None; frag_total as usize],
                });
                g.frag_reassembly.len() - 1
            };
            let slot = &mut g.frag_reassembly[idx];
            slot.chunks[frag_idx as usize] = Some(chunk.to_vec());
            if slot.chunks.iter().all(Option::is_some) {
                let completed = g.frag_reassembly.remove(idx).expect("slot index valid");
                let total_len: usize = completed
                    .chunks
                    .iter()
                    .map(|c| c.as_ref().map_or(0, Vec::len))
                    .sum();
                let mut full = Vec::with_capacity(total_len);
                for c in completed.chunks.into_iter().flatten() {
                    full.extend_from_slice(&c);
                }
                Some(full)
            } else {
                None
            }
        };

        let Some(full_frame) = reassembled else {
            return;
        };
        if !is_pq_psk_shaped(&full_frame)
            || claimed_sender(&full_frame).as_ref() != Some(&self.peer_public)
        {
            return;
        }
        match inner_kind {
            KIND_INIT if full_frame.len() == INIT_FRAME_LEN => {
                self.on_init(&full_frame, reply_carrier).await;
            }
            KIND_RESP if full_frame.len() == RESP_FRAME_LEN => {
                self.on_resp(&full_frame, reply_carrier).await;
            }
            _ => {}
        }
    }

    async fn on_init(&self, pkt: &[u8], reply_carrier: &Arc<Carrier>) {
        let body = &pkt[..INIT_FRAME_LEN - MAC_LEN];
        let mac_bytes: [u8; 32] = pkt[INIT_FRAME_LEN - MAC_LEN..].try_into().expect("len");
        if !verify_mac(&self.auth_key, &[body], &mac_bytes) {
            return;
        }
        let Some(_sender_mode) = PqPskMode::from_wire_byte(pkt[9]) else {
            return;
        };
        let req_epoch = u64::from_be_bytes(pkt[10..18].try_into().expect("len"));
        if req_epoch == 0 {
            return;
        }
        let init_nonce: [u8; 16] = pkt[18..34].try_into().expect("len");
        let ek_slice = &pkt[INIT_HEADER_LEN..INIT_HEADER_LEN + MLKEM768_EK_LEN];

        let reply = {
            let mut g = self.inner.lock().await;
            if g.config.mode == PqPskMode::Off {
                Some(self.build_reject_frame(
                    PqPskMode::Off,
                    req_epoch,
                    &init_nonce,
                    REJECT_MODE_OFF,
                ))
            } else if (req_epoch < g.current_epoch && req_epoch != 1)
                || g.committed_init_nonces.contains(&init_nonce)
            {
                // Reject stale (`req_epoch < current_epoch` and `!= 1`) or
                // replayed KIND_INIT from an already-committed exchange.
                None
            } else if let Some(existing) =
                g.pending_resps.iter().find(|r| r.init_nonce == init_nonce)
            {
                // Deduplicate retransmitted KIND_INIT for an already-cached response
                Some(existing.resp_frame.clone())
            } else if let Some(conf) = g.pending_confirm.as_ref() {
                // Never clear or abort an already-sent KIND_CONFIRM on either
                // primary or non-primary: our peer already answered our KIND_INIT
                // with KIND_RESP and holds the matching PendingResp (or has
                // already committed it). Re-send our KIND_CONFIRM so the peer
                // commits or re-sends its cached KIND_ACK.
                Some(conf.confirm_frame.clone())
            } else if g.pending_init.is_some() && self.is_primary_initiator() {
                // Simultaneous initiation glare while both peers are still in
                // `stage = "init"`: the lexicographically smaller static pubkey
                // wins the initiator role so the two peers never cross-install
                // distinct PSKs. Re-send our in-flight KIND_INIT over `reply_carrier`.
                g.pending_init.as_ref().map(|i| i.frame.clone())
            } else {
                if g.pending_init.is_some() && !self.is_primary_initiator() {
                    g.pending_init = None;
                }
                let ek_arr = ml_kem::array::Array::try_from(ek_slice).ok();
                let Some(ek) = ek_arr.and_then(|a| EncapsulationKey768::new(&a).ok()) else {
                    g.failed_exchanges = g.failed_exchanges.saturating_add(1);
                    g.status = PqPeerStatus::ExchangeFailed;
                    let rej = self.build_reject_frame(
                        g.config.mode,
                        req_epoch,
                        &init_nonce,
                        REJECT_INVALID_KEY,
                    );
                    drop(g);
                    self.send_control_frame(reply_carrier, &rej).await;
                    return;
                };
                // If an authenticated peer initiates with `req_epoch <= current_epoch`
                // (e.g. after a restart at `req_epoch = 1`, or when epoch-behind
                // after a lost KIND_ACK / confirm timeout), advance monotonically
                // to `current_epoch + 1` so both peers converge to the same key.
                let effective_epoch = g.current_epoch.saturating_add(1).max(req_epoch);
                // NIST FIPS 203 §7.2 Algorithm 20 `ML-KEM.Encaps(ek)` samples 32
                // CSPRNG bytes `m` and invokes `ML-KEM.Encaps_internal(ek, m)`.
                // Using `rand::rng()` + `encapsulate_deterministic(&m)` implements
                // Algorithm 20 directly without the `rand_core 0.9` vs `0.10`
                // trait mismatch in `ml-kem 0.3.0-pre.2`; `m_bytes` is zeroized
                // immediately after encapsulation.
                let mut m_bytes = random_bytes::<32>();
                let m = B32::from(m_bytes);
                m_bytes.fill(0);
                let (ct, k_pq) = ek.encapsulate_deterministic(&m);
                let ct_slice: &[u8] = ct.as_slice();
                let ek_hash = sha256_bytes(ek_slice);
                let ct_hash = sha256_bytes(ct_slice);
                let resp_nonce = random_bytes::<NONCE_LEN>();
                let candidate_psk = derive_hybrid_psk(
                    k_pq.as_slice(),
                    &self.auth_key,
                    g.config.configured_psk.as_ref(),
                    &self.peer_public,
                    &self.self_public,
                    effective_epoch,
                    &init_nonce,
                    &resp_nonce,
                    &ek_hash,
                    &ct_hash,
                );

                let mut resp_frame = Vec::with_capacity(RESP_FRAME_LEN);
                resp_frame.extend_from_slice(MAGIC);
                resp_frame.push(KIND_RESP);
                resp_frame.push(g.config.mode.wire_byte());
                resp_frame.extend_from_slice(&effective_epoch.to_be_bytes());
                resp_frame.extend_from_slice(&init_nonce);
                resp_frame.extend_from_slice(&resp_nonce);
                resp_frame.extend_from_slice(&self.self_public);
                resp_frame.extend_from_slice(ct_slice);
                let mac = compute_mac(&self.auth_key, &[&resp_frame, &ek_hash]);
                resp_frame.extend_from_slice(&mac);
                debug_assert_eq!(resp_frame.len(), RESP_FRAME_LEN);

                if g.pending_resps.len() >= MAX_PENDING_RESP {
                    g.pending_resps.pop_front();
                }
                g.pending_resps.push_back(PendingResp {
                    epoch: effective_epoch,
                    init_nonce,
                    resp_nonce,
                    candidate_psk,
                    resp_frame: resp_frame.clone(),
                    created_at: Instant::now(),
                });
                Some(resp_frame)
            }
        };

        if let Some(bytes) = reply {
            self.send_control_frame(reply_carrier, &bytes).await;
        }
    }

    async fn on_resp(&self, pkt: &[u8], reply_carrier: &Arc<Carrier>) {
        let body = &pkt[..RESP_FRAME_LEN - MAC_LEN];
        let mac_bytes: [u8; 32] = pkt[RESP_FRAME_LEN - MAC_LEN..].try_into().expect("len");
        let Some(_responder_mode) = PqPskMode::from_wire_byte(pkt[9]) else {
            return;
        };
        let resp_epoch = u64::from_be_bytes(pkt[10..18].try_into().expect("len"));
        let init_nonce: [u8; 16] = pkt[18..34].try_into().expect("len");
        let resp_nonce: [u8; 16] = pkt[34..50].try_into().expect("len");
        let ct_slice = &pkt[RESP_HEADER_LEN..RESP_HEADER_LEN + MLKEM768_CT_LEN];

        let confirm_to_send = {
            let mut g = self.inner.lock().await;
            if g.config.mode == PqPskMode::Off {
                return;
            }
            // If we already built a PendingConfirm for this exact (init_nonce, resp_nonce), re-send it.
            if let Some(conf) = g.pending_confirm.as_ref()
                && conf.init_nonce == init_nonce
                && conf.resp_nonce == resp_nonce
            {
                Some(conf.confirm_frame.clone())
            } else {
                let Some(pending) = g.pending_init.as_ref() else {
                    return;
                };
                if pending.init_nonce != init_nonce
                    || resp_epoch < pending.epoch
                    || resp_epoch <= g.current_epoch
                {
                    return;
                }
                if !verify_mac(&self.auth_key, &[body, &pending.ek_hash], &mac_bytes) {
                    return;
                }
                let Ok(ct) = ml_kem::Ciphertext::<ml_kem::MlKem768>::try_from(ct_slice) else {
                    g.failed_exchanges = g.failed_exchanges.saturating_add(1);
                    g.status = PqPeerStatus::ExchangeFailed;
                    return;
                };
                let pending = g.pending_init.take().expect("checked above");
                let k_pq = pending.dk.decapsulate(&ct);
                let ct_hash = sha256_bytes(ct_slice);
                let candidate_psk = derive_hybrid_psk(
                    k_pq.as_slice(),
                    &self.auth_key,
                    g.config.configured_psk.as_ref(),
                    &self.self_public,
                    &self.peer_public,
                    resp_epoch,
                    &init_nonce,
                    &resp_nonce,
                    &pending.ek_hash,
                    &ct_hash,
                );
                let tag = confirm_tag(
                    &candidate_psk,
                    KIND_CONFIRM,
                    resp_epoch,
                    &init_nonce,
                    &resp_nonce,
                    &self.self_public,
                    &self.peer_public,
                );
                let mut confirm_frame = Vec::with_capacity(CONFIRM_FRAME_LEN);
                confirm_frame.extend_from_slice(MAGIC);
                confirm_frame.push(KIND_CONFIRM);
                confirm_frame.push(g.config.mode.wire_byte());
                confirm_frame.extend_from_slice(&resp_epoch.to_be_bytes());
                confirm_frame.extend_from_slice(&init_nonce);
                confirm_frame.extend_from_slice(&resp_nonce);
                confirm_frame.extend_from_slice(&self.self_public);
                confirm_frame.extend_from_slice(&tag);
                debug_assert_eq!(confirm_frame.len(), CONFIRM_FRAME_LEN);

                g.pending_resps.retain(|r| r.epoch > resp_epoch);
                g.pending_confirm = Some(PendingConfirm {
                    epoch: resp_epoch,
                    init_nonce,
                    resp_nonce,
                    candidate_psk,
                    confirm_frame: confirm_frame.clone(),
                    last_sent: Instant::now(),
                    retries: 0,
                });
                Some(confirm_frame)
            }
        };

        if let Some(bytes) = confirm_to_send {
            self.send_control_frame(reply_carrier, &bytes).await;
        }
    }

    async fn on_confirm(&self, pkt: &[u8], reply_carrier: &Arc<Carrier>) {
        let Some(_sender_mode) = PqPskMode::from_wire_byte(pkt[9]) else {
            return;
        };
        let epoch = u64::from_be_bytes(pkt[10..18].try_into().expect("len"));
        let init_nonce: [u8; 16] = pkt[18..34].try_into().expect("len");
        let resp_nonce: [u8; 16] = pkt[34..50].try_into().expect("len");
        let received_tag: [u8; 32] = pkt[CONFIRM_HEADER_LEN..].try_into().expect("len");

        let mut install_psk: Option<[u8; 32]> = None;
        let mut lock_guard_psk: Option<[u8; 32]> = None;
        let mut queued_packets: Vec<Vec<u8>> = Vec::new();
        let reply_frame = {
            let mut g = self.inner.lock().await;
            if g.config.mode == PqPskMode::Off {
                return;
            }
            // Retransmitted KIND_CONFIRM for an already-committed exchange: re-send cached ACK.
            if let Some(ack) = g.committed_acks.iter().find(|ack| {
                ack.epoch == epoch && ack.init_nonce == init_nonce && ack.resp_nonce == resp_nonce
            }) {
                Some(ack.ack_frame.clone())
            } else if let Some(pos) = g.pending_resps.iter().position(|r| {
                r.epoch == epoch && r.init_nonce == init_nonce && r.resp_nonce == resp_nonce
            }) {
                let resp = g.pending_resps.remove(pos).expect("position checked");
                let expected = confirm_tag(
                    &resp.candidate_psk,
                    KIND_CONFIRM,
                    epoch,
                    &init_nonce,
                    &resp_nonce,
                    &self.peer_public,
                    &self.self_public,
                );
                if bool::from(expected.ct_eq(&received_tag)) {
                    if epoch <= g.current_epoch {
                        return;
                    }
                    let was_established = g.current_epoch > 0;
                    g.current_epoch = epoch;
                    g.active_psk = Some(resp.candidate_psk);
                    g.established_at = Some(Instant::now());
                    g.status = PqPeerStatus::Established { epoch };
                    if was_established {
                        g.rotations_completed = g.rotations_completed.saturating_add(1);
                    }
                    record_committed_nonce(&mut g.committed_init_nonces, init_nonce);
                    g.pending_init = None;
                    g.pending_confirm = None;
                    g.pending_resps.retain(|r| r.epoch > epoch);
                    queued_packets = g.pending_packets.drain(..).collect();
                    self.epoch_atomic.store(epoch, Ordering::Relaxed);
                    install_psk = Some(resp.candidate_psk);

                    let ack_tag = confirm_tag(
                        &resp.candidate_psk,
                        KIND_ACK,
                        epoch,
                        &init_nonce,
                        &resp_nonce,
                        &self.peer_public,
                        &self.self_public,
                    );
                    let mut ack_frame = Vec::with_capacity(CONFIRM_FRAME_LEN);
                    ack_frame.extend_from_slice(MAGIC);
                    ack_frame.push(KIND_ACK);
                    ack_frame.push(g.config.mode.wire_byte());
                    ack_frame.extend_from_slice(&epoch.to_be_bytes());
                    ack_frame.extend_from_slice(&init_nonce);
                    ack_frame.extend_from_slice(&resp_nonce);
                    ack_frame.extend_from_slice(&self.self_public);
                    ack_frame.extend_from_slice(&ack_tag);
                    debug_assert_eq!(ack_frame.len(), CONFIRM_FRAME_LEN);

                    record_committed_ack(
                        &mut g.committed_acks,
                        CommittedAckCache {
                            epoch,
                            init_nonce,
                            resp_nonce,
                            ack_frame: ack_frame.clone(),
                        },
                    );
                    info!(
                        peer = %short_hex(&self.peer_public),
                        epoch,
                        role = "responder",
                        "overlay pq-psk: ML-KEM-768 PSK established"
                    );
                    Some(ack_frame)
                } else {
                    g.mismatch_count = g.mismatch_count.saturating_add(1);
                    g.failed_exchanges = g.failed_exchanges.saturating_add(1);
                    g.status = PqPeerStatus::PeerMismatch;
                    g.active_psk = None;
                    g.established_at = None;
                    g.pending_packets.clear();
                    lock_guard_psk = Some(random_bytes::<32>());
                    warn!(
                        peer = %short_hex(&self.peer_public),
                        epoch,
                        "overlay pq-psk: confirmation tag mismatch (configured PSK or KEM mismatch); failing closed"
                    );
                    Some(self.build_reject_frame(
                        g.config.mode,
                        epoch,
                        &init_nonce,
                        REJECT_PSK_MISMATCH,
                    ))
                }
            } else {
                None
            }
        };

        // Install the new PSK (or fail-closed guard PSK) BEFORE sending KIND_ACK so
        // the responder is guaranteed ready when the initiator's WG handshake arrives.
        if let Some(psk) = install_psk {
            self.reinstall_tunn_psk(Some(psk), false, false, queued_packets, Some(reply_carrier))
                .await;
        } else if let Some(guard) = lock_guard_psk {
            self.reinstall_tunn_psk(Some(guard), true, false, Vec::new(), None)
                .await;
        }
        if let Some(bytes) = reply_frame {
            self.send_control_frame(reply_carrier, &bytes).await;
        }
    }

    async fn on_ack(&self, pkt: &[u8], reply_carrier: &Arc<Carrier>) {
        let epoch = u64::from_be_bytes(pkt[10..18].try_into().expect("len"));
        let init_nonce: [u8; 16] = pkt[18..34].try_into().expect("len");
        let resp_nonce: [u8; 16] = pkt[34..50].try_into().expect("len");
        let received_tag: [u8; 32] = pkt[CONFIRM_HEADER_LEN..].try_into().expect("len");

        let install_psk = {
            let mut g = self.inner.lock().await;
            let Some(conf) = g.pending_confirm.as_ref() else {
                return;
            };
            if epoch <= g.current_epoch
                || conf.epoch != epoch
                || conf.init_nonce != init_nonce
                || conf.resp_nonce != resp_nonce
            {
                return;
            }
            let expected = confirm_tag(
                &conf.candidate_psk,
                KIND_ACK,
                epoch,
                &init_nonce,
                &resp_nonce,
                &self.self_public,
                &self.peer_public,
            );
            if !bool::from(expected.ct_eq(&received_tag)) {
                return;
            }
            let conf = g.pending_confirm.take().expect("checked above");
            let was_established = g.current_epoch > 0;
            g.current_epoch = epoch;
            g.active_psk = Some(conf.candidate_psk);
            g.established_at = Some(Instant::now());
            g.status = PqPeerStatus::Established { epoch };
            if was_established {
                g.rotations_completed = g.rotations_completed.saturating_add(1);
            }
            record_committed_nonce(&mut g.committed_init_nonces, init_nonce);
            g.pending_init = None;
            g.pending_resps.retain(|r| r.epoch > epoch);
            let queued: Vec<Vec<u8>> = g.pending_packets.drain(..).collect();
            self.epoch_atomic.store(epoch, Ordering::Relaxed);
            info!(
                peer = %short_hex(&self.peer_public),
                epoch,
                role = "initiator",
                "overlay pq-psk: ML-KEM-768 PSK established"
            );
            Some((conf.candidate_psk, queued))
        };

        if let Some((psk, queued_packets)) = install_psk {
            self.reinstall_tunn_psk(Some(psk), false, true, queued_packets, Some(reply_carrier))
                .await;
        }
    }

    async fn on_reject(&self, pkt: &[u8], reply_carrier: &Arc<Carrier>) {
        let body = &pkt[..REJECT_FRAME_LEN - MAC_LEN];
        let mac_bytes: [u8; 32] = pkt[REJECT_FRAME_LEN - MAC_LEN..].try_into().expect("len");
        if !verify_mac(&self.auth_key, &[body], &mac_bytes) {
            return;
        }
        let Some(peer_mode) = PqPskMode::from_wire_byte(pkt[9]) else {
            return;
        };
        let epoch = u64::from_be_bytes(pkt[10..18].try_into().expect("len"));
        let init_nonce: [u8; 16] = pkt[18..34].try_into().expect("len");
        let reason = pkt[34];

        let mut downgrade_reinstall = false;
        let mut lock_guard_psk: Option<[u8; 32]> = None;

        {
            let mut g = self.inner.lock().await;
            let matches_init = g
                .pending_init
                .as_ref()
                .is_some_and(|i| i.init_nonce == init_nonce && i.epoch == epoch);
            let matches_conf = g
                .pending_confirm
                .as_ref()
                .is_some_and(|c| c.init_nonce == init_nonce && c.epoch == epoch);
            if !matches_init && !matches_conf {
                return;
            }
            g.pending_init = None;
            g.pending_confirm = None;

            if reason == REJECT_MODE_OFF && peer_mode == PqPskMode::Off {
                match g.config.mode {
                    PqPskMode::Optional => {
                        let had_custom_psk =
                            g.config.configured_psk.is_some() || g.current_epoch > 0;
                        g.downgraded_count = g.downgraded_count.saturating_add(1);
                        g.status = PqPeerStatus::DowngradedToClassical;
                        g.current_epoch = 0;
                        self.epoch_atomic.store(0, Ordering::Release);
                        g.active_psk = None;
                        g.established_at = None;
                        self.set_guard_active(false);
                        downgrade_reinstall = had_custom_psk;
                        info!(
                            peer = %short_hex(&self.peer_public),
                            "overlay pq-psk: remote peer has PQ-PSK off; downgrading to classical WG in optional mode"
                        );
                    }
                    PqPskMode::Required => {
                        g.mismatch_count = g.mismatch_count.saturating_add(1);
                        g.status = PqPeerStatus::PeerMismatch;
                        g.active_psk = None;
                        g.established_at = None;
                        g.pending_packets.clear();
                        lock_guard_psk = Some(random_bytes::<32>());
                        warn!(
                            peer = %short_hex(&self.peer_public),
                            "overlay pq-psk: remote peer has PQ-PSK off while local mode is Required; failing closed"
                        );
                    }
                    PqPskMode::Off => {}
                }
            } else if reason == REJECT_PSK_MISMATCH {
                g.mismatch_count = g.mismatch_count.saturating_add(1);
                g.failed_exchanges = g.failed_exchanges.saturating_add(1);
                g.status = PqPeerStatus::PeerMismatch;
                g.active_psk = None;
                g.established_at = None;
                g.pending_packets.clear();
                lock_guard_psk = Some(random_bytes::<32>());
                warn!(
                    peer = %short_hex(&self.peer_public),
                    epoch,
                    "overlay pq-psk: peer reported PSK mismatch; failing closed"
                );
            } else {
                g.failed_exchanges = g.failed_exchanges.saturating_add(1);
                g.status = PqPeerStatus::ExchangeFailed;
            }
        }

        if downgrade_reinstall {
            self.reinstall_tunn_psk(None, false, true, Vec::new(), Some(reply_carrier))
                .await;
        } else if let Some(guard) = lock_guard_psk {
            self.reinstall_tunn_psk(Some(guard), true, false, Vec::new(), Some(reply_carrier))
                .await;
        }
    }

    async fn reinstall_tunn_psk(
        &self,
        psk: Option<[u8; 32]>,
        guard_after: bool,
        initiate_wg: bool,
        queued_packets: Vec<Vec<u8>>,
        reply_carrier: Option<&Arc<Carrier>>,
    ) {
        let (primary_binding, shadow_binding) = {
            let b = self.bindings.read().unwrap_or_else(|e| e.into_inner());
            (b.primary.clone(), b.shadow.clone())
        };
        *self
            .cached_tunn_psk
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = psk;
        self.set_guard_active(guard_after);

        if let (Some(tunn), Some(stats)) = (
            primary_binding.tunn.upgrade(),
            primary_binding.stats.upgrade(),
        ) {
            let out_packets = {
                let mut t = tunn.lock().await;
                // B7 in-place PSK update: update `handshake.params.preshared_key`
                // without reconstructing `Tunn`, preserving `last_handshake_timestamp`
                // (TAI64N anti-replay watermark) across all PSK establishments and
                // rotations.
                t.set_preshared_key(psk);
                if guard_after {
                    // Fail-closed guard lock (`Required` mode expiry or mismatch):
                    // drop active transport sessions immediately while preserving
                    // the TAI64N replay watermark.
                    t.reset_sessions_preserving_replay_and_psk();
                    stats.handshake.store(false, Ordering::Release);
                    stats.handshake_at.store(0, Ordering::Release);
                    stats.hs_response_at.store(0, Ordering::Release);
                    Vec::new()
                } else {
                    // If downgrading to classical WG (`psk.is_none()`), clear any
                    // stale PQ-keyed transport sessions while preserving the TAI64N
                    // replay watermark so outbound traffic uses the classical session.
                    if psk.is_none() {
                        t.reset_sessions_preserving_replay_and_psk();
                    }
                    // Normal PQ-PSK establishment or rotation: keep any already-active
                    // transport `sessions` intact so in-flight data packets suffer
                    // zero packet loss while the new WG handshake is in flight.
                    let mut outs: Vec<Vec<u8>> = Vec::new();
                    let mut buf = vec![0u8; WG_BUF];
                    if initiate_wg
                        && let TunnResult::WriteToNetwork(b) =
                            t.format_handshake_initiation(&mut buf, true)
                    {
                        outs.push(b.to_vec());
                    }
                    for pkt in &queued_packets {
                        if t.has_current_session() {
                            if let TunnResult::WriteToNetwork(b) = t.encapsulate(pkt, &mut buf) {
                                outs.push(b.to_vec());
                            }
                        } else {
                            t.queue_packet_only(pkt);
                        }
                    }
                    outs
                }
            };
            if !out_packets.is_empty() {
                let upgraded = primary_binding.carrier.upgrade();
                if let Some(out_carrier) = reply_carrier.or(upgraded.as_ref()) {
                    for pkt in &out_packets {
                        let _ = super::wg::send_wg_recorded(out_carrier, &stats, pkt).await;
                    }
                }
            }
        }

        if let Some(shadow) = shadow_binding
            && let (Some(s_tunn), Some(s_stats)) = (shadow.tunn.upgrade(), shadow.stats.upgrade())
        {
            let shadow_out = {
                let mut st = s_tunn.lock().await;
                st.set_preshared_key(psk);
                if guard_after {
                    st.reset_sessions_preserving_replay_and_psk();
                    s_stats.handshake.store(false, Ordering::Release);
                    s_stats.handshake_at.store(0, Ordering::Release);
                    s_stats.hs_response_at.store(0, Ordering::Release);
                    None
                } else {
                    if psk.is_none() {
                        st.reset_sessions_preserving_replay_and_psk();
                    }
                    let mut buf = vec![0u8; WG_BUF];
                    let should_initiate_shadow = initiate_wg
                        || (shadow.initiate_when_ready
                            && !s_stats.handshake.load(Ordering::Acquire));
                    if should_initiate_shadow
                        && let TunnResult::WriteToNetwork(b) =
                            st.format_handshake_initiation(&mut buf, true)
                    {
                        Some(b.to_vec())
                    } else {
                        None
                    }
                }
            };
            if let Some(pkt) = shadow_out
                && let Some(s_carrier) = shadow.carrier.upgrade()
            {
                let _ = super::wg::send_wg_recorded(&s_carrier, &s_stats, &pkt).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::overlay::WgKeypair;

    #[test]
    fn pq_psk_shape_is_disjoint_from_wg_stun_disco_and_follow() {
        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let auth = static_auth_key(&a.secret, a.public.as_bytes(), b.public.as_bytes());
        let seed = Seed::from([7u8; 64]);
        let dk = DecapsulationKey768::from_seed(seed);
        let ek = dk.encapsulation_key().to_bytes();

        let mut init = Vec::with_capacity(INIT_FRAME_LEN);
        init.extend_from_slice(MAGIC);
        init.push(KIND_INIT);
        init.push(PqPskMode::Required.wire_byte());
        init.extend_from_slice(&1u64.to_be_bytes());
        init.extend_from_slice(&[9u8; 16]);
        init.extend_from_slice(a.public.as_bytes());
        init.extend_from_slice(ek.as_slice());
        let mac = compute_mac(&auth, &[&init]);
        init.extend_from_slice(&mac);

        assert!(is_pq_psk_shaped(&init));
        assert!(!super::super::wg::is_wg_shaped(&init));
        assert!(!crate::transport::stun::has_stun_cookie(&init));
        assert!(!super::super::disco::is_disco_shaped(&init));
        assert!(!super::super::disco::derp_follow::shaped(&init));
        assert_eq!(claimed_sender(&init), Some(a.public.to_bytes()));
    }

    #[test]
    fn debug_formats_redact_all_secret_material() {
        let cfg = PqPskConfig {
            mode: PqPskMode::Required,
            configured_psk: Some([0xAA; 32]),
            ..PqPskConfig::default()
        };
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("170"));
        assert!(!dbg.contains("aa"));
    }

    #[tokio::test]
    async fn pq_psk_fragmentation_keeps_all_wire_frames_under_700_bytes_and_rejects_unauth_frags() {
        use tokio::net::UdpSocket;

        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let tunn_a = Arc::new(Mutex::new(Tunn::new(
            a.secret.clone(),
            b.public,
            None,
            None,
            1,
            None,
        )));
        let tunn_b = Arc::new(Mutex::new(Tunn::new(
            b.secret.clone(),
            a.public,
            None,
            None,
            2,
            None,
        )));
        let carrier_a = Carrier::direct(sock_a.clone(), addr_b);
        let carrier_b = Carrier::direct(sock_b.clone(), addr_a);
        let stats_a = Arc::new(PeerStats::default());
        let stats_b = Arc::new(PeerStats::default());

        let cfg = PqPskConfig {
            mode: PqPskMode::Required,
            ..PqPskConfig::default()
        };
        let handle_a = PqPeerHandle::new(
            cfg.clone(),
            a.secret.clone(),
            a.public.to_bytes(),
            b.public.to_bytes(),
            1,
            None,
            tunn_a,
            carrier_a.clone(),
            stats_a,
        );
        let handle_b = PqPeerHandle::new(
            cfg,
            b.secret.clone(),
            b.public.to_bytes(),
            a.public.to_bytes(),
            2,
            None,
            tunn_b,
            carrier_b.clone(),
            stats_b,
        );

        let raw_init = {
            let mut ga = handle_a.inner.lock().await;
            handle_a.build_init_locked(&mut ga, 1)
        };
        assert_eq!(raw_init.len(), INIT_FRAME_LEN);
        let frags = handle_a.fragment_control_frame(&raw_init);
        assert_eq!(
            frags.len(),
            3,
            "1282 B KIND_INIT must split into 3 sub-700B fragments"
        );
        for f in &frags {
            assert!(
                f.len() <= MAX_WIRE_CONTROL_FRAME_LEN && f.len() < 700,
                "fragment wire size {} must be <= 680 (< 700 B)",
                f.len()
            );
            assert!(is_pq_psk_shaped(f));
            assert!(!super::super::wg::is_wg_shaped(f));
            assert!(!crate::transport::stun::has_stun_cookie(f));
            assert!(!super::super::disco::is_disco_shaped(f));
            assert_eq!(claimed_sender(f), Some(a.public.to_bytes()));
        }

        // Tampered fragment MAC must be rejected before allocating any slot in `frag_reassembly`.
        let mut tampered = frags[0].clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x55;
        handle_b.handle_inbound(&tampered, &carrier_b).await;
        assert!(
            handle_b.inner.lock().await.frag_reassembly.is_empty(),
            "unauthenticated fragment must not allocate in frag_reassembly"
        );

        // Deliver fragments out-of-order (2, 0, duplicate 2, 1) and verify reassembly triggers on_init.
        handle_b.handle_inbound(&frags[2], &carrier_b).await;
        handle_b.handle_inbound(&frags[0], &carrier_b).await;
        handle_b.handle_inbound(&frags[2], &carrier_b).await;
        assert_eq!(handle_b.inner.lock().await.frag_reassembly.len(), 1);
        handle_b.handle_inbound(&frags[1], &carrier_b).await;
        assert!(
            handle_b.inner.lock().await.frag_reassembly.is_empty(),
            "completed fragment slot must be drained on reassembly"
        );
        assert_eq!(
            handle_b.inner.lock().await.pending_resps.len(),
            1,
            "reassembled KIND_INIT must produce a pending response"
        );
    }

    #[test]
    fn in_place_set_preshared_key_preserves_tai64n_replay_watermark_and_active_sessions() {
        use boringtun::noise::errors::WireGuardError;

        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let psk_1 = [0x11u8; 32];
        let psk_2 = [0x22u8; 32];

        let mut t_a = Tunn::new(a.secret.clone(), b.public, Some(psk_1), None, 1, None);
        let mut t_b = Tunn::new(b.secret.clone(), a.public, Some(psk_1), None, 2, None);

        // 1. Complete epoch-1 handshake under `psk_1` and capture the `HandshakeInit` wire bytes.
        let mut buf_a = vec![0u8; WG_BUF];
        let mut buf_b = vec![0u8; WG_BUF];
        let init_1 = match t_a.format_handshake_initiation(&mut buf_a, false) {
            TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
            other => panic!("expected HandshakeInit, got {other:?}"),
        };
        let resp_1 = match t_b.decapsulate(None, &init_1, &mut buf_b) {
            TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
            other => panic!("expected HandshakeResponse, got {other:?}"),
        };
        let keepalive_1 = match t_a.decapsulate(None, &resp_1, &mut buf_a) {
            TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
            other => panic!("expected keepalive, got {other:?}"),
        };
        assert!(matches!(
            t_b.decapsulate(None, &keepalive_1, &mut buf_b),
            TunnResult::Done
        ));

        // 2. Rotate PSK in-place to `psk_2` on BOTH peers (`set_preshared_key`).
        //    Verify that BEFORE the new WG handshake completes, in-flight data
        //    packets continue to encrypt and decrypt on the existing session
        //    with ZERO packet loss!
        t_b.set_preshared_key(Some(psk_2));
        t_a.set_preshared_key(Some(psk_2));
        assert_eq!(t_a.preshared_key(), Some(psk_2));
        assert_eq!(t_b.preshared_key(), Some(psk_2));

        let ipv4_pkt = [
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 100, 64, 0, 1,
            100, 64, 0, 2, 0x04, 0xd2, 0x04, 0xd2, 0x00, 0x08, 0x00, 0x00,
        ];
        let enc_during_rot = match t_a.encapsulate(&ipv4_pkt, &mut buf_a) {
            TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
            other => panic!("active session must stay alive during rotation window: {other:?}"),
        };
        match t_b.decapsulate(None, &enc_during_rot, &mut buf_b) {
            TunnResult::WriteToTunnelV4(dec, _) => assert_eq!(dec, ipv4_pkt),
            other => panic!("responder must decrypt in-flight packet during rotation: {other:?}"),
        }

        // 3. Initiate and complete the new WG handshake under `psk_2`.
        let init_2 = match t_a.format_handshake_initiation(&mut buf_a, true) {
            TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
            other => panic!("expected rotated HandshakeInit, got {other:?}"),
        };
        let resp_2 = match t_b.decapsulate(None, &init_2, &mut buf_b) {
            TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
            other => panic!("expected rotated HandshakeResponse, got {other:?}"),
        };
        let keepalive_2 = match t_a.decapsulate(None, &resp_2, &mut buf_a) {
            TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
            other => panic!("expected rotated keepalive, got {other:?}"),
        };
        assert!(matches!(
            t_b.decapsulate(None, &keepalive_2, &mut buf_b),
            TunnResult::Done
        ));

        // 4. Even if `t_b` is set back to `Some(psk_1)` (or in `Optional` mode),
        //    replaying the captured pre-rotation `init_1` is rejected with
        //    `WrongTai64nTimestamp` because `set_preshared_key` preserved
        //    `handshake.last_handshake_timestamp`!
        t_b.set_preshared_key(Some(psk_1));
        assert!(
            matches!(
                t_b.decapsulate(None, &init_1, &mut buf_b),
                TunnResult::Err(WireGuardError::WrongTai64nTimestamp)
            ),
            "replayed pre-rotation HandshakeInit must fail WrongTai64nTimestamp"
        );

        // 5. `reset_sessions_preserving_replay_and_psk` drops active sessions
        //    while still preserving `last_handshake_timestamp` and `preshared_key`.
        t_b.reset_sessions_preserving_replay_and_psk();
        assert_eq!(t_b.preshared_key(), Some(psk_1));
        assert!(matches!(
            t_b.decapsulate(None, &enc_during_rot, &mut buf_b),
            TunnResult::Err(WireGuardError::NoCurrentSession)
        ));
        assert!(
            matches!(
                t_b.decapsulate(None, &init_1, &mut buf_b),
                TunnResult::Err(WireGuardError::WrongTai64nTimestamp)
            ),
            "TAI64N watermark must survive reset_sessions_preserving_replay_and_psk"
        );
    }

    async fn drain_udp_into(
        rx_sock: &tokio::net::UdpSocket,
        dst_handle: &PqPeerHandle,
        dst_carrier: &Arc<Carrier>,
    ) -> usize {
        let mut count = 0;
        let mut buf = [0u8; 2048];
        while let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(15), rx_sock.recv_from(&mut buf)).await
        {
            if is_pq_psk_shaped(&buf[..n]) {
                count += 1;
                dst_handle.handle_inbound(&buf[..n], dst_carrier).await;
            }
        }
        count
    }

    async fn read_pq_datagrams(rx_sock: &tokio::net::UdpSocket) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = [0u8; 2048];
        while let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(15), rx_sock.recv_from(&mut buf)).await
        {
            if is_pq_psk_shaped(&buf[..n]) {
                out.push(buf[..n].to_vec());
            }
        }
        out
    }

    #[tokio::test]
    async fn pq_psk_simultaneous_rotation_glare_converges_in_both_orderings_and_respects_rekey_stagger()
     {
        use tokio::net::UdpSocket;

        let k1 = WgKeypair::generate();
        let k2 = WgKeypair::generate();
        // Order keys so `primary` has lexicographically smaller public key (`is_primary_initiator() == true`).
        let (primary, non_primary) = if k1.public.to_bytes() < k2.public.to_bytes() {
            (k1, k2)
        } else {
            (k2, k1)
        };

        let sock_p = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_np = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_p = sock_p.local_addr().unwrap();
        let addr_np = sock_np.local_addr().unwrap();

        let cfg = PqPskConfig {
            mode: PqPskMode::Required,
            rekey_interval: Duration::from_millis(400),
            max_lifetime: Duration::from_secs(30),
            retry_interval: Duration::from_millis(100),
            max_retries: 6,
            configured_psk: None,
        };

        let tunn_p = Arc::new(Mutex::new(Tunn::new(
            primary.secret.clone(),
            non_primary.public,
            PqPeerHandle::initial_tunn_psk(&cfg),
            None,
            1,
            None,
        )));
        let tunn_np = Arc::new(Mutex::new(Tunn::new(
            non_primary.secret.clone(),
            primary.public,
            PqPeerHandle::initial_tunn_psk(&cfg),
            None,
            2,
            None,
        )));
        let carrier_p = Carrier::direct(sock_p.clone(), addr_np);
        let carrier_np = Carrier::direct(sock_np.clone(), addr_p);
        let stats_p = Arc::new(PeerStats::default());
        let stats_np = Arc::new(PeerStats::default());

        let _stats_p = stats_p.clone();
        let _stats_np = stats_np.clone();
        let handle_p = PqPeerHandle::new(
            cfg.clone(),
            primary.secret.clone(),
            primary.public.to_bytes(),
            non_primary.public.to_bytes(),
            1,
            None,
            tunn_p.clone(),
            carrier_p.clone(),
            stats_p,
        );
        let handle_np = PqPeerHandle::new(
            cfg,
            non_primary.secret.clone(),
            non_primary.public.to_bytes(),
            primary.public.to_bytes(),
            2,
            None,
            tunn_np.clone(),
            carrier_np.clone(),
            stats_np,
        );
        assert!(handle_p.is_primary_initiator());
        assert!(!handle_np.is_primary_initiator());

        // Establish epoch = 1 first.
        assert!(handle_p.start_initial().await);
        for _ in 0..4 {
            drain_udp_into(&sock_np, &handle_np, &carrier_np).await;
            drain_udp_into(&sock_p, &handle_p, &carrier_p).await;
        }
        let s_p1 = handle_p.snapshot().await;
        let s_np1 = handle_np.snapshot().await;
        assert_eq!(s_p1.current_epoch, 1);
        assert_eq!(s_np1.current_epoch, 1);
        assert_eq!(s_p1.psk_fingerprint, s_np1.psk_fingerprint);

        // Ordering A: Both peers simultaneously initiate epoch = 2 (`pending_init` on both)
        // and their KIND_INIT fragments cross in flight.
        assert!(handle_p.start_or_rotate().await);
        assert!(handle_np.start_or_rotate().await);
        let init_from_p = read_pq_datagrams(&sock_np).await;
        let init_from_np = read_pq_datagrams(&sock_p).await;
        assert_eq!(init_from_p.len(), 3);
        assert_eq!(init_from_np.len(), 3);

        // Deliver non-primary's KIND_INIT to primary (primary must keep its pending_init and re-send it),
        // and primary's KIND_INIT to non-primary (non-primary must drop pending_init and reply KIND_RESP).
        for pkt in &init_from_np {
            handle_p.handle_inbound(pkt, &carrier_p).await;
        }
        for pkt in &init_from_p {
            handle_np.handle_inbound(pkt, &carrier_np).await;
        }
        for _ in 0..4 {
            drain_udp_into(&sock_p, &handle_p, &carrier_p).await;
            drain_udp_into(&sock_np, &handle_np, &carrier_np).await;
        }
        let s_p2 = handle_p.snapshot().await;
        let s_np2 = handle_np.snapshot().await;
        assert_eq!(s_p2.current_epoch, 2);
        assert_eq!(s_np2.current_epoch, 2);
        assert_eq!(s_p2.psk_fingerprint, s_np2.psk_fingerprint);
        assert_eq!(
            tunn_p.lock().await.preshared_key(),
            tunn_np.lock().await.preshared_key()
        );

        // Ordering B (exact B7 R1 t=120s glare sequence):
        // 1. Non-primary initiates epoch = 3 (`KIND_INIT`).
        // 2. Primary receives non-primary's `KIND_INIT` and replies `KIND_RESP` (storing `PendingResp`).
        // 3. Verify `tick_timer` on primary does NOT start a competing rotation while `pending_resps` is non-empty!
        // 4. Even if primary explicitly sends a competing `KIND_INIT(epoch = 3)` that arrives at non-primary
        //    AFTER non-primary has already processed `KIND_RESP` and entered `pending_confirm`,
        //    non-primary must NOT clear `pending_confirm`; it re-sends `KIND_CONFIRM`, primary commits
        //    epoch = 3 and replies `KIND_ACK`, and both converge to epoch = 3 with identical PSKs!
        assert!(handle_np.start_or_rotate().await);
        let np_init_e3 = read_pq_datagrams(&sock_p).await;
        for pkt in &np_init_e3 {
            handle_p.handle_inbound(pkt, &carrier_p).await;
        }
        let p_resp_e3 = read_pq_datagrams(&sock_np).await;
        assert_eq!(
            p_resp_e3.len(),
            3,
            "primary must reply with 3 KIND_RESP fragments"
        );

        // Advance primary's `established_at` past `rekey_interval` and verify `tick_timer`
        // does NOT initiate a competing rotation because `pending_resps` is non-empty.
        handle_p.inner.lock().await.established_at = Some(Instant::now() - Duration::from_secs(10));
        handle_p.tick_timer().await;
        assert!(
            read_pq_datagrams(&sock_np).await.is_empty(),
            "tick_timer must not start a rotation while pending_resps is non-empty"
        );

        // Now deliver primary's `KIND_RESP` to non-primary so non-primary transitions to `pending_confirm`
        // and sends `KIND_CONFIRM`.
        for pkt in &p_resp_e3 {
            handle_np.handle_inbound(pkt, &carrier_np).await;
        }
        let np_confirm_e3 = read_pq_datagrams(&sock_p).await;
        assert_eq!(np_confirm_e3.len(), 1);
        assert!(handle_np.inner.lock().await.pending_confirm.is_some());

        // Inject a competing `KIND_INIT(epoch = 3)` from primary into non-primary BEFORE non-primary
        // receives `KIND_ACK` (simulating an in-flight glare packet).
        let competing_p_init = {
            let mut gp = handle_p.inner.lock().await;
            handle_p.build_init_locked(&mut gp, 3)
        };
        for frag in handle_p.fragment_control_frame(&competing_p_init) {
            handle_np.handle_inbound(&frag, &carrier_np).await;
        }
        assert!(
            handle_np.inner.lock().await.pending_confirm.is_some(),
            "non-primary must NEVER clear pending_confirm when an inbound KIND_INIT arrives"
        );
        // Non-primary re-sent its `KIND_CONFIRM`; deliver `KIND_CONFIRM` to primary and `KIND_ACK` back.
        let resent_confirm = read_pq_datagrams(&sock_p).await;
        assert_eq!(resent_confirm.len(), 1);
        handle_p.handle_inbound(&np_confirm_e3[0], &carrier_p).await;
        for _ in 0..3 {
            drain_udp_into(&sock_np, &handle_np, &carrier_np).await;
            drain_udp_into(&sock_p, &handle_p, &carrier_p).await;
        }

        let s_p3 = handle_p.snapshot().await;
        let s_np3 = handle_np.snapshot().await;
        assert_eq!(s_p3.current_epoch, 3);
        assert_eq!(s_np3.current_epoch, 3);
        assert_eq!(s_p3.psk_fingerprint, s_np3.psk_fingerprint);
        assert_ne!(s_p3.psk_fingerprint, s_p2.psk_fingerprint);
        assert_eq!(
            tunn_p.lock().await.preshared_key(),
            tunn_np.lock().await.preshared_key()
        );

        // Verify `NON_PRIMARY_REKEY_STAGGER` (1_000 ms): at `rekey_interval + 200 ms`,
        // non-primary `tick_timer` must NOT initiate rotation yet.
        handle_np.inner.lock().await.established_at =
            Some(Instant::now() - Duration::from_millis(600));
        handle_np.tick_timer().await;
        assert!(
            handle_np.inner.lock().await.pending_init.is_none(),
            "non-primary must wait for rekey_interval + NON_PRIMARY_REKEY_STAGGER (400 + 1000 ms)"
        );
    }

    #[tokio::test]
    async fn pq_psk_recovers_from_lost_init_resp_confirm_and_ack_and_replays_cached_ack_on_duplicate_confirm()
     {
        use tokio::net::UdpSocket;

        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let cfg = PqPskConfig {
            mode: PqPskMode::Required,
            rekey_interval: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(300),
            retry_interval: Duration::from_millis(20),
            max_retries: 6,
            configured_psk: None,
        };
        let tunn_a = Arc::new(Mutex::new(Tunn::new(
            a.secret.clone(),
            b.public,
            PqPeerHandle::initial_tunn_psk(&cfg),
            None,
            1,
            None,
        )));
        let tunn_b = Arc::new(Mutex::new(Tunn::new(
            b.secret.clone(),
            a.public,
            PqPeerHandle::initial_tunn_psk(&cfg),
            None,
            2,
            None,
        )));
        let carrier_a = Carrier::direct(sock_a.clone(), addr_b);
        let carrier_b = Carrier::direct(sock_b.clone(), addr_a);
        let stats_a = Arc::new(PeerStats::default());
        let stats_b = Arc::new(PeerStats::default());
        let handle_a = PqPeerHandle::new(
            cfg.clone(),
            a.secret.clone(),
            a.public.to_bytes(),
            b.public.to_bytes(),
            1,
            None,
            tunn_a.clone(),
            carrier_a.clone(),
            stats_a.clone(),
        );
        let handle_b = PqPeerHandle::new(
            cfg,
            b.secret.clone(),
            b.public.to_bytes(),
            a.public.to_bytes(),
            2,
            None,
            tunn_b.clone(),
            carrier_b.clone(),
            stats_b.clone(),
        );

        // 1. Initiate epoch = 1, drop fragment 1 of KIND_INIT, and verify retry recovers.
        assert!(handle_a.start_initial().await);
        let init_frags = read_pq_datagrams(&sock_b).await;
        assert_eq!(init_frags.len(), 3);
        handle_b.handle_inbound(&init_frags[0], &carrier_b).await;
        handle_b.handle_inbound(&init_frags[2], &carrier_b).await;
        assert!(read_pq_datagrams(&sock_a).await.is_empty());

        tokio::time::sleep(Duration::from_millis(25)).await;
        handle_a.tick_timer().await;
        for f in read_pq_datagrams(&sock_b).await {
            handle_b.handle_inbound(&f, &carrier_b).await;
        }

        // 2. Drop fragment 0 of KIND_RESP, and verify retry of KIND_INIT hits cached `pending_resps` and recovers.
        let resp_frags = read_pq_datagrams(&sock_a).await;
        assert_eq!(resp_frags.len(), 3);
        handle_a.handle_inbound(&resp_frags[1], &carrier_a).await;
        handle_a.handle_inbound(&resp_frags[2], &carrier_a).await;
        assert!(handle_a.inner.lock().await.pending_confirm.is_none());

        tokio::time::sleep(Duration::from_millis(25)).await;
        handle_a.tick_timer().await;
        for f in read_pq_datagrams(&sock_b).await {
            handle_b.handle_inbound(&f, &carrier_b).await;
        }
        for f in read_pq_datagrams(&sock_a).await {
            handle_a.handle_inbound(&f, &carrier_a).await;
        }

        // 3. Drop the initial KIND_CONFIRM, and verify `pending_confirm` retry delivers it.
        let first_confirm = read_pq_datagrams(&sock_b).await;
        assert_eq!(first_confirm.len(), 1);
        assert_eq!(handle_b.snapshot().await.current_epoch, 0);

        tokio::time::sleep(Duration::from_millis(25)).await;
        handle_a.tick_timer().await;
        let retry_confirm = read_pq_datagrams(&sock_b).await;
        assert_eq!(retry_confirm.len(), 1);
        handle_b.handle_inbound(&retry_confirm[0], &carrier_b).await;
        // Peer B has now committed epoch = 1 and sent KIND_ACK!
        assert_eq!(handle_b.snapshot().await.current_epoch, 1);

        // 4. Drop Peer B's initial KIND_ACK! Peer A is still at epoch = 0 in `pending_confirm`.
        let dropped_ack = read_pq_datagrams(&sock_a).await;
        assert_eq!(dropped_ack.len(), 1);
        assert_eq!(handle_a.snapshot().await.current_epoch, 0);

        // Peer A's timer retransmits the same KIND_CONFIRM (duplicate nonce); Peer B must
        // re-send its cached KIND_ACK from `committed_acks` so Peer A converges to epoch = 1!
        tokio::time::sleep(Duration::from_millis(25)).await;
        handle_a.tick_timer().await;
        for c in read_pq_datagrams(&sock_b).await {
            handle_b.handle_inbound(&c, &carrier_b).await;
        }
        let replayed_ack = read_pq_datagrams(&sock_a).await;
        assert_eq!(
            replayed_ack.len(),
            1,
            "responder must re-send cached KIND_ACK on duplicate KIND_CONFIRM"
        );
        handle_a.handle_inbound(&replayed_ack[0], &carrier_a).await;

        let sa = handle_a.snapshot().await;
        let sb = handle_b.snapshot().await;
        assert_eq!(sa.current_epoch, 1);
        assert_eq!(sb.current_epoch, 1);
        assert_eq!(sa.psk_fingerprint, sb.psk_fingerprint);
        assert_eq!(
            tunn_a.lock().await.preshared_key(),
            tunn_b.lock().await.preshared_key()
        );
    }

    #[tokio::test]
    async fn pq_psk_epoch_behind_peer_converges_via_monotonic_effective_epoch() {
        use tokio::net::UdpSocket;

        let a = WgKeypair::generate();
        let b = WgKeypair::generate();
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_a = sock_a.local_addr().unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let cfg = PqPskConfig {
            mode: PqPskMode::Required,
            rekey_interval: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(300),
            retry_interval: Duration::from_millis(10),
            max_retries: 2,
            configured_psk: None,
        };
        let tunn_a = Arc::new(Mutex::new(Tunn::new(
            a.secret.clone(),
            b.public,
            PqPeerHandle::initial_tunn_psk(&cfg),
            None,
            1,
            None,
        )));
        let tunn_b = Arc::new(Mutex::new(Tunn::new(
            b.secret.clone(),
            a.public,
            PqPeerHandle::initial_tunn_psk(&cfg),
            None,
            2,
            None,
        )));
        let carrier_a = Carrier::direct(sock_a.clone(), addr_b);
        let carrier_b = Carrier::direct(sock_b.clone(), addr_a);
        let stats_a = Arc::new(PeerStats::default());
        let stats_b = Arc::new(PeerStats::default());
        let handle_a = PqPeerHandle::new(
            cfg.clone(),
            a.secret.clone(),
            a.public.to_bytes(),
            b.public.to_bytes(),
            1,
            None,
            tunn_a.clone(),
            carrier_a.clone(),
            stats_a.clone(),
        );
        let handle_b = PqPeerHandle::new(
            cfg,
            b.secret.clone(),
            b.public.to_bytes(),
            a.public.to_bytes(),
            2,
            None,
            tunn_b.clone(),
            carrier_b.clone(),
            stats_b.clone(),
        );

        // Establish epoch = 1 on both peers.
        assert!(handle_a.start_initial().await);
        for _ in 0..4 {
            drain_udp_into(&sock_b, &handle_b, &carrier_b).await;
            drain_udp_into(&sock_a, &handle_a, &carrier_a).await;
        }
        assert_eq!(handle_a.snapshot().await.current_epoch, 1);
        assert_eq!(handle_b.snapshot().await.current_epoch, 1);

        // Start rotation to epoch = 2 from Peer A, let Peer B commit epoch = 2,
        // then drop KIND_ACK and all `max_retries` of Peer A's `pending_confirm`
        // so Peer B is at `current_epoch = 2` while Peer A remains at `current_epoch = 1`!
        assert!(handle_a.start_or_rotate().await);
        drain_udp_into(&sock_b, &handle_b, &carrier_b).await; // B receives INIT(2), sends RESP(2)
        drain_udp_into(&sock_a, &handle_a, &carrier_a).await; // A receives RESP(2), sends CONFIRM(2)
        drain_udp_into(&sock_b, &handle_b, &carrier_b).await; // B receives CONFIRM(2), commits epoch = 2, sends ACK(2)
        let _lost_ack = read_pq_datagrams(&sock_a).await; // Drop ACK(2)
        assert_eq!(handle_b.snapshot().await.current_epoch, 2);
        assert_eq!(handle_a.snapshot().await.current_epoch, 1);

        // Exhaust Peer A's `pending_confirm` retries (simulating a transient blackhole)
        // so Peer A times out `pending_confirm` and immediately initiates a fresh `KIND_INIT(req_epoch = 2)`.
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(15)).await;
            handle_a.tick_timer().await;
            let _dropped = read_pq_datagrams(&sock_b).await;
        }
        // On the timeout tick, Peer A immediately launched a fresh KIND_INIT(req_epoch = 2);
        // trigger one retry and deliver it to Peer B (which is already at epoch = 2).
        tokio::time::sleep(Duration::from_millis(15)).await;
        handle_a.tick_timer().await;
        for _ in 0..4 {
            drain_udp_into(&sock_b, &handle_b, &carrier_b).await;
            drain_udp_into(&sock_a, &handle_a, &carrier_a).await;
        }

        // Peer B answered `req_epoch = 2 <= current_epoch (2)` with `effective_epoch = 3`,
        // converging both peers to `epoch = 3` with identical PSK!
        let sa = handle_a.snapshot().await;
        let sb = handle_b.snapshot().await;
        assert_eq!(sa.current_epoch, 3);
        assert_eq!(sb.current_epoch, 3);
        assert_eq!(sa.psk_fingerprint, sb.psk_fingerprint);
        assert_eq!(
            tunn_a.lock().await.preshared_key(),
            tunn_b.lock().await.preshared_key()
        );
    }

    #[tokio::test]
    async fn pq_psk_rejects_replayed_stale_epoch_init_without_allocating_pending_resp_or_aborting_pending_init()
     {
        use tokio::net::UdpSocket;

        let k1 = WgKeypair::generate();
        let k2 = WgKeypair::generate();
        let (primary, non_primary) = if k1.public.to_bytes() < k2.public.to_bytes() {
            (k1, k2)
        } else {
            (k2, k1)
        };

        let sock_p = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_np = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr_p = sock_p.local_addr().unwrap();
        let addr_np = sock_np.local_addr().unwrap();

        let cfg = PqPskConfig {
            mode: PqPskMode::Required,
            rekey_interval: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(300),
            retry_interval: Duration::from_millis(50),
            max_retries: 6,
            configured_psk: None,
        };
        let tunn_p = Arc::new(Mutex::new(Tunn::new(
            primary.secret.clone(),
            non_primary.public,
            PqPeerHandle::initial_tunn_psk(&cfg),
            None,
            1,
            None,
        )));
        let tunn_np = Arc::new(Mutex::new(Tunn::new(
            non_primary.secret.clone(),
            primary.public,
            PqPeerHandle::initial_tunn_psk(&cfg),
            None,
            2,
            None,
        )));
        let carrier_p = Carrier::direct(sock_p.clone(), addr_np);
        let carrier_np = Carrier::direct(sock_np.clone(), addr_p);
        let stats_p = Arc::new(PeerStats::default());
        let stats_np = Arc::new(PeerStats::default());
        let handle_p = PqPeerHandle::new(
            cfg.clone(),
            primary.secret.clone(),
            primary.public.to_bytes(),
            non_primary.public.to_bytes(),
            1,
            None,
            tunn_p.clone(),
            carrier_p.clone(),
            stats_p,
        );
        let handle_np = PqPeerHandle::new(
            cfg,
            non_primary.secret.clone(),
            non_primary.public.to_bytes(),
            primary.public.to_bytes(),
            2,
            None,
            tunn_np.clone(),
            carrier_np.clone(),
            stats_np,
        );

        // Capture a valid authenticated `KIND_INIT(req_epoch = 2)` from primary BEFORE it is ever committed
        // (so its `init_nonce` is NOT in `committed_init_nonces`).
        let captured_stale_init_e2 = {
            let mut gp = handle_p.inner.lock().await;
            let f = handle_p.build_init_locked(&mut gp, 2);
            gp.pending_init = None;
            f
        };
        let captured_stale_frags_e2 = handle_p.fragment_control_frame(&captured_stale_init_e2);
        assert_eq!(captured_stale_frags_e2.len(), 3);

        // Advance both peers normally through epoch 1 -> 2 -> 3 (`current_epoch == 3`).
        assert!(handle_p.start_initial().await);
        for _ in 0..4 {
            drain_udp_into(&sock_np, &handle_np, &carrier_np).await;
            drain_udp_into(&sock_p, &handle_p, &carrier_p).await;
        }
        for target_epoch in 2..=3u64 {
            assert!(handle_p.start_or_rotate().await);
            for _ in 0..4 {
                drain_udp_into(&sock_np, &handle_np, &carrier_np).await;
                drain_udp_into(&sock_p, &handle_p, &carrier_p).await;
            }
            assert_eq!(handle_p.snapshot().await.current_epoch, target_epoch);
            assert_eq!(handle_np.snapshot().await.current_epoch, target_epoch);
        }

        // Start a legitimate rotation on `non_primary` (`pending_init` is `Some(epoch = 4)`).
        assert!(handle_np.start_or_rotate().await);
        let _ = read_pq_datagrams(&sock_p).await;
        let orig_init_nonce = handle_np
            .inner
            .lock()
            .await
            .pending_init
            .as_ref()
            .expect("pending_init must exist on non-primary")
            .init_nonce;

        // Replay the captured `req_epoch = 2` (`< current_epoch (3)` and `!= 1`) both as fragments
        // (`on_frag`) and as a full frame (`on_init`) against `non_primary`.
        for frag in &captured_stale_frags_e2 {
            handle_np.handle_inbound(frag, &carrier_np).await;
        }
        assert!(
            handle_np.inner.lock().await.frag_reassembly.is_empty(),
            "stale-epoch KIND_INIT fragments must be dropped in on_frag without allocating reassembly slots"
        );
        handle_np
            .handle_inbound(&captured_stale_init_e2, &carrier_np)
            .await;

        {
            let g_np = handle_np.inner.lock().await;
            assert!(
                g_np.pending_resps.is_empty(),
                "replayed stale-epoch KIND_INIT must not allocate a PendingResp or block periodic rotation"
            );
            assert_eq!(
                g_np.pending_init.as_ref().map(|p| (p.epoch, p.init_nonce)),
                Some((4, orig_init_nonce)),
                "replayed stale-epoch KIND_INIT must not abort non-primary's in-flight pending_init"
            );
        }
        assert!(
            read_pq_datagrams(&sock_p).await.is_empty(),
            "replayed stale-epoch KIND_INIT must not elicit any response packet"
        );
    }
}
