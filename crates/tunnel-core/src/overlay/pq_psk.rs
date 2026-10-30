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
use ml_kem::{
    B32, DecapsulationKey768, EncapsulationKey768, KeyExport, Seed,
    kem::Decapsulate,
};
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
    frag_reassembly: VecDeque<FragReassemblySlot>,
    last_ack: Option<CommittedAckCache>,
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

impl fmt::Debug for PqPeerInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqPeerInner")
            .field("config", &self.config)
            .field("status", &self.status)
            .field("current_epoch", &self.current_epoch)
            .field("active_psk", &self.active_psk.as_ref().map(|_| "[REDACTED]"))
            .field("rotations_completed", &self.rotations_completed)
            .field("mismatch_count", &self.mismatch_count)
            .field("downgraded_count", &self.downgraded_count)
            .field("expired_count", &self.expired_count)
            .field("failed_exchanges", &self.failed_exchanges)
            .finish()
    }
}

/// Shared handle for one peer's PQ-PSK state machine and [`Tunn`] binding.
///
/// Holds [`std::sync::Weak`] references to `Tunn`, `Carrier`, and `PeerStats`
/// so storing `Arc<PqPeerHandle>` inside `PeerStats::pq` never forms an `Arc`
/// reference cycle and dropping `Peer` immediately releases `Tunn`.
pub(crate) struct PqPeerHandle {
    mode: PqPskMode,
    self_public: [u8; 32],
    peer_public: [u8; 32],
    auth_key: [u8; 32],
    tunn_index: u32,
    tunn: std::sync::Weak<Mutex<Tunn>>,
    carrier: std::sync::Weak<Carrier>,
    stats: std::sync::Weak<PeerStats>,
    inner: Mutex<PqPeerInner>,
    /// Lock-free mirror of whether PQ-PSK is currently blocking classical
    /// handshakes (`Required` mode before PQ establishment).
    guard_active: std::sync::atomic::AtomicBool,
    epoch_atomic: AtomicU64,
}

impl fmt::Debug for PqPeerHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqPeerHandle")
            .field("peer_public", &short_hex(&self.peer_public))
            .field("tunn_index", &self.tunn_index)
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
        stats
            .pq_guard_active
            .store(guard_active, Ordering::Release);
        Arc::new(Self {
            mode,
            self_public,
            peer_public,
            auth_key,
            tunn_index,
            tunn: Arc::downgrade(&tunn),
            carrier: Arc::downgrade(&carrier),
            stats: Arc::downgrade(&stats),
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
                frag_reassembly: VecDeque::new(),
                last_ack: None,
                rotations_completed: 0,
                mismatch_count: 0,
                downgraded_count: 0,
                expired_count: 0,
                failed_exchanges: 0,
            }),
            guard_active: std::sync::atomic::AtomicBool::new(guard_active),
            epoch_atomic: AtomicU64::new(0),
        })
    }

    fn set_guard_active(&self, active: bool) {
        self.guard_active.store(active, Ordering::Release);
        if let Some(stats) = self.stats.upgrade() {
            stats.pq_guard_active.store(active, Ordering::Release);
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
            && let Some(carrier) = self.carrier.upgrade()
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
            && let Some(carrier) = self.carrier.upgrade()
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
                        }
                    }
                } else if let Some(est_at) = g.established_at {
                    // 3. Check periodic rekey / rotation (rekey_interval)
                    let stagger = if self.is_primary_initiator() {
                        Duration::ZERO
                    } else {
                        NON_PRIMARY_INITIAL_STAGGER
                    };
                    if est_at.elapsed() >= g.config.rekey_interval.saturating_add(stagger) {
                        let next_epoch = g.current_epoch.saturating_add(1);
                        to_send = Some(self.build_init_locked(&mut g, next_epoch));
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
            && let Some(carrier) = self.carrier.upgrade()
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

    fn build_reject_frame(&self, mode: PqPskMode, epoch: u64, init_nonce: &[u8; 16], reason: u8) -> Vec<u8> {
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
                if g.committed_init_nonces.contains(&msg_nonce)
                    || (epoch <= g.current_epoch && epoch != 1)
                {
                    return;
                }
            } else if inner_kind == KIND_RESP {
                let matches_pending_init = g.pending_init.as_ref().is_some_and(|p| epoch >= p.epoch);
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
            } else if g.committed_init_nonces.contains(&init_nonce) {
                // Reject replayed KIND_INIT from an already-committed exchange.
                None
            } else if let Some(existing) = g
                .pending_resps
                .iter()
                .find(|r| r.init_nonce == init_nonce)
            {
                // Deduplicate retransmitted KIND_INIT for an already-cached response
                Some(existing.resp_frame.clone())
            } else if req_epoch <= g.current_epoch && req_epoch != 1 {
                // Reject stale non-restart KIND_INIT epochs (a live peer always
                // requests current_epoch + 1; a restarted peer requests 1).
                None
            } else if (g.pending_init.is_some() || g.pending_confirm.is_some())
                && self.is_primary_initiator()
            {
                // Simultaneous initiation glare (automatic or explicit): the
                // lexicographically smaller static pubkey wins the initiator
                // role so the two peers never cross-install distinct PSKs.
                // Re-send our in-flight KIND_INIT over `reply_carrier` so a
                // NATted non-primary peer receives it across the punched pinhole.
                g.pending_init.as_ref().map(|i| i.frame.clone())
            } else {
                if (g.pending_init.is_some() || g.pending_confirm.is_some())
                    && !self.is_primary_initiator()
                {
                    g.pending_init = None;
                    g.pending_confirm = None;
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
            if let Some(ack) = g.last_ack.as_ref()
                && ack.epoch == epoch
                && ack.init_nonce == init_nonce
                && ack.resp_nonce == resp_nonce
            {
                Some(ack.ack_frame.clone())
            } else if let Some(pos) = g
                .pending_resps
                .iter()
                .position(|r| r.epoch == epoch && r.init_nonce == init_nonce && r.resp_nonce == resp_nonce)
            {
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

                    g.last_ack = Some(CommittedAckCache {
                        epoch,
                        init_nonce,
                        resp_nonce,
                        ack_frame: ack_frame.clone(),
                    });
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
        let Some(tunn) = self.tunn.upgrade() else {
            return;
        };
        let Some(stats) = self.stats.upgrade() else {
            return;
        };
        let out_packets = {
            let mut t = tunn.lock().await;
            // B7 in-place PSK update: update `handshake.params.preshared_key`
            // without reconstructing `Tunn`, preserving `last_handshake_timestamp`
            // (TAI64N anti-replay watermark) across all PSK establishments and
            // rotations.
            t.set_preshared_key(psk);
            self.set_guard_active(guard_after);
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
            let upgraded = self.carrier.upgrade();
            if let Some(out_carrier) = reply_carrier.or(upgraded.as_ref()) {
                for pkt in &out_packets {
                    let _ = super::wg::send_wg_recorded(out_carrier, &stats, pkt).await;
                }
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
        assert_eq!(frags.len(), 3, "1282 B KIND_INIT must split into 3 sub-700B fragments");
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
}
