// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Wire protocol for the `rc:*` WebSocket namespace.
//!
//! Both the agent and the controller browser speak the same envelope shape;
//! they're distinguished by which JWT audience their connection authenticated
//! with. See `signaling::Role`.
//!
//! Every message is a JSON object with a `t` discriminator. We use serde's
//! `tag = "t"` adjacent encoding so the wire is small and stable.
//!
//! **ObjectId fields are serialised as raw hex strings, not bson-extended
//! JSON (`{"$oid":"…"}`).** This matches the REST responses and is what
//! the browser / native agent clients actually produce. See
//! [`serde_helpers`] for the pinning shims; a regression test in that
//! module locks the format.

use bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

use crate::models::{AgentCaps, ConsentMode, DisplayInfo, EndReason, OsKind};
use crate::permissions::Permissions;
use crate::serde_helpers::{oid_hex, option_oid_hex, vec_oid_hex};

/// Which side of the connection sent / receives a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Agent,
    Controller,
}

// ────────────────────────────────────────────────────────────────────────────
// Tunnel supporting types
// ────────────────────────────────────────────────────────────────────────────

/// Role advertised in `rc:tunnel.hello`. Distinguishes the
/// `roomler` CLI (which initiates forwards) from the agent
/// (which serves them). Wire form: `"client"` | `"agent"`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelRole {
    Client,
    Agent,
}

/// Why a `TcpForwardRequest` was rejected. The discriminator drives
/// the CLI's exit-code mapping + the audit log row's `kind`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RejectKind {
    /// Tenant of the requesting client ≠ tenant of the target agent.
    /// Server-side gate (plan §"Multi-tenancy gotcha"); never reached
    /// after the WS handshake's tenant_id check, but locked here as
    /// defence-in-depth.
    CrossTenant,
    /// Tenant policy denies this (subject, agent, dst) tuple.
    AclDenied,
    /// Agent dialed dst and got a hard failure (connection refused,
    /// dst unreachable, dns failure).
    DialFailed,
    /// Per-session concurrent-flow ceiling reached.
    RateLimited,
    /// Per-peer concurrent-flow ceiling reached (default 256 per plan
    /// "Structural issues" #1a — bounds the leak risk under JDBC churn).
    TooManyFlows,
    /// Catch-all for agent-side errors that don't fit above.
    AgentError,
}

/// Reject reason the agent sends when a forward names a `session_id` it
/// doesn't know. Canonical signal that the agent lost its tunnel-session
/// state: its per-connection peer maps die with the WS, so after a network
/// flap + reconnect EVERY forward on a pre-flap session gets this reject,
/// forever. Tunnel clients match on it (`RejectKind::AgentError` + this
/// substring) and treat it as session death — end the session so the flow
/// supervisor re-opens with fresh state instead of failing every local
/// connection. Wire-stable: the string predates the client-side match, so
/// rejects from older agents match too. Do not reword.
pub const REJECT_REASON_SESSION_GONE: &str = "tunnel session not open on agent";

/// Reject reason the SERVER sends when it holds NO tunnel session for the
/// connection a forward arrived on (the client sent `TcpForwardRequest`
/// before/without a live `TunnelOpen`, or the server tore the session down —
/// e.g. an agent-disconnect teardown — while the client kept forwarding).
/// Same session-death class as [`REJECT_REASON_SESSION_GONE`] but raised one
/// hop earlier, at the server: clients match it too and re-open. Wire-stable,
/// do not reword. Emitted at `crates/api/src/ws/tunnel.rs` (handle_forward_request).
pub const REJECT_REASON_NO_SESSION: &str = "no open session (send rc:tunnel.open first)";

/// Reject reason the SERVER sends when a forward's `session_id` doesn't match
/// the session currently open on that connection — the client is still
/// forwarding on a stale session id after the server rebuilt/replaced it.
/// Also session-death: re-opening yields a fresh id both sides agree on.
/// Wire-stable, do not reword. Emitted at `crates/api/src/ws/tunnel.rs`.
pub const REJECT_REASON_SESSION_MISMATCH: &str = "session_id mismatch";

/// #2251 — the `limit` an agent's `rc:terminate` names, with `reason`
/// `Error`, when the browser's offer carries no codec the device's RTP video
/// track can send. Nothing a retry changes would fix that, so a viewer reads
/// it as final and says why. The hub honours it only from the agent and only
/// with `Error` (`device_end_limit`); an older server drops it, and the
/// session ends as the plain `Error` every reader knows. Wire-stable, do not
/// reword.
pub const LIMIT_NO_COMMON_CODEC: &str = "no_common_codec";

/// FR-90 P3-3a — the length of a vault key on the wire: the standard, padded
/// base64 of 32 bytes.
pub const VAULT_KEY_B64_LEN: usize = 44;

/// FR-90 P3-3a — is `key` a vault key as [`ClientMsg::AgentHello`] carries
/// one: the standard, padded base64 of exactly 32 bytes, spelled canonically
/// (the bytes encode back to the same text, so one key has one stored form),
/// and not all zeros.
///
/// The server stores a hello's key only when this holds, and stores the empty
/// string otherwise, so the vault never meets a key it cannot seal to. The
/// zero check is a sanity check on a device's bug, not a security boundary: a
/// device that wants its own leased values read elsewhere can send them there
/// itself.
pub fn vault_key_is_well_formed(key: &str) -> bool {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    if key.len() != VAULT_KEY_B64_LEN {
        return false;
    }
    match STANDARD.decode(key) {
        Ok(bytes) => {
            bytes.len() == 32 && STANDARD.encode(&bytes) == key && bytes.iter().any(|b| *b != 0)
        }
        Err(_) => false,
    }
}

/// FR-100 P1a — the length of a device key on the wire: the standard, padded
/// base64 of a 65-byte uncompressed P-256 point.
pub const PEER_AUTH_KEY_B64_LEN: usize = 88;

/// FR-100 P1a — is `key` a device key as [`ClientMsg::AgentHello`] carries
/// one: the standard, padded base64 of an uncompressed SEC1 P-256 point
/// (65 bytes, `0x04 ‖ X ‖ Y`), spelled canonically, so one key has one
/// stored form.
///
/// The server stores a hello's key only when this holds, and the empty
/// string otherwise. It checks the SHAPE, not that the point is on the
/// curve: the server's copy is a hint for a browser's first pin, never an
/// authority (`docs/fr/FR-100-controller-identity.md` §3e), and WebCrypto
/// refuses to import a point that is not on the curve. A device that sends
/// one only ever makes itself unable to prove who it is.
pub fn peer_auth_key_is_well_formed(key: &str) -> bool {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    if key.len() != PEER_AUTH_KEY_B64_LEN {
        return false;
    }
    match STANDARD.decode(key) {
        Ok(bytes) => bytes.len() == 65 && bytes[0] == 0x04 && STANDARD.encode(&bytes) == key,
        Err(_) => false,
    }
}

/// FR-100 P1a — how a person reads a device key: the first 10 bytes of the
/// SHA-256 of the 65-byte point, as lowercase hex in groups of four
/// (`3f2a 9c01 77de 0b4e 51c8`). `None` for a key that is not well formed.
///
/// The device page shows it today. The browser's pin (P2) and the device's
/// approval prompt (P3) must show the SAME string for the same key, so this
/// is the one definition, locked by a known-answer test.
pub fn peer_auth_fingerprint(key: &str) -> Option<String> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    if !peer_auth_key_is_well_formed(key) {
        return None;
    }
    let point = STANDARD.decode(key).ok()?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &point);
    let hex: String = digest.as_ref()[..10]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Some(
        hex.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// FR-100 P1b — what a controller's offer carries for the device to sign
/// against: the nonce. With P2b the browser also signs its offer, and `key`
/// and `sig` carry that: fields an older reader skips, and an older viewer
/// never sends.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PeerAuthOffer {
    /// The browser's fresh nonce, base64url without padding, 16 to 32 bytes
    /// ([`peer_auth_nonce_is_well_formed`]). It is what makes a signed answer
    /// this offer's and no other's.
    pub nonce: String,
    /// FR-100 P2b — the browser's own key, in the device key's shape
    /// ([`peer_auth_key_is_well_formed`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// FR-100 P2b — the browser's signature over the transcript with role
    /// `offer` and an EMPTY answer fingerprint ([`peer_auth_transcript`]),
    /// base64url without padding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

/// FR-100 P1c — what the device concluded about the browser that offered a
/// session, as its answer reports it and the session's audit records it:
/// - `absent`: the offer carried no browser signature;
/// - `unknown`: a signature that verifies, by a key the device had not seen
///   for this user (under `audit` it is now remembered);
/// - `verified`: a signature that verifies, by a key the device remembers
///   for this user, or an outsider's session FR-52's MAC admitted;
/// - `mismatch`: a signature that does not verify over this session.
///
/// ⚠️ A STRING on the wire, never an enum: a word a newer device sends must
/// not fail an older server's whole answer frame. Readers check it with
/// [`peer_auth_verdict_is_known`] and record nothing they do not know.
pub const PEER_AUTH_VERDICTS: [&str; 4] = ["absent", "unknown", "verified", "mismatch"];

/// FR-100 P1c — is `verdict` one of [`PEER_AUTH_VERDICTS`]? Equality only.
pub fn peer_auth_verdict_is_known(verdict: &str) -> bool {
    PEER_AUTH_VERDICTS.contains(&verdict)
}

/// FR-100 P1b — the device's signature over its answer: the transcript
/// ([`peer_auth_transcript`], role `answer`) signed with the enrollment's
/// device key. ECDSA P-256 over SHA-256, as the fixed-size `r ‖ s` that
/// WebCrypto verifies, base64url without padding.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PeerAuthAnswer {
    /// The key that signed, as the hello carries it
    /// ([`peer_auth_key_is_well_formed`]). A browser pins THIS, on first use;
    /// the server's copy is only ever a hint.
    pub key: String,
    pub sig: String,
}

/// FR-100 P1b — the label every peer-auth signature is scoped by. Part of the
/// wire: changing it invalidates every signature in both directions.
pub const PEER_AUTH_LABEL: &[u8] = b"roomler-peer-auth-v1";

/// FR-100 P1b — the bytes a peer-auth signature covers: the label, then each
/// field as `u16be(len) ‖ bytes` (FR-52's transport MAC frames its fields the
/// same way), in this order:
/// 1. the role, `offer` or `answer`, so one side's signature can never be
///    replayed as the other's;
/// 2. the session id, the agent id and the user id, 24 lowercase hex digits
///    each, so it holds for one session between one user and one device;
/// 3. the offer's DTLS fingerprint and the answer's, as
///    [`sdp_dtls_fingerprint`] normalises them: what the handshake then holds
///    each side to. For role `offer` (P2) the answer does not exist yet, and
///    its fingerprint is the empty string;
/// 4. the browser's nonce, which makes it fresh.
///
/// `None` when a field is too long to frame, which no well-formed input is:
/// the caller then signs nothing. The viewer builds the same bytes, and both
/// are held to one known answer.
pub fn peer_auth_transcript(
    role: &str,
    session_id: &str,
    agent_id: &str,
    user_id: &str,
    offer_fingerprint: &str,
    answer_fingerprint: &str,
    nonce: &str,
) -> Option<Vec<u8>> {
    let fields = [
        role,
        session_id,
        agent_id,
        user_id,
        offer_fingerprint,
        answer_fingerprint,
        nonce,
    ];
    let mut out = Vec::with_capacity(
        PEER_AUTH_LABEL.len() + fields.iter().map(|f| f.len() + 2).sum::<usize>(),
    );
    out.extend_from_slice(PEER_AUTH_LABEL);
    for field in fields {
        let len = u16::try_from(field.len()).ok()?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    Some(out)
}

/// FR-100 P1b — is `nonce` a browser's nonce as [`PeerAuthOffer`] carries one:
/// base64url without padding of 16 to 32 bytes, spelled canonically. Anything
/// else is not signed against.
pub fn peer_auth_nonce_is_well_formed(nonce: &str) -> bool {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    if nonce.len() > 43 {
        return false;
    }
    match URL_SAFE_NO_PAD.decode(nonce) {
        Ok(bytes) => (16..=32).contains(&bytes.len()) && URL_SAFE_NO_PAD.encode(&bytes) == nonce,
        Err(_) => false,
    }
}

/// FR-100 P1b — does `sig` (base64url, the fixed 64-byte `r ‖ s`) verify over
/// `transcript` under `key` (a device key as the hello carries it)? The
/// browser's check, in Rust, so the tests here and the server's can prove
/// what a device signed.
pub fn peer_auth_verify(key: &str, transcript: &[u8], sig: &str) -> bool {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    if !peer_auth_key_is_well_formed(key) {
        return false;
    }
    let (Ok(point), Ok(sig)) = (STANDARD.decode(key), URL_SAFE_NO_PAD.decode(sig)) else {
        return false;
    };
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, point)
        .verify(transcript, &sig)
        .is_ok()
}

/// Why an SDP's DTLS fingerprint could not be read
/// ([`sdp_dtls_fingerprint`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdpFingerprintError {
    /// The SDP names no DTLS certificate.
    Missing,
    /// It names more than one, or a line is not exactly a hash name and one
    /// value.
    Ambiguous,
}

/// The one DTLS fingerprint an SDP names, as `"<hash> <HEX:PAIRS>"`, with the
/// hash name lowercased and the hex uppercased. Repeated `a=fingerprint:`
/// lines are fine when they agree (a bundle repeats it per media section);
/// two different ones are ambiguous.
///
/// FR-52 P4 wrote it for the external binding's MAC; FR-100 P1b moved it here
/// unchanged, because the device signs over the same fingerprints in every
/// build, and two copies of a normalisation are two chances to disagree.
pub fn sdp_dtls_fingerprint(sdp: &str) -> Result<String, SdpFingerprintError> {
    let mut found: Option<String> = None;
    for line in sdp.lines() {
        let Some(value) = line.trim().strip_prefix("a=fingerprint:") else {
            continue;
        };
        let mut parts = value.split_whitespace();
        let (Some(hash), Some(hex), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(SdpFingerprintError::Ambiguous);
        };
        let normalised = format!("{} {}", hash.to_ascii_lowercase(), hex.to_ascii_uppercase());
        match &found {
            None => found = Some(normalised),
            Some(seen) if *seen == normalised => {}
            Some(_) => return Err(SdpFingerprintError::Ambiguous),
        }
    }
    found.ok_or(SdpFingerprintError::Missing)
}

/// Half-close direction in `TcpHalfClose`. SMTP / HTTP-1.1-long-poll /
/// some legacy protocols rely on this.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Source (client-side listener) has finished writing; reads still
    /// alive. Mirrors `TcpStream::shutdown(Shutdown::Write)`.
    SrcToDst,
    /// Destination (agent's dialed dst) has finished writing.
    DstToSrc,
}

/// Why a `TcpClosed` was emitted. Mostly free-form but the common
/// cases are enumerated for the audit log's roll-up.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    /// Clean EOF from one side.
    Eof,
    /// I/O error on the agent's dst socket or the client's local
    /// socket.
    IoError,
    /// Agent-side allowlist (belt-and-suspenders) denied dst.
    AgentAclDenied,
    /// Client-side `tunnel forward` Ctrl-C / shutdown.
    ClientShutdown,
    /// Server kicked the session (admin terminate, revocation, etc.).
    ServerTerminated,
    /// Idle-timeout (default 5 min — see plan §"Missing pieces").
    IdleTimeout,
}

// ────────────────────────────────────────────────────────────────────────────
// Agent connection-level close reasons (rc.53)
// ────────────────────────────────────────────────────────────────────────────

/// Server-initiated close reason for an agent WS connection. Carried
/// by [`ServerMsg::Goodbye`]. Distinct from the session-level
/// [`EndReason`] (which terminates one remote-control session) and
/// from [`CloseReason`] (which terminates one tunnel flow) — this is
/// connection-level.
///
/// `Deserialize` is implemented by hand so that unknown variants
/// (rc.54+ additions) decode to [`PolicyRejected`] rather than
/// serde-failing the whole message. This is the future-compat
/// hatch a fielded rc.53 agent needs to survive a server that
/// learned new reasons.
///
/// [`PolicyRejected`]: AgentCloseReason::PolicyRejected
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentCloseReason {
    /// Server-side `agents` row has `deleted_at != null` or is
    /// otherwise refused by the WS handler's lookup. The agent's
    /// stored token is cryptographically valid but useless. Re-enrol
    /// to revive (soft-deleted rows rehydrate on `(tenant_id,
    /// machine_id)` match — `Hub::register_agent` calls `rehydrate()`).
    AgentDeleted,
    /// A newer WS connection presented the SAME `agent_id`; the Hub
    /// kept the new one, dropped this old one. Indicates a duplicate
    /// install somewhere (another physical host with a copy of this
    /// `config.toml`, the tray companion, etc.).
    ReplacedByNewerConnection,
    /// Server-side policy refused (account suspended, tenant
    /// disabled, version too old). Reserved for future use; also the
    /// default the decoder picks for unknown-string variants so
    /// future rc.54+ variants don't hard-fault rc.53 agents in the
    /// field.
    PolicyRejected,
}

impl<'de> Deserialize<'de> for AgentCloseReason {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "agent_deleted" => AgentCloseReason::AgentDeleted,
            "replaced_by_newer_connection" => AgentCloseReason::ReplacedByNewerConnection,
            "policy_rejected" => AgentCloseReason::PolicyRejected,
            // Forward-compat: unknown rc.54+ reasons decode to a
            // safe non-panicking default. The agent's handle_server_msg
            // arm treats PolicyRejected as fatal, which matches the
            // semantics of "server told us to stop and we don't know
            // why" better than `ReplacedByNewer` (which is recoverable).
            _ => AgentCloseReason::PolicyRejected,
        })
    }
}

/// FR-47 — why an [`ServerMsg::OverlayJoinRefused`] was sent.
///
/// Enumerated rather than free text because the daemon acts on it: address
/// exhaustion is an operator problem that retrying cannot fix, while a
/// transient store failure is worth another attempt. The `detail` string
/// carries the human-readable specifics.
///
/// `Deserialize` is hand-written for the same reason [`AgentCloseReason`]'s
/// is: a fielded node must survive a server that learned a new reason. Unknown
/// decodes to [`Unknown`](OverlayJoinRefusal::Unknown), which the daemon
/// reports verbatim and treats as non-retryable — the conservative arm, since
/// a reason we cannot interpret is not one we can safely retry against.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OverlayJoinRefusal {
    /// Every host ordinal in the tenant's block is leased. Retrying cannot
    /// help; the block needs to grow or devices need releasing.
    AddressSpaceExhausted,
    /// The tenant's network row or CIDR could not be resolved.
    NetworkUnavailable,
    /// A transient persistence failure. Retryable.
    StoreUnavailable,
    /// A reason this build does not know.
    Unknown,
}

impl<'de> Deserialize<'de> for OverlayJoinRefusal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "address_space_exhausted" => OverlayJoinRefusal::AddressSpaceExhausted,
            "network_unavailable" => OverlayJoinRefusal::NetworkUnavailable,
            "store_unavailable" => OverlayJoinRefusal::StoreUnavailable,
            _ => OverlayJoinRefusal::Unknown,
        })
    }
}

impl OverlayJoinRefusal {
    /// Is another join attempt worth making?
    ///
    /// Only the transient arm. Exhaustion in particular must NOT retry: the
    /// daemon would hammer a server that is already telling an operator it is
    /// out of addresses, and the reconnect loop would bury the one log line
    /// that explains the outage.
    pub fn is_retryable(self) -> bool {
        matches!(self, OverlayJoinRefusal::StoreUnavailable)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Inbound from clients (agent or controller browser)
// ────────────────────────────────────────────────────────────────────────────

/// Messages the server receives.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t")]
pub enum ClientMsg {
    #[serde(rename = "rc:share.ssh.connect")]
    SharedSshConnect {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
    },
    #[serde(rename = "rc:share.ssh.prepared")]
    SharedSshPrepared {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        accepted: bool,
    },
    #[serde(rename = "rc:share.ssh.lease.challenge")]
    SharedSshLeaseChallenge {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        lease_epoch: String,
        challenge_id: u64,
    },
    /// Agent-originated fresh PDP challenge; not a controller authority.
    #[serde(rename = "rc:share.lease.challenge")]
    SharedLeaseChallenge {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        lease_epoch: String,
        challenge_id: u64,
    },
    // ─── agent → server ───────────────────────────────────────────────
    /// Agent announces itself after WS auth.
    #[serde(rename = "rc:agent.hello")]
    AgentHello {
        machine_name: String,
        os: OsKind,
        /// FR-97 P0d — the machine's NATIVE CPU architecture, in Rust's
        /// `target_arch` spelling (`x86_64`, `aarch64`, `x86`, `arm`). The
        /// hardware, not this binary: an x86_64 build under Rosetta 2, or
        /// under emulation on Windows on Arm, reports `aarch64` and sets
        /// `arch_emulated`. The fleet's capability words
        /// are counted by OS and by this (`scripts/fr97-caps-census.sh`).
        /// Empty from an agent that predates the field, and never sent empty.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        arch: String,
        /// FR-97 P0d — this agent's binary runs under emulation on `arch`
        /// hardware (an x86_64 build on Apple silicon or Windows on Arm).
        /// Absent ⇒ `false`.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        arch_emulated: bool,
        agent_version: String,
        displays: Vec<DisplayInfo>,
        /// Boxed: `AgentCaps` is ~15 `Vec` fields and dominates the size of
        /// the WHOLE `ClientMsg` enum — every message in every per-peer
        /// channel (`PEER_OUTBOUND_CAP` slots each) was paying for it, though
        /// only the once-per-connection hello carries one. Serde is
        /// transparent through `Box`, so the wire format is unchanged.
        caps: Box<AgentCaps>,
        /// Subnet CIDRs the agent advertises it can route for the tunnel mesh
        /// subnet-router (from its `advertise_routes` config). Admin-gated —
        /// stored as untrusted suggestions until approved into `Agent.routes`.
        /// `#[serde(default)]` keeps pre-feature agents (no field) compatible.
        #[serde(default)]
        advertised_routes: Vec<String>,
        /// Multi-region relay PoPs: the agent can receive
        /// [`ServerMsg::RelayRegions`] and answer with
        /// [`ClientMsg::RelayProbeReport`]. Capability-gates the push — a
        /// pre-feature agent's `ServerMsg` deserializer would ERROR on the
        /// unknown variant. Absent ⇒ `false`.
        #[serde(default)]
        supports_relay_regions: bool,
        /// P6 — the OpenSSH **public** half of this device's SSH host key
        /// (`ssh-ed25519 AAAA… roomler-host`), so a caller can verify what it
        /// dialled instead of trusting it on first use.
        ///
        /// Reported here rather than in [`AgentCaps`] because it is an
        /// identity, not a capability: caps answer "what can this device do",
        /// and two devices that can do identical things still must not be
        /// interchangeable to a client checking who it reached.
        ///
        /// Empty when the device stores no host key — never SSH-enabled, or a
        /// build without the `ssh-server` feature. Empty must therefore never
        /// be read as "any key is fine"; it means "this device cannot prove
        /// itself", and a client that cares should refuse rather than fall
        /// back to TOFU. Absent from an older agent's hello deserialises the
        /// same way.
        ///
        /// ⚠️ Non-empty does NOT imply SSH is on: the key survives in the
        /// config after `ssh_enabled` goes false, so a device that once served
        /// keeps publishing.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        ssh_host_pubkey: String,
        /// FR-90 P3-3a — the public half of this daemon's vault key, standard
        /// base64 of the 32-byte X25519 key (see [`vault_key_is_well_formed`]):
        /// what the vault seals a leased value to. An identity like
        /// `ssh_host_pubkey`, so here rather than in [`AgentCaps`].
        ///
        /// Sent only while the device's own `vault_enabled` is on, on the
        /// primary enrollment's connection only. The key lives in daemon
        /// memory and a new one is made at every start, so a value sealed to
        /// it is readable by this process alone, and by nothing that later
        /// reads the disk.
        ///
        /// Empty = the device takes no leases: switched off, a secondary org's
        /// connection, a build without the `vault` feature, or an agent that
        /// predates the field.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        vault_key: String,
        /// FR-100 P1a — the public half of THIS enrollment's device key,
        /// the standard base64 of an uncompressed P-256 point (see
        /// [`peer_auth_key_is_well_formed`]): the key a controller's browser
        /// pins, and the one the device will sign its session answers with.
        /// An identity like `ssh_host_pubkey`, so here rather than in
        /// [`AgentCaps`].
        ///
        /// One key per org enrollment, never shared between them: a key two
        /// orgs both saw would let them correlate the device
        /// (`docs/multi-org.md`, the per-org WG key rule). It is made on the
        /// device and kept in its own file beside the config. Only this
        /// public half ever leaves.
        ///
        /// Empty = the device cannot prove who it is: a key it could not
        /// keep on disk (a per-boot key would break every pin at the next
        /// start, so none is offered), or an agent that predates the field.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        peer_auth_key: String,
    },

    /// Agent periodic stats.
    ///
    /// The legacy top-level `rss_mb`/`cpu_pct` were hardcoded 0 by every
    /// shipped agent, so the server deliberately ignores them; real
    /// telemetry rides the optional [`AgentSysStats`] block (stats PR-5),
    /// whose ABSENCE means "not measured" — old agents simply omit it
    /// (`#[serde(default)]` server-side, additive client→server = no
    /// capability flag needed).
    #[serde(rename = "rc:agent.heartbeat")]
    AgentHeartbeat {
        rss_mb: u32,
        cpu_pct: f32,
        active_sessions: u8,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sys: Option<AgentSysStats>,
        /// NAT-traversal health: how many server-reflexive candidates this
        /// node currently advertises.
        ///
        /// `Some(0)` is the interesting value — it means the node cannot
        /// hole-punch and every peer reads it as UDP-blocked, so all its pairs
        /// degrade to the relay/DERP tier. That state existed **fleet-wide and
        /// unnoticed** until 2026-08-06 because the only signals were `debug!`
        /// log lines on each device; one server-side counter would have caught
        /// it immediately. `None` = an agent that predates the field, which is
        /// distinct from a measured zero.
        ///
        /// Additive agent→server, so no capability flag is needed (unlike a
        /// `ServerMsg` a caller awaits).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        srflx_count: Option<u8>,
        /// C4 stage 2 — the live warm TURN allocation's relayed transport
        /// address (`worker-ip:port`), when one is standing. The server
        /// stores it pair-less so a PEER whose pair to this node just died
        /// can dial the relayed address immediately — no coordination
        /// round-trip through this node's (possibly captured) control WS.
        /// `None` = no live leg, or a pre-stage-2 agent. Additive
        /// agent→server like `srflx_count`, so no capability flag.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        warm_relay: Option<String>,
        /// FR-43 P2c — updated capabilities, when they have CHANGED since the
        /// last announcement.
        ///
        /// Caps otherwise travel exactly once, in `rc:agent.hello`, and that is
        /// too early for a macOS daemon: it must say hello immediately (the
        /// whole point of the root half is being reachable before anyone logs
        /// in), while the GUI worker whose `permissions` it reports attaches on
        /// its own schedule — ~260 ms later at boot, but also after a
        /// console-user change, after a hand-back, and never at all when nobody
        /// is logged in.
        ///
        /// ⚠️ Sent ONLY on change, never on every beat: caps are ~200 bytes
        /// against a frequent heartbeat, and the steady state must stay free.
        /// `None` therefore means "nothing to report", NOT "no capabilities" —
        /// a reader must leave the stored caps alone, exactly like
        /// `AgentCaps::permissions`' own `None` vs `Some([])` rule.
        ///
        /// ⚠️ It must also carry the caps BACK DOWN when a worker detaches. A
        /// row that keeps claiming a capture target which has gone hands the
        /// next session a black screen, which is the bug P2b existed to fix.
        ///
        /// ⚠️ Boxed: `AgentCaps` is large, and inline it made this variant
        /// ~536 bytes — a cost every frequent `AgentHeartbeat` and every other
        /// variant would pay for a field that is almost always absent. Serde is
        /// transparent through `Box`, so the wire is unchanged. Same reasoning
        /// as `localapi::Response::Status`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caps: Option<Box<AgentCaps>>,
        /// FR-27 — the version of the `roomler-desktop` companion installed on
        /// this host, or `None` when none is installed / the probe failed /
        /// the agent predates the field. Additive agent→server like
        /// `srflx_count`, so no capability flag.
        ///
        /// Reported because the daemon and the companion update by DIFFERENT
        /// mechanisms on all three platforms, so a fleet-wide "Update all"
        /// moving `agent_version` says nothing about the companion — which is
        /// exactly the skew the operator hit on macOS.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        companion_version: Option<String>,
        /// FR-92 P5b — keep busy, as this device runs it: shown on the device
        /// list, never enforced on. `None` = nothing to report (no keep busy
        /// here, a pre-P5b agent, or a supervised Mac's daemon, which cannot
        /// speak for its GUI worker). Additive like `companion_version`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        keep_busy: Option<crate::models::KeepBusyBrief>,
    },

    /// Multi-region relay PoPs: the agent's timed STUN probe results for the
    /// regions last pushed in [`ServerMsg::RelayRegions`]. The server derives
    /// the agent's `relay_home` (with hysteresis) and persists it on the
    /// `agents` + `overlay_nodes` rows.
    #[serde(rename = "rc:relay.probe_report")]
    RelayProbeReport { results: Vec<RelayRegionRtt> },

    /// MeshHarbor #19 — one page of the node's read-only network inventory
    /// ([`crate::net_inventory`]). The server binds it to the authenticated
    /// connection's agent, never to anything in the body. `boot_id` is
    /// random per agent process and `seq` rises within it, so a replayed or
    /// stale snapshot is dropped; `page` of `pages` share one `seq`.
    ///
    /// Additive agent→server: a server that predates it ignores the frame.
    /// MeshHarbor #20 — what the agent made of the last
    /// [`ServerMsg::ManagedForwardSet`]: one entry per desired forward. The
    /// server binds it to the authenticated agent and the exact revision.
    ///
    /// `confirm` is the nft backend's change generation awaiting
    /// [`ServerMsg::ManagedForwardConfirm`]; absent when nothing waits.
    #[serde(rename = "rc:forward.status")]
    ManagedForwardStatus {
        statuses: Vec<ManagedForwardStatusWire>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        confirm: Option<u64>,
    },

    #[serde(rename = "rc:agent.net_inventory")]
    NetInventory {
        boot_id: String,
        seq: u64,
        page: u16,
        pages: u16,
        /// When the node read it (Unix ms, the node's clock: shown, never
        /// trusted for freshness).
        observed_at_ms: i64,
        inventory: Box<crate::net_inventory::NetInventory>,
    },

    /// Live remote-control session telemetry (wave 2). Sent by the agent
    /// every ~15 s while a session is active; the server folds it into
    /// `remote_sessions.stats`, which was declared-but-never-written
    /// since Phase 4 (every session recorded zeros).
    #[serde(rename = "rc:session.stats")]
    SessionStats {
        session_id: String,
        bytes_sent: u64,
        bytes_recv: u64,
        fps: f32,
        rtt_ms: f32,
        keyframe_requests: u32,
        input_events: u64,
        /// P8 Phase 4 (mixed-dial gate) — cumulative seconds this
        /// session's pipeline served ≥1 follower. `serde(default)`
        /// so pre-Phase-4 agents' samples still parse.
        #[serde(default)]
        shared_seconds: u64,
        /// … of which the viewers' dials (Priority / resolution pick)
        /// were NOT all equal — the share-shape a per-viewer pipeline
        /// (SVC / tiered transcode) would serve better than the
        /// floor-merge. The 2-4-week aggregate of this field is the
        /// SVC go/no-go input.
        #[serde(default)]
        mixed_dial_seconds: u64,
        /// FR-101 P3 — clipboard and file traffic, for the audit. Absent
        /// when there was none, so older servers never see it, and an
        /// older agent's sample parses with none.
        #[serde(default, skip_serializing_if = "Transfers::is_empty")]
        transfers: Transfers,
        /// FR-102 P9c — the carrier the session rides, as the agent
        /// recorded it once the session reached Active: `direct` · `turn` ·
        /// `turn_local` · `overlay_direct` · `overlay_turn` · `derp` ·
        /// `org_relay` · `unknown` (`roomlerd::session_carrier`). Absent
        /// from an agent older than the field and from a sample before the
        /// observation landed; the server stores it beside
        /// `remote_sessions.stats` and reads absence as **unknown, never
        /// direct**. Additive: an older server ignores the key.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        carrier: Option<String>,
    },

    /// Multi-region DERP: request an EdDSA admission ticket for the regional
    /// relays (`derp_url`s in [`ServerMsg::RelayRegions`]). The server answers
    /// with [`ServerMsg::DerpTicket`]. Sent only by agents that saw a region
    /// list carrying a DERP endpoint, so an old server never receives it.
    #[serde(rename = "rc:relay.derp_ticket_request")]
    DerpTicketRequest {},

    // ─── Fleet RPC (rc:rpc.*) ────────────────────────────────────────
    /// Result of a [`ServerMsg::RpcExec`]. Always sent — a gate-4 refusal, a
    /// timeout, or a cancel come back carrying `error` rather than as
    /// silence, because a caller is blocked on this.
    #[serde(rename = "rc:rpc.result")]
    RpcResult {
        request_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        /// Redacted (agent token / `Bearer …` / JWT-shaped strings masked)
        /// and capped at the request's `max_output_bytes`.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        stdout: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        stderr: String,
        /// Output hit the cap and was cut.
        #[serde(default)]
        truncated: bool,
        #[serde(default)]
        duration_ms: u64,
        /// Set when the command never ran or was killed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },

    /// Device-originated exec against ANOTHER device — the `roomler exec`
    /// CLI leg, where the local daemon's own agent WS carries the request so
    /// the CLI needs no user credentials of its own.
    ///
    /// The server resolves this device's `owner_user_id` as the acting
    /// principal, requires that user to hold `EXEC_DEVICE`, and additionally
    /// requires THIS device to be blessed with
    /// [`crate::models::ExecPolicy::can_originate`] — otherwise a single
    /// compromised laptop would inherit its owner's exec rights fleet-wide.
    /// Answered with [`ServerMsg::RpcExecResponse`].
    #[serde(rename = "rc:rpc.request")]
    RpcExecRequest {
        /// Client-minted correlation id, echoed on the response.
        request_id: String,
        /// Target device: an agent id (hex) or its device name.
        target: String,
        shell: String,
        command: String,
        timeout_ms: u64,
    },

    /// Device-originated roomler-SSH against ANOTHER device — the
    /// `roomler ssh` CLI leg, the twin of [`Self::RpcExecRequest`].
    ///
    /// The caller mints an **ephemeral** keypair per session and sends only
    /// the public half. If the server authorizes, it pushes the key to the
    /// target as a single-use [`ServerMsg::SshGrant`] and answers here with
    /// where to connect. Nothing long-lived is distributed and no secret
    /// crosses the wire: the private half never leaves the calling device, and
    /// the target learns a key it will accept exactly once, briefly.
    #[serde(rename = "rc:ssh.request")]
    SshRequest {
        /// Client-minted correlation id, echoed on the response.
        request_id: String,
        /// Target device: an agent id (hex) or its device name.
        target: String,
        /// OpenSSH public key of the ephemeral session keypair
        /// (`ssh-ed25519 AAAA…`).
        public_key: String,
        /// Requested session lifetime in seconds. Server-clamped to
        /// [`crate::models::ssh_limits::MAX_SESSION_SECS`]; 0 ⇒ the ceiling.
        #[serde(default)]
        session_secs: u64,
        /// FR-90 P3-8-1b — an agent session's own decision: the vault's
        /// ticket (`rc:vault.ssh.granted`), under which the SESSION is the
        /// principal, never the device's owner. A request whose ticket does
        /// not hold is refused, never served as the owner's. Absent from
        /// every request a person makes (`roomler ssh`), so that frame is
        /// byte for byte what it was.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ssh_ticket: Option<String>,
    },

    /// FR-85 P3 — the device reports one thing that happened to a REMOTE
    /// recording: the host's answer to the just-in-time prompt, a start, a
    /// stop (bytes, length, why), a download. The host's CLAIM, kept apart
    /// from the server's DECISION (`remote_audit`'s grant) exactly as
    /// `ssh_activity` is kept apart from `ssh_audit`.
    ///
    /// Fire-and-forget, like [`Self::SshActivity`]: an older server ignores
    /// the frame. ⚠️ `tenant_id` / `agent_id` come from the authenticated WS,
    /// and the server records it only for a live session of THIS agent whose
    /// grant holds `RECORD` — never content, only the fact.
    #[serde(rename = "rc:recording.activity")]
    RecordingActivity {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        kind: crate::models::RecordingActivityKind,
        /// The recording's file name (no path).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bytes: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        /// A stop reason or refusal code (the closed sets in
        /// `docs/recording.md`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },

    /// FR-99 P1d — the device reports what happened to a session's privacy
    /// curtain: up, down (and why), or a request it refused. The host's
    /// CLAIM, kept apart from the server's DECISION (the `PRIVACY` grant in
    /// `remote_audit`), as `rc:recording.activity` is.
    ///
    /// Fire-and-forget: an older server ignores the frame. ⚠️ `tenant_id` /
    /// `agent_id` come from the authenticated WS, and the server records it
    /// only for a session of THIS agent whose grant holds `PRIVACY`. A
    /// `worker_exit` arrives after its session ended, from the next process to
    /// start, so the stored session row decides then.
    #[serde(rename = "rc:privacy.activity")]
    PrivacyActivity {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        kind: crate::models::PrivacyActivityKind,
        /// A reason code (`models::PrivacyActivityKind` lists them).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },

    /// Device reports one thing that happened inside an SSH session (P8).
    ///
    /// Fire-and-forget: no reply, and the server drops it silently if the
    /// device is not entitled to report. A caller never awaits this, so unlike
    /// `rc:rpc.exec` it needs no capability gate — an older server that has
    /// never heard of the frame just ignores it, which is the correct
    /// behaviour for a log line.
    ///
    /// ⚠️ `tenant_id` / `agent_id` are taken from the authenticated WS, NOT
    /// from this frame, so a device can only ever write rows about itself.
    #[serde(rename = "rc:ssh.activity")]
    SshActivity {
        /// The grant this session redeemed; absent for a key-list session.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant_id: Option<String>,
        /// Principal as the device saw it.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        caller: String,
        kind: crate::models::SshActivityKind,
        /// Command for `Exec`, `host:port` for `Forward`. Already redacted and
        /// length-capped by the device.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        /// `false` when the device itself refused the action.
        allowed: bool,
    },

    /// FR-83 — the target's answer to a [`ServerMsg::SshGrant`]: whether the
    /// grant can now be redeemed.
    ///
    /// Sent only AFTER the grant is in the table the device's auth path reads,
    /// so "acknowledged" means "a connection authenticating with this key now
    /// succeeds". The server holds the caller until this arrives
    /// ([`crate::models::ssh_limits::GRANT_ACK_TIMEOUT_SECS`]): before it,
    /// "queued for the device" was read as "the device has it", and a caller
    /// whose control path was faster than the target's dialled first and got
    /// `Permission denied (publickey)` (#1597).
    ///
    /// Only an agent advertising [`crate::models::RpcCap::SshGrantAck`] is
    /// waited for. An older server cannot parse the frame and drops it at
    /// `debug!`, which is harmless.
    ///
    /// ⚠️ `tenant_id` / `agent_id` come from the authenticated WS, NOT from
    /// this frame, and the server honours an ack only from the agent the grant
    /// was pushed to — grant ids are ObjectIds, structured, not secret.
    #[serde(rename = "rc:ssh.grant_ack")]
    SshGrantAck {
        /// Echo of the `grant_id` in the `rc:ssh.grant` being answered.
        grant_id: String,
        /// Absent = recorded. Present = refused, and why — decoded leniently,
        /// see [`crate::models::SshGrantRefusal`].
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "grant_refusal_lenient"
        )]
        refused: Option<crate::models::SshGrantRefusal>,
    },

    /// The agent's answer to a [`ServerMsg::ConfigPush`] — what it actually
    /// did (`docs/remote-config.md`).
    ///
    /// This is the frame `ConfigPush::revision`'s doc has always promised:
    /// without it, a device that REFUSED a push and a device that never heard
    /// about one are indistinguishable on the dashboard, and only one of those
    /// is something an operator can fix.
    ///
    /// Sent on every outcome, including the refusals — especially the
    /// refusals. `not_opted_in` and `not_primary` are the two states an
    /// operator will actually hit, and both have a concrete next action that
    /// they can only take if they are told.
    ///
    /// ⚠️ `tenant_id` / `agent_id` come from the authenticated WS, NOT from
    /// this frame, so a device can only ever report about itself — the same
    /// rule as [`Self::SshActivity`].
    ///
    /// ⚠️ Unlike `SshActivity` this one IS capability-gated on the server's
    /// read side ([`RpcCap::ConfigReport`]): rc.457/rc.458 agents apply pushed
    /// config and stay silent, so "no report" has to mean "cannot report"
    /// there, and "has not answered yet" on a newer device.
    ///
    /// [`RpcCap::ConfigReport`]: crate::models::RpcCap::ConfigReport
    #[serde(rename = "rc:agent.config_status")]
    ConfigStatus {
        /// The `desired_config.revision` being reported on, echoed from the
        /// push.
        revision: u64,
        outcome: crate::models::ConfigOutcome,
        /// Keys now IN FORCE.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        live: Vec<String>,
        /// Keys written but waiting for a restart. Never merged into `live` —
        /// see [`crate::models::ConfigReport::needs_restart`].
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        needs_restart: Vec<String>,
        /// Why, for `failed`. Redacted and capped by the device; re-clamped on
        /// receipt.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },

    /// FR-40 — the device's answer to [`ServerMsg::KeyRotate`], sent on the
    /// session that received the order (that session is about to end: a
    /// `rotated` device reconnects immediately under its new key).
    ///
    /// Sent on EVERY outcome, refusals included — the refusals are what an
    /// operator can act on. `tenant_id` / `agent_id` come from the
    /// authenticated WS, never this frame. Keys here are PUBLIC halves only.
    #[serde(rename = "rc:agent.key_rotated")]
    KeyRotated {
        request_id: String,
        outcome: crate::models::KeyRotationOutcome,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_public_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        new_public_key: Option<String>,
        /// The epoch the device will present on its next join.
        #[serde(default)]
        key_epoch: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },

    /// FR-90 — the device's answer to [`ServerMsg::HiveStart`]: whether its
    /// own gates let the session run.
    ///
    /// Sent once the device has decided — accepted means the harness is being
    /// launched, and what follows arrives as [`Self::HiveState`]. Sent on
    /// EVERY outcome, refusals included: each refusal names a different gate
    /// with a different fix.
    ///
    /// ⚠️ `tenant_id` / `agent_id` come from the authenticated WS, NOT from
    /// this frame, and the server applies an answer only to a session located
    /// on the device that sent it, at the fence it was started with — session
    /// ids are ObjectIds, structured, not secret.
    #[serde(rename = "rc:hive.start_ack")]
    HiveStartAck {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        /// Echo of the start's `fence`. An answer to an older start of the
        /// same session is stale and changes nothing.
        fence: u64,
        /// Absent = accepted. Present = refused, decoded leniently — see
        /// [`crate::hive::HiveRefusal`].
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::hive::refusal_lenient"
        )]
        refused: Option<crate::hive::HiveRefusal>,
        /// On acceptance, the local account the device mapped the starter to
        /// — shown with the session, so "who is this running as" has an
        /// answer. A claim by the device, like everything in this frame.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account: Option<String>,
        /// A short reason for the person who started it. Redacted and capped
        /// by the device; re-clamped on receipt. Never transcript content.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },

    /// FR-90 — a session's lifecycle on the device: idle, running, waiting
    /// for an approval, ended.
    ///
    /// Whether, never what: no prompt, tool name, argument or output rides
    /// this frame. The same ownership rule as [`Self::HiveStartAck`] — the
    /// server moves only a session located on the sending device, at its
    /// current fence.
    #[serde(rename = "rc:hive.state")]
    HiveState {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        fence: u64,
        /// `None` = a state this build cannot name (a newer device); the
        /// server keeps what it knew. Decoded leniently.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::hive::run_state_lenient"
        )]
        state: Option<crate::hive::HiveRunState>,
        /// For `ended`: stopped, exited, or crashed, in a few words. Capped
        /// like [`Self::HiveStartAck`]'s.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },

    /// FR-90 — one turn's STUB: who asked, how it stands, how big it was.
    /// Sent when a prompt goes in (`running`) and again when the turn ends.
    ///
    /// ⚠️ Never what was asked or answered, never a tool's name, argument or
    /// output — the field set is locked by test. The server turns this into a
    /// message in the session's room; the content streams to a viewer from a
    /// replica, never through the server (`docs/roomler-hive-design.md` §5.1).
    #[serde(rename = "rc:hive.turn")]
    HiveTurn {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        fence: u64,
        /// 1-based, counted per session by the device that runs it.
        turn: u32,
        /// `None` = a status this build cannot name; decoded leniently.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::hive::turn_status_lenient"
        )]
        status: Option<crate::hive::HiveTurnStatus>,
        /// The user whose prompt started the turn, when one did.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "option_oid_hex"
        )]
        prompted_by: Option<ObjectId>,
        /// Tool calls in the turn so far.
        #[serde(default)]
        steps: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cost_usd: Option<f64>,
    },

    /// FR-90 P1a-2 — an approval opened or ended in a session: the server's
    /// stub in the session's room and its `agent_approvals` record.
    ///
    /// ⚠️ METADATA ONLY, and the field set is LOCKED by test: which tool and
    /// what it would do travel device-to-browser over the viewer peer, so a
    /// `tool`, `input` or `command` field here would put them in a room's
    /// message store.
    #[serde(rename = "rc:hive.approval")]
    HiveApproval {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        fence: u64,
        /// The device's id for the approval.
        approval_id: String,
        /// The turn it came up in, when one runs.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        turn: Option<u32>,
        /// `None` = a word this build cannot name; decoded leniently.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::hive::approval_status_lenient"
        )]
        status: Option<crate::hive::HiveApprovalStatus>,
        /// The driver who answered, when one did.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "option_oid_hex"
        )]
        answered_by: Option<ObjectId>,
    },

    /// FR-90 P1b — the sessions this device RUNS now, sent on every
    /// connection of its primary enrollment. The server ends every session
    /// it holds as running on this device that the list leaves out: a daemon
    /// that restarted runs none of them, and nothing else would ever say so
    /// (finding 7, 2026-10-08). Ids and fences only.
    #[serde(rename = "rc:hive.manifest")]
    HiveManifest {
        #[serde(default)]
        sessions: Vec<crate::hive::HiveManifestEntry>,
    },

    /// FR-90 P1j — a terminal session this device mirrors (`roomler hive
    /// adopt`), offered for a record. Sent once per Claude Code session, when
    /// its first hook reaches the device, and answered by
    /// [`ServerMsg::HiveAdoptAck`]. What follows is the usual `rc:hive.state`
    /// and `rc:hive.turn`, under the session id the ack names.
    ///
    /// ⚠️ METADATA ONLY, and the field set is LOCKED by test: no title, no
    /// prompt. A terminal's first prompt is content, and the server keeps
    /// none.
    /// ⚠️ `keys` are the device's own `hive_accounts` keys that map to the
    /// account the session runs as, every one of them. The SERVER resolves
    /// them and adopts only when they name exactly one person, a member of
    /// this org: the attribution is the device owner's statement, never a
    /// guess.
    #[serde(rename = "rc:hive.adopt")]
    HiveAdopt {
        /// The device's id for this offer, echoed by the ack.
        adopt_id: String,
        /// The harness's own session id (a UUID).
        harness_session: String,
        keys: Vec<String>,
        /// The local account the session runs as, attested by the device's
        /// kernel (the hook's peer credentials) — a claim by the device.
        account: String,
        /// The terminal's working directory.
        folder: String,
    },

    /// FR-90 P2c-3 — the device's answer to [`ServerMsg::HiveReplicaJoin`]:
    /// whether it holds a copy of the session now (from the primary, P2c-4:
    /// whether it checkpoints now). Sent on EVERY outcome, refusals included:
    /// each names a different gate with a different fix.
    ///
    /// ⚠️ The server applies it only to a member the session's replicaset
    /// names as the sending device, at the session's fence; session ids are
    /// ObjectIds, structured, not secret.
    #[serde(rename = "rc:hive.replica.join_ack")]
    HiveReplicaJoinAck {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        /// Echo of the join's `fence`.
        fence: u64,
        /// Absent = joined. Present = refused, decoded leniently — see
        /// [`crate::hive::HiveJoinRefusal`].
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::hive::join_refusal_lenient"
        )]
        refused: Option<crate::hive::HiveJoinRefusal>,
        /// A few words for the owner. Capped by the device, re-clamped on
        /// receipt.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },

    /// FR-90 P2c-3 — where this device's copy of a session ends, from a
    /// member or the primary, at most every
    /// [`crate::hive::replica_limits::TIP_INTERVAL_SECS`] and at each
    /// checkpoint. What the server learns a copy's freshness from, without
    /// seeing any of it.
    ///
    /// ⚠️ NUMBERS AND HASHES ONLY, and the field set is LOCKED by test.
    #[serde(rename = "rc:hive.replica.tip")]
    HiveReplicaTip {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        /// The fence of the event at `seq`.
        fence: u64,
        seq: u64,
        /// That event's hash, as [`crate::hive::is_hash_hex`] reads it.
        hash: String,
        /// The newest checkpoint the copy holds, when it holds one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        checkpoint: Option<crate::hive::HiveCheckpointMark>,
    },

    /// FR-90 P2c-3 — every session this device holds a copy of, its own
    /// replicated ones included, each with its tip; sent on every connection
    /// of its primary enrollment. How a member's freshness reaches the server
    /// when it reconnects, primary or not.
    #[serde(rename = "rc:hive.replica.manifest")]
    HiveReplicaManifest {
        #[serde(default)]
        sessions: Vec<crate::hive::HiveReplicaManifestEntry>,
        /// FR-90 P2g-3c — copies this device purged on its own clock (the
        /// retention word, [`crate::hive::HiveRetainWord`]), each named on
        /// its next [`crate::hive::retain_limits::COPY_PURGED_REPORTS`]
        /// manifests, at most [`crate::hive::retain_limits::MAX_COPY_PURGED`].
        /// Absent when empty, so every other manifest is the frame it was,
        /// and a server before it ignores the field.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        purged: Vec<crate::hive::HiveCopyPurged>,
    },

    /// FR-90 P2d — a member asks for a stream of a session it holds a copy
    /// of, on one rung of the ladder. Answered by [`ServerMsg::HiveReplicaDial`]
    /// once the source is ready, or by [`ServerMsg::HiveReplicaRefused`]. Read
    /// only from a connection advertising `hive-stream`.
    #[serde(rename = "rc:hive.replica.want")]
    HiveReplicaWant {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        /// The fence the member holds the session at.
        fence: u64,
        /// Where its copy ends: what the source streams from.
        seq: u64,
        hash: String,
        /// The rung to try. `None` on the server = a rung this build cannot
        /// name: refused `path_unavailable`.
        #[serde(default, deserialize_with = "crate::hive::stream_path_lenient")]
        path: Option<crate::hive::HiveStreamPath>,
        /// The member's WireGuard key, which the `derp` rung addresses.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        derp_pubkey: Option<String>,
    },

    /// FR-90 P2d — the source's answer to [`ServerMsg::HiveReplicaGrant`]:
    /// ready, with what the member pins and dials; or refused, and why. The
    /// member is told to dial only after an answer without `refused` (FR-83).
    #[serde(rename = "rc:hive.replica.ready")]
    HiveReplicaReady {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        /// Absent = ready. Present = refused, decoded leniently — see
        /// [`crate::hive::HiveStreamRefusal`].
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::hive::stream_refusal_lenient"
        )]
        refused: Option<crate::hive::HiveStreamRefusal>,
        /// A few words for the owner. Capped by the device, re-clamped on
        /// receipt.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        /// The SHA-256 of the source's ephemeral certificate, as lowercase
        /// hex: the member pins it. Required when ready.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cert_fingerprint: Option<String>,
        /// Where the member dials: host and server-reflexive candidates on
        /// `direct`, the relayed address on `relay`; none on `derp`.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        addrs: Vec<String>,
        /// The source's WireGuard key, on the `derp` rung.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        derp_pubkey: Option<String>,
    },

    /// FR-90 P2d — the member's relayed address, for the source to permit on
    /// the `relay` rung: a TURN allocation lets in only what a permission
    /// names. Relayed only for a grant the source confirmed.
    #[serde(rename = "rc:hive.replica.candidate")]
    HiveReplicaCandidate {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        addr: String,
    },

    /// FR-90 P2d — the device ended a stream, as its member or its source:
    /// the server forgets the grant and tells the other side.
    #[serde(rename = "rc:hive.replica.close")]
    HiveReplicaClose {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        reason: String,
    },

    /// FR-90 P2e-3 — the member's answer to [`ServerMsg::HivePrepare`]:
    /// whether every start gate lets the session run here, as the device is
    /// configured now. Sent on EVERY outcome, refusals included, in the
    /// start's words: each names a different gate with a different fix.
    ///
    /// ⚠️ The server applies it only to the promotion it is preparing on THIS
    /// device, at the fence it named; session ids are ObjectIds, structured,
    /// not secret.
    #[serde(rename = "rc:hive.prepare_ack")]
    HivePrepareAck {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        /// Echo of the prepare's `fence`.
        fence: u64,
        /// Absent = ready. Present = refused, decoded leniently — see
        /// [`crate::hive::HiveRefusal`].
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::hive::refusal_lenient"
        )]
        refused: Option<crate::hive::HiveRefusal>,
        /// When ready, the local account the device would run the session as.
        /// A claim by the device.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account: Option<String>,
        /// A few words for the owner. Capped by the device, re-clamped on
        /// receipt.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        /// FR-90 P2e-6a — when ready, where the device's copy ends: what a
        /// promotion away from an unreachable primary moves the lease to.
        /// Absent from a device before P2e-6a, which such a promotion then
        /// refuses rather than guesses.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tip: Option<crate::hive::HiveCopyTip>,
    },

    /// FR-90 P2e-3 — the primary's answer to [`ServerMsg::HiveDrain`]: it
    /// takes no new prompt, its turn has ended, its open approvals are
    /// withdrawn and its last checkpoint taken, and its copy of the session
    /// ends at `seq`, whose event's hash is `hash`. The lease moves only once
    /// the member it moves to holds that same tip.
    ///
    /// ⚠️ NUMBERS AND HASHES ONLY, and the field set is LOCKED by test. The
    /// server applies it only to the promotion draining THIS device, at the
    /// fence it named.
    #[serde(rename = "rc:hive.drained")]
    HiveDrained {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        /// Echo of the drain's `fence`.
        fence: u64,
        /// The last event the copy holds, when drained.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seq: Option<u64>,
        /// That event's hash, as [`crate::hive::is_hash_hex`] reads it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hash: Option<String>,
        /// Absent = drained. Present = not drained, decoded leniently — see
        /// [`crate::hive::HiveDrainRefusal`].
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::hive::drain_refusal_lenient"
        )]
        refused: Option<crate::hive::HiveDrainRefusal>,
        /// A few words for the owner. Capped by the device, re-clamped on
        /// receipt.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },

    /// FR-90 P2g — the device's answer to a [`ServerMsg::HivePurge`], per
    /// part: its own copy (`store`), and what the session's account held of
    /// it (`account`). A part `failed` stays pending with `detail`, and the
    /// purge comes again.
    ///
    /// ⚠️ Metadata only, and the field set is locked by test. Each part is
    /// decoded leniently ([`crate::hive::HivePurgePart`]): an unknown word,
    /// or none, is `failed`, never `done`.
    #[serde(rename = "rc:hive.purge_ack")]
    HivePurgeAck {
        #[serde(with = "oid_hex")]
        purge_id: ObjectId,
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        #[serde(deserialize_with = "crate::hive::purge_part_lenient")]
        store: crate::hive::HivePurgePart,
        #[serde(deserialize_with = "crate::hive::purge_part_lenient")]
        account: crate::hive::HivePurgePart,
        /// Why a part failed, in a few words. Capped by the device,
        /// re-clamped on receipt.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },

    /// FR-90 P2g-3c — what keeps each copy this device holds: the sessions
    /// it asks about, answered [`ServerMsg::HiveRetain`] on the same
    /// connection. Asked at each connection, right after the device takes a
    /// session up, and once a day while it stays connected
    /// ([`crate::hive::retain_limits::RETAIN_ASK_EVERY_SECS`]). A server
    /// before it ignores it, and the device then keeps what it holds, as
    /// before.
    ///
    /// ⚠️ Ids only, at most
    /// [`crate::hive::retain_limits::MAX_RETAIN_ASK`]: a longer ask is no
    /// device's, and is answered with nothing.
    #[serde(rename = "rc:hive.retain_ask")]
    HiveRetainAsk {
        #[serde(default, with = "vec_oid_hex")]
        sessions: Vec<ObjectId>,
    },

    /// FR-90 P0d-2 — the device's answer to [`ServerMsg::HiveViewGrant`]:
    /// whether it will serve this viewer. The server tells the browser to
    /// dial only after an answer without `refused` (FR-83).
    ///
    /// ⚠️ The server applies it only to a grant it pushed to the sending
    /// device; grant ids are ObjectIds, structured, not secret.
    #[serde(rename = "rc:hive.view.grant_ack")]
    HiveViewGrantAck {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        /// Absent = the device will answer the viewer's offer. Present =
        /// refused, decoded leniently — see [`crate::hive::HiveViewRefusal`].
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::hive::view_refusal_lenient"
        )]
        refused: Option<crate::hive::HiveViewRefusal>,
        /// A few words for the viewer. Capped by the device, re-clamped on
        /// receipt.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },

    /// FR-90 P0d-2 — the device's SDP answer to a viewer's offer, relayed to
    /// the browser connection that holds the grant.
    #[serde(rename = "rc:hive.view.answer")]
    HiveViewAnswer {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        sdp: String,
    },

    /// FR-90 P0d-2 — one of the device's ICE candidates for a viewer peer.
    #[serde(rename = "rc:hive.view.ice")]
    HiveViewIce {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        candidate: serde_json::Value,
    },

    /// FR-90 P0d-2 — the device closed a viewer peer on its own side: the
    /// grant ran out, the peer failed, the viewer went away. The server drops
    /// the grant and tells the browser.
    #[serde(rename = "rc:hive.view.closed")]
    HiveViewClosed {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        reason: String,
    },

    /// FR-90 P3-3b — a session on this device asks the vault for a value. The
    /// vault believes it only from the device the session's record places it
    /// on, at the record's fence, and answers on this connection with
    /// [`ServerMsg::VaultLeased`] (the value sealed to this daemon's vault
    /// key) or [`ServerMsg::VaultRefused`], naming `req_id`. Bounds:
    /// [`crate::vault::lease_limits`].
    #[serde(rename = "rc:vault.lease")]
    VaultLease {
        /// The device's own id for this request, echoed in the answer.
        req_id: String,
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        fence: u64,
        /// The secret, by its path or its RRN (`rrn:{org}:secret:{path}`).
        secret: String,
        /// The field; empty or absent = `value`, a static secret's one field.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        field: String,
        /// How the session will use it (`env`, `file`, `exec`, `proxy`…):
        /// what a policy reads as `context.mode`.
        mode: String,
        /// Where the value is meant for; a policy's `context.audience`.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        audience: String,
        /// How long the session wants it, in seconds. The vault clamps it.
        ttl_secs: u32,
    },

    /// FR-90 P3-4b — a session on this device asks what its role may list in
    /// the vault, under `prefix` when one is given. Believed as a lease
    /// request is (the session's record, at its fence, on this device), and
    /// answered with [`ServerMsg::VaultListed`] or [`ServerMsg::VaultRefused`].
    #[serde(rename = "rc:vault.list")]
    VaultList {
        req_id: String,
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        fence: u64,
        /// A folder (`db` or `db/`); empty or absent = every secret.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        prefix: String,
    },

    /// FR-90 P3-4b — a session on this device asks for one secret's metadata,
    /// by its path or its RRN. Answered with [`ServerMsg::VaultDescribed`] or
    /// [`ServerMsg::VaultRefused`].
    #[serde(rename = "rc:vault.describe")]
    VaultDescribe {
        req_id: String,
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        fence: u64,
        secret: String,
    },

    /// FR-90 P3-4d — the device reports one use of leased values: a command
    /// `vault_exec` ran, or a file `vault_render` wrote. A CLAIM, by a host
    /// that may be compromised, so the server keeps it in `vault_activity`,
    /// never with its own decisions in `vault_audit`, and only when every
    /// lease it names was released to this device, for this session, in the
    /// use's mode and toward its target.
    ///
    /// Fire-and-forget, like [`Self::SshActivity`]: no answer, and an older
    /// server ignores it. Sent only while the device's own
    /// `vault_activity_log` is on (default off).
    ///
    /// ⚠️ `tenant_id` / `agent_id` come from the authenticated WS, NOT from
    /// this frame.
    #[serde(rename = "rc:vault.activity")]
    VaultActivity {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        fence: u64,
        /// A [`crate::vault::VaultActivityKind`] word; one this server cannot
        /// name is dropped.
        kind: String,
        /// The leases whose values were used, at most
        /// [`crate::vault::lease_limits::MAX_ACTIVITY_LEASES`].
        lease_ids: Vec<String>,
        /// `exec`: the program's bare name; `render`: the file's.
        target: String,
        /// `exec`: how the command ended; absent when it was killed, and for
        /// a render.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        /// `exec`: the command ran past its timeout and was killed.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        timed_out: bool,
    },

    /// FR-90 P3-7-1b — a session on this device asks for its own egress
    /// through `exit`: a SOCKS5 listener, or a forward to `host:port`
    /// ([`crate::vault::NetKind`]). Believed as a lease request is (the
    /// session's record, at its fence, on this device), decided by Cedar's
    /// `net:socks` or `net:forward`, and answered with
    /// [`ServerMsg::VaultNetGranted`] or [`ServerMsg::VaultRefused`], naming
    /// `req_id`.
    ///
    /// ⚠️ `tenant_id` and the origin device come from the authenticated WS,
    /// NOT from this frame.
    #[serde(rename = "rc:vault.net")]
    VaultNet {
        req_id: String,
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        fence: u64,
        /// The device the flows exit through.
        #[serde(with = "oid_hex")]
        exit: ObjectId,
        /// A [`crate::vault::NetKind`] word.
        kind: String,
        /// A forward's destination; empty for SOCKS. The vault decides and
        /// grants it as [`crate::vault::canonical_net_host`] spells it.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        host: String,
        /// A forward's destination port; absent for SOCKS.
        #[serde(default, skip_serializing_if = "is_zero_u16")]
        port: u16,
        /// How long the session wants it, in seconds. The vault clamps it to
        /// a lease's bounds ([`crate::vault::lease_limits`]).
        ttl_secs: u32,
    },

    /// FR-90 P3-8-1a — a session on this device asks to run one command on
    /// `target` over Roomler SSH (`ssh_run`). Believed as a lease request is
    /// (the session's record, at its fence, on this device), decided by
    /// Cedar's `ssh:run`, and answered with [`ServerMsg::VaultSshGranted`] or
    /// [`ServerMsg::VaultRefused`], naming `req_id`.
    ///
    /// ⚠️ `tenant_id` and the origin device come from the authenticated WS,
    /// NOT from this frame, and the target is never that device: a session
    /// already runs there, as its own account.
    #[serde(rename = "rc:vault.ssh")]
    VaultSsh {
        req_id: String,
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        fence: u64,
        /// The device the command runs on.
        #[serde(with = "oid_hex")]
        target: ObjectId,
        /// How long the session wants it, in seconds. The vault clamps it to
        /// a lease's bounds ([`crate::vault::lease_limits`]).
        ttl_secs: u32,
    },

    /// FR-90 P3-9-1 — a PERSON on this device asks for one field of a secret,
    /// for an endpoint the device serves them (`roomler connect`): always in
    /// `proxy` mode, toward `audience`, the upstream the endpoint signs in to.
    /// One frame per field, as a session's `vault_connect` asks its leases.
    /// Decided by Cedar's `secret:connect` for the device's OWNER, and
    /// answered as a lease is, with [`ServerMsg::VaultLeased`] or
    /// [`ServerMsg::VaultRefused`], naming `req_id`.
    ///
    /// ⚠️ It names no session and no person: the principal is the device's
    /// owner as its ROW holds it, never as a frame says, so a device can ask
    /// for what its owner may and for nobody else. It is a frame of its own,
    /// never [`ClientMsg::VaultLease`] with the session left out, whose every
    /// field is believed against a session's record.
    #[serde(rename = "rc:vault.connect")]
    VaultConnect {
        req_id: String,
        /// The secret, by its path or its RRN (`rrn:{org}:secret:{path}`).
        secret: String,
        /// The field; empty or absent = `value`, a static secret's one field.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        field: String,
        /// The upstream the endpoint presents the value to, exactly as the
        /// secret's `audiences` names it: a policy's `context.audience`.
        /// Absent reads as empty, which the vault refuses `bad_request`: a
        /// frame the server cannot decode is never answered, and the device
        /// would wait on it.
        #[serde(default)]
        audience: String,
        /// How long the person wants it, in seconds. The vault clamps it to a
        /// lease's bounds ([`crate::vault::lease_limits`]).
        ttl_secs: u32,
    },

    /// Agent answers a controller's offer.
    #[serde(rename = "rc:sdp.answer")]
    SdpAnswer {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        sdp: String,
        /// FR-52 P4 — on an EXTERNAL session, the device's MAC over its own
        /// DTLS fingerprint under the verified login's key. The browser checks
        /// it before trusting the transport: without it, a server that answered
        /// the offer itself could pose as the device — show a fake screen and
        /// read what the outsider types.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        extauth_mac: Option<String>,
        /// FR-100 P1b — the device's signature over this answer, made with
        /// its device key, when the offer asked for one (a nonce) on an
        /// in-org session. A browser that pinned the key checks it before
        /// trusting the transport. Absent from a build without it, and on
        /// any session whose offer did not ask.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_auth: Option<PeerAuthAnswer>,
        /// FR-100 P1c — what the device concluded about the browser that
        /// offered this session (one of [`PEER_AUTH_VERDICTS`]), for the hub to
        /// record. Sent whether or not the offer asked for a signed answer, so
        /// a session nobody signed is recorded as `absent` rather than not at
        /// all. Absent when the device's `peer_auth` is `off`, and from a build
        /// without it. A string, never an enum: see [`PEER_AUTH_VERDICTS`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_auth_verdict: Option<String>,
    },

    /// Agent decision on a control request.
    #[serde(rename = "rc:consent")]
    Consent {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        granted: bool,
        /// FR-27 — why, when `granted` is false. Absent (every pre-FR-27
        /// agent) means an ordinary deny, which is what a bare `false` has
        /// always meant. Present values come from
        /// [`crate::consent::ConsentDenyReason::wire`]; an unrecognised one
        /// degrades to the same ordinary deny, so a newer agent can name a
        /// reason this server has never heard of.
        ///
        /// This exists because the agent's OWN prompt timeout produced a bare
        /// `false`, and the hub turned that into `EndReason::UserDenied` — so
        /// "nobody was at the machine" reached the controller as "a human
        /// refused you", which is both wrong and un-actionable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },

    /// FR-34 — the on-host consent prompt is up, but the host is LOCKED, so
    /// nobody can see it until the machine is unlocked. Sent once when the
    /// prompt begins on a locked host so the controller's "awaiting consent"
    /// wait can explain WHY (walk over, unlock, approve) instead of looking
    /// like a hang. Advisory + additive: an old server ignores it, and it
    /// never changes the consent outcome — a locked host is still answered by
    /// unlocking and clicking the panel (the sound flow), just with 5 minutes
    /// (FR-34 P4) to get there.
    #[serde(rename = "rc:consent.pending")]
    ConsentPending {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        host_locked: bool,
    },

    // ─── controller → server ─────────────────────────────────────────
    /// Controller initiates a session. Server creates the RemoteSession,
    /// notifies the agent, and waits for consent.
    ///
    /// `browser_caps` is the controller's `RTCRtpReceiver.
    /// getCapabilities('video').codecs` filtered to the codecs the
    /// agent's negotiation logic cares about (h264 / h265 / av1 / vp9).
    /// Phase 2 commit 2B.2 uses the intersection of this list with the
    /// agent's `AgentCaps.codecs` to pick the best codec for the
    /// session. Optional + default-empty so older controllers that
    /// don't include it still get an h264 session.
    ///
    /// `preferred_transport` (Phase Y.3) tells the agent which video
    /// transport the controller wants to use. Recognised values match
    /// `AgentCaps.transports`: today only `data-channel-vp9-444` is
    /// defined. `None` / unset means "use the WebRTC video track" —
    /// the legacy default that all in-flight controllers default to.
    /// The agent only honours the request when its own caps advertise
    /// the same transport (browser × agent intersection); otherwise
    /// it ignores the field and falls back to the WebRTC track.
    #[serde(rename = "rc:session.request")]
    SessionRequest {
        #[serde(with = "oid_hex")]
        agent_id: ObjectId,
        /// Explicit account-to-device authority, never tenant membership.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "option_oid_hex"
        )]
        share_grant_id: Option<ObjectId>,
        permissions: Permissions,
        #[serde(default)]
        browser_caps: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preferred_transport: Option<String>,
        /// rc.62 — per-session VP9 chroma override. Recognised values:
        /// `"yuv420"` (VP9 profile 0; ~30% lower bandwidth; slight
        /// ClearType softening) and `"yuv444"` (VP9 profile 1; sharpest
        /// text; current default). `None` / unset means "use the
        /// agent's `ROOMLERD_VP9_CHROMA` env-var default". Only
        /// applies when `preferred_transport` is `data-channel-vp9-444`;
        /// ignored otherwise. Forwarded verbatim to the agent in the
        /// matching server-side [`ServerMsg::SessionRequest`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chroma_pref: Option<String>,
        /// FR-17 — the controller can parse the framed DataChannel wire
        /// format (every message prefixed with
        /// `[frame_seq | chunk_idx | chunk_count]`). Sent only when the
        /// agent advertised `chunk-framing` in `AgentCaps.video`, so the
        /// two ends can never disagree about bytes already in flight.
        /// `None` / unset (older controllers) means the legacy unframed
        /// format, which is reassemblable only because the channel is
        /// reliable + ordered.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chunk_framing: Option<bool>,
        /// Opt-in system/desktop audio. When `true` the controller wants
        /// the agent to add a WebRTC Opus audio track (the agent must
        /// also advertise `"opus"` in `AgentCaps.audio` and be built with
        /// the `audio` feature). `#[serde(default)]` → older controllers
        /// that omit the field get no audio track (silent-by-default).
        #[serde(default)]
        audio_enabled: bool,
        /// Phase 5 — admin break-glass. When an `ADMINISTRATOR` force-starts a
        /// session against a device they don't own, this carries the mandatory
        /// reason. The API gate VALIDATES it (admin + non-owner); a non-admin
        /// setting it has no effect. A validated override skips consent (`Auto`)
        /// and is recorded as `AuditKind::AdminOverride`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        override_reason: Option<String>,
        /// Loopback-TURN corp-relay (Phase 2). When the controller's browser
        /// discovered a local-agent TURN via its loopback probe, it forwards the
        /// descriptor here so the Hub appends `turn:{overlay_ip}:{turn_port}` to
        /// the REMOTE agent's ICE servers — letting a corp-Chrome viewer that
        /// can't punch direct relay through the local agent's overlay instead of
        /// the capped far coturn. `#[serde(default)]` → older controllers that
        /// omit it get today's behaviour. See [`LocalRelayDescriptor`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        local_relay: Option<LocalRelayDescriptor>,
    },

    /// Controller sends an SDP offer (after consent granted).
    #[serde(rename = "rc:sdp.offer")]
    SdpOffer {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        sdp: String,
        /// FR-52 P4 — on an EXTERNAL session, the controller's MAC over its own
        /// DTLS fingerprint under the verified login's key. The device refuses
        /// an external offer without a valid one: this is what binds "someone
        /// proved the password" to "this transport" — without it the relaying
        /// server could open the session with a peer of its own.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        extauth_mac: Option<String>,
        /// FR-100 P1b — asks the device to sign its answer: the browser's
        /// nonce (P2 adds the controller's own key and signature). Relayed to
        /// the device verbatim.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_auth: Option<PeerAuthOffer>,
    },

    // ─── either side → server ────────────────────────────────────────
    /// Trickle ICE candidate. Server forwards to the peer.
    #[serde(rename = "rc:ice")]
    Ice {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        candidate: serde_json::Value, // { candidate, sdpMid, sdpMLineIndex, ... }
    },

    /// Either side hangs up.
    #[serde(rename = "rc:terminate")]
    Terminate {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        reason: EndReason,
        /// FR-101 P4b-2 — the limit that ended it, from the DEVICE: `idle`
        /// (with `IdleTimeout`) when the agent ended a session that sat idle
        /// past its `Request.idle_secs`; #2251 — or `no_common_codec` (with
        /// `Error`, [`LIMIT_NO_COMMON_CODEC`]) when the offer carried no
        /// codec its RTP video track can send. The hub honours each only from
        /// the agent and only with its reason, and names it on the
        /// `rc:terminate` it sends both ends. Absent otherwise; an older
        /// server ignores it and still ends the session on the reason.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<String>,
    },

    /// Liveness ping (cheap; the WS handler also has its own ping/pong).
    #[serde(rename = "rc:ping")]
    Ping { id: u32 },

    // ─── tunnel-client / agent → server (rc:tunnel.*) ────────────────
    //
    // Plan v2 §"What changed from v1" #1 + #2:
    //   * Wire types fold into the existing `rc:*` namespace, NOT a
    //     separate `rc-tunnel:*` namespace or WS endpoint.
    //   * Each `roomler forward` invocation owns ONE peer; many
    //     TCP flows multiplex onto a fixed DC pool via `flow_id`
    //     framing (see `tunnel-core::mux`). No per-flow DC creation.
    //   * Server is the auth boundary — `TcpForwardRequest` rides the
    //     WS so the server can apply the cross-tenant gate + policy
    //     eval before forwarding to the agent.
    //
    /// Sent right after WS upgrade by either a `roomler` client
    /// or an agent that wants to advertise tunnel support. Locks in
    /// the wire transport for the rest of the session.
    ///
    /// `supported_transports` carries strings (not an enum) so a
    /// newer client and an older agent can still negotiate a common
    /// transport. v1 ships `["webrtc-dc-v1"]`; v0.5 adds
    /// `"wireguard-v1"`.
    #[serde(rename = "rc:tunnel.hello")]
    TunnelHello {
        role: TunnelRole,
        version: String,
        supported_transports: Vec<String>,
    },

    /// Client → server: open a tunnel peer-channel to a specific
    /// agent. Server applies the cross-tenant gate (rejects if
    /// `client.tenant_id != agent.tenant_id`), forwards the request
    /// to the agent's WS, and replies with `rc:tunnel.opened` once
    /// the SDP offer/answer + ICE exchange + DC pool negotiation
    /// completes (driven by the existing `rc:sdp.*` + `rc:ice` flow,
    /// keyed by the `session_id` the server assigns).
    #[serde(rename = "rc:tunnel.open")]
    TunnelOpen {
        #[serde(with = "oid_hex")]
        agent_id: ObjectId,
        /// One of `supported_transports` from the client's hello.
        transport: String,
        /// Client-chosen correlation id, echoed verbatim on the matching
        /// `TunnelOpened` (success) or open-failure `Error`. Lets ONE WS
        /// carry N concurrent opens: the `roomlerd` daemon (P3b-2)
        /// multiplexes many client sessions over its single agent WS and
        /// demuxes the reply by this nonce (post-open it switches to the
        /// server-minted `session_id`). The standalone `roomler`
        /// CLI has a single in-flight open and sends `None`, matching the
        /// reply positionally. `None` is omitted on the wire, so a
        /// pre-P3b-2 server/client stays byte-identical.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        open_nonce: Option<String>,
        /// R4 (`quic-derp-v1`): the CLIENT's overlay/DERP pubkey (64
        /// lowercase hex chars), so the agent can address its tunnel QUIC
        /// endpoint at this client over the established `/derp` WS. Only
        /// sent when the client can serve the derp flavor; the server
        /// copies it into `TunnelQuicSetup.client_derp_pubkey` when the
        /// flavor is negotiated. Absent ⇒ omitted on the wire (pre-R4
        /// byte-identical).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        derp_pubkey: Option<String>,
        /// FR-90 P3-7-2a — the vault's grant (`rc:vault.net.granted`): this
        /// tunnel carries an agent SESSION's own flows, not the device's.
        /// Accepted only from an agent's own WS, verified, and bound to the
        /// tunnel session: its device, its exit, its end, and a forward's
        /// one destination. A grant that does not hold refuses the open.
        ///
        /// ⚠️ A server from before P3-7-2a ignores the field and would open
        /// the tunnel as the DEVICE's. A device that sends a grant must
        /// therefore find it echoed in `rc:tunnel.opened`
        /// (`ServerMsg::TunnelOpened::net_grant_id`) before it carries a
        /// session's flow over the tunnel.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        net_grant: Option<String>,
    },

    /// Client → server (forwarded to agent): open one TCP forward.
    /// Server-side ACL gate runs HERE — the cross-tenant check fires
    /// first, then `tunnel_policies` is evaluated, then either a
    /// `TcpForwardReject` is sent back to the client OR the request
    /// is forwarded to the agent for the actual dial.
    ///
    /// `flow_id` is client-chosen + monotonic per `session_id`; it
    /// prefixes every DC message belonging to this flow (see
    /// `tunnel-core::mux::encode`). Server treats `flow_id` as opaque
    /// — only the client and agent demux on it.
    #[serde(rename = "rc:tunnel.tcp.request")]
    TcpForwardRequest {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        dst_host: String,
        dst_port: u16,
    },

    /// Agent → server: agent dialed `dst_host:dst_port` for the flow
    /// and is ready to pump bytes. Server relays the accept back to
    /// the client. `dc_index` tells the client which DC in the pool
    /// has been assigned for this flow.
    #[serde(rename = "rc:tunnel.tcp.accept")]
    TcpForwardAccept {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        dc_index: u8,
    },

    /// Agent → server (or server-generated on ACL deny): the flow is
    /// rejected. Server relays to the client. Servers MAY synthesise
    /// this with `RejectKind::CrossTenant` or `AclDenied` without
    /// touching the agent.
    #[serde(rename = "rc:tunnel.tcp.reject")]
    TcpForwardReject {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        kind: RejectKind,
        reason: String,
    },

    /// Either side announces half-close on a flow. Carried over WS
    /// (rather than the DC) because the close needs to drive
    /// audit-log accounting in addition to the actual socket
    /// shutdown.
    #[serde(rename = "rc:tunnel.tcp.half_close")]
    TcpHalfClose {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        direction: Direction,
    },

    /// Either side closes a flow (clean EOF or error). Server relays
    /// to the peer and appends to `tunnel_audit`.
    ///
    /// The byte counts are the flow's final totals, reported by the
    /// endpoint because the server never sees them: tunnel payload
    /// rides the peer-to-peer data channel, which is why the
    /// `tunnel_audit.bytes_in`/`bytes_out` columns held a literal 0 on
    /// every row written before this. TCP-side application payload (not
    /// framed DC bytes), so the number is comparable across the WebRTC
    /// and QUIC transports. `#[serde(default)]` ⇒ a pre-wave-3 client
    /// still parses and simply books zero.
    #[serde(rename = "rc:tunnel.tcp.closed")]
    TcpClosed {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        reason: CloseReason,
        /// Peer → local app (what the operator's tool received).
        #[serde(default)]
        bytes_in: u64,
        /// Local app → peer (what the operator's tool sent).
        #[serde(default)]
        bytes_out: u64,
    },

    /// Client → server (→ agent): open one UDP forward (SOCKS5 UDP
    /// ASSOCIATE). Gated exactly like [`TcpForwardRequest`] but the
    /// server evaluates the policy with `proto = udp`. `flow_id` is
    /// client-chosen + monotonic per `session_id`; one UDP flow is
    /// opened per distinct `(dst_host, dst_port)` the app addresses
    /// within a single SOCKS association. Datagrams for the flow are
    /// carried length-prefixed over the negotiated transport (DC: one
    /// `mux`-framed message per datagram; QUIC: a per-flow bidi stream
    /// of `[u16 len | datagram]`). Association lifetime = the SOCKS
    /// control TCP connection on the client; individual flows
    /// idle-close.
    #[serde(rename = "rc:tunnel.udp.request")]
    UdpForwardRequest {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        dst_host: String,
        dst_port: u16,
    },

    /// Agent → server → client: agent bound a UDP socket for the flow
    /// and is ready to relay datagrams. Mirrors [`TcpForwardAccept`];
    /// `dc_index` selects the pool DC for the WebRTC transport (0 for
    /// QUIC, which has no DC pool).
    #[serde(rename = "rc:tunnel.udp.accept")]
    UdpForwardAccept {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        dc_index: u8,
    },

    /// Agent → server (or server-synthesised on ACL deny): the UDP flow
    /// is rejected. Mirrors [`TcpForwardReject`].
    #[serde(rename = "rc:tunnel.udp.reject")]
    UdpForwardReject {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        kind: RejectKind,
        reason: String,
    },

    /// Either side closes a UDP flow (idle-timeout, or the client's
    /// SOCKS association tore down). No half-close — UDP is
    /// datagram-oriented, there is no read-half to shut. Server relays
    /// to the peer + appends to `tunnel_audit` like [`TcpClosed`].
    #[serde(rename = "rc:tunnel.udp.closed")]
    UdpClosed {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        reason: CloseReason,
    },

    /// Either side tears down the whole peer (Ctrl-C on the CLI,
    /// agent shutdown, etc.). Server cleans up state + audits.
    #[serde(rename = "rc:tunnel.terminate")]
    TunnelTerminate {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        reason: CloseReason,
    },

    /// Tunnel-client → server → agent: SDP offer for the WebRTC peer
    /// negotiation. Distinct discriminator from the remote-control
    /// `rc:sdp.offer` so the server's session_id namespaces don't
    /// have to overlap. Carries no `ice_servers` (already delivered
    /// in `TunnelOpened`).
    #[serde(rename = "rc:tunnel.sdp.offer")]
    TunnelSdpOffer {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        sdp: String,
    },

    /// Agent → server → tunnel-client: SDP answer for the WebRTC peer
    /// negotiation. Mirror of `TunnelSdpOffer` on the answerer path.
    #[serde(rename = "rc:tunnel.sdp.answer")]
    TunnelSdpAnswer {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        sdp: String,
    },

    /// Either side trickles an ICE candidate for the tunnel peer.
    /// Server relays to the other side. Distinct discriminator from
    /// the remote-control `rc:ice` for the same reason as the SDP
    /// variants above.
    #[serde(rename = "rc:tunnel.ice")]
    TunnelIce {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        candidate: serde_json::Value,
    },

    /// Agent → server → tunnel-client: the agent's QUIC server endpoint
    /// is up. Carries the SHA-256 fingerprint of the agent's ephemeral
    /// self-signed cert (the client PINS it — there is no CA) plus the
    /// candidate address(es) to dial. The QUIC analogue of
    /// `TunnelSdpAnswer`. Phase 1 ships direct/host `addrs`; Phase 2
    /// adds STUN server-reflexive candidates.
    #[serde(rename = "rc:tunnel.quic.ready")]
    TunnelQuicReady {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        /// Lowercase-hex SHA-256 of the agent's ephemeral cert (DER).
        cert_fingerprint: String,
        /// `ip:port` candidates the client may dial (priority order).
        addrs: Vec<String>,
        /// R4 (`quic-derp-v1`): the AGENT's overlay/DERP pubkey (64 hex),
        /// which the client's DERP-backed QUIC endpoint addresses. Only
        /// present on derp-flavor sessions; absent ⇒ omitted (pre-R4
        /// byte-identical).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        derp_pubkey: Option<String>,
    },

    /// Tunnel-client → server → agent: the client's own QUIC candidate
    /// address(es) — specifically its TURN-relayed address when the
    /// session uses QUIC-over-TURN (Tier 2/3). The agent needs this to
    /// install a TURN permission for the client's relay address BEFORE
    /// the QUIC handshake: the agent is the QUIC *server* and never
    /// sends first, so without a permission pre-installed for the
    /// client's relay address coturn would drop the client's opening
    /// Initial packets. The client→agent mirror of `TunnelQuicReady`'s
    /// agent→client `addrs`. Phase 3c.
    #[serde(rename = "rc:tunnel.quic.candidate")]
    TunnelQuicCandidate {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        /// `ip:port` candidates — the client's relay address for Tier
        /// 2/3, optionally plus host/srflx. Priority order.
        addrs: Vec<String>,
    },

    // ─── overlay node → server (rc:overlay.*) ────────────────────────
    /// Node (agent or tunnel-client) announces itself to the overlay and
    /// registers its WireGuard static public key. The server does IPAM
    /// (allocating or rehydrating the node's overlay IP), persists the
    /// `OverlayNode`, and replies with a full `rc:overlay.netmap`.
    #[serde(rename = "rc:overlay.join")]
    OverlayJoin {
        /// Optional hint for which network to join (multi-network is a
        /// later phase; today the tenant has exactly one).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network_hint: Option<String>,
        /// base64 Curve25519 public key.
        wg_public_key: String,
        #[serde(default)]
        key_epoch: u32,
        /// Transports the node speaks (`["wireguard-v1", ...]`).
        #[serde(default)]
        supported: Vec<String>,
        /// Node's overlay MTU preference (server clamps to the network).
        mtu: u16,
        /// Initial connectivity candidates (host/srflx/relay).
        #[serde(default)]
        endpoints: Vec<String>,
        /// rc.142 — the node can carry WG over a QUIC-over-TURN relay carrier
        /// (`ROOMLERD_OVERLAY_QUIC=1`). The server persists it and echoes it
        /// per-peer in the netmap so QUIC is only attempted when BOTH ends
        /// advertise it (a QUIC/raw split would silently break the pair).
        #[serde(default)]
        supports_quic: bool,
        /// Phase D — the node can carry WG over the v1 single-relay carrier (ONE
        /// anchor allocation + a raw dialer, `ROOMLERD_OVERLAY_RELAY_SINGLE=1`).
        /// Persisted + echoed per-peer like `supports_quic`, so single-relay is
        /// only chosen when BOTH ends advertise it (a mixed pair stays on the
        /// both-allocate relay). Absent from a pre-Phase-D node ⇒ `false`.
        #[serde(default)]
        supports_relay_single: bool,
        /// Phase D (DERP) — the node can carry WG over the pubkey-addressed
        /// `/derp` WS relay (`ROOMLERD_OVERLAY_DERP=1`), the last-resort
        /// carrier for two BOTH-UDP-blocked peers. Persisted + echoed per-peer
        /// like `supports_relay_single`, so DERP is only chosen when BOTH ends
        /// advertise it. Absent from a pre-DERP node ⇒ `false`.
        #[serde(default)]
        supports_derp: bool,
        /// P7 (corp-DERP fallback) — the node honors the server's
        /// [`ServerMsg::OverlayForceDerp`] per-pair escalation push (it can pin
        /// a churning TURN pair onto the DERP carrier mid-run). The capability
        /// flag — not a version — gates the server: it only escalates a pair
        /// when BOTH ends advertise this. Absent from a pre-P7 node ⇒ `false`.
        #[serde(default)]
        supports_forced_derp: bool,
        /// U2 — the node accepts a SERVER-COMPUTED relay-tier verdict
        /// ([`NetmapPeer::relay_strategy`]) and uses it in place of its own
        /// local `relay_strategy()` derivation. The server populates the
        /// per-edge verdict ONLY when BOTH ends advertise this (an unflagged
        /// end computes locally from its own — possibly frozen — UDP-capability
        /// view the server can't reproduce, so a one-sided verdict would
        /// manufacture anchor/dialer role disagreements). Absent from a
        /// pre-U2 node ⇒ `false` ⇒ every pair keeps the client-authoritative
        /// path. Advertised only when the node's own
        /// `OVERLAY_SERVER_RELAY_STRATEGY` env/config is on.
        #[serde(default)]
        supports_server_relay_strategy: bool,
        /// Phase A (overlay v3) — the node runs the DERP always-on floor: its
        /// central `/derp` mux is open and registered for the whole session
        /// (not just when its srflx gather came up empty), so a pair may be
        /// floored on DERP at birth without predicting mux state. The server
        /// echoes it per-peer; the floor (and any measured DERP keying) is
        /// gated on BOTH ends advertising it — a pre-floor peer whose srflx
        /// gather succeeded holds no mux and never registers, so a floor
        /// toward it would blackhole. Absent ⇒ `false`.
        #[serde(default)]
        supports_derp_floor: bool,
        /// Data-probe — the node's overlay engine answers the overlay-native
        /// echo probe inline (the non-ICMP half of the hybrid carrier
        /// data-probe). Persisted + echoed per-peer so a prober prefers the
        /// engine-guaranteed echo toward capable peers (netstack-only nodes
        /// have no OS ICMP responder) and falls back to the ICMP probe for
        /// the rest. Absent from an older node ⇒ `false` ⇒ ICMP.
        #[serde(default)]
        supports_overlay_echo: bool,
        /// FR-19 — this node UNDERSTANDS `rc:overlay.relay_session` /
        /// `rc:overlay.relay_revoke` and the `org-relay` verdict. The server
        /// never pushes those to a node that has not said so: an unknown
        /// `ServerMsg` tag is dropped at `debug!` on the agent, which would make
        /// a minted session evaporate silently. Absent from an older node ⇒
        /// `false`. ⚠️ Distinct from the `relay-server` RPC verb, which says
        /// "I SERVE relays" — this says "I can USE one".
        #[serde(default)]
        supports_org_relay: bool,
        /// Accepts up to three distinct one-hop discovery hints. Absent on
        /// older clients whose cache accepts only one pure one-hop hint.
        #[serde(default)]
        supports_org_relay_multi_candidate: bool,
        /// Understands bounded traversal cursors; this does not enable org-relay.
        #[serde(default)]
        supports_org_relay_discovery_cursor: bool,
        /// Understands bilateral candidate trials; absent on legacy clients.
        #[serde(default)]
        supports_path_trial_v1: bool,
        #[serde(default)]
        supports_path_backbone_v1: bool,
        #[serde(default)]
        relay_backbone_ready: bool,
        /// FR-47 — this node understands [`ServerMsg::OverlayJoinRefused`], so
        /// a join the server cannot complete comes back as a stated reason
        /// instead of silence. Absent from an older node ⇒ `false`, and such a
        /// node keeps exactly the pre-FR-47 behaviour: it waits for a netmap
        /// that never arrives, and the server-side ERROR log is the only
        /// signal. Deliberately NOT persisted — the refusal decision is made
        /// inside the same handler that parsed this join, so there is nothing
        /// to remember.
        #[serde(default)]
        supports_join_refusal: bool,
        /// FR-19 (P3c) — whether this join comes from the device's PRIMARY
        /// org. Relay serving and relay use are primary-only: a UDP listener
        /// is host-global, and a secondary org's admin must not be able to
        /// mint sessions onto the device owner's listener — the same trust
        /// line `rc:agent.update` draws. `None` (a build that does not say)
        /// is treated as NOT primary for every relay decision: fail closed.
        /// P4 sets it from `OrgCtx`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        org_primary: Option<bool>,
        /// FR-19 (P3c) — the UDP port this node's org-relay server listens
        /// on when it serves one; the mint pairs it with the node's public
        /// addresses. `None` ⇒ `peer_relay_limits::DEFAULT_RELAY_PORT`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        relay_port: Option<u16>,
        /// Phase 1 — subnet CIDRs this node offers to route for peers
        /// (`--advertise-routes` / config). The server stores them as *claimed*
        /// routes; an admin must **approve** each before it's distributed in the
        /// netmap `routes`. Empty for a normal node (`#[serde(default)]`).
        #[serde(default)]
        advertised_routes: Vec<String>,
        /// FR-97 P0b — why `advertised_routes` is empty although the device was
        /// configured to offer routes: the host cannot forward or NAT for the
        /// overlay (a Mac; Windows Home, #2077). The server can show it beside
        /// the route approval, so an admin sees "cannot serve" rather than
        /// nothing at all. Additive both ways: an older agent never sends it,
        /// an older server ignores it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        route_offer_withheld: Option<String>,
    },

    /// Node trickles updated connectivity candidates; the server fans a
    /// delta to permitted peers.
    #[serde(rename = "rc:overlay.endpoints")]
    OverlayEndpoints { candidates: Vec<String> },

    /// Node trickles its server-reflexive (srflx) candidates — its public
    /// `ip:port` discovered via STUN on its own traffic sockets (NAT-traversal
    /// Phase B). The server stores them in a SEPARATE `srflx_endpoints` bucket
    /// (so the relay-endpoint trickle can't clobber them) and fans a delta to
    /// permitted peers, who may then dial this node directly through its NAT.
    /// Deliberately distinct from `rc:overlay.endpoints` (relay addresses):
    /// different lifecycle, different provenance, different bucket.
    ///
    /// `nat` (Phase C) is this node's probed NAT mapping type — `"cone"` (hole-
    /// punchable) or `"symmetric"` (not) — or omitted when it couldn't be probed
    /// ("unknown"). The server stores it alongside the srflx so peers can skip a
    /// futile punch when BOTH ends are symmetric. Optional + omitted-when-None ⇒
    /// a pre-Phase-C agent (rc.199, sends only `candidates`) still parses.
    ///
    /// `udp_dialer_ok` (dialer honesty, 2026-08-16) — whether this node can
    /// raw-UDP-dial arbitrary high ports (relay band), as opposed to merely
    /// having reached a well-known STUN port. New agents ALWAYS send
    /// `Some(_)` — field presence is the capability signal (an old server
    /// ignores it; an old agent omits it and every pair against it keeps
    /// the legacy srflx-only role inputs).
    #[serde(rename = "rc:overlay.srflx")]
    OverlaySrflx {
        candidates: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nat: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_dialer_ok: Option<bool>,
    },

    /// Phase B (overlay v3) — the node's MEASURED capability vector
    /// (netcheck): relay-band reachability over the exact dialer path,
    /// STUN/NAT snapshot, `/derp` WS health. Sent after each measurement
    /// pass (startup / netstate Major / ~20 min cadence). The server stores
    /// it with a receipt stamp and surfaces it per-peer behind a FRESHNESS
    /// gate — a stalled prober's vector must never stay fleet-
    /// authoritative. Unknown to a pre-B2 server ⇒ logged-and-ignored on
    /// the agent socket (no capability gate needed).
    #[serde(rename = "rc:overlay.netcheck")]
    OverlayNetcheck { caps: CapVectorWire },

    /// Node leaves the overlay (graceful). Server marks it offline and
    /// pushes a `netmap_delta` removing it from peers.
    #[serde(rename = "rc:overlay.leave")]
    OverlayLeave {},

    /// FR-19 P1 — reachability report: can THIS node reach an offered org
    /// relay's endpoint? Pairwise (node × relay × endpoint), which is why it is
    /// its own message and not a `CapVector` field — the vector is one
    /// process-global slot per node. Unknown to a pre-FR-19 server ⇒
    /// logged-and-ignored on the agent socket, no capability gate needed.
    #[serde(rename = "rc:overlay.relay_probe")]
    OverlayRelayProbe {
        #[serde(with = "oid_hex")]
        relay_node_id: ObjectId,
        /// The `ip:port` probed.
        endpoint: String,
        reachable: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rtt_ms: Option<u32>,
    },

    /// Negotiate a separate, reversible candidate; never an active session replacement.
    #[serde(rename = "rc:overlay.path_trial_request")]
    OverlayPathTrialRequest {
        #[serde(with = "oid_hex")]
        peer_node_id: ObjectId,
        #[serde(with = "oid_hex")]
        relay_node_id: ObjectId,
        request_id: u64,
        #[serde(
            default,
            with = "option_oid_hex",
            skip_serializing_if = "Option::is_none"
        )]
        exit_relay_node_id: Option<ObjectId>,
    },
    #[serde(rename = "rc:overlay.path_trial_ready")]
    OverlayPathTrialReady {
        #[serde(with = "oid_hex")]
        trial_id: ObjectId,
    },
    #[serde(rename = "rc:overlay.path_trial_committed")]
    OverlayPathTrialCommitted {
        #[serde(with = "oid_hex")]
        trial_id: ObjectId,
    },
    #[serde(rename = "rc:overlay.path_trial_abort")]
    OverlayPathTrialAbort {
        #[serde(with = "oid_hex")]
        trial_id: ObjectId,
    },
    #[serde(rename = "rc:overlay.path_trial_return_request")]
    OverlayPathTrialReturnRequest {
        #[serde(with = "oid_hex")]
        trial_id: ObjectId,
        #[serde(with = "oid_hex")]
        return_id: ObjectId,
    },
    #[serde(rename = "rc:overlay.path_trial_return_ready")]
    OverlayPathTrialReturnReady {
        #[serde(with = "oid_hex")]
        trial_id: ObjectId,
        #[serde(with = "oid_hex")]
        return_id: ObjectId,
    },
    #[serde(rename = "rc:overlay.path_trial_returned")]
    OverlayPathTrialReturned {
        #[serde(with = "oid_hex")]
        trial_id: ObjectId,
        #[serde(with = "oid_hex")]
        return_id: ObjectId,
    },
    #[serde(rename = "rc:overlay.path_trial_return_abort")]
    OverlayPathTrialReturnAbort {
        #[serde(with = "oid_hex")]
        trial_id: ObjectId,
        #[serde(with = "oid_hex")]
        return_id: ObjectId,
    },

    /// Discover one authorized tenant relay for this pair without allocating
    /// TURN or an org-relay session. Metadata only: never changes a carrier.
    #[serde(rename = "rc:overlay.org_relay_discover")]
    OverlayOrgRelayDiscover {
        #[serde(with = "oid_hex")]
        peer_node_id: ObjectId,
        /// Correlates replies to a pending local identity generation.
        request_id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<OrgRelayDiscoveryCursorWire>,
    },

    /// Node asks for short-lived coturn credentials to stand up a relay
    /// leg to a specific peer (used when direct hole-punch to that peer
    /// fails). The server replies with `rc:overlay.relay_grant` carrying
    /// creds keyed by the symmetric `pair_key`.
    ///
    /// U1 — the request now carries the requester's EVIDENCE, so the P7
    /// churn escalation can act on what actually happened instead of
    /// inferring everything from arrival timing. All three fields are
    /// additive with serde defaults: an old client omits them, an old
    /// server ignores them.
    #[serde(rename = "rc:overlay.relay_request")]
    OverlayRelayRequest {
        #[serde(with = "oid_hex")]
        peer_node_id: ObjectId,
        /// Which relay flavour this request is REPLACING (`"turn"` /
        /// `"derp"`); absent = a fresh establishment, which the churn
        /// counter should never mistake for a died-carrier cycle.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        current_kind: Option<String>,
        /// Why the prior carrier died (the `DeathReason` short string) —
        /// diagnostic evidence for the server's escalation logs.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        /// STICKY failure evidence: this client recently ATTEMPTED to open a
        /// `/derp` mux and failed (the `force_derp` veto condition). While
        /// set, the server must not choose or hold forced-DERP for this
        /// pair — a client that vetoes the pin while the server refuses TURN
        /// grants for the pin's TTL is a hard dark window (the silent-veto
        /// bug). Deliberately NOT "is a mux open": the mux opens lazily on
        /// first use, so a healthy client that never needed DERP has none.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        derp_mux_failed: bool,
    },

    /// ORG-only fallback query. Sent only after the server's explicit
    /// network capability; it must never enter TURN grant/churn handling.
    #[serde(rename = "rc:overlay.org_relay_fallback_request")]
    OverlayOrgRelayFallbackRequest {
        #[serde(with = "oid_hex")]
        peer_node_id: ObjectId,
        request_id: u64,
    },

    /// ORG loss report: one closed window of the stream `peer_node_id` sends
    /// this member over their ORG session `vni`, read from the peer's WG
    /// transport counters. `packets` is how far the counters advanced, and
    /// `lost` how many of those never arrived. The server decides what a
    /// lossy window means for the pair. Sent only after the server's
    /// [`OverlayNetworkInfo::org_relay_loss_v1`].
    #[serde(rename = "rc:overlay.org_relay_loss")]
    OverlayOrgRelayLoss {
        #[serde(with = "oid_hex")]
        peer_node_id: ObjectId,
        vni: u32,
        packets: u64,
        lost: u64,
    },

    /// C4 stage 1 — pair-less coturn credentials for the node's standing
    /// WARM allocation (one TURN/UDP allocation established while UDP
    /// works and kept alive so corp-VPN flow-grandfathering preserves a
    /// UDP relay leg — see `docs/overlay-warm-relay.md`). Request-driven,
    /// so no hello capability flag is needed: an agent that predates the
    /// feature never sends this, and therefore never sees the grant.
    /// The grant itself confers no reach — per-peer permissions still go
    /// through the ACL-checked `rc:overlay.relay_request` at pairing time.
    #[serde(rename = "rc:overlay.warm_relay_request")]
    OverlayWarmRelayRequest {},

    // ── FR-52 P3 — external access (`rc:extauth.*`) ──────────────────────
    //
    // An OPAQUE login between someone OUTSIDE the device's organization and
    // the device, relayed by a server that learns nothing it can use: no
    // password, nothing to attack offline, no proof it could replay. Every
    // login blob is base64url WITHOUT padding — `@serenity-kit/opaque`'s
    // encoding, so the browser's output crosses unmodified.
    //
    // Both CONTROLLER frames carry the connect code, not an agent id: an
    // outsider never learns the device's internal id, and the pod the browser
    // landed on re-resolves the code on every frame to route it to the pod
    // that holds the device — the outsider has no tenant, so tenant affinity
    // cannot put them on that pod to begin with.
    /// FR-52 P3 — controller → server: begin an external-access login.
    #[serde(rename = "rc:extauth.start")]
    ExtauthStart {
        /// As typed: grouping dashes and Crockford confusables are normalised
        /// server-side.
        connect_code: String,
        /// OPAQUE KE1.
        ke1: String,
    },
    /// FR-52 P3 — controller → server: finish the login the server's
    /// `rc:extauth.challenge` answered.
    ///
    /// ⚠️ Only the principal who STARTED `attempt_id` may finish it; the server
    /// checks, and the device checks again against the principal it was given
    /// at KE1.
    #[serde(rename = "rc:extauth.finish")]
    ExtauthFinish {
        connect_code: String,
        attempt_id: String,
        /// OPAQUE KE3.
        ke3: String,
    },
    /// FR-52 P3 — device → server: the device answered KE1. One guess spent.
    ///
    /// ⚠️ `agent_id` comes from the authenticated socket, never from this
    /// frame, and the server honours it only from the agent the KE1 was sent
    /// to — attempt ids are relayed to both parties and are not secret.
    #[serde(rename = "rc:extauth.ke2")]
    ExtauthKe2 {
        attempt_id: String,
        /// OPAQUE KE2.
        ke2: String,
    },
    /// FR-52 P3 — device → server: a login step is over. `refused` absent
    /// after KE3 = VERIFIED; present at either step = refused, and why.
    #[serde(rename = "rc:extauth.outcome")]
    ExtauthOutcome {
        attempt_id: String,
        /// Decoded leniently: an unknown refusal is still a refusal
        /// ([`crate::models::ExtauthRefusal::Other`]), never "verified".
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "extauth_refusal_lenient"
        )]
        refused: Option<crate::models::ExtauthRefusal>,
        /// Only with [`crate::models::ExtauthRefusal::Throttled`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_secs: Option<u32>,
    },
    /// FR-52 P4 — controller → server: open a session on the strength of a
    /// login the device VERIFIED (`attempt_id`, from this principal's own
    /// `rc:extauth.start` / `.finish`).
    ///
    /// Its own frame rather than new fields on `rc:session.request`, for two
    /// properties a type can hold better than a check:
    /// - it names the device by connect code, never by agent id — an outsider
    ///   never needs the internal id;
    /// - it has NO `local_relay` and NO `override_reason`. FR-52 finding F4: a
    ///   relay descriptor is validated as *an* overlay address, not *the
    ///   caller's*, so from someone outside the org it would be a probe into
    ///   the org's mesh. Absent from the frame, it cannot be smuggled in.
    ///
    /// The media fields mirror `rc:session.request` and mean the same thing.
    #[serde(rename = "rc:extauth.session")]
    ExtauthSession {
        connect_code: String,
        attempt_id: String,
        /// What the outsider asks for. The server narrows it to the org's
        /// ceiling (gate 2); the DEVICE narrows it again to its own.
        permissions: Permissions,
        #[serde(default)]
        browser_caps: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preferred_transport: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chroma_pref: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chunk_framing: Option<bool>,
        #[serde(default)]
        audio_enabled: bool,
        /// FR-115 P3b (O6) — the org (hex) the outsider runs this session
        /// for: one of their own orgs, whose concurrent-session slots it
        /// takes. Honoured only for an org the principal belongs to; absent
        /// (or not theirs), the server takes their only org, or, with none or
        /// several, counts it against the account with Free's quota. It rides
        /// this frame because the frame is what crosses to the device's pod.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        charge_org: Option<String>,
    },
}

/// FR-90 P3-7-1b — serde's test for a port that is absent: SOCKS names none.
fn is_zero_u16(port: &u16) -> bool {
    *port == 0
}

/// FR-52 P4 — carried in `rc:request` when the session is an EXTERNAL one:
/// opened on a verified login, not on org membership.
///
/// The principal is the request's `controller_user_id`; this names the login
/// the device must find verified for that principal, single-use.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ExternalGrant {
    pub attempt_id: String,
}

// ────────────────────────────────────────────────────────────────────────────
// FR-69 D7 — who owns each client message
// ────────────────────────────────────────────────────────────────────────────

/// The server module that owns a client message (FR-69 D7). The wire stays
/// ONE socket and ONE `rc:*` enum; this is the map that tells the socket
/// which module's handler a message belongs to. The prefix is NOT the owner:
/// `rc:consent*` is fleet's (one consent payload for RC, exec and SSH since
/// FR-27), `rc:relay.*` is network's, and `rc:agent.key_rotated` is
/// network's (overlay-key rotation) although it arrives on the agent's
/// `rc:agent.*` lane. So the map is explicit per variant, exhaustive, and
/// locked by the tests below.
///
/// The wire crate is MPL and agent-linked, so this names modules by id and
/// never by type; `roomler-core` checks the ids against its module graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Owner {
    /// Device management: the agent's own lane (hello, heartbeat, config
    /// status), fleet RPC, owner consent, the socket keepalive.
    Fleet,
    /// Remote-desktop sessions: request, SDP, ICE, terminate, stats.
    Remote,
    /// The mesh and what rides it: overlay, tunnels, relays and DERP
    /// tickets, SSH, key rotation.
    Network,
    /// FR-90 — agent sessions: a device's answer to a start, and each
    /// session's lifecycle.
    Hive,
    /// FR-90 P3-3b — the vault: a session's lease requests.
    Vault,
}

impl Owner {
    /// The module id, as `roomler_core::graph::MODULES` spells it.
    pub const fn id(self) -> &'static str {
        match self {
            Owner::Fleet => "fleet",
            Owner::Remote => "remote",
            Owner::Network => "network",
            Owner::Hive => "hive",
            Owner::Vault => "vault",
        }
    }
}

impl ClientMsg {
    /// The wire tag this variant serialises as (`t`) — the same string as its
    /// `#[serde(rename)]`, spelled out so a variant can be named without an
    /// instance. Exhaustive: a new variant does not compile until it is here.
    pub fn wire_tag(&self) -> &'static str {
        match self {
            ClientMsg::AgentHello { .. } => "rc:agent.hello",
            ClientMsg::AgentHeartbeat { .. } => "rc:agent.heartbeat",
            ClientMsg::RelayProbeReport { .. } => "rc:relay.probe_report",
            ClientMsg::NetInventory { .. } => "rc:agent.net_inventory",
            ClientMsg::ManagedForwardStatus { .. } => "rc:forward.status",
            ClientMsg::SessionStats { .. } => "rc:session.stats",
            ClientMsg::SharedSshConnect { .. } => "rc:share.ssh.connect",
            ClientMsg::SharedSshPrepared { .. } => "rc:share.ssh.prepared",
            ClientMsg::SharedSshLeaseChallenge { .. } => "rc:share.ssh.lease.challenge",
            ClientMsg::SharedLeaseChallenge { .. } => "rc:share.lease.challenge",
            ClientMsg::DerpTicketRequest { .. } => "rc:relay.derp_ticket_request",
            ClientMsg::RpcResult { .. } => "rc:rpc.result",
            ClientMsg::RpcExecRequest { .. } => "rc:rpc.request",
            ClientMsg::SshRequest { .. } => "rc:ssh.request",
            ClientMsg::SshActivity { .. } => "rc:ssh.activity",
            ClientMsg::RecordingActivity { .. } => "rc:recording.activity",
            ClientMsg::PrivacyActivity { .. } => "rc:privacy.activity",
            ClientMsg::SshGrantAck { .. } => "rc:ssh.grant_ack",
            ClientMsg::ConfigStatus { .. } => "rc:agent.config_status",
            ClientMsg::KeyRotated { .. } => "rc:agent.key_rotated",
            ClientMsg::HiveStartAck { .. } => "rc:hive.start_ack",
            ClientMsg::HiveState { .. } => "rc:hive.state",
            ClientMsg::HiveTurn { .. } => "rc:hive.turn",
            ClientMsg::HiveApproval { .. } => "rc:hive.approval",
            ClientMsg::HiveManifest { .. } => "rc:hive.manifest",
            ClientMsg::HiveAdopt { .. } => "rc:hive.adopt",
            ClientMsg::HiveReplicaJoinAck { .. } => "rc:hive.replica.join_ack",
            ClientMsg::HiveReplicaTip { .. } => "rc:hive.replica.tip",
            ClientMsg::HiveReplicaManifest { .. } => "rc:hive.replica.manifest",
            ClientMsg::HiveReplicaWant { .. } => "rc:hive.replica.want",
            ClientMsg::HiveReplicaReady { .. } => "rc:hive.replica.ready",
            ClientMsg::HiveReplicaCandidate { .. } => "rc:hive.replica.candidate",
            ClientMsg::HiveReplicaClose { .. } => "rc:hive.replica.close",
            ClientMsg::HivePrepareAck { .. } => "rc:hive.prepare_ack",
            ClientMsg::HiveDrained { .. } => "rc:hive.drained",
            ClientMsg::HivePurgeAck { .. } => "rc:hive.purge_ack",
            ClientMsg::HiveRetainAsk { .. } => "rc:hive.retain_ask",
            ClientMsg::HiveViewGrantAck { .. } => "rc:hive.view.grant_ack",
            ClientMsg::HiveViewAnswer { .. } => "rc:hive.view.answer",
            ClientMsg::HiveViewIce { .. } => "rc:hive.view.ice",
            ClientMsg::HiveViewClosed { .. } => "rc:hive.view.closed",
            ClientMsg::VaultLease { .. } => "rc:vault.lease",
            ClientMsg::VaultList { .. } => "rc:vault.list",
            ClientMsg::VaultDescribe { .. } => "rc:vault.describe",
            ClientMsg::VaultActivity { .. } => "rc:vault.activity",
            ClientMsg::VaultNet { .. } => "rc:vault.net",
            ClientMsg::VaultSsh { .. } => "rc:vault.ssh",
            ClientMsg::VaultConnect { .. } => "rc:vault.connect",
            ClientMsg::SdpAnswer { .. } => "rc:sdp.answer",
            ClientMsg::Consent { .. } => "rc:consent",
            ClientMsg::ConsentPending { .. } => "rc:consent.pending",
            ClientMsg::SessionRequest { .. } => "rc:session.request",
            ClientMsg::SdpOffer { .. } => "rc:sdp.offer",
            ClientMsg::Ice { .. } => "rc:ice",
            ClientMsg::Terminate { .. } => "rc:terminate",
            ClientMsg::Ping { .. } => "rc:ping",
            ClientMsg::TunnelHello { .. } => "rc:tunnel.hello",
            ClientMsg::TunnelOpen { .. } => "rc:tunnel.open",
            ClientMsg::TcpForwardRequest { .. } => "rc:tunnel.tcp.request",
            ClientMsg::TcpForwardAccept { .. } => "rc:tunnel.tcp.accept",
            ClientMsg::TcpForwardReject { .. } => "rc:tunnel.tcp.reject",
            ClientMsg::TcpHalfClose { .. } => "rc:tunnel.tcp.half_close",
            ClientMsg::TcpClosed { .. } => "rc:tunnel.tcp.closed",
            ClientMsg::UdpForwardRequest { .. } => "rc:tunnel.udp.request",
            ClientMsg::UdpForwardAccept { .. } => "rc:tunnel.udp.accept",
            ClientMsg::UdpForwardReject { .. } => "rc:tunnel.udp.reject",
            ClientMsg::UdpClosed { .. } => "rc:tunnel.udp.closed",
            ClientMsg::TunnelTerminate { .. } => "rc:tunnel.terminate",
            ClientMsg::TunnelSdpOffer { .. } => "rc:tunnel.sdp.offer",
            ClientMsg::TunnelSdpAnswer { .. } => "rc:tunnel.sdp.answer",
            ClientMsg::TunnelIce { .. } => "rc:tunnel.ice",
            ClientMsg::TunnelQuicReady { .. } => "rc:tunnel.quic.ready",
            ClientMsg::TunnelQuicCandidate { .. } => "rc:tunnel.quic.candidate",
            ClientMsg::OverlayJoin { .. } => "rc:overlay.join",
            ClientMsg::OverlayEndpoints { .. } => "rc:overlay.endpoints",
            ClientMsg::OverlaySrflx { .. } => "rc:overlay.srflx",
            ClientMsg::OverlayNetcheck { .. } => "rc:overlay.netcheck",
            ClientMsg::OverlayLeave { .. } => "rc:overlay.leave",
            ClientMsg::OverlayRelayProbe { .. } => "rc:overlay.relay_probe",
            ClientMsg::OverlayRelayRequest { .. } => "rc:overlay.relay_request",
            ClientMsg::OverlayOrgRelayDiscover { .. } => "rc:overlay.org_relay_discover",
            ClientMsg::OverlayOrgRelayFallbackRequest { .. } => {
                "rc:overlay.org_relay_fallback_request"
            }
            ClientMsg::OverlayOrgRelayLoss { .. } => "rc:overlay.org_relay_loss",
            ClientMsg::OverlayPathTrialRequest { .. } => "rc:overlay.path_trial_request",
            ClientMsg::OverlayPathTrialReady { .. } => "rc:overlay.path_trial_ready",
            ClientMsg::OverlayPathTrialCommitted { .. } => "rc:overlay.path_trial_committed",
            ClientMsg::OverlayPathTrialAbort { .. } => "rc:overlay.path_trial_abort",
            ClientMsg::OverlayPathTrialReturnRequest { .. } => {
                "rc:overlay.path_trial_return_request"
            }
            ClientMsg::OverlayPathTrialReturnReady { .. } => "rc:overlay.path_trial_return_ready",
            ClientMsg::OverlayPathTrialReturned { .. } => "rc:overlay.path_trial_returned",
            ClientMsg::OverlayPathTrialReturnAbort { .. } => "rc:overlay.path_trial_return_abort",

            ClientMsg::OverlayWarmRelayRequest { .. } => "rc:overlay.warm_relay_request",
            ClientMsg::ExtauthStart { .. } => "rc:extauth.start",
            ClientMsg::ExtauthFinish { .. } => "rc:extauth.finish",
            ClientMsg::ExtauthKe2 { .. } => "rc:extauth.ke2",
            ClientMsg::ExtauthOutcome { .. } => "rc:extauth.outcome",
            ClientMsg::ExtauthSession { .. } => "rc:extauth.session",
        }
    }

    /// The module that owns this message. Exhaustive on purpose (FR-69 AC6):
    /// a new variant does not compile until it names an owner — the
    /// structural replacement for the `_ =>` catch-all hazard.
    pub fn namespace(&self) -> Owner {
        match self {
            ClientMsg::AgentHello { .. }
            | ClientMsg::AgentHeartbeat { .. }
            | ClientMsg::RpcResult { .. }
            | ClientMsg::RpcExecRequest { .. }
            | ClientMsg::ConfigStatus { .. }
            | ClientMsg::Consent { .. }
            | ClientMsg::ConsentPending { .. }
            | ClientMsg::Ping { .. } => Owner::Fleet,
            ClientMsg::SharedLeaseChallenge { .. }
            | ClientMsg::SessionRequest { .. }
            | ClientMsg::SdpOffer { .. }
            | ClientMsg::SdpAnswer { .. }
            | ClientMsg::Ice { .. }
            | ClientMsg::Terminate { .. }
            | ClientMsg::SessionStats { .. }
            | ClientMsg::RecordingActivity { .. }
            | ClientMsg::PrivacyActivity { .. }
            // FR-52 — what a controller reaches (§2d of the spec), including
            // the device's answers, which exist only to be relayed back to it.
            | ClientMsg::ExtauthStart { .. }
            | ClientMsg::ExtauthFinish { .. }
            | ClientMsg::ExtauthKe2 { .. }
            | ClientMsg::ExtauthOutcome { .. }
            | ClientMsg::ExtauthSession { .. } => Owner::Remote,
            ClientMsg::SharedSshConnect { .. }
            | ClientMsg::SharedSshPrepared { .. }
            | ClientMsg::SharedSshLeaseChallenge { .. }
            | ClientMsg::RelayProbeReport { .. }
            | ClientMsg::NetInventory { .. }
            | ClientMsg::ManagedForwardStatus { .. }
            | ClientMsg::DerpTicketRequest { .. }
            | ClientMsg::SshRequest { .. }
            | ClientMsg::SshActivity { .. }
            | ClientMsg::SshGrantAck { .. }
            | ClientMsg::KeyRotated { .. }
            | ClientMsg::TunnelHello { .. }
            | ClientMsg::TunnelOpen { .. }
            | ClientMsg::TcpForwardRequest { .. }
            | ClientMsg::TcpForwardAccept { .. }
            | ClientMsg::TcpForwardReject { .. }
            | ClientMsg::TcpHalfClose { .. }
            | ClientMsg::TcpClosed { .. }
            | ClientMsg::UdpForwardRequest { .. }
            | ClientMsg::UdpForwardAccept { .. }
            | ClientMsg::UdpForwardReject { .. }
            | ClientMsg::UdpClosed { .. }
            | ClientMsg::TunnelTerminate { .. }
            | ClientMsg::TunnelSdpOffer { .. }
            | ClientMsg::TunnelSdpAnswer { .. }
            | ClientMsg::TunnelIce { .. }
            | ClientMsg::TunnelQuicReady { .. }
            | ClientMsg::TunnelQuicCandidate { .. }
            | ClientMsg::OverlayJoin { .. }
            | ClientMsg::OverlayEndpoints { .. }
            | ClientMsg::OverlaySrflx { .. }
            | ClientMsg::OverlayNetcheck { .. }
            | ClientMsg::OverlayLeave { .. }
            | ClientMsg::OverlayRelayProbe { .. }
            | ClientMsg::OverlayRelayRequest { .. }
            | ClientMsg::OverlayOrgRelayDiscover { .. }
            | ClientMsg::OverlayOrgRelayFallbackRequest { .. }
            | ClientMsg::OverlayOrgRelayLoss { .. }
            | ClientMsg::OverlayPathTrialRequest { .. }
            | ClientMsg::OverlayPathTrialReady { .. }
            | ClientMsg::OverlayPathTrialCommitted { .. }
            | ClientMsg::OverlayPathTrialAbort { .. }
            | ClientMsg::OverlayPathTrialReturnRequest { .. }
            | ClientMsg::OverlayPathTrialReturnReady { .. }
            | ClientMsg::OverlayPathTrialReturned { .. }
            | ClientMsg::OverlayPathTrialReturnAbort { .. }

            | ClientMsg::OverlayWarmRelayRequest { .. } => Owner::Network,
            ClientMsg::HiveStartAck { .. }
            | ClientMsg::HiveState { .. }
            | ClientMsg::HiveTurn { .. }
            | ClientMsg::HiveApproval { .. }
            | ClientMsg::HiveManifest { .. }
            | ClientMsg::HiveAdopt { .. }
            | ClientMsg::HiveReplicaJoinAck { .. }
            | ClientMsg::HiveReplicaTip { .. }
            | ClientMsg::HiveReplicaManifest { .. }
            | ClientMsg::HiveReplicaWant { .. }
            | ClientMsg::HiveReplicaReady { .. }
            | ClientMsg::HiveReplicaCandidate { .. }
            | ClientMsg::HiveReplicaClose { .. }
            | ClientMsg::HivePrepareAck { .. }
            | ClientMsg::HiveDrained { .. }
            | ClientMsg::HivePurgeAck { .. }
            | ClientMsg::HiveRetainAsk { .. }
            | ClientMsg::HiveViewGrantAck { .. }
            | ClientMsg::HiveViewAnswer { .. }
            | ClientMsg::HiveViewIce { .. }
            | ClientMsg::HiveViewClosed { .. } => Owner::Hive,
            ClientMsg::VaultLease { .. }
            | ClientMsg::VaultList { .. }
            | ClientMsg::VaultDescribe { .. }
            | ClientMsg::VaultActivity { .. }
            | ClientMsg::VaultNet { .. }
            | ClientMsg::VaultSsh { .. }
            | ClientMsg::VaultConnect { .. } => Owner::Vault,
        }
    }
}

/// Every client wire tag with its owner: the table the composition baseline
/// snapshots (`crates/tests/fixtures/composition.baseline.json`, section
/// `namespaces`), so a message that changes hands is a visible line in a
/// review. Kept next to [`ClientMsg::namespace`] and locked against both the
/// enum's renames and the match by the tests below.
pub const CLIENT_MSG_OWNERS: &[(&str, Owner)] = &[
    ("rc:share.ssh.connect", Owner::Network),
    ("rc:share.ssh.prepared", Owner::Network),
    ("rc:share.ssh.lease.challenge", Owner::Network),
    ("rc:share.lease.challenge", Owner::Remote),
    ("rc:agent.hello", Owner::Fleet),
    ("rc:agent.heartbeat", Owner::Fleet),
    ("rc:relay.probe_report", Owner::Network),
    ("rc:agent.net_inventory", Owner::Network),
    ("rc:forward.status", Owner::Network),
    ("rc:session.stats", Owner::Remote),
    ("rc:recording.activity", Owner::Remote),
    ("rc:privacy.activity", Owner::Remote),
    ("rc:relay.derp_ticket_request", Owner::Network),
    ("rc:rpc.result", Owner::Fleet),
    ("rc:rpc.request", Owner::Fleet),
    ("rc:ssh.request", Owner::Network),
    ("rc:ssh.activity", Owner::Network),
    ("rc:ssh.grant_ack", Owner::Network),
    ("rc:agent.config_status", Owner::Fleet),
    ("rc:agent.key_rotated", Owner::Network),
    ("rc:hive.start_ack", Owner::Hive),
    ("rc:hive.state", Owner::Hive),
    ("rc:hive.turn", Owner::Hive),
    ("rc:hive.approval", Owner::Hive),
    ("rc:hive.manifest", Owner::Hive),
    ("rc:hive.adopt", Owner::Hive),
    ("rc:hive.replica.join_ack", Owner::Hive),
    ("rc:hive.replica.tip", Owner::Hive),
    ("rc:hive.replica.manifest", Owner::Hive),
    ("rc:hive.replica.want", Owner::Hive),
    ("rc:hive.replica.ready", Owner::Hive),
    ("rc:hive.replica.candidate", Owner::Hive),
    ("rc:hive.replica.close", Owner::Hive),
    ("rc:hive.prepare_ack", Owner::Hive),
    ("rc:hive.drained", Owner::Hive),
    ("rc:hive.purge_ack", Owner::Hive),
    ("rc:hive.retain_ask", Owner::Hive),
    ("rc:hive.view.grant_ack", Owner::Hive),
    ("rc:hive.view.answer", Owner::Hive),
    ("rc:hive.view.ice", Owner::Hive),
    ("rc:hive.view.closed", Owner::Hive),
    ("rc:vault.lease", Owner::Vault),
    ("rc:vault.list", Owner::Vault),
    ("rc:vault.describe", Owner::Vault),
    ("rc:vault.activity", Owner::Vault),
    ("rc:vault.net", Owner::Vault),
    ("rc:vault.ssh", Owner::Vault),
    ("rc:vault.connect", Owner::Vault),
    ("rc:sdp.answer", Owner::Remote),
    ("rc:consent", Owner::Fleet),
    ("rc:consent.pending", Owner::Fleet),
    ("rc:session.request", Owner::Remote),
    ("rc:sdp.offer", Owner::Remote),
    ("rc:ice", Owner::Remote),
    ("rc:terminate", Owner::Remote),
    ("rc:ping", Owner::Fleet),
    ("rc:tunnel.hello", Owner::Network),
    ("rc:tunnel.open", Owner::Network),
    ("rc:tunnel.tcp.request", Owner::Network),
    ("rc:tunnel.tcp.accept", Owner::Network),
    ("rc:tunnel.tcp.reject", Owner::Network),
    ("rc:tunnel.tcp.half_close", Owner::Network),
    ("rc:tunnel.tcp.closed", Owner::Network),
    ("rc:tunnel.udp.request", Owner::Network),
    ("rc:tunnel.udp.accept", Owner::Network),
    ("rc:tunnel.udp.reject", Owner::Network),
    ("rc:tunnel.udp.closed", Owner::Network),
    ("rc:tunnel.terminate", Owner::Network),
    ("rc:tunnel.sdp.offer", Owner::Network),
    ("rc:tunnel.sdp.answer", Owner::Network),
    ("rc:tunnel.ice", Owner::Network),
    ("rc:tunnel.quic.ready", Owner::Network),
    ("rc:tunnel.quic.candidate", Owner::Network),
    ("rc:overlay.join", Owner::Network),
    ("rc:overlay.endpoints", Owner::Network),
    ("rc:overlay.srflx", Owner::Network),
    ("rc:overlay.netcheck", Owner::Network),
    ("rc:overlay.leave", Owner::Network),
    ("rc:overlay.relay_probe", Owner::Network),
    ("rc:overlay.relay_request", Owner::Network),
    ("rc:overlay.org_relay_discover", Owner::Network),
    ("rc:overlay.org_relay_fallback_request", Owner::Network),
    ("rc:overlay.org_relay_loss", Owner::Network),
    ("rc:overlay.path_trial_request", Owner::Network),
    ("rc:overlay.path_trial_ready", Owner::Network),
    ("rc:overlay.path_trial_committed", Owner::Network),
    ("rc:overlay.path_trial_abort", Owner::Network),
    ("rc:overlay.path_trial_return_request", Owner::Network),
    ("rc:overlay.path_trial_return_ready", Owner::Network),
    ("rc:overlay.path_trial_returned", Owner::Network),
    ("rc:overlay.path_trial_return_abort", Owner::Network),
    ("rc:overlay.warm_relay_request", Owner::Network),
    ("rc:extauth.start", Owner::Remote),
    ("rc:extauth.finish", Owner::Remote),
    ("rc:extauth.ke2", Owner::Remote),
    ("rc:extauth.outcome", Owner::Remote),
    ("rc:extauth.session", Owner::Remote),
];

#[cfg(test)]
mod namespace_tests {
    use super::*;

    /// The renames inside the `ClientMsg` enum, read from this file's own
    /// source — so the table below is checked against what serde actually
    /// emits, not against a second hand-written list.
    fn client_renames() -> Vec<String> {
        // Normalised first: a Windows checkout with `core.autocrlf` has CRLF
        // line ends, `"\n}\n"` below then never matches, and this test fails
        // there on a table that is perfectly correct (found on the dev box).
        let src = include_str!("signaling.rs").replace("\r\n", "\n");
        let src = src.as_str();
        let start = src
            .find("pub enum ClientMsg {")
            .expect("the enum is in this file");
        let body = &src[start..];
        let end = body.find("\n}\n").expect("the enum closes");
        let body = &body[..end];
        let needle = "rename = \"";
        let mut out = Vec::new();
        let mut rest = body;
        while let Some(i) = rest.find(needle) {
            rest = &rest[i + needle.len()..];
            let Some(j) = rest.find('"') else { break };
            out.push(rest[..j].to_string());
            rest = &rest[j + 1..];
        }
        out
    }

    fn owner_of(tag: &str) -> Option<Owner> {
        CLIENT_MSG_OWNERS
            .iter()
            .find(|(t, _)| *t == tag)
            .map(|(_, o)| *o)
    }

    /// The table names every client wire tag exactly once — no variant
    /// without an owner, no owner for a variant that is gone.
    #[test]
    fn the_owner_table_names_every_client_wire_tag_exactly_once() {
        let renames = client_renames();
        assert!(
            renames.len() >= 40,
            "the enum span was not read: {} renames",
            renames.len()
        );
        let table: Vec<&str> = CLIENT_MSG_OWNERS.iter().map(|(t, _)| *t).collect();
        let mut deduped = table.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(deduped.len(), table.len(), "a wire tag is listed twice");
        let mut missing: Vec<&str> = renames
            .iter()
            .map(String::as_str)
            .filter(|r| !table.contains(r))
            .collect();
        let mut extra: Vec<&str> = table
            .iter()
            .copied()
            .filter(|t| !renames.iter().any(|r| r == t))
            .collect();
        missing.sort_unstable();
        extra.sort_unstable();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "owner table drift — missing: {missing:?}, extra: {extra:?}"
        );
    }

    /// `wire_tag()` is the tag serde emits, and `namespace()` is the table's
    /// owner — checked on the variants cheap enough to build.
    #[test]
    fn wire_tag_and_namespace_agree_with_the_table() {
        let samples = [
            ClientMsg::Ping { id: 7 },
            ClientMsg::Terminate {
                session_id: ObjectId::new(),
                reason: EndReason::AdminTerminated,
                limit: None,
            },
            ClientMsg::OverlayLeave {},
            ClientMsg::OverlayOrgRelayFallbackRequest {
                peer_node_id: ObjectId::new(),
                request_id: 1,
            },
            ClientMsg::OverlayOrgRelayLoss {
                peer_node_id: ObjectId::new(),
                vni: 7,
                packets: 3000,
                lost: 240,
            },
            ClientMsg::TunnelTerminate {
                session_id: ObjectId::new(),
                reason: CloseReason::ClientShutdown,
            },
            ClientMsg::SshGrantAck {
                grant_id: "g1".into(),
                refused: None,
            },
            ClientMsg::HiveStartAck {
                session_id: ObjectId::new(),
                fence: 1,
                refused: None,
                account: None,
                detail: None,
            },
            ClientMsg::HiveState {
                session_id: ObjectId::new(),
                fence: 1,
                state: Some(crate::hive::HiveRunState::Idle),
                detail: None,
            },
            ClientMsg::ExtauthStart {
                connect_code: "ABCD-EFGH-JKMN".into(),
                ke1: "a2Ux".into(),
            },
            ClientMsg::ExtauthFinish {
                connect_code: "ABCD-EFGH-JKMN".into(),
                attempt_id: "a1".into(),
                ke3: "a2Uz".into(),
            },
            ClientMsg::ExtauthKe2 {
                attempt_id: "a1".into(),
                ke2: "a2Uy".into(),
            },
            ClientMsg::ExtauthOutcome {
                attempt_id: "a1".into(),
                refused: None,
                retry_after_secs: None,
            },
            ClientMsg::ExtauthSession {
                connect_code: "ABCD-EFGH-JKMN".into(),
                attempt_id: "a1".into(),
                permissions: Permissions::VIEW,
                browser_caps: vec![],
                preferred_transport: None,
                chroma_pref: None,
                chunk_framing: None,
                audio_enabled: false,
                charge_org: Some("6a975e17971e2d55ddcdedb2".into()),
            },
        ];
        for m in &samples {
            let v = serde_json::to_value(m).expect("a client message serialises");
            assert_eq!(v["t"].as_str(), Some(m.wire_tag()), "{m:?}");
            let owner = owner_of(m.wire_tag()).expect("every variant is in the table");
            assert_eq!(m.namespace(), owner, "{m:?}");
        }
    }

    /// The three placements D7 calls out because the prefix would mislead.
    #[test]
    fn the_prefix_is_not_the_owner() {
        assert_eq!(owner_of("rc:consent"), Some(Owner::Fleet));
        assert_eq!(owner_of("rc:consent.pending"), Some(Owner::Fleet));
        assert_eq!(owner_of("rc:relay.probe_report"), Some(Owner::Network));
        assert_eq!(owner_of("rc:agent.key_rotated"), Some(Owner::Network));
    }

    /// The ids are what the module graph spells, and they serialise as such.
    #[test]
    fn owner_ids_are_stable_lowercase_module_ids() {
        for owner in [Owner::Fleet, Owner::Remote, Owner::Network, Owner::Hive] {
            let json = serde_json::to_string(&owner).unwrap();
            assert_eq!(json, format!("\"{}\"", owner.id()));
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Outbound from server
// ────────────────────────────────────────────────────────────────────────────

/// Shared sessions require a peer-owned short monotonic lease. Missing means
/// ordinary legacy session, never permission to share with an old agent.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SharedSessionLease {
    #[serde(with = "oid_hex")]
    pub grant_id: ObjectId,
    pub lease_epoch: String,
}

/// Target-bound stream specification received only on the authenticated agent WS.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SharedSshSetup {
    #[serde(with = "oid_hex")]
    pub device_id: ObjectId,
    #[serde(with = "oid_hex")]
    pub owner_user_id: ObjectId,
    #[serde(with = "oid_hex")]
    pub recipient_user_id: ObjectId,
    pub shared_lease: SharedSessionLease,
    pub ssh_grant_id: String,
    pub public_key: String,
    pub caller: String,
    pub account_mode: crate::models::SshAccountMode,
    pub account: Option<String>,
    pub consent_mode: Option<ConsentMode>,
    pub expires_at_ms: u64,
    pub session_secs: u64,
}

/// Messages the server sends.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t")]
pub enum ServerMsg {
    #[serde(rename = "rc:share.ssh.setup")]
    SharedSshSetup {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        setup: SharedSshSetup,
    },
    #[serde(rename = "rc:share.ssh.forward")]
    SharedSshForward {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
    },
    #[serde(rename = "rc:share.ssh.lease.renewal")]
    SharedSshLeaseRenewal {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        lease_epoch: String,
        challenge_id: u64,
    },
    /// Echo only after the exact session live PDP succeeds.
    #[serde(rename = "rc:share.lease.renewal")]
    SharedLeaseRenewal {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        lease_epoch: String,
        challenge_id: u64,
    },
    /// Sent to the controller right after `SessionRequest` so it knows the id.
    #[serde(rename = "rc:session.created")]
    SessionCreated {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        #[serde(with = "oid_hex")]
        agent_id: ObjectId,
        /// Multi-user P3 — the EFFECTIVE permission grant, which may be
        /// narrower than requested (the single-INPUT-holder rule strips
        /// INPUT while another live session on the agent holds it). Additive:
        /// `None` from a pre-P3 server means "as requested" (the legacy
        /// contract); serde-default so old viewers ignore it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        permissions: Option<crate::permissions::Permissions>,
        /// FR-85 P3 — why `RECORD` was taken out of the requested grant, when
        /// it was: `device_cannot_record` (P3c-2: no recorder on the device
        /// at all — the viewer shows no Record control), `controller_not_allowed`
        /// (not the device's owner, an ADMINISTRATOR or a
        /// `RECORD_REMOTE_SCREEN` holder — or a break-glass session) or
        /// `device_not_opted_in` (the device's owner has not switched remote
        /// recording on). The viewer says so for the last two rather than
        /// just hiding a button. Additive: absent = not requested, or granted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        record_refused: Option<String>,
        /// FR-99 — why `PRIVACY` was taken out of the requested grant, when
        /// it was: `device_cannot_curtain` (no curtain is possible on the
        /// device — the viewer offers no privacy control), `break_glass` (a
        /// break-glass session never covers the screen of the person it
        /// skipped asking) or `device_not_opted_in` (the device's owner has
        /// not allowed privacy mode). Additive: absent = not requested, or
        /// granted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        privacy_refused: Option<String>,
        /// FR-101 P2 — the session features the policy took out of what was
        /// asked for, each with why: `{"files": "org_policy_off"}`. Keys are
        /// `clipboard`, `files` and `audio`; reasons are `org_policy_off`
        /// (the organization switched it off), `device_policy_off` (P2b: the
        /// device's owner did, `AgentCaps.session_policy`), `needs_consent` (the policy
        /// says to ask, and nobody at the device is asked under this
        /// session's consent mode), `device_cannot_ask` (it would be asked,
        /// but the device's agent predates `session-policy`) and
        /// `policy_unavailable` (the org's policy could not be read).
        /// A viewer shows the reason rather than a control that silently
        /// fails. Additive: absent = nothing refused; a key or reason this
        /// viewer does not know still reads as "not granted".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        features_refused: Option<std::collections::BTreeMap<String, String>>,
        /// FR-101 P4b-2 — the idle limit this session runs under, in seconds:
        /// it ends after this long with no input from its controller and no
        /// significant change on the screen. Present only when the device
        /// enforces it (its agent advertises `idle-timeout`), so a viewer
        /// never promises a limit an older agent ignores. Absent = no idle
        /// limit, or none this device can keep.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idle_secs: Option<u32>,
    },

    /// Sent to the agent when a controller asks for control. The agent prompts
    /// the user (or auto-grants per AccessPolicy) and replies with `Consent`.
    ///
    /// `browser_caps` is forwarded verbatim from the controller's
    /// `rc:session.request` (codec short names like `"h264"`,
    /// `"h265"`, etc.). The agent intersects this with its own
    /// `AgentCaps.codecs` to pick the best codec for the session.
    /// Empty on controllers that don't advertise — the agent then
    /// defaults to H.264.
    ///
    /// `preferred_transport` (Phase Y.3) is also forwarded verbatim.
    /// `None` / unset means "use the WebRTC video track" (legacy
    /// default). Recognised values match `AgentCaps.transports` —
    /// today only `data-channel-vp9-444`. The agent honours the
    /// request when its caps advertise the same transport, else
    /// falls back to the WebRTC track silently.
    #[serde(rename = "rc:request")]
    Request {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shared_lease: Option<SharedSessionLease>,
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        #[serde(with = "oid_hex")]
        controller_user_id: ObjectId,
        controller_name: String,
        permissions: Permissions,
        consent_timeout_secs: u32,
        #[serde(default)]
        browser_caps: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        preferred_transport: Option<String>,
        /// rc.62 — per-session VP9 chroma override forwarded verbatim
        /// from the controller's [`ClientMsg::SessionRequest::chroma_pref`].
        /// `None` / unset means "use the agent's
        /// `ROOMLERD_VP9_CHROMA` env-var default".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chroma_pref: Option<String>,
        /// FR-17 — forwarded verbatim from the controller's
        /// [`ClientMsg::SessionRequest::chunk_framing`]. `Some(true)` means
        /// the controller can parse the framed wire format; anything else
        /// keeps the legacy unframed one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chunk_framing: Option<bool>,
        /// Opt-in system/desktop audio, forwarded verbatim from the
        /// controller's [`ClientMsg::SessionRequest::audio_enabled`]. When
        /// `true` the agent adds a WebRTC Opus audio track (if built with
        /// the `audio` feature). `#[serde(default)]` → older servers /
        /// controllers that omit it get no audio track.
        #[serde(default)]
        audio_enabled: bool,
        /// Phase 2 — server-authoritative consent directive. `None` (an older
        /// server that predates consent modes) → the agent falls back to its
        /// local `auto_grant_session` config; `Some(mode)` → the agent OBEYS:
        /// `Auto` grants immediately with no prompt, everything else runs the
        /// on-host prompt path. Resolved server-side from the device's
        /// `AccessPolicy.consent_mode` (self-control → `Auto`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        consent_mode: Option<ConsentMode>,
        /// FR-27 — how long the ON-HOST prompt should stand, which is not
        /// always `consent_timeout_secs`.
        ///
        /// The two coincide for `prompt`, and diverge for `prompt_then_email`:
        /// the session waits the full async window for the owner's emailed
        /// link, but the modal on the host's screen has no business standing
        /// there for five minutes. Sent by the server rather than derived by
        /// the agent so there is ONE authority for the split; `None` (older
        /// server) means "use `consent_timeout_secs`", i.e. exactly the
        /// pre-FR-27 behaviour.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host_prompt_timeout_secs: Option<u32>,
        /// P6 — the device's input arbitration mode directive from
        /// `AccessPolicy.input_mode`. `None` (older server / unset policy) →
        /// the agent's arbiter default (free). Only the FIRST session's hint
        /// seeds the mode; in-session toggles win afterwards. Additive —
        /// serde-default so old agents/servers interop.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        input_mode: Option<crate::models::InputMode>,
        /// Multi-org — the DISPLAY NAME of the organization this request
        /// comes from, so the consent prompt can say who is asking.
        ///
        /// A device enrolled in N orgs runs N signalling loops into the same
        /// host. Without this the operator sees "Alice wants to control this
        /// machine" and cannot tell whether Alice is asking as a colleague or
        /// as a contractor from another company — which is precisely the
        /// decision consent exists to make. The agent knows only its
        /// `tenant_id` (an opaque hex), so the NAME has to come from here.
        ///
        /// `None` on an older server → the prompt falls back to the org's
        /// config label, and to nothing at all for the primary enrollment
        /// (the pre-multi-org behaviour).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tenant_name: Option<String>,
        /// #1882 — the device's `AccessPolicy.rc_overlay`, resolved: may this
        /// session's ICE use the WireGuard overlay? `false` — absent from an
        /// older server, and the policy default — makes the agent keep every
        /// overlay address out of the session (its own overlay interface, an
        /// overlay-addressed remote candidate, an overlay TURN server).
        /// `true` is the behaviour from before the field. Skipped when false,
        /// so the default costs nothing on the wire.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        rc_overlay: bool,
        /// FR-101 P2 — the org's session policy for clipboard, files and
        /// audio. The hub has already taken out of `permissions` (and
        /// `audio_enabled`) what the policy refuses here; an agent that
        /// advertises `session-policy` names the `ask` features on its prompt
        /// and enforces the rest again, which is what survives a hub that was
        /// bypassed. `None` (an older server, or an org that restricts
        /// nothing) = unrestricted; older agents ignore the field.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_policy: Option<crate::models::SessionPolicy>,
        /// FR-101 P4b-2 — end the session after this many seconds with no
        /// input from its controller and no significant change on the screen.
        /// The stricter of the org's idle limit and the device's
        /// `AccessPolicy::auto_terminate_idle_minutes`. Only the agent sees
        /// both halves of "idle", so it measures and ends the session itself
        /// (`ClientMsg::Terminate` with `IdleTimeout` and `limit: "idle"`).
        /// `None` (an older server, or no limit) = never idle out; an older
        /// agent ignores the field, which is why the hub tells a viewer the
        /// limit only for one that advertises `idle-timeout`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        idle_secs: Option<u32>,
        /// FR-99 P3b — what the device's access policy asks of the end of
        /// this session (`auto` / `always`). The agent takes the stricter of
        /// this and its own `lock_on_end`, so an ask can only tighten it.
        /// Sent only to an agent advertising `lock-on-end`; `None` (an older
        /// server, nothing asked, or `never`) leaves the device's own setting.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lock_on_end: Option<crate::models::LockOnEnd>,
        /// FR-52 P4 — present when this is an EXTERNAL session: the controller
        /// is not in the device's organization, and was admitted on a login
        /// the device verified. The device must bind the session to that
        /// login, apply its OWN ceiling and consent mode for outsiders, and
        /// say "outside your organization" in the prompt.
        ///
        /// ⚠️ An agent that predates this field would IGNORE it and run an
        /// ordinary session — which is why the server sends it only to an
        /// agent advertising `RpcCap::ExternalSession`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        external: Option<ExternalGrant>,
    },

    /// Server forwards SDP offer from controller → agent.
    #[serde(rename = "rc:sdp.offer")]
    SdpOffer {
        /// Immutable server-derived scope; shared offers never downgrade to legacy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shared_lease: Option<SharedSessionLease>,
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        sdp: String,
        ice_servers: Vec<IceServer>,
        /// FR-52 P4 — relayed verbatim from the controller's offer. The server
        /// cannot check it (it never holds the key) and must not drop it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        extauth_mac: Option<String>,
        /// FR-100 P1b — relayed verbatim from the controller's offer, like
        /// `extauth_mac`: the nonce the device signs its answer against.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_auth: Option<PeerAuthOffer>,
    },

    /// Server forwards SDP answer from agent → controller.
    #[serde(rename = "rc:sdp.answer")]
    SdpAnswer {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        sdp: String,
        ice_servers: Vec<IceServer>,
        /// FR-52 P4 — relayed verbatim from the device's answer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        extauth_mac: Option<String>,
        /// FR-100 P1b — relayed verbatim from the device's answer: its
        /// signature, which the server neither checks nor may drop. The
        /// browser is the party that verifies it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer_auth: Option<PeerAuthAnswer>,
    },

    /// Forward ICE candidate to the peer.
    #[serde(rename = "rc:ice")]
    Ice {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        candidate: serde_json::Value,
    },

    /// Sent to the controller after the agent has consented and is ready for
    /// the SDP offer. Controller now creates its PeerConnection.
    /// FR-34 — relayed from the agent's [`ClientMsg::ConsentPending`]: the
    /// host is locked while a consent prompt is pending, so the operator has
    /// to unlock the machine before they can see and approve it. Advisory; the
    /// viewer uses it to turn a bare "awaiting consent" into an instruction.
    #[serde(rename = "rc:consent.pending")]
    ConsentPending {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        host_locked: bool,
    },

    #[serde(rename = "rc:ready")]
    Ready {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        ice_servers: Vec<IceServer>,
    },

    /// Either peer is gone, or admin terminated, or consent denied.
    #[serde(rename = "rc:terminate")]
    Terminate {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        reason: EndReason,
        /// FR-101 P4b — which limit ended the session, when one did:
        /// `max_duration` (the org's maximum session length, ended by the
        /// hub) or `idle` (P4b-2: the idle limit, ended by the device), with
        /// `reason` `IdleTimeout`, the variant every reader already knows.
        /// #2251 — or `no_common_codec` with `reason` `Error`: the device can
        /// send none of the codecs the browser offered, so asking again fails
        /// the same way. Lets a viewer say which, and not retry that one.
        /// Absent otherwise; older readers ignore it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<String>,
    },

    /// Reply to `Ping`.
    #[serde(rename = "rc:pong")]
    Pong { id: u32 },

    /// Generic error pushed to the client.
    #[serde(rename = "rc:error")]
    Error {
        #[serde(with = "option_oid_hex")]
        session_id: Option<ObjectId>,
        code: String,
        message: String,
        /// Set only when this error rejects a `TunnelOpen` — carries that
        /// open's `open_nonce` so a multiplexing daemon can fail the exact
        /// pending flow instead of guessing. `None` (omitted) for every
        /// non-open error and whenever the originator sent no nonce. A
        /// nonce-less `Error` arriving mid-open therefore reads as "open
        /// rejected / server too old" and fails that flow fast.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        open_nonce: Option<String>,
    },

    /// Server-initiated close of an agent WS connection (rc.53).
    /// Sent immediately before the WS Close frame so the agent can
    /// surface a useful reason in its log + decide whether to
    /// reconnect or stop.
    ///
    /// Emitted at three sites:
    ///   * `crates/api/src/ws/handler.rs:189` — agent row is
    ///     deleted/quarantined, `reason = AgentDeleted`.
    ///   * `crates/remote_control/src/hub.rs::register_agent`
    ///     displacement path, `reason = ReplacedByNewerConnection`.
    ///   * (future) policy gate (account suspended, etc.),
    ///     `reason = PolicyRejected`.
    ///
    /// Pre-rc.53 agents hit their existing `Err(e) => debug!`
    /// decoder branch and ignore the message; the subsequent WS
    /// Close still fires, so no regression. Pre-rc.53 server +
    /// rc.53 agent: agent never receives Goodbye; raw close
    /// is treated as transient (no fatal exit). Both directions
    /// covered by Phase 4 back-compat tests.
    #[serde(rename = "rc:goodbye")]
    Goodbye {
        reason: AgentCloseReason,
        /// Human-readable, operator-targeted. Used verbatim in the
        /// agent's `needs-attention.txt` sentinel + the
        /// `tracing::error!` line that surfaces the close to the
        /// operator.
        message: String,
    },

    /// S1a — operator-triggered forced self-update ("Update now" in the
    /// admin UI, single or bulk). The agent runs one update cycle
    /// immediately — the same download/verify/install path as its
    /// periodic updater, still honouring the 5-min install-storm
    /// cooldown. Back-compat mirrors `Goodbye`: pre-S1a agents fail to
    /// decode the unknown tag in their `Err(e) => debug!` decoder branch
    /// and ignore it — no WS disruption.
    #[serde(rename = "rc:agent.update")]
    UpdateNow {
        /// Optional release tag to install (e.g. `agent-v0.3.0-rc.260`);
        /// `None` = latest. Pinning bypasses the is-newer check (the
        /// admin explicitly chose a version).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pin: Option<String>,
    },

    /// The device config an operator has asked for, for the agent to
    /// reconcile against its own (`docs/remote-config.md`).
    ///
    /// A REQUEST, not an instruction. Three independent things can make the
    /// agent decline it, and all three are the point rather than edge cases:
    /// the device may not have opted in (`remote_config_enabled`, default
    /// off), the frame may have arrived on a SECONDARY org's WS (these keys
    /// are machine-wide, so only the primary enrollment may drive them —
    /// the same rule `UpdateNow` applies to the machine-wide updater), and a
    /// device is always free to be running an older build.
    ///
    /// ⚠️ Unlike `Goodbye`/`UpdateNow`, the server must NOT send this
    /// blind. Those are fire-and-forget, so a pre-feature agent dropping the
    /// unknown tag in its `Err(e) => debug!` branch costs nothing. Here the
    /// dashboard is showing an operator that a change is pending, so a
    /// silently-evaporated frame becomes a lie on a screen. Gate on
    /// [`RpcCap::Config`] and surface "device too old" instead.
    ///
    /// [`RpcCap::Config`]: crate::models::RpcCap::Config
    #[serde(rename = "rc:agent.config")]
    ConfigPush {
        /// The `desired_config.revision` this frame carries. The agent echoes
        /// it back once applied, which is what lets the UI tell "refused" from
        /// "never heard" — two states that otherwise look identical.
        revision: u64,
        /// Only the keys under management; absent keys mean "leave alone".
        desired: crate::models::DesiredConfig,
    },

    /// FR-40 — order the device to retire its overlay (WireGuard) key: mint
    /// a fresh one LOCALLY, persist it, report back with
    /// [`ClientMsg::KeyRotated`], then reconnect and re-join under the new
    /// key (`docs/fr/FR-40-overlay-key-rotation.md`).
    ///
    /// An ORDER, never a delivery: this frame carries no key material and a
    /// test locks that it never grows any. The server never sees a private
    /// key at any step — which is the property that makes the overlay's
    /// end-to-end encryption mean something.
    ///
    /// Per org, honoured on whichever org's WS it arrives on: a device's
    /// overlay key is per enrollment (`AgentConfig::for_org` scopes it), so
    /// org B rotating its own key on a shared host touches nothing of org
    /// A's. This is the OPPOSITE of [`Self::UpdateNow`] / [`Self::ConfigPush`],
    /// which drive machine-wide state and are therefore primary-only.
    ///
    /// ⚠️ Gate on [`RpcCap::KeyRotate`] — never send it blind (see that
    /// verb's doc). Disruptive by design: the device ends every session it
    /// carries on that org and rebuilds its overlay runtime.
    ///
    /// [`RpcCap::KeyRotate`]: crate::models::RpcCap::KeyRotate
    /// MeshHarbor #20 — the WHOLE set of managed forwards this agent should
    /// run (an empty set stops them all). Idempotent by `id` + `revision`;
    /// the agent answers with [`ClientMsg::ManagedForwardStatus`]. Sent only
    /// to a device advertising [`RpcCap::ManagedForward`].
    ///
    /// [`RpcCap::ManagedForward`]: crate::models::RpcCap::ManagedForward
    #[serde(rename = "rc:forward.set")]
    ManagedForwardSet {
        forwards: Vec<ManagedForwardAssignment>,
    },

    /// MeshHarbor #20 — the server heard the agent's
    /// [`ClientMsg::ManagedForwardStatus`] carrying `confirm: generation`:
    /// its nft change kept the control path, so the agent keeps it. Without
    /// this in time the agent's watchdog restores the last confirmed table.
    #[serde(rename = "rc:forward.confirm")]
    ManagedForwardConfirm { generation: u64 },

    #[serde(rename = "rc:agent.key_rotate")]
    KeyRotate {
        /// Echoed in the report so an answer can be matched to THIS order.
        request_id: String,
    },

    /// FR-92 — this org's standing keep-busy policy. Sent on EVERY connect
    /// (both ways, so a re-allow made while the device was offline clears
    /// its persisted deny) and again whenever an org admin changes it.
    ///
    /// The device enforces it: the strictest of every org it is enrolled in
    /// wins, a deny stops a keep busy already running, and the last value is
    /// persisted so it holds at boot, before the device reconnects. The
    /// server can only ADD a deny this way — `keep_busy_enabled` on the
    /// device stays the owner's, and absent from `DesiredConfig`.
    ///
    /// ⚠️ Cap-gated on `AgentCaps.input` containing `keep-busy` (equality):
    /// a pre-FR-92 agent cannot parse the tag and logs every unknown `rc:*`
    /// frame at WARN.
    #[serde(rename = "rc:agent.keep_busy_policy")]
    KeepBusyPolicy { denied: bool },

    /// Multi-org — join an ADDITIONAL org from the admin UI ("Add to another
    /// organization"), so a device that can't be reached for a hands-on
    /// `roomler enroll` still gets a second enrollment.
    ///
    /// The agent exchanges the token for its own agent JWT in the target
    /// tenant, APPENDS an `[[orgs]]` entry (with a freshly minted per-org WG
    /// key — never a copy) and brings that org's supervised WS loop up
    /// in-process, no restart.
    ///
    /// **There is deliberately no `server_url` field.** The agent always
    /// enrolls against the control plane it is ALREADY talking to, so a
    /// forged/relayed frame can never point a device at a foreign server —
    /// and same-control-plane is a hard requirement for shared-TUN meshing
    /// anyway (`docs/multi-org.md` §4.4).
    ///
    /// Honoured ONLY on the PRIMARY enrollment's socket (mirroring
    /// [`Self::UpdateNow`]): a secondary org's admin must not be able to
    /// enroll a device it merely borrows into further orgs.
    ///
    /// Back-compat mirrors `Goodbye`/`UpdateNow`: an agent that predates the
    /// variant fails to decode the unknown tag in its `Err(e) => debug!`
    /// branch and ignores it — no WS disruption. The server still gates on
    /// `AgentCaps.multi_org` so the UI can be honest about which devices
    /// support it.
    #[serde(rename = "rc:agent.join_org")]
    JoinOrg {
        /// Single-use enrollment token for the TARGET tenant (10 min).
        enrollment_token: String,
        /// Label for the new `[[orgs]]` entry. `None` ⇒ the agent derives
        /// one (server host), same as a CLI `enroll` without `--label`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        /// Overlay participation for the new org: `off` (default) |
        /// `netstack` | `tun`. `tun` additionally needs the daemon's
        /// `overlay_multi_org` opt-in to take effect.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        overlay_mode: Option<String>,
    },

    // ─── Fleet RPC (rc:rpc.*) ────────────────────────────────────────
    /// Run one bounded shell command on this device and answer with
    /// [`ClientMsg::RpcResult`].
    ///
    /// The server has already cleared gates 1–3 (org kill-switch, caller
    /// permission, device [`crate::models::ExecPolicy`]) before this is sent;
    /// the agent enforces gate 4 — its own `exec_enabled` config key — plus
    /// consent and the execution bounds below. A gate-4 refusal comes back as
    /// an `RpcResult` carrying `error`, never as silence.
    ///
    /// Unlike `Goodbye`/`UpdateNow`, this variant must NOT rely on the
    /// unknown-tag debug branch: a caller is blocked on the answer, so
    /// silence reads as a hang. The server gates on `AgentCaps.rpc`
    /// containing `exec` and fails the request with `412` when it is absent.
    #[serde(rename = "rc:rpc.exec")]
    RpcExec {
        /// Correlates with [`ClientMsg::RpcResult`]. Server-minted.
        request_id: String,
        /// `pwsh` | `powershell` | `cmd` on Windows; `bash` | `sh` elsewhere.
        shell: String,
        command: String,
        /// Server-clamped wall-clock budget. The agent kills the whole
        /// process tree when it expires.
        timeout_ms: u64,
        /// Server-clamped output ceiling across both streams combined.
        max_output_bytes: u64,
        /// Working directory; `None` ⇒ the daemon's own.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        /// Display name of the acting principal — shown in the consent prompt
        /// and written to the agent's local log, so the person at the device
        /// can see who asked.
        caller: String,
        /// Server-resolved consent directive from the device's
        /// [`crate::models::ExecPolicy`], mirroring how [`Self::Request`]
        /// carries `consent_mode` for a session. `Auto` runs immediately
        /// (unattended servers); anything else prompts the person at the
        /// device and denies on timeout. Absent ⇒ the agent prompts, because
        /// the fail-safe direction for a gate that grants root is "ask".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        consent_mode: Option<crate::models::ConsentMode>,
        /// FR-94 — run through the device's SYSTEM service, not in this
        /// process. Sent only to a device advertising `exec-system`. The worker
        /// still asks for consent (its person sees the prompt), then rings the
        /// service's doorbell with `request_id` and nothing else. The service
        /// claims the command from the server and runs it there, so the worker
        /// never decides what SYSTEM runs. A worker that cannot reach the
        /// service answers with an `RpcResult` error. It never falls back to
        /// running the command itself, as an identity it was not asked for.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        via_service: bool,
        /// FR-97 P5a — who runs it in this process: `console_user`, the
        /// person at the device's screen, instead of the daemon. Sent only to
        /// a Linux or macOS device advertising `console-user`
        /// ([`crate::models::RpcCap::ConsoleUser`]): an older agent ignores
        /// the field and would run the command as root, the identity the
        /// policy refused. Absent ⇒ the daemon, as ever. A word this build
        /// does not know is refused, never run as the daemon. A string, not
        /// [`crate::models::ExecRunAs`]: a newer server's word must fail the
        /// command, not the whole frame, which a caller would wait out.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        run_as: Option<String>,
    },

    /// Kill an in-flight [`Self::RpcExec`] and its whole process tree. The
    /// agent still answers with an [`ClientMsg::RpcResult`] (carrying
    /// `error`), so a cancelled caller is never left waiting.
    #[serde(rename = "rc:rpc.cancel")]
    RpcCancel { request_id: String },

    /// Authorize ONE inbound roomler-SSH session on this device.
    ///
    /// Pushed to the **target** after the server has cleared gates 1-3 (org
    /// kill-switch, the caller's `SSH_DEVICE` permission, the device's
    /// `SshPolicy`). The agent holds it briefly and consumes it when a
    /// connection authenticates with the named key.
    ///
    /// This is why roomler SSH needs no key distribution and no shared secret
    /// with the server: the agent does not *verify* the grant cryptographically,
    /// it receives it over the control WS it is already authenticated on —
    /// the same trust path `rc:request` uses to open a remote-control session.
    #[serde(rename = "rc:ssh.grant")]
    SshGrant {
        /// Server-minted, single-use.
        grant_id: String,
        /// OpenSSH public key the caller will authenticate with. Accepted for
        /// exactly one session, until `expires_at_ms`.
        public_key: String,
        /// Display name of the acting principal — shown in the consent prompt,
        /// written to the agent's local log and carried into the audit record,
        /// so the person at the device can see who connected.
        caller: String,
        /// Which local account the session runs as, server-resolved from the
        /// device's policy: `daemon` | `console_user` | `named`.
        account_mode: String,
        /// The account for `named`. Absent otherwise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account: Option<String>,
        /// Unix ms after which the grant may no longer be redeemed. Short —
        /// see [`crate::models::ssh_limits::GRANT_TTL_SECS`].
        expires_at_ms: u64,
        /// Server-clamped lifetime of the session once redeemed.
        session_secs: u64,
        /// Server-resolved consent directive, mirroring [`Self::RpcExec`].
        /// Absent ⇒ the agent prompts, the fail-safe direction.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        consent_mode: Option<crate::models::ConsentMode>,
        /// FR-105 — this grant is for the device's SYSTEM service, not the
        /// worker. The worker must NOT record it (its own server would then
        /// accept the key as the signed-in user); it rings the service with
        /// `grant_id` alone, and the service claims the grant from the server
        /// with its own credential. Sent only to a device advertising
        /// `ssh-system`; absent (false) on every other grant, so the frame
        /// is byte-for-byte what older agents parse.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        via_service: bool,
        /// FR-90 P3-8-1b — an agent session's grant: the device serves the
        /// key ONE `exec` and refuses anything else on it (P3-8-2a). Sent only
        /// to a device advertising `ssh-one-command`, which can read it; absent
        /// (false) on every other grant, so the frame is byte for byte what
        /// older agents parse.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        one_command: bool,
    },

    /// Answer to a device-originated [`ClientMsg::SshRequest`] — the
    /// `roomler ssh` CLI leg. Carries where to connect, or why not.
    #[serde(rename = "rc:ssh.response")]
    SshResponse {
        request_id: String,
        /// The target's overlay address. Absent on refusal.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<String>,
        /// The target's intercepted SSH port. Absent on refusal.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
        /// Echo of the grant the target was given, for correlation in logs.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant_id: Option<String>,
        /// P6a — the target's SSH host public key, so the dialling device can
        /// verify what it reached instead of trusting it on first use.
        ///
        /// This leg needs it MORE than the HTTP one, not less: `roomler ssh`
        /// originates here, and it is the caller that has no other channel to
        /// learn the key. Absent ⇒ the device reported none, which means it
        /// cannot prove itself — never "any key is fine".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host_pubkey: Option<String>,
        /// Unix ms the grant stops being redeemable — the caller should dial
        /// before this and give up after.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_at_ms: Option<u64>,
        /// Set when the server refused. A caller is blocked on this frame, so
        /// a refusal is always answered rather than dropped.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        /// FR-90 P3-8-1b — the echo of the agent session's ticket
        /// (`SshRequest::ssh_ticket`), by its id, once the server held the
        /// request to it. A server before P3-8-1b ignores the ticket and
        /// would answer the request as the device owner's, so the session's
        /// daemon never dials on an answer that does not echo the ticket it
        /// presented (P3-8-2b). Absent from every other answer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ssh_ticket_id: Option<String>,
    },

    /// Answer to a device-originated [`ClientMsg::RpcExecRequest`] — the
    /// `roomler exec` CLI leg. Carries the same payload the HTTP caller would
    /// have received, plus `error` for a gate refusal the server itself made.
    #[serde(rename = "rc:rpc.response")]
    RpcExecResponse {
        request_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        stdout: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        stderr: String,
        #[serde(default)]
        truncated: bool,
        #[serde(default)]
        duration_ms: u64,
        /// Set when the command never ran (gate refusal, offline, timeout).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },

    // ─── server → tunnel-client / agent (rc:tunnel.*) ────────────────
    /// Server → client: peer-channel is up. `dc_pool_size` confirms
    /// the negotiated DC pool size (8 in v1) so the client knows
    /// which `dc_index` values are valid. `sctp_rwnd_bytes` reports
    /// the advertised SCTP receive window for diagnostics — useful
    /// when verifying the vendored `webrtc-0.12.0` patch took effect
    /// at runtime (default upstream = 1 MiB, tuned native↔native =
    /// 8 MiB).
    #[serde(rename = "rc:tunnel.opened")]
    TunnelOpened {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        transport: String,
        dc_pool_size: u8,
        sctp_rwnd_bytes: u32,
        ice_servers: Vec<IceServer>,
        /// Short-lived token the client presents on the QUIC connection
        /// so the agent's quinn endpoint can authorize the dialer (the
        /// server is no longer in the byte path for QUIC). `None` for
        /// `webrtc-dc-v1` sessions. Minted by the server, bound to the
        /// `session_id` + agent. Wired in Phase 1c/1d.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        quic_auth_token: Option<String>,
        /// Correlation id echoed from the originating `TunnelOpen`, so a
        /// daemon multiplexing N opens over one WS can match THIS
        /// `TunnelOpened` to the pending open that caused it. `None`
        /// (omitted) for the single-open CLI and for pre-P3b-2 servers.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        open_nonce: Option<String>,
        /// FR-90 P3-7-2a — the id of the grant (`ClientMsg::TunnelOpen::net_grant`)
        /// this server bound to the tunnel: its flows are the SESSION's.
        /// Absent when none was sent, and from every server before P3-7-2a,
        /// which ignores a grant. A device that sent a grant and finds no echo
        /// must not carry the session's flows over this tunnel.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        net_grant_id: Option<String>,
    },

    /// Server → agent: a tunnel-client wants to open this TCP
    /// forward; the server has already passed the cross-tenant gate
    /// and the tenant policy. Agent dials and replies with
    /// `TcpForwardAccept` or `TcpForwardReject`. Distinct
    /// discriminator from the client-side `rc:tunnel.tcp.request` —
    /// makes the agent handler's match exhaustive without ambiguity.
    #[serde(rename = "rc:tunnel.tcp.forward")]
    TcpForwardForward {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        dst_host: String,
        dst_port: u16,
        /// User on whose behalf the forward is being opened. Recorded
        /// in `tunnel_audit` rows from the agent side too.
        #[serde(with = "oid_hex")]
        owner_user_id: ObjectId,
    },

    /// Server → client: relays the agent's `TcpForwardAccept`.
    #[serde(rename = "rc:tunnel.tcp.accept")]
    TcpForwardAccept {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        dc_index: u8,
    },

    /// Server → client: either relays the agent's reject OR
    /// synthesises one from the server-side ACL gate.
    #[serde(rename = "rc:tunnel.tcp.reject")]
    TcpForwardReject {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        kind: RejectKind,
        reason: String,
    },

    /// Server → peer: relays a half-close from the other side.
    #[serde(rename = "rc:tunnel.tcp.half_close")]
    TcpHalfClose {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        direction: Direction,
    },

    /// Server → peer: relays a flow close.
    #[serde(rename = "rc:tunnel.tcp.closed")]
    TcpClosed {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        reason: CloseReason,
    },

    /// Server → agent: a tunnel-client wants to open this UDP forward;
    /// the server has already passed the cross-tenant gate + the tenant
    /// policy (evaluated with `proto = udp`). Mirrors
    /// [`TcpForwardForward`]. Agent binds a UDP socket + replies with
    /// `UdpForwardAccept` / `UdpForwardReject`.
    #[serde(rename = "rc:tunnel.udp.forward")]
    UdpForwardForward {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        dst_host: String,
        dst_port: u16,
        #[serde(with = "oid_hex")]
        owner_user_id: ObjectId,
    },

    /// Server → client: relays the agent's `UdpForwardAccept`.
    #[serde(rename = "rc:tunnel.udp.accept")]
    UdpForwardAccept {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        dc_index: u8,
    },

    /// Server → client: relays the agent's reject OR synthesises one
    /// from the server-side ACL gate.
    #[serde(rename = "rc:tunnel.udp.reject")]
    UdpForwardReject {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        kind: RejectKind,
        reason: String,
    },

    /// Server → peer: relays a UDP flow close.
    #[serde(rename = "rc:tunnel.udp.closed")]
    UdpClosed {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        flow_id: u32,
        reason: CloseReason,
    },

    /// Server → either peer: the whole peer is being torn down.
    /// Carries the same `CloseReason` taxonomy as flow close.
    #[serde(rename = "rc:tunnel.terminate")]
    TunnelTerminate {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        reason: CloseReason,
    },

    /// Server → client: status changed mid-session (admin set
    /// `Quarantined`, soft-deleted the row, etc.). The WS will be
    /// closed immediately after. Mirrors the T1 stub frame the
    /// revocation re-check task already emits in `ws/tunnel.rs`.
    #[serde(rename = "rc:tunnel.revoked")]
    TunnelRevoked { reason: String },

    /// Server → agent: relays a tunnel-client's SDP offer. Distinct
    /// discriminator from `rc:sdp.offer` so the agent doesn't
    /// confuse this with a remote-control session offer.
    #[serde(rename = "rc:tunnel.sdp.offer")]
    TunnelSdpOffer {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shared_lease: Option<SharedSessionLease>,
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        sdp: String,
    },

    /// Server → tunnel-client: relays the agent's SDP answer.
    #[serde(rename = "rc:tunnel.sdp.answer")]
    TunnelSdpAnswer {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        sdp: String,
    },

    /// Server → either peer: relays a tunnel ICE candidate. Mirror of
    /// `ClientMsg::TunnelIce`.
    #[serde(rename = "rc:tunnel.ice")]
    TunnelIce {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        candidate: serde_json::Value,
    },

    /// Server → agent: prepare a QUIC server endpoint for this session
    /// and authorize the client that presents `quic_auth_token`. The
    /// agent's trigger to mint its ephemeral cert + bind a quinn
    /// endpoint, then reply with `ClientMsg::TunnelQuicReady`. The QUIC
    /// analogue of the server relaying an SDP offer to the agent.
    #[serde(rename = "rc:tunnel.quic.setup")]
    TunnelQuicSetup {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        quic_auth_token: String,
        /// Short-lived coturn ICE/TURN credentials the AGENT uses to
        /// allocate its own relay for QUIC-over-TURN (Tier 2/3). Empty
        /// for direct-only sessions and from pre-3c servers (hence
        /// `#[serde(default)]` — an older agent simply ignores the field
        /// and a newer agent treats its absence as "no relay creds, go
        /// direct"). Phase 3c.
        #[serde(default)]
        ice_servers: Vec<IceServer>,
        /// R4: the negotiated transport flavor when it is NOT the default
        /// QUIC-over-TURN path — today only `quic-derp-v1`. A pre-R4 agent
        /// never receives it (the server version-gates the flavor), and a
        /// pre-R4 SERVER omits it, which a new agent reads as the classic
        /// TURN/direct path. Absent ⇒ omitted on the wire.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transport: Option<String>,
        /// R4 (`quic-derp-v1`): the CLIENT's overlay/DERP pubkey (64 hex),
        /// copied verbatim from `TunnelOpen.derp_pubkey` — the peer the
        /// agent's DERP-backed QUIC endpoint serves.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_derp_pubkey: Option<String>,
    },

    /// Server → tunnel-client: relays the agent's `TunnelQuicReady`
    /// (cert fingerprint to pin + dialable addrs). Mirror of
    /// `ClientMsg::TunnelQuicReady`.
    #[serde(rename = "rc:tunnel.quic.ready")]
    TunnelQuicReady {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        cert_fingerprint: String,
        addrs: Vec<String>,
        /// R4 — see `ClientMsg::TunnelQuicReady::derp_pubkey` (relayed
        /// verbatim).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        derp_pubkey: Option<String>,
    },

    /// Server → agent: relays the tunnel-client's `TunnelQuicCandidate`
    /// (the client's relay address the agent must permit before the
    /// handshake). Mirror of `ClientMsg::TunnelQuicCandidate`. Phase 3c.
    #[serde(rename = "rc:tunnel.quic.candidate")]
    TunnelQuicCandidate {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        addrs: Vec<String>,
    },

    // ─── server → overlay node (rc:overlay.*) ────────────────────────
    /// Full network map sent to a node on join. Carries the node's own
    /// `self_ip`, the network parameters, and every peer it may reach.
    /// `epoch` monotonically increases per network so a node can detect
    /// a missed delta and (in a later phase) request a resync.
    #[serde(rename = "rc:overlay.netmap")]
    OverlayNetmap {
        /// Explicit server support. An older server omits this, so a new
        /// client must not send discovery requests until a full map says true.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        org_relay_discovery: bool,
        /// Only explicitly capable servers may receive new trial requests.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        path_trial_v1: bool,
        self_ip: String,
        network: OverlayNetworkInfo,
        peers: Vec<NetmapPeer>,
        /// ⚠️ `#[serde(default)]` because this field is REQUIRED to decode the
        /// frame and is read by NOBODY. The agent destructures
        /// `{ self_ip, network, peers, .. }` and discards it; the resync it was
        /// added for was never built.
        ///
        /// Without the default, a netmap that omitted `epoch` — a rolled-back
        /// server, or any future sender that forgets it — fails the whole
        /// `ServerMsg` parse and the node gets NO address and NO peers. A field
        /// no consumer reads must not be able to destroy the frame carrying it.
        #[serde(default)]
        epoch: u64,
    },

    /// Incremental netmap update: peers to add/update and node_ids to
    /// remove. Pushed on join/leave/endpoint-change (and, later,
    /// ACL-change/rekey).
    #[serde(rename = "rc:overlay.netmap_delta")]
    OverlayNetmapDelta {
        /// Defaulted for the same reason as [`ServerMsg::OverlayNetmap`]'s: the
        /// agent reads `{ upserts, removes, .. }` and never this. A delta lost
        /// to a missing `epoch` silently strands a peer add or, worse, a peer
        /// REMOVAL — leaving a node routing to an address that has been
        /// recycled to someone else.
        #[serde(default)]
        epoch: u64,
        #[serde(default)]
        upserts: Vec<NetmapPeer>,
        #[serde(default, with = "vec_oid_hex")]
        removes: Vec<ObjectId>,
    },

    /// On-demand coturn credentials for a relay leg to a specific peer.
    /// `pair_key = sorted(node_a_hex, node_b_hex)` so both ends derive
    /// identical short-lived creds (same-worker hairpin), exactly like
    /// the QUIC tunnel's per-session creds.
    #[serde(rename = "rc:overlay.relay_grant")]
    OverlayRelayGrant {
        ice_servers: Vec<IceServer>,
        #[serde(with = "oid_hex")]
        peer_node_id: ObjectId,
        pair_key: String,
    },

    /// C4 stage 1 — reply to `rc:overlay.warm_relay_request`: ephemeral
    /// coturn creds keyed by the requesting node itself (no pair). The
    /// agent allocates over TURN/UDP and keeps the allocation alive; cred
    /// expiry is derivable client-side from the ephemeral username's
    /// timestamp prefix. Only ever sent in reply, never pushed — that is
    /// what exempts it from the hello-capability-flag rule.
    #[serde(rename = "rc:overlay.warm_relay_grant")]
    OverlayWarmRelayGrant { ice_servers: Vec<IceServer> },

    /// P7 (corp-DERP fallback) — the server observed sustained TURN-relay
    /// churn for this pair (repeated grant→re-request cycles: a corp
    /// middlebox RST-ing the TURNS/TCP control socket kills every
    /// allocation) and escalates it to the DERP carrier. Pushed to **BOTH**
    /// ends of the pair — this must NOT ride the relay grant, because the
    /// single-relay DIALER never sends a `relay_request` and so never sees a
    /// grant. Each end pins the pair to `RelayStrategy::Derp` for `ttl_ms`;
    /// the pin governs (re)establishment only — an already-healthy carrier
    /// is left alone, and LAN/direct upgrades keep working (DERP is a
    /// fallback tier, not a destination). Only sent when BOTH ends
    /// advertised `supports_forced_derp` + `supports_derp`, so a mixed-
    /// version pair can never split tiers.
    #[serde(rename = "rc:overlay.force_derp")]
    OverlayForceDerp {
        #[serde(with = "oid_hex")]
        peer_node_id: ObjectId,
        /// How long the pin lasts, in ms (server-side TTL mirrored so both
        /// ends expire together).
        ttl_ms: u64,
        /// Multi-region DERP: the REGIONAL relay both ends must dial for this
        /// pair (server-computed from the pair's relay homes, pushed
        /// identically to both — symmetric by construction). Absent/`None` =
        /// the central `/derp`. `#[serde(default)]` for pre-region agents.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        derp_url: Option<String>,
    },

    /// Dedicated candidate authority. Legacy org-relay sessions are untouched.
    #[serde(rename = "rc:overlay.path_trial_start")]
    OverlayPathTrialStart {
        #[serde(with = "oid_hex")]
        trial_id: ObjectId,
        request_id: u64,
        #[serde(with = "oid_hex")]
        peer_node_id: ObjectId,
        peer_wg_public_key: String,
        vni: u32,
        generation: u64,
        #[serde(with = "oid_hex")]
        relay_node_id: ObjectId,
        relay_endpoints: Vec<String>,
        bind_secret: String,
        bind_secs: u32,
        max_lifetime_secs: u32,
    },
    #[serde(rename = "rc:overlay.path_trial_commit")]
    OverlayPathTrialCommit {
        #[serde(with = "oid_hex")]
        trial_id: ObjectId,
    },
    #[serde(rename = "rc:overlay.path_trial_finalize")]
    OverlayPathTrialFinalize {
        #[serde(with = "oid_hex")]
        trial_id: ObjectId,
    },
    #[serde(rename = "rc:overlay.path_trial_abort")]
    OverlayPathTrialAbort {
        #[serde(with = "oid_hex")]
        trial_id: ObjectId,
    },
    #[serde(rename = "rc:overlay.path_trial_return_prepare")]
    OverlayPathTrialReturnPrepare {
        #[serde(with = "oid_hex")]
        trial_id: ObjectId,
        #[serde(with = "oid_hex")]
        return_id: ObjectId,
    },
    #[serde(rename = "rc:overlay.path_trial_return_commit")]
    OverlayPathTrialReturnCommit {
        #[serde(with = "oid_hex")]
        trial_id: ObjectId,
        #[serde(with = "oid_hex")]
        return_id: ObjectId,
    },
    #[serde(rename = "rc:overlay.path_trial_return_finalize")]
    OverlayPathTrialReturnFinalize {
        #[serde(with = "oid_hex")]
        trial_id: ObjectId,
        #[serde(with = "oid_hex")]
        return_id: ObjectId,
    },
    #[serde(rename = "rc:overlay.path_trial_return_abort")]
    OverlayPathTrialReturnAbort {
        #[serde(with = "oid_hex")]
        trial_id: ObjectId,
        #[serde(with = "oid_hex")]
        return_id: ObjectId,
    },

    /// Pair-specific discovery metadata, sent only to the requester. No bind
    /// secret or session authority. Empty/TTL zero clears a cached result;
    /// expiry is relative to receipt and must not be extended by cache reads.
    #[serde(rename = "rc:overlay.org_relay_candidates")]
    OverlayOrgRelayCandidates {
        #[serde(with = "oid_hex")]
        peer_node_id: ObjectId,
        request_id: u64,
        candidates: Vec<OrgRelayCandidateWire>,
        ttl_secs: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next_cursor: Option<OrgRelayDiscoveryCursorWire>,
    },

    /// FR-19 — a minted org-relay session, pushed to each MEMBER of the pair.
    /// Only ever sent to a node that advertised `supports_org_relay` on join.
    /// The `bind_secret` is per-(session, member): possession of it is what
    /// "this is the node the session was minted for" means at the relay.
    #[serde(rename = "rc:overlay.relay_session")]
    OverlayRelaySession {
        /// 24-bit session id, unique per relay node.
        vni: u32,
        /// Re-mint counter for this (pair, relay); covered by the bind MAC.
        generation: u64,
        #[serde(with = "oid_hex")]
        peer_node_id: ObjectId,
        #[serde(with = "oid_hex")]
        relay_node_id: ObjectId,
        /// The relay's reachable `ip:port`s, measured + static. Try in order.
        relay_endpoints: Vec<String>,
        /// This member's bind secret, base64 (32 bytes).
        bind_secret: String,
        /// Seconds the relay allows to complete the bind; the agent re-clamps
        /// against its own clock (server timestamps only ever shorten).
        bind_secs: u32,
        /// Absolute session lifetime in seconds, independent of traffic.
        max_lifetime_secs: u32,
    },

    /// FR-19 — the same session, pushed to the RELAY node with BOTH members'
    /// secrets so it can verify either party's bind. Only ever sent to a node
    /// whose hello advertised the `relay-server` verb.
    #[serde(rename = "rc:overlay.relay_bridge_serve")]
    OverlayRelayBridgeServe { bridge: RelayBridgeWire },
    #[serde(rename = "rc:overlay.relay_bridge_revoke")]
    OverlayRelayBridgeRevoke {
        #[serde(with = "oid_hex")]
        trial_id: ObjectId,
        generation: u64,
    },
    #[serde(rename = "rc:overlay.relay_serve")]
    OverlayRelayServe {
        vni: u32,
        generation: u64,
        /// The two members. Exactly two — a relay session is a pair.
        members: Vec<RelayMemberWire>,
        bind_secs: u32,
        idle_secs: u32,
        max_lifetime_secs: u32,
    },

    /// FR-19 — revoke a session immediately, on relay AND members. Pushed on
    /// org mode-off, ACL revoke, policy revoke and device removal. Revocation
    /// is a push rather than an expiry because a session's idle deadline is
    /// refreshed by traffic and never fires under a WireGuard keepalive.
    #[serde(rename = "rc:overlay.relay_revoke")]
    OverlayRelayRevoke { vni: u32 },

    /// FR-47 — the join could not be completed, and this says why.
    ///
    /// Before this frame a join that failed IPAM was a server-side `warn!` and
    /// nothing else: the node sat waiting for a netmap that would never come,
    /// so a device that could not be given an address looked exactly like one
    /// that was merely offline — to the operator as much as to the daemon.
    ///
    /// Hello-gated on `supports_join_refusal`, following the
    /// [`ServerMsg::RelayRegions`] convention: a fielded agent's `ServerMsg`
    /// deserializer errors on an unknown variant, and while that error is
    /// absorbed harmlessly (`pre_rc53_server_msg_rejects_goodbye_so_agent_err_arm_fires`
    /// locks it), a frame nobody can read is not worth sending. Pre-FR-47
    /// nodes keep exactly today's behaviour, and the server-side ERROR log
    /// remains their signal.
    #[serde(rename = "rc:overlay.join_refused")]
    OverlayJoinRefused {
        reason: OverlayJoinRefusal,
        /// Operator-facing detail. Safe to log; never contains another
        /// tenant's identifiers.
        detail: String,
    },

    /// Multi-region relay PoPs: the probe-target list the server pushes to a
    /// node that advertised `supports_relay_regions` (hello-gated — the agent's
    /// `ServerMsg` deserializer errors on unknown variants, so this is NEVER
    /// sent to a node that didn't advertise the capability). The node times a
    /// STUN binding against each region's `stun` target and reports back via
    /// [`ClientMsg::RelayProbeReport`]; the resulting `relay_home` drives every
    /// per-session/per-pair TURN region pick. Re-pushed with a new `rev` when
    /// the region set changes; same `rev` ⇒ the node may skip re-probing early.
    #[serde(rename = "rc:relay.regions")]
    RelayRegions {
        regions: Vec<RelayRegionInfo>,
        /// Stable hash of the region list — change detection for re-probes.
        rev: u64,
    },

    /// Multi-region DERP: the admission ticket for the regional relays, in
    /// reply to [`ClientMsg::DerpTicketRequest`] (never unsolicited — reply-
    /// only makes it capability-safe for old agents). `exp` is unix seconds;
    /// the agent re-requests at ~90 % of the TTL.
    #[serde(rename = "rc:relay.derp_ticket")]
    DerpTicket { ticket: String, exp: u64 },

    // ── FR-52 P3 — external access (`rc:extauth.*`) ──────────────────────
    /// FR-52 P3 — server → device: an outsider's KE1, relayed.
    ///
    /// `principal` is the controller's user id, as the SERVER knows it. The
    /// device binds it into the key a verified login leaves behind, so a server
    /// that names the wrong principal produces a key the real controller does
    /// not share, and the session that key must authenticate fails closed.
    ///
    /// ⚠️ Honoured only on the PRIMARY org's socket: the password is the
    /// device owner's, and a secondary org must not be able to point outsiders
    /// at it (FR-19's rule for host-global resources).
    #[serde(rename = "rc:extauth.ke1")]
    ExtauthKe1 {
        attempt_id: String,
        principal: String,
        ke1: String,
    },
    /// FR-52 P3 — server → device: the controller's KE3 for `attempt_id`.
    #[serde(rename = "rc:extauth.ke3")]
    ExtauthKe3 {
        attempt_id: String,
        principal: String,
        ke3: String,
    },
    /// FR-52 P3 — server → controller: the device's KE2, relayed. The browser
    /// opens it; a wrong password is detected THERE, and a well-behaved client
    /// then simply stops.
    #[serde(rename = "rc:extauth.challenge")]
    ExtauthChallenge { attempt_id: String, ke2: String },
    /// FR-52 P3 — server → controller: the end of a login. `refused` absent =
    /// the device verified the login. `attempt_id` is absent when the refusal
    /// came before one was allocated (an unresolvable connect code, a server
    /// rate limit).
    ///
    /// A distinct tag from the device's `rc:extauth.outcome`, so a log line or
    /// a frame dump is never ambiguous about which hop it came from.
    #[serde(rename = "rc:extauth.result")]
    ExtauthResult {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attempt_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        refused: Option<crate::models::ExtauthRefusal>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_secs: Option<u32>,
        /// FR-115 P3b — words for the person, with `session_limit`: whose
        /// session holds the slot. Absent on every other refusal.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },

    // ─── Hive (rc:hive.*) — FR-90 ─────────────────────────────────────
    /// Start (or resume) one agent session on this device, and answer with
    /// [`ClientMsg::HiveStartAck`].
    ///
    /// The server has cleared its gates before this is sent: the module is
    /// on, the starter holds `HIVE_RUN`, the device is in the starter's org,
    /// the per-(user, device) ceiling. The device then applies its own, which
    /// survive a compromised server: `hive_enabled`, the account
    /// `hive_accounts` maps the starter to (never SYSTEM/root, never an
    /// account the server names — this frame carries none), and the folder
    /// confined to `hive_roots`.
    ///
    /// ⚠️ Metadata only. No prompt, no context, no secret: the first prompt
    /// reaches the harness over the viewer peer, and the field set is locked
    /// by test so this frame cannot grow one.
    ///
    /// ⚠️ Gate on [`crate::models::RpcCap::Hive`] — a caller waits for the
    /// answer, so it is never sent blind.
    ///
    /// ⚠️ IDEMPOTENT on `session_id` + `fence`, and a device must keep it so:
    /// a start whose answer was lost is sent again when the device reconnects
    /// (reconcile-on-connect), so a device already running that session at
    /// that fence answers `accepted` again and launches nothing.
    #[serde(rename = "rc:hive.start")]
    HiveStart {
        /// The server's record of the session (`agent_sessions._id`).
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        /// Which harness to run — [`crate::hive::HARNESS_CLAUDE_CODE`] in P0.
        harness: String,
        /// The harness's OWN session id (a UUID), server-minted so every
        /// replica resumes the same conversation: `--session-id` on a first
        /// start, `--resume` when `resume` is set.
        harness_session: String,
        /// The lease fence this start runs under. The device writes it into
        /// every transcript event and refuses work from an older one.
        fence: u64,
        /// The folder as the starter typed it. The device resolves it as the
        /// mapped account and refuses anything outside `hive_roots`.
        folder: String,
        /// Who is starting it — the key the device's `hive_accounts` maps
        /// through (by id or by the proven address below).
        #[serde(with = "oid_hex")]
        user_id: ObjectId,
        /// The starter's address, only if their account PROVED it — otherwise
        /// the `.invalid` placeholder `users.email` holds, which no
        /// `hive_accounts` entry should ever match.
        user_email: String,
        /// Display name — written to the device's log, so the person at the
        /// device can see who started what.
        caller: String,
        /// `true` = resume the harness session (`--resume`); `false` = a
        /// first start (`--session-id`).
        resume: bool,
        /// FR-90 P2c-3 — the session has members besides this device: take
        /// a checkpoint at each turn's end (P2b-3b), so a member can hold a
        /// copy it could resume. Absent, as from every server before it: no
        /// member, no checkpoint. A device that predates it ignores it, and
        /// its members then hold no checkpoint.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        replicated: bool,
        /// FR-90 P2e-2 — the session is leased: after a restart or a
        /// reconnect the device runs it, and lets it call the model, only
        /// once the server has said on THAT connection that it still holds it
        /// ([`ServerMsg::HiveLease`]). The start is that word for its own
        /// connection. Sent only to a connection advertising
        /// [`crate::models::RpcCap::HiveLease`], for a session the record
        /// holds as replicated; absent, the device keeps P1's behaviour.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        lease: bool,
        /// FR-90 P2f-3 — the session is a fork of this one: carried by every
        /// start of the fork, its first (which the device takes from the
        /// parent's copy and launches `--resume <parent> --fork-session`) and
        /// every later one (whose checkpoints keep the parent's files the
        /// fork resumed from). Sent only to a connection advertising
        /// [`crate::models::RpcCap::HiveFork`]: a device before it would
        /// start the fork empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fork_of: Option<crate::hive::HiveForkOf>,
        /// FR-90 P2f-4 — the session is a terminal session this device
        /// adopted, whose terminal ended here, made a managed one: at its
        /// first start the device puts the terminal's own history in place
        /// as the account it ran as, and resumes it. Carried by every start
        /// the device has not answered yet. Sent only to a connection
        /// advertising [`crate::models::RpcCap::HiveManage`]: a device before
        /// it would start the conversation afresh. Absent when false, so
        /// every other start is the frame it was.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        from_terminal: bool,
    },

    /// FR-90 P2c-3 — hold a copy of a session: placement chose this device
    /// as a member. Answered by [`ClientMsg::HiveReplicaJoinAck`]. Pushed only
    /// to a connection advertising `hive-replica`, and re-sent on every
    /// connection until it is answered.
    ///
    /// P2c-4 — with `role: primary`, to the device that runs the session, on
    /// a connection that runs Hive: the session has members now, so it
    /// checkpoints. Re-sent on every such connection until it is answered
    /// `joined`.
    ///
    /// ⚠️ It carries no content and opens nothing: the copy arrives over the
    /// carrier (P2d), from a source the server grants then.
    #[serde(rename = "rc:hive.replica.join")]
    HiveReplicaJoin {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        /// The session's fence: the device's floor for it rises to this
        /// before it holds anything of it.
        fence: u64,
        /// Why it holds a copy. `None` on the device = a role this build
        /// cannot name, decoded leniently: it refuses (`other`).
        #[serde(default, deserialize_with = "crate::hive::replica_role_lenient")]
        role: Option<crate::hive::HiveReplicaRole>,
        /// FR-90 P2e-5b — where each fence a promotion superseded ended, the
        /// record's `fences`: below its floor, the copy still takes each such
        /// fence's events up to its mark, so a member that joins after a move,
        /// or was behind at it, syncs the whole history. At most
        /// [`crate::hive::replica_limits::MAX_FENCE_MARKS`]; an older daemon
        /// ignores it.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        fences: Vec<crate::hive::HiveFenceMark>,
    },

    /// FR-90 P2d — serve a stream of a session this device holds to one of
    /// its members: stand up a QUIC endpoint on `path`, authorize only the
    /// member presenting `token`, and answer [`ClientMsg::HiveReplicaReady`].
    /// Pushed only to a connection advertising `hive-stream`.
    ///
    /// ⚠️ It opens nothing by itself: the member dials only once the source
    /// said ready (FR-83), and the endpoint serves the one member the token
    /// names, for `ttl_secs`.
    #[serde(rename = "rc:hive.replica.grant")]
    HiveReplicaGrant {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        fence: u64,
        /// The member the stream is for.
        #[serde(with = "oid_hex")]
        member_id: ObjectId,
        /// The rung. `None` on the device = a rung this build cannot name:
        /// it refuses (`path_unavailable`).
        #[serde(default, deserialize_with = "crate::hive::stream_path_lenient")]
        path: Option<crate::hive::HiveStreamPath>,
        /// What the member presents once connected: minted per grant,
        /// unguessable.
        token: String,
        /// STUN, and on `relay` TURN, credentials minted for this grant.
        #[serde(default)]
        ice_servers: Vec<IceServer>,
        /// The grant's life from receipt.
        ttl_secs: u32,
        /// The member's WireGuard key, on the `derp` rung.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        member_derp_pubkey: Option<String>,
    },

    /// FR-90 P2d — the source is ready: dial it on `path`, pinning
    /// `cert_fingerprint`, and present `token`. Sent only after the source's
    /// `ready` (FR-83).
    #[serde(rename = "rc:hive.replica.dial")]
    HiveReplicaDial {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        fence: u64,
        /// The device that serves the stream.
        #[serde(with = "oid_hex")]
        source_id: ObjectId,
        #[serde(default, deserialize_with = "crate::hive::stream_path_lenient")]
        path: Option<crate::hive::HiveStreamPath>,
        token: String,
        /// The SHA-256 the source's certificate must have.
        cert_fingerprint: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        addrs: Vec<String>,
        /// The source's WireGuard key, on the `derp` rung.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        derp_pubkey: Option<String>,
        #[serde(default)]
        ice_servers: Vec<IceServer>,
        ttl_secs: u32,
    },

    /// FR-90 P2d — the member's relayed address, relayed to the source to
    /// permit (mirror of [`ClientMsg::HiveReplicaCandidate`]).
    #[serde(rename = "rc:hive.replica.candidate")]
    HiveReplicaCandidate {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        addr: String,
    },

    /// FR-90 P2d — no stream this time: the server's word, or the source's.
    /// The member asks again later, or on the next rung.
    #[serde(rename = "rc:hive.replica.refused")]
    HiveReplicaRefused {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        fence: u64,
        /// The rung that was asked for, as named in the want.
        #[serde(default, deserialize_with = "crate::hive::stream_path_lenient")]
        path: Option<crate::hive::HiveStreamPath>,
        /// Decoded leniently: an unknown word is still a refusal.
        #[serde(default, deserialize_with = "crate::hive::stream_refusal_lenient")]
        reason: Option<crate::hive::HiveStreamRefusal>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },

    /// FR-90 P2d — a stream is over: the grant was revoked (a member that
    /// left, a device removed), or the other side closed it.
    #[serde(rename = "rc:hive.replica.close")]
    HiveReplicaClose {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        reason: String,
    },

    /// Stop a session: interrupt any running turn, let the harness exit, and
    /// report `ended` through [`ClientMsg::HiveState`]. Idempotent — a stop
    /// for a session the device does not run is answered `ended` too.
    #[serde(rename = "rc:hive.stop")]
    HiveStop {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        /// The fence the stop applies to; a device holding a NEWER fence for
        /// this session ignores it (the session moved on).
        fence: u64,
        /// Why, in a word, for the device's log: `owner`, `member_removed`,
        /// `device_removed`, `tenant_archived`.
        #[serde(default)]
        reason: String,
    },

    /// FR-90 P2e-2 — the server's word that this device holds the session at
    /// `fence`, said on THIS connection: a leased run here may call the
    /// model again after a reconnect, and a leased session it hosted
    /// launches after a restart. A word on an older connection counts for
    /// nothing once a newer one is up, so it is said again on every
    /// connection, in answer to the device's manifest. The first word for a
    /// session also makes it leased from then on, as a start's `lease` does.
    /// Pushed only to a connection advertising
    /// [`crate::models::RpcCap::HiveLease`]; nothing answers it.
    #[serde(rename = "rc:hive.lease")]
    HiveLease {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        fence: u64,
    },

    /// FR-90 P2e-1 — this device no longer holds the session: its lease is
    /// at `fence` now, on another device. A run of it here at an OLDER fence
    /// ends: its model calls, prompts and approval answers at once, its
    /// harness as a stop ends it. The device's fence floor for the session
    /// rises to `fence`, so what that run still writes is refused there as
    /// on every member, and what the device hosts forgets the session, so no
    /// restart resumes it. A run at `fence` or newer is not this frame's: the
    /// session came back. Whether the device then holds a copy is its own
    /// `hive_replica` and the server's join. Nothing answers it: the run's
    /// `ended` goes at its own, older fence, which the server ignores.
    #[serde(rename = "rc:hive.demote")]
    HiveDemote {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        /// The fence the session's lease is at now.
        fence: u64,
        /// Why, in a word, for the device's log: `not_location` (it reported
        /// a session held elsewhere), `promoted` (it moved to another device).
        #[serde(default)]
        reason: String,
    },

    /// FR-90 P2g — purge the session from this device: a run of it here
    /// stops first; then the daemon's own copy goes (its events, index,
    /// tips, blobs and membership, its runtime directory, what the device
    /// hosts and adopts of it), and, as the session's account, its state
    /// directory and the refs and index its checkpoints left in the folder's
    /// repository: never the person's working tree. What is deleted is this
    /// device's own record of the session, never this frame's word. The
    /// device keeps the session's id and refuses any join, start or event for
    /// it afterwards, unless `leaving` says this was its copy alone.
    /// Answered [`ClientMsg::HivePurgeAck`], per part; idempotent by
    /// `purge_id`, so a re-send after a failed part retries it. Pushed only
    /// to a connection advertising [`crate::models::RpcCap::HivePurge`].
    ///
    /// ⚠️ Metadata only, and the field set is locked by test.
    #[serde(rename = "rc:hive.purge")]
    HivePurge {
        #[serde(with = "oid_hex")]
        purge_id: ObjectId,
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        /// FR-90 P2k-3 — this device's copy alone, as a member that leaves
        /// (P2g-4b): purged as any purge is, but its removal is not final
        /// there, so placement may choose the device again and a teleport may
        /// land on it. Absent on a whole session's purge, so that wire is as
        /// before; a device before P2k-3 ignores the word and keeps every
        /// removal final, as it did.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        leaving: bool,
    },

    /// FR-90 P2g-4a — this device's enrollment is being removed from the
    /// organization: purge every session it holds, each as
    /// [`Self::HivePurge`] would, a run stopped first. Pushed by the removal
    /// while the device's socket is still up, best effort: nothing answers
    /// it, its credentials are revoked right after, and a device offline at
    /// its removal keeps what it held (until P7). A device holds copies for
    /// its primary organization only, so a secondary organization's
    /// connection ignores it, as it does every Hive frame. Pushed only to a
    /// connection advertising [`crate::models::RpcCap::HivePurgeAll`]: a
    /// build that purges a session but predates this frame cannot decode it.
    ///
    /// ⚠️ An id only, for the logs; the field set is locked by test.
    #[serde(rename = "rc:hive.purge_all")]
    HivePurgeAll {
        #[serde(with = "oid_hex")]
        purge_id: ObjectId,
    },

    /// FR-90 P2g-3c — the answer to [`ClientMsg::HiveRetainAsk`], on the
    /// connection that asked: for each session asked about whose record names
    /// this device, what keeps its copy ([`crate::hive::HiveRetainWord`]).
    /// A session it says nothing of keeps the device's last word, or none: a
    /// server's silence never deletes. Only a build that asks receives it, so
    /// no capability word gates it.
    ///
    /// ⚠️ Numbers only, and the field set is locked by test.
    #[serde(rename = "rc:hive.retain")]
    HiveRetain {
        #[serde(default)]
        words: Vec<crate::hive::HiveRetainWord>,
    },

    /// FR-90 P2e-3 — a promotion's first step, to the member the session
    /// moves to: apply every start gate, as the device is configured now, and
    /// answer [`ClientMsg::HivePrepareAck`]. Nothing launches and nothing
    /// moves: the lease is still on the primary, and the start comes later,
    /// at `fence`, once this member's copy holds what the primary drained.
    /// The prepare holds nothing on the device beyond its answer. Pushed only
    /// to a connection advertising [`crate::models::RpcCap::HivePromote`].
    ///
    /// FR-90 P2f-1a — `teleport`: the device holds no copy yet, and takes one
    /// after this (a join in [`crate::hive::HiveReplicaRole::Teleport`]).
    /// Every start gate but the copy is applied, and a device that passes
    /// them admits that one session's teleport join, whatever its own
    /// `hive_replica`. Pushed only to a connection advertising
    /// [`crate::models::RpcCap::HiveTeleport`].
    ///
    /// ⚠️ Metadata only, as [`Self::HiveStart`]: the field set is locked by
    /// test.
    #[serde(rename = "rc:hive.prepare")]
    HivePrepare {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        /// The fence the start will carry: the session's current one, plus
        /// one.
        fence: u64,
        harness: String,
        harness_session: String,
        /// The folder the session will run in, as the owner typed it or as
        /// the record holds it.
        folder: String,
        /// The session's owner, the person it will run for: the key the
        /// device's `hive_accounts` maps through.
        #[serde(with = "oid_hex")]
        user_id: ObjectId,
        /// The owner's address, only if their account proved it, as
        /// [`Self::HiveStart`] carries it.
        user_email: String,
        /// Display name, for the device's log.
        caller: String,
        /// P2f-1a — a teleport's prepare: the device holds no copy yet.
        /// Absent = a promotion's, to a member that holds one (every prepare
        /// before P2f-1a).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        teleport: bool,
        /// P2f-2b — a teleport's target may take the workspace's first pack
        /// as one thin against what its folder's repository holds already
        /// (git's have and want; FR-90 decision 16). Absent = it takes the
        /// whole pack, as every target before P2f-2b did.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        have_want: bool,
    },

    /// FR-90 P2e-3 — the session's lease is about to leave this device, its
    /// primary: take no new prompt, let the running turn end (cut it
    /// [`crate::hive::promote_limits::DRAIN_TURN_CUT_SECS`] after this
    /// frame), withdraw the open approvals, take a last checkpoint, and answer
    /// [`ClientMsg::HiveDrained`] with the tip the copy then ends at. A later
    /// [`Self::HiveLease`] at the same fence lifts the drain: the lease
    /// stayed. [`Self::HiveDemote`] ends the run: it moved. Pushed only to a
    /// connection advertising [`crate::models::RpcCap::HivePromote`].
    #[serde(rename = "rc:hive.drain")]
    HiveDrain {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        /// The fence the device runs the session at.
        fence: u64,
    },

    /// FR-90 P2e-3 — the record's word for the run that starts at `fence`,
    /// sent immediately before that run's [`Self::HiveStart`]: how many turns
    /// the session has had, where it ran before, and who moved it, when. The
    /// device counts turns on from `turns`, and composes its resume note
    /// from the rest (P2e-7). Pushed only to a connection advertising
    /// [`crate::models::RpcCap::HivePromote`].
    ///
    /// ⚠️ Metadata the record holds, and the field set is locked by test.
    #[serde(rename = "rc:hive.move")]
    HiveMove {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        fence: u64,
        /// The newest turn the session's room has a stub for.
        turns: u32,
        /// Where it ran before this start: the device, its name and the
        /// folder. On a move back after a refused start, the device itself.
        #[serde(with = "oid_hex")]
        from_device_id: ObjectId,
        from_device_name: String,
        from_folder: String,
        /// Who moved it: the session's owner.
        #[serde(with = "oid_hex")]
        moved_by: ObjectId,
        moved_by_name: String,
        /// When the lease moved, as the server's clock read it (Unix ms).
        moved_at_ms: u64,
        /// FR-90 P2f-5 — every place it ran before this start, oldest first,
        /// one per folder, the newest
        /// [`crate::hive::promote_limits::MAX_EARLIER_PLACES`]: the record's
        /// path map, the `from_*` place last. Old turns keep the paths they
        /// had there. Absent from a server before P2f-5, and for a session
        /// with no move it recorded.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        earlier: Vec<crate::hive::HivePlace>,
    },

    /// FR-90 P1e — a session's core memory, rendered from the org's brain at
    /// the revision the session pinned when it was created, and sent
    /// IMMEDIATELY BEFORE its [`ServerMsg::HiveStart`] (and before that
    /// start's re-send on connect), so the device holds it when the launch
    /// comes. Only to a device that advertises
    /// [`crate::models::RpcCap::HiveMemory`].
    ///
    /// ⚠️ The one Hive frame with text a model reads — and reads as the
    /// user's own overriding instructions (Claude Code frames `CLAUDE.md`
    /// that way). So it is its own frame, keeping `rc:hive.start` metadata
    /// only, and the device's own `hive_core_memory` (default off) decides
    /// whether any session sees it. Curated facts only: never a prompt, a
    /// transcript line or a secret.
    ///
    /// ⚠️ FROZEN: the snapshot is the one rendered when the session was
    /// created; a fact added later reaches the next session, never this one.
    #[serde(rename = "rc:hive.memory")]
    HiveMemory {
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        /// The fence of the start this snapshot goes with.
        fence: u64,
        /// The org's brain revision it was rendered from.
        brain_rev: u64,
        /// `CLAUDE.md` — the org's facts, then the starter's. Absent when
        /// both scopes are empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        claude_md: Option<String>,
        /// The auto-memory index `MEMORY.md` — the device's facts. Absent
        /// when that scope is empty.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        memory_md: Option<String>,
    },

    /// FR-90 P1j — the server's answer to [`ClientMsg::HiveAdopt`]: the
    /// session's record, or why there is none. The device mirrors the
    /// terminal only after an answer without `refused`.
    #[serde(rename = "rc:hive.adopt_ack")]
    HiveAdoptAck {
        /// Echo of the offer's `adopt_id`.
        adopt_id: String,
        /// The record's id, when adopted.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "option_oid_hex"
        )]
        session_id: Option<ObjectId>,
        /// The fence the device reports it under, when adopted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fence: Option<u64>,
        /// Absent = adopted. Present = refused, decoded leniently — see
        /// [`crate::hive::HiveAdoptRefusal`].
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "crate::hive::adopt_refusal_lenient"
        )]
        refused: Option<crate::hive::HiveAdoptRefusal>,
    },

    // ─── Hive viewer peer (rc:hive.view.*) — FR-90 P0d-2 ─────────────────
    /// A view grant: `user_id` may read `session_id` over a data-only WebRTC
    /// peer for `ttl_secs`, and send it prompts if `may_prompt`. The device
    /// answers [`ClientMsg::HiveViewGrantAck`] before the server tells the
    /// browser to dial; a repeated grant id is answered again, not doubled.
    ///
    /// The TTL is RELATIVE — the device starts its own clock on receipt, so
    /// clock skew cannot expire a fresh grant or extend a stale one.
    #[serde(rename = "rc:hive.view.grant")]
    HiveViewGrant {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        #[serde(with = "oid_hex")]
        session_id: ObjectId,
        #[serde(with = "oid_hex")]
        user_id: ObjectId,
        /// How this viewer's prompts are attributed in the transcript.
        #[serde(default)]
        user_name: String,
        /// The viewer drives the session: prompts go to its harness. False =
        /// read only; a prompt over the peer is refused on the device.
        #[serde(default)]
        may_prompt: bool,
        /// FR-90 P1c-2 — the viewer's address as `users.email` holds it (a
        /// PROVEN one, or the `.invalid` placeholder), sent ONLY with
        /// `may_prompt`: the device lets a driver other than the session's
        /// starter act only when its own `hive_accounts` maps them to the
        /// account the session runs as, and that map may name people by
        /// address. A reader's address never leaves the server.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user_email: Option<String>,
        ttl_secs: u32,
    },

    /// FR-90 P2i-1 — a search grant: `user_id` may search the copies this
    /// device holds of `sessions`, over a data-only WebRTC peer, for
    /// `ttl_secs`. Only to a connection advertising `hive-search`. The device
    /// answers [`ClientMsg::HiveViewGrantAck`], as for a view grant, and the
    /// peer then rides the view's frames, keyed by the grant: the offer, the
    /// candidates, the renewals and the close. The query, and all it finds,
    /// travel only over the peer: the server never sees either.
    ///
    /// ⚠️ A frame of its own, never a field on [`ServerMsg::HiveViewGrant`]:
    /// a build before it must never read a search grant as a view of one
    /// session.
    #[serde(rename = "rc:hive.search.grant")]
    HiveSearchGrant {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        #[serde(with = "oid_hex")]
        user_id: ObjectId,
        /// The sessions the viewer may search: those it may read that this
        /// device holds a copy of, as the server knows them, at most
        /// [`crate::hive::search_limits::MAX_SESSIONS`]. The device searches
        /// only the ones it does hold.
        #[serde(default, with = "vec_oid_hex")]
        sessions: Vec<ObjectId>,
        ttl_secs: u32,
    },

    /// A grant's renewal: a fresh `ttl_secs` from receipt, after the server
    /// re-checked the viewer's right to read.
    #[serde(rename = "rc:hive.view.renew")]
    HiveViewRenew {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        ttl_secs: u32,
    },

    /// The viewer's SDP offer for a confirmed grant, with the ICE servers
    /// the server minted for this peer (the browser gets the same).
    #[serde(rename = "rc:hive.view.offer")]
    HiveViewOffer {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        sdp: String,
        ice_servers: Vec<IceServer>,
    },

    /// One of the viewer's ICE candidates.
    #[serde(rename = "rc:hive.view.ice")]
    HiveViewIce {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        candidate: serde_json::Value,
    },

    /// The grant is over — the viewer closed the room, its socket went, it
    /// lost the right to read. The device closes the peer. Idempotent.
    #[serde(rename = "rc:hive.view.close")]
    HiveViewClose {
        #[serde(with = "oid_hex")]
        grant_id: ObjectId,
        #[serde(default)]
        reason: String,
    },

    /// FR-90 P3-3b — the vault leased a value: `sealed` is a libsodium sealed
    /// box (`crypto_box_seal`, standard base64) for the vault key the
    /// device's hello carried, which only that daemon opens. Sent only on the
    /// connection that asked ([`ClientMsg::VaultLease`]), never pushed.
    #[serde(rename = "rc:vault.leased")]
    VaultLeased {
        req_id: String,
        /// The vault's id for this lease (`vault_leases.lease_id`).
        lease_id: String,
        /// The version leased, as the vault numbers a field's versions.
        /// `0` for a dynamic secret's bundle, which spans its fields.
        n: i64,
        sealed: String,
        /// When the device must drop it.
        expires_at_ms: i64,
        /// P3-6b — a dynamic secret's provider (`crate::vault::providers`).
        /// Then `sealed` opens to a bundle, a JSON object of the issuer's
        /// fields, for the device to mint with. Absent for a stored value,
        /// as from every earlier server.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
    },

    /// FR-90 P3-3b — the vault refused a lease, in one word from
    /// [`crate::vault::LeaseRefusal`]. Never says which policy decided.
    #[serde(rename = "rc:vault.refused")]
    VaultRefused {
        req_id: String,
        reason: String,
        /// P3-4e — with `awaiting_approval`, the approval whose card waits
        /// in the session's room; no other word carries one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        approval_id: Option<String>,
    },

    /// FR-90 P3-3c — the vault took these leases back, for one reason
    /// ([`crate::vault::RevokeReason`]): the device drops each, whatever the
    /// word. Sent only on a connection that advertises
    /// [`crate::models::RpcCap::Vault`]; at most
    /// [`crate::vault::lease_limits::MAX_REVOKE_IDS`] a frame. Not
    /// acknowledged: every hello is told again of each revoked lease that has
    /// not yet expired, so a frame that was lost costs only a repeat.
    #[serde(rename = "rc:vault.revoke")]
    VaultRevoke {
        lease_ids: Vec<String>,
        reason: String,
    },

    /// FR-90 P3-4b — what the session's role may list: at most
    /// [`crate::vault::lease_limits::MAX_LISTED`] secrets, `more` when there
    /// were more. Metadata only, never a value.
    #[serde(rename = "rc:vault.listed")]
    VaultListed {
        req_id: String,
        secrets: Vec<crate::vault::VaultSecretMeta>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        more: bool,
    },

    /// FR-90 P3-4b — one secret's metadata, never a value.
    #[serde(rename = "rc:vault.described")]
    VaultDescribed {
        req_id: String,
        secret: crate::vault::VaultSecretMeta,
    },

    /// FR-90 P3-7-1b — the vault granted a session's egress
    /// ([`ClientMsg::VaultNet`]): `grant`, a token signed by the server under
    /// its own audience (`net_grant`), which the device attaches when it
    /// opens the tunnel (P3-7-2). Sent only on the connection that asked,
    /// never pushed. A grant carries no value and is no lease: nothing
    /// revokes it, and it ends at `expires_at_ms`.
    #[serde(rename = "rc:vault.net.granted")]
    VaultNetGranted {
        req_id: String,
        /// The grant's id, as the vault records its allow (`grant:<id>`).
        grant_id: String,
        grant: String,
        /// When it ends, in whole seconds as the grant names it.
        expires_at_ms: i64,
        /// A forward's destination exactly as granted: the host in
        /// [`crate::vault::canonical_net_host`]'s spelling, which the device
        /// dials. Absent for SOCKS.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        host: String,
        #[serde(default, skip_serializing_if = "is_zero_u16")]
        port: u16,
    },

    /// FR-90 P3-8-1a — the vault allowed a session's command on another
    /// device ([`ClientMsg::VaultSsh`]): `ticket`, a token signed by the
    /// server under its own audience (`ssh_ticket`), which the device attaches
    /// to `rc:ssh.request` (P3-8-1b). Sent only on the connection that asked,
    /// never pushed. Named a ticket, not a grant: `rc:ssh.grant` is the
    /// target's (FR-83), and the request carries both.
    #[serde(rename = "rc:vault.ssh.granted")]
    VaultSshGranted {
        req_id: String,
        /// The ticket's id, as the vault records its allow (`ticket:<id>`).
        ticket_id: String,
        ticket: String,
        /// When it ends, in whole seconds as the ticket names it.
        expires_at_ms: i64,
        /// The target's OS as its row holds it (`linux`, `macos`,
        /// `windows`), which the vault read for Cedar: the session's command
        /// meets that system's shell.
        os: String,
        /// The account the target's SSH policy maps, which the vault decided
        /// on (a [`crate::models::SshAccountMode`] word) and the ticket names.
        account: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

/// Phase B (overlay v3) — the MEASURED capability vector on the wire
/// (netcheck). Every field serde-defaulted so the shape can grow; `Option`
/// fields distinguish "measured false" from "not measured" — absence of
/// measurement is NEVER evidence of absence of capability, and consumers
/// fall back to presence rules on `None`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default, Copy)]
pub struct CapVectorWire {
    /// The srflx gather found a public mapping.
    #[serde(default)]
    pub stun_udp: bool,
    /// Raw UDP reaches coturn's relay band, measured over the exact
    /// single-relay dialer path. `Some(false)` = the CORPLAP-class egress drop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_band_udp: Option<bool>,
    /// The central `/derp` WS is up + registered (the floor's health).
    #[serde(default)]
    pub derp_ws_ok: bool,
}

/// Discovery hint only, never permission to install or promote a carrier.
/// Server emits at most one candidate with at most four public endpoints.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OrgRelayCandidateWire {
    #[serde(with = "oid_hex")]
    pub relay_node_id: ObjectId,
    pub endpoints: Vec<String>,
    #[serde(
        default,
        with = "option_oid_hex",
        skip_serializing_if = "Option::is_none"
    )]
    pub exit_relay_node_id: Option<ObjectId>,
}

/// Non-authorizing position in a freshly filtered discovery set. Never a grant.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrgRelayDiscoveryCursorWire {
    #[serde(with = "oid_hex")]
    pub relay_node_id: ObjectId,
    #[serde(
        default,
        with = "option_oid_hex",
        skip_serializing_if = "Option::is_none"
    )]
    pub exit_relay_node_id: Option<ObjectId>,
}

/// A same-tenant, policy-approved two-leg bridge. Never emitted to a legacy
/// relay, and not a general-purpose dial command. Native local CIDR refusal
/// remains authoritative even for a server-issued grant.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RelayBridgeWire {
    #[serde(with = "oid_hex")]
    pub trial_id: ObjectId,
    pub generation: u64,
    #[serde(with = "oid_hex")]
    pub source_agent_id: ObjectId,
    #[serde(with = "oid_hex")]
    pub target_agent_id: ObjectId,
    pub local_vni: u32,
    pub local_generation: u64,
    pub local_bind_secret: String,
    pub remote_endpoint: String,
    pub remote_vni: u32,
    pub remote_generation: u64,
    pub remote_bind_secret: String,
    pub max_lifetime_secs: u32,
}

/// One member of an org-relay session as pushed to the relay in
/// [`ServerMsg::OverlayRelayServe`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RelayMemberWire {
    /// base64 WireGuard public key — the member's identity as the mint names it.
    pub wg_public_key: String,
    /// base64 32-byte bind secret for THIS member.
    pub bind_secret: String,
}

/// One relay region as pushed in [`ServerMsg::RelayRegions`] — the probe
/// target, not the credential set (creds keep flowing through the normal
/// grant paths; this only lets the node measure which PoP is nearest).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RelayRegionInfo {
    /// Region id (`relay_home` value), e.g. `"us-east"`.
    pub id: String,
    /// STUN probe target `host:port` (the region's coturn answers STUN
    /// Binding on its TURN UDP port).
    pub stun: String,
    /// The region's DERP endpoint, when it runs one (regional-DERP dialing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derp_url: Option<String>,
    /// Phase E (overlay v3) — the region's coturn relay allocation band
    /// (`min..=max` UDP ports). Lets the netcheck relay-band probe target
    /// the region's REAL band; absent from a pre-E server ⇒ agents keep
    /// the allocation-derived behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_band: Option<(u16, u16)>,
}

/// Agent host/process telemetry riding [`ClientMsg::AgentHeartbeat`]
/// (stats PR-5). Persisted into the `stats_machine` minute buckets; the
/// carrier tallies come from the overlay runtime's live view. Absence of
/// the whole block means "not measured" (pre-v2 agent).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AgentSysStats {
    /// Agent process resident set, MiB.
    pub rss_mb: u32,
    /// Agent process CPU share, percent of one core.
    pub cpu_pct: f32,
    /// Host-total cumulative network counters (bytes since boot, summed
    /// over interfaces) — the server derives rates from successive
    /// samples; a reboot reads as a counter reset.
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    /// Live overlay carriers by kind at sample time.
    pub direct: u32,
    pub relay: u32,
    pub derp: u32,
    /// Median prober RTT across live overlay peers, ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_rtt_ms: Option<u32>,
    /// Cumulative overlay IP-data volume, summed across this node's peer
    /// carriers (wave 3). Host-total `net_*_bytes` above counts ALL traffic
    /// on every interface; these two isolate the mesh's own share, which is
    /// what "how much did the overlay move" actually means.
    ///
    /// Cumulative-since-carrier-install, NOT since boot: a carrier rebuild
    /// resets its counters, so the sum can step DOWN. The server stores it
    /// with the same min/max-per-bucket treatment as `net_*_bytes` and
    /// differences read-side, which under-reports across a rebuild rather
    /// than going negative. Absent on pre-wave-3 agents.
    #[serde(default)]
    pub overlay_rx_bytes: u64,
    #[serde(default)]
    pub overlay_tx_bytes: u64,
    /// Cumulative tunnel-forward volume across this node's live flows
    /// (wave 3), from the endpoint's own counters.
    ///
    /// The server cannot measure this itself: tunnel payload rides the
    /// peer-to-peer data channel, which is why `tunnel_audit.bytes_in`/
    /// `bytes_out` have held a literal 0 on every row ever written. These
    /// two are DEVICE-attributed — a daemon-supervised forward belongs to
    /// the host, not to a person. A dedicated `roomler` client's
    /// flows are user-owned and still report nothing; that needs the same
    /// counters wired into the CLI's own heartbeat.
    ///
    /// `in` = the local app received, `out` = the local app sent.
    #[serde(default)]
    pub tunnel_rx_bytes: u64,
    #[serde(default)]
    pub tunnel_tx_bytes: u64,
    /// Per-peer mesh edges as this node currently reaches them (wave 2).
    /// The aggregate counters above answer "how many carriers of each
    /// kind"; this answers "which peer, over what, how fast" — the graph
    /// the org dashboard draws. Absent on pre-wave-2 agents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<PeerLink>,
}

/// One overlay edge from the reporting node's point of view.
///
/// BOTH ends report the same pair, so the read side dedupes on the
/// sorted node pair and merges — the two ends can legitimately disagree
/// (one has a direct carrier installed while the other still relays),
/// and the pessimistic merge keeps the graph honest.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PeerLink {
    /// The peer's overlay node id (hex).
    pub node: String,
    /// How this node reaches it: `direct` | `relay` | `derp` | `tunnel` |
    /// `blocked` | `offline`.
    pub carrier: String,
    /// Prober round-trip in ms, when measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
    /// The health sweep's silently-one-way verdict — an edge that looks
    /// installed but carries nothing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stalled: bool,
    /// IP-data bytes carried over this edge since its carrier was installed
    /// (wave 3). Handshakes and keepalives touch neither, so `tx > 0` with
    /// `rx == 0` is exactly the one-way signal `stalled` reports — the two
    /// corroborate each other. Zero on pre-wave-3 agents.
    #[serde(default)]
    pub tx: u64,
    #[serde(default)]
    pub rx: u64,
    /// Relay flavour + transport as one qualified suffix — `turn/udp`,
    /// `turn/tcp`, `derp/tcp` — the same detail the CLI's CONN column
    /// renders after `relay:` (wave 4). A bare carrier can't distinguish a
    /// ~50 ms coturn/UDP hop from a ~175 ms DERP/TCP one, which is exactly
    /// what the mesh graph exists to show. `None` for non-relay edges and
    /// for agents older than the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
}

/// One region's probe outcome in [`ClientMsg::RelayProbeReport`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RelayRegionRtt {
    pub region: String,
    /// Median STUN round-trip in ms; `None` = every sample timed out
    /// (UDP-blocked path or dead PoP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
}

/// FR-101 P3 — a session's clipboard and file traffic, as the device saw it,
/// in [`ClientMsg::SessionStats`]. Counts, sizes and a hash of each file's
/// name; never content, and never a name.
///
/// The clipboard tallies are cumulative for the session and only grow, so
/// the server writes the difference from what it stored last: a lost sample
/// costs nothing, and a repeated one adds nothing. `files` are the transfers
/// that completed since the previous sample, each sent once.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct Transfers {
    /// Writes the controller made to the host's clipboard.
    #[serde(default, skip_serializing_if = "Tally::is_zero")]
    pub clipboard_to_host: Tally,
    /// Clipboard content the host sent the controller: reads it asked for,
    /// and changes pushed to a subscribed viewer.
    #[serde(default, skip_serializing_if = "Tally::is_zero")]
    pub clipboard_from_host: Tally,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileNote>,
}

impl Transfers {
    pub fn is_empty(&self) -> bool {
        self.clipboard_to_host.is_zero()
            && self.clipboard_from_host.is_zero()
            && self.files.is_empty()
    }
}

/// How many, and how many bytes.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    pub count: u64,
    pub bytes: u64,
}

impl Tally {
    pub fn is_zero(&self) -> bool {
        self.count == 0 && self.bytes == 0
    }

    /// What `self` adds to an earlier reading. A reading that went
    /// backwards (a restarted counter) adds nothing.
    pub fn since(&self, earlier: Tally) -> Tally {
        Tally {
            count: self.count.saturating_sub(earlier.count),
            bytes: self.bytes.saturating_sub(earlier.bytes),
        }
    }
}

/// Which way a transfer went.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    /// The controller sent it to the host.
    ToHost,
    /// The host sent it to the controller.
    FromHost,
}

/// One completed file transfer.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FileNote {
    pub dir: TransferDirection,
    /// SHA-256 of the file's name (its UTF-8 bytes), lowercase hex. Equal
    /// names hash equally, so transfers of one file can be told apart from
    /// many; the name itself never leaves the device.
    pub name_sha256: String,
    pub bytes: u64,
}

/// Loopback-TURN corp-relay descriptor (loopback-TURN Phase 2). Minted + served
/// by the controller host's LOCAL enrolled agent on its loopback probe endpoint
/// (`http://127.0.0.1:47989/rc-local-turn`); the browser forwards it verbatim in
/// [`ClientMsg::SessionRequest::local_relay`] so the Hub can append
/// `turn:{overlay_ip}:{turn_port}` to the REMOTE agent's ICE servers. The media
/// then relays through the local agent's overlay (WFP-permitted, corp-traversal
/// proven) instead of the capped far coturn — the whole point of the feature.
///
/// One type, three hops: the agent SERIALIZES it (loopback response), the
/// browser parses + re-emits it (`LocalRelayDescriptor` in `useRemoteControl.ts`,
/// same snake_case field names so the JSON round-trips unchanged), and the Hub
/// DESERIALIZES it here. WebRTC media is DTLS-E2E, so a relay only ever moves
/// ciphertext — the server is a dumb pass-through of the descriptor.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LocalRelayDescriptor {
    /// UDP port the local agent's TURN server listens on (loopback + overlay).
    pub turn_port: u16,
    /// The local agent's assigned overlay IP (100.64.x.y) — the relay-candidate
    /// address the remote agent routes to over the roomler adapter. The Hub
    /// validates this is inside the overlay range before trusting it.
    pub overlay_ip: String,
    /// coturn-REST username (`{expiry}:{user_id}`) minted by the local agent.
    pub username: String,
    /// coturn-REST credential (hex HMAC-SHA1 over `username`) matching it.
    pub credential: String,
}

// ────────────────────────────────────────────────────────────────────────────
// Overlay network supporting types (rc:overlay.*)
// ────────────────────────────────────────────────────────────────────────────

/// U2 — the server's per-edge relay-tier verdict (the recipient's view of
/// THIS peer), mirroring the client's own `RelayStrategy` so the client can
/// use it verbatim in place of its local derivation. Serialised as a
/// lowercase-kebab string tag; an unknown/absent value ⇒ the client falls
/// back to its local computation, so adding a variant later is
/// forward-compatible.
///
/// ⚠️ That last sentence is only true because [`NetmapPeer::relay_strategy`]
/// decodes through [`relay_strategy_lenient`]. The derive alone does **not**
/// deliver it — see that function for what happens without it. Any *new*
/// field or message carrying this type must use the same shim.
///
/// Anchor/dialer symmetry is the whole reason this is server-computed: the
/// server holds BOTH ends' pubkeys, so it stamps exactly one end
/// `SingleRelayAnchor` and the other `SingleRelayDialer` — the client's own
/// derivation depends on its (possibly frozen) `my_udp_relay_ok`, which the
/// server can't reproduce and which is what let the two ends disagree.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RelayStrategyWire {
    /// v1 single-relay ANCHOR (allocate the one relay, advertise `R`).
    SingleRelayAnchor,
    /// v1 single-relay DIALER (no allocation; raw-dial the anchor's `R`).
    SingleRelayDialer,
    /// DERP `/derp` WS relay (both ends UDP-blocked).
    Derp,
    /// Two coturn allocations (the fall-through).
    BothAllocate,
    /// FR-19 — ride a tenant-owned org relay. A UNIT variant on purpose: this
    /// enum derives `Copy` and is serialised as a bare string tag, so the
    /// session itself travels out-of-band in `rc:overlay.relay_session`.
    /// Only ever emitted to a peer whose join advertised `supports_org_relay`;
    /// a pre-FR-19 agent that somehow received it decodes it to `None` via
    /// `relay_strategy_lenient` (#811) rather than losing the frame.
    OrgRelay,
}

/// Lenient decoder for [`NetmapPeer::relay_strategy`]: an **unrecognised**
/// tag becomes `None` instead of failing the parse.
///
/// ⚠️ Without this, [`RelayStrategyWire`]'s own doc comment is a lie with
/// fleet-wide consequences, and the failure is invisible. The enum is
/// externally tagged with only unit variants, so it decodes from a bare
/// string; `#[serde(default)]` on the field covers an **absent** value and
/// does nothing for an **unknown** one. An unknown tag is therefore a hard
/// serde error that fails the *whole enclosing `ServerMsg`* — not just this
/// field, not just this peer — and the agent's parse arm swallows that at
/// `debug!`. So the first server to add a variant would make every older
/// agent drop entire netmap frames and stop installing peers, silently.
///
/// `#[serde(other)]` cannot express this: serde permits it only on
/// internally or adjacently tagged enums, and this one is neither.
///
/// Unknown ⇒ `None` ⇒ the client computes the tier locally — precisely what
/// an absent field already means, so every existing consumer handles it with
/// no new arm. A non-string value degrades the same way rather than
/// exploding, so a future variant that grows a payload is survivable too.
fn relay_strategy_lenient<'de, D>(de: D) -> Result<Option<RelayStrategyWire>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(raw) = Option::<serde_json::Value>::deserialize(de)? else {
        return Ok(None);
    };
    let serde_json::Value::String(tag) = raw else {
        return Ok(None);
    };
    // Re-parse through the derive so the kebab-case spellings live in exactly
    // one place; a rename cannot drift away from this shim.
    Ok(RelayStrategyWire::deserialize(
        serde::de::value::StrDeserializer::<serde::de::value::Error>::new(tag.as_str()),
    )
    .ok())
}

/// FR-83 — lenient decoder for [`ClientMsg::SshGrantAck::refused`], the same
/// shape and for the same reason as [`relay_strategy_lenient`]: the refusal
/// enum is externally tagged with unit variants, so an unknown spelling from
/// a NEWER agent would be a hard error failing the whole frame — dropped at
/// `debug!`, leaving the caller to wait out the full bound and then be told
/// the grant was *unconfirmed* when the device had clearly refused it.
///
/// ⚠️ The direction of the fallback is the point. An unrecognised or
/// malformed refusal is still a REFUSAL ([`SshGrantRefusal::Other`]); only an
/// absent or `null` field means "recorded". Falling back to `None` would tell
/// a caller to dial a device that has just said no.
///
/// [`SshGrantRefusal::Other`]: crate::models::SshGrantRefusal::Other
fn grant_refusal_lenient<'de, D>(de: D) -> Result<Option<crate::models::SshGrantRefusal>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use crate::models::SshGrantRefusal;
    let Some(raw) = Option::<serde_json::Value>::deserialize(de)? else {
        return Ok(None);
    };
    let serde_json::Value::String(tag) = raw else {
        return Ok(Some(SshGrantRefusal::Other));
    };
    // Re-parse through the derive so the spellings live in exactly one place.
    Ok(Some(
        SshGrantRefusal::deserialize(
            serde::de::value::StrDeserializer::<serde::de::value::Error>::new(tag.as_str()),
        )
        .unwrap_or(SshGrantRefusal::Other),
    ))
}

/// FR-52 P3 — lenient decoder for [`ClientMsg::ExtauthOutcome::refused`], the
/// same shape as [`grant_refusal_lenient`] and for the same reason.
///
/// ⚠️ The direction of the fallback is the security property here, not a
/// convenience: an unrecognised or malformed refusal is still a REFUSAL
/// ([`ExtauthRefusal::Other`]); only an absent or `null` field means
/// "verified". Falling back to `None` would turn any refusal this server has
/// not heard of into a verified login for an outsider.
///
/// [`ExtauthRefusal::Other`]: crate::models::ExtauthRefusal::Other
fn extauth_refusal_lenient<'de, D>(de: D) -> Result<Option<crate::models::ExtauthRefusal>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use crate::models::ExtauthRefusal;
    let Some(raw) = Option::<serde_json::Value>::deserialize(de)? else {
        return Ok(None);
    };
    let serde_json::Value::String(tag) = raw else {
        return Ok(Some(ExtauthRefusal::Other));
    };
    Ok(Some(
        ExtauthRefusal::deserialize(
            serde::de::value::StrDeserializer::<serde::de::value::Error>::new(tag.as_str()),
        )
        .unwrap_or(ExtauthRefusal::Other),
    ))
}

/// One peer in a netmap. `node_id` is the peer's `overlay_nodes._id`
/// (the stable handle the control plane uses for fan-out + ACL). The
/// node installs this peer as a WireGuard `Tunn` keyed by
/// `wg_public_key`, with `allowed_ips = overlay_ip/32`. `reachable` is
/// **server-precomputed** from the ACL — a forbidden peer is dropped
/// from the netmap entirely, so this is `true` for every peer the node
/// actually receives (the field is retained so a future soft-deny can
/// ship a peer with `reachable=false` without a wire change).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct NetmapPeer {
    #[serde(with = "oid_hex")]
    pub node_id: ObjectId,
    pub overlay_ip: String,
    /// Human-facing node name (Phase 0) — the MagicDNS label for this peer,
    /// unique per network. Empty from a pre-Phase-0 server (`#[serde(default)]`).
    #[serde(default)]
    pub name: String,
    pub wg_public_key: String,
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// NAT-traversal Phase A — the peer's JOIN-TIME NIC-derived endpoints (the
    /// server's `lan_endpoints` bucket, verbatim — NOT unioned with the relay
    /// trickle like `endpoints`). A globally-routable address in here means the
    /// peer's NIC itself holds a public IP (bare-metal / no NAT in front), so
    /// any node can dial it directly without STUN — the *direct-to-public*
    /// carrier tier. Provenance matters: `endpoints` also contains coturn
    /// relayed addresses, and on this fleet the coturn worker IPs COLLIDE with
    /// host public IPs (the workers run on the same hosts), so a "public and
    /// not a coturn IP" heuristic over the union cannot distinguish them —
    /// only the join-time bucket can. Empty from a pre-Phase-A server
    /// (`#[serde(default)]`) → the public-direct tier stays inert.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lan_endpoints: Vec<String>,
    /// NAT-traversal Phase B — the peer's **server-reflexive** (srflx)
    /// candidates: its public `ip:port` as seen through its NAT, discovered by
    /// the peer querying a STUN server (`OverlayNetworkInfo.stun_urls`) on each
    /// of its own traffic sockets and trickled up via `rc:overlay.srflx`. Lets a
    /// node behind a 1:1 / cone NAT (e.g. a cloud exit whose NIC IP is private)
    /// become directly dialable without a relay: a dialer sends its WireGuard
    /// INIT here and the peer accepts it over the NAT mapping its own STUN query
    /// opened. Kept in a SEPARATE bucket from `endpoints` (relay) and
    /// `lan_endpoints` (public NIC) so each provenance stays distinct (CC2) and
    /// the relay trickle can't clobber it. Empty from a pre-Phase-B server or a
    /// node that gathered no public srflx (`#[serde(default)]`) → the srflx tier
    /// stays inert.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub srflx_endpoints: Vec<String>,
    /// Phase C — this peer's probed NAT mapping type (`"cone"` / `"symmetric"`),
    /// or `None` when unknown. A dialer skips the srflx punch only when BOTH ends
    /// are `"symmetric"` (neither can predict the other's per-destination port);
    /// any other combination attempts. Optional + omitted-when-None ⇒ a
    /// pre-Phase-C server/peer stays "unknown" (attempted, never skipped).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srflx_nat: Option<String>,
    /// FR-19 — echoed from the peer's join so a node knows whether its peer can
    /// use an org relay (both ends must). Skipped when `false` so a pre-FR-19
    /// node's netmap shape is byte-identical.
    #[serde(default, skip_serializing_if = "<&bool as std::ops::Not>::not")]
    pub supports_org_relay: bool,
    /// Phase B (overlay v3) — this peer's MEASURED capability vector, or
    /// `None` when the peer hasn't measured (pre-B agent) or its vector went
    /// STALE (the server's freshness gate treats >3× cadence as absent — a
    /// stalled prober must not stay fleet-authoritative). Consumers fall
    /// back to the presence rules whenever this is `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caps: Option<CapVectorWire>,
    /// Dialer honesty (field 2026-08-16, CORPLAP-3) — can this peer
    /// raw-UDP-dial ARBITRARY high ports (the single-relay DIALER's job:
    /// its raw socket sends straight to a coturn relay-band port)? A srflx
    /// candidate only proves UDP to WELL-KNOWN ports (a corp egress that
    /// whitelists STUN:3478 still drops the ~10-13k relay band), so
    /// srflx-presence alone mis-assigns such hosts the dialer role and the
    /// pair dies undialed. `Some(false)` = the peer PROVED it can't (its
    /// dialer-role relay carriers convicted against ≥2 distinct peers);
    /// `Some(true)` = no such evidence; `None` = pre-honesty peer — both
    /// ends then keep the legacy srflx-only inputs, so a mixed-version
    /// pair can never split roles (presence of the field IS the
    /// capability signal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_dialer_ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_home: Option<String>,
    /// C4 stage 2 — this peer's STANDING warm TURN allocation's relayed
    /// address (`worker-ip:port`), refreshed by its heartbeats while a leg
    /// is live. A dialer whose pair to this peer died can dial it
    /// IMMEDIATELY (validated against the coturn worker set like any
    /// anchor advert) — no waiting for the peer's per-pair relay
    /// advertisement to crawl through a possibly-captured control WS.
    /// `None` from a pre-stage-2 server or while the peer holds no leg.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warm_relay_endpoint: Option<String>,
    pub reachable: bool,
    /// rc.142 — this peer advertised it can carry WG over a QUIC-over-TURN
    /// relay carrier. A node only attempts the QUIC upgrade with a peer when
    /// both ends set this (else raw relay), so a capability mismatch can't
    /// leave one side on QUIC and the other on raw (which wouldn't decapsulate).
    #[serde(default)]
    pub supports_quic: bool,
    /// Phase D — this peer advertised it can run the v1 single-relay carrier
    /// (one anchor allocation + a raw dialer). The runtime picks single-relay
    /// only when both ends set this AND the local `OVERLAY_RELAY_SINGLE` flag is
    /// on, so a mismatch can't split a pair into anchor/dialer and deadlock.
    /// Absent from a pre-Phase-D server/peer ⇒ `false` (both-allocate).
    #[serde(default)]
    pub supports_relay_single: bool,
    /// Phase D (DERP) — this peer advertised it can carry WG over the
    /// pubkey-addressed `/derp` relay. The runtime falls to DERP only when BOTH
    /// ends set this AND both are UDP-blocked (the single-relay `(false,false)`
    /// arm) AND the local `OVERLAY_DERP` flag is on. Pre-DERP peer ⇒ `false`.
    #[serde(default)]
    pub supports_derp: bool,
    /// U2 — this peer advertised `supports_forced_derp`. Echoed per-peer (it
    /// was NOT before U2) so the client can tell whether a peer will honor a
    /// pin, and so the server-computed [`relay_strategy`](Self::relay_strategy)
    /// is only applied by a client whose peer also participates. Pre-U2
    /// server/peer ⇒ `false`.
    #[serde(default)]
    pub supports_forced_derp: bool,
    /// U2 — the server's relay-tier verdict for THIS edge (the recipient →
    /// this peer). Populated ONLY when both ends advertised
    /// `supports_server_relay_strategy`; `None` otherwise (and for every
    /// pre-U2 server), in which case the client computes the tier locally as
    /// before. Skipped-when-None so a pre-U2 node's wire shape is unchanged.
    ///
    /// ⚠️ Decodes through [`relay_strategy_lenient`], NOT the bare derive:
    /// an unknown tag from a newer server must degrade to `None`, not fail
    /// the whole `ServerMsg`. Do not "simplify" this back to `#[serde(default)]`.
    #[serde(
        default,
        deserialize_with = "relay_strategy_lenient",
        skip_serializing_if = "Option::is_none"
    )]
    pub relay_strategy: Option<RelayStrategyWire>,
    /// Data-probe — this peer's overlay engine answers the overlay-native
    /// echo probe inline. The prober uses the engine echo toward such peers
    /// (guaranteed responder, netstack included) and the ICMP probe toward
    /// the rest. Pre-capability server/peer ⇒ `false` ⇒ ICMP.
    #[serde(default)]
    pub supports_overlay_echo: bool,
    /// Phase A (overlay v3) — this peer advertised the DERP always-on floor
    /// (its `/derp` mux is permanently open + registered). A pair is floored
    /// at birth only when BOTH ends carry this. Pre-floor server/peer ⇒
    /// `false` ⇒ the lazy-mux rules apply unchanged.
    #[serde(default)]
    pub supports_derp_floor: bool,
    /// Phase 1 — subnet routes this peer is an **approved** router for (CIDR
    /// strings like `"192.168.1.0/24"`). A receiving node installs each CIDR
    /// into its router (allowed_ips) + OS route table pointing at this peer, so
    /// LAN behind the peer is reachable over the overlay. Empty for a normal
    /// (non-router) peer or a pre-Phase-1 server (`#[serde(default)]`).
    #[serde(default)]
    pub routes: Vec<String>,
    /// P3b-3 — the `agents._id` backing this overlay node, when the node is an
    /// agent (`OverlayNode.node_ref == Agent`). `None` for a tunnel-client node
    /// or a pre-P3b-3 server (`#[serde(default)]`). Lets a controlling node join
    /// this overlay peer to a daemon-originated tunnel flow (which is keyed by
    /// agent id, a DIFFERENT ObjectId namespace than `node_id` = overlay-node
    /// id) and surface `ConnectionType::Tunnel`. `option_oid_hex` keeps it a
    /// bare-hex string on the wire (NOT bson `{"$oid":…}`), matching `node_id`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_oid_hex"
    )]
    pub agent_id: Option<ObjectId>,
    /// P4 — **server-compiled ingress rules**: what THIS peer may address when
    /// its packets arrive at the recipient of this netmap. Per-(recipient,peer),
    /// which is why it lives on the peer entry rather than on the network.
    ///
    /// Compiled from `overlay_policies` by evaluating the REVERSE direction
    /// (this peer as the source, the recipient as the `via` router), so the node
    /// never sees policy documents and a policy edit rides the existing
    /// netmap-delta fan-out — no restart, no new message type.
    ///
    /// `None` vs `Some(vec![])` is load-bearing and must not be collapsed:
    /// **`None`** = no rules compiled (a pre-P4 server, or the tenant's
    /// `acl_mode` is `off`) ⇒ the node falls back to its coarse
    /// [`LocalScope`](../../tunnel_core/overlay/router/struct.LocalScope.html)
    /// check only. **`Some(vec![])`** = the ACL ran and granted this peer
    /// nothing ⇒ deny. Skipped when absent so a pre-P4 node's wire shape is
    /// unchanged (13 serde wire-lock tests depend on that).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_rules: Option<Vec<crate::models::OverlayRule>>,
}

/// Network-wide parameters carried in a full netmap so the node can size
/// its TUN/MTU and validate its own address against the range.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OverlayNetworkInfo {
    /// Explicit support for the typed ORG-only fallback query. Old servers
    /// omit it, so a new client must not send the new request to them.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub org_relay_fallback_v1: bool,
    /// Explicit support for the ORG loss report
    /// ([`ClientMsg::OverlayOrgRelayLoss`]). Old servers omit it, so a new
    /// client must not send the report to them.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub org_relay_loss_v1: bool,
    /// The block containing **this recipient's own** overlay address.
    ///
    /// FR-47 P5d — this used to be the network's single CIDR, and for every
    /// network that has not grown it still is exactly that value: a one-block
    /// address space has one block, and it is the one the node lives in. The
    /// field only becomes recipient-specific once a network holds more than
    /// one block, which requires `overlay.multi_block_enabled`.
    ///
    /// ⚠️ Why per-recipient rather than "the first block": a fielded agent
    /// derives its TUN netmask and its subnet-router NAT source scope from
    /// this string. Both are correct only for the block its OWN address lives
    /// in — sending block 0 to a node addressed in block 1 would mis-size its
    /// netmask, which is a fleet-wide failure mode, not a cosmetic one. Peers
    /// in *other* blocks stay reachable through the per-peer `/32`s the agent
    /// already installs, so a pre-P5d agent needs nothing else.
    pub cidr: String,
    /// FR-47 P5d — every block in the network's address space, in allocation
    /// order. `#[serde(default)]` so a pre-P5d server (which sends none) and a
    /// pre-P5d agent (which reads none) both behave exactly as before.
    ///
    /// A node that understands this uses the union — for RPF scope and for
    /// knowing the full extent of its own org. A node that does not still has
    /// `cidr`, which is correct for it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cidrs: Vec<String>,
    pub mtu: u16,
    /// Phase 2 MagicDNS — the tenant's overlay DNS suffix (e.g.
    /// `"myorg.roomler.net"`), or `None` when MagicDNS is off. A node with a
    /// domain set brings up its local split-DNS resolver. `#[serde(default)]`
    /// for pre-Phase-2 servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic_domain: Option<String>,
    /// Phase 2 MagicDNS — upstream nameservers for non-overlay queries. Empty →
    /// the node's existing system resolvers.
    #[serde(default)]
    pub nameservers: Vec<String>,
    /// W2 MagicDNS — THIS node's own display name, so its local resolver can
    /// answer `<own-name>.<domain>` (the netmap's peer list excludes self,
    /// and the agent has no other authoritative source for its server-side
    /// name). `#[serde(default)]` + skip-when-None keeps both directions
    /// compatible with pre-W2 peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_name: Option<String>,
    /// NAT-traversal Phase B — STUN server URLs the node queries (on each of its
    /// own traffic sockets) to discover its server-reflexive candidates — its
    /// public `ip:port` as seen through the NAT. Lets a peer/exit behind a 1:1
    /// (or cone) NAT become directly dialable without a relay. Typically the
    /// same coturn workers used for TURN (a `turn:` host doubles as a STUN
    /// server). The runtime has no per-peer ICE creds at join/`setup_direct`
    /// time (those arrive only via `RelayGrant`), so the STUN endpoints must
    /// ride the netmap itself. Empty → no srflx gathering (pre-Phase-B server,
    /// or STUN disabled). `#[serde(default)]` for back-compat.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stun_urls: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_msg_roundtrip() {
        let m = ClientMsg::Ping { id: 42 };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:ping""#));
        let back: ClientMsg = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, ClientMsg::Ping { id: 42 }));
    }

    #[test]
    fn agent_hello_advertised_routes_default_and_roundtrip() {
        // New agent: round-trip preserves advertised_routes on the wire.
        let m = ClientMsg::AgentHello {
            machine_name: "host".into(),
            os: OsKind::Linux,
            arch: String::new(),
            arch_emulated: false,
            agent_version: "0.3.0".into(),
            displays: vec![],
            caps: Box::new(AgentCaps::default()),
            advertised_routes: vec!["192.168.1.0/24".into()],
            supports_relay_regions: true,
            ssh_host_pubkey: String::new(),
            vault_key: String::new(),
            peer_auth_key: String::new(),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:agent.hello""#));
        assert!(s.contains(r#""advertised_routes":["192.168.1.0/24"]"#));
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::AgentHello {
                advertised_routes, ..
            } => assert_eq!(advertised_routes, vec!["192.168.1.0/24".to_string()]),
            other => panic!("wrong variant: {other:?}"),
        }

        // Old (pre-feature) agent: the same hello minus the field must
        // deserialize with advertised_routes defaulted to [] (wire back-compat).
        let mut obj = serde_json::to_value(&m).unwrap();
        obj.as_object_mut().unwrap().remove("advertised_routes");
        match serde_json::from_value::<ClientMsg>(obj).unwrap() {
            ClientMsg::AgentHello {
                advertised_routes, ..
            } => assert!(
                advertised_routes.is_empty(),
                "a hello without advertised_routes must default to none"
            ),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// P8 wire lock. The tag and the `kind` spellings are a compatibility
    /// surface with every deployed agent: renaming one doesn't fail loudly,
    /// it makes a fleet's activity reports silently unparseable — the same
    /// class the `RpcCap` wire test exists to prevent.
    #[test]
    fn ssh_activity_wire_shape_is_locked() {
        use crate::models::SshActivityKind;

        let m = ClientMsg::SshActivity {
            grant_id: Some("g1".into()),
            caller: "ssh:Someone@100.65.4.2:1".into(),
            kind: SshActivityKind::Exec,
            detail: Some("uptime".into()),
            exit_code: Some(0),
            allowed: true,
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["t"], "rc:ssh.activity");
        assert_eq!(v["kind"], "exec");
        assert_eq!(v["allowed"], true);

        for (k, want) in [
            (SshActivityKind::SessionOpen, "session_open"),
            (SshActivityKind::SessionClose, "session_close"),
            (SshActivityKind::Exec, "exec"),
            (SshActivityKind::Shell, "shell"),
            (SshActivityKind::Sftp, "sftp"),
            (SshActivityKind::Forward, "forward"),
        ] {
            assert_eq!(
                serde_json::to_value(k).unwrap(),
                serde_json::Value::String(want.into()),
                "activity kind wire spelling changed"
            );
        }
    }

    /// FR-90 P3-4d — the device's report of a use, as it crosses the wire:
    /// an exec's exit code and timeout ride only when present, so a render's
    /// report is the smallest; it reads back the same.
    #[test]
    fn vault_activity_wire_shape_is_locked() {
        let sid = ObjectId::new();
        let exec = ClientMsg::VaultActivity {
            session_id: sid,
            fence: 3,
            kind: crate::vault::VaultActivityKind::Exec.wire().into(),
            lease_ids: vec!["L1".into(), "L2".into()],
            target: "psql".into(),
            exit_code: Some(2),
            timed_out: false,
        };
        let v = serde_json::to_value(&exec).unwrap();
        assert_eq!(v["t"], "rc:vault.activity");
        assert_eq!(v["session_id"], sid.to_hex());
        assert_eq!(v["kind"], "exec");
        assert_eq!(v["lease_ids"], serde_json::json!(["L1", "L2"]));
        assert_eq!(v["exit_code"], 2);
        assert!(v.get("timed_out").is_none(), "false is left out: {v}");
        let back: ClientMsg = serde_json::from_value(v).unwrap();
        assert!(matches!(
            back,
            ClientMsg::VaultActivity {
                exit_code: Some(2),
                ..
            }
        ));
        let render: ClientMsg = serde_json::from_value(serde_json::json!({
            "t": "rc:vault.activity", "session_id": sid.to_hex(), "fence": 3,
            "kind": "render", "lease_ids": ["L3"], "target": "db.env",
        }))
        .unwrap();
        assert!(matches!(
            render,
            ClientMsg::VaultActivity {
                exit_code: None,
                timed_out: false,
                ..
            }
        ));
    }

    /// FR-90 P3-4e — a refusal is one word, and only `awaiting_approval`
    /// names an approval: every other refusal is exactly the frame it was,
    /// and one from before the field reads back without it.
    #[test]
    fn vault_refused_wire_shape_is_locked() {
        let denied = ServerMsg::VaultRefused {
            req_id: "r1".into(),
            reason: crate::vault::LeaseRefusal::Denied.wire().into(),
            approval_id: None,
        };
        assert_eq!(
            serde_json::to_value(&denied).unwrap(),
            serde_json::json!({"t": "rc:vault.refused", "req_id": "r1", "reason": "denied"})
        );
        let awaiting = ServerMsg::VaultRefused {
            req_id: "r2".into(),
            reason: crate::vault::LeaseRefusal::AwaitingApproval.wire().into(),
            approval_id: Some("a1".into()),
        };
        let v = serde_json::to_value(&awaiting).unwrap();
        assert_eq!(v["reason"], "awaiting_approval");
        assert_eq!(v["approval_id"], "a1");
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(v).unwrap(),
            ServerMsg::VaultRefused {
                approval_id: Some(ref a),
                ..
            } if a == "a1"
        ));
        let before: ServerMsg = serde_json::from_value(serde_json::json!({
            "t": "rc:vault.refused", "req_id": "r3", "reason": "busy",
        }))
        .unwrap();
        assert!(matches!(
            before,
            ServerMsg::VaultRefused {
                approval_id: None,
                ..
            }
        ));
    }

    /// FR-90 P3-7-1b — a session's egress request and its grant, as they
    /// cross the wire: a SOCKS request names no destination, so it is the
    /// smaller frame, and both read back the same.
    #[test]
    fn vault_net_wire_shape_is_locked() {
        let (sid, exit) = (ObjectId::new(), ObjectId::new());
        let socks = ClientMsg::VaultNet {
            req_id: "n1".into(),
            session_id: sid,
            fence: 4,
            exit,
            kind: crate::vault::NetKind::Socks.wire().into(),
            host: String::new(),
            port: 0,
            ttl_secs: 300,
        };
        assert_eq!(
            serde_json::to_value(&socks).unwrap(),
            serde_json::json!({
                "t": "rc:vault.net", "req_id": "n1", "session_id": sid.to_hex(),
                "fence": 4, "exit": exit.to_hex(), "kind": "socks", "ttl_secs": 300,
            })
        );
        let forward: ClientMsg = serde_json::from_value(serde_json::json!({
            "t": "rc:vault.net", "req_id": "n2", "session_id": sid.to_hex(),
            "fence": 4, "exit": exit.to_hex(), "kind": "forward",
            "host": "db.internal", "port": 5432, "ttl_secs": 60,
        }))
        .unwrap();
        assert!(matches!(
            forward,
            ClientMsg::VaultNet { ref host, port: 5432, exit: e, .. }
                if host == "db.internal" && e == exit
        ));
        assert_eq!(forward.namespace(), Owner::Vault);

        let granted = ServerMsg::VaultNetGranted {
            req_id: "n2".into(),
            grant_id: "g1".into(),
            grant: "the-signed-grant".into(),
            expires_at_ms: 1_700_000_060_000,
            host: "db.internal".into(),
            port: 5432,
        };
        let v = serde_json::to_value(&granted).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "t": "rc:vault.net.granted", "req_id": "n2", "grant_id": "g1",
                "grant": "the-signed-grant", "expires_at_ms": 1_700_000_060_000_i64,
                "host": "db.internal", "port": 5432,
            })
        );
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(v).unwrap(),
            ServerMsg::VaultNetGranted { port: 5432, .. }
        ));
        let socks_granted = ServerMsg::VaultNetGranted {
            req_id: "n1".into(),
            grant_id: "g2".into(),
            grant: "another".into(),
            expires_at_ms: 1,
            host: String::new(),
            port: 0,
        };
        let v = serde_json::to_value(&socks_granted).unwrap();
        assert!(
            v.get("host").is_none() && v.get("port").is_none(),
            "SOCKS names no destination: {v}"
        );
    }

    /// FR-90 P3-8-1a — a session's ask for one command on another device, and
    /// its ticket, as they cross the wire; both read back the same, and the
    /// ask belongs to the vault.
    #[test]
    fn vault_ssh_wire_shape_is_locked() {
        let (sid, target) = (ObjectId::new(), ObjectId::new());
        let ask = ClientMsg::VaultSsh {
            req_id: "s1".into(),
            session_id: sid,
            fence: 4,
            target,
            ttl_secs: 120,
        };
        let v = serde_json::to_value(&ask).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "t": "rc:vault.ssh", "req_id": "s1", "session_id": sid.to_hex(),
                "fence": 4, "target": target.to_hex(), "ttl_secs": 120,
            })
        );
        let back: ClientMsg = serde_json::from_value(v).unwrap();
        assert!(matches!(
            back,
            ClientMsg::VaultSsh { target: t, fence: 4, ttl_secs: 120, .. } if t == target
        ));
        assert_eq!(back.namespace(), Owner::Vault);

        let granted = ServerMsg::VaultSshGranted {
            req_id: "s1".into(),
            ticket_id: "k1".into(),
            ticket: "the-signed-ticket".into(),
            expires_at_ms: 1_700_000_120_000,
            os: "linux".into(),
            account: "console_user".into(),
        };
        let v = serde_json::to_value(&granted).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "t": "rc:vault.ssh.granted", "req_id": "s1", "ticket_id": "k1",
                "ticket": "the-signed-ticket", "expires_at_ms": 1_700_000_120_000_i64,
                "os": "linux", "account": "console_user",
            })
        );
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(v).unwrap(),
            ServerMsg::VaultSshGranted { ref account, .. } if account == "console_user"
        ));
    }

    /// FR-90 P3-9-1 — a person's ask for one field, as it crosses the wire: no
    /// session and no person in it, a `value` field left out, and the ask the
    /// vault's. A lease's frame with its session left out is no such ask: it
    /// does not decode at all, so a request with no session never reaches the
    /// path that believes one.
    #[test]
    fn vault_connect_wire_shape_is_locked() {
        let ask = ClientMsg::VaultConnect {
            req_id: "c1".into(),
            secret: "db/orders".into(),
            field: "password".into(),
            audience: "db.internal:5432".into(),
            ttl_secs: 600,
        };
        let v = serde_json::to_value(&ask).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "t": "rc:vault.connect", "req_id": "c1", "secret": "db/orders",
                "field": "password", "audience": "db.internal:5432",
                "ttl_secs": 600,
            })
        );
        let back: ClientMsg = serde_json::from_value(v).unwrap();
        assert!(matches!(
            back,
            ClientMsg::VaultConnect { ref field, ttl_secs: 600, .. } if field == "password"
        ));
        assert_eq!(back.namespace(), Owner::Vault);

        let value = ClientMsg::VaultConnect {
            req_id: "c2".into(),
            secret: "api/billing".into(),
            field: String::new(),
            audience: "api.internal:443".into(),
            ttl_secs: 60,
        };
        let v = serde_json::to_value(&value).unwrap();
        assert!(v.get("field").is_none(), "{v}");
        assert!(matches!(
            serde_json::from_value::<ClientMsg>(v).unwrap(),
            ClientMsg::VaultConnect { ref field, .. } if field.is_empty()
        ));

        let sessionless = serde_json::json!({
            "t": "rc:vault.lease", "req_id": "c3", "fence": 1, "secret": "db/orders",
            "mode": "proxy", "audience": "db.internal:5432", "ttl_secs": 60,
        });
        assert!(serde_json::from_value::<ClientMsg>(sessionless).is_err());

        // An ask that names no upstream still decodes, so the vault can answer
        // it (`bad_request`) rather than leave the device waiting.
        let nowhere = serde_json::json!({
            "t": "rc:vault.connect", "req_id": "c4", "secret": "db/orders", "ttl_secs": 60,
        });
        assert!(matches!(
            serde_json::from_value::<ClientMsg>(nowhere).unwrap(),
            ClientMsg::VaultConnect { ref audience, .. } if audience.is_empty()
        ));
    }

    /// FR-83 — the ack's wire shape. "Recorded" is the ABSENCE of `refused`,
    /// so the commonest ack on the wire is the smallest one, and the
    /// spellings of the refusals are a compatibility surface like the RpcCap
    /// verbs.
    #[test]
    fn ssh_grant_ack_wire_shape_is_locked() {
        use crate::models::SshGrantRefusal;

        let recorded = ClientMsg::SshGrantAck {
            grant_id: "g1".into(),
            refused: None,
        };
        let v = serde_json::to_value(&recorded).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"t": "rc:ssh.grant_ack", "grant_id": "g1"})
        );

        for (r, want) in [
            (SshGrantRefusal::SshDisabled, "ssh_disabled"),
            (SshGrantRefusal::Expired, "expired"),
            (SshGrantRefusal::Invalid, "invalid"),
            (SshGrantRefusal::Other, "other"),
        ] {
            let m = ClientMsg::SshGrantAck {
                grant_id: "g1".into(),
                refused: Some(r),
            };
            let v = serde_json::to_value(&m).unwrap();
            assert_eq!(v["refused"], want, "refusal wire spelling changed");
            match serde_json::from_value::<ClientMsg>(v).unwrap() {
                ClientMsg::SshGrantAck { refused, .. } => assert_eq!(refused, Some(r)),
                other => panic!("wrong variant: {other:?}"),
            }
        }
    }

    /// FR-83 — the lenient decode, in both directions that matter.
    ///
    /// A refusal this build does not know must stay a REFUSAL (a strict
    /// decode would fail the frame, and the caller would wait out the bound
    /// only to be told "unconfirmed"), and must never collapse into
    /// "recorded" (which would send a caller to dial a device that said no).
    #[test]
    fn an_unknown_refusal_is_still_a_refusal_and_never_a_confirmation() {
        use crate::models::SshGrantRefusal;

        // Always PRESENT here, explicit `null` included; absence is checked
        // separately below.
        let parse = |refused: serde_json::Value| {
            let mut v = serde_json::json!({"t": "rc:ssh.grant_ack", "grant_id": "g1"});
            v["refused"] = refused;
            match serde_json::from_value::<ClientMsg>(v).expect("the frame must still parse") {
                ClientMsg::SshGrantAck { refused, .. } => refused,
                other => panic!("wrong variant: {other:?}"),
            }
        };
        assert_eq!(
            parse(serde_json::json!("a_reason_from_2027")),
            Some(SshGrantRefusal::Other)
        );
        assert_eq!(
            parse(serde_json::json!({"quota": 3})),
            Some(SshGrantRefusal::Other),
            "a reason that grew a payload is still a refusal"
        );
        assert_eq!(
            parse(serde_json::json!("ssh_disabled")),
            Some(SshGrantRefusal::SshDisabled)
        );
        // Only absent / null means recorded.
        assert_eq!(parse(serde_json::Value::Null), None);
        let absent: ClientMsg =
            serde_json::from_str(r#"{"t":"rc:ssh.grant_ack","grant_id":"g1"}"#).unwrap();
        assert!(matches!(
            absent,
            ClientMsg::SshGrantAck { refused: None, .. }
        ));
    }

    /// FR-90 — the start frame carries metadata and nothing else. Its field
    /// set is spelled out here so adding a `prompt`, a `context` or an
    /// `env` is a deliberate edit to this test — the server never carries
    /// session content (`docs/roomler-hive-design.md` §3.3), and the first
    /// prompt reaches the harness over the viewer peer. Also locks that it
    /// names no ACCOUNT: which local account runs a session is the device's
    /// decision (`hive_accounts`), never the server's.
    #[test]
    fn hive_start_is_metadata_only_and_names_no_account() {
        let sid = ObjectId::new();
        let uid = ObjectId::new();
        let m = ServerMsg::HiveStart {
            session_id: sid,
            harness: crate::hive::HARNESS_CLAUDE_CODE.into(),
            harness_session: "0b9e3c7e-6a43-4a43-9d63-2d1b0d1c2f10".into(),
            fence: 1,
            folder: "/home/dev/src/app".into(),
            user_id: uid,
            user_email: "dev@example.com".into(),
            caller: "Dev".into(),
            resume: false,
            replicated: false,
            lease: false,
            fork_of: None,
            from_terminal: false,
        };
        let v = serde_json::to_value(&m).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "caller",
                "fence",
                "folder",
                "harness",
                "harness_session",
                "resume",
                "session_id",
                "t",
                "user_email",
                "user_id",
            ],
            "an unreplicated start is the frame every earlier server sent"
        );
        assert_eq!(v["t"], "rc:hive.start");
        assert_eq!(v["session_id"], sid.to_hex(), "ObjectIds are raw hex");
        assert_eq!(v["user_id"], uid.to_hex());
        match serde_json::from_value::<ServerMsg>(v).unwrap() {
            ServerMsg::HiveStart {
                session_id,
                fence,
                replicated,
                ..
            } => assert_eq!((session_id, fence, replicated), (sid, 1, false)),
            other => panic!("wrong variant: {other:?}"),
        }
        // P2c-3 — a replicated start says so, and only then.
        let mut replicated = serde_json::to_value(&m).unwrap();
        replicated["replicated"] = serde_json::json!(true);
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(replicated).unwrap(),
            ServerMsg::HiveStart {
                replicated: true,
                lease: false,
                ..
            }
        ));
        // P2e-2 — and a leased one says that too, and only then.
        let leased = ServerMsg::HiveStart {
            session_id: sid,
            harness: crate::hive::HARNESS_CLAUDE_CODE.into(),
            harness_session: "0b9e3c7e-6a43-4a43-9d63-2d1b0d1c2f10".into(),
            fence: 1,
            folder: "/home/dev/src/app".into(),
            user_id: uid,
            user_email: "dev@example.com".into(),
            caller: "Dev".into(),
            resume: false,
            replicated: true,
            lease: true,
            fork_of: None,
            from_terminal: false,
        };
        let v = serde_json::to_value(&leased).unwrap();
        assert_eq!(
            (v["replicated"].clone(), v["lease"].clone()),
            (true.into(), true.into())
        );
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(v).unwrap(),
            ServerMsg::HiveStart { lease: true, .. }
        ));
        // P2f-3 — a fork's start names what it was made from, and only then.
        let parent = ObjectId::new();
        let fork = ServerMsg::HiveStart {
            session_id: sid,
            harness: crate::hive::HARNESS_CLAUDE_CODE.into(),
            harness_session: "0b9e3c7e-6a43-4a43-9d63-2d1b0d1c2f10".into(),
            fence: 1,
            folder: "/home/dev/src/app".into(),
            user_id: uid,
            user_email: "dev@example.com".into(),
            caller: "Dev".into(),
            resume: false,
            replicated: false,
            lease: false,
            fork_of: Some(crate::hive::HiveForkOf {
                session_id: parent,
                harness_session: "9d1c2f10-6a43-4a43-9d63-2d1b0b9e3c7e".into(),
            }),
            from_terminal: false,
        };
        let v = serde_json::to_value(&fork).unwrap();
        assert_eq!(
            v["fork_of"],
            serde_json::json!({"session_id": parent.to_hex(),
                               "harness_session": "9d1c2f10-6a43-4a43-9d63-2d1b0b9e3c7e"})
        );
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(v).unwrap(),
            ServerMsg::HiveStart { fork_of: Some(f), .. } if f.session_id == parent
        ));
        // P2f-4 — a terminal session made a managed one says so, and only
        // then: every frame above went without the key.
        let mut managed = serde_json::to_value(&m).unwrap();
        assert!(managed.get("from_terminal").is_none());
        managed["from_terminal"] = serde_json::json!(true);
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(managed).unwrap(),
            ServerMsg::HiveStart {
                from_terminal: true,
                fork_of: None,
                ..
            }
        ));
    }

    /// FR-90 P2e-2 — the lease word's field set is locked: which session, at
    /// which fence. It carries no content, and nothing answers it.
    #[test]
    fn hive_lease_wire_shape_is_locked() {
        let sid = ObjectId::new();
        let m = ServerMsg::HiveLease {
            session_id: sid,
            fence: 3,
        };
        assert_eq!(
            serde_json::to_value(&m).unwrap(),
            serde_json::json!({"t": "rc:hive.lease", "session_id": sid.to_hex(), "fence": 3})
        );
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(serde_json::to_value(&m).unwrap()).unwrap(),
            ServerMsg::HiveLease { fence: 3, .. }
        ));
    }

    /// FR-90 P2c-3 — the join's field set is locked: which session, at which
    /// fence, in which role. It carries no content and no source; and a role
    /// this build cannot name still decodes, as `None`, so the device refuses
    /// it instead of dropping it unanswered.
    #[test]
    fn hive_replica_join_wire_shape_is_locked() {
        use crate::hive::{HiveFenceMark, HiveReplicaRole};

        let sid = ObjectId::new();
        let m = ServerMsg::HiveReplicaJoin {
            session_id: sid,
            fence: 2,
            role: Some(HiveReplicaRole::Archive),
            fences: Vec::new(),
        };
        assert_eq!(
            serde_json::to_value(&m).unwrap(),
            serde_json::json!({
                "t": "rc:hive.replica.join", "session_id": sid.to_hex(), "fence": 2,
                "role": "archive"
            }),
            "a session no promotion moved carries no marks, as before P2e-5b"
        );
        // P2e-5b — where each superseded fence ended, numbers and a hash.
        let hash = "ab".repeat(32);
        let marked = ServerMsg::HiveReplicaJoin {
            session_id: sid,
            fence: 3,
            role: Some(HiveReplicaRole::Owner),
            fences: vec![
                HiveFenceMark {
                    fence: 1,
                    seq: 40,
                    hash: hash.clone(),
                },
                HiveFenceMark {
                    fence: 2,
                    seq: 55,
                    hash: hash.clone(),
                },
            ],
        };
        assert_eq!(
            serde_json::to_value(&marked).unwrap(),
            serde_json::json!({
                "t": "rc:hive.replica.join", "session_id": sid.to_hex(), "fence": 3,
                "role": "owner",
                "fences": [
                    {"fence": 1, "seq": 40, "hash": hash},
                    {"fence": 2, "seq": 55, "hash": hash}
                ]
            }),
            "a moved session's join names where each fence ended"
        );
        let back: ServerMsg =
            serde_json::from_value(serde_json::to_value(&marked).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&back).unwrap(),
            serde_json::to_value(&marked).unwrap(),
            "the marks come back as they went"
        );
        let unknown = serde_json::json!({
            "t": "rc:hive.replica.join", "session_id": sid.to_hex(), "fence": 2, "role": "witness"
        });
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(unknown).unwrap(),
            ServerMsg::HiveReplicaJoin {
                fence: 2,
                role: None,
                ..
            }
        ));
    }

    /// FR-90 P2c-3 — "joined" is the ABSENCE of `refused`, as for the start
    /// ack; an unknown refusal is still a refusal and never a copy counted.
    #[test]
    fn hive_replica_join_ack_wire_shape_and_lenient_refusal() {
        use crate::hive::HiveJoinRefusal;

        let sid = ObjectId::new();
        let joined = ClientMsg::HiveReplicaJoinAck {
            session_id: sid,
            fence: 2,
            refused: None,
            detail: None,
        };
        assert_eq!(
            serde_json::to_value(&joined).unwrap(),
            serde_json::json!({"t": "rc:hive.replica.join_ack", "session_id": sid.to_hex(), "fence": 2})
        );
        assert_eq!(joined.namespace(), Owner::Hive);
        let parse = |refused: serde_json::Value| {
            let mut v = serde_json::json!({
                "t": "rc:hive.replica.join_ack", "session_id": sid.to_hex(), "fence": 2
            });
            v["refused"] = refused;
            match serde_json::from_value::<ClientMsg>(v).expect("the frame must still parse") {
                ClientMsg::HiveReplicaJoinAck { refused, .. } => refused,
                other => panic!("wrong variant: {other:?}"),
            }
        };
        assert_eq!(
            parse(serde_json::json!("replica_disabled")),
            Some(HiveJoinRefusal::ReplicaDisabled)
        );
        assert_eq!(
            parse(serde_json::json!("a_word_from_2027")),
            Some(HiveJoinRefusal::Other)
        );
        assert_eq!(
            parse(serde_json::json!({"x": 1})),
            Some(HiveJoinRefusal::Other)
        );
        assert_eq!(parse(serde_json::Value::Null), None);
    }

    /// FR-90 P2d — the stream's handshake, both directions, field sets locked:
    /// numbers, hashes, keys, addresses and a token, never content. A rung
    /// this build cannot name still decodes, as `None`, and is refused in
    /// words; an unknown refusal is still a refusal.
    #[test]
    fn hive_replica_stream_wire_shapes_are_locked() {
        use crate::hive::{HiveStreamPath, HiveStreamRefusal};

        let (sid, gid, dev) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let hash = "ab".repeat(32);
        let key = "cd".repeat(32);
        let want = ClientMsg::HiveReplicaWant {
            session_id: sid,
            fence: 2,
            seq: 7,
            hash: hash.clone(),
            path: Some(HiveStreamPath::Direct),
            derp_pubkey: None,
        };
        assert_eq!(
            serde_json::to_value(&want).unwrap(),
            serde_json::json!({
                "t": "rc:hive.replica.want", "session_id": sid.to_hex(), "fence": 2,
                "seq": 7, "hash": hash, "path": "direct"
            })
        );
        let unnamed = serde_json::json!({
            "t": "rc:hive.replica.want", "session_id": sid.to_hex(), "fence": 2,
            "seq": 7, "hash": hash, "path": "smoke_signals"
        });
        assert!(matches!(
            serde_json::from_value::<ClientMsg>(unnamed).unwrap(),
            ClientMsg::HiveReplicaWant { path: None, .. }
        ));

        let ready = ClientMsg::HiveReplicaReady {
            grant_id: gid,
            refused: None,
            detail: None,
            cert_fingerprint: Some(hash.clone()),
            addrs: vec!["192.0.2.7:41641".into()],
            derp_pubkey: None,
        };
        assert_eq!(
            serde_json::to_value(&ready).unwrap(),
            serde_json::json!({
                "t": "rc:hive.replica.ready", "grant_id": gid.to_hex(),
                "cert_fingerprint": hash, "addrs": ["192.0.2.7:41641"]
            })
        );
        let refused = serde_json::json!({
            "t": "rc:hive.replica.ready", "grant_id": gid.to_hex(), "refused": "a_word_from_2027"
        });
        assert!(matches!(
            serde_json::from_value::<ClientMsg>(refused).unwrap(),
            ClientMsg::HiveReplicaReady {
                refused: Some(HiveStreamRefusal::Other),
                ..
            }
        ));
        let candidate = ClientMsg::HiveReplicaCandidate {
            grant_id: gid,
            addr: "198.51.100.4:3478".into(),
        };
        assert_eq!(
            serde_json::to_value(&candidate).unwrap(),
            serde_json::json!({
                "t": "rc:hive.replica.candidate", "grant_id": gid.to_hex(),
                "addr": "198.51.100.4:3478"
            })
        );
        let close = ClientMsg::HiveReplicaClose {
            grant_id: gid,
            reason: "replaced".into(),
        };
        assert_eq!(
            serde_json::to_value(&close).unwrap(),
            serde_json::json!({"t": "rc:hive.replica.close", "grant_id": gid.to_hex(), "reason": "replaced"})
        );
        for m in [&want, &ready, &candidate, &close] {
            assert_eq!(m.namespace(), Owner::Hive);
        }

        let grant = ServerMsg::HiveReplicaGrant {
            grant_id: gid,
            session_id: sid,
            fence: 2,
            member_id: dev,
            path: Some(HiveStreamPath::Derp),
            token: "t0k".into(),
            ice_servers: Vec::new(),
            ttl_secs: 600,
            member_derp_pubkey: Some(key.clone()),
        };
        assert_eq!(
            serde_json::to_value(&grant).unwrap(),
            serde_json::json!({
                "t": "rc:hive.replica.grant", "grant_id": gid.to_hex(), "session_id": sid.to_hex(),
                "fence": 2, "member_id": dev.to_hex(), "path": "derp", "token": "t0k",
                "ice_servers": [], "ttl_secs": 600, "member_derp_pubkey": key
            })
        );
        let dial = ServerMsg::HiveReplicaDial {
            grant_id: gid,
            session_id: sid,
            fence: 2,
            source_id: dev,
            path: Some(HiveStreamPath::Relay),
            token: "t0k".into(),
            cert_fingerprint: hash.clone(),
            addrs: vec!["203.0.113.9:49152".into()],
            derp_pubkey: None,
            ice_servers: Vec::new(),
            ttl_secs: 600,
        };
        assert_eq!(
            serde_json::to_value(&dial).unwrap(),
            serde_json::json!({
                "t": "rc:hive.replica.dial", "grant_id": gid.to_hex(), "session_id": sid.to_hex(),
                "fence": 2, "source_id": dev.to_hex(), "path": "relay", "token": "t0k",
                "cert_fingerprint": hash, "addrs": ["203.0.113.9:49152"],
                "ice_servers": [], "ttl_secs": 600
            })
        );
        let no = ServerMsg::HiveReplicaRefused {
            session_id: sid,
            fence: 2,
            path: Some(HiveStreamPath::Direct),
            reason: Some(HiveStreamRefusal::SourceOffline),
            detail: None,
        };
        assert_eq!(
            serde_json::to_value(&no).unwrap(),
            serde_json::json!({
                "t": "rc:hive.replica.refused", "session_id": sid.to_hex(), "fence": 2,
                "path": "direct", "reason": "source_offline"
            })
        );
        assert_eq!(
            serde_json::to_value(ServerMsg::HiveReplicaCandidate {
                grant_id: gid,
                addr: "198.51.100.4:3478".into()
            })
            .unwrap(),
            serde_json::json!({
                "t": "rc:hive.replica.candidate", "grant_id": gid.to_hex(),
                "addr": "198.51.100.4:3478"
            })
        );
        assert_eq!(
            serde_json::to_value(ServerMsg::HiveReplicaClose {
                grant_id: gid,
                reason: "member_left".into()
            })
            .unwrap(),
            serde_json::json!({"t": "rc:hive.replica.close", "grant_id": gid.to_hex(), "reason": "member_left"})
        );
    }

    /// FR-90 P2c-3 — a tip and a manifest are numbers and hashes. Their field
    /// sets are spelled out so a `summary`, an `event` or a `title` riding
    /// along is a deliberate edit to this test: the server learns how fresh a
    /// copy is, never what is in it.
    #[test]
    fn hive_replica_tip_and_manifest_are_numbers_and_hashes_only() {
        use crate::hive::{HiveCheckpointMark, HiveReplicaManifestEntry};

        let sid = ObjectId::new();
        let hash = "ab".repeat(32);
        let tip = ClientMsg::HiveReplicaTip {
            session_id: sid,
            fence: 1,
            seq: 42,
            hash: hash.clone(),
            checkpoint: Some(HiveCheckpointMark {
                seq: 40,
                hash: "cd".repeat(32),
            }),
        };
        let v = serde_json::to_value(&tip).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["checkpoint", "fence", "hash", "seq", "session_id", "t"]
        );
        let mut mark: Vec<&str> = v["checkpoint"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        mark.sort_unstable();
        assert_eq!(mark, ["hash", "seq"]);
        assert_eq!(v["t"], "rc:hive.replica.tip");
        assert_eq!(tip.namespace(), Owner::Hive);

        let manifest = ClientMsg::HiveReplicaManifest {
            sessions: vec![HiveReplicaManifestEntry {
                session_id: sid,
                fence: 1,
                seq: 42,
                hash,
                checkpoint: None,
            }],
            purged: Vec::new(),
        };
        let v = serde_json::to_value(&manifest).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["sessions", "t"]);
        let mut entry: Vec<&str> = v["sessions"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        entry.sort_unstable();
        assert_eq!(
            entry,
            ["fence", "hash", "seq", "session_id"],
            "no checkpoint is absent, not null"
        );
        assert_eq!(v["sessions"][0]["session_id"], sid.to_hex());
        assert!(matches!(
            serde_json::from_value::<ClientMsg>(serde_json::json!({"t": "rc:hive.replica.manifest"}))
                .unwrap(),
            ClientMsg::HiveReplicaManifest { ref sessions, ref purged }
                if sessions.is_empty() && purged.is_empty()
        ));
        assert_eq!(manifest.namespace(), Owner::Hive);

        // P2g-3c — a copy its own clock purged: an id and a time, nothing else.
        let purged = ClientMsg::HiveReplicaManifest {
            sessions: Vec::new(),
            purged: vec![crate::hive::HiveCopyPurged {
                session_id: sid,
                at_ms: 1_700_000_000_000,
            }],
        };
        assert_eq!(
            serde_json::to_value(&purged).unwrap(),
            serde_json::json!({"t": "rc:hive.replica.manifest", "sessions": [],
                               "purged": [{"session_id": sid.to_hex(), "at_ms": 1_700_000_000_000_i64}]})
        );
    }

    /// FR-90 P2g-3c — the retention word's ask and answer: ids, days and an
    /// end, the field sets locked. A live session's word names no end, absent
    /// rather than null, and an answer with no words is still an answer.
    #[test]
    fn hive_retain_frames_wire_shape_is_locked() {
        use crate::hive::HiveRetainWord;

        let (live, over) = (ObjectId::new(), ObjectId::new());
        let ask = ClientMsg::HiveRetainAsk {
            sessions: vec![live, over],
        };
        assert_eq!(
            serde_json::to_value(&ask).unwrap(),
            serde_json::json!({"t": "rc:hive.retain_ask",
                               "sessions": [live.to_hex(), over.to_hex()]})
        );
        assert_eq!(ask.namespace(), Owner::Hive);
        assert!(matches!(
            serde_json::from_value::<ClientMsg>(serde_json::json!({"t": "rc:hive.retain_ask"}))
                .unwrap(),
            ClientMsg::HiveRetainAsk { ref sessions } if sessions.is_empty()
        ));

        let answer = ServerMsg::HiveRetain {
            words: vec![
                HiveRetainWord {
                    session_id: live,
                    days: 90,
                    ended_at_ms: None,
                },
                HiveRetainWord {
                    session_id: over,
                    days: 0,
                    ended_at_ms: Some(1_700_000_000_000),
                },
            ],
        };
        assert_eq!(
            serde_json::to_value(&answer).unwrap(),
            serde_json::json!({"t": "rc:hive.retain", "words": [
                {"session_id": live.to_hex(), "days": 90},
                {"session_id": over.to_hex(), "days": 0, "ended_at_ms": 1_700_000_000_000_i64},
            ]})
        );
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(serde_json::json!({"t": "rc:hive.retain"})).unwrap(),
            ServerMsg::HiveRetain { ref words } if words.is_empty()
        ));
    }

    /// FR-90 P1e — the core-memory frame's field set is locked: who, which
    /// fence, which brain revision, and the two documents — nothing a session
    /// produced can ride along.
    #[test]
    fn hive_memory_wire_shape_is_locked() {
        let sid = ObjectId::new();
        let m = ServerMsg::HiveMemory {
            session_id: sid,
            fence: 1,
            brain_rev: 7,
            claude_md: Some("# Organization memory\n\n- Deploys go through `release`.\n".into()),
            memory_md: None,
        };
        let v = serde_json::to_value(&m).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["brain_rev", "claude_md", "fence", "session_id", "t"],
            "an empty document is absent, not null: {v}"
        );
        assert_eq!(v["t"], "rc:hive.memory");
        assert_eq!(v["session_id"], sid.to_hex(), "ObjectIds are raw hex");
        match serde_json::from_value::<ServerMsg>(v).unwrap() {
            ServerMsg::HiveMemory {
                brain_rev,
                memory_md,
                ..
            } => assert_eq!((brain_rev, memory_md), (7, None)),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// FR-90 P1j — the adopt offer's field set is locked: whose (the keys and
    /// the account), which harness session, where. No title and no prompt can
    /// ride along: a terminal's first prompt is content.
    #[test]
    fn hive_adopt_wire_shape_is_locked() {
        let m = ClientMsg::HiveAdopt {
            adopt_id: "a1".into(),
            harness_session: "6f1c8a2e-3b7d-4e5f-9a10-2b3c4d5e6f70".into(),
            keys: vec!["dev@example.com".into()],
            account: "dev".into(),
            folder: "/home/dev/work".into(),
        };
        let v = serde_json::to_value(&m).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "account",
                "adopt_id",
                "folder",
                "harness_session",
                "keys",
                "t"
            ]
        );
        assert_eq!(v["t"], "rc:hive.adopt");
        assert!(matches!(
            serde_json::from_value::<ClientMsg>(v).unwrap(),
            ClientMsg::HiveAdopt { ref keys, .. } if keys.len() == 1
        ));
        assert_eq!(m.namespace(), Owner::Hive);
    }

    /// FR-90 P1j — "adopted" is the ABSENCE of `refused`, as for the start
    /// ack; an unknown refusal is still a refusal and never an adoption.
    #[test]
    fn hive_adopt_ack_wire_shape_and_lenient_refusal() {
        use crate::hive::HiveAdoptRefusal;

        let sid = ObjectId::new();
        let adopted = ServerMsg::HiveAdoptAck {
            adopt_id: "a1".into(),
            session_id: Some(sid),
            fence: Some(1),
            refused: None,
        };
        assert_eq!(
            serde_json::to_value(&adopted).unwrap(),
            serde_json::json!({
                "t": "rc:hive.adopt_ack", "adopt_id": "a1", "session_id": sid.to_hex(), "fence": 1
            })
        );
        let refused = ServerMsg::HiveAdoptAck {
            adopt_id: "a2".into(),
            session_id: None,
            fence: None,
            refused: Some(HiveAdoptRefusal::AmbiguousAccount),
        };
        assert_eq!(
            serde_json::to_value(&refused).unwrap(),
            serde_json::json!({"t": "rc:hive.adopt_ack", "adopt_id": "a2", "refused": "ambiguous_account"})
        );
        let unknown = serde_json::json!({"t": "rc:hive.adopt_ack", "adopt_id": "a3", "refused": "solar_flare"});
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(unknown).unwrap(),
            ServerMsg::HiveAdoptAck {
                refused: Some(HiveAdoptRefusal::Other),
                session_id: None,
                ..
            }
        ));
    }

    #[test]
    fn hive_stop_wire_shape_is_locked() {
        let sid = ObjectId::new();
        let m = ServerMsg::HiveStop {
            session_id: sid,
            fence: 3,
            reason: "owner".into(),
        };
        assert_eq!(
            serde_json::to_value(&m).unwrap(),
            serde_json::json!({
                "t": "rc:hive.stop", "session_id": sid.to_hex(), "fence": 3, "reason": "owner"
            })
        );
        // A stop from a server that sent no reason still decodes.
        let bare = serde_json::json!({"t": "rc:hive.stop", "session_id": sid.to_hex(), "fence": 3});
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(bare).unwrap(),
            ServerMsg::HiveStop { fence: 3, .. }
        ));
    }

    /// FR-90 P2e-1 — the demote names the fence the lease is at NOW, not the
    /// one the device ran: the device ends what it runs below it.
    #[test]
    fn hive_demote_wire_shape_is_locked() {
        let sid = ObjectId::new();
        let m = ServerMsg::HiveDemote {
            session_id: sid,
            fence: 4,
            reason: "not_location".into(),
        };
        assert_eq!(
            serde_json::to_value(&m).unwrap(),
            serde_json::json!({
                "t": "rc:hive.demote", "session_id": sid.to_hex(), "fence": 4,
                "reason": "not_location"
            })
        );
        let bare =
            serde_json::json!({"t": "rc:hive.demote", "session_id": sid.to_hex(), "fence": 4});
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(bare).unwrap(),
            ServerMsg::HiveDemote { fence: 4, reason, .. } if reason.is_empty()
        ));
    }

    /// FR-90 P2e-3 — WIRE LOCK on the promotion's three server frames:
    /// metadata and numbers only, every field named, nothing a prompt or a
    /// transcript line could ride in.
    #[test]
    fn hive_promotion_frames_wire_shape_is_locked() {
        let (sid, uid, from) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let prepare = ServerMsg::HivePrepare {
            session_id: sid,
            fence: 2,
            harness: "claude-code".into(),
            harness_session: "u-1".into(),
            folder: "/srv/app".into(),
            user_id: uid,
            user_email: "a@example.com".into(),
            caller: "Alice".into(),
            teleport: false,
            have_want: false,
        };
        let promotion_prepare = serde_json::json!({
            "t": "rc:hive.prepare", "session_id": sid.to_hex(), "fence": 2,
            "harness": "claude-code", "harness_session": "u-1", "folder": "/srv/app",
            "user_id": uid.to_hex(), "user_email": "a@example.com", "caller": "Alice"
        });
        assert_eq!(
            serde_json::to_value(&prepare).unwrap(),
            promotion_prepare,
            "a promotion's prepare is the frame it was before P2f-1a"
        );
        // P2f-1a — a teleport's says so, and a prepare that does not say is
        // a promotion's.
        let teleport = ServerMsg::HivePrepare {
            session_id: sid,
            fence: 2,
            harness: "claude-code".into(),
            harness_session: "u-1".into(),
            folder: "/srv/app".into(),
            user_id: uid,
            user_email: "a@example.com".into(),
            caller: "Alice".into(),
            teleport: true,
            have_want: false,
        };
        let mut teleport_prepare = promotion_prepare.clone();
        teleport_prepare["teleport"] = serde_json::json!(true);
        assert_eq!(serde_json::to_value(&teleport).unwrap(), teleport_prepare);
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(teleport_prepare).unwrap(),
            ServerMsg::HivePrepare { teleport: true, .. }
        ));
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(promotion_prepare).unwrap(),
            ServerMsg::HivePrepare {
                teleport: false,
                ..
            }
        ));
        // P2f-2b — a teleport whose target may take the workspace against
        // its clone says so too; a prepare that does not say takes it whole.
        let mut have_want = teleport.clone();
        if let ServerMsg::HivePrepare { have_want: hw, .. } = &mut have_want {
            *hw = true;
        }
        let mut have_want_prepare = serde_json::to_value(&teleport).unwrap();
        have_want_prepare["have_want"] = serde_json::json!(true);
        assert_eq!(serde_json::to_value(&have_want).unwrap(), have_want_prepare);
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(serde_json::to_value(&teleport).unwrap()).unwrap(),
            ServerMsg::HivePrepare {
                teleport: true,
                have_want: false,
                ..
            }
        ));
        let drain = ServerMsg::HiveDrain {
            session_id: sid,
            fence: 1,
        };
        assert_eq!(
            serde_json::to_value(&drain).unwrap(),
            serde_json::json!({"t": "rc:hive.drain", "session_id": sid.to_hex(), "fence": 1})
        );
        let mv = ServerMsg::HiveMove {
            session_id: sid,
            fence: 2,
            turns: 7,
            from_device_id: from,
            from_device_name: "mars".into(),
            from_folder: "/srv/app".into(),
            moved_by: uid,
            moved_by_name: "Alice".into(),
            moved_at_ms: 1_760_000_000_000,
            earlier: Vec::new(),
        };
        let v = serde_json::to_value(&mv).unwrap();
        // P2f-5 — no earlier place: the frame every earlier server sent.
        assert_eq!(
            v,
            serde_json::json!({
                "t": "rc:hive.move", "session_id": sid.to_hex(), "fence": 2, "turns": 7,
                "from_device_id": from.to_hex(), "from_device_name": "mars",
                "from_folder": "/srv/app", "moved_by": uid.to_hex(),
                "moved_by_name": "Alice", "moved_at_ms": 1_760_000_000_000_u64
            }),
            "no earlier place: the frame every earlier server sent"
        );
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(v).unwrap(),
            ServerMsg::HiveMove {
                turns: 7,
                fence: 2,
                ..
            }
        ));
        // P2f-5 — and the places before it, names and folders only.
        let mut many = mv.clone();
        if let ServerMsg::HiveMove { earlier, .. } = &mut many {
            earlier.push(crate::hive::HivePlace {
                device_name: "laptop".into(),
                folder: "C:\\dev\\app".into(),
            });
        }
        let v = serde_json::to_value(&many).unwrap();
        assert_eq!(
            v["earlier"],
            serde_json::json!([{"device_name": "laptop", "folder": "C:\\dev\\app"}]),
            "{v}"
        );
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(v).unwrap(),
            ServerMsg::HiveMove { earlier, .. } if earlier.len() == 1
        ));
    }

    /// FR-90 P2g — the purge and its acknowledgement: ids and words only, the
    /// field sets locked; a part's unknown word, or none, is `failed`, so a
    /// newer device's answer never completes a purge it did not do.
    #[test]
    fn hive_purge_frames_wire_shape_is_locked() {
        use crate::hive::HivePurgePart;

        let (purge, sid) = (ObjectId::new(), ObjectId::new());
        let order = ServerMsg::HivePurge {
            purge_id: purge,
            session_id: sid,
            leaving: false,
        };
        assert_eq!(
            serde_json::to_value(&order).unwrap(),
            serde_json::json!({"t": "rc:hive.purge", "purge_id": purge.to_hex(),
                               "session_id": sid.to_hex()}),
            "a whole session's purge: the wire as before"
        );
        // P2k-3 — a leaving member's copy alone says so; a frame without the
        // word, from a server before it, is a whole session's.
        let leaving = ServerMsg::HivePurge {
            purge_id: purge,
            session_id: sid,
            leaving: true,
        };
        let v = serde_json::to_value(&leaving).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"t": "rc:hive.purge", "purge_id": purge.to_hex(),
                               "session_id": sid.to_hex(), "leaving": true})
        );
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(v).unwrap(),
            ServerMsg::HivePurge { purge_id, session_id, leaving: true }
                if purge_id == purge && session_id == sid
        ));
        assert!(
            matches!(
                serde_json::from_value::<ServerMsg>(serde_json::json!({"t": "rc:hive.purge",
                    "purge_id": purge.to_hex(), "session_id": sid.to_hex()}))
                .unwrap(),
                ServerMsg::HivePurge { leaving: false, .. }
            ),
            "no word: a whole session's purge, final"
        );
        // P2g-4a — a removal's purge of everything: an id, nothing else.
        assert_eq!(
            serde_json::to_value(ServerMsg::HivePurgeAll { purge_id: purge }).unwrap(),
            serde_json::json!({"t": "rc:hive.purge_all", "purge_id": purge.to_hex()})
        );
        let ack = ClientMsg::HivePurgeAck {
            purge_id: purge,
            session_id: sid,
            store: HivePurgePart::Done,
            account: HivePurgePart::Failed,
            detail: Some("the account is not signed in".into()),
        };
        let v = serde_json::to_value(&ack).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"t": "rc:hive.purge_ack", "purge_id": purge.to_hex(),
                               "session_id": sid.to_hex(), "store": "done",
                               "account": "failed",
                               "detail": "the account is not signed in"})
        );
        assert_eq!(ack.namespace(), Owner::Hive);
        // A word this build does not know, or none at all: failed.
        let newer = serde_json::json!({"t": "rc:hive.purge_ack", "purge_id": purge.to_hex(),
                                       "session_id": sid.to_hex(), "store": "shredded",
                                       "account": null});
        assert!(matches!(
            serde_json::from_value::<ClientMsg>(newer).unwrap(),
            ClientMsg::HivePurgeAck {
                store: HivePurgePart::Failed,
                account: HivePurgePart::Failed,
                ..
            }
        ));
    }

    /// FR-90 P2e-3 — "ready" and "drained" are the ABSENCE of `refused`, and
    /// an unknown word is still a refusal: never a member ready to run what it
    /// said no to, never a primary drained that did not drain.
    #[test]
    fn hive_prepare_ack_and_drained_wire_shape_and_lenient_refusal() {
        use crate::hive::{HiveDrainRefusal, HiveRefusal};

        let sid = ObjectId::new();
        let ready = ClientMsg::HivePrepareAck {
            session_id: sid,
            fence: 2,
            refused: None,
            account: Some("dev".into()),
            detail: None,
            tip: None,
        };
        assert_eq!(
            serde_json::to_value(&ready).unwrap(),
            serde_json::json!({
                "t": "rc:hive.prepare_ack", "session_id": sid.to_hex(), "fence": 2,
                "account": "dev"
            }),
            "a ready with no tip is the frame it was before P2e-6a"
        );
        // P2e-6a — where the copy ends, numbers and a hash.
        let tipped = ClientMsg::HivePrepareAck {
            session_id: sid,
            fence: 2,
            refused: None,
            account: Some("dev".into()),
            detail: None,
            tip: Some(crate::hive::HiveCopyTip {
                fence: 1,
                seq: 41,
                hash: "cd".repeat(32),
            }),
        };
        assert_eq!(
            serde_json::to_value(&tipped).unwrap(),
            serde_json::json!({
                "t": "rc:hive.prepare_ack", "session_id": sid.to_hex(), "fence": 2,
                "account": "dev",
                "tip": {"fence": 1, "seq": 41, "hash": "cd".repeat(32)}
            }),
            "a ready names where its copy ends"
        );
        let refused: ClientMsg = serde_json::from_value(serde_json::json!({
            "t": "rc:hive.prepare_ack", "session_id": sid.to_hex(), "fence": 2,
            "refused": "some_gate_from_2027"
        }))
        .unwrap();
        assert!(matches!(
            refused,
            ClientMsg::HivePrepareAck {
                refused: Some(HiveRefusal::Other),
                ..
            }
        ));

        let hash = "ab".repeat(32);
        let drained = ClientMsg::HiveDrained {
            session_id: sid,
            fence: 1,
            seq: Some(41),
            hash: Some(hash.clone()),
            refused: None,
            detail: None,
        };
        assert_eq!(
            serde_json::to_value(&drained).unwrap(),
            serde_json::json!({
                "t": "rc:hive.drained", "session_id": sid.to_hex(), "fence": 1,
                "seq": 41, "hash": hash
            })
        );
        let not: ClientMsg = serde_json::from_value(serde_json::json!({
            "t": "rc:hive.drained", "session_id": sid.to_hex(), "fence": 1,
            "refused": "not_running"
        }))
        .unwrap();
        assert!(matches!(
            not,
            ClientMsg::HiveDrained {
                refused: Some(HiveDrainRefusal::NotRunning),
                seq: None,
                hash: None,
                ..
            }
        ));
        let unknown: ClientMsg = serde_json::from_value(serde_json::json!({
            "t": "rc:hive.drained", "session_id": sid.to_hex(), "fence": 1,
            "seq": 41, "hash": "ab".repeat(32), "refused": "busy_later"
        }))
        .unwrap();
        assert!(
            matches!(
                unknown,
                ClientMsg::HiveDrained {
                    refused: Some(HiveDrainRefusal::Other),
                    ..
                }
            ),
            "an unknown word is a refusal, whatever tip came with it"
        );
        for m in [&ready, &drained] {
            assert_eq!(m.namespace(), Owner::Hive);
        }
    }

    /// FR-90 — "accepted" is the ABSENCE of `refused`, as for FR-83's grant
    /// ack; an unknown refusal is still a refusal and never an acceptance.
    #[test]
    fn hive_start_ack_wire_shape_and_lenient_refusal() {
        use crate::hive::HiveRefusal;

        let sid = ObjectId::new();
        let accepted = ClientMsg::HiveStartAck {
            session_id: sid,
            fence: 1,
            refused: None,
            account: None,
            detail: None,
        };
        assert_eq!(
            serde_json::to_value(&accepted).unwrap(),
            serde_json::json!({"t": "rc:hive.start_ack", "session_id": sid.to_hex(), "fence": 1})
        );
        let with_account: ClientMsg = serde_json::from_value(serde_json::json!({
            "t": "rc:hive.start_ack", "session_id": sid.to_hex(), "fence": 1, "account": "dev"
        }))
        .unwrap();
        assert!(matches!(
            with_account,
            ClientMsg::HiveStartAck { refused: None, account: Some(ref a), .. } if a == "dev"
        ));

        let parse = |refused: serde_json::Value| {
            let mut v = serde_json::json!({
                "t": "rc:hive.start_ack", "session_id": sid.to_hex(), "fence": 1
            });
            v["refused"] = refused;
            match serde_json::from_value::<ClientMsg>(v).expect("the frame must still parse") {
                ClientMsg::HiveStartAck { refused, .. } => refused,
                other => panic!("wrong variant: {other:?}"),
            }
        };
        assert_eq!(
            parse(serde_json::json!("no_account")),
            Some(HiveRefusal::NoAccount)
        );
        assert_eq!(
            parse(serde_json::json!("a_reason_from_2027")),
            Some(HiveRefusal::Other)
        );
        assert_eq!(
            parse(serde_json::json!({"quota": 3})),
            Some(HiveRefusal::Other)
        );
        assert_eq!(parse(serde_json::Value::Null), None);
    }

    /// FR-90 — a state this build cannot name keeps the FRAME: the session id
    /// and fence still arrive, and `state` is `None` rather than the whole
    /// report being dropped at `debug!`.
    #[test]
    fn hive_state_survives_an_unknown_state() {
        use crate::hive::HiveRunState;

        let sid = ObjectId::new();
        let m = ClientMsg::HiveState {
            session_id: sid,
            fence: 2,
            state: Some(HiveRunState::AwaitingApproval),
            detail: None,
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "t": "rc:hive.state", "session_id": sid.to_hex(), "fence": 2,
                "state": "awaiting_approval"
            })
        );
        let newer = serde_json::json!({
            "t": "rc:hive.state", "session_id": sid.to_hex(), "fence": 2, "state": "compacting"
        });
        match serde_json::from_value::<ClientMsg>(newer).expect("the frame must still parse") {
            ClientMsg::HiveState {
                session_id,
                fence,
                state,
                ..
            } => assert_eq!((session_id, fence, state), (sid, 2, None)),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// FR-90 — a turn's stub carries its shape and nothing it said: the field
    /// set is spelled out so a `prompt`, `text`, `tool` or `output` field is a
    /// deliberate edit here, not a quiet addition that ships content through
    /// the server into a room's message store.
    #[test]
    fn hive_turn_is_a_stub_and_carries_no_content() {
        use crate::hive::HiveTurnStatus;

        let sid = ObjectId::new();
        let who = ObjectId::new();
        let m = ClientMsg::HiveTurn {
            session_id: sid,
            fence: 1,
            turn: 3,
            status: Some(HiveTurnStatus::Ok),
            prompted_by: Some(who),
            steps: 5,
            duration_ms: Some(42_000),
            cost_usd: Some(0.12),
        };
        let v = serde_json::to_value(&m).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "cost_usd",
                "duration_ms",
                "fence",
                "prompted_by",
                "session_id",
                "status",
                "steps",
                "t",
                "turn",
            ]
        );
        assert_eq!(v["t"], "rc:hive.turn");
        assert_eq!(v["prompted_by"], who.to_hex());
        assert_eq!(m.namespace(), Owner::Hive);

        // A newer device's status keeps the frame; a bare running stub parses.
        let newer = serde_json::json!({
            "t": "rc:hive.turn", "session_id": sid.to_hex(), "fence": 1, "turn": 1,
            "status": "paused"
        });
        match serde_json::from_value::<ClientMsg>(newer).expect("the frame must still parse") {
            ClientMsg::HiveTurn {
                status,
                steps,
                prompted_by,
                ..
            } => assert_eq!((status, steps, prompted_by), (None, 0, None)),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// FR-90 P1a-2 — an approval's frame says THAT a session waits for a
    /// driver, and how it ended — never which tool or what it would do. The
    /// field set is spelled out so a `tool`, `input` or `command` field is a
    /// deliberate edit here (AC5: the server's stub holds no tool arguments).
    #[test]
    fn hive_approval_is_a_stub_and_carries_no_tool_or_arguments() {
        use crate::hive::HiveApprovalStatus;

        let (sid, who) = (ObjectId::new(), ObjectId::new());
        let m = ClientMsg::HiveApproval {
            session_id: sid,
            fence: 1,
            approval_id: "0f1e2d3c4b5a6978".into(),
            turn: Some(2),
            status: Some(HiveApprovalStatus::Denied),
            answered_by: Some(who),
        };
        let v = serde_json::to_value(&m).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "answered_by",
                "approval_id",
                "fence",
                "session_id",
                "status",
                "t",
                "turn",
            ]
        );
        assert_eq!(v["t"], "rc:hive.approval");
        assert_eq!(v["answered_by"], who.to_hex());
        assert_eq!(m.namespace(), Owner::Hive);

        // A newer device's word keeps the frame; an open one needs no more.
        let newer = serde_json::json!({
            "t": "rc:hive.approval", "session_id": sid.to_hex(), "fence": 1,
            "approval_id": "a1", "status": "delegated"
        });
        match serde_json::from_value::<ClientMsg>(newer).expect("the frame must still parse") {
            ClientMsg::HiveApproval {
                status,
                turn,
                answered_by,
                ..
            } => assert_eq!((status, turn, answered_by), (None, None, None)),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// FR-90 P1b — the manifest names the sessions a device runs: ids and
    /// fences, LOCKED, so nothing about what runs in them can join the list.
    /// A malformed entry fails the whole frame, which the server then never
    /// sees — and no manifest means nothing ends, the safe direction.
    #[test]
    fn hive_manifest_names_sessions_and_nothing_in_them() {
        use crate::hive::HiveManifestEntry;

        let sid = ObjectId::new();
        let m = ClientMsg::HiveManifest {
            sessions: vec![HiveManifestEntry {
                session_id: sid,
                fence: 1,
            }],
        };
        let v = serde_json::to_value(&m).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["sessions", "t"]);
        let mut entry: Vec<&str> = v["sessions"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        entry.sort_unstable();
        assert_eq!(entry, ["fence", "session_id"]);
        assert_eq!(v["t"], "rc:hive.manifest");
        assert_eq!(v["sessions"][0]["session_id"], sid.to_hex());
        assert_eq!(m.namespace(), Owner::Hive);

        // An empty manifest is a real one: the device runs nothing.
        let empty = serde_json::json!({"t": "rc:hive.manifest", "sessions": []});
        assert!(matches!(
            serde_json::from_value::<ClientMsg>(empty).unwrap(),
            ClientMsg::HiveManifest { sessions } if sessions.is_empty()
        ));
        let broken =
            serde_json::json!({"t": "rc:hive.manifest", "sessions": [{"session_id": "x"}]});
        assert!(serde_json::from_value::<ClientMsg>(broken).is_err());
    }

    /// FR-90 P0d-2 — the viewer peer's signalling: a grant, its answer, and
    /// a WebRTC handshake. The field sets are LOCKED: the server relays these
    /// frames, and none of them may grow a field that carries what the peer
    /// is for. The grant's TTL is relative (`ttl_secs`), never a timestamp.
    #[test]
    fn the_view_frames_carry_a_handshake_and_nothing_of_the_session() {
        use crate::hive::HiveViewRefusal;

        let (grant, sid, user) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let keys = |v: &serde_json::Value| {
            let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
            k.sort_unstable();
            k
        };

        let g = serde_json::to_value(ServerMsg::HiveViewGrant {
            grant_id: grant,
            session_id: sid,
            user_id: user,
            user_name: "Alice".into(),
            may_prompt: true,
            user_email: Some("alice@example.com".into()),
            ttl_secs: 600,
        })
        .unwrap();
        assert_eq!(g["t"], "rc:hive.view.grant");
        assert_eq!(g["grant_id"], grant.to_hex());
        assert_eq!(
            keys(&g),
            [
                "grant_id",
                "may_prompt",
                "session_id",
                "t",
                "ttl_secs",
                "user_email",
                "user_id",
                "user_name"
            ]
        );
        // A reader's grant carries no address at all — not even a null.
        let reader = serde_json::to_value(ServerMsg::HiveViewGrant {
            grant_id: grant,
            session_id: sid,
            user_id: user,
            user_name: "Bob".into(),
            may_prompt: false,
            user_email: None,
            ttl_secs: 600,
        })
        .unwrap();
        assert!(reader.get("user_email").is_none(), "{reader}");
        // And a grant from a server before P1c-2 still reads.
        let older: ServerMsg = serde_json::from_value(serde_json::json!({
            "t": "rc:hive.view.grant", "grant_id": grant.to_hex(),
            "session_id": sid.to_hex(), "user_id": user.to_hex(),
            "user_name": "Carol", "may_prompt": true, "ttl_secs": 600,
        }))
        .unwrap();
        assert!(matches!(
            older,
            ServerMsg::HiveViewGrant {
                user_email: None,
                ..
            }
        ));

        let offer = serde_json::to_value(ServerMsg::HiveViewOffer {
            grant_id: grant,
            sdp: "v=0".into(),
            ice_servers: vec![],
        })
        .unwrap();
        assert_eq!(keys(&offer), ["grant_id", "ice_servers", "sdp", "t"]);
        for (frame, t) in [
            (
                ServerMsg::HiveViewRenew {
                    grant_id: grant,
                    ttl_secs: 600,
                },
                "rc:hive.view.renew",
            ),
            (
                ServerMsg::HiveViewIce {
                    grant_id: grant,
                    candidate: serde_json::json!({"candidate": "c"}),
                },
                "rc:hive.view.ice",
            ),
            (
                ServerMsg::HiveViewClose {
                    grant_id: grant,
                    reason: "viewer_left".into(),
                },
                "rc:hive.view.close",
            ),
        ] {
            assert_eq!(serde_json::to_value(frame).unwrap()["t"], t);
        }

        // The device's side — every one owned by `hive`.
        let accepted = ClientMsg::HiveViewGrantAck {
            grant_id: grant,
            refused: None,
            detail: None,
        };
        let v = serde_json::to_value(&accepted).unwrap();
        assert_eq!(keys(&v), ["grant_id", "t"], "an acceptance is just the id");
        for m in [
            accepted,
            ClientMsg::HiveViewAnswer {
                grant_id: grant,
                sdp: "v=0".into(),
            },
            ClientMsg::HiveViewIce {
                grant_id: grant,
                candidate: serde_json::json!({}),
            },
            ClientMsg::HiveViewClosed {
                grant_id: grant,
                reason: "expired".into(),
            },
        ] {
            assert_eq!(m.namespace(), Owner::Hive, "{m:?}");
        }

        // A newer device's refusal word is still a refusal.
        let newer = serde_json::json!({
            "t": "rc:hive.view.grant_ack", "grant_id": grant.to_hex(), "refused": "busy_elsewhere"
        });
        match serde_json::from_value::<ClientMsg>(newer).expect("the frame must still parse") {
            ClientMsg::HiveViewGrantAck { refused, .. } => {
                assert_eq!(refused, Some(HiveViewRefusal::Other))
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// FR-90 P2i-1 — a search grant names who searches and which sessions,
    /// and nothing more: never a query, never a word of what it may find,
    /// which travel only over the peer. Its TTL is relative, as a view's.
    #[test]
    fn a_search_grant_names_who_and_which_sessions_and_carries_no_query() {
        let (grant, user) = (ObjectId::new(), ObjectId::new());
        let sessions = vec![ObjectId::new(), ObjectId::new()];
        let g = serde_json::to_value(ServerMsg::HiveSearchGrant {
            grant_id: grant,
            user_id: user,
            sessions: sessions.clone(),
            ttl_secs: 600,
        })
        .unwrap();
        assert_eq!(g["t"], "rc:hive.search.grant");
        let mut keys: Vec<&String> = g.as_object().unwrap().keys().collect();
        keys.sort_unstable();
        assert_eq!(keys, ["grant_id", "sessions", "t", "ttl_secs", "user_id"]);
        assert_eq!(
            g["sessions"],
            serde_json::json!([sessions[0].to_hex(), sessions[1].to_hex()])
        );
        let back: ServerMsg = serde_json::from_value(g).unwrap();
        match back {
            ServerMsg::HiveSearchGrant {
                grant_id,
                sessions: s,
                ttl_secs,
                ..
            } => assert_eq!((grant_id, s, ttl_secs), (grant, sessions, 600)),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// FR-52 P3 — a device's outcome can only mean "verified" by the ABSENCE
    /// of a refusal. Anything present, whatever its shape, is a refusal.
    ///
    /// This is FR-83's rule with higher stakes: there a wrong fallback sent a
    /// caller to dial a device that said no; here it would hand an OUTSIDER a
    /// verified login the device refused.
    #[test]
    fn an_extauth_outcome_is_verified_only_when_no_refusal_is_present() {
        use crate::models::ExtauthRefusal;

        let parse = |refused: serde_json::Value| {
            let mut v = serde_json::json!({"t": "rc:extauth.outcome", "attempt_id": "a1"});
            v["refused"] = refused;
            match serde_json::from_value::<ClientMsg>(v).expect("the frame must still parse") {
                ClientMsg::ExtauthOutcome { refused, .. } => refused,
                other => panic!("wrong variant: {other:?}"),
            }
        };
        assert_eq!(
            parse(serde_json::json!("a_reason_from_2027")),
            Some(ExtauthRefusal::Other)
        );
        assert_eq!(
            parse(serde_json::json!({"quota": 3})),
            Some(ExtauthRefusal::Other)
        );
        assert_eq!(parse(serde_json::json!(false)), Some(ExtauthRefusal::Other));
        assert_eq!(
            parse(serde_json::json!("throttled")),
            Some(ExtauthRefusal::Throttled)
        );
        assert_eq!(parse(serde_json::Value::Null), None);
        let absent: ClientMsg =
            serde_json::from_str(r#"{"t":"rc:extauth.outcome","attempt_id":"a1"}"#).unwrap();
        assert!(matches!(
            absent,
            ClientMsg::ExtauthOutcome { refused: None, .. }
        ));
    }

    /// FR-52 P3 — the refusal spellings are a compatibility surface (the
    /// browser renders them, older agents send them), and every `rc:extauth.*`
    /// frame survives the wire in both directions.
    #[test]
    fn extauth_wire_shapes_are_locked() {
        use crate::models::ExtauthRefusal;

        for (r, want) in [
            (ExtauthRefusal::Unavailable, "unavailable"),
            (ExtauthRefusal::Throttled, "throttled"),
            (ExtauthRefusal::RateLimited, "rate_limited"),
            (ExtauthRefusal::Busy, "busy"),
            (ExtauthRefusal::Malformed, "malformed"),
            (ExtauthRefusal::Rejected, "rejected"),
            (ExtauthRefusal::UnknownAttempt, "unknown_attempt"),
            (ExtauthRefusal::Other, "other"),
        ] {
            let m = ClientMsg::ExtauthOutcome {
                attempt_id: "a1".into(),
                refused: Some(r),
                retry_after_secs: None,
            };
            let v = serde_json::to_value(&m).unwrap();
            assert_eq!(v["refused"], want, "refusal wire spelling changed");
        }

        // A verified outcome is the smallest frame on the wire.
        let verified = ClientMsg::ExtauthOutcome {
            attempt_id: "a1".into(),
            refused: None,
            retry_after_secs: None,
        };
        assert_eq!(
            serde_json::to_value(&verified).unwrap(),
            serde_json::json!({"t": "rc:extauth.outcome", "attempt_id": "a1"})
        );

        let server_frames = [
            ServerMsg::ExtauthKe1 {
                attempt_id: "a1".into(),
                principal: "665f1c2a9b3e4d5f6a7b8c9d".into(),
                ke1: "a2Ux".into(),
            },
            ServerMsg::ExtauthKe3 {
                attempt_id: "a1".into(),
                principal: "665f1c2a9b3e4d5f6a7b8c9d".into(),
                ke3: "a2Uz".into(),
            },
            ServerMsg::ExtauthChallenge {
                attempt_id: "a1".into(),
                ke2: "a2Uy".into(),
            },
            ServerMsg::ExtauthResult {
                attempt_id: None,
                refused: Some(ExtauthRefusal::Unavailable),
                retry_after_secs: None,
                message: None,
            },
            ServerMsg::ExtauthResult {
                attempt_id: Some("a1".into()),
                refused: Some(ExtauthRefusal::Throttled),
                retry_after_secs: Some(30),
                message: None,
            },
            ServerMsg::ExtauthResult {
                attempt_id: Some("a1".into()),
                refused: Some(ExtauthRefusal::SessionLimit),
                retry_after_secs: None,
                message: Some("Your organization's plan runs one remote session at a time.".into()),
            },
        ];
        for m in server_frames {
            let json = serde_json::to_string(&m).unwrap();
            let back: ServerMsg = serde_json::from_str(&json).unwrap();
            assert_eq!(
                serde_json::to_string(&back).unwrap(),
                json,
                "{json} did not survive the wire"
            );
        }
    }

    /// The optional fields must all be omissible: a `session_open` carries no
    /// command, no exit code and no grant (key-list sessions). If any of them
    /// stopped defaulting, the commonest row on the wire would fail to parse.
    #[test]
    fn a_minimal_activity_report_round_trips() {
        use crate::models::SshActivityKind;

        let m = ClientMsg::SshActivity {
            grant_id: None,
            caller: String::new(),
            kind: SshActivityKind::SessionOpen,
            detail: None,
            exit_code: None,
            allowed: true,
        };
        let v = serde_json::to_value(&m).unwrap();
        let obj = v.as_object().unwrap();
        for absent in ["grant_id", "caller", "detail", "exit_code"] {
            assert!(!obj.contains_key(absent), "{absent} should be skipped");
        }
        match serde_json::from_value::<ClientMsg>(v).unwrap() {
            ClientMsg::SshActivity {
                grant_id,
                caller,
                kind,
                detail,
                exit_code,
                allowed,
            } => {
                assert!(grant_id.is_none() && detail.is_none() && exit_code.is_none());
                assert!(caller.is_empty() && allowed);
                assert_eq!(kind, SshActivityKind::SessionOpen);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// FR-99 P1d — the privacy report's wire shape: the session id as raw hex,
    /// the kind in snake case, and a reason only when there is one (an `on`
    /// carries none).
    #[test]
    fn a_privacy_activity_report_keeps_its_wire_shape() {
        use crate::models::PrivacyActivityKind;

        let sid = ObjectId::parse_str("6ad0e0359836bb5de09f59f4").unwrap();
        let m = ClientMsg::PrivacyActivity {
            session_id: sid,
            kind: PrivacyActivityKind::Off,
            reason: Some("worker_exit".into()),
        };
        assert_eq!(
            serde_json::to_value(&m).unwrap(),
            serde_json::json!({
                "t": "rc:privacy.activity",
                "session_id": "6ad0e0359836bb5de09f59f4",
                "kind": "off",
                "reason": "worker_exit",
            })
        );
        let on = serde_json::json!({
            "t": "rc:privacy.activity",
            "session_id": "6ad0e0359836bb5de09f59f4",
            "kind": "on",
        });
        match serde_json::from_value::<ClientMsg>(on.clone()).unwrap() {
            ClientMsg::PrivacyActivity {
                session_id,
                kind,
                reason,
            } => {
                assert_eq!(
                    (session_id, kind, reason),
                    (sid, PrivacyActivityKind::On, None)
                );
            }
            other => panic!("wrong variant: {other:?}"),
        }
        let back =
            serde_json::to_value(serde_json::from_value::<ClientMsg>(on.clone()).unwrap()).unwrap();
        assert_eq!(back, on, "an absent reason stays absent");
    }

    #[test]
    fn ssh_response_carries_the_host_key_on_the_device_leg() {
        // `roomler ssh` originates on THIS leg, and the dialling device has no
        // other channel to learn the key — so if it goes missing here, the
        // client is back to TOFU with no way to notice. It went missing once
        // already: the HTTP body gained the field and the hand-written wire
        // mapping kept sending the old shape, which compiles cleanly.
        const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample target";
        let m = ServerMsg::SshResponse {
            request_id: "r1".into(),
            address: Some("100.65.4.30".into()),
            port: Some(2222),
            grant_id: Some("g1".into()),
            host_pubkey: Some(KEY.into()),
            expires_at_ms: Some(123),
            error: None,
            ssh_ticket_id: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""host_pubkey""#), "must reach the wire");
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::SshResponse { host_pubkey, .. } => {
                assert_eq!(host_pubkey.as_deref(), Some(KEY))
            }
            other => panic!("wrong variant: {other:?}"),
        }

        // A refusal carries neither an address nor a key — they are only ever
        // meaningful together — and an older server that omits the field must
        // land on "cannot verify", not on something a client treats as a key.
        let refused = ServerMsg::SshResponse {
            request_id: "r2".into(),
            address: None,
            port: None,
            grant_id: None,
            host_pubkey: None,
            expires_at_ms: None,
            error: Some("nope".into()),
            ssh_ticket_id: None,
        };
        let s = serde_json::to_string(&refused).unwrap();
        assert!(!s.contains("host_pubkey"), "absent, not null");
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::SshResponse { host_pubkey, .. } => assert!(host_pubkey.is_none()),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// FR-90 P3-8-1b — an agent session's three fields cross only when set:
    /// a person's `roomler ssh` request, every grant to a device, and every
    /// answer stay byte for byte what older builds parse, and each field reads
    /// back as sent.
    #[test]
    fn ssh_session_fields_cross_only_when_set() {
        let request = |ssh_ticket: Option<&str>| ClientMsg::SshRequest {
            request_id: "q1".into(),
            target: "devbox".into(),
            public_key: "a-public-key".into(),
            session_secs: 60,
            ssh_ticket: ssh_ticket.map(String::from),
        };
        let v = serde_json::to_value(request(None)).unwrap();
        assert!(v.get("ssh_ticket").is_none(), "a person's request: {v}");
        let v = serde_json::to_value(request(Some("the-ticket"))).unwrap();
        assert_eq!(v["ssh_ticket"], "the-ticket");
        assert!(matches!(
            serde_json::from_value::<ClientMsg>(v).unwrap(),
            ClientMsg::SshRequest { ssh_ticket: Some(ref t), .. } if t == "the-ticket"
        ));

        let grant = |one_command: bool| ServerMsg::SshGrant {
            grant_id: "g1".into(),
            public_key: "a-public-key".into(),
            caller: "someone".into(),
            account_mode: "console_user".into(),
            account: None,
            expires_at_ms: 1,
            session_secs: 60,
            consent_mode: None,
            via_service: false,
            one_command,
        };
        let v = serde_json::to_value(grant(false)).unwrap();
        assert!(v.get("one_command").is_none(), "a person's grant: {v}");
        let v = serde_json::to_value(grant(true)).unwrap();
        assert_eq!(v["one_command"], true);
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(v).unwrap(),
            ServerMsg::SshGrant {
                one_command: true,
                ..
            }
        ));

        let answer = |ssh_ticket_id: Option<&str>| ServerMsg::SshResponse {
            request_id: "q1".into(),
            address: None,
            port: None,
            grant_id: None,
            host_pubkey: None,
            expires_at_ms: None,
            error: Some("refused".into()),
            ssh_ticket_id: ssh_ticket_id.map(String::from),
        };
        let v = serde_json::to_value(answer(None)).unwrap();
        assert!(v.get("ssh_ticket_id").is_none(), "{v}");
        let v = serde_json::to_value(answer(Some("k1"))).unwrap();
        assert_eq!(v["ssh_ticket_id"], "k1");
        assert!(matches!(
            serde_json::from_value::<ServerMsg>(v).unwrap(),
            ServerMsg::SshResponse { ssh_ticket_id: Some(ref k), .. } if k == "k1"
        ));
    }

    #[test]
    fn agent_hello_ssh_host_pubkey_roundtrips_and_absent_means_no_key() {
        const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExample host";
        let m = ClientMsg::AgentHello {
            machine_name: "host".into(),
            os: OsKind::Linux,
            arch: String::new(),
            arch_emulated: false,
            agent_version: "0.3.0".into(),
            displays: vec![],
            caps: Box::new(AgentCaps::default()),
            advertised_routes: vec![],
            supports_relay_regions: true,
            ssh_host_pubkey: KEY.into(),
            vault_key: String::new(),
            peer_auth_key: String::new(),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(
            s.contains(r#""ssh_host_pubkey""#),
            "field must reach the wire"
        );
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::AgentHello {
                ssh_host_pubkey, ..
            } => assert_eq!(ssh_host_pubkey, KEY),
            other => panic!("wrong variant: {other:?}"),
        }

        // An agent that predates the field — the overwhelming majority of a
        // fleet on the day this ships — must still parse, and must land on
        // "no key" rather than anything a client could mistake for one.
        let mut obj = serde_json::to_value(&m).unwrap();
        obj.as_object_mut().unwrap().remove("ssh_host_pubkey");
        match serde_json::from_value::<ClientMsg>(obj).unwrap() {
            ClientMsg::AgentHello {
                ssh_host_pubkey, ..
            } => assert!(
                ssh_host_pubkey.is_empty(),
                "a hello without the field must mean NO host key, never a wildcard"
            ),
            other => panic!("wrong variant: {other:?}"),
        }

        // And an empty key must not be emitted at all, so "absent" and
        // "empty" cannot drift into two different meanings on the wire.
        let none = ClientMsg::AgentHello {
            machine_name: "host".into(),
            os: OsKind::Linux,
            arch: String::new(),
            arch_emulated: false,
            agent_version: "0.3.0".into(),
            displays: vec![],
            caps: Box::new(AgentCaps::default()),
            advertised_routes: vec![],
            supports_relay_regions: true,
            ssh_host_pubkey: String::new(),
            vault_key: String::new(),
            peer_auth_key: String::new(),
        };
        assert!(
            !serde_json::to_string(&none)
                .unwrap()
                .contains("ssh_host_pubkey"),
            "an empty host key must be omitted, not sent as \"\""
        );
    }

    /// FR-90 P3-3a — the vault key rides the hello beside the host key: it
    /// round-trips, an empty one is not sent, and a hello without it (every
    /// agent before P3-3a) parses as a device that takes no leases. The key is
    /// made here rather than written down, as every test key in the tree is.
    #[test]
    fn agent_hello_vault_key_roundtrips_and_absent_means_no_leases() {
        use base64::Engine;
        let key = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let hello = |vault_key: String| ClientMsg::AgentHello {
            machine_name: "host".into(),
            os: OsKind::Linux,
            arch: String::new(),
            arch_emulated: false,
            agent_version: "0.4.142".into(),
            displays: vec![],
            caps: Box::new(AgentCaps::default()),
            advertised_routes: vec![],
            supports_relay_regions: true,
            ssh_host_pubkey: String::new(),
            vault_key,
            peer_auth_key: String::new(),
        };
        let s = serde_json::to_string(&hello(key.clone())).unwrap();
        assert!(s.contains(r#""vault_key""#), "{s}");
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::AgentHello { vault_key, .. } => assert_eq!(vault_key, key),
            other => panic!("wrong variant: {other:?}"),
        }

        let mut old = serde_json::to_value(hello(key)).unwrap();
        old.as_object_mut().unwrap().remove("vault_key");
        match serde_json::from_value::<ClientMsg>(old).unwrap() {
            ClientMsg::AgentHello { vault_key, .. } => assert!(vault_key.is_empty()),
            other => panic!("wrong variant: {other:?}"),
        }

        let none = serde_json::to_string(&hello(String::new())).unwrap();
        assert!(!none.contains("vault_key"), "{none}");
    }

    /// FR-100 P1a — the P-256 generator G (its coordinates from FIPS 186-4
    /// D.1.2.3), as a device key would carry a point: `0x04 ‖ X ‖ Y`,
    /// standard base64. A real point, so the tests below are about shape and
    /// spelling. Built here rather than written as a base64 literal: a
    /// secret scanner cannot tell a public curve constant from a key.
    fn p256_g_b64() -> String {
        use base64::Engine;
        const GX: [u8; 32] = [
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96,
        ];
        const GY: [u8; 32] = [
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
            0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
            0x37, 0xbf, 0x51, 0xf5,
        ];
        let mut point = vec![0x04];
        point.extend_from_slice(&GX);
        point.extend_from_slice(&GY);
        base64::engine::general_purpose::STANDARD.encode(point)
    }

    /// FR-100 P1a — the device key rides the hello, and its absence (an
    /// older agent, or one that could not keep a key) reads as empty.
    #[test]
    fn agent_hello_peer_auth_key_roundtrips_and_absent_means_none() {
        let hello = |peer_auth_key: String| ClientMsg::AgentHello {
            machine_name: "host".into(),
            os: OsKind::Linux,
            arch: String::new(),
            arch_emulated: false,
            agent_version: "0.4.145".into(),
            displays: vec![],
            caps: Box::new(AgentCaps::default()),
            advertised_routes: vec![],
            supports_relay_regions: true,
            ssh_host_pubkey: String::new(),
            vault_key: String::new(),
            peer_auth_key,
        };
        let g = p256_g_b64();
        let s = serde_json::to_string(&hello(g.clone())).unwrap();
        assert!(s.contains(r#""peer_auth_key""#), "{s}");
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::AgentHello { peer_auth_key, .. } => assert_eq!(peer_auth_key, g),
            other => panic!("wrong variant: {other:?}"),
        }

        let mut old = serde_json::to_value(hello(g)).unwrap();
        old.as_object_mut().unwrap().remove("peer_auth_key");
        match serde_json::from_value::<ClientMsg>(old).unwrap() {
            ClientMsg::AgentHello { peer_auth_key, .. } => assert!(peer_auth_key.is_empty()),
            other => panic!("wrong variant: {other:?}"),
        }

        let none = serde_json::to_string(&hello(String::new())).unwrap();
        assert!(!none.contains("peer_auth_key"), "{none}");
    }

    /// FR-100 P1a — what the server will store as a device key: an
    /// uncompressed point, 65 bytes, in the standard alphabet's one
    /// canonical spelling. Everything else is stored as none.
    #[test]
    fn a_device_key_is_an_uncompressed_point_in_canonical_standard_base64() {
        use base64::Engine;
        use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE};
        let g = p256_g_b64();
        assert!(peer_auth_key_is_well_formed(&g));
        let point = STANDARD.decode(&g).unwrap();
        assert_eq!(point.len(), 65);

        // Compressed (0x02/0x03 ‖ X) and hybrid points are other shapes.
        let mut compressed = vec![0x02];
        compressed.extend_from_slice(&point[1..33]);
        assert!(!peer_auth_key_is_well_formed(&STANDARD.encode(&compressed)));
        let mut wrong_tag = point.clone();
        wrong_tag[0] = 0x06;
        assert!(!peer_auth_key_is_well_formed(&STANDARD.encode(&wrong_tag)));
        // Too short, too long, empty.
        assert!(!peer_auth_key_is_well_formed(
            &STANDARD.encode(&point[..64])
        ));
        let mut long = point.clone();
        long.push(0);
        assert!(!peer_auth_key_is_well_formed(&STANDARD.encode(&long)));
        assert!(!peer_auth_key_is_well_formed(""));
        // The same bytes in another spelling: one key, one stored form.
        assert!(!peer_auth_key_is_well_formed(&URL_SAFE.encode(&point)));
        assert!(!peer_auth_key_is_well_formed(
            &STANDARD_NO_PAD.encode(&point)
        ));
        assert!(!peer_auth_key_is_well_formed(&format!(" {}", &g[1..])));
    }

    /// FR-100 P1a — the fingerprint's one definition, against a digest
    /// computed outside this code (coreutils `sha256sum` over the point's
    /// bytes): every surface that shows a device key must agree with it.
    #[test]
    fn a_device_key_fingerprint_is_the_first_ten_bytes_of_its_sha256() {
        assert_eq!(
            peer_auth_fingerprint(&p256_g_b64()).as_deref(),
            Some("698b ea63 dc44 a344 663f")
        );
        assert_eq!(peer_auth_fingerprint(""), None);
        assert_eq!(peer_auth_fingerprint("not a key"), None);
    }

    /// FR-100 P1b — the framing, by hand: the label, then each field as a
    /// big-endian u16 length and its bytes, in the documented order.
    #[test]
    fn a_peer_auth_transcript_frames_each_field_with_its_length() {
        let t = peer_auth_transcript("offer", "a", "b", "c", "d", "e", "f").unwrap();
        let mut want = b"roomler-peer-auth-v1".to_vec();
        want.extend_from_slice(&[0, 5]);
        want.extend_from_slice(b"offer");
        for field in [b"a", b"b", b"c", b"d", b"e", b"f"] {
            want.extend_from_slice(&[0, 1]);
            want.extend_from_slice(field);
        }
        assert_eq!(t, want);
        // The framing is what keeps two field splits apart.
        assert_ne!(
            peer_auth_transcript("answer", "ab", "c", "d", "e", "f", "g"),
            peer_auth_transcript("answer", "a", "bc", "d", "e", "f", "g")
        );
        // Nothing well formed is too long to frame; a field that is gets no
        // transcript, so nothing is signed.
        assert_eq!(
            peer_auth_transcript("answer", &"x".repeat(70_000), "b", "c", "d", "e", "f"),
            None
        );
    }

    /// FR-100 P1b — a realistic transcript against a digest computed outside
    /// this code (bash `printf` for the bytes, coreutils `sha256sum`). The
    /// viewer's implementation (P2a) is held to the same vector.
    #[test]
    fn a_peer_auth_transcript_matches_its_known_answer() {
        let t = peer_auth_transcript(
            "answer",
            "66f0c0ffee0000000000000a",
            "66f0c0ffee0000000000000b",
            "66f0c0ffee0000000000000c",
            "sha-256 AA:BB:CC",
            "sha-256 DD:EE:FF",
            &nonce_0_to_15(),
        )
        .unwrap();
        assert_eq!(t.len(), 166);
        let digest = ring::digest::digest(&ring::digest::SHA256, &t);
        let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "9e9736b2e6a5db65f5c536bf0cba1042fdca9517c63fd18d6bb8454206e7ac94"
        );
    }

    /// FR-100 P2b — the browser's OFFER transcript: role `offer` and an EMPTY
    /// answer fingerprint, the one the device judges (P1c). Its known answer
    /// was computed outside both implementations (Perl's `Digest::SHA` over
    /// the same framing), and the viewer's tests pin the same bytes.
    #[test]
    fn a_peer_auth_offer_transcript_matches_its_known_answer() {
        let t = peer_auth_transcript(
            "offer",
            "66f0c0ffee0000000000000a",
            "66f0c0ffee0000000000000b",
            "66f0c0ffee0000000000000c",
            "sha-256 AA:BB:CC",
            "",
            &nonce_0_to_15(),
        )
        .unwrap();
        assert_eq!(t.len(), 149);
        let digest = ring::digest::digest(&ring::digest::SHA256, &t);
        let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "3c3da0182f79f04f878356ddbb0983d748b8152a15912a92d095429756428840"
        );
    }

    /// FR-100 P2a — a signature made OUTSIDE both implementations: an OpenSSL
    /// 3.5 P-256 key (its private half deleted after signing) over the
    /// known-answer transcript, converted from DER to `r ‖ s`. The viewer's
    /// tests verify the same vector with WebCrypto, so ring and the browser are
    /// held to one signer neither of them wrote. Bytes, not base64 literals: a
    /// secret scanner cannot tell a public key or a signature from a secret.
    #[test]
    fn a_signature_made_outside_both_implementations_verifies() {
        use base64::Engine;
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        const POINT: [u8; 65] = [
            0x04, 0xdf, 0x87, 0x14, 0xf1, 0x2a, 0x41, 0xd2, 0x32, 0x32, 0x0a, 0x24, 0xea, 0xb5,
            0x75, 0x78, 0xc7, 0x4e, 0x63, 0xa3, 0x4d, 0x57, 0xad, 0x90, 0x8a, 0x92, 0xb1, 0xde,
            0xca, 0x53, 0x7a, 0xa5, 0xfb, 0xfd, 0x9a, 0x83, 0x24, 0x1b, 0x9c, 0xdd, 0xd1, 0x06,
            0xbd, 0x0c, 0x7e, 0x0e, 0x0a, 0x87, 0x4e, 0xb1, 0x48, 0x14, 0x0d, 0x14, 0xe3, 0x4a,
            0x9e, 0x7c, 0xe3, 0xba, 0x07, 0xf4, 0xa7, 0x8e, 0xc4,
        ];
        const SIG: [u8; 64] = [
            0x73, 0x2a, 0xa2, 0x53, 0xdc, 0x6e, 0x3a, 0x5b, 0x06, 0xaa, 0x6d, 0x32, 0x37, 0x5a,
            0x5e, 0x08, 0x8e, 0xe1, 0x28, 0x8f, 0x5c, 0x7e, 0x00, 0xd7, 0xba, 0x16, 0x4f, 0x98,
            0x9c, 0xc4, 0x29, 0x6c, 0x38, 0x9f, 0xaa, 0xf2, 0x9c, 0x7b, 0x64, 0xe7, 0x23, 0xb3,
            0x97, 0xb2, 0xe3, 0xb3, 0x46, 0xab, 0x49, 0xb9, 0x74, 0x1b, 0x27, 0x6d, 0x99, 0x71,
            0xee, 0x95, 0xb3, 0x71, 0x83, 0x2d, 0xe5, 0xb3,
        ];
        let key = STANDARD.encode(POINT);
        let sig = URL_SAFE_NO_PAD.encode(SIG);
        let kat = |user: &str| {
            peer_auth_transcript(
                "answer",
                "66f0c0ffee0000000000000a",
                "66f0c0ffee0000000000000b",
                user,
                "sha-256 AA:BB:CC",
                "sha-256 DD:EE:FF",
                &nonce_0_to_15(),
            )
            .unwrap()
        };
        assert!(peer_auth_key_is_well_formed(&key));
        assert!(peer_auth_verify(
            &key,
            &kat("66f0c0ffee0000000000000c"),
            &sig
        ));
        assert!(!peer_auth_verify(
            &key,
            &kat("66f0c0ffee0000000000000d"),
            &sig
        ));
    }

    /// FR-100 P1b — the nonce the vectors use: bytes 0 to 15, base64url without
    /// padding. Built here rather than written as a base64 literal: a secret
    /// scanner cannot tell a counting sequence from a key.
    fn nonce_0_to_15() -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode((0u8..16).collect::<Vec<u8>>())
    }

    /// FR-100 P1b — a nonce is 16 to 32 random bytes in canonical base64url.
    #[test]
    fn a_peer_auth_nonce_is_16_to_32_bytes_of_canonical_base64url() {
        use base64::Engine;
        use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
        assert!(peer_auth_nonce_is_well_formed(&nonce_0_to_15()));
        assert!(peer_auth_nonce_is_well_formed(
            &URL_SAFE_NO_PAD.encode([0xfbu8; 32])
        ));
        // Too short, too long, empty.
        assert!(!peer_auth_nonce_is_well_formed(
            &URL_SAFE_NO_PAD.encode([1u8; 15])
        ));
        assert!(!peer_auth_nonce_is_well_formed(
            &URL_SAFE_NO_PAD.encode([1u8; 33])
        ));
        assert!(!peer_auth_nonce_is_well_formed(""));
        // The same bytes in other spellings.
        assert!(!peer_auth_nonce_is_well_formed(
            &URL_SAFE.encode([0xfbu8; 16])
        ));
        assert!(!peer_auth_nonce_is_well_formed(
            &STANDARD.encode([0xfbu8; 16])
        ));
    }

    /// FR-100 P1b — a signature made with a P-256 key verifies over the
    /// transcript it was made over, and over nothing else.
    #[test]
    fn a_peer_auth_signature_verifies_over_its_own_transcript_only() {
        use base64::Engine;
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
        let rng = ring::rand::SystemRandom::new();
        let pair = |rng: &ring::rand::SystemRandom| {
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, rng).unwrap();
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), rng).unwrap()
        };
        let device = pair(&rng);
        let key = STANDARD.encode(device.public_key().as_ref());
        let t =
            peer_auth_transcript("answer", "s", "a", "u", "sha-256 AA", "sha-256 BB", "n").unwrap();
        let sig = URL_SAFE_NO_PAD.encode(device.sign(&rng, &t).unwrap().as_ref());
        assert!(peer_auth_verify(&key, &t, &sig));
        // Another field, another key, another signature: no.
        let other_t =
            peer_auth_transcript("answer", "s", "a", "u", "sha-256 AA", "sha-256 CC", "n").unwrap();
        assert!(!peer_auth_verify(&key, &other_t, &sig));
        let other_key = STANDARD.encode(pair(&rng).public_key().as_ref());
        assert!(!peer_auth_verify(&other_key, &t, &sig));
        assert!(!peer_auth_verify(&key, &t, "not a signature"));
        assert!(!peer_auth_verify("not a key", &t, &sig));
    }

    /// FR-100 P1b (from FR-52 P4) — the one fingerprint an SDP names,
    /// normalised; agreeing repeats are one, disagreeing ones are ambiguous.
    #[test]
    fn an_sdp_names_one_dtls_fingerprint_normalised() {
        let one = "v=0\r\na=fingerprint:SHA-256 ab:cd:ef\r\nm=application\r\na=fingerprint:sha-256 AB:CD:EF\r\n";
        assert_eq!(sdp_dtls_fingerprint(one).as_deref(), Ok("sha-256 AB:CD:EF"));
        let two = "a=fingerprint:sha-256 AB:CD:EF\r\na=fingerprint:sha-256 AB:CD:00\r\n";
        assert_eq!(
            sdp_dtls_fingerprint(two),
            Err(SdpFingerprintError::Ambiguous)
        );
        let odd = "a=fingerprint:sha-256 AB:CD EF\r\n";
        assert_eq!(
            sdp_dtls_fingerprint(odd),
            Err(SdpFingerprintError::Ambiguous)
        );
        assert_eq!(
            sdp_dtls_fingerprint("v=0\r\n"),
            Err(SdpFingerprintError::Missing)
        );
    }

    /// FR-100 P1b — the offer's ask and the answer's signature ride their
    /// frames, absent when unset, and an older frame without them still reads.
    #[test]
    fn the_offer_and_answer_carry_peer_auth_and_absent_means_none() {
        let offer = ClientMsg::SdpOffer {
            session_id: ObjectId::new(),
            sdp: "v=0".into(),
            extauth_mac: None,
            peer_auth: Some(PeerAuthOffer {
                nonce: nonce_0_to_15(),
                key: None,
                sig: None,
            }),
        };
        let v = serde_json::to_value(&offer).unwrap();
        assert_eq!(v["peer_auth"]["nonce"], nonce_0_to_15());
        let mut old = v.clone();
        old.as_object_mut().unwrap().remove("peer_auth");
        match serde_json::from_value::<ClientMsg>(old).unwrap() {
            ClientMsg::SdpOffer { peer_auth, .. } => assert_eq!(peer_auth, None),
            other => panic!("wrong variant: {other:?}"),
        }
        let answer = ClientMsg::SdpAnswer {
            session_id: ObjectId::new(),
            sdp: "v=0".into(),
            extauth_mac: None,
            peer_auth: None,
            peer_auth_verdict: None,
        };
        let v = serde_json::to_value(&answer).unwrap();
        assert!(v.get("peer_auth").is_none(), "{v}");
        assert!(v.get("peer_auth_verdict").is_none(), "{v}");
    }

    /// FR-100 P1c — the device's verdict rides its answer as a plain string.
    /// An older server reads the frame, field and all (it skips what it does
    /// not know); a newer device's word reaches this server as a word, and is
    /// checked against the vocabulary before anything records it.
    #[test]
    fn the_answer_carries_the_verdict_as_a_word_older_readers_skip() {
        let raw = r#"{"t":"rc:sdp.answer","session_id":"66f0c0ffee0000000000000a",
            "sdp":"v=0","peer_auth_verdict":"some-future-word"}"#;
        let ClientMsg::SdpAnswer {
            peer_auth_verdict, ..
        } = serde_json::from_str::<ClientMsg>(raw).expect("an unknown word never fails the frame")
        else {
            panic!("not an answer")
        };
        assert_eq!(peer_auth_verdict.as_deref(), Some("some-future-word"));
        assert!(!peer_auth_verdict_is_known("some-future-word"));
        for word in ["absent", "unknown", "verified", "mismatch"] {
            assert!(peer_auth_verdict_is_known(word), "{word}");
        }
        // Equality only: a prefix or a case change is not a verdict.
        assert!(!peer_auth_verdict_is_known("verified-ish"));
        assert!(!peer_auth_verdict_is_known("Verified"));
        assert!(!peer_auth_verdict_is_known(""));
    }

    /// FR-90 P3-3a — what the server will store as a vault key: 32 bytes in
    /// the standard alphabet's one canonical spelling, never all zeros.
    #[test]
    fn a_vault_key_is_32_bytes_of_canonical_standard_base64() {
        use base64::Engine;
        use base64::engine::general_purpose::{STANDARD, URL_SAFE};
        let good = STANDARD.encode([7u8; 32]);
        assert_eq!(good.len(), VAULT_KEY_B64_LEN);
        assert!(vault_key_is_well_formed(&good));
        assert!(vault_key_is_well_formed(&STANDARD.encode([0xfbu8; 32])));

        assert!(!vault_key_is_well_formed(""));
        assert!(
            !vault_key_is_well_formed(&STANDARD.encode([0u8; 32])),
            "all zeros"
        );
        // 31 and 33 bytes are 44 characters too: the length alone proves nothing.
        assert!(!vault_key_is_well_formed(&STANDARD.encode([7u8; 31])));
        assert!(!vault_key_is_well_formed(&STANDARD.encode([7u8; 33])));
        assert!(
            !vault_key_is_well_formed(&URL_SAFE.encode([0xfbu8; 32])),
            "the URL-safe alphabet"
        );
        // `…Bwc=` with a padding bit set: the same bytes, a second spelling.
        let mut loose = good.clone();
        loose.replace_range(42..43, "d");
        assert!(!vault_key_is_well_formed(&loose), "{loose}");
        assert!(!vault_key_is_well_formed(&format!("{good}\n")));
        assert!(!vault_key_is_well_formed(&"!".repeat(VAULT_KEY_B64_LEN)));
    }

    /// FR-97 P0d — the native architecture rides the hello beside the OS.
    /// Locked: its spelling, that an empty value and a `false` emulation flag
    /// stay off the wire, and that an agent predating both still parses.
    #[test]
    fn agent_hello_native_arch_roundtrips_and_absent_reads_unreported() {
        let m = ClientMsg::AgentHello {
            machine_name: "host".into(),
            os: OsKind::Macos,
            arch: "aarch64".into(),
            arch_emulated: true,
            agent_version: "0.4.142".into(),
            displays: vec![],
            caps: Box::new(AgentCaps::default()),
            advertised_routes: vec![],
            supports_relay_regions: true,
            ssh_host_pubkey: String::new(),
            vault_key: String::new(),
            peer_auth_key: String::new(),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""arch":"aarch64""#), "{s}");
        assert!(s.contains(r#""arch_emulated":true"#), "{s}");
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::AgentHello {
                arch,
                arch_emulated,
                ..
            } => assert_eq!((arch.as_str(), arch_emulated), ("aarch64", true)),
            other => panic!("wrong variant: {other:?}"),
        }
        let mut obj = serde_json::to_value(&m).unwrap();
        obj.as_object_mut().unwrap().remove("arch");
        obj.as_object_mut().unwrap().remove("arch_emulated");
        let old = serde_json::to_string(&obj).unwrap();
        match serde_json::from_str::<ClientMsg>(&old).unwrap() {
            ClientMsg::AgentHello {
                arch,
                arch_emulated,
                ..
            } => assert!(arch.is_empty() && !arch_emulated),
            other => panic!("wrong variant: {other:?}"),
        }
        let native = ClientMsg::AgentHello {
            machine_name: "host".into(),
            os: OsKind::Linux,
            arch: String::new(),
            arch_emulated: false,
            agent_version: "0.4.142".into(),
            displays: vec![],
            caps: Box::new(AgentCaps::default()),
            advertised_routes: vec![],
            supports_relay_regions: false,
            ssh_host_pubkey: String::new(),
            vault_key: String::new(),
            peer_auth_key: String::new(),
        };
        let s = serde_json::to_string(&native).unwrap();
        assert!(
            !s.contains(r#""arch""#) && !s.contains(r#""arch_emulated""#),
            "empty and false stay off the wire: {s}"
        );
    }

    /// Multi-region relay wire locks: exact tags, field defaults, and the
    /// hello capability flag's absent⇒false back-compat.
    #[test]
    fn relay_regions_wire_roundtrip_and_defaults() {
        let m = ServerMsg::RelayRegions {
            regions: vec![
                RelayRegionInfo {
                    id: "us-east".into(),
                    stun: "coturn-us-east.roomler.ai:3478".into(),
                    derp_url: Some("wss://derp-us-east.roomler.ai/derp".into()),
                    relay_band: Some((49152, 65535)),
                },
                RelayRegionInfo {
                    id: "eu-central".into(),
                    stun: "coturn.roomler.ai:3478".into(),
                    derp_url: None,
                    relay_band: None,
                },
            ],
            rev: 7,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:relay.regions""#));
        assert!(s.contains(r#""stun":"coturn-us-east.roomler.ai:3478""#));
        // Absent derp_url is OMITTED, not null.
        assert!(!s.contains(r#""derp_url":null"#));
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::RelayRegions { regions, rev } => {
                assert_eq!(rev, 7);
                assert_eq!(regions.len(), 2);
                assert_eq!(regions[0].id, "us-east");
                assert!(regions[1].derp_url.is_none());
            }
            other => panic!("wrong variant: {other:?}"),
        }

        let r = ClientMsg::RelayProbeReport {
            results: vec![
                RelayRegionRtt {
                    region: "us-east".into(),
                    rtt_ms: Some(23),
                },
                RelayRegionRtt {
                    region: "eu-central".into(),
                    rtt_ms: None,
                },
            ],
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""t":"rc:relay.probe_report""#));
        assert!(s.contains(r#""rtt_ms":23"#));
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::RelayProbeReport { results } => {
                assert_eq!(results[0].rtt_ms, Some(23));
                assert_eq!(results[1].rtt_ms, None, "all-timed-out region is None");
            }
            other => panic!("wrong variant: {other:?}"),
        }

        // Pre-feature hello (no flag) ⇒ supports_relay_regions == false, so
        // the server never pushes rc:relay.regions at an old agent.
        let hello = serde_json::json!({
            "t": "rc:agent.hello",
            "machine_name": "old-host",
            "os": "linux",
            "agent_version": "0.3.0-rc.200",
            "displays": [],
            "caps": AgentCaps::default(),
        });
        match serde_json::from_value::<ClientMsg>(hello).unwrap() {
            ClientMsg::AgentHello {
                supports_relay_regions,
                ..
            } => assert!(
                !supports_relay_regions,
                "absent capability flag must default to false"
            ),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn ice_server_minimal() {
        let s = IceServer {
            urls: vec!["stun:stun.l.google.com:19302".into()],
            username: None,
            credential: None,
        };
        let j = serde_json::to_string(&s).unwrap();
        assert!(!j.contains("username"));
    }

    #[test]
    fn object_ids_serialise_as_raw_hex_on_wire() {
        // Lock-in: no `$oid` wrapping anywhere in the WS protocol envelope.
        let session_id = ObjectId::parse_str("507f1f77bcf86cd799439011").unwrap();
        let agent_id = ObjectId::parse_str("507f1f77bcf86cd799439012").unwrap();

        let created = ServerMsg::SessionCreated {
            session_id,
            agent_id,
            permissions: None,
            record_refused: None,
            privacy_refused: None,
            features_refused: None,
            idle_secs: None,
        };
        let s = serde_json::to_string(&created).unwrap();
        assert!(
            !s.contains("$oid"),
            "extended JSON leaked into wire format: {s}"
        );
        assert!(s.contains("\"session_id\":\"507f1f77bcf86cd799439011\""));
        assert!(s.contains("\"agent_id\":\"507f1f77bcf86cd799439012\""));

        let req = ClientMsg::SessionRequest {
            share_grant_id: None,
            agent_id,
            permissions: Permissions::VIEW | Permissions::INPUT,
            browser_caps: vec!["h264".into(), "h265".into()],
            preferred_transport: None,
            chroma_pref: None,
            chunk_framing: None,
            audio_enabled: false,
            override_reason: None,
            local_relay: None,
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(!s.contains("$oid"));
        assert!(s.contains("\"agent_id\":\"507f1f77bcf86cd799439012\""));
        assert!(s.contains("\"browser_caps\":[\"h264\",\"h265\"]"));
        // Default None must NOT serialise — keeps the wire compatible
        // with controllers that don't know about the field at all.
        assert!(
            !s.contains("preferred_transport"),
            "None should be skipped via skip_serializing_if"
        );

        // With a value set, the field appears
        let req_with_t = ClientMsg::SessionRequest {
            share_grant_id: None,
            agent_id,
            permissions: Permissions::VIEW,
            browser_caps: vec![],
            preferred_transport: Some("data-channel-vp9-444".into()),
            chroma_pref: None,
            chunk_framing: None,
            audio_enabled: true,
            override_reason: None,
            local_relay: None,
        };
        let s = serde_json::to_string(&req_with_t).unwrap();
        assert!(s.contains("\"preferred_transport\":\"data-channel-vp9-444\""));

        // Loopback-TURN corp-relay (Phase 2): a set `local_relay` round-trips
        // with the browser's snake_case field names, and the default None is
        // skipped so the wire stays compatible with older controllers.
        assert!(
            !s.contains("local_relay"),
            "None local_relay must be skipped"
        );
        let req_lr = ClientMsg::SessionRequest {
            share_grant_id: None,
            agent_id,
            permissions: Permissions::VIEW,
            browser_caps: vec![],
            preferred_transport: None,
            chroma_pref: None,
            chunk_framing: None,
            audio_enabled: false,
            override_reason: None,
            local_relay: Some(LocalRelayDescriptor {
                turn_port: 47989,
                overlay_ip: "100.64.0.7".into(),
                username: "1700000600:507f1f77bcf86cd799439012".into(),
                credential: "deadbeef".into(),
            }),
        };
        let s = serde_json::to_string(&req_lr).unwrap();
        assert!(
            s.contains("\"local_relay\":{"),
            "set local_relay serialises: {s}"
        );
        assert!(s.contains("\"turn_port\":47989"));
        assert!(s.contains("\"overlay_ip\":\"100.64.0.7\""));
        // Round-trips back to the same descriptor.
        let back: ClientMsg = serde_json::from_str(&s).unwrap();
        match back {
            ClientMsg::SessionRequest { local_relay, .. } => {
                let d = local_relay.expect("local_relay present");
                assert_eq!(d.turn_port, 47989);
                assert_eq!(d.overlay_ip, "100.64.0.7");
            }
            _ => panic!("expected SessionRequest"),
        }
    }

    /// #1882 — `rc_overlay` is OFF unless the server says otherwise. An older
    /// server never sends it, so absent has to read `false`; `false` is
    /// skipped so the default costs nothing on the wire; `true` round-trips.
    #[test]
    fn request_rc_overlay_is_off_when_absent_and_round_trips_when_on() {
        let req = |rc_overlay| ServerMsg::Request {
            shared_lease: None,
            session_id: ObjectId::parse_str("507f1f77bcf86cd799439011").unwrap(),
            controller_user_id: ObjectId::parse_str("507f1f77bcf86cd799439012").unwrap(),
            controller_name: "Alice".into(),
            permissions: Permissions::VIEW,
            consent_timeout_secs: 30,
            browser_caps: vec![],
            preferred_transport: None,
            chroma_pref: None,
            chunk_framing: None,
            audio_enabled: false,
            consent_mode: None,
            host_prompt_timeout_secs: None,
            input_mode: None,
            tenant_name: None,
            rc_overlay,
            session_policy: None,
            idle_secs: None,
            lock_on_end: None,
            external: None,
        };
        let off = serde_json::to_string(&req(false)).unwrap();
        assert!(
            !off.contains("rc_overlay"),
            "false is the default and must not reach the wire: {off}"
        );
        match serde_json::from_str::<ServerMsg>(&off).unwrap() {
            ServerMsg::Request { rc_overlay, .. } => {
                assert!(!rc_overlay, "absent (an older server) must read OFF")
            }
            _ => panic!("expected Request"),
        }
        let on = serde_json::to_string(&req(true)).unwrap();
        assert!(on.contains("\"rc_overlay\":true"), "{on}");
        match serde_json::from_str::<ServerMsg>(&on).unwrap() {
            ServerMsg::Request { rc_overlay, .. } => assert!(rc_overlay),
            _ => panic!("expected Request"),
        }
    }

    /// FR-101 P2 — `session_policy` on `rc:request`: absent (an older server,
    /// an org that restricts nothing) is skipped and reads as no policy; a
    /// policy round-trips in lowercase; a value from a newer server reads as
    /// `off` without failing the frame, so the session still starts.
    #[test]
    fn request_session_policy_is_additive_and_reads_unknown_values_as_off() {
        use crate::models::{FeaturePolicy, SessionPolicy};
        let req = |session_policy| ServerMsg::Request {
            shared_lease: None,
            session_id: ObjectId::parse_str("507f1f77bcf86cd799439011").unwrap(),
            controller_user_id: ObjectId::parse_str("507f1f77bcf86cd799439012").unwrap(),
            controller_name: "Alice".into(),
            permissions: Permissions::VIEW,
            consent_timeout_secs: 30,
            browser_caps: vec![],
            preferred_transport: None,
            chroma_pref: None,
            chunk_framing: None,
            audio_enabled: false,
            consent_mode: None,
            host_prompt_timeout_secs: None,
            input_mode: None,
            tenant_name: None,
            rc_overlay: false,
            session_policy,
            idle_secs: None,
            lock_on_end: None,
            external: None,
        };
        let none = serde_json::to_string(&req(None)).unwrap();
        assert!(!none.contains("session_policy"), "{none}");
        match serde_json::from_str::<ServerMsg>(&none).unwrap() {
            ServerMsg::Request { session_policy, .. } => assert_eq!(session_policy, None),
            _ => panic!("expected Request"),
        }
        let p = SessionPolicy {
            clipboard: FeaturePolicy::Ask,
            files: FeaturePolicy::Off,
            audio: FeaturePolicy::On,
        };
        let some = serde_json::to_string(&req(Some(p))).unwrap();
        assert!(
            some.contains(r#""session_policy":{"clipboard":"ask","files":"off","audio":"on"}"#),
            "{some}"
        );
        match serde_json::from_str::<ServerMsg>(&some).unwrap() {
            ServerMsg::Request { session_policy, .. } => assert_eq!(session_policy, Some(p)),
            _ => panic!("expected Request"),
        }
        let newer = some.replace(r#""clipboard":"ask""#, r#""clipboard":"ask_twice""#);
        match serde_json::from_str::<ServerMsg>(&newer).unwrap() {
            ServerMsg::Request { session_policy, .. } => {
                assert_eq!(session_policy.unwrap().clipboard, FeaturePolicy::Off)
            }
            _ => panic!("expected Request"),
        }
    }

    /// FR-101 P2 — `features_refused` on `rc:session.created`: skipped when
    /// nothing was refused, a map of feature → reason when something was.
    #[test]
    fn session_created_features_refused_is_additive() {
        let mk = |features_refused| ServerMsg::SessionCreated {
            session_id: ObjectId::parse_str("507f1f77bcf86cd799439011").unwrap(),
            agent_id: ObjectId::parse_str("507f1f77bcf86cd799439012").unwrap(),
            permissions: Some(Permissions::VIEW),
            record_refused: None,
            privacy_refused: None,
            features_refused,
            idle_secs: None,
        };
        let none = serde_json::to_string(&mk(None)).unwrap();
        assert!(!none.contains("features_refused"), "{none}");
        let refused: std::collections::BTreeMap<String, String> = [
            ("audio".to_string(), "needs_consent".to_string()),
            ("files".to_string(), "org_policy_off".to_string()),
        ]
        .into();
        let some = serde_json::to_string(&mk(Some(refused.clone()))).unwrap();
        assert!(
            some.contains(
                r#""features_refused":{"audio":"needs_consent","files":"org_policy_off"}"#
            ),
            "{some}"
        );
        match serde_json::from_str::<ServerMsg>(&some).unwrap() {
            ServerMsg::SessionCreated {
                features_refused, ..
            } => assert_eq!(features_refused, Some(refused)),
            _ => panic!("expected SessionCreated"),
        }
    }

    /// FR-101 P4b-2 — the idle limit on the wire. `idle_secs` on
    /// `rc:request` and `rc:session.created` is skipped when absent and
    /// round-trips when set; `limit` on an agent's `rc:terminate`
    /// round-trips, and a frame from a sender older than the fields reads as
    /// no limit, so neither direction breaks across a rollout.
    #[test]
    fn the_idle_limit_fields_are_additive() {
        let sid = ObjectId::parse_str("507f1f77bcf86cd799439011").unwrap();
        let req = |idle_secs| ServerMsg::Request {
            shared_lease: None,
            session_id: sid,
            controller_user_id: ObjectId::parse_str("507f1f77bcf86cd799439012").unwrap(),
            controller_name: "Alice".into(),
            permissions: Permissions::VIEW,
            consent_timeout_secs: 30,
            browser_caps: vec![],
            preferred_transport: None,
            chroma_pref: None,
            chunk_framing: None,
            audio_enabled: false,
            consent_mode: None,
            host_prompt_timeout_secs: None,
            input_mode: None,
            tenant_name: None,
            rc_overlay: false,
            session_policy: None,
            idle_secs,
            lock_on_end: None,
            external: None,
        };
        let none = serde_json::to_string(&req(None)).unwrap();
        assert!(!none.contains("idle_secs"), "{none}");
        let some = serde_json::to_string(&req(Some(900))).unwrap();
        assert!(some.contains(r#""idle_secs":900"#), "{some}");
        match serde_json::from_str::<ServerMsg>(&some).unwrap() {
            ServerMsg::Request { idle_secs, .. } => assert_eq!(idle_secs, Some(900)),
            _ => panic!("expected Request"),
        }

        let created = |idle_secs| ServerMsg::SessionCreated {
            session_id: sid,
            agent_id: ObjectId::parse_str("507f1f77bcf86cd799439012").unwrap(),
            permissions: None,
            record_refused: None,
            privacy_refused: None,
            features_refused: None,
            idle_secs,
        };
        let none = serde_json::to_string(&created(None)).unwrap();
        assert!(!none.contains("idle_secs"), "{none}");
        match serde_json::from_str::<ServerMsg>(
            &serde_json::to_string(&created(Some(300))).unwrap(),
        )
        .unwrap()
        {
            ServerMsg::SessionCreated { idle_secs, .. } => assert_eq!(idle_secs, Some(300)),
            _ => panic!("expected SessionCreated"),
        }

        // An agent's terminate naming the limit, and one from before the field.
        let up = serde_json::to_string(&ClientMsg::Terminate {
            session_id: sid,
            reason: EndReason::IdleTimeout,
            limit: Some("idle".into()),
        })
        .unwrap();
        assert!(up.contains(r#""reason":"idle_timeout""#), "{up}");
        assert!(up.contains(r#""limit":"idle""#), "{up}");
        match serde_json::from_str::<ClientMsg>(&up).unwrap() {
            ClientMsg::Terminate { limit, .. } => assert_eq!(limit.as_deref(), Some("idle")),
            other => panic!("wrong variant: {other:?}"),
        }
        let older = r#"{"t":"rc:terminate","session_id":"507f1f77bcf86cd799439011","reason":"idle_timeout"}"#;
        match serde_json::from_str::<ClientMsg>(older).unwrap() {
            ClientMsg::Terminate { reason, limit, .. } => {
                assert_eq!(reason, EndReason::IdleTimeout);
                assert_eq!(limit, None);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// FR-99 P3b — the lock ask on `rc:request`: skipped when absent, its
    /// three spellings round-trip, a frame from an older server reads as no
    /// ask, and a value this build does not know reads as the strictest, so
    /// a newer server's ask is never read as looser than it was meant.
    #[test]
    fn the_lock_on_end_ask_is_additive() {
        use crate::models::LockOnEnd;
        let sid = ObjectId::parse_str("507f1f77bcf86cd799439011").unwrap();
        let req = |lock_on_end| ServerMsg::Request {
            shared_lease: None,
            session_id: sid,
            controller_user_id: ObjectId::parse_str("507f1f77bcf86cd799439012").unwrap(),
            controller_name: "Alice".into(),
            permissions: Permissions::VIEW,
            consent_timeout_secs: 30,
            browser_caps: vec![],
            preferred_transport: None,
            chroma_pref: None,
            chunk_framing: None,
            audio_enabled: false,
            consent_mode: None,
            host_prompt_timeout_secs: None,
            input_mode: None,
            tenant_name: None,
            rc_overlay: false,
            session_policy: None,
            idle_secs: None,
            lock_on_end,
            external: None,
        };
        let none = serde_json::to_string(&req(None)).unwrap();
        assert!(!none.contains("lock_on_end"), "{none}");
        for (ask, wire) in [(LockOnEnd::Auto, "auto"), (LockOnEnd::Always, "always")] {
            let some = serde_json::to_string(&req(Some(ask))).unwrap();
            assert!(
                some.contains(&format!(r#""lock_on_end":"{wire}""#)),
                "{some}"
            );
            match serde_json::from_str::<ServerMsg>(&some).unwrap() {
                ServerMsg::Request { lock_on_end, .. } => assert_eq!(lock_on_end, Some(ask)),
                _ => panic!("expected Request"),
            }
        }
        let mut older: serde_json::Value = serde_json::from_str(&none).unwrap();
        assert!(older.get("lock_on_end").is_none());
        match serde_json::from_value::<ServerMsg>(older.clone()).unwrap() {
            ServerMsg::Request { lock_on_end, .. } => assert_eq!(lock_on_end, None),
            _ => panic!("expected Request"),
        }
        older["lock_on_end"] = serde_json::json!("on_every_tuesday");
        match serde_json::from_value::<ServerMsg>(older).unwrap() {
            ServerMsg::Request { lock_on_end, .. } => {
                assert_eq!(lock_on_end, Some(LockOnEnd::Always))
            }
            _ => panic!("expected Request"),
        }
    }

    #[test]
    fn agent_heartbeat_round_trips_with_stable_field_names() {
        // Wire-format lock for Phase 7 (heartbeat telemetry). The agent
        // emits this every 30 s and the server uses it to refresh
        // `agents.last_seen_at`. Field names match the JS controllers'
        // expectations; renaming any of them is a wire break that needs
        // a coordinated agent + server release.
        let m = ClientMsg::AgentHeartbeat {
            rss_mb: 142,
            cpu_pct: 3.25,
            active_sessions: 2,
            sys: None,
            srflx_count: Some(2),
            warm_relay: Some("5.9.157.221:12586".into()),
            companion_version: Some("0.4.16".into()),
            keep_busy: None,
            // FR-43 P2c — absent means "no news", which is the steady state.
            caps: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:agent.heartbeat""#));
        assert!(s.contains(r#""rss_mb":142"#));
        assert!(s.contains(r#""cpu_pct":3.25"#));
        assert!(s.contains(r#""active_sessions":2"#));
        assert!(s.contains(r#""warm_relay":"5.9.157.221:12586""#));
        // v1 shape stays byte-identical: `sys: None` must not serialize.
        assert!(!s.contains(r#""sys""#));

        let back: ClientMsg = serde_json::from_str(&s).unwrap();
        match back {
            ClientMsg::AgentHeartbeat {
                rss_mb,
                cpu_pct,
                active_sessions,
                sys,
                srflx_count,
                warm_relay,
                companion_version,
                caps,
                keep_busy,
            } => {
                // FR-43 P2c — the steady state is ABSENT, and that is the
                // property worth asserting: caps ride the heartbeat only when
                // they change, so an ordinary beat must carry none.
                assert!(caps.is_none(), "an ordinary heartbeat must not carry caps");
                // FR-92 P5b — and a beat that has nothing to say about keep
                // busy says nothing: the key is absent on the wire.
                assert!(keep_busy.is_none());
                assert!(!s.contains("keep_busy"), "{s}");
                assert_eq!(rss_mb, 142);
                assert!((cpu_pct - 3.25).abs() < f32::EPSILON);
                assert_eq!(active_sessions, 2);
                assert!(sys.is_none());
                assert_eq!(srflx_count, Some(2));
                assert_eq!(warm_relay.as_deref(), Some("5.9.157.221:12586"));
                assert_eq!(companion_version.as_deref(), Some("0.4.16"));
            }
            other => panic!("wrong variant: {other:?}"),
        }
        assert!(s.contains(r#""companion_version":"0.4.16""#));
        // A stage-1 agent omits the field — decodes as None, and a
        // warm-less stage-2 agent's None must not serialize at all.
        let stage1 = r#"{"t":"rc:agent.heartbeat","rss_mb":0,"cpu_pct":0.0,"active_sessions":1}"#;
        let back: ClientMsg = serde_json::from_str(stage1).unwrap();
        assert!(matches!(
            back,
            ClientMsg::AgentHeartbeat {
                warm_relay: None,
                ..
            }
        ));
        // FR-27 — same rule for the companion version: a pre-FR-27 agent omits
        // it, and that must decode as "not reported", never as an empty string
        // the grid would render as a version.
        assert!(matches!(
            serde_json::from_str::<ClientMsg>(stage1).unwrap(),
            ClientMsg::AgentHeartbeat {
                companion_version: None,
                keep_busy: None,
                ..
            }
        ));
    }

    #[test]
    fn agent_heartbeat_sys_block_round_trips_and_v1_payload_parses() {
        // Stats PR-5 wire lock. Old agents omit `sys` entirely — the
        // server-side deserializer must default it.
        let v1 = r#"{"t":"rc:agent.heartbeat","rss_mb":0,"cpu_pct":0.0,"active_sessions":1}"#;
        let back: ClientMsg = serde_json::from_str(v1).unwrap();
        assert!(matches!(back, ClientMsg::AgentHeartbeat { sys: None, .. }));
        // A pre-feature agent omits the field entirely — that must decode as
        // None ("not reported"), never as a measured Some(0).
        assert!(matches!(
            serde_json::from_str::<ClientMsg>(v1).unwrap(),
            ClientMsg::AgentHeartbeat {
                srflx_count: None,
                ..
            }
        ));

        let m = ClientMsg::AgentHeartbeat {
            rss_mb: 0,
            cpu_pct: 0.0,
            active_sessions: 1,
            sys: Some(AgentSysStats {
                rss_mb: 87,
                cpu_pct: 1.5,
                net_rx_bytes: 123_456_789,
                net_tx_bytes: 987_654,
                direct: 3,
                relay: 1,
                derp: 1,
                peer_rtt_ms: Some(42),
                overlay_rx_bytes: 4_096,
                overlay_tx_bytes: 8_192,
                tunnel_rx_bytes: 65_536,
                tunnel_tx_bytes: 1_024,
                links: vec![
                    PeerLink {
                        node: "6a1f00000000000000000001".into(),
                        carrier: "direct".into(),
                        rtt_ms: Some(12),
                        stalled: false,
                        tx: 512,
                        rx: 256,
                        relay: None,
                    },
                    PeerLink {
                        node: "6a1f00000000000000000002".into(),
                        carrier: "relay".into(),
                        rtt_ms: Some(87),
                        stalled: false,
                        tx: 0,
                        rx: 0,
                        relay: Some("turn/udp".into()),
                    },
                ],
            }),
            // The value that matters operationally: a measured ZERO must be
            // distinguishable on the wire from an agent that doesn't report.
            srflx_count: Some(0),
            warm_relay: None,
            // No companion on this host — must not serialize at all, so a
            // server reading it cannot tell it apart from an old agent (both
            // mean "nothing to show").
            companion_version: None,
            keep_busy: None,
            caps: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(
            s.contains(r#""srflx_count":0"#),
            "a measured zero must serialise, not be skipped: {s}"
        );
        assert!(s.contains(r#""net_rx_bytes":123456789"#));
        assert!(s.contains(r#""direct":3"#));
        assert!(s.contains(r#""peer_rtt_ms":42"#));
        // Wave 2: mesh edges ride the same block; an empty list is
        // skipped so a pre-mesh agent's payload stays byte-identical.
        assert!(s.contains(r#""carrier":"direct""#));
        assert!(
            !s.contains(r#""stalled""#),
            "false stalled must be skipped: {s}"
        );
        // Wave 3: per-edge and per-agent overlay volume. Unlike `stalled`
        // these are NOT skipped when zero — a mesh that genuinely moved no
        // bytes has to stay distinguishable from an agent too old to count.
        assert!(s.contains(r#""tx":512"#));
        assert!(s.contains(r#""rx":256"#));
        // Wave 4: the relay qualifier serialises when present and is SKIPPED
        // when absent — a direct edge must not carry a null `relay` key
        // (pre-wave-4 payloads stay byte-identical for such links).
        assert!(s.contains(r#""relay":"turn/udp""#));
        assert!(
            !s.contains(r#""relay":null"#),
            "a direct edge must omit `relay`, not null it: {s}"
        );
        assert!(s.contains(r#""overlay_rx_bytes":4096"#));
        assert!(s.contains(r#""overlay_tx_bytes":8192"#));
        assert!(s.contains(r#""tunnel_rx_bytes":65536"#));
        assert!(s.contains(r#""tunnel_tx_bytes":1024"#));
        let back: ClientMsg = serde_json::from_str(&s).unwrap();
        match back {
            ClientMsg::AgentHeartbeat { sys: Some(sys), .. } => {
                assert_eq!(sys.rss_mb, 87);
                assert_eq!(sys.net_tx_bytes, 987_654);
                assert_eq!(sys.derp, 1);
                assert_eq!(sys.peer_rtt_ms, Some(42));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn session_request_browser_caps_default_empty_for_back_compat() {
        // A pre-2B.1 controller that doesn't include browser_caps
        // must still parse — the agent will fall back to h264-only
        // negotiation in that case.
        let json = r#"{"t":"rc:session.request","agent_id":"507f1f77bcf86cd799439012","permissions":"VIEW"}"#;
        let m: ClientMsg = serde_json::from_str(json).unwrap();
        match m {
            ClientMsg::SessionRequest { browser_caps, .. } => {
                assert!(
                    browser_caps.is_empty(),
                    "missing field must default to empty"
                );
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn accepts_extended_json_for_backward_compat() {
        // A client still sending extended JSON parses fine — eases rollout.
        let json = r#"{"t":"rc:session.request","agent_id":{"$oid":"507f1f77bcf86cd799439012"},"permissions":"VIEW | INPUT"}"#;
        let m: ClientMsg = serde_json::from_str(json).unwrap();
        assert!(matches!(m, ClientMsg::SessionRequest { .. }));
    }

    #[test]
    fn error_msg_omits_null_session_id_is_ok() {
        let e = ServerMsg::Error {
            session_id: None,
            code: "x".into(),
            message: "y".into(),
            open_nonce: None,
        };
        let s = serde_json::to_string(&e).unwrap();
        // None → null, not omitted.
        assert!(s.contains("\"session_id\":null"));
    }

    // ─── AgentCloseReason / ServerMsg::Goodbye wire-format locks (rc.53) ───

    #[test]
    fn agent_close_reason_serialises_snake_case() {
        // Lock-in: every variant rides as its canonical snake_case
        // wire name. The agent's `handle_server_msg` match arm + the
        // server's emit sites both pivot on these strings; renaming
        // any is a wire break that strands fielded agents.
        for (variant, expected) in [
            (AgentCloseReason::AgentDeleted, "agent_deleted"),
            (
                AgentCloseReason::ReplacedByNewerConnection,
                "replaced_by_newer_connection",
            ),
            (AgentCloseReason::PolicyRejected, "policy_rejected"),
        ] {
            let m = ServerMsg::Goodbye {
                reason: variant,
                message: "x".into(),
            };
            let s = serde_json::to_string(&m).unwrap();
            assert!(
                s.contains(&format!("\"reason\":\"{expected}\"")),
                "variant {variant:?} did not serialise to {expected:?} in: {s}"
            );
            assert!(s.contains(r#""t":"rc:goodbye""#));
        }
    }

    #[test]
    fn goodbye_round_trips() {
        let m = ServerMsg::Goodbye {
            reason: AgentCloseReason::AgentDeleted,
            message: "re-enrol required".into(),
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: ServerMsg = serde_json::from_str(&s).unwrap();
        match back {
            ServerMsg::Goodbye { reason, message } => {
                assert_eq!(reason, AgentCloseReason::AgentDeleted);
                assert_eq!(message, "re-enrol required");
            }
            other => panic!("expected Goodbye, got {other:?}"),
        }
    }

    #[test]
    fn pre_rc53_server_msg_rejects_goodbye_so_agent_err_arm_fires() {
        // Phase 4 back-compat lock (rc.53 plan v2).
        //
        // A pre-rc.53 agent's `ServerMsg` enum does NOT have the
        // `Goodbye` variant. When the rc.53 server emits an
        // `rc:goodbye` frame, the old agent's `serde_json::from_str`
        // returns `Err` and the existing `Err(e) => debug!(…,
        // "ignoring non-rc:* frame")` arm at
        // `agents/roomlerd/src/signaling.rs:333` swallows it
        // silently — no panic, no fatal exit.
        //
        // We simulate the rc.52 ServerMsg shape via a stripped local
        // enum + the same `#[serde(tag = "t")]` attribute the real
        // enum uses. If serde ever started succeeding here (e.g.
        // because someone added `#[serde(other)]` to `ServerMsg` or
        // changed the tag scheme), this test fires and rc.52 hosts
        // would start panicking on the new variant.

        #[derive(Deserialize, Debug)]
        #[serde(tag = "t")]
        #[allow(dead_code)]
        enum Rc52ServerMsg {
            #[serde(rename = "rc:pong")]
            Pong { id: u32 },
            #[serde(rename = "rc:error")]
            Error { code: String },
        }

        let goodbye_json = r#"{"t":"rc:goodbye","reason":"agent_deleted","message":"x"}"#;
        let result: Result<Rc52ServerMsg, _> = serde_json::from_str(goodbye_json);
        assert!(
            result.is_err(),
            "pre-rc.53 ServerMsg shape must Err on the new Goodbye discriminator \
             (rc.52 agents rely on the `Err(_) => debug!(…)` arm to absorb it)"
        );
    }

    #[test]
    fn goodbye_with_unknown_reason_decodes_to_policy_rejected_default() {
        // Forward-compat: a fielded rc.53 agent that receives a
        // future rc.54+ `reason` string it doesn't know MUST NOT
        // panic / hard-fault. The custom `Deserialize` for
        // `AgentCloseReason` rounds unknown strings to
        // `PolicyRejected` (which the agent treats as fatal —
        // semantically "server told us to stop and we don't know
        // why" matches PolicyRejected better than ReplacedByNewer
        // which would invite a reconnect loop).
        let json = r#"{"t":"rc:goodbye","reason":"xyzzy_brand_new","message":"hi"}"#;
        let back: ServerMsg = serde_json::from_str(json).unwrap();
        match back {
            ServerMsg::Goodbye { reason, message } => {
                assert_eq!(reason, AgentCloseReason::PolicyRejected);
                assert_eq!(message, "hi");
            }
            other => panic!("expected Goodbye, got {other:?}"),
        }
    }

    // ─── FR-27 P10: the host's Disconnect on the wire ─────────────────

    /// The device's Disconnect ends a session as `host_disconnect`, in both
    /// directions, under the unchanged `rc:terminate` tag. The spelling is a
    /// compatibility surface: the viewer keys its "the person at the device
    /// ended the session" notice on it, and the audit stores it.
    #[test]
    fn host_disconnect_rides_rc_terminate_both_ways() {
        let sid = ObjectId::new();
        let up = ClientMsg::Terminate {
            session_id: sid,
            reason: EndReason::HostDisconnect,
            limit: None,
        };
        let s = serde_json::to_string(&up).unwrap();
        assert!(s.contains(r#""t":"rc:terminate""#), "{s}");
        assert!(s.contains(r#""reason":"host_disconnect""#), "{s}");
        assert!(!s.contains("limit"), "no limit is skipped: {s}");
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::Terminate {
                session_id,
                reason,
                limit,
            } => {
                assert_eq!(session_id, sid);
                assert_eq!(reason, EndReason::HostDisconnect);
                assert_eq!(limit, None);
            }
            other => panic!("wrong variant: {other:?}"),
        }

        let down = ServerMsg::Terminate {
            session_id: sid,
            reason: EndReason::HostDisconnect,
            limit: None,
        };
        let s = serde_json::to_string(&down).unwrap();
        assert!(s.contains(r#""reason":"host_disconnect""#), "{s}");
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::Terminate { reason, .. } => assert_eq!(reason, EndReason::HostDisconnect),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// The version matrix's "new agent, old server" cell, documented the way
    /// `pre_rc53_server_msg_rejects_goodbye_so_agent_err_arm_fires` does it:
    /// a pre-P10 `EndReason` has no `host_disconnect`, so a pre-P10 server
    /// fails to decode the WHOLE frame and its
    /// `Err(e) => debug!(…, "ignoring non-rc:* message on agent socket")`
    /// arm drops it — the socket stays up, the session ends when the peer
    /// closes, and the viewer reconnects as it did before P10. Degraded,
    /// never broken. If this ever started decoding, the cell would have
    /// changed shape and the matrix in the FR-27 spec would be stale.
    #[test]
    fn pre_p10_end_reason_rejects_host_disconnect_so_old_servers_drop_the_frame() {
        // A pre-P10 server's `EndReason`, re-declared on its own. A mock
        // `ClientMsg` would need the `rc:terminate` tag spelled as a serde
        // rename, and `composition::wire_names` reads every such literal in
        // this file as a wire name (the FR-69 composition gate). Serde fails
        // the whole frame when one field fails, so the reason is the cell.
        #[derive(Deserialize, Debug)]
        #[serde(rename_all = "snake_case")]
        #[allow(dead_code)]
        enum PreP10EndReason {
            ControllerHangup,
            AgentHangup,
            UserDenied,
            ConsentTimeout,
            NoPromptSurface,
            AgentDisconnect,
            AdminTerminated,
            IdleTimeout,
            Error,
        }
        let reason_of = |reason: EndReason| -> serde_json::Value {
            serde_json::to_value(ClientMsg::Terminate {
                session_id: ObjectId::new(),
                reason,
                limit: None,
            })
            .unwrap()["reason"]
                .clone()
        };
        let new = reason_of(EndReason::HostDisconnect);
        assert_eq!(new, serde_json::json!("host_disconnect"));
        assert!(
            serde_json::from_value::<PreP10EndReason>(new).is_err(),
            "a pre-P10 decoder must reject host_disconnect"
        );
        // And the same decoder still takes what a pre-P10 agent sends, so the
        // test proves the VARIANT is the difference, not the shape.
        assert!(
            serde_json::from_value::<PreP10EndReason>(reason_of(EndReason::AgentHangup)).is_ok()
        );
    }

    // ─── rc:tunnel.* wire-format locks (T2.1) ─────────────────────────
    //
    // Every new variant gets a roundtrip test AND a discriminator-pin
    // assertion. Multi-tenant tunneling is a security boundary —
    // renaming a discriminator without coordinating client + server +
    // agent is a wire break that strands enrolled clients in the
    // field.

    #[test]
    fn tunnel_hello_roundtrip() {
        let m = ClientMsg::TunnelHello {
            role: TunnelRole::Client,
            version: "0.4.0".into(),
            supported_transports: vec!["webrtc-dc-v1".into()],
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:tunnel.hello""#));
        assert!(s.contains(r#""role":"client""#));
        assert!(s.contains(r#""supported_transports":["webrtc-dc-v1"]"#));
        let back: ClientMsg = serde_json::from_str(&s).unwrap();
        match back {
            ClientMsg::TunnelHello {
                role,
                version,
                supported_transports,
            } => {
                assert_eq!(role, TunnelRole::Client);
                assert_eq!(version, "0.4.0");
                assert_eq!(supported_transports, vec!["webrtc-dc-v1".to_string()]);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn tunnel_open_uses_raw_hex_agent_id() {
        let agent_id = ObjectId::parse_str("507f1f77bcf86cd799439012").unwrap();
        let m = ClientMsg::TunnelOpen {
            agent_id,
            transport: "webrtc-dc-v1".into(),
            open_nonce: None,
            derp_pubkey: None,
            net_grant: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(!s.contains("$oid"), "extended JSON leaked: {s}");
        assert!(s.contains(r#""agent_id":"507f1f77bcf86cd799439012""#));
        assert!(s.contains(r#""t":"rc:tunnel.open""#));
    }

    #[test]
    fn tcp_forward_request_roundtrip() {
        let session_id = ObjectId::parse_str("507f1f77bcf86cd799439011").unwrap();
        let m = ClientMsg::TcpForwardRequest {
            session_id,
            flow_id: 42,
            dst_host: "db.intranet".into(),
            dst_port: 5432,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:tunnel.tcp.request""#));
        assert!(s.contains(r#""flow_id":42"#));
        assert!(s.contains(r#""dst_host":"db.intranet""#));
        assert!(s.contains(r#""dst_port":5432"#));
        let back: ClientMsg = serde_json::from_str(&s).unwrap();
        assert!(matches!(
            back,
            ClientMsg::TcpForwardRequest {
                flow_id: 42,
                dst_port: 5432,
                ..
            }
        ));
    }

    #[test]
    fn udp_forward_wire_discriminators_and_roundtrip() {
        let session_id = ObjectId::parse_str("507f1f77bcf86cd799439011").unwrap();
        // Client → server request.
        let req = ClientMsg::UdpForwardRequest {
            session_id,
            flow_id: 7,
            dst_host: "dns.intranet".into(),
            dst_port: 53,
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(s.contains(r#""t":"rc:tunnel.udp.request""#));
        assert!(s.contains(r#""dst_port":53"#));
        assert!(matches!(
            serde_json::from_str::<ClientMsg>(&s).unwrap(),
            ClientMsg::UdpForwardRequest {
                flow_id: 7,
                dst_port: 53,
                ..
            }
        ));

        // Client → server close (agent-emitted too).
        let closed = ClientMsg::UdpClosed {
            session_id,
            flow_id: 7,
            reason: CloseReason::IdleTimeout,
        };
        let s = serde_json::to_string(&closed).unwrap();
        assert!(s.contains(r#""t":"rc:tunnel.udp.closed""#));

        // Server → agent forward.
        let owner = ObjectId::parse_str("507f1f77bcf86cd799439012").unwrap();
        let fwd = ServerMsg::UdpForwardForward {
            session_id,
            flow_id: 7,
            dst_host: "dns.intranet".into(),
            dst_port: 53,
            owner_user_id: owner,
        };
        let s = serde_json::to_string(&fwd).unwrap();
        assert!(s.contains(r#""t":"rc:tunnel.udp.forward""#));
        assert!(matches!(
            serde_json::from_str::<ServerMsg>(&s).unwrap(),
            ServerMsg::UdpForwardForward {
                flow_id: 7,
                dst_port: 53,
                ..
            }
        ));

        // Server → client accept.
        let acc = ServerMsg::UdpForwardAccept {
            session_id,
            flow_id: 7,
            dc_index: 3,
        };
        let s = serde_json::to_string(&acc).unwrap();
        assert!(s.contains(r#""t":"rc:tunnel.udp.accept""#));
        assert!(s.contains(r#""dc_index":3"#));
    }

    #[test]
    fn destination_rule_proto_defaults_to_any_and_roundtrips() {
        use crate::models::{DestinationRule, HostPattern, PortRange, ProtocolKind};
        // A pre-UDP stored rule (no `proto` field) deserialises to Any.
        let legacy = r#"{"host_pattern":{"kind":"exact","value":"db"},"port_range":{"low":5432,"high":5432}}"#;
        let r: DestinationRule = serde_json::from_str(legacy).unwrap();
        assert_eq!(r.proto, ProtocolKind::Any);
        // Explicit proto round-trips snake_case.
        let udp = DestinationRule {
            host_pattern: HostPattern::Exact("dns".into()),
            port_range: PortRange { low: 53, high: 53 },
            proto: ProtocolKind::Udp,
        };
        let s = serde_json::to_string(&udp).unwrap();
        assert!(s.contains(r#""proto":"udp""#));
        assert_eq!(
            serde_json::from_str::<DestinationRule>(&s).unwrap().proto,
            ProtocolKind::Udp
        );
    }

    #[test]
    fn tcp_forward_reject_kind_serialises_snake_case() {
        // Reject taxonomy drives the audit log roll-up — locking the
        // wire form so a kind:"AclDenied" never sneaks past a
        // case-sensitive matcher.
        let session_id = ObjectId::new();
        let m = ClientMsg::TcpForwardReject {
            session_id,
            flow_id: 7,
            kind: RejectKind::AclDenied,
            reason: "no policy matches".into(),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""kind":"acl_denied""#));

        let cross_tenant = ClientMsg::TcpForwardReject {
            session_id,
            flow_id: 7,
            kind: RejectKind::CrossTenant,
            reason: "x".into(),
        };
        let s = serde_json::to_string(&cross_tenant).unwrap();
        assert!(s.contains(r#""kind":"cross_tenant""#));
    }

    #[test]
    fn tcp_half_close_direction_roundtrip() {
        let m = ClientMsg::TcpHalfClose {
            session_id: ObjectId::new(),
            flow_id: 1,
            direction: Direction::SrcToDst,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""direction":"src_to_dst""#));
        let back: ClientMsg = serde_json::from_str(&s).unwrap();
        assert!(matches!(
            back,
            ClientMsg::TcpHalfClose {
                direction: Direction::SrcToDst,
                ..
            }
        ));
    }

    #[test]
    fn tcp_closed_reason_roundtrip() {
        // Locks every CloseReason variant — the audit log roll-up
        // (T2.2) pivots on these strings; renaming any is a wire +
        // dashboard break.
        for r in [
            CloseReason::Eof,
            CloseReason::IoError,
            CloseReason::AgentAclDenied,
            CloseReason::ClientShutdown,
            CloseReason::ServerTerminated,
            CloseReason::IdleTimeout,
        ] {
            let m = ClientMsg::TcpClosed {
                session_id: ObjectId::new(),
                flow_id: 1,
                reason: r,
                bytes_in: 4_096,
                bytes_out: 512,
            };
            let s = serde_json::to_string(&m).unwrap();
            let back: ClientMsg = serde_json::from_str(&s).unwrap();
            match back {
                ClientMsg::TcpClosed {
                    reason,
                    bytes_in,
                    bytes_out,
                    ..
                } => {
                    assert_eq!(reason, r);
                    assert_eq!((bytes_in, bytes_out), (4_096, 512));
                }
                _ => panic!("wrong variant"),
            }
        }
    }

    /// Wave 3 — a pre-wave-3 client omits the byte counts entirely; the
    /// server must still parse the close and simply book zero, because a
    /// flow that fails to close would leak its audit row.
    #[test]
    fn tcp_closed_without_byte_counts_still_parses() {
        let legacy = r#"{"t":"rc:tunnel.tcp.closed","session_id":"6a1f00000000000000000001","flow_id":7,"reason":"eof"}"#;
        match serde_json::from_str::<ClientMsg>(legacy).unwrap() {
            ClientMsg::TcpClosed {
                flow_id,
                bytes_in,
                bytes_out,
                ..
            } => {
                assert_eq!(flow_id, 7);
                assert_eq!((bytes_in, bytes_out), (0, 0));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn server_tunnel_opened_carries_diagnostics() {
        // dc_pool_size + sctp_rwnd_bytes are critical for the CLI's
        // diagnose subcommand — verifying the vendored webrtc patch
        // took effect at runtime needs sctp_rwnd_bytes ≥ 1 MiB.
        let session_id = ObjectId::new();
        let m = ServerMsg::TunnelOpened {
            session_id,
            transport: "webrtc-dc-v1".into(),
            dc_pool_size: 8,
            sctp_rwnd_bytes: 8 * 1024 * 1024,
            ice_servers: vec![],
            quic_auth_token: None,
            open_nonce: None,
            net_grant_id: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:tunnel.opened""#));
        assert!(s.contains(r#""dc_pool_size":8"#));
        assert!(s.contains(r#""sctp_rwnd_bytes":8388608"#));
        // Back-compat: a None quic_auth_token must NOT appear on the
        // wire, so a webrtc-dc-v1 controller predating the field parses
        // TunnelOpened unchanged. Same contract for the P3b-2 open_nonce,
        // and for FR-90 P3-7-2a's net_grant_id.
        assert!(!s.contains("quic_auth_token"));
        assert!(!s.contains("open_nonce"));
        assert!(!s.contains("net_grant_id"));
    }

    #[test]
    fn tunnel_opened_carries_quic_auth_token_when_set() {
        let m = ServerMsg::TunnelOpened {
            session_id: ObjectId::new(),
            transport: "quic-v1".into(),
            dc_pool_size: 0,
            sctp_rwnd_bytes: 0,
            ice_servers: vec![],
            quic_auth_token: Some("tok-abc123".into()),
            open_nonce: None,
            net_grant_id: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""transport":"quic-v1""#));
        assert!(s.contains(r#""quic_auth_token":"tok-abc123""#));
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::TunnelOpened {
                quic_auth_token,
                transport,
                ..
            } => {
                assert_eq!(transport, "quic-v1");
                assert_eq!(quic_auth_token.as_deref(), Some("tok-abc123"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn tunnel_opened_missing_quic_auth_token_defaults_to_none() {
        // An OLD server (no field) → the wire omits it → a NEW client
        // must deserialize None (serde default) and treat it as a
        // webrtc-dc-v1 session. Locks the back-compat path.
        let json = r#"{"t":"rc:tunnel.opened","session_id":"6a11682e804368d30edf57c6","transport":"webrtc-dc-v1","dc_pool_size":8,"sctp_rwnd_bytes":8388608,"ice_servers":[]}"#;
        match serde_json::from_str::<ServerMsg>(json).unwrap() {
            ServerMsg::TunnelOpened {
                quic_auth_token, ..
            } => assert_eq!(quic_auth_token, None),
            _ => panic!("wrong variant"),
        }
    }

    // ─── open_nonce correlation-id wire locks (P3b-2) ──────────────────
    //
    // The daemon multiplexes N tunnel-client opens over its single agent
    // WS and demuxes each `TunnelOpened` / open-failure `Error` by the
    // `open_nonce` it stamped on the `TunnelOpen`. These lock: (a) the
    // nonce round-trips on all three carriers when set, (b) it is OMITTED
    // (not null) when None so a pre-P3b-2 peer is byte-identical, and
    // (c) a wire frame with no `open_nonce` deserialises to None (the
    // single-open CLI + old-server safe-degrade path).

    #[test]
    fn tunnel_open_carries_open_nonce_when_set() {
        let m = ClientMsg::TunnelOpen {
            agent_id: ObjectId::new(),
            transport: "webrtc-dc-v1".into(),
            open_nonce: Some("nonce-7f3a".into()),
            derp_pubkey: None,
            net_grant: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""open_nonce":"nonce-7f3a""#));
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::TunnelOpen { open_nonce, .. } => {
                assert_eq!(open_nonce.as_deref(), Some("nonce-7f3a"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn tunnel_open_omits_open_nonce_when_none() {
        // A single-open CLI sends None → the field must not appear, so a
        // pre-P3b-2 server (which has no such field) parses it unchanged.
        let m = ClientMsg::TunnelOpen {
            agent_id: ObjectId::new(),
            transport: "webrtc-dc-v1".into(),
            open_nonce: None,
            derp_pubkey: None,
            net_grant: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(
            !s.contains("open_nonce"),
            "None nonce leaked onto wire: {s}"
        );
        assert!(!s.contains("net_grant"), "None grant leaked onto wire: {s}");
    }

    #[test]
    fn tunnel_open_missing_open_nonce_defaults_to_none() {
        // A pre-P3b-2 client omits the field → a P3b-2 server must
        // deserialize None (serde default) and match the reply
        // positionally.
        let json = r#"{"t":"rc:tunnel.open","agent_id":"507f1f77bcf86cd799439012","transport":"webrtc-dc-v1"}"#;
        match serde_json::from_str::<ClientMsg>(json).unwrap() {
            ClientMsg::TunnelOpen { open_nonce, .. } => assert_eq!(open_nonce, None),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn tunnel_opened_carries_open_nonce_when_set() {
        let m = ServerMsg::TunnelOpened {
            session_id: ObjectId::new(),
            transport: "webrtc-dc-v1".into(),
            dc_pool_size: 8,
            sctp_rwnd_bytes: 8 * 1024 * 1024,
            ice_servers: vec![],
            quic_auth_token: None,
            open_nonce: Some("nonce-7f3a".into()),
            net_grant_id: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""open_nonce":"nonce-7f3a""#));
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::TunnelOpened { open_nonce, .. } => {
                assert_eq!(open_nonce.as_deref(), Some("nonce-7f3a"));
            }
            _ => panic!("wrong variant"),
        }
    }

    /// FR-90 P3-7-2a — a session's grant rides `rc:tunnel.open`, and the id
    /// of the grant the server bound comes back on `rc:tunnel.opened`. An
    /// `opened` from a server before the field reads back with no id: a
    /// device must take that as "not bound".
    #[test]
    fn tunnel_open_carries_a_grant_and_opened_echoes_its_id() {
        let m = ClientMsg::TunnelOpen {
            agent_id: ObjectId::new(),
            transport: "webrtc-dc-v1".into(),
            open_nonce: Some("n1".into()),
            derp_pubkey: None,
            net_grant: Some("the-grant".into()),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""net_grant":"the-grant""#), "{s}");
        assert!(matches!(
            serde_json::from_str::<ClientMsg>(&s).unwrap(),
            ClientMsg::TunnelOpen { net_grant: Some(ref g), .. } if g == "the-grant"
        ));
        let opened = ServerMsg::TunnelOpened {
            session_id: ObjectId::new(),
            transport: "webrtc-dc-v1".into(),
            dc_pool_size: 8,
            sctp_rwnd_bytes: 0,
            ice_servers: vec![],
            quic_auth_token: None,
            open_nonce: Some("n1".into()),
            net_grant_id: Some("g1".into()),
        };
        let s = serde_json::to_string(&opened).unwrap();
        assert!(s.contains(r#""net_grant_id":"g1""#), "{s}");
        let before = r#"{"t":"rc:tunnel.opened","session_id":"6a11682e804368d30edf57c6","transport":"webrtc-dc-v1","dc_pool_size":8,"sctp_rwnd_bytes":0,"ice_servers":[]}"#;
        assert!(matches!(
            serde_json::from_str::<ServerMsg>(before).unwrap(),
            ServerMsg::TunnelOpened {
                net_grant_id: None,
                ..
            }
        ));
    }

    #[test]
    fn error_carries_open_nonce_when_set() {
        // The open-failure carrier: the server rejects a TunnelOpen and
        // echoes the nonce so the daemon fails the exact pending flow.
        let e = ServerMsg::Error {
            session_id: None,
            code: "cross_tenant".into(),
            message: "agent belongs to a different tenant".into(),
            open_nonce: Some("nonce-dead".into()),
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains(r#""open_nonce":"nonce-dead""#));
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::Error {
                open_nonce, code, ..
            } => {
                assert_eq!(open_nonce.as_deref(), Some("nonce-dead"));
                assert_eq!(code, "cross_tenant");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn error_missing_open_nonce_defaults_to_none() {
        // A nonce-less Error mid-open (e.g. from a pre-P3b-2 server that
        // routed the open to the Hub) MUST decode to None so the daemon
        // reads it as "open rejected / server too old" and fails fast —
        // never hangs the pending waiter.
        let json = r#"{"t":"rc:error","session_id":null,"code":"boom","message":"x"}"#;
        match serde_json::from_str::<ServerMsg>(json).unwrap() {
            ServerMsg::Error { open_nonce, .. } => assert_eq!(open_nonce, None),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn tunnel_quic_ready_round_trips_with_distinct_discriminator() {
        let m = ClientMsg::TunnelQuicReady {
            session_id: ObjectId::new(),
            cert_fingerprint: "ab".repeat(32),
            addrs: vec!["203.0.113.7:51820".into(), "192.168.1.5:51820".into()],
            derp_pubkey: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:tunnel.quic.ready""#));
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::TunnelQuicReady {
                cert_fingerprint,
                addrs,
                ..
            } => {
                assert_eq!(cert_fingerprint.len(), 64);
                assert_eq!(addrs.len(), 2);
            }
            _ => panic!("wrong variant"),
        }
    }

    /// R4 wire lock — the derp-flavor fields: absent ⇒ omitted (pre-R4
    /// byte-identical wire), present ⇒ they survive serialization + parse on
    /// BOTH enums. The server relays `ClientMsg::TunnelQuicReady` by
    /// REBUILDING `ServerMsg::TunnelQuicReady` — a lagging server struct is
    /// exactly where the field would silently vanish, so both sides lock.
    #[test]
    fn tunnel_derp_fields_lock_omission_and_presence() {
        let pk = "ab".repeat(32);
        let m = ClientMsg::TunnelOpen {
            agent_id: ObjectId::new(),
            transport: "quic-derp-v1".into(),
            open_nonce: None,
            derp_pubkey: Some(pk.clone()),
            net_grant: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(&format!(r#""derp_pubkey":"{pk}""#)));

        let m = ServerMsg::TunnelQuicSetup {
            session_id: ObjectId::new(),
            quic_auth_token: "tok".into(),
            ice_servers: vec![],
            transport: Some("quic-derp-v1".into()),
            client_derp_pubkey: Some(pk.clone()),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""transport":"quic-derp-v1""#));
        assert!(s.contains(&format!(r#""client_derp_pubkey":"{pk}""#)));
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::TunnelQuicSetup {
                transport,
                client_derp_pubkey,
                ..
            } => {
                assert_eq!(transport.as_deref(), Some("quic-derp-v1"));
                assert_eq!(client_derp_pubkey.as_deref(), Some(pk.as_str()));
            }
            other => panic!("wrong variant: {other:?}"),
        }

        // The agent→server ready and its server→client relay twin BOTH carry
        // the pubkey; None omits it on both.
        let m = ClientMsg::TunnelQuicReady {
            session_id: ObjectId::new(),
            cert_fingerprint: "cd".repeat(32),
            addrs: vec![],
            derp_pubkey: Some(pk.clone()),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(&format!(r#""derp_pubkey":"{pk}""#)));
        let m = ServerMsg::TunnelQuicReady {
            session_id: ObjectId::new(),
            cert_fingerprint: "cd".repeat(32),
            addrs: vec![],
            derp_pubkey: Some(pk.clone()),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(&format!(r#""derp_pubkey":"{pk}""#)));
        let m = ServerMsg::TunnelQuicReady {
            session_id: ObjectId::new(),
            cert_fingerprint: "cd".repeat(32),
            addrs: vec![],
            derp_pubkey: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(!s.contains("derp_pubkey"), "None leaked onto the wire: {s}");
    }

    #[test]
    fn tunnel_quic_setup_is_server_to_agent() {
        let m = ServerMsg::TunnelQuicSetup {
            session_id: ObjectId::new(),
            quic_auth_token: "tok-xyz".into(),
            ice_servers: vec![IceServer {
                urls: vec!["turn:coturn.roomler.live:3478?transport=udp".into()],
                username: Some("1780000000:agent".into()),
                credential: Some("base64hmac".into()),
            }],
            transport: None,
            client_derp_pubkey: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:tunnel.quic.setup""#));
        assert!(s.contains(r#""quic_auth_token":"tok-xyz""#));
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::TunnelQuicSetup { ice_servers, .. } => {
                assert_eq!(ice_servers.len(), 1, "agent gets its own TURN creds");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn tunnel_quic_setup_back_compat_no_ice_servers() {
        // A pre-3c server omits `ice_servers`; a 3c+ agent must still
        // deserialize it (serde default → empty), treating the absence
        // as "no relay creds, direct only".
        let json = r#"{"t":"rc:tunnel.quic.setup","session_id":"69e2a1ee7af054f8a14e84c6","quic_auth_token":"tok"}"#;
        match serde_json::from_str::<ServerMsg>(json).unwrap() {
            ServerMsg::TunnelQuicSetup { ice_servers, .. } => assert!(ice_servers.is_empty()),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn tunnel_quic_candidate_round_trips_both_directions() {
        // client → server
        let c = ClientMsg::TunnelQuicCandidate {
            session_id: ObjectId::new(),
            addrs: vec!["94.130.141.74:49160".into()],
        };
        let cs = serde_json::to_string(&c).unwrap();
        assert!(cs.contains(r#""t":"rc:tunnel.quic.candidate""#));
        match serde_json::from_str::<ClientMsg>(&cs).unwrap() {
            ClientMsg::TunnelQuicCandidate { addrs, .. } => assert_eq!(addrs.len(), 1),
            _ => panic!("wrong client variant"),
        }
        // server → agent (same wire tag, mirror variant)
        let s = ServerMsg::TunnelQuicCandidate {
            session_id: ObjectId::new(),
            addrs: vec!["94.130.141.74:49160".into(), "10.0.0.4:51820".into()],
        };
        let ss = serde_json::to_string(&s).unwrap();
        assert!(ss.contains(r#""t":"rc:tunnel.quic.candidate""#));
        match serde_json::from_str::<ServerMsg>(&ss).unwrap() {
            ServerMsg::TunnelQuicCandidate { addrs, .. } => assert_eq!(addrs.len(), 2),
            _ => panic!("wrong server variant"),
        }
    }

    #[test]
    fn server_tunnel_revoked_round_trips() {
        // Promoted from the T1 stub plain-JSON frame in
        // crates/api/src/ws/tunnel.rs. Reason field is human-readable;
        // discriminator is what handlers gate on.
        let m = ServerMsg::TunnelRevoked {
            reason: "status changed to Quarantined".into(),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:tunnel.revoked""#));
        let back: ServerMsg = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, ServerMsg::TunnelRevoked { .. }));
    }

    #[test]
    fn server_tcp_forward_forward_has_distinct_discriminator() {
        // ServerMsg uses a different variant name + discriminator
        // (`rc:tunnel.tcp.forward`) than the client-side
        // `rc:tunnel.tcp.request` so the agent's match is exhaustive
        // without an ambiguous `t` shared across enums.
        let m = ServerMsg::TcpForwardForward {
            session_id: ObjectId::new(),
            flow_id: 1,
            dst_host: "h".into(),
            dst_port: 1,
            owner_user_id: ObjectId::new(),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:tunnel.tcp.forward""#));
        assert!(!s.contains("rc:tunnel.tcp.request"));
    }

    #[test]
    fn tunnel_terminate_uses_close_reason() {
        // Re-uses the CloseReason taxonomy from per-flow closes — one
        // taxonomy means one audit dashboard, no double maintenance.
        let m = ClientMsg::TunnelTerminate {
            session_id: ObjectId::new(),
            reason: CloseReason::ClientShutdown,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""reason":"client_shutdown""#));
    }

    #[test]
    fn tunnel_sdp_offer_uses_distinct_discriminator() {
        // `rc:tunnel.sdp.offer` is distinct from the remote-control
        // `rc:sdp.offer` so the server can route by session-namespace
        // without ambiguity.
        let m = ClientMsg::TunnelSdpOffer {
            session_id: ObjectId::new(),
            sdp: "v=0\r\n".into(),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:tunnel.sdp.offer""#));
        assert!(!s.contains(r#""t":"rc:sdp.offer""#));
        let back: ClientMsg = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, ClientMsg::TunnelSdpOffer { .. }));
    }

    #[test]
    fn server_tunnel_sdp_answer_round_trips() {
        let m = ServerMsg::TunnelSdpAnswer {
            session_id: ObjectId::new(),
            sdp: "v=0\r\n".into(),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:tunnel.sdp.answer""#));
        let back: ServerMsg = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, ServerMsg::TunnelSdpAnswer { .. }));
    }

    #[test]
    fn tunnel_ice_carries_arbitrary_json_candidate() {
        // Candidates ride as opaque JSON so we don't have to mirror
        // the webrtc-rs RTCIceCandidateInit shape in this crate.
        let candidate = serde_json::json!({
            "candidate": "candidate:1 1 udp 2122252543 192.0.2.1 12345 typ host",
            "sdpMid": "0",
            "sdpMLineIndex": 0,
        });
        let m = ClientMsg::TunnelIce {
            session_id: ObjectId::new(),
            candidate: candidate.clone(),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:tunnel.ice""#));
        let back: ClientMsg = serde_json::from_str(&s).unwrap();
        match back {
            ClientMsg::TunnelIce { candidate: c2, .. } => assert_eq!(c2, candidate),
            other => panic!("expected TunnelIce, got {other:?}"),
        }
    }

    // ─── rc:overlay.* wire-format locks ───────────────────────────────

    /// A netmap missing `epoch` still decodes.
    ///
    /// `epoch` was REQUIRED and read by nobody: the agent destructures
    /// `{ self_ip, network, peers, .. }`, and the resync it was added for was
    /// never built. So a sender that omitted it failed the whole `ServerMsg`
    /// parse, and the node got no address and no peers — a total mesh failure
    /// caused by a field with no consumer.
    ///
    /// This is the shape of the bug, not just the instance: any required field
    /// on a frame the agent must parse can silently destroy it. The parse arm
    /// in `signaling.rs` now WARNs when an `rc:`-tagged frame fails to decode,
    /// so the next one is visible instead of invisible.
    #[test]
    fn a_netmap_without_epoch_still_decodes_and_does_not_strand_the_node() {
        let no_epoch = r#"{"t":"rc:overlay.netmap","self_ip":"100.65.0.7",
            "network":{"cidr":"100.65.0.0/22","mtu":1280},"peers":[]}"#;
        match serde_json::from_str::<ServerMsg>(no_epoch).unwrap() {
            ServerMsg::OverlayNetmap {
                self_ip,
                epoch,
                peers,
                ..
            } => {
                assert_eq!(self_ip, "100.65.0.7", "the address still arrives");
                assert_eq!(epoch, 0, "a missing epoch defaults rather than failing");
                assert!(peers.is_empty());
            }
            other => panic!("expected OverlayNetmap, got {other:?}"),
        }

        // Same for a delta — where the cost of losing one is worse: a dropped
        // REMOVAL leaves a node routing to an address that may since have been
        // recycled to a different device.
        let delta = r#"{"t":"rc:overlay.netmap_delta","upserts":[],
            "removes":["6a95ba653d54d39b773c56ba"]}"#;
        match serde_json::from_str::<ServerMsg>(delta).unwrap() {
            ServerMsg::OverlayNetmapDelta { epoch, removes, .. } => {
                assert_eq!(epoch, 0);
                assert_eq!(
                    removes.iter().map(|o| o.to_hex()).collect::<Vec<_>>(),
                    vec!["6a95ba653d54d39b773c56ba".to_string()],
                    "the removal survives a missing epoch"
                );
            }
            other => panic!("expected OverlayNetmapDelta, got {other:?}"),
        }
    }

    /// FR-47 P5d — a netmap from a pre-P5d server decodes, and carries no
    /// block list rather than an invented one.
    #[test]
    fn a_pre_p5d_netmap_still_decodes_and_carries_no_block_list() {
        // FR-47 P5d — the compatibility property the whole phase rests on: a
        // netmap from a server that has never heard of `cidrs` must decode, and
        // must leave the field EMPTY rather than inventing a list. An agent
        // then falls back to `cidr`, which is what it always used.
        let old = r#"{"t":"rc:overlay.netmap","self_ip":"100.65.0.7",
            "network":{"cidr":"100.65.0.0/22","mtu":1280},"peers":[],"epoch":1}"#;
        match serde_json::from_str::<ServerMsg>(old).unwrap() {
            ServerMsg::OverlayNetmap { network, .. } => {
                assert_eq!(network.cidr, "100.65.0.0/22");
                assert!(
                    network.cidrs.is_empty(),
                    "a pre-P5d server sends no block list; inventing one would make \
                     the agent trust a space the server never described"
                );
            }
            other => panic!("expected OverlayNetmap, got {other:?}"),
        }

        // And the reverse direction: a P5d server's netmap for a network that
        // has NOT grown carries a one-element list whose only entry equals
        // `cidr`. That equality is what makes multi-block inert on every
        // deployment that exists today.
        let net = OverlayNetworkInfo {
            org_relay_fallback_v1: false,
            org_relay_loss_v1: false,
            cidr: "100.65.0.0/22".into(),
            cidrs: vec!["100.65.0.0/22".into()],
            mtu: 1280,
            magic_domain: None,
            nameservers: vec![],
            self_name: None,
            stun_urls: vec![],
        };
        let s = serde_json::to_string(&net).unwrap();
        let back: OverlayNetworkInfo = serde_json::from_str(&s).unwrap();
        assert_eq!(back.cidrs, vec![back.cidr.clone()]);
    }

    /// FR-68 / FR-47 P5d — the half of the compatibility claim that was missing.
    ///
    /// The test above proves OLD-server → NEW-decoder. This proves the direction
    /// that actually carries risk, and the one FR-47 flagged as unargued: a P5d
    /// server's netmap **for a GROWN org**, decoded by an agent that has never
    /// heard of `cidrs`.
    ///
    /// The decoder below is copied VERBATIM from `agent-v0.4.42` — the last
    /// release before P5d (`agent-v0.4.43` is the first with it). ⚠️ Do not
    /// "modernise" it or share it with the real types: its entire value is that
    /// it is frozen. It has no `cidrs` and no `deny_unknown_fields`, and that
    /// pairing is the property under test — serde ignores an unknown FIELD,
    /// while an unknown internally-tagged VARIANT would fail the whole frame
    /// (locked separately by
    /// `pre_rc53_server_msg_rejects_goodbye_so_agent_err_arm_fires`).
    ///
    /// ⚠️ What this does NOT prove: that the SERVER picks the right block. The
    /// netmap here is hand-built, so `cidr` is whatever this test wrote. The
    /// server's per-recipient choice is asserted end-to-end in
    /// `overlay_growth_tests`, against a netmap the server actually sent.
    #[test]
    fn a_grown_org_netmap_decodes_on_a_pinned_pre_p5d_agent() {
        #[derive(Deserialize)]
        struct PinnedNetworkInfo {
            cidr: String,
            #[allow(dead_code)]
            mtu: u16,
        }

        #[derive(Deserialize)]
        #[serde(tag = "t")]
        enum PinnedServerMsg {
            #[serde(rename = "rc:overlay.netmap")]
            OverlayNetmap {
                self_ip: String,
                network: PinnedNetworkInfo,
            },
        }

        // A GROWN org: block 0 is full, block 1 was appended. This node holds an
        // ordinal in block 1, so P5d sends it block 1 as its own `cidr`.
        let grown = ServerMsg::OverlayNetmap {
            org_relay_discovery: true,
            path_trial_v1: true,
            self_ip: "100.65.8.1".into(),
            network: OverlayNetworkInfo {
                org_relay_fallback_v1: false,
                org_relay_loss_v1: false,
                cidr: "100.65.8.0/22".into(),
                cidrs: vec!["100.65.4.0/22".into(), "100.65.8.0/22".into()],
                mtu: 1280,
                magic_domain: None,
                nameservers: vec![],
                self_name: None,
                stun_urls: vec![],
            },
            peers: vec![],
            epoch: 7,
        };
        let wire = serde_json::to_string(&grown).unwrap();

        let decoded: PinnedServerMsg = serde_json::from_str(&wire).expect(
            "a pre-P5d agent must still decode a grown-org netmap; if this fails, \
             every agent below 0.4.43 is stranded the moment an org grows",
        );
        let PinnedServerMsg::OverlayNetmap { self_ip, network } = decoded;

        // The on-link prefix the old agent derives contains its own address and
        // excludes the other block — checked structurally, never by string
        // prefix. FR-47 recorded that trap: a `starts_with` test passed against
        // wrong behaviour.
        let (base, plen) = network.cidr.split_once('/').unwrap();
        let base: std::net::Ipv4Addr = base.parse().unwrap();
        let plen: u32 = plen.parse().unwrap();
        let mask = u32::MAX << (32 - plen);
        let contains = |ip: &str| {
            let ip: std::net::Ipv4Addr = ip.parse().unwrap();
            u32::from(ip) & mask == u32::from(base) & mask
        };
        assert!(contains(&self_ip), "the node's own address must be on-link");
        assert!(
            !contains("100.65.4.7"),
            "a block-0 address must NOT fall inside block 1's on-link prefix — \
             cross-block peers are reached by their per-peer /32s"
        );
    }

    /// FR-47 — the refusal frame round-trips, and an OLD node that omits
    /// `supports_join_refusal` decodes as `false` so the server withholds it.
    #[test]
    fn overlay_join_refused_roundtrips_and_the_capability_defaults_off() {
        let m = ServerMsg::OverlayJoinRefused {
            reason: OverlayJoinRefusal::AddressSpaceExhausted,
            detail: "every host ordinal up to 1022 is leased".into(),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:overlay.join_refused""#));
        assert!(s.contains(r#""reason":"address_space_exhausted""#));
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::OverlayJoinRefused { reason, detail } => {
                assert_eq!(reason, OverlayJoinRefusal::AddressSpaceExhausted);
                assert!(
                    !reason.is_retryable(),
                    "a full block does not empty on retry"
                );
                assert!(detail.contains("1022"));
            }
            other => panic!("expected OverlayJoinRefused, got {other:?}"),
        }

        // A pre-FR-47 join carries no capability field at all.
        let old = r#"{"t":"rc:overlay.join","wg_public_key":"k","key_epoch":0,
            "supported":[],"mtu":1280,"endpoints":[]}"#;
        match serde_json::from_str::<ClientMsg>(old).unwrap() {
            ClientMsg::OverlayJoin {
                supports_join_refusal,
                ..
            } => assert!(
                !supports_join_refusal,
                "an older node must default OFF, so the server never sends it a \
                 frame it cannot parse"
            ),
            other => panic!("expected OverlayJoin, got {other:?}"),
        }
    }

    /// A reason this build has never heard of must not fail the frame — the
    /// same forward-compat hatch `AgentCloseReason` has. It lands on
    /// `Unknown`, which is deliberately NOT retryable: a refusal we cannot
    /// interpret is not one we can safely retry against.
    #[test]
    fn an_unknown_refusal_reason_decodes_to_unknown_and_is_not_retryable() {
        let json = r#"{"t":"rc:overlay.join_refused","reason":"quota_exceeded_v9",
            "detail":"from a newer server"}"#;
        match serde_json::from_str::<ServerMsg>(json).unwrap() {
            ServerMsg::OverlayJoinRefused { reason, detail } => {
                assert_eq!(reason, OverlayJoinRefusal::Unknown);
                assert!(!reason.is_retryable());
                assert_eq!(detail, "from a newer server");
            }
            other => panic!("expected OverlayJoinRefused, got {other:?}"),
        }
    }

    #[test]
    fn overlay_join_roundtrip() {
        let m = ClientMsg::OverlayJoin {
            network_hint: None,
            wg_public_key: "cHVia2V5".into(),
            key_epoch: 0,
            supported: vec!["wireguard-v1".into(), "quic-v1".into()],
            mtu: 1280,
            endpoints: vec!["203.0.113.5:51820".into()],
            supports_quic: true,
            supports_relay_single: true,
            supports_derp: true,
            supports_forced_derp: true,
            supports_overlay_echo: false,
            supports_org_relay: false,
            supports_org_relay_multi_candidate: false,
            supports_org_relay_discovery_cursor: false,
            supports_path_trial_v1: false,
            supports_path_backbone_v1: false,
            relay_backbone_ready: false,
            supports_join_refusal: true,
            org_primary: None,
            relay_port: None,
            supports_server_relay_strategy: true,
            supports_derp_floor: true,
            advertised_routes: vec!["192.168.1.0/24".into()],
            route_offer_withheld: Some("WinNAT is not available".into()),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:overlay.join""#));
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::OverlayJoin {
                wg_public_key,
                mtu,
                supported,
                supports_quic,
                supports_relay_single,
                supports_derp,
                supports_forced_derp,
                supports_server_relay_strategy,
                supports_derp_floor,
                advertised_routes,
                route_offer_withheld,
                ..
            } => {
                assert_eq!(wg_public_key, "cHVia2V5");
                // FR-97 P0b — the reason a device offers nothing round-trips.
                assert_eq!(
                    route_offer_withheld.as_deref(),
                    Some("WinNAT is not available")
                );
                assert_eq!(mtu, 1280);
                assert!(supported.iter().any(|t| t == "wireguard-v1"));
                assert!(supports_quic, "supports_quic must round-trip");
                assert!(
                    supports_relay_single,
                    "supports_relay_single must round-trip"
                );
                assert!(supports_derp, "supports_derp must round-trip");
                assert!(
                    supports_forced_derp,
                    "supports_forced_derp must round-trip (P7)"
                );
                assert!(
                    supports_server_relay_strategy,
                    "supports_server_relay_strategy must round-trip (U2)"
                );
                assert!(
                    supports_derp_floor,
                    "supports_derp_floor must round-trip (Phase A)"
                );
                assert_eq!(advertised_routes, vec!["192.168.1.0/24".to_string()]);
            }
            other => panic!("expected OverlayJoin, got {other:?}"),
        }
        // P7 back-compat lock: a pre-P7 join (no supports_forced_derp key)
        // parses with the flag defaulted false.
        let legacy = r#"{"t":"rc:overlay.join","wg_public_key":"cHVia2V5","mtu":1280}"#;
        match serde_json::from_str::<ClientMsg>(legacy).unwrap() {
            ClientMsg::OverlayJoin {
                supports_forced_derp,
                supports_overlay_echo,
                route_offer_withheld,
                ..
            } => {
                assert!(!supports_forced_derp, "absent flag must default false");
                // FR-97 P0b back-compat lock: an older agent says nothing.
                assert_eq!(route_offer_withheld, None);
                // Data-probe back-compat lock: a pre-capability join (no
                // supports_overlay_echo key) defaults false ⇒ peers probe
                // this node with ICMP, never the overlay-native echo.
                assert!(
                    !supports_overlay_echo,
                    "absent supports_overlay_echo must default false"
                );
            }
            other => panic!("expected OverlayJoin, got {other:?}"),
        }
    }

    /// P7 — `rc:overlay.force_derp` wire-format lock: hex node id + ttl_ms
    /// round-trip, and the tag string is stable.
    #[test]
    fn overlay_force_derp_roundtrip() {
        let id = ObjectId::new();
        let m = ServerMsg::OverlayForceDerp {
            peer_node_id: id,
            ttl_ms: 1_800_000,
            derp_url: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:overlay.force_derp""#));
        assert!(
            s.contains(&id.to_hex()),
            "node id must serialize as raw hex"
        );
        // Wire-compat lock: a central-DERP pin (None) serializes WITHOUT the
        // field — byte-identical to the pre-region message, so old agents see
        // exactly what they always saw.
        assert!(!s.contains("derp_url"));
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::OverlayForceDerp {
                peer_node_id,
                ttl_ms,
                derp_url,
            } => {
                assert_eq!(peer_node_id, id);
                assert_eq!(ttl_ms, 1_800_000);
                assert_eq!(derp_url, None);
            }
            other => panic!("expected OverlayForceDerp, got {other:?}"),
        }
        // Regional pin round-trips the url.
        let m = ServerMsg::OverlayForceDerp {
            peer_node_id: id,
            ttl_ms: 1,
            derp_url: Some("wss://derp-us-east.roomler.ai/derp".into()),
        };
        let s = serde_json::to_string(&m).unwrap();
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::OverlayForceDerp { derp_url, .. } => {
                assert_eq!(
                    derp_url.as_deref(),
                    Some("wss://derp-us-east.roomler.ai/derp")
                );
            }
            other => panic!("expected OverlayForceDerp, got {other:?}"),
        }
    }

    /// Multi-region DERP ticket wire locks.
    #[test]
    fn derp_ticket_request_and_reply_roundtrip() {
        let m = ClientMsg::DerpTicketRequest {};
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:relay.derp_ticket_request""#));
        assert!(matches!(
            serde_json::from_str::<ClientMsg>(&s).unwrap(),
            ClientMsg::DerpTicketRequest {}
        ));

        let m = ServerMsg::DerpTicket {
            ticket: "eyJ.header.sig".into(),
            exp: 1_900_000_000,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:relay.derp_ticket""#));
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::DerpTicket { ticket, exp } => {
                assert_eq!(ticket, "eyJ.header.sig");
                assert_eq!(exp, 1_900_000_000);
            }
            other => panic!("expected DerpTicket, got {other:?}"),
        }
    }

    #[test]
    fn agent_update_now_roundtrip() {
        // pin omitted entirely when None (wire-compat lock: old servers /
        // agents never see a null field).
        let m = ServerMsg::UpdateNow { pin: None };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:agent.update""#));
        assert!(!s.contains("pin"), "pin must be omitted when None: {s}");
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::UpdateNow { pin } => assert_eq!(pin, None),
            other => panic!("expected UpdateNow, got {other:?}"),
        }

        let m = ServerMsg::UpdateNow {
            pin: Some("agent-v0.3.0-rc.260".to_string()),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""pin":"agent-v0.3.0-rc.260""#));
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::UpdateNow { pin } => {
                assert_eq!(pin.as_deref(), Some("agent-v0.3.0-rc.260"))
            }
            other => panic!("expected UpdateNow, got {other:?}"),
        }
    }

    // ─── FR-40 key-rotation wire locks ───────────────────────────────

    /// The order carries NO key material — and never may. A future field
    /// named like a key would turn "the server orders a re-mint it never
    /// sees" into a delivery path, so the frame's whole shape is pinned.
    #[test]
    fn key_rotate_order_carries_no_key_shaped_field() {
        let m = ServerMsg::KeyRotate {
            request_id: "req-1".to_string(),
        };
        let v: serde_json::Value = serde_json::to_value(&m).unwrap();
        assert_eq!(v["t"], "rc:agent.key_rotate");
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["request_id", "t"],
            "the order is exactly {{t, request_id}}: {v}"
        );
        for k in &keys {
            let k = k.to_ascii_lowercase();
            assert!(
                !k.contains("key") && !k.contains("secret") && !k.contains("priv"),
                "a key-shaped field on the ORDER would make the server a key path: {k}"
            );
        }
        match serde_json::from_str::<ServerMsg>(&serde_json::to_string(&m).unwrap()).unwrap() {
            ServerMsg::KeyRotate { request_id } => assert_eq!(request_id, "req-1"),
            other => panic!("expected KeyRotate, got {other:?}"),
        }
    }

    /// FR-92 — the org policy frame is exactly `{t, denied}`, both ways.
    /// It can only carry a deny; a field that could turn keep busy ON from
    /// the server would make it a server-forgeable input path.
    #[test]
    fn keep_busy_policy_frame_is_pinned() {
        for denied in [true, false] {
            let m = ServerMsg::KeepBusyPolicy { denied };
            let v: serde_json::Value = serde_json::to_value(&m).unwrap();
            assert_eq!(v["t"], "rc:agent.keep_busy_policy");
            assert_eq!(v["denied"], denied);
            let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(keys, ["denied", "t"], "{v}");
            match serde_json::from_str::<ServerMsg>(&v.to_string()).unwrap() {
                ServerMsg::KeepBusyPolicy { denied: d } => assert_eq!(d, denied),
                other => panic!("expected KeepBusyPolicy, got {other:?}"),
            }
        }
    }

    /// FR-92 P5b — the keep-busy brief rides the heartbeat both ways, and a
    /// heartbeat from an agent that predates it still parses, as "nothing to
    /// say". An off brief carries no pattern and no name.
    #[test]
    fn keep_busy_brief_rides_the_heartbeat_and_is_optional() {
        use crate::models::KeepBusyBrief;
        let old = r#"{"t":"rc:agent.heartbeat","rss_mb":0,"cpu_pct":0.0,"active_sessions":0}"#;
        match serde_json::from_str::<ClientMsg>(old).unwrap() {
            ClientMsg::AgentHeartbeat { keep_busy, .. } => assert!(keep_busy.is_none()),
            other => panic!("expected a heartbeat, got {other:?}"),
        }
        let brief = KeepBusyBrief {
            on: true,
            phase: "paused".into(),
            reason: Some("user_active".into()),
            pattern: Some("heart".into()),
            set_by: Some("Alice".into()),
        };
        let hb = ClientMsg::AgentHeartbeat {
            rss_mb: 0,
            cpu_pct: 0.0,
            active_sessions: 0,
            sys: None,
            srflx_count: None,
            warm_relay: None,
            caps: None,
            companion_version: None,
            keep_busy: Some(brief.clone()),
        };
        let v: serde_json::Value = serde_json::to_value(&hb).unwrap();
        assert_eq!(v["keep_busy"]["phase"], "paused");
        assert_eq!(v["keep_busy"]["set_by"], "Alice");
        match serde_json::from_value::<ClientMsg>(v).unwrap() {
            ClientMsg::AgentHeartbeat { keep_busy, .. } => assert_eq!(keep_busy, Some(brief)),
            other => panic!("expected a heartbeat, got {other:?}"),
        }
        let off = KeepBusyBrief {
            on: false,
            phase: "off".into(),
            reason: None,
            pattern: None,
            set_by: None,
        };
        assert_eq!(
            serde_json::to_string(&off).unwrap(),
            r#"{"on":false,"phase":"off"}"#
        );
    }

    #[test]
    fn key_rotated_report_roundtrip_and_public_only() {
        use crate::models::KeyRotationOutcome;
        let m = ClientMsg::KeyRotated {
            request_id: "req-1".to_string(),
            outcome: KeyRotationOutcome::Rotated,
            old_public_key: Some("old==".to_string()),
            new_public_key: Some("new==".to_string()),
            key_epoch: 3,
            detail: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:agent.key_rotated""#));
        assert!(s.contains(r#""outcome":"rotated""#));
        assert!(!s.contains("detail"), "detail omitted when None: {s}");
        assert!(!s.contains("secret"), "{s}");
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::KeyRotated {
                request_id,
                outcome,
                new_public_key,
                key_epoch,
                ..
            } => {
                assert_eq!(request_id, "req-1");
                assert_eq!(outcome, KeyRotationOutcome::Rotated);
                assert_eq!(new_public_key.as_deref(), Some("new=="));
                assert_eq!(key_epoch, 3);
            }
            other => panic!("expected KeyRotated, got {other:?}"),
        }
        // A refusal parses with no keys and a detail.
        let refused = r#"{"t":"rc:agent.key_rotated","request_id":"r","outcome":"disabled","detail":"overlay_key_rotation=false"}"#;
        match serde_json::from_str::<ClientMsg>(refused).unwrap() {
            ClientMsg::KeyRotated {
                outcome, key_epoch, ..
            } => {
                assert_eq!(outcome, KeyRotationOutcome::Disabled);
                assert_eq!(key_epoch, 0);
            }
            other => panic!("expected KeyRotated, got {other:?}"),
        }
    }

    // ─── Fleet RPC wire locks ────────────────────────────────────────

    #[test]
    fn rpc_exec_roundtrip() {
        let m = ServerMsg::RpcExec {
            request_id: "r1".into(),
            shell: "pwsh".into(),
            command: "Get-NetRoute -AddressFamily IPv4".into(),
            timeout_ms: 30_000,
            max_output_bytes: 262_144,
            cwd: None,
            caller: "goran".into(),
            consent_mode: Some(crate::models::ConsentMode::Auto),
            via_service: false,
            run_as: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:rpc.exec""#));
        assert!(s.contains(r#""consent_mode":"auto""#));
        // `cwd` omitted entirely when None — an older decoder must never see
        // a null it has to special-case.
        assert!(!s.contains("cwd"), "cwd must be omitted when None: {s}");
        // FR-94 — `via_service` is omitted when false, so every frame to a
        // worker-path device stays byte-for-byte what it was before.
        assert!(
            !s.contains("via_service"),
            "via_service must be omitted when false: {s}"
        );
        // FR-97 P5a — and `run_as` when absent, for the same reason.
        assert!(
            !s.contains("run_as"),
            "run_as must be omitted when None: {s}"
        );
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::RpcExec {
                request_id,
                shell,
                timeout_ms,
                max_output_bytes,
                caller,
                ..
            } => {
                assert_eq!(request_id, "r1");
                assert_eq!(shell, "pwsh");
                assert_eq!(timeout_ms, 30_000);
                assert_eq!(max_output_bytes, 262_144);
                assert_eq!(caller, "goran");
            }
            other => panic!("expected RpcExec, got {other:?}"),
        }

        // An absent consent_mode must decode to None — which the agent reads
        // as "prompt". The fail-safe direction for a gate that grants root is
        // to ask, so a frame from an older/partial server can never be taken
        // as blanket unattended approval.
        let bare = r#"{"t":"rc:rpc.exec","request_id":"r2","shell":"bash",
            "command":"id","timeout_ms":1000,"max_output_bytes":1024,"caller":"x"}"#;
        match serde_json::from_str::<ServerMsg>(bare).unwrap() {
            ServerMsg::RpcExec {
                consent_mode,
                via_service,
                run_as,
                ..
            } => {
                assert_eq!(consent_mode, None);
                // FR-94 — and an absent `via_service` is the worker path.
                assert!(!via_service);
                // FR-97 P5a — and an absent `run_as` is the daemon.
                assert_eq!(run_as, None);
            }
            other => panic!("expected RpcExec, got {other:?}"),
        }
        let as_person = r#"{"t":"rc:rpc.exec","request_id":"r4","shell":"bash",
            "command":"id","timeout_ms":1000,"max_output_bytes":1024,"caller":"x",
            "run_as":"console_user"}"#;
        match serde_json::from_str::<ServerMsg>(as_person).unwrap() {
            ServerMsg::RpcExec { run_as, .. } => {
                assert_eq!(run_as.as_deref(), Some("console_user"))
            }
            other => panic!("expected RpcExec, got {other:?}"),
        }
        let via = r#"{"t":"rc:rpc.exec","request_id":"r3","shell":"pwsh",
            "command":"whoami","timeout_ms":1000,"max_output_bytes":1024,"caller":"x",
            "via_service":true}"#;
        match serde_json::from_str::<ServerMsg>(via).unwrap() {
            ServerMsg::RpcExec { via_service, .. } => assert!(via_service),
            other => panic!("expected RpcExec, got {other:?}"),
        }

        let c = ServerMsg::RpcCancel {
            request_id: "r1".into(),
        };
        let s = serde_json::to_string(&c).unwrap();
        assert!(s.contains(r#""t":"rc:rpc.cancel""#));
        assert!(matches!(
            serde_json::from_str::<ServerMsg>(&s).unwrap(),
            ServerMsg::RpcCancel { .. }
        ));
    }

    #[test]
    fn rpc_result_roundtrip() {
        let m = ClientMsg::RpcResult {
            request_id: "r1".into(),
            exit_code: Some(0),
            stdout: "ok".into(),
            stderr: String::new(),
            truncated: false,
            duration_ms: 12,
            error: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:rpc.result""#));
        // Empty streams + a None error stay off the wire: a fleet-wide
        // heartbeat-rate message shouldn't carry three empty strings.
        assert!(!s.contains("stderr"), "empty stderr must be omitted: {s}");
        assert!(!s.contains("error"), "None error must be omitted: {s}");
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::RpcResult {
                exit_code,
                stdout,
                stderr,
                error,
                ..
            } => {
                assert_eq!(exit_code, Some(0));
                assert_eq!(stdout, "ok");
                assert_eq!(stderr, "");
                assert_eq!(error, None);
            }
            other => panic!("expected RpcResult, got {other:?}"),
        }

        // A refusal / timeout carries `error` and no exit code — the shape a
        // caller must be able to distinguish from "ran and exited 0".
        let m = ClientMsg::RpcResult {
            request_id: "r2".into(),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
            duration_ms: 30_000,
            error: Some("timed out after 30000ms".into()),
        };
        let s = serde_json::to_string(&m).unwrap();
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::RpcResult {
                exit_code, error, ..
            } => {
                assert_eq!(exit_code, None);
                assert_eq!(error.as_deref(), Some("timed out after 30000ms"));
            }
            other => panic!("expected RpcResult, got {other:?}"),
        }
    }

    #[test]
    fn rpc_request_and_response_roundtrip() {
        let m = ClientMsg::RpcExecRequest {
            request_id: "c1".into(),
            target: "winhost-a".into(),
            shell: "pwsh".into(),
            command: "Get-NetAdapter".into(),
            timeout_ms: 0,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:rpc.request""#));
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::RpcExecRequest { target, shell, .. } => {
                assert_eq!(target, "winhost-a");
                assert_eq!(shell, "pwsh");
            }
            other => panic!("expected RpcExecRequest, got {other:?}"),
        }

        let r = ServerMsg::RpcExecResponse {
            request_id: "c1".into(),
            exit_code: Some(1),
            stdout: String::new(),
            stderr: "boom".into(),
            truncated: true,
            duration_ms: 5,
            error: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""t":"rc:rpc.response""#));
        assert!(s.contains(r#""truncated":true"#));
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::RpcExecResponse {
                exit_code,
                stderr,
                truncated,
                ..
            } => {
                assert_eq!(exit_code, Some(1));
                assert_eq!(stderr, "boom");
                assert!(truncated);
            }
            other => panic!("expected RpcExecResponse, got {other:?}"),
        }
    }

    #[test]
    fn rpc_caps_absent_on_older_agents() {
        // An agent that predates Fleet RPC sends no `rpc` key at all; the
        // server must read that as "no exec capability" and refuse with 412
        // rather than pushing a message into its unknown-tag debug branch.
        let caps: crate::models::AgentCaps =
            serde_json::from_str(r#"{"hw_encoders":[],"codecs":[],"has_input_permission":false,"supports_clipboard":false,"supports_file_transfer":false,"max_simultaneous_sessions":1}"#)
                .unwrap();
        assert!(caps.rpc.is_empty());

        // And an empty list must not be serialised back onto the wire.
        let s = serde_json::to_string(&caps).unwrap();
        assert!(!s.contains("rpc"), "empty rpc caps must be omitted: {s}");
    }

    #[test]
    fn overlay_endpoints_and_leave_roundtrip() {
        let e = ClientMsg::OverlayEndpoints {
            candidates: vec!["198.51.100.7:51820".into()],
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains(r#""t":"rc:overlay.endpoints""#));
        assert!(matches!(
            serde_json::from_str::<ClientMsg>(&s).unwrap(),
            ClientMsg::OverlayEndpoints { .. }
        ));

        let l = ClientMsg::OverlayLeave {};
        let s = serde_json::to_string(&l).unwrap();
        assert!(s.contains(r#""t":"rc:overlay.leave""#));
        assert!(matches!(
            serde_json::from_str::<ClientMsg>(&s).unwrap(),
            ClientMsg::OverlayLeave {}
        ));
    }

    #[test]
    fn overlay_srflx_trickle_roundtrip() {
        // Phase B — the srflx trickle is its own message tag, distinct from
        // `rc:overlay.endpoints`, so the server routes it into the separate
        // `srflx_endpoints` bucket.
        let e = ClientMsg::OverlaySrflx {
            candidates: vec!["198.51.100.7:41820".into()],
            nat: Some("cone".into()),
            udp_dialer_ok: None,
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains(r#""t":"rc:overlay.srflx""#));
        assert!(s.contains(r#""candidates":["198.51.100.7:41820"]"#));
        assert!(s.contains(r#""nat":"cone""#));
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::OverlaySrflx {
                candidates, nat, ..
            } => {
                assert_eq!(candidates, vec!["198.51.100.7:41820".to_string()]);
                assert_eq!(nat.as_deref(), Some("cone"));
            }
            other => panic!("expected OverlaySrflx, got {other:?}"),
        }

        // Phase C back-compat: a pre-Phase-C agent (rc.199) sends only
        // `candidates` (no `nat`) → parses with nat = None; and a None nat is
        // OMITTED on the wire (skip_serializing_if).
        let legacy = r#"{"t":"rc:overlay.srflx","candidates":["1.2.3.4:5"]}"#;
        match serde_json::from_str::<ClientMsg>(legacy).unwrap() {
            ClientMsg::OverlaySrflx {
                candidates, nat, ..
            } => {
                assert_eq!(candidates, vec!["1.2.3.4:5".to_string()]);
                assert_eq!(nat, None);
            }
            other => panic!("expected OverlaySrflx, got {other:?}"),
        }
        let none_nat = ClientMsg::OverlaySrflx {
            candidates: vec!["1.2.3.4:5".into()],
            nat: None,
            udp_dialer_ok: None,
        };
        assert!(
            !serde_json::to_string(&none_nat).unwrap().contains("nat"),
            "a None nat must be omitted on the wire"
        );
    }

    /// C4 stage 1 — the warm-relay request/grant pair's wire tags are
    /// LOCKED (request-driven, so no hello capability flag exists to catch
    /// a tag drift — the tag itself is the contract).
    #[test]
    fn warm_relay_wire_roundtrip() {
        let m = ClientMsg::OverlayWarmRelayRequest {};
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains("\"rc:overlay.warm_relay_request\""), "{s}");
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::OverlayWarmRelayRequest {} => {}
            other => panic!("roundtrip mismatch: {other:?}"),
        }
        let g = ServerMsg::OverlayWarmRelayGrant {
            ice_servers: vec![],
        };
        let s = serde_json::to_string(&g).unwrap();
        assert!(s.contains("\"rc:overlay.warm_relay_grant\""), "{s}");
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::OverlayWarmRelayGrant { ice_servers } => assert!(ice_servers.is_empty()),
            other => panic!("roundtrip mismatch: {other:?}"),
        }
    }

    #[test]
    fn overlay_relay_request_uses_raw_hex_peer_id() {
        let peer = ObjectId::parse_str("507f1f77bcf86cd799439014").unwrap();
        let m = ClientMsg::OverlayRelayRequest {
            peer_node_id: peer,
            current_kind: None,
            reason: None,
            derp_mux_failed: false,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:overlay.relay_request""#));
        assert!(!s.contains("$oid"));
        // U1 — absent evidence stays OFF the wire entirely, so an old server
        // sees byte-identical requests from a new fresh-establishment client.
        assert!(!s.contains("current_kind"));
        assert!(!s.contains("reason"));
        assert!(!s.contains("derp_mux_failed"));
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::OverlayRelayRequest { peer_node_id, .. } => assert_eq!(peer_node_id, peer),
            other => panic!("expected OverlayRelayRequest, got {other:?}"),
        }
    }

    /// U1 — wire-compat both directions: a LEGACY request (no evidence
    /// fields) decodes with inert defaults, and a populated one round-trips.
    #[test]
    fn overlay_relay_request_evidence_fields_roundtrip_and_default() {
        let legacy =
            r#"{"t":"rc:overlay.relay_request","peer_node_id":"507f1f77bcf86cd799439014"}"#;
        match serde_json::from_str::<ClientMsg>(legacy).unwrap() {
            ClientMsg::OverlayRelayRequest {
                current_kind,
                reason,
                derp_mux_failed,
                ..
            } => {
                assert_eq!(current_kind, None);
                assert_eq!(reason, None);
                assert!(!derp_mux_failed);
            }
            other => panic!("expected OverlayRelayRequest, got {other:?}"),
        }
        let m = ClientMsg::OverlayRelayRequest {
            peer_node_id: ObjectId::parse_str("507f1f77bcf86cd799439014").unwrap(),
            current_kind: Some("turn".into()),
            reason: Some("rekey-unanswered".into()),
            derp_mux_failed: true,
        };
        let s = serde_json::to_string(&m).unwrap();
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::OverlayRelayRequest {
                current_kind,
                reason,
                derp_mux_failed,
                ..
            } => {
                assert_eq!(current_kind.as_deref(), Some("turn"));
                assert_eq!(reason.as_deref(), Some("rekey-unanswered"));
                assert!(derp_mux_failed);
            }
            other => panic!("expected OverlayRelayRequest, got {other:?}"),
        }
    }

    #[test]
    fn overlay_netmap_roundtrip_with_raw_hex_node_id() {
        let node_id = ObjectId::parse_str("507f1f77bcf86cd799439011").unwrap();
        // P3b-3: the agent_id backing an agent node — a DISTINCT ObjectId from
        // node_id (different namespace), so the test can assert both round-trip.
        let agent_id = ObjectId::parse_str("aaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let m = ServerMsg::OverlayNetmap {
            org_relay_discovery: false,
            path_trial_v1: false,
            self_ip: "100.64.0.3".into(),
            network: OverlayNetworkInfo {
                org_relay_fallback_v1: false,
                org_relay_loss_v1: false,
                cidr: "100.64.0.0/10".into(),
                cidrs: vec![],
                mtu: 1280,
                magic_domain: Some("myorg.roomler.net".into()),
                nameservers: vec!["1.1.1.1".into()],
                self_name: None,
                stun_urls: vec!["stun:5.9.157.221:3478".into()],
            },
            peers: vec![NetmapPeer {
                node_id,
                overlay_ip: "100.64.0.4".into(),
                name: "devbox".into(),
                wg_public_key: "cGVlcg==".into(),
                endpoints: vec!["203.0.113.9:51820".into()],
                lan_endpoints: vec!["203.0.113.9:51820".into()],
                srflx_endpoints: vec!["198.51.100.7:41820".into()],
                srflx_nat: Some("cone".into()),
                caps: None,
                udp_dialer_ok: None,
                relay_home: None,
                warm_relay_endpoint: None,
                reachable: true,
                supports_quic: true,
                supports_relay_single: true,
                supports_derp: true,
                supports_forced_derp: true,
                supports_derp_floor: false,
                supports_org_relay: false,
                supports_overlay_echo: false,
                relay_strategy: Some(RelayStrategyWire::SingleRelayDialer),
                routes: vec!["10.0.0.0/24".into()],
                agent_id: Some(agent_id),
                ingress_rules: None,
            }],
            epoch: 7,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:overlay.netmap""#));
        // P4 — an un-compiled `ingress_rules` must be ABSENT from the wire, not
        // `null`: a pre-P4 node's netmap shape has to stay byte-identical, and
        // `None` (no ACL) must never be confused with `Some([])` (denied).
        assert!(!s.contains("ingress_rules"));
        // Both node_id AND the populated agent_id are bare hex on the wire (no
        // $oid) — the latter locks the `option_oid_hex` serde (a bare
        // `Option<ObjectId>` would leak bson `{"$oid":…}`, the B1 trap).
        assert!(!s.contains("$oid"));

        // …and when rules ARE compiled they round-trip, including the
        // Some([]) = "denied" shape that must survive as distinct from None.
        let mut m2 = m.clone();
        if let ServerMsg::OverlayNetmap { peers, .. } = &mut m2 {
            peers[0].ingress_rules = Some(vec![crate::models::OverlayRule {
                cidr: "10.66.0.0/16".into(),
                port_range: crate::models::PortRange { low: 22, high: 22 },
                proto: crate::models::ProtocolKind::Tcp,
            }]);
        }
        let s2 = serde_json::to_string(&m2).unwrap();
        assert!(s2.contains(r#""cidr":"10.66.0.0/16""#));
        assert!(s2.contains(r#""proto":"tcp""#));
        let back: ServerMsg = serde_json::from_str(&s2).unwrap();
        let ServerMsg::OverlayNetmap { peers, .. } = &back else {
            panic!("wrong variant");
        };
        let rules = peers[0].ingress_rules.as_ref().unwrap();
        assert_eq!(rules[0].port_range.high, 22);

        let mut m3 = m.clone();
        if let ServerMsg::OverlayNetmap { peers, .. } = &mut m3 {
            peers[0].ingress_rules = Some(Vec::new());
        }
        let back3: ServerMsg = serde_json::from_str(&serde_json::to_string(&m3).unwrap()).unwrap();
        let ServerMsg::OverlayNetmap { peers, .. } = &back3 else {
            panic!("wrong variant");
        };
        assert_eq!(
            peers[0].ingress_rules.as_deref(),
            Some(&[][..]),
            "Some([]) must survive the wire as DENY, never decay to None"
        );
        assert!(s.contains("\"507f1f77bcf86cd799439011\""));
        assert!(s.contains("\"aaaaaaaaaaaaaaaaaaaaaaaa\""));
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::OverlayNetmap {
                self_ip,
                peers,
                epoch,
                ..
            } => {
                assert_eq!(self_ip, "100.64.0.3");
                assert_eq!(epoch, 7);
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].node_id, node_id);
                assert_eq!(peers[0].agent_id, Some(agent_id));
                // U2 — the server verdict + echoed forced-DERP support
                // round-trip.
                assert_eq!(
                    peers[0].relay_strategy,
                    Some(RelayStrategyWire::SingleRelayDialer)
                );
                assert!(peers[0].supports_forced_derp);
            }
            other => panic!("expected OverlayNetmap, got {other:?}"),
        }
        // U2 — the verdict serialises as a kebab string tag.
        assert!(s.contains(r#""relay_strategy":"single-relay-dialer""#));
    }

    /// U2 — wire compat both directions: a pre-U2 peer omits both
    /// `relay_strategy` and `supports_forced_derp` (⇒ `None`/`false`, the
    /// client-authoritative path), and every verdict variant round-trips
    /// through its kebab tag.
    #[test]
    fn relay_strategy_wire_defaults_and_roundtrips() {
        let legacy = r#"{
            "node_id":"507f1f77bcf86cd799439011",
            "overlay_ip":"100.64.0.4",
            "wg_public_key":"cGVlcg==",
            "reachable":true
        }"#;
        let p: NetmapPeer = serde_json::from_str(legacy).unwrap();
        assert_eq!(p.relay_strategy, None);
        assert!(!p.supports_forced_derp);
        // An absent verdict must stay OFF the wire (pre-U2 shape unchanged).
        assert!(
            !serde_json::to_string(&p)
                .unwrap()
                .contains("relay_strategy")
        );

        for (v, tag) in [
            (RelayStrategyWire::SingleRelayAnchor, "single-relay-anchor"),
            (RelayStrategyWire::SingleRelayDialer, "single-relay-dialer"),
            (RelayStrategyWire::Derp, "derp"),
            (RelayStrategyWire::BothAllocate, "both-allocate"),
        ] {
            let j = serde_json::to_string(&v).unwrap();
            assert_eq!(j, format!("\"{tag}\""), "{v:?} tag");
            assert_eq!(serde_json::from_str::<RelayStrategyWire>(&j).unwrap(), v);
        }
    }

    /// Back-compat: a netmap peer from a pre-P3b-3 server carries no `agent_id`
    /// field → it deserialises to `None` (no Tunnel labelling), unchanged.
    #[test]
    fn netmap_peer_without_agent_id_defaults_to_none() {
        let json = r#"{
            "node_id":"507f1f77bcf86cd799439011",
            "overlay_ip":"100.64.0.4",
            "name":"devbox",
            "wg_public_key":"cGVlcg==",
            "reachable":true
        }"#;
        let p: NetmapPeer = serde_json::from_str(json).unwrap();
        assert!(p.agent_id.is_none());
    }

    /// FR-19 wire locks: the three relay-session tags, raw-hex ObjectIds, the
    /// skipped-when-absent `rtt_ms`, and the `org-relay` verdict string. A
    /// rename here does not fail loudly — it makes every deployed device look
    /// like it lacks the feature.
    #[test]
    fn org_relay_messages_wire_roundtrip_and_tags_are_locked() {
        let oid = ObjectId::parse_str("507f1f77bcf86cd799439011").unwrap();
        let m = ServerMsg::OverlayRelaySession {
            vni: 0x0042_4242,
            generation: 3,
            peer_node_id: oid,
            relay_node_id: oid,
            relay_endpoints: vec!["62.210.194.66:3478".into()],
            bind_secret: "AAAA".into(),
            bind_secs: 30,
            max_lifetime_secs: 3600,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:overlay.relay_session""#), "{s}");
        assert!(
            s.contains(r#""peer_node_id":"507f1f77bcf86cd799439011""#),
            "ObjectIds must be raw hex, not $oid: {s}"
        );
        let ServerMsg::OverlayRelaySession {
            vni, generation, ..
        } = serde_json::from_str(&s).unwrap()
        else {
            panic!("relay_session must round-trip");
        };
        assert_eq!((vni, generation), (0x0042_4242, 3));

        let m = ServerMsg::OverlayRelayServe {
            vni: 7,
            generation: 1,
            members: vec![
                RelayMemberWire {
                    wg_public_key: "a".into(),
                    bind_secret: "b".into(),
                },
                RelayMemberWire {
                    wg_public_key: "c".into(),
                    bind_secret: "d".into(),
                },
            ],
            bind_secs: 30,
            idle_secs: 300,
            max_lifetime_secs: 3600,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:overlay.relay_serve""#), "{s}");
        let ServerMsg::OverlayRelayServe { members, .. } = serde_json::from_str(&s).unwrap() else {
            panic!("relay_serve must round-trip");
        };
        assert_eq!(members.len(), 2);
        assert_eq!(members[1].bind_secret, "d");

        let s = serde_json::to_string(&ServerMsg::OverlayRelayRevoke { vni: 7 }).unwrap();
        assert!(s.contains(r#""t":"rc:overlay.relay_revoke""#), "{s}");

        let m = ClientMsg::OverlayRelayProbe {
            relay_node_id: oid,
            endpoint: "62.210.194.66:3478".into(),
            reachable: true,
            rtt_ms: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:overlay.relay_probe""#), "{s}");
        assert!(!s.contains("rtt_ms"), "an absent rtt must be skipped: {s}");

        assert_eq!(
            serde_json::to_string(&RelayStrategyWire::OrgRelay).unwrap(),
            r#""org-relay""#
        );
    }

    /// The join flag and its netmap echo both default to `false`, and the echo
    /// is SKIPPED when false, so a pre-FR-19 node's netmap shape is unchanged.
    #[test]
    fn supports_org_relay_defaults_false_and_is_skipped_in_the_netmap() {
        let json = r#"{"node_id":"507f1f77bcf86cd799439011","overlay_ip":"100.64.0.4",
                       "name":"d","wg_public_key":"cGVlcg==","reachable":true}"#;
        let p: NetmapPeer = serde_json::from_str(json).unwrap();
        assert!(!p.supports_org_relay);
        assert!(
            !serde_json::to_string(&p)
                .unwrap()
                .contains("supports_org_relay"),
            "false must be skipped, not serialised"
        );
    }

    /// The regression this shim exists for, at the level where it actually
    /// bites: a NEWER server stamps a `relay_strategy` tag this build has
    /// never heard of, and an OLDER agent must still parse the **whole
    /// netmap** and install its peers.
    ///
    /// Without `relay_strategy_lenient` the unknown tag is a hard serde error
    /// on the enclosing `ServerMsg` — the frame is lost, not the field — and
    /// the agent's parse arm swallows it at `debug!`. That is a fleet-wide,
    /// silent peer-install outage triggered by a server-side deploy, which is
    /// why this asserts the surviving peer's other fields too: "it parsed" is
    /// the claim, not merely "the enum was None".
    #[test]
    fn unknown_relay_strategy_tag_keeps_the_whole_netmap_parseable() {
        let json = r#"{
            "t":"rc:overlay.netmap",
            "self_ip":"100.64.0.2",
            "network":{"cidr":"100.64.0.0/10","mtu":1280},
            "epoch":7,
            "peers":[{
                "node_id":"507f1f77bcf86cd799439011",
                "overlay_ip":"100.64.0.4",
                "name":"devbox",
                "wg_public_key":"cGVlcg==",
                "reachable":true,
                "relay_strategy":"some-future-relay-kind"
            }]
        }"#;
        let msg: ServerMsg =
            serde_json::from_str(json).expect("unknown tag must not fail the frame");
        let ServerMsg::OverlayNetmap { peers, epoch, .. } = msg else {
            panic!("expected an OverlayNetmap");
        };
        assert_eq!(epoch, 7);
        assert_eq!(peers.len(), 1, "the peer must survive, not be dropped");
        assert_eq!(peers[0].name, "devbox");
        assert_eq!(peers[0].overlay_ip, "100.64.0.4");
        assert!(
            peers[0].relay_strategy.is_none(),
            "unknown ⇒ None ⇒ the client derives the tier locally, exactly as for an absent field"
        );
    }

    /// Leniency must not swallow the values that DO exist — a shim that
    /// mapped everything to `None` would pass the test above while silently
    /// disabling the server verdict fleet-wide.
    #[test]
    fn every_known_relay_strategy_tag_still_decodes() {
        for (tag, want) in [
            ("single-relay-anchor", RelayStrategyWire::SingleRelayAnchor),
            ("single-relay-dialer", RelayStrategyWire::SingleRelayDialer),
            ("derp", RelayStrategyWire::Derp),
            ("both-allocate", RelayStrategyWire::BothAllocate),
            ("org-relay", RelayStrategyWire::OrgRelay),
        ] {
            let json = format!(
                r#"{{"node_id":"507f1f77bcf86cd799439011","overlay_ip":"100.64.0.4",
                     "name":"d","wg_public_key":"cGVlcg==","reachable":true,
                     "relay_strategy":"{tag}"}}"#
            );
            let p: NetmapPeer = serde_json::from_str(&json).unwrap();
            assert_eq!(p.relay_strategy, Some(want), "tag {tag} must still decode");
            // …and still serialise back to the same tag.
            let s = serde_json::to_string(&p).unwrap();
            assert!(s.contains(&format!(r#""relay_strategy":"{tag}""#)), "{s}");
        }
    }

    /// Absent, `null`, and a non-string shape all mean "no verdict". The last
    /// case matters because a future variant that grows a payload would arrive
    /// as a map, and an older agent must degrade rather than lose the frame.
    #[test]
    fn relay_strategy_absent_null_and_non_string_all_decode_to_none() {
        let base = r#""node_id":"507f1f77bcf86cd799439011","overlay_ip":"100.64.0.4",
                      "name":"d","wg_public_key":"cGVlcg==","reachable":true"#;
        for tail in [
            String::new(),
            r#","relay_strategy":null"#.to_string(),
            r#","relay_strategy":{"org-relay":{"vni":7}}"#.to_string(),
            r#","relay_strategy":42"#.to_string(),
        ] {
            let p: NetmapPeer = serde_json::from_str(&format!("{{{base}{tail}}}")).unwrap();
            assert!(
                p.relay_strategy.is_none(),
                "tail {tail} must decode to None"
            );
        }
    }

    /// Back-compat both directions for the Phase-A `lan_endpoints` field: a
    /// pre-Phase-A server omits it → defaults empty (public-direct tier inert);
    /// and an empty vec is OMITTED on the wire (`skip_serializing_if`), so a
    /// Phase-A node talking to any consumer serialises byte-identically to
    /// before unless the bucket is populated.
    #[test]
    fn netmap_peer_lan_endpoints_default_and_skip() {
        let json = r#"{
            "node_id":"507f1f77bcf86cd799439011",
            "overlay_ip":"100.64.0.4",
            "wg_public_key":"cGVlcg==",
            "reachable":true
        }"#;
        let p: NetmapPeer = serde_json::from_str(json).unwrap();
        assert!(p.lan_endpoints.is_empty());
        let s = serde_json::to_string(&p).unwrap();
        assert!(
            !s.contains("lan_endpoints"),
            "empty lan_endpoints must be omitted on the wire: {s}"
        );
        // Populated → serialised and round-trips.
        let mut p2 = p.clone();
        p2.lan_endpoints = vec!["5.9.157.226:41234".into()];
        let s2 = serde_json::to_string(&p2).unwrap();
        assert!(s2.contains(r#""lan_endpoints":["5.9.157.226:41234"]"#));
        assert_eq!(serde_json::from_str::<NetmapPeer>(&s2).unwrap(), p2);
    }

    /// Back-compat both directions for the Phase-B `srflx_endpoints` field: a
    /// pre-Phase-B server omits it → defaults empty (srflx tier inert); an empty
    /// vec is OMITTED on the wire (`skip_serializing_if`); populated round-trips.
    #[test]
    fn netmap_peer_srflx_endpoints_default_and_skip() {
        let json = r#"{
            "node_id":"507f1f77bcf86cd799439011",
            "overlay_ip":"100.64.0.4",
            "wg_public_key":"cGVlcg==",
            "reachable":true
        }"#;
        let p: NetmapPeer = serde_json::from_str(json).unwrap();
        assert!(p.srflx_endpoints.is_empty());
        let s = serde_json::to_string(&p).unwrap();
        assert!(
            !s.contains("srflx_endpoints"),
            "empty srflx_endpoints must be omitted on the wire: {s}"
        );
        let mut p2 = p.clone();
        p2.srflx_endpoints = vec!["198.51.100.7:41820".into()];
        let s2 = serde_json::to_string(&p2).unwrap();
        assert!(s2.contains(r#""srflx_endpoints":["198.51.100.7:41820"]"#));
        assert_eq!(serde_json::from_str::<NetmapPeer>(&s2).unwrap(), p2);
    }

    /// Dialer honesty — `udp_dialer_ok` back-compat, BOTH directions: a
    /// pre-honesty server/peer omits it → `None` (legacy role inputs on both
    /// ends); `None` is OMITTED on the wire (an old shape stays byte-stable);
    /// `Some(_)` round-trips — its PRESENCE is the capability signal.
    #[test]
    fn netmap_peer_and_srflx_msg_udp_dialer_ok_default_skip_and_roundtrip() {
        let json = r#"{
            "node_id":"507f1f77bcf86cd799439011",
            "overlay_ip":"100.64.0.4",
            "wg_public_key":"cGVlcg==",
            "reachable":true
        }"#;
        let p: NetmapPeer = serde_json::from_str(json).unwrap();
        assert_eq!(p.udp_dialer_ok, None);
        let s = serde_json::to_string(&p).unwrap();
        assert!(
            !s.contains("udp_dialer_ok"),
            "absent verdict must be omitted on the wire: {s}"
        );
        let mut p2 = p.clone();
        p2.udp_dialer_ok = Some(false);
        let s2 = serde_json::to_string(&p2).unwrap();
        assert!(s2.contains(r#""udp_dialer_ok":false"#));
        assert_eq!(serde_json::from_str::<NetmapPeer>(&s2).unwrap(), p2);

        // The srflx trickle: an OLD agent's message (no field) parses to
        // `None`; a NEW agent's `Some(_)` round-trips.
        let old = r#"{"t":"rc:overlay.srflx","candidates":["1.2.3.4:5"],"nat":"cone"}"#;
        match serde_json::from_str::<ClientMsg>(old).unwrap() {
            ClientMsg::OverlaySrflx { udp_dialer_ok, .. } => assert_eq!(udp_dialer_ok, None),
            other => panic!("wrong variant: {other:?}"),
        }
        let new = ClientMsg::OverlaySrflx {
            candidates: vec!["1.2.3.4:5".into()],
            nat: Some("symmetric".into()),
            udp_dialer_ok: Some(false),
        };
        let wire = serde_json::to_string(&new).unwrap();
        assert!(wire.contains(r#""udp_dialer_ok":false"#));
        match serde_json::from_str::<ClientMsg>(&wire).unwrap() {
            ClientMsg::OverlaySrflx { udp_dialer_ok, .. } => {
                assert_eq!(udp_dialer_ok, Some(false));
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// Phase C — `srflx_nat` back-compat: a pre-Phase-C server/peer omits it →
    /// defaults `None` (unknown ⇒ punch attempted, never skipped); `None` is
    /// OMITTED on the wire; populated round-trips.
    #[test]
    fn netcheck_msg_and_netmap_caps_default_skip_and_roundtrip() {
        // Wire message: a populated vector round-trips; the tag is stable.
        let m = ClientMsg::OverlayNetcheck {
            caps: CapVectorWire {
                stun_udp: true,
                relay_band_udp: Some(false),
                derp_ws_ok: true,
            },
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:overlay.netcheck""#));
        assert!(s.contains(r#""relay_band_udp":false"#));
        match serde_json::from_str::<ClientMsg>(&s).unwrap() {
            ClientMsg::OverlayNetcheck { caps } => {
                assert!(caps.stun_udp && caps.derp_ws_ok);
                assert_eq!(caps.relay_band_udp, Some(false));
            }
            other => panic!("wrong variant: {other:?}"),
        }
        // Unmeasured relay_band is OMITTED on the wire; absent parses None.
        let partial = serde_json::to_string(&CapVectorWire {
            stun_udp: true,
            relay_band_udp: None,
            derp_ws_ok: false,
        })
        .unwrap();
        assert!(!partial.contains("relay_band_udp"));

        // NetmapPeer.caps: absent from a pre-B server ⇒ None + omitted on
        // the wire; populated round-trips.
        let json = r#"{
            "node_id":"507f1f77bcf86cd799439011",
            "overlay_ip":"100.64.0.4",
            "wg_public_key":"cGVlcg==",
            "reachable":true
        }"#;
        let p: NetmapPeer = serde_json::from_str(json).unwrap();
        assert!(p.caps.is_none());
        let s = serde_json::to_string(&p).unwrap();
        assert!(!s.contains("\"caps\""), "absent caps omitted: {s}");
        let mut p2 = p.clone();
        p2.caps = Some(CapVectorWire {
            stun_udp: false,
            relay_band_udp: Some(true),
            derp_ws_ok: true,
        });
        let s2 = serde_json::to_string(&p2).unwrap();
        assert_eq!(serde_json::from_str::<NetmapPeer>(&s2).unwrap(), p2);
    }

    #[test]
    fn netmap_peer_supports_derp_floor_default_and_roundtrip() {
        // Phase A back-compat: absent from a pre-floor server ⇒ false (the
        // lazy-mux rules apply); a set flag round-trips.
        let json = r#"{
            "node_id":"507f1f77bcf86cd799439011",
            "overlay_ip":"100.64.0.4",
            "wg_public_key":"cGVlcg==",
            "reachable":true
        }"#;
        let p: NetmapPeer = serde_json::from_str(json).unwrap();
        assert!(!p.supports_derp_floor, "pre-floor peer must default false");
        let mut p2 = p.clone();
        p2.supports_derp_floor = true;
        let s = serde_json::to_string(&p2).unwrap();
        assert_eq!(serde_json::from_str::<NetmapPeer>(&s).unwrap(), p2);
    }

    #[test]
    fn netmap_peer_srflx_nat_default_and_skip() {
        let json = r#"{
            "node_id":"507f1f77bcf86cd799439011",
            "overlay_ip":"100.64.0.4",
            "wg_public_key":"cGVlcg==",
            "reachable":true
        }"#;
        let p: NetmapPeer = serde_json::from_str(json).unwrap();
        assert_eq!(p.srflx_nat, None);
        let s = serde_json::to_string(&p).unwrap();
        assert!(
            !s.contains("srflx_nat"),
            "a None srflx_nat must be omitted on the wire: {s}"
        );
        let mut p2 = p.clone();
        p2.srflx_nat = Some("symmetric".into());
        let s2 = serde_json::to_string(&p2).unwrap();
        assert!(s2.contains(r#""srflx_nat":"symmetric""#));
        assert_eq!(serde_json::from_str::<NetmapPeer>(&s2).unwrap(), p2);
    }

    /// Phase B — `stun_urls` back-compat: a pre-Phase-B server omits it →
    /// defaults empty (no srflx gathering); empty is skipped on the wire;
    /// populated round-trips byte-for-byte.
    #[test]
    fn overlay_network_stun_urls_default_and_skip() {
        let json = r#"{"cidr":"100.64.0.0/10","mtu":1280}"#;
        let n: OverlayNetworkInfo = serde_json::from_str(json).unwrap();
        assert!(n.stun_urls.is_empty());
        let s = serde_json::to_string(&n).unwrap();
        assert!(
            !s.contains("stun_urls"),
            "empty stun_urls must be omitted: {s}"
        );
        let mut n2 = n.clone();
        n2.stun_urls = vec!["stun:5.9.157.221:3478".into()];
        let s2 = serde_json::to_string(&n2).unwrap();
        assert!(s2.contains(r#""stun_urls":["stun:5.9.157.221:3478"]"#));
        assert_eq!(serde_json::from_str::<OverlayNetworkInfo>(&s2).unwrap(), n2);
    }

    #[test]
    fn overlay_netmap_delta_removes_are_raw_hex() {
        let rm = ObjectId::parse_str("507f1f77bcf86cd799439012").unwrap();
        let m = ServerMsg::OverlayNetmapDelta {
            epoch: 8,
            upserts: vec![],
            removes: vec![rm],
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:overlay.netmap_delta""#));
        assert!(!s.contains("$oid"));
        assert!(s.contains("\"507f1f77bcf86cd799439012\""));
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::OverlayNetmapDelta { removes, epoch, .. } => {
                assert_eq!(epoch, 8);
                assert_eq!(removes, vec![rm]);
            }
            other => panic!("expected OverlayNetmapDelta, got {other:?}"),
        }
    }

    #[test]
    fn overlay_relay_grant_roundtrip() {
        let peer = ObjectId::parse_str("507f1f77bcf86cd799439013").unwrap();
        let m = ServerMsg::OverlayRelayGrant {
            ice_servers: vec![IceServer {
                urls: vec!["turns:coturn.roomler.ai:443?transport=tcp".into()],
                username: Some("u".into()),
                credential: Some("c".into()),
            }],
            peer_node_id: peer,
            pair_key: "a..b".into(),
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(s.contains(r#""t":"rc:overlay.relay_grant""#));
        match serde_json::from_str::<ServerMsg>(&s).unwrap() {
            ServerMsg::OverlayRelayGrant {
                peer_node_id,
                ice_servers,
                ..
            } => {
                assert_eq!(peer_node_id, peer);
                assert_eq!(ice_servers.len(), 1);
            }
            other => panic!("expected OverlayRelayGrant, got {other:?}"),
        }
    }
    /// FR-43 P2c — an absent `caps` must not appear on the wire at ALL.
    ///
    /// The whole design rests on caps riding the heartbeat only when they
    /// CHANGE: they are ~200 bytes against a frequent message, so a steady
    /// state that serialised `"caps":null` would cost every device every beat
    /// for nothing. And a reader must be able to tell "no news" from "no
    /// capabilities" — the same `None` vs `Some([])` rule `AgentCaps.permissions`
    /// already carries.
    #[test]
    fn heartbeat_caps_are_absent_from_the_wire_unless_they_changed() {
        let quiet = ClientMsg::AgentHeartbeat {
            rss_mb: 10,
            cpu_pct: 1.0,
            active_sessions: 0,
            sys: None,
            srflx_count: None,
            warm_relay: None,
            companion_version: None,
            keep_busy: None,
            caps: None,
        };
        let s = serde_json::to_string(&quiet).unwrap();
        assert!(
            !s.contains("caps"),
            "a steady-state heartbeat must not mention caps at all: {s}"
        );

        // …and when they DO change, they travel whole.
        let announcing = ClientMsg::AgentHeartbeat {
            rss_mb: 10,
            cpu_pct: 1.0,
            active_sessions: 0,
            sys: None,
            srflx_count: None,
            warm_relay: None,
            companion_version: None,
            keep_busy: None,
            caps: Some(Box::new(AgentCaps {
                permissions: Some(vec!["screen-capture".into(), "input".into()]),
                has_input_permission: true,
                ..Default::default()
            })),
        };
        let s = serde_json::to_string(&announcing).unwrap();
        assert!(s.contains(r#""screen-capture""#), "got {s}");
        let back: ClientMsg = serde_json::from_str(&s).unwrap();
        match back {
            ClientMsg::AgentHeartbeat { caps: Some(c), .. } => {
                assert_eq!(
                    c.permissions.as_deref(),
                    Some(&["screen-capture".to_string(), "input".to_string()][..]),
                    "the permissions a device announces must survive the round trip"
                );
                assert!(c.has_input_permission);
            }
            other => panic!("expected caps to survive, got {other:?}"),
        }
    }

    /// FR-101 P3 — `transfers` is absent from a sample that moved nothing, so
    /// an older server never sees the field; an older agent's sample, which
    /// FR-102 P9c — the carrier is additive both ways: a sample from an
    /// agent older than the field (or before the observation landed) parses
    /// with none, a sample without one serialises without the key (an older
    /// server never sees it), and a named carrier travels as its spelling.
    #[test]
    fn session_stats_carrier_is_optional_both_ways() {
        let older = r#"{"t":"rc:session.stats","session_id":"a","bytes_sent":1,"bytes_recv":2,
            "fps":30.0,"rtt_ms":4.0,"keyframe_requests":0,"input_events":0}"#;
        match serde_json::from_str::<ClientMsg>(older).unwrap() {
            ClientMsg::SessionStats { carrier, .. } => assert_eq!(carrier, None),
            other => panic!("wrong variant: {other:?}"),
        }
        let named = r#"{"t":"rc:session.stats","session_id":"a","bytes_sent":1,"bytes_recv":2,
            "fps":30.0,"rtt_ms":4.0,"keyframe_requests":0,"input_events":0,"carrier":"org_relay"}"#;
        let msg = serde_json::from_str::<ClientMsg>(named).unwrap();
        match &msg {
            ClientMsg::SessionStats { carrier, .. } => {
                assert_eq!(carrier.as_deref(), Some("org_relay"))
            }
            other => panic!("wrong variant: {other:?}"),
        }
        let s = serde_json::to_string(&msg).unwrap();
        assert!(s.contains(r#""carrier":"org_relay""#), "{s}");
        let none = ClientMsg::SessionStats {
            session_id: "a".into(),
            bytes_sent: 0,
            bytes_recv: 0,
            fps: 0.0,
            rtt_ms: 0.0,
            keyframe_requests: 0,
            input_events: 0,
            shared_seconds: 0,
            mixed_dial_seconds: 0,
            transfers: Transfers::default(),
            carrier: None,
        };
        assert!(!serde_json::to_string(&none).unwrap().contains("carrier"));
    }

    /// has none, parses with none; and the wire names are a compatibility
    /// surface.
    #[test]
    fn session_stats_transfers_are_optional_both_ways_and_keep_their_names() {
        let base = r#"{"t":"rc:session.stats","session_id":"a","bytes_sent":1,"bytes_recv":2,
            "fps":30.0,"rtt_ms":4.0,"keyframe_requests":0,"input_events":0}"#;
        match serde_json::from_str::<ClientMsg>(base).unwrap() {
            ClientMsg::SessionStats { transfers, .. } => assert!(transfers.is_empty()),
            other => panic!("wrong variant: {other:?}"),
        }

        let quiet = ClientMsg::SessionStats {
            session_id: "a".into(),
            bytes_sent: 1,
            bytes_recv: 2,
            fps: 30.0,
            rtt_ms: 4.0,
            keyframe_requests: 0,
            input_events: 0,
            shared_seconds: 0,
            mixed_dial_seconds: 0,
            transfers: Transfers::default(),
            carrier: None,
        };
        let s = serde_json::to_string(&quiet).unwrap();
        assert!(!s.contains("transfers"), "{s}");

        let busy = ClientMsg::SessionStats {
            session_id: "a".into(),
            bytes_sent: 1,
            bytes_recv: 2,
            fps: 30.0,
            rtt_ms: 4.0,
            keyframe_requests: 0,
            input_events: 0,
            shared_seconds: 0,
            mixed_dial_seconds: 0,
            transfers: Transfers {
                clipboard_to_host: Tally {
                    count: 2,
                    bytes: 15,
                },
                clipboard_from_host: Tally::default(),
                files: vec![FileNote {
                    dir: TransferDirection::FromHost,
                    name_sha256: "ab".repeat(32),
                    bytes: 9,
                }],
            },
            carrier: None,
        };
        let v = serde_json::to_value(&busy).unwrap();
        let t = &v["transfers"];
        assert_eq!(
            t["clipboard_to_host"],
            serde_json::json!({"count": 2, "bytes": 15})
        );
        assert!(
            t.get("clipboard_from_host").is_none(),
            "a zero tally is left out: {t}"
        );
        assert_eq!(t["files"][0]["dir"], "from_host");
        assert_eq!(t["files"][0]["bytes"], 9);
        match serde_json::from_value::<ClientMsg>(v).unwrap() {
            ClientMsg::SessionStats { transfers, .. } => {
                assert_eq!(transfers.clipboard_to_host.count, 2);
                assert_eq!(transfers.files.len(), 1);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// FR-101 P3 — the server keeps what a sample ADDS to the stored reading;
    /// a reading that went backwards adds nothing rather than wrapping.
    #[test]
    fn a_tally_reports_only_what_a_later_reading_adds() {
        let earlier = Tally {
            count: 3,
            bytes: 300,
        };
        assert_eq!(
            Tally {
                count: 5,
                bytes: 450
            }
            .since(earlier),
            Tally {
                count: 2,
                bytes: 150
            }
        );
        assert_eq!(earlier.since(earlier), Tally::default());
        assert_eq!(
            Tally {
                count: 1,
                bytes: 10
            }
            .since(earlier),
            Tally::default()
        );
    }

    #[test]
    fn org_relay_multi_candidate_join_capability_defaults_closed_and_round_trips() {
        let old = serde_json::json!({"t":"rc:overlay.join", "wg_public_key":"k",
            "endpoints":[], "mtu":1280});
        for advertised in [None, Some(false), Some(true)] {
            let mut value = old.clone();
            if let Some(flag) = advertised {
                value["supports_org_relay_multi_candidate"] = serde_json::json!(flag);
            }
            let decoded: ClientMsg = serde_json::from_value(value).unwrap();
            assert!(matches!(&decoded, ClientMsg::OverlayJoin {
                supports_org_relay_multi_candidate, ..
            } if *supports_org_relay_multi_candidate == advertised.unwrap_or(false)));
            let encoded = serde_json::to_value(decoded).unwrap();
            assert_eq!(
                encoded["supports_org_relay_multi_candidate"],
                advertised.unwrap_or(false)
            );
            serde_json::from_value::<ClientMsg>(encoded).unwrap();
        }
        // OverlayJoin has always ignored additive fields: this capability is
        // a response-shape negotiation, not a new message or feature opt-in.
        let mut value = old;
        value["future_unrecognized_join_capability"] = serde_json::json!(true);
        assert!(matches!(
            serde_json::from_value::<ClientMsg>(value).unwrap(),
            ClientMsg::OverlayJoin {
                supports_org_relay_multi_candidate: false,
                supports_org_relay_discovery_cursor: false,
                ..
            }
        ));
    }

    #[test]
    fn org_relay_discovery_wire_is_pair_specific_metadata_only() {
        let old_netmap = r#"{"t":"rc:overlay.netmap","self_ip":"100.64.0.7","network":{"cidr":"100.64.0.0/10","mtu":1280},"peers":[]}"#;
        assert!(matches!(
            serde_json::from_str::<ServerMsg>(old_netmap).unwrap(),
            ServerMsg::OverlayNetmap {
                org_relay_discovery: false,
                path_trial_v1: false,
                ..
            }
        ));
        let peer = ObjectId::new();
        let request = ClientMsg::OverlayOrgRelayDiscover {
            peer_node_id: peer,
            request_id: 7,
            cursor: None,
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["t"], "rc:overlay.org_relay_discover");
        let decoded: ClientMsg = serde_json::from_value(value).unwrap();
        assert!(
            matches!(decoded, ClientMsg::OverlayOrgRelayDiscover { peer_node_id, request_id: 7, .. } if peer_node_id == peer)
        );
        let response = ServerMsg::OverlayOrgRelayCandidates {
            peer_node_id: peer,
            request_id: 7,
            candidates: vec![OrgRelayCandidateWire {
                exit_relay_node_id: None,
                relay_node_id: ObjectId::new(),
                endpoints: vec!["8.8.8.8:3478".into()],
            }],
            ttl_secs: 30,
            next_cursor: None,
        };
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["t"], "rc:overlay.org_relay_candidates");
        assert!(value.get("vni").is_none() && value.get("bind_secret").is_none());
        let decoded: ServerMsg = serde_json::from_value(value).unwrap();
        assert!(
            matches!(decoded, ServerMsg::OverlayOrgRelayCandidates { peer_node_id, request_id: 7, ttl_secs: 30, .. } if peer_node_id == peer)
        );
    }

    #[test]
    fn path_trial_capabilities_default_closed_and_new_messages_round_trip() {
        let old = r#"{"t":"rc:overlay.join","wg_public_key":"legacy","endpoints":[],"mtu":1280}"#;
        assert!(matches!(
            serde_json::from_str::<ClientMsg>(old).unwrap(),
            ClientMsg::OverlayJoin {
                supports_path_trial_v1: false,
                supports_path_backbone_v1: false,
                relay_backbone_ready: false,
                ..
            }
        ));
        let id = ObjectId::new();
        for message in [
            ClientMsg::OverlayPathTrialReady { trial_id: id },
            ClientMsg::OverlayPathTrialCommitted { trial_id: id },
            ClientMsg::OverlayPathTrialAbort { trial_id: id },
        ] {
            let json = serde_json::to_value(message).unwrap();
            assert!(
                json["t"]
                    .as_str()
                    .unwrap()
                    .starts_with("rc:overlay.path_trial_")
            );
            assert_eq!(json["trial_id"], id.to_hex());
            serde_json::from_value::<ClientMsg>(json).unwrap();
        }
        for message in [
            ServerMsg::OverlayPathTrialCommit { trial_id: id },
            ServerMsg::OverlayPathTrialFinalize { trial_id: id },
            ServerMsg::OverlayPathTrialAbort { trial_id: id },
        ] {
            serde_json::from_value::<ServerMsg>(serde_json::to_value(message).unwrap()).unwrap();
        }
    }
    #[test]
    fn return_wire_carries_attempt_identity_and_round_trips() {
        let id = ObjectId::new();
        let r = ObjectId::new();
        for msg in [
            ClientMsg::OverlayPathTrialReturnRequest {
                trial_id: id,
                return_id: r,
            },
            ClientMsg::OverlayPathTrialReturnReady {
                trial_id: id,
                return_id: r,
            },
            ClientMsg::OverlayPathTrialReturned {
                trial_id: id,
                return_id: r,
            },
            ClientMsg::OverlayPathTrialReturnAbort {
                trial_id: id,
                return_id: r,
            },
        ] {
            let value = serde_json::to_value(msg).unwrap();
            assert_eq!(value["trial_id"], id.to_hex());
            assert_eq!(value["return_id"], r.to_hex());
            let decoded: ClientMsg = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), value);
        }
        for msg in [
            ServerMsg::OverlayPathTrialReturnPrepare {
                trial_id: id,
                return_id: r,
            },
            ServerMsg::OverlayPathTrialReturnCommit {
                trial_id: id,
                return_id: r,
            },
            ServerMsg::OverlayPathTrialReturnFinalize {
                trial_id: id,
                return_id: r,
            },
            ServerMsg::OverlayPathTrialReturnAbort {
                trial_id: id,
                return_id: r,
            },
        ] {
            let value = serde_json::to_value(msg).unwrap();
            let decoded: ServerMsg = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), value);
        }
    }
}

#[cfg(test)]
mod discovery_cursor_wire_tests {
    use super::*;
    #[test]
    fn discovery_cursor_wire_capability_defaults_and_roundtrips() {
        for cap in [None, Some(false), Some(true)] {
            let mut v = serde_json::json!({"t":"rc:overlay.join","wg_public_key":"legacy","endpoints":[],"mtu":1280});
            if let Some(cap) = cap {
                v["supports_org_relay_discovery_cursor"] = cap.into();
            }
            assert!(
                matches!(serde_json::from_value::<ClientMsg>(v).unwrap(),ClientMsg::OverlayJoin {supports_org_relay_discovery_cursor:c,..} if c==cap.unwrap_or(false))
            );
        }
        let peer = ObjectId::new();
        let relay = ObjectId::new();
        let old = serde_json::json!({"t":"rc:overlay.org_relay_discover","peer_node_id":peer.to_hex(),"request_id":1});
        let oldmsg: ClientMsg = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(serde_json::to_value(oldmsg).unwrap(), old);
        let mut new = old;
        new["cursor"] = serde_json::json!({"relay_node_id":relay.to_hex()});
        let decoded: ClientMsg = serde_json::from_value(new.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), new);
        let reply = serde_json::json!({"t":"rc:overlay.org_relay_candidates","peer_node_id":peer.to_hex(),"request_id":1,"candidates":[],"ttl_secs":0});
        assert_eq!(
            serde_json::to_value(serde_json::from_value::<ServerMsg>(reply.clone()).unwrap())
                .unwrap(),
            reply
        );
        new["cursor"] = serde_json::json!({"relay_node_id":"not-an-id"});
        assert!(serde_json::from_value::<ClientMsg>(new).is_err());
    }
}

#[cfg(test)]
mod org_fallback_wire_tests {
    use super::*;
    #[test]
    fn org_fallback_wire_support_defaults_closed_and_request_is_distinct() {
        let old = r#"{"cidr":"100.64.0.0/10","mtu":1280}"#;
        let mut network: OverlayNetworkInfo = serde_json::from_str(old).unwrap();
        assert!(!network.org_relay_fallback_v1);
        assert!(
            !serde_json::to_string(&network)
                .unwrap()
                .contains("org_relay_fallback_v1")
        );
        network.org_relay_fallback_v1 = true;
        assert!(
            serde_json::from_value::<OverlayNetworkInfo>(serde_json::to_value(network).unwrap())
                .unwrap()
                .org_relay_fallback_v1
        );
        let id = ObjectId::new();
        let message = ClientMsg::OverlayOrgRelayFallbackRequest {
            peer_node_id: id,
            request_id: 17,
        };
        let value = serde_json::to_value(message).unwrap();
        assert_eq!(value["t"], "rc:overlay.org_relay_fallback_request");
        assert!(value.get("current_kind").is_none() && value.get("reason").is_none());
        let parsed: ClientMsg = serde_json::from_value(value).unwrap();
        assert!(
            matches!(parsed,ClientMsg::OverlayOrgRelayFallbackRequest {peer_node_id,request_id:17}if peer_node_id==id)
        );
        assert!(matches!(parsed.namespace(), Owner::Network));
        let legacy: ClientMsg = serde_json::from_value(
            serde_json::json!({"t":"rc:overlay.relay_request","peer_node_id":id.to_hex()}),
        )
        .unwrap();
        assert!(matches!(
            legacy,
            ClientMsg::OverlayRelayRequest {
                current_kind: None,
                reason: None,
                derp_mux_failed: false,
                ..
            }
        ));
    }

    #[test]
    fn org_loss_wire_support_defaults_closed_and_the_report_round_trips() {
        let old = r#"{"cidr":"100.64.0.0/10","mtu":1280,"org_relay_fallback_v1":true}"#;
        let mut network: OverlayNetworkInfo = serde_json::from_str(old).unwrap();
        assert!(!network.org_relay_loss_v1, "an old server never said it");
        assert!(
            !serde_json::to_string(&network)
                .unwrap()
                .contains("org_relay_loss_v1")
        );
        network.org_relay_loss_v1 = true;
        assert!(
            serde_json::from_value::<OverlayNetworkInfo>(serde_json::to_value(network).unwrap())
                .unwrap()
                .org_relay_loss_v1
        );
        let id = ObjectId::new();
        let value = serde_json::to_value(ClientMsg::OverlayOrgRelayLoss {
            peer_node_id: id,
            vni: 42,
            packets: 31_000,
            lost: 2_294,
        })
        .unwrap();
        assert_eq!(
            value,
            serde_json::json!({"t":"rc:overlay.org_relay_loss","peer_node_id":id.to_hex(),
                "vni":42,"packets":31_000,"lost":2_294})
        );
        let parsed: ClientMsg = serde_json::from_value(value).unwrap();
        assert!(matches!(parsed, ClientMsg::OverlayOrgRelayLoss {
            peer_node_id, vni: 42, packets: 31_000, lost: 2_294 } if peer_node_id == id));
        assert!(matches!(parsed.namespace(), Owner::Network));
    }
}

/// Which engine runs a managed forward (MeshHarbor #20).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ForwardBackend {
    /// The agent's userspace TCP/UDP relay; always masquerades.
    #[default]
    Userspace,
    /// The agent's owned nftables table (DNAT), Linux only, under
    /// commit-confirm. Sent only to a device advertising
    /// [`RpcCap::ManagedForwardNft`].
    ///
    /// [`RpcCap::ManagedForwardNft`]: crate::models::RpcCap::ManagedForwardNft
    Nft,
}

impl ForwardBackend {
    pub fn is_userspace(&self) -> bool {
        *self == ForwardBackend::Userspace
    }
}

/// One forward of a [`ServerMsg::ManagedForwardSet`] (MeshHarbor #20): listen
/// on `bind_addr:port`, admit `sources` (CIDRs), relay to
/// `dest_addr:dest_port`, masquerading unless `preserve_source` (nft only).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedForwardAssignment {
    pub id: String,
    pub revision: u64,
    pub bind_addr: String,
    pub port: u16,
    pub proto: crate::net_inventory::L4,
    pub sources: Vec<String>,
    pub dest_addr: String,
    pub dest_port: u16,
    #[serde(default, skip_serializing_if = "ForwardBackend::is_userspace")]
    pub backend: ForwardBackend,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub preserve_source: bool,
}

/// One forward's state in a [`ClientMsg::ManagedForwardStatus`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedForwardStatusWire {
    pub id: String,
    pub revision: u64,
    pub listening: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
