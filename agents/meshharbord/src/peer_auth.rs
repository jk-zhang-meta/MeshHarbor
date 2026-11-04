// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-100 P1a — this device's identity key, one per org enrollment
//! (`docs/fr/FR-100-controller-identity.md` §3a).
//!
//! An ECDSA P-256 key made HERE, on first use, and kept in its own file beside
//! the config: `<config dir>/peer-auth/<tenant id>.json`. Never in
//! `config.toml`, which has several writers and is reported to the server
//! (FR-92's state rule). Only the public half ever leaves the device, on the
//! hello: it is the key a controller's browser will pin (P2) and the key the
//! device will sign its session answers with (P1c).
//!
//! One key per enrollment, never shared between them: a key two orgs both saw
//! would let them correlate the device (`docs/multi-org.md`, the per-org WG
//! key rule).
//!
//! **A key that cannot be kept is never offered.** A key made in memory and
//! lost at the next start would break every browser's pin at every restart,
//! and teach people to click through the warning. So when the key cannot be
//! written, or read back as written, the hello carries none, and the device
//! reads as "cannot prove who it is". That is the SSH host key's rule
//! (FR-52 §2b).
//!
//! ⚠️ The file holds a PRIVATE key, and gets the config's own protection. On
//! Windows the machine-global config directory grants only SYSTEM and
//! Administrators, inherited by what is made inside it; a per-user install's
//! is the person's own profile. On Unix the directory is made 0700 and the
//! file 0600, whoever runs the daemon.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde::{Deserialize, Serialize};

/// The directory beside the config that holds one key file per enrollment.
pub const DIR_NAME: &str = "peer-auth";
const VERSION: u32 = 1;
/// ECDSA over P-256 with SHA-256, signatures as the fixed-size `r ‖ s` that
/// WebCrypto verifies.
const ALG: &str = "ecdsa-p256-sha256";

/// The file. A newer agent may write a newer `version`; an older one leaves
/// such a file alone rather than replace a key it cannot read.
#[derive(Serialize, Deserialize)]
struct Stored {
    version: u32,
    alg: String,
    /// PKCS#8 v1, standard base64, as ring makes and reads it.
    pkcs8: String,
}

/// One enrollment's device key.
pub struct DeviceKey {
    pair: EcdsaKeyPair,
}

impl DeviceKey {
    /// The public half as the hello carries it: the standard base64 of the
    /// uncompressed point (`meshharbor_remote_control::signaling::
    /// peer_auth_key_is_well_formed`).
    pub fn public_b64(&self) -> String {
        STANDARD.encode(self.pair.public_key().as_ref())
    }

    /// FR-100 P1b — `message` signed: ECDSA P-256 over SHA-256, the fixed
    /// 64-byte `r ‖ s` that WebCrypto verifies. `None` only if the system's
    /// randomness fails, and then nothing is signed.
    pub fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        self.pair
            .sign(&SystemRandom::new(), message)
            .ok()
            .map(|sig| sig.as_ref().to_vec())
    }
}

/// FR-100 P1b — what the daemon needs to sign a session's answer, gathered as
/// the session's frames pass through it: the controller from `rc:request`,
/// then the offer's DTLS fingerprint and nonce from `rc:sdp.offer`.
///
/// Kept in the DAEMON, and held by `RemoteConfigServices` (one per daemon,
/// cloned into every org's loop), not in a static, so the many agents an
/// integration test runs in one process never see each other's sessions. The
/// daemon is also where the key is: a GUI worker that built the answer
/// (FR-43) never holds it, so the daemon signs what it relays.
#[derive(Default)]
pub struct PendingOffers {
    table: Mutex<Table>,
}

#[derive(Default)]
struct Table {
    sessions: HashMap<bson::oid::ObjectId, Pending>,
    /// Noting order, for evicting the oldest past the cap: a clock read in a
    /// tight loop can tie, an increment cannot.
    next_seq: u64,
}

struct Pending {
    user_id: bson::oid::ObjectId,
    /// `(offer fingerprint, nonce)` while an offer that asked is unanswered.
    asked: Option<(String, String)>,
    /// FR-100 P1c — what the device concluded about the browser that made the
    /// current offer, until its answer reports it. `None` before the offer is
    /// judged, and under `peer_auth = off`.
    verdict: Option<Verdict>,
    noted_at: std::time::Instant,
    seq: u64,
}

/// Sessions noted at once. A session that is never answered or ended is
/// forgotten by age or by this cap, so the table cannot grow without bound.
const MAX_PENDING: usize = 64;
const PENDING_TTL: std::time::Duration = std::time::Duration::from_secs(600);

impl PendingOffers {
    /// An in-org session's request reached this daemon: remember who asked.
    /// An external session is never noted: FR-52's own MAC binds it.
    pub fn note_request(&self, session_id: bson::oid::ObjectId, user_id: bson::oid::ObjectId) {
        let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        table
            .sessions
            .retain(|_, p| now.duration_since(p.noted_at) < PENDING_TTL);
        if table.sessions.len() >= MAX_PENDING
            && !table.sessions.contains_key(&session_id)
            && let Some(oldest) = table
                .sessions
                .iter()
                .min_by_key(|(_, p)| p.seq)
                .map(|(id, _)| *id)
        {
            table.sessions.remove(&oldest);
        }
        let seq = table.next_seq;
        table.next_seq += 1;
        table.sessions.insert(
            session_id,
            Pending {
                user_id,
                asked: None,
                verdict: None,
                noted_at: now,
                seq,
            },
        );
    }

    /// The session's offer reached this daemon. One that asks (a nonce) is
    /// remembered with its fingerprint, to sign the answer against; one that
    /// does not ask clears an earlier ask, so a re-offer that did not ask is
    /// never answered with a signature made for another offer.
    pub fn note_offer(
        &self,
        session_id: bson::oid::ObjectId,
        offer_sdp: &str,
        ask: Option<&meshharbor_remote_control::signaling::PeerAuthOffer>,
    ) {
        use meshharbor_remote_control::signaling::{
            peer_auth_nonce_is_well_formed, sdp_dtls_fingerprint,
        };
        let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
        let Some(pending) = table.sessions.get_mut(&session_id) else {
            if ask.is_some() {
                tracing::info!(%session_id, "peer-auth: an offer asked for a signed answer, but no in-org request for it reached this process; it will be answered unsigned");
            }
            return;
        };
        pending.asked = None;
        // A verdict belongs to one offer: a re-offer is judged afresh.
        pending.verdict = None;
        let Some(ask) = ask else {
            return;
        };
        if !peer_auth_nonce_is_well_formed(&ask.nonce) {
            tracing::warn!(%session_id, len = ask.nonce.len(), "peer-auth: the offer's nonce is not well formed; its answer goes unsigned");
            return;
        }
        match sdp_dtls_fingerprint(offer_sdp) {
            Ok(fingerprint) => pending.asked = Some((fingerprint, ask.nonce.clone())),
            Err(why) => {
                tracing::warn!(%session_id, ?why, "peer-auth: the offer names no single DTLS fingerprint; its answer goes unsigned");
            }
        }
    }

    /// The session ended: nothing more to sign for it.
    pub fn forget(&self, session_id: bson::oid::ObjectId) {
        self.table
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .remove(&session_id);
    }

    /// What signing this offer's answer needs, consumed: one answer per
    /// offer. The controller stays noted for a re-offer.
    fn take(&self, session_id: bson::oid::ObjectId) -> Option<Asked> {
        let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
        let pending = table.sessions.get_mut(&session_id)?;
        let (offer_fingerprint, nonce) = pending.asked.take()?;
        Some(Asked {
            user_id: pending.user_id,
            offer_fingerprint,
            nonce,
        })
    }

    /// FR-100 P1c — judge the browser behind `session_id`'s offer under
    /// `check`, and keep the verdict for the answer to report. Only for an
    /// in-org session this daemon noted at its request (an outsider's is
    /// judged by FR-52's MAC, at the answer). `None` under `peer_auth = off`.
    ///
    /// Called right after [`Self::note_offer`], in the daemon and ahead of
    /// any delegation, for the reason `note_offer` is.
    pub fn judge_offer(
        &self,
        session_id: bson::oid::ObjectId,
        offer_sdp: &str,
        ask: Option<&meshharbor_remote_control::signaling::PeerAuthOffer>,
        check: &OfferCheck<'_>,
    ) -> Option<Verdict> {
        let user_id = {
            let table = self.table.lock().unwrap_or_else(|e| e.into_inner());
            table.sessions.get(&session_id)?.user_id
        };
        let verdict = match check.policy {
            PeerAuthPolicy::Off => None,
            PeerAuthPolicy::Audit => Some(judge(session_id, user_id, offer_sdp, ask, check)),
        };
        if let Some(v) = verdict {
            tracing::info!(%session_id, verdict = v.wire(), "peer-auth: the browser behind this offer");
        }
        let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pending) = table.sessions.get_mut(&session_id) {
            pending.verdict = verdict;
        }
        verdict
    }

    /// FR-100 P1c — the verdict on `session_id`'s current offer, consumed: one
    /// report per offer, as one signature per offer.
    fn take_verdict(&self, session_id: bson::oid::ObjectId) -> Option<Verdict> {
        let mut table = self.table.lock().unwrap_or_else(|e| e.into_inner());
        table.sessions.get_mut(&session_id)?.verdict.take()
    }
}

/// An offer that asked for a signed answer, taken from the table to sign.
struct Asked {
    user_id: bson::oid::ObjectId,
    offer_fingerprint: String,
    nonce: String,
}

/// FR-100 P1b — the device's signature for `session_id`'s answer, when its
/// offer asked for one and this enrollment has a key it keeps: the transcript
/// (`peer_auth_transcript`, role `answer`) signed with the device key. `None`
/// otherwise, and the answer goes out unsigned, which is exactly what an offer
/// that did not ask expects.
pub fn sign_answer(
    offers: &PendingOffers,
    config_path: &Path,
    tenant_id: &str,
    agent_id: &str,
    session_id: bson::oid::ObjectId,
    answer_sdp: &str,
) -> Option<meshharbor_remote_control::signaling::PeerAuthAnswer> {
    let asked = offers.take(session_id)?;
    let signed = signed_answer(
        config_path,
        tenant_id,
        agent_id,
        session_id,
        &asked,
        answer_sdp,
    );
    match signed {
        Ok(answer) => {
            tracing::info!(%session_id, "peer-auth: answer signed with this enrollment's device key");
            Some(answer)
        }
        Err(why) => {
            tracing::warn!(%session_id, %why, "peer-auth: the offer asked for a signed answer, but it goes unsigned");
            None
        }
    }
}

/// [`sign_answer`]'s work, with the reason it could not be done.
fn signed_answer(
    config_path: &Path,
    tenant_id: &str,
    agent_id: &str,
    session_id: bson::oid::ObjectId,
    asked: &Asked,
    answer_sdp: &str,
) -> Result<meshharbor_remote_control::signaling::PeerAuthAnswer, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use meshharbor_remote_control::signaling::{
        PeerAuthAnswer, peer_auth_transcript, sdp_dtls_fingerprint,
    };
    let answer_fingerprint = sdp_dtls_fingerprint(answer_sdp)
        .map_err(|why| format!("the answer names no single DTLS fingerprint ({why:?})"))?;
    let transcript = peer_auth_transcript(
        "answer",
        &session_id.to_hex(),
        agent_id,
        &asked.user_id.to_hex(),
        &asked.offer_fingerprint,
        &answer_fingerprint,
        &asked.nonce,
    )
    .ok_or("a transcript field is too long to frame")?;
    let key = device_key(config_path, tenant_id)?;
    let sig = key.sign(&transcript).ok_or("signing failed")?;
    Ok(PeerAuthAnswer {
        key: key.public_b64(),
        sig: URL_SAFE_NO_PAD.encode(sig),
    })
}

/// FR-100 P1b — sign `msg` in place if it is an answer: the choke point for
/// answers this process did not build itself (a GUI worker's, relayed up by
/// the delegation host). Whatever the worker put in `peer_auth` is not the
/// daemon's to vouch for, so it is replaced by the daemon's own signature, or
/// by none. FR-100 P1c — the same for `peer_auth_verdict`: the daemon judged
/// the offer before delegating it, and a worker holds no pins to judge with.
/// Run after FR-52's sealing, which is what marks an outsider's answer.
pub fn sign_outbound(
    offers: &PendingOffers,
    config_path: &Path,
    tenant_id: &str,
    agent_id: &str,
    policy: PeerAuthPolicy,
    msg: &mut meshharbor_remote_control::signaling::ClientMsg,
) {
    if let meshharbor_remote_control::signaling::ClientMsg::SdpAnswer {
        session_id,
        sdp,
        extauth_mac,
        peer_auth,
        peer_auth_verdict,
    } = msg
    {
        *peer_auth = sign_answer(offers, config_path, tenant_id, agent_id, *session_id, sdp);
        *peer_auth_verdict = answer_verdict(offers, policy, *session_id, extauth_mac.is_some());
    }
}

/// FR-100 P1c — the verdict `session_id`'s answer reports, as the wire spells
/// it. An outsider's session (its answer sealed under FR-52's login key) is
/// `verified`: FR-52 admitted it on a MAC the device checked, and refused it
/// otherwise. An in-org session reports what [`PendingOffers::judge_offer`]
/// found. Nothing under `peer_auth = off`.
pub fn answer_verdict(
    offers: &PendingOffers,
    policy: PeerAuthPolicy,
    session_id: bson::oid::ObjectId,
    external: bool,
) -> Option<String> {
    if policy == PeerAuthPolicy::Off {
        return None;
    }
    let verdict = if external {
        Some(Verdict::Verified)
    } else {
        offers.take_verdict(session_id)
    };
    verdict.map(|v| v.wire().to_string())
}

// ─── FR-100 P1c — the device checks the browser ─────────────────────────────

pub use crate::config::PeerAuthPolicy;

/// FR-100 P1c — what the device concluded about the browser that offered a
/// session. The words the answer carries are
/// [`meshharbor_remote_control::signaling::PEER_AUTH_VERDICTS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The offer carried no browser signature.
    Absent,
    /// A signature that verifies, by a key not yet seen for this user. Under
    /// `audit` it is now remembered, so the user's next session from that
    /// browser reads `Verified`.
    Unknown,
    /// A signature that verifies, by a key remembered for this user; or an
    /// outsider admitted by FR-52's MAC.
    Verified,
    /// A signature that does not verify over this session, or an offer that
    /// names no single certificate for one to cover.
    Mismatch,
}

impl Verdict {
    /// The word on the wire and in the audit.
    pub fn wire(self) -> &'static str {
        match self {
            Verdict::Absent => "absent",
            Verdict::Unknown => "unknown",
            Verdict::Verified => "verified",
            Verdict::Mismatch => "mismatch",
        }
    }
}

/// FR-100 P1c — what judging an offer needs beyond the offer: the device's
/// policy at that moment, and the enrollment whose pins it reads.
pub struct OfferCheck<'a> {
    pub policy: PeerAuthPolicy,
    pub config_path: &'a Path,
    pub tenant_id: &'a str,
    pub agent_id: &'a str,
}

/// The verdict on one offer: verify the browser's signature over the
/// transcript (role `offer`, an EMPTY answer fingerprint), then look its key
/// up among the keys this enrollment has seen for the user, remembering it if
/// new. A key that cannot be remembered still reads `Unknown`: the signature
/// held, but nothing vouches for the key yet.
fn judge(
    session_id: bson::oid::ObjectId,
    user_id: bson::oid::ObjectId,
    offer_sdp: &str,
    ask: Option<&meshharbor_remote_control::signaling::PeerAuthOffer>,
    check: &OfferCheck<'_>,
) -> Verdict {
    use meshharbor_remote_control::signaling::{
        peer_auth_nonce_is_well_formed, peer_auth_transcript, peer_auth_verify,
        sdp_dtls_fingerprint,
    };
    let Some((key, sig, nonce)) =
        ask.and_then(|a| Some((a.key.as_deref()?, a.sig.as_deref()?, a.nonce.as_str())))
    else {
        return Verdict::Absent;
    };
    if !peer_auth_nonce_is_well_formed(nonce) {
        return Verdict::Mismatch;
    }
    let Ok(offer_fingerprint) = sdp_dtls_fingerprint(offer_sdp) else {
        return Verdict::Mismatch;
    };
    let Some(transcript) = peer_auth_transcript(
        "offer",
        &session_id.to_hex(),
        check.agent_id,
        &user_id.to_hex(),
        &offer_fingerprint,
        "",
        nonce,
    ) else {
        return Verdict::Mismatch;
    };
    if !peer_auth_verify(key, &transcript, sig) {
        return Verdict::Mismatch;
    }
    match remember(check.config_path, check.tenant_id, user_id, key) {
        Ok(true) => Verdict::Verified,
        Ok(false) => Verdict::Unknown,
        Err(why) => {
            tracing::warn!(%session_id, %why, "peer-auth: a browser key that cannot be remembered");
            Verdict::Unknown
        }
    }
}

/// FR-100 P1c — the browser keys this enrollment has seen, per user: what
/// `audit` remembers on first sight, so that `enforce` (P3) asks only about a
/// browser the device has never met. Public keys only; what matters is that
/// the file is the device's own memory, so it lives beside the device key, in
/// the same directory and with the same protections.
#[derive(Serialize, Deserialize, Clone, Default)]
struct PinFile {
    version: u32,
    /// The user's id (lowercase hex) → the keys seen for that user, oldest
    /// first.
    users: std::collections::BTreeMap<String, Vec<PinnedKey>>,
}

#[derive(Serialize, Deserialize, Clone)]
struct PinnedKey {
    /// As the offer carried it: the device key's shape, standard base64 of the
    /// 65-byte point.
    key: String,
    /// When the device first saw it, RFC 3339.
    first_seen: String,
}

/// A person with more browsers than this loses the oldest one's pin first.
const MAX_KEYS_PER_USER: usize = 16;
/// The file stays small on a device a whole org connects to: past this, the
/// user whose newest key is oldest is forgotten first.
const MAX_USERS: usize = 256;

/// Where `tenant_id`'s pins live: `<config dir>/peer-auth/<tenant id>.controllers.json`,
/// beside its key and under the same naming rule.
fn pins_path(config_path: &Path, tenant_id: &str) -> Result<PathBuf, String> {
    let key = key_path(config_path, tenant_id)?;
    Ok(key.with_file_name(format!(
        "{}.controllers.json",
        tenant_id.to_ascii_lowercase()
    )))
}

/// Has `user_id` offered with `key` before, on this enrollment? Remembered now
/// if not (`Ok(false)`). Read once per process and kept in memory; a new key
/// is written through, whole or not at all, BEFORE it counts as remembered.
fn remember(
    config_path: &Path,
    tenant_id: &str,
    user_id: bson::oid::ObjectId,
    key: &str,
) -> Result<bool, String> {
    static PINS: OnceLock<Mutex<HashMap<PathBuf, PinFile>>> = OnceLock::new();
    let path = pins_path(config_path, tenant_id)?;
    let mut all = PINS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let file = match all.entry(path.clone()) {
        std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
        std::collections::hash_map::Entry::Vacant(e) => e.insert(load_pins(&path)?),
    };
    let user = user_id.to_hex();
    if file
        .users
        .get(&user)
        .is_some_and(|keys| keys.iter().any(|k| k.key == key))
    {
        return Ok(true);
    }
    let mut next = file.clone();
    next.version = VERSION;
    let keys = next.users.entry(user).or_default();
    keys.push(PinnedKey {
        key: key.to_string(),
        first_seen: bson::DateTime::now()
            .try_to_rfc3339_string()
            .unwrap_or_default(),
    });
    if keys.len() > MAX_KEYS_PER_USER {
        let excess = keys.len() - MAX_KEYS_PER_USER;
        keys.drain(..excess);
    }
    while next.users.len() > MAX_USERS {
        let Some(stalest) = next
            .users
            .iter()
            .min_by(|a, b| newest(a.1).cmp(newest(b.1)))
            .map(|(u, _)| u.clone())
        else {
            break;
        };
        next.users.remove(&stalest);
    }
    let bytes = serde_json::to_vec_pretty(&next).map_err(|e| e.to_string())?;
    write_private(&path, &bytes)?;
    *file = next;
    Ok(false)
}

/// The newest `first_seen` among `keys`: RFC 3339 in UTC sorts as text.
fn newest(keys: &[PinnedKey]) -> &str {
    keys.iter()
        .map(|k| k.first_seen.as_str())
        .max()
        .unwrap_or("")
}

/// The pins at `path`. None yet is an empty set. A file that is not a pin
/// file starts over (it is only ever a cache of first sightings, and the
/// verdicts say so as `unknown` again); a NEWER version is left alone, and
/// nothing is remembered on top of it.
fn load_pins(path: &Path) -> Result<PinFile, String> {
    match std::fs::read(path) {
        Ok(bytes) => {
            #[derive(Deserialize)]
            struct Header {
                version: u32,
            }
            match serde_json::from_slice::<Header>(&bytes) {
                Ok(h) if h.version != VERSION => Err(format!(
                    "{} is a pin file this build does not read (version {}); left alone",
                    path.display(),
                    h.version
                )),
                Ok(_) => serde_json::from_slice(&bytes).or_else(|e| {
                    tracing::warn!(path = %path.display(), %e, "peer-auth: the browser-key file is unreadable; starting it over");
                    Ok(PinFile::default())
                }),
                Err(e) => {
                    tracing::warn!(path = %path.display(), %e, "peer-auth: the browser-key file is unreadable; starting it over");
                    Ok(PinFile::default())
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PinFile::default()),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

/// What reading a key file found.
enum Read {
    /// Boxed: a key pair is ~240 bytes, the other two a `String` each.
    Key(Box<DeviceKey>),
    /// Not a key file at all (truncated, not JSON, a PKCS#8 ring refuses):
    /// nothing in it is worth keeping, so a new key replaces it.
    Corrupt(String),
    /// A key file this build does not understand (a newer version or
    /// algorithm). Left alone: replacing it would destroy a newer agent's key
    /// after a rollback.
    Foreign(String),
}

/// The public half of `tenant_id`'s device key for the hello, made on first
/// use. Empty when this enrollment has no key it can keep (see the module
/// docs), which the hello reports as "cannot prove who it is".
pub fn hello_key(config_path: &Path, tenant_id: &str) -> String {
    match device_key(config_path, tenant_id) {
        Ok(key) => key.public_b64(),
        Err(why) => {
            tracing::warn!(tenant = %tenant_id, %why, "peer-auth: no device key this run, so the hello offers none");
            String::new()
        }
    }
}

/// `tenant_id`'s device key: read from its file, or made and written there.
/// Kept in memory for the life of the process once it is on disk, so every
/// hello of one run offers the same key.
pub fn device_key(config_path: &Path, tenant_id: &str) -> Result<Arc<DeviceKey>, String> {
    static KEYS: OnceLock<Mutex<HashMap<PathBuf, Arc<DeviceKey>>>> = OnceLock::new();
    let path = key_path(config_path, tenant_id)?;
    let mut keys = KEYS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(key) = keys.get(&path) {
        return Ok(key.clone());
    }
    // Read, or made and written, under the lock: two callers for one
    // enrollment can never each write a different key, leaving one of them
    // offering a key that is no longer on disk.
    let key = Arc::new(load_or_make(&path)?);
    keys.insert(path, key.clone());
    Ok(key)
}

/// Where `tenant_id`'s key lives: `<config dir>/peer-auth/<tenant id>.json`.
/// The tenant id names a file, so only an object id's 24 hex digits may.
///
/// ⚠️ A config path with no directory part (a bare `config.toml`) gets no
/// key: its directory would be whatever the process's working directory
/// happens to be, which is no place for a private key. The daemon resolves
/// an absolute path; the test harnesses pass a bare name they never read.
fn key_path(config_path: &Path, tenant_id: &str) -> Result<PathBuf, String> {
    if tenant_id.len() != 24 || !tenant_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("tenant id {tenant_id:?} is not an object id"));
    }
    let dir = config_path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or_else(|| format!("config path {} has no directory", config_path.display()))?;
    Ok(dir
        .join(DIR_NAME)
        .join(format!("{}.json", tenant_id.to_ascii_lowercase())))
}

/// Read the key at `path`, or make one and write it there. A key is returned
/// only once it is on disk as the next start will read it.
fn load_or_make(path: &Path) -> Result<DeviceKey, String> {
    match std::fs::read(path) {
        Ok(bytes) => match parse(&bytes) {
            Read::Key(key) => return Ok(*key),
            Read::Foreign(why) => {
                return Err(format!(
                    "{} is a key file this build does not read ({why}); left alone",
                    path.display()
                ));
            }
            Read::Corrupt(why) => tracing::warn!(
                path = %path.display(), %why,
                "peer-auth: the device key file is unreadable, so a new key replaces it; \
                 a browser that pinned the old one will warn"
            ),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        // Present but unreadable (permissions, I/O): never overwrite a file
        // that may hold a good key this process merely cannot open.
        Err(e) => return Err(format!("reading {}: {e}", path.display())),
    }
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|_| "making a P-256 key failed".to_string())?;
    let stored = Stored {
        version: VERSION,
        alg: ALG.to_string(),
        pkcs8: STANDARD.encode(pkcs8.as_ref()),
    };
    let bytes = serde_json::to_vec_pretty(&stored).map_err(|e| e.to_string())?;
    write_private(path, &bytes)?;
    let written =
        std::fs::read(path).map_err(|e| format!("reading back {}: {e}", path.display()))?;
    match parse(&written) {
        Read::Key(key) => {
            tracing::info!(path = %path.display(), "peer-auth: made this enrollment's device key");
            Ok(*key)
        }
        Read::Corrupt(why) | Read::Foreign(why) => Err(format!(
            "{} did not read back as written: {why}",
            path.display()
        )),
    }
}

fn parse(bytes: &[u8]) -> Read {
    // Version first, from a shape every version shares: a newer file is
    // never mistaken for a corrupt one.
    #[derive(Deserialize)]
    struct Header {
        version: u32,
        #[serde(default)]
        alg: String,
    }
    let header: Header = match serde_json::from_slice(bytes) {
        Ok(h) => h,
        Err(e) => return Read::Corrupt(format!("not a key file: {e}")),
    };
    if header.version != VERSION || header.alg != ALG {
        return Read::Foreign(format!("version {} alg {:?}", header.version, header.alg));
    }
    let stored: Stored = match serde_json::from_slice(bytes) {
        Ok(s) => s,
        Err(e) => return Read::Corrupt(format!("not a version-{VERSION} key file: {e}")),
    };
    let pkcs8 = match STANDARD.decode(stored.pkcs8.trim()) {
        Ok(p) => p,
        Err(e) => return Read::Corrupt(format!("the key is not base64: {e}")),
    };
    match EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &pkcs8,
        &SystemRandom::new(),
    ) {
        Ok(pair) => Read::Key(Box::new(DeviceKey { pair })),
        Err(e) => Read::Corrupt(format!("the key is refused: {e}")),
    }
}

/// Write `bytes` to `path` whole or not at all (a sibling, synced, renamed),
/// readable by the daemon's own identity alone.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let dir = path
        .parent()
        .ok_or_else(|| format!("{} has no directory", path.display()))?;
    std::fs::create_dir_all(dir).map_err(|e| format!("making {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("restricting {}: {e}", dir.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    // A stale sibling would keep its own mode: `mode` applies only to a file
    // being made.
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .map_err(|e| format!("making {}: {e}", tmp.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    drop(file);
    std::fs::rename(&tmp, path).map_err(|e| format!("placing {}: {e}", path.display()))?;
    // The rename itself survives a power cut only once the directory is
    // synced. Best effort: the key is already whole on disk either way.
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_remote_control::signaling::peer_auth_key_is_well_formed;

    const TENANT_A: &str = "66f0c0ffee00000000000a01";
    const TENANT_B: &str = "66f0c0ffee00000000000b02";

    fn config_in(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("config.toml")
    }

    #[test]
    fn a_key_is_made_once_and_read_back_the_same() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(&config_in(&dir), TENANT_A).unwrap();
        assert!(!path.exists());
        let made = load_or_make(&path).unwrap().public_b64();
        assert!(path.exists());
        assert!(peer_auth_key_is_well_formed(&made), "{made}");
        // A second read — a restart — finds the same key, and makes none.
        assert_eq!(load_or_make(&path).unwrap().public_b64(), made);
    }

    /// AC7 at the unit level: two enrollments on one device, two keys, two
    /// files.
    #[test]
    fn two_enrollments_get_two_keys() {
        let dir = tempfile::tempdir().unwrap();
        let a = key_path(&config_in(&dir), TENANT_A).unwrap();
        let b = key_path(&config_in(&dir), TENANT_B).unwrap();
        assert_ne!(a, b);
        assert_ne!(
            load_or_make(&a).unwrap().public_b64(),
            load_or_make(&b).unwrap().public_b64()
        );
    }

    #[test]
    fn the_hello_offers_the_same_key_for_the_whole_run() {
        let dir = tempfile::tempdir().unwrap();
        let first = hello_key(&config_in(&dir), TENANT_A);
        assert!(peer_auth_key_is_well_formed(&first), "{first}");
        assert_eq!(hello_key(&config_in(&dir), TENANT_A), first);
    }

    #[test]
    fn a_corrupt_file_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(&config_in(&dir), TENANT_A).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            b"{\"version\":1,\"alg\":\"ecdsa-p256-sha256\",\"pkcs8\":\"AAAA\"}",
        )
        .unwrap();
        let key = load_or_make(&path).unwrap().public_b64();
        assert!(peer_auth_key_is_well_formed(&key));
        assert_eq!(
            load_or_make(&path).unwrap().public_b64(),
            key,
            "the replacement stuck"
        );
        std::fs::write(&path, b"\0\0\0\0").unwrap();
        assert!(
            load_or_make(&path).is_ok(),
            "NUL-filled, as an unclean shutdown leaves"
        );
    }

    /// A rollback must not destroy the newer agent's key: its file is left
    /// as it was, and this build offers none.
    #[test]
    fn a_newer_key_file_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(&config_in(&dir), TENANT_A).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let newer = br#"{"version":2,"alg":"ecdsa-p256-sha256","pkcs8":"from the future"}"#;
        std::fs::write(&path, newer).unwrap();
        assert!(load_or_make(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), newer);
    }

    /// A key that cannot be written is not offered: `peer-auth` is a FILE
    /// here, so the directory cannot be made.
    #[test]
    fn a_key_that_cannot_be_kept_is_not_offered() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(DIR_NAME), b"in the way").unwrap();
        assert_eq!(hello_key(&config_in(&dir), TENANT_A), "");
        assert!(
            device_key(&config_in(&dir), TENANT_A).is_err(),
            "and nothing was cached"
        );
    }

    /// A bare config name has no directory of its own: no key, and nothing
    /// written where the process happens to be standing.
    #[test]
    fn a_config_path_without_a_directory_gets_no_key() {
        let bare = Path::new("unused-in-tests.toml");
        assert!(key_path(bare, TENANT_A).is_err());
        assert_eq!(hello_key(bare, TENANT_A), "");
        assert!(
            !Path::new(DIR_NAME).exists(),
            "nothing made in the working directory"
        );
    }

    #[test]
    fn only_an_object_id_names_a_key_file() {
        let dir = tempfile::tempdir().unwrap();
        for bad in [
            "",
            "../../etc/passwd",
            "66f0c0ffee00000000000a0",
            "66f0c0ffee00000000000a01x",
            "zzf0c0ffee00000000000a01",
        ] {
            assert!(key_path(&config_in(&dir), bad).is_err(), "{bad:?}");
        }
        let upper = key_path(&config_in(&dir), &TENANT_A.to_ascii_uppercase()).unwrap();
        assert_eq!(
            upper,
            key_path(&config_in(&dir), TENANT_A).unwrap(),
            "one file per tenant"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_key_is_readable_by_its_owner_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = key_path(&config_in(&dir), TENANT_A).unwrap();
        load_or_make(&path).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    // ─── P1b — signing the answer ───────────────────────────────────────

    use bson::oid::ObjectId;
    use meshharbor_remote_control::signaling::{
        ClientMsg, PeerAuthAnswer, PeerAuthOffer, peer_auth_transcript, peer_auth_verify,
    };

    const OFFER_SDP: &str = "v=0\r\na=fingerprint:sha-256 aa:bb:cc\r\n";
    const ANSWER_SDP: &str = "v=0\r\na=fingerprint:sha-256 dd:ee:ff\r\n";
    const AGENT: &str = "66f0c0ffee00000000000d01";

    /// A browser's nonce: bytes 0 to 15, base64url without padding. Built,
    /// not written as a literal: a secret scanner cannot tell a counting
    /// sequence from a key.
    fn nonce() -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            (0u8..16).collect::<Vec<u8>>(),
        )
    }

    fn ask() -> PeerAuthOffer {
        PeerAuthOffer {
            nonce: nonce(),
            key: None,
            sig: None,
        }
    }

    /// The transcript the browser would rebuild for this session's answer.
    fn transcript_for(session: ObjectId, user: ObjectId) -> Vec<u8> {
        peer_auth_transcript(
            "answer",
            &session.to_hex(),
            AGENT,
            &user.to_hex(),
            "sha-256 AA:BB:CC",
            "sha-256 DD:EE:FF",
            &nonce(),
        )
        .unwrap()
    }

    #[test]
    fn an_asked_answer_is_signed_over_the_sessions_transcript() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_in(&dir);
        let offers = PendingOffers::default();
        let (session, user) = (ObjectId::new(), ObjectId::new());
        offers.note_request(session, user);
        offers.note_offer(session, OFFER_SDP, Some(&ask()));
        let signed = sign_answer(&offers, &cfg, TENANT_A, AGENT, session, ANSWER_SDP)
            .expect("an asked answer is signed");
        // The key that signed is this enrollment's, the one its hello offers.
        assert_eq!(signed.key, hello_key(&cfg, TENANT_A));
        assert!(peer_auth_verify(
            &signed.key,
            &transcript_for(session, user),
            &signed.sig
        ));
        // …and over that session's transcript only: another controller's
        // would not verify.
        assert!(!peer_auth_verify(
            &signed.key,
            &transcript_for(session, ObjectId::new()),
            &signed.sig
        ));
        // One answer per offer; a re-offer that asks is answered again, the
        // controller having stayed noted.
        assert!(sign_answer(&offers, &cfg, TENANT_A, AGENT, session, ANSWER_SDP).is_none());
        offers.note_offer(session, OFFER_SDP, Some(&ask()));
        assert!(sign_answer(&offers, &cfg, TENANT_A, AGENT, session, ANSWER_SDP).is_some());
    }

    #[test]
    fn an_answer_nobody_asked_to_sign_goes_unsigned() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_in(&dir);
        let offers = PendingOffers::default();
        let (session, user) = (ObjectId::new(), ObjectId::new());
        let sign = |offers: &PendingOffers, session| {
            sign_answer(offers, &cfg, TENANT_A, AGENT, session, ANSWER_SDP)
        };
        offers.note_request(session, user);

        offers.note_offer(session, OFFER_SDP, None);
        assert!(sign(&offers, session).is_none(), "the offer did not ask");
        let bad = PeerAuthOffer {
            nonce: "too-short".into(),
            key: None,
            sig: None,
        };
        offers.note_offer(session, OFFER_SDP, Some(&bad));
        assert!(
            sign(&offers, session).is_none(),
            "a nonce that is not well formed"
        );
        offers.note_offer(session, "v=0\r\n", Some(&ask()));
        assert!(
            sign(&offers, session).is_none(),
            "an offer with no fingerprint"
        );
        offers.note_offer(session, OFFER_SDP, Some(&ask()));
        offers.note_offer(session, OFFER_SDP, None);
        assert!(
            sign(&offers, session).is_none(),
            "a re-offer that did not ask"
        );
        offers.note_offer(session, OFFER_SDP, Some(&ask()));
        offers.forget(session);
        assert!(sign(&offers, session).is_none(), "an ended session");

        // A session whose request never reached this process: an outsider's
        // (bound by FR-52 instead), or one another daemon admitted.
        let stranger = ObjectId::new();
        offers.note_offer(stranger, OFFER_SDP, Some(&ask()));
        assert!(sign(&offers, stranger).is_none());
    }

    #[test]
    fn an_enrollment_without_a_kept_key_signs_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(DIR_NAME), b"in the way").unwrap();
        let offers = PendingOffers::default();
        let (session, user) = (ObjectId::new(), ObjectId::new());
        offers.note_request(session, user);
        offers.note_offer(session, OFFER_SDP, Some(&ask()));
        assert!(
            sign_answer(
                &offers,
                &config_in(&dir),
                TENANT_A,
                AGENT,
                session,
                ANSWER_SDP
            )
            .is_none()
        );
    }

    /// The FR-43 choke point: a worker's answer leaves signed by the daemon,
    /// and whatever the worker claimed is never passed on.
    #[test]
    fn a_workers_answer_is_signed_by_the_daemon_and_its_own_claim_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_in(&dir);
        let offers = PendingOffers::default();
        let (session, user) = (ObjectId::new(), ObjectId::new());
        offers.note_request(session, user);
        offers.note_offer(session, OFFER_SDP, Some(&ask()));
        let forged = || {
            Some(PeerAuthAnswer {
                key: "a worker's key".into(),
                sig: "a worker's signature".into(),
            })
        };
        let mut msg = ClientMsg::SdpAnswer {
            session_id: session,
            sdp: ANSWER_SDP.into(),
            extauth_mac: None,
            peer_auth: forged(),
            // FR-100 P1c — a worker's verdict is not the daemon's either.
            peer_auth_verdict: Some("verified".into()),
        };
        sign_outbound(
            &offers,
            &cfg,
            TENANT_A,
            AGENT,
            PeerAuthPolicy::Audit,
            &mut msg,
        );
        let ClientMsg::SdpAnswer {
            peer_auth: Some(signed),
            peer_auth_verdict,
            ..
        } = msg
        else {
            panic!("the daemon signs the worker's answer");
        };
        assert!(peer_auth_verify(
            &signed.key,
            &transcript_for(session, user),
            &signed.sig
        ));
        assert_eq!(
            peer_auth_verdict, None,
            "the daemon judged nothing here, so it reports nothing"
        );

        // Nothing noted for this one: the worker's claim is dropped, not kept.
        let mut msg = ClientMsg::SdpAnswer {
            session_id: ObjectId::new(),
            sdp: ANSWER_SDP.into(),
            extauth_mac: None,
            peer_auth: forged(),
            peer_auth_verdict: Some("verified".into()),
        };
        sign_outbound(
            &offers,
            &cfg,
            TENANT_A,
            AGENT,
            PeerAuthPolicy::Audit,
            &mut msg,
        );
        assert!(matches!(
            msg,
            ClientMsg::SdpAnswer {
                peer_auth: None,
                peer_auth_verdict: None,
                ..
            }
        ));
    }

    #[test]
    fn the_table_forgets_its_oldest_session_past_its_cap() {
        let dir = tempfile::tempdir().unwrap();
        let offers = PendingOffers::default();
        let first = ObjectId::new();
        offers.note_request(first, ObjectId::new());
        for _ in 0..MAX_PENDING {
            offers.note_request(ObjectId::new(), ObjectId::new());
        }
        assert_eq!(offers.table.lock().unwrap().sessions.len(), MAX_PENDING);
        offers.note_offer(first, OFFER_SDP, Some(&ask()));
        assert!(
            sign_answer(
                &offers,
                &config_in(&dir),
                TENANT_A,
                AGENT,
                first,
                ANSWER_SDP
            )
            .is_none(),
            "the oldest session was forgotten"
        );
    }

    // ─── P1c — the device checks the browser ────────────────────────────

    /// A browser: a P-256 key the test holds, its public half as an offer
    /// carries it. Made fresh, never a literal.
    struct Browser {
        pair: EcdsaKeyPair,
        key: String,
    }

    fn browser() -> Browser {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let key = STANDARD.encode(pair.public_key().as_ref());
        Browser { pair, key }
    }

    /// `browser`'s offer for this session and user, signed over the
    /// transcript with role `offer` and an EMPTY answer fingerprint.
    fn signed_offer(browser: &Browser, session: ObjectId, user: ObjectId) -> PeerAuthOffer {
        let transcript = peer_auth_transcript(
            "offer",
            &session.to_hex(),
            AGENT,
            &user.to_hex(),
            "sha-256 AA:BB:CC",
            "",
            &nonce(),
        )
        .unwrap();
        let sig = browser
            .pair
            .sign(&SystemRandom::new(), &transcript)
            .unwrap();
        PeerAuthOffer {
            nonce: nonce(),
            key: Some(browser.key.clone()),
            sig: Some(base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                sig.as_ref(),
            )),
        }
    }

    fn check<'a>(cfg: &'a Path, policy: PeerAuthPolicy) -> OfferCheck<'a> {
        OfferCheck {
            policy,
            config_path: cfg,
            tenant_id: TENANT_A,
            agent_id: AGENT,
        }
    }

    /// One in-org offer, noted and judged as the daemon does it.
    fn judged(
        offers: &PendingOffers,
        cfg: &Path,
        policy: PeerAuthPolicy,
        session: ObjectId,
        user: ObjectId,
        ask: &PeerAuthOffer,
    ) -> Option<Verdict> {
        offers.note_request(session, user);
        offers.note_offer(session, OFFER_SDP, Some(ask));
        offers.judge_offer(session, OFFER_SDP, Some(ask), &check(cfg, policy))
    }

    #[test]
    fn an_offer_nobody_signed_reads_absent_and_is_reported_once() {
        let dir = tempfile::tempdir().unwrap();
        let offers = PendingOffers::default();
        let session = ObjectId::new();
        let verdict = judged(
            &offers,
            &config_in(&dir),
            PeerAuthPolicy::Audit,
            session,
            ObjectId::new(),
            &ask(),
        );
        assert_eq!(verdict, Some(Verdict::Absent));
        assert_eq!(
            answer_verdict(&offers, PeerAuthPolicy::Audit, session, false).as_deref(),
            Some("absent")
        );
        assert_eq!(
            answer_verdict(&offers, PeerAuthPolicy::Audit, session, false),
            None,
            "one report per offer"
        );
        // An offer that did not even ask is judged too: nobody signed it.
        let other = ObjectId::new();
        offers.note_request(other, ObjectId::new());
        offers.note_offer(other, OFFER_SDP, None);
        assert_eq!(
            offers.judge_offer(
                other,
                OFFER_SDP,
                None,
                &check(&config_in(&dir), PeerAuthPolicy::Audit)
            ),
            Some(Verdict::Absent)
        );
    }

    /// Trust on first use, per user: a browser's first offer is `unknown` and
    /// remembered; its next is `verified`; the same key for ANOTHER user is
    /// that user's first sighting.
    #[test]
    fn a_browser_is_unknown_once_then_verified_per_user() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_in(&dir);
        let offers = PendingOffers::default();
        let chrome = browser();
        let user = ObjectId::new();
        let first = ObjectId::new();
        let ask = signed_offer(&chrome, first, user);
        assert_eq!(
            judged(&offers, &cfg, PeerAuthPolicy::Audit, first, user, &ask),
            Some(Verdict::Unknown)
        );
        assert!(
            pins_path(&cfg, TENANT_A).unwrap().exists(),
            "remembered on disk"
        );
        let second = ObjectId::new();
        let ask = signed_offer(&chrome, second, user);
        assert_eq!(
            judged(&offers, &cfg, PeerAuthPolicy::Audit, second, user, &ask),
            Some(Verdict::Verified)
        );
        let someone_else = ObjectId::new();
        let third = ObjectId::new();
        let ask = signed_offer(&chrome, third, someone_else);
        assert_eq!(
            judged(
                &offers,
                &cfg,
                PeerAuthPolicy::Audit,
                third,
                someone_else,
                &ask
            ),
            Some(Verdict::Unknown)
        );
    }

    /// A signature that does not cover THIS session is a mismatch, whatever
    /// it would verify over: another session, another user, a nonce that is
    /// not a nonce. So is an offer that names no single certificate.
    #[test]
    fn a_signature_over_anything_else_is_a_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_in(&dir);
        let offers = PendingOffers::default();
        let chrome = browser();
        let user = ObjectId::new();

        let session = ObjectId::new();
        let for_another_session = signed_offer(&chrome, ObjectId::new(), user);
        assert_eq!(
            judged(
                &offers,
                &cfg,
                PeerAuthPolicy::Audit,
                session,
                user,
                &for_another_session
            ),
            Some(Verdict::Mismatch)
        );

        let session = ObjectId::new();
        let for_another_user = signed_offer(&chrome, session, ObjectId::new());
        assert_eq!(
            judged(
                &offers,
                &cfg,
                PeerAuthPolicy::Audit,
                session,
                user,
                &for_another_user
            ),
            Some(Verdict::Mismatch)
        );

        let session = ObjectId::new();
        let mut bad_nonce = signed_offer(&chrome, session, user);
        bad_nonce.nonce = "too-short".into();
        assert_eq!(
            judged(
                &offers,
                &cfg,
                PeerAuthPolicy::Audit,
                session,
                user,
                &bad_nonce
            ),
            Some(Verdict::Mismatch)
        );

        let session = ObjectId::new();
        let ask = signed_offer(&chrome, session, user);
        offers.note_request(session, user);
        offers.note_offer(session, "v=0\r\n", Some(&ask));
        assert_eq!(
            offers.judge_offer(
                session,
                "v=0\r\n",
                Some(&ask),
                &check(&cfg, PeerAuthPolicy::Audit)
            ),
            Some(Verdict::Mismatch),
            "no certificate for the signature to cover"
        );
        assert!(
            !pins_path(&cfg, TENANT_A).unwrap().exists(),
            "a mismatch is never remembered"
        );
    }

    /// `off` judges nothing, remembers nothing and reports nothing, for an
    /// outsider's session too.
    #[test]
    fn off_judges_remembers_and_reports_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_in(&dir);
        let offers = PendingOffers::default();
        let session = ObjectId::new();
        let user = ObjectId::new();
        let ask = signed_offer(&browser(), session, user);
        assert_eq!(
            judged(&offers, &cfg, PeerAuthPolicy::Off, session, user, &ask),
            None
        );
        assert_eq!(
            answer_verdict(&offers, PeerAuthPolicy::Off, session, false),
            None
        );
        assert_eq!(
            answer_verdict(&offers, PeerAuthPolicy::Off, session, true),
            None
        );
        assert!(!pins_path(&cfg, TENANT_A).unwrap().exists());
    }

    /// An outsider's session is never noted in-org: its answer reports
    /// `verified`, because FR-52 admitted it on a MAC the device checked.
    #[test]
    fn an_outsiders_answer_reports_verified() {
        let offers = PendingOffers::default();
        assert_eq!(
            answer_verdict(&offers, PeerAuthPolicy::Audit, ObjectId::new(), true).as_deref(),
            Some("verified")
        );
        assert_eq!(
            answer_verdict(&offers, PeerAuthPolicy::Audit, ObjectId::new(), false),
            None,
            "an in-org session nobody judged reports nothing"
        );
    }

    /// A re-offer is judged afresh: the first offer's verdict never answers
    /// the second.
    #[test]
    fn a_re_offer_drops_the_earlier_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_in(&dir);
        let offers = PendingOffers::default();
        let session = ObjectId::new();
        let user = ObjectId::new();
        let ask = signed_offer(&browser(), session, user);
        judged(&offers, &cfg, PeerAuthPolicy::Audit, session, user, &ask);
        offers.note_offer(session, OFFER_SDP, None);
        assert_eq!(
            answer_verdict(&offers, PeerAuthPolicy::Audit, session, false),
            None,
            "noted but not yet judged"
        );
    }

    /// A person with more browsers than the cap loses the OLDEST one's pin.
    #[test]
    fn a_users_pins_are_bounded_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_in(&dir);
        let user = ObjectId::new();
        let keys: Vec<String> = (0..=MAX_KEYS_PER_USER).map(|_| browser().key).collect();
        for key in &keys {
            assert_eq!(remember(&cfg, TENANT_A, user, key), Ok(false));
        }
        let stored: PinFile =
            serde_json::from_slice(&std::fs::read(pins_path(&cfg, TENANT_A).unwrap()).unwrap())
                .unwrap();
        let kept: Vec<&str> = stored.users[&user.to_hex()]
            .iter()
            .map(|k| k.key.as_str())
            .collect();
        assert_eq!(kept.len(), MAX_KEYS_PER_USER);
        assert!(!kept.contains(&keys[0].as_str()), "the oldest went first");
        assert!(kept.contains(&keys[MAX_KEYS_PER_USER].as_str()));
    }

    /// A rollback must not destroy a newer agent's pins: the file is left as
    /// it was, and nothing is remembered on top of it (the verdict still says
    /// `unknown`, honestly).
    #[test]
    fn a_newer_pin_file_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_in(&dir);
        let path = pins_path(&cfg, TENANT_A).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let newer = br#"{"version":2,"users":{"from":"the future"}}"#;
        std::fs::write(&path, newer).unwrap();
        let offers = PendingOffers::default();
        let session = ObjectId::new();
        let user = ObjectId::new();
        let ask = signed_offer(&browser(), session, user);
        assert_eq!(
            judged(&offers, &cfg, PeerAuthPolicy::Audit, session, user, &ask),
            Some(Verdict::Unknown)
        );
        assert_eq!(std::fs::read(&path).unwrap(), newer);
    }

    /// A bare config name has no directory: nothing is remembered, nothing is
    /// written where the process stands, and the verdict says `unknown`.
    #[test]
    fn a_config_path_without_a_directory_remembers_nothing() {
        let bare = Path::new("unused-in-tests.toml");
        let offers = PendingOffers::default();
        let session = ObjectId::new();
        let user = ObjectId::new();
        let ask = signed_offer(&browser(), session, user);
        assert_eq!(
            judged(&offers, bare, PeerAuthPolicy::Audit, session, user, &ask),
            Some(Verdict::Unknown)
        );
        assert!(!Path::new(DIR_NAME).exists());
    }

    #[cfg(unix)]
    #[test]
    fn the_pins_are_readable_by_their_owner_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let cfg = config_in(&dir);
        remember(&cfg, TENANT_A, ObjectId::new(), &browser().key).unwrap();
        let path = pins_path(&cfg, TENANT_A).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
