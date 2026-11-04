// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-52 P3b — the device's external-login state: which logins are in flight,
//! how many guesses this device has answered, and which logins verified.
//!
//! [`crate::external_access`] speaks the OPAQUE protocol and nothing else. This
//! module decides who may be answered, how often, and what a verified login is
//! good for. It has no wire and no gates of its own — the caller (P3c's frame
//! handler) checks gate 3 and loads the credential; this is gate 4's *policy*.
//!
//! # The one rule everything here follows
//!
//! **A guess is debited when a KE2 leaves the device — never when a KE3 fails.**
//! In OPAQUE the client learns whether its password is right while opening KE2,
//! before any KE3 exists. A guessing client stops there, so the device never
//! sees a failure. Measured with the real browser library (FR-52 field log,
//! 2026-09-24): wrong password ⇒ the client refused at KE2 and the device saw an
//! abandoned login. A throttle that counted failed KE3s would count nothing.
//!
//! Three consequences, each easy to get wrong in a way that reads as tidying:
//!
//! 1. **Check and debit are one critical section.** If the budget were checked,
//!    the lock released and the debit taken later, an attacker who sends a
//!    hundred KE1s at once gets every one of them past the check before the
//!    first debit lands. [`ExternalLogins::begin`] holds the lock across the
//!    check, the (cheap) OPAQUE step and the debit.
//! 2. **An exhausted budget answers nothing.** A refusal that still carried a
//!    KE2 would still be an oracle.
//! 3. **A success refunds ITS OWN debit, not the streak.** Resetting the count
//!    on any verified login would hand an attacker a fresh budget every time the
//!    legitimate outsider logged in.
//!
//! # What this is not
//!
//! Not DoS protection. Answering KE1 costs the device one OPRF evaluation and a
//! 3DH — the Argon2 is the *client's* cost — so the throttle is tuned for
//! guesses, not CPU. And it is in-memory: a daemon restart forgives the window.
//! An attacker cannot restart the daemon without either local access or a crash
//! bug, and a restart forgives at most one day's worth of guesses; persisting the
//! window is recorded as an open decision in the FR-52 spec rather than done
//! quietly here.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;

use crate::external_access::{self, Credential, PendingLogin};

/// Guesses answered within [`GUESS_WINDOW`] before any delay applies.
pub const FREE_GUESSES: usize = 5;
/// The first delay, after the free guesses are spent. Doubles per guess.
pub const BACKOFF_BASE: Duration = Duration::from_secs(30);
/// The delay stops doubling here. Steady state for an attacker who knows the
/// connect code: about 34 answered guesses a day — against a password of at
/// least [`external_access::MIN_PASSWORD_CHARS`] characters.
pub const BACKOFF_MAX: Duration = Duration::from_secs(60 * 60);
/// How long an unrefunded guess counts against the device.
pub const GUESS_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
/// KE1 → KE3. Generous: it covers the client's Argon2 (about a second on a
/// laptop, several on a phone) plus two relayed round trips.
pub const PENDING_TTL: Duration = Duration::from_secs(60);
/// Verified login → P4's session offer.
pub const VERIFIED_TTL: Duration = Duration::from_secs(120);
/// Ceiling on in-flight logins, on unconsumed verified ones, and (P4) on
/// admitted external sessions that have not yet been answered. A backstop:
/// the throttle already keeps each table far below it.
pub const TABLE_CAP: usize = 32;
/// P4 — how long an admitted external session may wait for consent and its
/// one offer before its binding is dropped. Longer than everything the server
/// allows the same wait — the attended consent window (5 min), its verdict
/// grace and the negotiating reaper (30 s) — so by the time a binding ages out
/// here the server has already ended its session, and nothing live is refused.
pub const BINDING_TTL: Duration = Duration::from_secs(15 * 60);
/// P4 — ended external session ids remembered, oldest first out. An id only
/// falls out after this many LATER external sessions, each of which cost a
/// verified login.
const ENDED_MEMORY: usize = 256;
/// Attempt ids and principals arrive from the server; anything longer than
/// this is not an id this protocol mints.
const MAX_ID_LEN: usize = 64;

/// The label that scopes [`AppKey`]. Part of the wire: the browser derives the
/// same key from the same bytes.
const APP_KEY_LABEL: &[u8] = b"roomler-extauth-v1 app-key";

/// Why a login step was refused. Each maps to a different line in the audit
/// log, so none of them may be folded into another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Too many guesses answered recently. Nothing was answered.
    Throttled { retry_after: Duration },
    /// The in-flight table is full. Nothing was answered and nothing debited.
    Busy,
    /// The attempt id or principal is not a well-formed id, or the attempt id
    /// is already in use. Nothing was answered and nothing debited.
    BadIdentifier,
    /// The client's message is not an OPAQUE message — a broken or hostile
    /// client, not a wrong password.
    Malformed,
    /// The stored credential cannot be used (corrupt); the owner must set the
    /// password again. Nothing was answered.
    Unavailable,
    /// KE3 for an attempt that is not in flight: never started, expired, or
    /// already finished.
    UnknownAttempt,
    /// KE3 arrived attributed to a different principal than the KE1 that
    /// started the attempt. The guess stays debited.
    PrincipalMismatch,
    /// KE3 did not verify. The guess stays debited.
    Rejected,
}

/// The key a verified login leaves behind for P4: 32 bytes derived from the
/// session key, bound to the attempt and to the principal the server named.
///
/// ⚠️ The principal is bound HERE, after the login, because the browser library
/// passes no OPAQUE `context` — and it cannot be bound through OPAQUE's
/// identifiers either, since those are fixed into the envelope at registration
/// and this password is shared by every outsider the owner gives it to. If the
/// server names the wrong principal to the device, the device derives a
/// different key from the browser's, and P4's MAC over the DTLS fingerprint
/// fails closed.
pub struct AppKey([u8; 32]);

impl std::fmt::Debug for AppKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AppKey(***)")
    }
}

impl AppKey {
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

/// `HKDF-SHA512(salt = none, ikm = session key)`, expanded under
/// `label ‖ u16be(len) ‖ attempt ‖ u16be(len) ‖ principal`.
///
/// Length-prefixed rather than separated so that no content of either field
/// can make two different (attempt, principal) pairs encode to the same bytes.
/// Locked by a known-answer test computed with an independent HKDF.
fn derive_app_key(session_key: &[u8], attempt_id: &str, principal: &str) -> AppKey {
    let mut info = Vec::with_capacity(APP_KEY_LABEL.len() + 4 + attempt_id.len() + principal.len());
    info.extend_from_slice(APP_KEY_LABEL);
    for field in [attempt_id.as_bytes(), principal.as_bytes()] {
        // Both fields are validated to at most MAX_ID_LEN bytes, so the length
        // always fits in a u16.
        info.extend_from_slice(&(field.len() as u16).to_be_bytes());
        info.extend_from_slice(field);
    }
    let mut okm = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha512>::new(None, session_key)
        .expand(&info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA512 output length");
    AppKey(okm)
}

/// FR-52 P4 — why an external session's offer or answer was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    /// No login was ever bound to this session: it is an ORDINARY session.
    ///
    /// ⚠️ The only answer on which a caller may go ahead without a MAC — so it
    /// must never be the answer for a session that WAS external. That is why an
    /// ended binding is remembered ([`Self::Ended`]) and why a full table
    /// refuses a new binding rather than evicting a live one.
    NotBound,
    /// An external session that is over: ended, already answered, or aged
    /// out. Remembered so that a later offer for it is refused, never read as
    /// an ordinary session's.
    Ended,
    /// The offer arrived before THIS device granted consent. Gate 5 is the
    /// device's own, so it is enforced here whatever the server's view of the
    /// session — the device does not take the server's word for it.
    NotConsented,
    /// A second offer. An external session gets exactly one: the device
    /// rebuilds its peer for each offer, and nothing about a second one is
    /// covered by the consent the first was given under.
    AlreadyOffered,
    /// An answer for a session whose offer was never admitted.
    NotOffered,
    /// The SDP carries no `a=fingerprint:` line to authenticate.
    NoFingerprint,
    /// The SDP carries MORE THAN ONE distinct fingerprint. Refused: the MAC
    /// could cover one certificate while the transport uses another.
    AmbiguousFingerprint,
    /// An external offer arrived with no MAC at all.
    MissingMac,
    /// The MAC does not verify under the login's key: whoever built this
    /// offer did not complete the login.
    BadMac,
}

/// The one DTLS certificate fingerprint an SDP announces, normalised.
///
/// Normalisation — the browser MUST apply the same, byte for byte: each
/// `a=fingerprint:<hash> <hex>` value becomes `lowercase(hash) + " " +
/// uppercase(hex)`. RFC 8122 makes the hash token case-insensitive and asks
/// for uppercase hex, but stacks differ on both, and the two ends of a MAC must
/// agree on every byte.
///
/// ⚠️ Exactly ONE distinct value, or an error. Every m-section of a
/// peer connection normally repeats the same certificate's fingerprint; an SDP
/// with two different ones is either broken or crafted so that the MAC covers
/// one certificate while DTLS negotiates the other.
///
/// FR-100 P1b moved the rule itself to
/// `meshharbor_remote_control::signaling::sdp_dtls_fingerprint`, unchanged:
/// the device's answer signature covers the same fingerprints in every build,
/// and two copies of one normalisation are two chances to disagree.
pub fn sdp_fingerprint(sdp: &str) -> Result<String, BindingError> {
    use meshharbor_remote_control::signaling::{SdpFingerprintError, sdp_dtls_fingerprint};
    sdp_dtls_fingerprint(sdp).map_err(|e| match e {
        SdpFingerprintError::Missing => BindingError::NoFingerprint,
        SdpFingerprintError::Ambiguous => BindingError::AmbiguousFingerprint,
    })
}

/// The label that scopes the transport MAC. Part of the wire.
const TRANSPORT_LABEL: &[u8] = b"roomler-extauth-v1 transport";

/// `HMAC-SHA256(app key, label ‖ u16be(len) ‖ role ‖ u16be(len) ‖ fingerprint)`.
///
/// The role (`offer` / `answer`) is in the MAC so that one side's tag can never
/// be replayed as the other's. Locked by a known-answer test computed with an
/// independent HMAC.
fn transport_hmac(key: &AppKey, role: &str, fingerprint: &str) -> hmac::Hmac<sha2::Sha256> {
    use hmac::Mac as _;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key.expose())
        .expect("HMAC takes a key of any length");
    mac.update(TRANSPORT_LABEL);
    for field in [role.as_bytes(), fingerprint.as_bytes()] {
        // Both are bounded well below u16: a role is one of two words, and a
        // fingerprint is a hash name plus at most 64 hex pairs.
        mac.update(&(field.len() as u16).to_be_bytes());
        mac.update(field);
    }
    mac
}

fn transport_mac(key: &AppKey, role: &str, fingerprint: &str) -> [u8; 32] {
    use hmac::Mac as _;
    transport_hmac(key, role, fingerprint)
        .finalize()
        .into_bytes()
        .into()
}

fn b64url() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

fn well_formed_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

struct Pending {
    login: PendingLogin,
    principal: String,
    started: Instant,
}

struct Verified {
    key: AppKey,
    principal: String,
    verified: Instant,
}

/// P4 — an admitted external session, from its `Request` to its sealed answer.
///
/// The key lives exactly as long as it has work to do: it verifies the one
/// offer and seals the one answer, and is dropped with the answer. What
/// outlives it is the session id, in [`Inner::ended`].
struct Bound {
    key: AppKey,
    /// The login that admitted the session. The server RE-PUSHES a pending
    /// `Request` when the agent's socket flaps before consent; that names the
    /// same login for the same session and is the same admission — not a
    /// second one, and not a refusal.
    attempt_id: String,
    principal: String,
    /// THIS device granted consent. Never set from anything the server says.
    consented: bool,
    /// The session's one offer was admitted; its answer is next.
    offered: bool,
    bound: Instant,
}

#[derive(Default)]
struct Inner {
    /// Every KE2 served and not yet refunded: when, and for which attempt.
    guesses: VecDeque<(Instant, String)>,
    pending: HashMap<String, Pending>,
    verified: HashMap<String, Verified>,
    /// P4 — session id → its admission, until the answer is sealed.
    sessions: HashMap<String, Bound>,
    /// P4 — external sessions that are over, most recent last. A later offer
    /// for one of these is REFUSED: without this record it would find no
    /// binding and be taken for an ordinary session's.
    ended: VecDeque<String>,
}

impl Inner {
    /// Drop what has aged out. Ages come from `saturating_duration_since`, never
    /// from `now - d`: that subtraction PANICS on a host up for less than `d`
    /// (see `crate::clock`), and a 24-hour window is exactly the shape that
    /// would reach for it.
    fn prune(&mut self, now: Instant) {
        while self
            .guesses
            .front()
            .is_some_and(|(t, _)| now.saturating_duration_since(*t) > GUESS_WINDOW)
        {
            self.guesses.pop_front();
        }
        self.pending
            .retain(|_, p| now.saturating_duration_since(p.started) <= PENDING_TTL);
        self.verified
            .retain(|_, v| now.saturating_duration_since(v.verified) <= VERIFIED_TTL);
        let stale: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, b)| now.saturating_duration_since(b.bound) > BINDING_TTL)
            .map(|(s, _)| s.clone())
            .collect();
        for session_id in stale {
            self.retire(&session_id);
        }
    }

    /// P4 — end an external session's binding, and remember that it was one.
    /// `false` = it was never bound: an ordinary session, nothing to record.
    fn retire(&mut self, session_id: &str) -> bool {
        if self.sessions.remove(session_id).is_none() {
            return false;
        }
        if self.ended.len() >= ENDED_MEMORY {
            self.ended.pop_front();
        }
        self.ended.push_back(session_id.to_owned());
        true
    }

    fn is_ended(&self, session_id: &str) -> bool {
        self.ended.iter().any(|s| s == session_id)
    }

    /// Consume the verified login for `attempt_id`, once: a verified login
    /// admits exactly one session. A principal that does not match leaves the
    /// grant in place for its rightful holder rather than burning it.
    fn take_verified(&mut self, attempt_id: &str, principal: &str) -> Option<AppKey> {
        if self.verified.get(attempt_id)?.principal != principal {
            return None;
        }
        self.verified.remove(attempt_id).map(|v| v.key)
    }

    /// How long until the next guess may be answered, or `None` if now.
    fn wait(&self, now: Instant) -> Option<Duration> {
        let answered = self.guesses.len();
        if answered < FREE_GUESSES {
            return None;
        }
        let doublings = u32::try_from(answered - FREE_GUESSES).unwrap_or(u32::MAX);
        let delay = 2u32
            .checked_pow(doublings)
            .and_then(|factor| BACKOFF_BASE.checked_mul(factor))
            .map_or(BACKOFF_MAX, |d| d.min(BACKOFF_MAX));
        let (last, _) = self.guesses.back()?;
        let elapsed = now.saturating_duration_since(*last);
        // `checked_sub`, not `(elapsed < delay).then(|| delay - elapsed)`: the
        // lazy form is correct only while it stays lazy, and the eager
        // `then_some` a lint would suggest PANICS on Duration underflow.
        delay.checked_sub(elapsed).filter(|left| !left.is_zero())
    }
}

/// The device's external-login state. ONE per daemon: it is held by
/// `remote_config::RemoteConfigServices`, which is built once and cloned into
/// every org's control loop — see the field there for why that, and not a
/// process-wide static, is the owner.
#[derive(Default)]
pub struct ExternalLogins {
    inner: Mutex<Inner>,
}

impl ExternalLogins {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock means a panic mid-update. The state is still
        // internally consistent at every await-free step below, and refusing
        // every future login because of one panic would turn a bug into a
        // permanent outage of gate 4.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// KE1 → KE2 for `attempt_id`, on behalf of `principal`.
    ///
    /// On success exactly one guess has been debited, because a KE2 is leaving
    /// the device. On any refusal nothing was answered and nothing was debited.
    pub fn begin(
        &self,
        attempt_id: &str,
        principal: &str,
        cred: &Credential,
        ke1: &[u8],
        now: Instant,
    ) -> Result<Vec<u8>, Refusal> {
        if !well_formed_id(attempt_id) || !well_formed_id(principal) {
            return Err(Refusal::BadIdentifier);
        }
        // ONE critical section from the throttle check to the debit — see the
        // module docs, rule 1. `login_start` is an OPRF evaluation and a 3DH;
        // holding a std mutex across it is fine, and never across an await.
        let mut g = self.lock();
        g.prune(now);
        if let Some(retry_after) = g.wait(now) {
            return Err(Refusal::Throttled { retry_after });
        }
        if g.pending.len() >= TABLE_CAP {
            return Err(Refusal::Busy);
        }
        if g.pending.contains_key(attempt_id) || g.verified.contains_key(attempt_id) {
            return Err(Refusal::BadIdentifier);
        }
        let (ke2, login) = external_access::login_start(cred, ke1).map_err(|e| match e {
            external_access::Error::Malformed => Refusal::Malformed,
            _ => Refusal::Unavailable,
        })?;
        // The debit — only now, because only now is a KE2 about to leave.
        g.guesses.push_back((now, attempt_id.to_owned()));
        g.pending.insert(
            attempt_id.to_owned(),
            Pending {
                login,
                principal: principal.to_owned(),
                started: now,
            },
        );
        Ok(ke2)
    }

    /// KE3 for `attempt_id`. On success the attempt's own guess is refunded
    /// and an [`AppKey`] is held for [`bind_session`](Self::bind_session).
    pub fn finish(
        &self,
        attempt_id: &str,
        principal: &str,
        ke3: &[u8],
        now: Instant,
    ) -> Result<(), Refusal> {
        let mut g = self.lock();
        g.prune(now);
        // Removed before anything else: whatever happens next, this attempt is
        // over. A KE3 cannot be retried against the same pending login.
        let pending = g
            .pending
            .remove(attempt_id)
            .ok_or(Refusal::UnknownAttempt)?;
        if pending.principal != principal {
            return Err(Refusal::PrincipalMismatch);
        }
        let session_key =
            external_access::login_finish(pending.login, ke3).map_err(|e| match e {
                external_access::Error::Malformed => Refusal::Malformed,
                _ => Refusal::Rejected,
            })?;
        // Refund THIS attempt's guess — not the streak (module docs, rule 3).
        if let Some(i) = g.guesses.iter().position(|(_, a)| a == attempt_id) {
            g.guesses.remove(i);
        }
        let key = derive_app_key(session_key.expose(), attempt_id, principal);
        // The master secret does not outlive the derivation.
        drop(session_key);
        if g.verified.len() >= TABLE_CAP {
            // Evict the oldest unconsumed grant rather than refuse a login that
            // just verified. Reaching this means 32 verified logins went unused
            // inside two minutes; the evicted holder logs in again.
            if let Some(oldest) = g
                .verified
                .iter()
                .min_by_key(|(_, v)| v.verified)
                .map(|(a, _)| a.clone())
            {
                g.verified.remove(&oldest);
            }
        }
        g.verified.insert(
            attempt_id.to_owned(),
            Verified {
                key,
                principal: principal.to_owned(),
                verified: now,
            },
        );
        Ok(())
    }

    /// P4 — admit `session_id` on the verified login `attempt_id` of
    /// `principal`, CONSUMING it: one verified login admits exactly one
    /// session. `false` = refuse the session.
    ///
    /// Refused: no such login (never verified, expired, already used, another
    /// principal's), a session id that already ended, or a full table. ⚠️ A
    /// full table REFUSES the newcomer rather than evicting a live binding —
    /// an evicted session would find no binding at its offer and be taken for
    /// an ordinary one, MAC-less.
    ///
    /// A `Request` re-pushed for a session already admitted on the SAME login
    /// is the same admission (`true`, nothing consumed); on any other login it
    /// is refused.
    ///
    /// The key moves into the binding and never comes back out: from here on a
    /// caller can only ask for a verdict on an offer and a seal for an answer.
    pub fn bind_session(
        &self,
        attempt_id: &str,
        principal: &str,
        session_id: &str,
        now: Instant,
    ) -> bool {
        if !well_formed_id(session_id) {
            return false;
        }
        let mut g = self.lock();
        g.prune(now);
        if let Some(bound) = g.sessions.get(session_id) {
            return bound.attempt_id == attempt_id && bound.principal == principal;
        }
        if g.is_ended(session_id) || g.sessions.len() >= TABLE_CAP {
            return false;
        }
        let Some(key) = g.take_verified(attempt_id, principal) else {
            return false;
        };
        g.sessions.insert(
            session_id.to_owned(),
            Bound {
                key,
                attempt_id: attempt_id.to_owned(),
                principal: principal.to_owned(),
                consented: false,
                offered: false,
                bound: now,
            },
        );
        true
    }

    /// P4 — this device granted consent for `session_id`. Called BEFORE the
    /// grant is sent, so the offer it unlocks cannot arrive first. `false` =
    /// no live binding (it ended meanwhile): send a refusal, not the grant.
    pub fn grant_consent(&self, session_id: &str) -> bool {
        match self.lock().sessions.get_mut(session_id) {
            Some(bound) => {
                bound.consented = true;
                true
            }
            None => false,
        }
    }

    /// P4 — admit `session_id`'s offer: consent granted HERE, the first offer,
    /// and a `mac` that authenticates its DTLS fingerprint under the login's
    /// key (constant-time). [`BindingError::NotBound`] = an ordinary session,
    /// the one answer on which the caller proceeds without a MAC.
    pub fn verify_offer(
        &self,
        session_id: &str,
        offer_sdp: &str,
        mac: Option<&str>,
        now: Instant,
    ) -> Result<(), BindingError> {
        use hmac::Mac as _;
        let mut g = self.lock();
        g.prune(now);
        if g.is_ended(session_id) {
            return Err(BindingError::Ended);
        }
        let bound = g
            .sessions
            .get_mut(session_id)
            .ok_or(BindingError::NotBound)?;
        if !bound.consented {
            return Err(BindingError::NotConsented);
        }
        if bound.offered {
            return Err(BindingError::AlreadyOffered);
        }
        let mac = mac.ok_or(BindingError::MissingMac)?;
        let fingerprint = sdp_fingerprint(offer_sdp)?;
        let tag = b64url().decode(mac).map_err(|_| BindingError::BadMac)?;
        transport_hmac(&bound.key, "offer", &fingerprint)
            .verify_slice(&tag)
            .map_err(|_| BindingError::BadMac)?;
        bound.offered = true;
        Ok(())
    }

    /// P4 — the MAC for `session_id`'s answer, over the device's own DTLS
    /// fingerprint. Sealing ENDS the binding: the key has done everything it
    /// is for, so it is dropped now rather than held for the session's
    /// lifetime, and the session id is remembered as ended.
    pub fn seal_answer(&self, session_id: &str, answer_sdp: &str) -> Result<String, BindingError> {
        let mut g = self.lock();
        if g.is_ended(session_id) {
            return Err(BindingError::Ended);
        }
        let bound = g.sessions.get(session_id).ok_or(BindingError::NotBound)?;
        if !bound.offered {
            return Err(BindingError::NotOffered);
        }
        let fingerprint = sdp_fingerprint(answer_sdp)?;
        let mac = b64url().encode(transport_mac(&bound.key, "answer", &fingerprint));
        g.retire(session_id);
        Ok(mac)
    }

    /// P4 — the session is over. Its key goes; its id is remembered. A no-op
    /// for a session that was never external.
    pub fn end_session(&self, session_id: &str) {
        self.lock().retire(session_id);
    }

    /// Consume a verified login outside a session — the P3 tests' view of it.
    /// Not callable elsewhere: outside the tests the key only ever moves into
    /// a binding.
    #[cfg(test)]
    pub(crate) fn take_verified(
        &self,
        attempt_id: &str,
        principal: &str,
        now: Instant,
    ) -> Option<AppKey> {
        let mut g = self.lock();
        g.prune(now);
        g.take_verified(attempt_id, principal)
    }

    /// Guesses currently counted against the device. For status and tests.
    pub fn answered_guesses(&self, now: Instant) -> usize {
        let mut g = self.lock();
        g.prune(now);
        g.guesses.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_access::{Suite, set_password};
    use opaque_ke::{ClientLogin, ClientLoginFinishParameters, CredentialResponse};
    use rand_opaque::rngs::OsRng;

    /// Built, never written — a secret scanner cannot tell a KDF input in a
    /// test from a leaked credential.
    fn pw(tag: &str) -> String {
        format!("fr52-not-a-credential-{tag}")
    }

    const WHO: &str = "665f1c2a9b3e4d5f6a7b8c9d";

    fn cred(tag: &str) -> Credential {
        set_password(None, &pw(tag)).unwrap().0
    }

    /// A client's KE1, plus the state to finish it with.
    fn ke1(password: &str) -> (ClientLogin<Suite>, Vec<u8>) {
        let started = ClientLogin::<Suite>::start(&mut OsRng, password.as_bytes()).unwrap();
        let bytes = started.message.serialize().to_vec();
        (started.state, bytes)
    }

    /// Finish a client login against a KE2 — `None` when the client refuses at
    /// KE2, which is what a wrong password looks like from the client's side.
    fn ke3(state: ClientLogin<Suite>, password: &str, ke2: &[u8]) -> Option<Vec<u8>> {
        state
            .finish(
                &mut OsRng,
                password.as_bytes(),
                CredentialResponse::<Suite>::deserialize(ke2).ok()?,
                ClientLoginFinishParameters::default(),
            )
            .ok()
            .map(|done| done.message.serialize().to_vec())
    }

    fn attempt(n: usize) -> String {
        format!("attempt-{n:04}")
    }

    /// The application key reproduces a vector from an INDEPENDENT HKDF.
    ///
    /// The expected bytes were computed with Node 24's `crypto.hkdfSync("sha512",
    /// ikm = 00..3f, salt = empty, info, 32)`, where `info` is the label and the
    /// two length-prefixed fields below. P4's page derives the same key with
    /// WebCrypto; this pins the label, the field order, the length prefixes, the
    /// hash and the output length in one assertion.
    #[test]
    fn the_app_key_matches_an_independent_hkdf() {
        let ikm: Vec<u8> = (0u8..64).collect();
        let key = derive_app_key(&ikm, "a1b2c3d4e5f60718293a4b5c6d7e8f90", WHO);
        let hex: String = key.expose().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, "7718aa60e955c361d08a866cc97778ce06006d767a0d0d5503510b98cde651e5",
            "the app key no longer matches what the browser will derive"
        );
    }

    /// Length prefixes, not separators: moving bytes between the two fields
    /// must change the key.
    #[test]
    fn the_fields_cannot_be_shifted_into_each_other() {
        let ikm = [7u8; 64];
        let a = derive_app_key(&ikm, "ab", "cd");
        let b = derive_app_key(&ikm, "a", "bcd");
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn a_correct_login_verifies_refunds_its_guess_and_leaves_a_single_use_key() {
        let logins = ExternalLogins::new();
        let cred = cred("right");
        let t0 = Instant::now();

        let (state, k1) = ke1(&pw("right"));
        let k2 = logins.begin(&attempt(1), WHO, &cred, &k1, t0).unwrap();
        assert_eq!(logins.answered_guesses(t0), 1, "a KE2 left the device");

        let k3 = ke3(state, &pw("right"), &k2).expect("the right password opens KE2");
        logins.finish(&attempt(1), WHO, &k3, t0).unwrap();
        assert_eq!(
            logins.answered_guesses(t0),
            0,
            "a verified login refunds its guess"
        );

        assert!(logins.take_verified(&attempt(1), WHO, t0).is_some());
        assert!(
            logins.take_verified(&attempt(1), WHO, t0).is_none(),
            "a verified login authorizes exactly one session offer"
        );
    }

    /// The rule the whole module exists for: a client that never sends KE3 —
    /// which is what a guessing client does — still costs a guess, and keeps
    /// costing it after its pending login has expired.
    #[test]
    fn an_abandoned_login_still_costs_a_guess() {
        let logins = ExternalLogins::new();
        let cred = cred("right");
        let t0 = Instant::now();

        let (state, k1) = ke1(&pw("wrong"));
        let k2 = logins.begin(&attempt(1), WHO, &cred, &k1, t0).unwrap();
        assert!(ke3(state, &pw("wrong"), &k2).is_none(), "refused at KE2");
        // The client stops here. No finish(), ever.

        let later = t0 + PENDING_TTL + Duration::from_secs(1);
        assert_eq!(
            logins.answered_guesses(later),
            1,
            "an abandoned login is an answered guess — counting only failed KE3s counts nothing"
        );
    }

    /// Five free, then the sixth waits — and while it waits, NOTHING is
    /// answered and nothing more is debited.
    #[test]
    fn an_exhausted_budget_answers_nothing() {
        let logins = ExternalLogins::new();
        let cred = cred("right");
        let t0 = Instant::now();

        for n in 0..FREE_GUESSES {
            let (_, k1) = ke1(&pw("wrong"));
            logins.begin(&attempt(n), WHO, &cred, &k1, t0).unwrap();
        }
        let (_, k1) = ke1(&pw("wrong"));
        assert_eq!(
            logins.begin(&attempt(99), WHO, &cred, &k1, t0),
            Err(Refusal::Throttled {
                retry_after: BACKOFF_BASE
            })
        );
        assert_eq!(
            logins.answered_guesses(t0),
            FREE_GUESSES,
            "a refusal is not a debit"
        );

        // Even the RIGHT password waits — the device cannot tell them apart
        // until it has answered, and answering is the thing being rationed.
        let (_, k1) = ke1(&pw("right"));
        assert!(matches!(
            logins.begin(&attempt(98), WHO, &cred, &k1, t0),
            Err(Refusal::Throttled { .. })
        ));
    }

    /// The delay doubles per answered guess and stops at the cap.
    #[test]
    fn the_backoff_doubles_and_stops_at_the_cap() {
        let logins = ExternalLogins::new();
        let cred = cred("right");
        let mut now = Instant::now();

        for n in 0..FREE_GUESSES {
            let (_, k1) = ke1(&pw("wrong"));
            logins.begin(&attempt(n), WHO, &cred, &k1, now).unwrap();
        }
        let mut expected = BACKOFF_BASE;
        for n in FREE_GUESSES..FREE_GUESSES + 10 {
            let (_, k1) = ke1(&pw("wrong"));
            match logins.begin(&attempt(n), WHO, &cred, &k1, now) {
                Err(Refusal::Throttled { retry_after }) => assert_eq!(retry_after, expected),
                other => panic!("guess {n}: expected a {expected:?} wait, got {other:?}"),
            }
            now += expected;
            logins.begin(&attempt(n), WHO, &cred, &k1, now).unwrap();
            expected = (expected * 2).min(BACKOFF_MAX);
        }
        assert_eq!(
            expected, BACKOFF_MAX,
            "ten doublings from 30 s must reach the cap"
        );
    }

    /// A success refunds ITS OWN guess. Resetting the streak instead would hand
    /// an attacker a fresh budget each time the legitimate outsider logged in.
    #[test]
    fn a_success_refunds_its_own_guess_not_the_streak() {
        let logins = ExternalLogins::new();
        let cred = cred("right");
        let t0 = Instant::now();

        for n in 0..3 {
            let (_, k1) = ke1(&pw("wrong"));
            logins.begin(&attempt(n), WHO, &cred, &k1, t0).unwrap();
        }
        let (state, k1) = ke1(&pw("right"));
        let k2 = logins.begin(&attempt(10), WHO, &cred, &k1, t0).unwrap();
        logins
            .finish(
                &attempt(10),
                WHO,
                &ke3(state, &pw("right"), &k2).unwrap(),
                t0,
            )
            .unwrap();
        assert_eq!(
            logins.answered_guesses(t0),
            3,
            "the three wrong guesses still count after a successful login"
        );
    }

    #[test]
    fn guesses_age_out_of_the_window() {
        let logins = ExternalLogins::new();
        let cred = cred("right");
        let t0 = Instant::now();
        for n in 0..FREE_GUESSES {
            let (_, k1) = ke1(&pw("wrong"));
            logins.begin(&attempt(n), WHO, &cred, &k1, t0).unwrap();
        }
        let next_day = t0 + GUESS_WINDOW + Duration::from_secs(1);
        assert_eq!(logins.answered_guesses(next_day), 0);
        let (_, k1) = ke1(&pw("right"));
        assert!(
            logins
                .begin(&attempt(50), WHO, &cred, &k1, next_day)
                .is_ok()
        );
    }

    /// Rule 1: the check and the debit are ONE critical section. Sixteen
    /// threads release together; exactly the free budget may be answered. A
    /// check-then-release-then-debit refactor lets most of them through.
    #[test]
    fn a_burst_cannot_outrun_the_debit() {
        let logins = ExternalLogins::new();
        let cred = cred("right");
        let t0 = Instant::now();
        let requests: Vec<Vec<u8>> = (0..16).map(|_| ke1(&pw("wrong")).1).collect();
        let barrier = std::sync::Barrier::new(requests.len());

        let answered = std::thread::scope(|s| {
            let handles: Vec<_> = requests
                .iter()
                .enumerate()
                .map(|(n, k1)| {
                    let (logins, cred, barrier) = (&logins, &cred, &barrier);
                    s.spawn(move || {
                        barrier.wait();
                        logins.begin(&attempt(n), WHO, cred, k1, t0).is_ok()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|ok| *ok)
                .count()
        });
        assert_eq!(
            answered, FREE_GUESSES,
            "a burst was answered past the budget"
        );
        assert_eq!(logins.answered_guesses(t0), FREE_GUESSES);
    }

    /// A KE3 that is well-formed but belongs to a different login is REJECTED,
    /// and the guess stays counted.
    #[test]
    fn a_ke3_that_does_not_verify_is_rejected_and_stays_counted() {
        let logins = ExternalLogins::new();
        let cred = cred("right");
        let t0 = Instant::now();

        let (_state_a, k1a) = ke1(&pw("right"));
        logins.begin(&attempt(1), WHO, &cred, &k1a, t0).unwrap();
        // A second, complete login elsewhere gives us a genuine KE3 that is
        // simply not THIS login's.
        let (state_b, k1b) = ke1(&pw("right"));
        let k2b = logins.begin(&attempt(2), WHO, &cred, &k1b, t0).unwrap();
        let k3b = ke3(state_b, &pw("right"), &k2b).unwrap();

        assert_eq!(
            logins.finish(&attempt(1), WHO, &k3b, t0),
            Err(Refusal::Rejected)
        );
        assert_eq!(
            logins.answered_guesses(t0),
            2,
            "a rejected KE3 refunds nothing"
        );
        assert_eq!(
            logins.finish(&attempt(1), WHO, &k3b, t0),
            Err(Refusal::UnknownAttempt),
            "an attempt is over after its first KE3, whatever it said"
        );
    }

    #[test]
    fn a_ke3_attributed_to_another_principal_is_refused() {
        let logins = ExternalLogins::new();
        let cred = cred("right");
        let t0 = Instant::now();
        let (state, k1) = ke1(&pw("right"));
        let k2 = logins.begin(&attempt(1), WHO, &cred, &k1, t0).unwrap();
        let k3 = ke3(state, &pw("right"), &k2).unwrap();
        assert_eq!(
            logins.finish(&attempt(1), "000000000000000000000000", &k3, t0),
            Err(Refusal::PrincipalMismatch)
        );
        assert_eq!(logins.answered_guesses(t0), 1);
    }

    /// Single-use, principal-bound, and it expires.
    #[test]
    fn a_verified_login_is_bound_to_its_principal_and_expires() {
        let logins = ExternalLogins::new();
        let cred = cred("right");
        let t0 = Instant::now();
        for (n, when) in [(1, t0), (2, t0)] {
            let (state, k1) = ke1(&pw("right"));
            let k2 = logins.begin(&attempt(n), WHO, &cred, &k1, when).unwrap();
            logins
                .finish(
                    &attempt(n),
                    WHO,
                    &ke3(state, &pw("right"), &k2).unwrap(),
                    when,
                )
                .unwrap();
        }
        assert!(
            logins
                .take_verified(&attempt(1), "000000000000000000000000", t0)
                .is_none()
        );
        assert!(
            logins.take_verified(&attempt(1), WHO, t0).is_some(),
            "a wrong principal must not burn the rightful holder's grant"
        );
        let expired = t0 + VERIFIED_TTL + Duration::from_secs(1);
        assert!(logins.take_verified(&attempt(2), WHO, expired).is_none());
    }

    /// Refusals that answer nothing debit nothing.
    #[test]
    fn a_refusal_before_the_answer_is_never_debited() {
        let logins = ExternalLogins::new();
        let cred = cred("right");
        let t0 = Instant::now();

        assert_eq!(
            logins.begin(&attempt(1), WHO, &cred, b"not a KE1", t0),
            Err(Refusal::Malformed)
        );
        let (_, k1) = ke1(&pw("right"));
        for (id, who) in [
            ("", WHO),
            ("has a space", WHO),
            (&"x".repeat(MAX_ID_LEN + 1)[..], WHO),
            ("ok", "nul\0inside"),
        ] {
            assert_eq!(
                logins.begin(id, who, &cred, &k1, t0),
                Err(Refusal::BadIdentifier),
                "{id:?} / {who:?}"
            );
        }
        let corrupt = Credential {
            setup: "!!".into(),
            verifier: "!!".into(),
        };
        assert_eq!(
            logins.begin(&attempt(2), WHO, &corrupt, &k1, t0),
            Err(Refusal::Unavailable)
        );
        assert_eq!(logins.answered_guesses(t0), 0);
    }

    /// An attempt id cannot be reused while its first use is live — a second
    /// KE1 under the same id would otherwise replace the pending login.
    #[test]
    fn an_attempt_id_is_not_reusable_while_live() {
        let logins = ExternalLogins::new();
        let cred = cred("right");
        let t0 = Instant::now();
        let (_, k1) = ke1(&pw("right"));
        logins.begin(&attempt(1), WHO, &cred, &k1, t0).unwrap();
        let (_, k1) = ke1(&pw("right"));
        assert_eq!(
            logins.begin(&attempt(1), WHO, &cred, &k1, t0),
            Err(Refusal::BadIdentifier)
        );
    }

    #[test]
    fn an_app_key_never_prints_itself() {
        let key = AppKey([0xCD; 32]);
        let printed = format!("{key:?}");
        assert!(!printed.to_lowercase().contains("cd"), "{printed}");
        assert!(!printed.contains("205"), "{printed}");
    }

    // ─── P4: an external session's transport, bound to its login ───────────

    const FP: &str = "sha-256 4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:3C:5F:03:24:5E:E5:66:1C:20:D2:28:A8";
    /// Another certificate: the device's own, or an interloper's.
    const OTHER_FP: &str = "sha-256 11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00";
    const SESSION: &str = "66f0c0ffee0000000000000a";

    /// A two-line SDP skeleton with one `a=fingerprint:` per m-section.
    fn sdp_with(fingerprints: &[&str]) -> String {
        let mut sdp = String::from("v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n");
        for (mid, fp) in fingerprints.iter().enumerate() {
            sdp.push_str(&format!(
                "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=mid:{mid}\r\na=fingerprint:{fp}\r\n"
            ));
        }
        sdp
    }

    fn mac(key: [u8; 32], role: &str, fingerprint: &str) -> String {
        b64url().encode(transport_mac(&AppKey(key), role, fingerprint))
    }

    /// A verified login with a KNOWN key, without running OPAQUE: these tests
    /// are about what happens after verification. The real login's hand-off
    /// is `a_real_login_binds_the_session_to_the_key_the_client_derives`.
    fn verified_with(logins: &ExternalLogins, attempt_id: &str, key: [u8; 32], now: Instant) {
        logins.lock().verified.insert(
            attempt_id.to_owned(),
            Verified {
                key: AppKey(key),
                principal: WHO.to_owned(),
                verified: now,
            },
        );
    }

    /// The MAC reproduces a vector from an INDEPENDENT HMAC: Node 24's
    /// `crypto.createHmac("sha256", key = 00..1f)` over the label and the two
    /// length-prefixed fields. The browser computes the same bytes with
    /// WebCrypto, so this pins the label, the role spellings, the prefixes and
    /// the encoding in one place.
    #[test]
    fn the_transport_mac_matches_an_independent_hmac() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(
            mac(key, "offer", FP),
            "9C7Hj7E39lXWd1VP-ttMoR3G39CrYJLXbaNjkGJ4W5w"
        );
        assert_eq!(
            mac(key, "answer", FP),
            "dvUftw510jDyQn0j9c6XslWOoB19z-QTW3FUgUCz6rY"
        );
    }

    #[test]
    fn a_fingerprint_is_normalised_and_must_name_one_certificate() {
        // One certificate, announced per m-section in two spellings.
        let (hash, hex) = FP.split_once(' ').unwrap();
        let shouted = format!("{} {}", hash.to_ascii_uppercase(), hex.to_ascii_lowercase());
        assert_eq!(
            sdp_fingerprint(&sdp_with(&[&shouted, FP])),
            Ok(FP.to_string())
        );
        assert_eq!(
            sdp_fingerprint(&sdp_with(&[FP, OTHER_FP])),
            Err(BindingError::AmbiguousFingerprint),
            "two certificates: the MAC could cover one while DTLS uses the other"
        );
        assert_eq!(
            sdp_fingerprint(&sdp_with(&[])),
            Err(BindingError::NoFingerprint)
        );
        for malformed in ["sha-256", "sha-256 AA:BB trailing"] {
            assert_eq!(
                sdp_fingerprint(&sdp_with(&[malformed])),
                Err(BindingError::AmbiguousFingerprint),
                "{malformed:?}"
            );
        }
    }

    /// The whole life of an external session: no offer before this device's
    /// consent, exactly one offer, and only under the login's key and over the
    /// offer's own certificate; then one sealed answer, after which the key is
    /// gone and the session id is remembered.
    #[test]
    fn an_external_session_takes_one_offer_after_consent_and_seals_one_answer() {
        let logins = ExternalLogins::new();
        let t0 = Instant::now();
        let key = [7u8; 32];
        verified_with(&logins, &attempt(1), key, t0);
        assert!(logins.bind_session(&attempt(1), WHO, SESSION, t0));
        let offer = sdp_with(&[FP]);
        let good = mac(key, "offer", FP);

        assert_eq!(
            logins.verify_offer(SESSION, &offer, Some(&good), t0),
            Err(BindingError::NotConsented),
            "gate 5 is this device's: no offer before it consents"
        );
        assert_eq!(
            logins.seal_answer(SESSION, &offer),
            Err(BindingError::NotOffered)
        );
        assert!(logins.grant_consent(SESSION));
        assert_eq!(
            logins.verify_offer(SESSION, &offer, None, t0),
            Err(BindingError::MissingMac)
        );
        for bad in [
            mac(key, "answer", FP),       // the other role's tag
            mac([8u8; 32], "offer", FP),  // a key from another login
            "not base64url!".to_string(), // not a tag at all
        ] {
            assert_eq!(
                logins.verify_offer(SESSION, &offer, Some(&bad), t0),
                Err(BindingError::BadMac),
                "{bad}"
            );
        }
        assert_eq!(
            logins.verify_offer(SESSION, &sdp_with(&[OTHER_FP]), Some(&good), t0),
            Err(BindingError::BadMac),
            "a genuine tag over ANOTHER certificate: the offer was swapped in transit"
        );
        logins
            .verify_offer(SESSION, &offer, Some(&good), t0)
            .expect("the login's own offer");
        assert_eq!(
            logins.verify_offer(SESSION, &offer, Some(&good), t0),
            Err(BindingError::AlreadyOffered),
            "exactly one offer"
        );

        let answer = sdp_with(&[OTHER_FP]);
        assert_eq!(
            logins.seal_answer(SESSION, &answer),
            Ok(mac(key, "answer", OTHER_FP)),
            "the seal covers the DEVICE's certificate, under the same key"
        );
        assert_eq!(
            logins.seal_answer(SESSION, &answer),
            Err(BindingError::Ended)
        );
        assert_eq!(
            logins.verify_offer(SESSION, &offer, Some(&good), t0),
            Err(BindingError::Ended),
            "a later offer is refused — never taken for an ordinary session's"
        );
    }

    #[test]
    fn a_session_nobody_bound_is_ordinary_and_stays_ordinary() {
        let logins = ExternalLogins::new();
        let t0 = Instant::now();
        let offer = sdp_with(&[FP]);
        assert_eq!(
            logins.verify_offer(SESSION, &offer, None, t0),
            Err(BindingError::NotBound)
        );
        assert_eq!(
            logins.seal_answer(SESSION, &offer),
            Err(BindingError::NotBound)
        );
        assert!(!logins.grant_consent(SESSION));
        logins.end_session(SESSION);
        assert_eq!(
            logins.verify_offer(SESSION, &offer, None, t0),
            Err(BindingError::NotBound),
            "ending an ordinary session records nothing"
        );
    }

    #[test]
    fn a_verified_login_admits_one_session_and_a_repush_is_the_same_admission() {
        let logins = ExternalLogins::new();
        let t0 = Instant::now();
        let second = "66f0c0ffee0000000000000b";
        verified_with(&logins, &attempt(1), [1u8; 32], t0);
        verified_with(&logins, &attempt(2), [2u8; 32], t0);
        assert!(
            !logins.bind_session(&attempt(1), "000000000000000000000000", SESSION, t0),
            "another principal's login"
        );
        assert!(logins.bind_session(&attempt(1), WHO, SESSION, t0));
        assert!(
            logins.bind_session(&attempt(1), WHO, SESSION, t0),
            "the server re-pushed the Request after the agent's socket flapped"
        );
        assert!(
            !logins.bind_session(&attempt(2), WHO, SESSION, t0),
            "a second login cannot re-admit an admitted session"
        );
        assert!(
            !logins.bind_session(&attempt(1), WHO, second, t0),
            "one login, one session"
        );
        assert!(
            logins.bind_session(&attempt(2), WHO, second, t0),
            "the refused re-admission did not burn login 2"
        );
    }

    #[test]
    fn an_ended_session_is_never_admitted_again() {
        let logins = ExternalLogins::new();
        let t0 = Instant::now();
        verified_with(&logins, &attempt(1), [1u8; 32], t0);
        verified_with(&logins, &attempt(2), [2u8; 32], t0);
        assert!(logins.bind_session(&attempt(1), WHO, SESSION, t0));
        logins.end_session(SESSION);
        assert!(
            !logins.grant_consent(SESSION),
            "a consent that raced the end"
        );
        assert!(!logins.bind_session(&attempt(2), WHO, SESSION, t0));
        assert_eq!(
            logins.verify_offer(SESSION, &sdp_with(&[FP]), None, t0),
            Err(BindingError::Ended)
        );
    }

    /// ⚠️ Refuse, never evict: an evicted binding would find nothing at its
    /// offer and be taken for an ordinary session, MAC-less.
    #[test]
    fn a_full_table_refuses_the_newcomer_and_evicts_nobody() {
        let logins = ExternalLogins::new();
        let t0 = Instant::now();
        let sid = |n: usize| format!("66f0c0ffee{n:014}");
        for n in 0..TABLE_CAP {
            verified_with(&logins, &attempt(n), [n as u8; 32], t0);
            assert!(logins.bind_session(&attempt(n), WHO, &sid(n), t0));
        }
        verified_with(&logins, &attempt(99), [99; 32], t0);
        assert!(!logins.bind_session(&attempt(99), WHO, &sid(99), t0));
        for n in 0..TABLE_CAP {
            assert!(
                logins.grant_consent(&sid(n)),
                "session {n} lost its binding"
            );
        }
    }

    #[test]
    fn an_unanswered_binding_ages_out_as_ended() {
        let logins = ExternalLogins::new();
        let t0 = Instant::now();
        let key = [1u8; 32];
        verified_with(&logins, &attempt(1), key, t0);
        assert!(logins.bind_session(&attempt(1), WHO, SESSION, t0));
        assert!(logins.grant_consent(SESSION));
        let later = t0 + BINDING_TTL + Duration::from_secs(1);
        assert_eq!(
            logins.verify_offer(
                SESSION,
                &sdp_with(&[FP]),
                Some(&mac(key, "offer", FP)),
                later
            ),
            Err(BindingError::Ended)
        );
    }

    /// P3 → P4 end to end: a REAL login binds the session to the key the
    /// CLIENT derives from its own OPAQUE session key — the one the browser
    /// will seal its offer with.
    #[test]
    fn a_real_login_binds_the_session_to_the_key_the_client_derives() {
        let logins = ExternalLogins::new();
        let cred = cred("right");
        let t0 = Instant::now();
        let (state, k1) = ke1(&pw("right"));
        let k2 = logins.begin(&attempt(1), WHO, &cred, &k1, t0).unwrap();
        let done = state
            .finish(
                &mut OsRng,
                pw("right").as_bytes(),
                CredentialResponse::<Suite>::deserialize(&k2).unwrap(),
                ClientLoginFinishParameters::default(),
            )
            .unwrap();
        logins
            .finish(&attempt(1), WHO, &done.message.serialize(), t0)
            .unwrap();
        let clients_key = derive_app_key(&done.session_key, &attempt(1), WHO);

        assert!(logins.bind_session(&attempt(1), WHO, SESSION, t0));
        assert!(
            logins.take_verified(&attempt(1), WHO, t0).is_none(),
            "binding consumed the login"
        );
        assert!(logins.grant_consent(SESSION));
        logins
            .verify_offer(
                SESSION,
                &sdp_with(&[FP]),
                Some(&mac(*clients_key.expose(), "offer", FP)),
                t0,
            )
            .expect("the device and the client derive the same key");
    }
}
