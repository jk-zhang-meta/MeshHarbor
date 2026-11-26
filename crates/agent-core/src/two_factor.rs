//! FR-129 — a device that asks for a code: TOTP two-factor, kept and checked by the device.
//!
//! With two-factor on, every way in that a person opens (remote desktop, `mh ssh`, `mh exec`)
//! must carry a 6-digit code from an authenticator app (RFC 6238: HMAC-SHA1, 30 s steps, 6
//! digits; what Microsoft and Google Authenticator both implement). The secret lives in
//! `two-factor.json` beside the daemon's config, never in `AgentConfig`: it is in no
//! `DesiredConfig`, no config report, no `mh config` output and no log line. The centre only
//! relays codes, so a stolen admin session or a compromised centre can neither compute one nor
//! switch two-factor off.
//!
//! - A code is used once: a step at or before the last accepted one is refused, so a code seen on
//!   its way through the centre cannot be replayed. Current step ±1 is accepted (clock skew).
//! - Five wrong codes lock checking for 1 min, doubling up to 15 min.
//! - Ten one-time recovery codes stand in for a lost phone; only their SHA-256 is kept.
//! - The file's presence is the switch (`active`): `meshharbord two-factor reset` (local, as
//!   the daemon's own user) removes it. A file that exists but cannot be read refuses every
//!   code, never falls back to "off".

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// The state file, beside the daemon's config.
pub const FILE: &str = "two-factor.json";
/// The issuer an authenticator app shows above the code.
pub const ISSUER: &str = "MeshHarbor";
const STEP_SECS: u64 = 30;
const SECRET_LEN: usize = 20;
const RECOVERY_CODES: usize = 10;
/// A `begin` stays confirmable this long.
const PENDING: Duration = Duration::from_secs(600);
const MAX_FAILURES: u32 = 5;
const FIRST_LOCK: Duration = Duration::from_secs(60);
const MAX_LOCK: Duration = Duration::from_secs(900);
/// Wrong 6-digit codes in a row after which only a recovery code (or a local reset) gets in:
/// without a cap, a patient guesser at 5 per 15 min wins about once in three years per device.
const HARD_CAP: u32 = 100;
/// How long a session this device admitted stays known (its offers and a replayed request).
const ADMITTED_FOR: Duration = Duration::from_secs(12 * 3600);
/// Recovery codes use no look-alike characters (no 0/o, 1/l/i).
const RECOVERY_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";

/// Why a code was not accepted. The wire spellings are a compatibility surface: a controller
/// matches on them to ask the person for a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No code came with the request.
    Required,
    /// The code is wrong, expired, or already used.
    Invalid,
    /// Too many wrong codes; checking resumes after the given seconds.
    Locked(u64),
    /// So many wrong codes in a row that 6-digit codes are refused until a recovery code is
    /// used (or a local reset). Same wire word as `Locked`.
    Blocked,
    /// The state file exists but cannot be read: every code is refused.
    Unavailable,
}

impl Refusal {
    pub fn wire(self) -> &'static str {
        match self {
            Refusal::Required => "two_factor_required",
            Refusal::Invalid => "two_factor_invalid",
            Refusal::Locked(_) | Refusal::Blocked => "two_factor_locked",
            Refusal::Unavailable => "two_factor_unavailable",
        }
    }

    /// Words for the person, next to the wire spelling.
    pub fn message(self) -> String {
        match self {
            Refusal::Required => "this device asks for a two-factor code".into(),
            Refusal::Invalid => "the two-factor code is wrong, expired or already used".into(),
            Refusal::Locked(s) => format!("too many wrong two-factor codes; try again in {s} s"),
            Refusal::Blocked => "too many wrong two-factor codes: only a recovery code (or a \
                                 local `meshharbord two-factor reset`) works now"
                .into(),
            Refusal::Unavailable => "the device cannot read its two-factor state".into(),
        }
    }
}

/// Why a setup step (`begin` / `confirm` / `disable`) was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupRefusal {
    /// `begin` on a device that already has it: `disable` first (which needs a code).
    AlreadyOn,
    /// `disable` on a device that does not have it.
    AlreadyOff,
    /// `confirm` with no `begin` in the last 10 min.
    NoPending,
    /// The code did not check out.
    Code(Refusal),
    /// The state could not be written.
    Storage(String),
}

impl SetupRefusal {
    pub fn wire(&self) -> &'static str {
        match self {
            SetupRefusal::AlreadyOn => "already_on",
            SetupRefusal::AlreadyOff => "already_off",
            SetupRefusal::NoPending => "no_pending",
            SetupRefusal::Code(r) => r.wire(),
            SetupRefusal::Storage(_) => "storage",
        }
    }
}

/// What `begin` hands to the admin page: the key to type in, and the URI the QR code carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Begun {
    pub secret: String,
    pub otpauth_uri: String,
    /// What `confirm` must carry: a `begin` from anyone else in between replaces the pending
    /// secret, and this page's confirm then fails visibly instead of switching on a secret
    /// someone else holds.
    pub setup_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Stored {
    v: u32,
    /// The secret, hex.
    secret: String,
    /// Unix seconds two-factor was switched on.
    enabled_at: u64,
    /// The last accepted time step (replay guard).
    last_step: u64,
    /// SHA-256 (hex) of each unused recovery code.
    recovery: Vec<String>,
    /// Wrong 6-digit codes in a row (kept, so a restart does not reset the lock).
    #[serde(default)]
    fails: u32,
    /// Unix seconds until which codes are not checked.
    #[serde(default)]
    locked_until: u64,
    /// The next lock's length, seconds (0 = the first).
    #[serde(default)]
    next_lock: u64,
}

enum Loaded {
    Off,
    On(Stored),
    Unreadable,
}

/// The device's two-factor state: the file, plus what lives only in memory (a pending secret, the
/// wrong-code count and lock).
pub struct Engine {
    path: PathBuf,
    /// `begin`'s secret, its setup id, and until when it may be confirmed.
    pending: Option<(Vec<u8>, String, Instant)>,
    // A wrong `confirm` (no file yet) is counted here.
    failures: u32,
    locked_until: Option<Instant>,
    next_lock: Duration,
    /// The file's replay guard and lock, mirrored: a write that failed (a full disk) still
    /// leaves a used code used and a lock locked, in this process.
    mem_last_step: u64,
    mem_fails: u32,
    mem_locked_until: u64,
}

impl Engine {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            pending: None,
            failures: 0,
            locked_until: None,
            next_lock: FIRST_LOCK,
            mem_last_step: 0,
            mem_fails: 0,
            mem_locked_until: 0,
        }
    }

    /// The file's presence is the switch. A file that cannot even be checked counts as there
    /// (closed), never as off.
    pub fn active(&self) -> bool {
        self.path.try_exists().unwrap_or(true)
    }

    fn load(&self) -> Loaded {
        match std::fs::read(&self.path) {
            Ok(b) => match serde_json::from_slice::<Stored>(&b) {
                Ok(s) if hex::decode(&s.secret).is_ok_and(|k| !k.is_empty()) => Loaded::On(s),
                _ => Loaded::Unreadable,
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Loaded::Off,
            Err(_) => Loaded::Unreadable,
        }
    }

    fn locked(&mut self, now: Instant) -> Option<Refusal> {
        match self.locked_until {
            Some(t) if now < t => Some(Refusal::Locked((t - now).as_secs().max(1))),
            Some(_) => {
                self.locked_until = None;
                None
            }
            None => None,
        }
    }

    fn fail(&mut self, now: Instant) -> Refusal {
        self.failures += 1;
        if self.failures >= MAX_FAILURES {
            self.failures = 0;
            let lock = self.next_lock;
            self.locked_until = Some(now + lock);
            self.next_lock = (lock * 2).min(MAX_LOCK);
            tracing::warn!(
                secs = lock.as_secs(),
                "two-factor: too many wrong codes; checking is locked"
            );
            return Refusal::Locked(lock.as_secs());
        }
        Refusal::Invalid
    }

    fn succeed(&mut self) {
        self.failures = 0;
        self.next_lock = FIRST_LOCK;
    }

    /// Keep the state; the in-memory mirror holds even when the write fails.
    fn keep(&mut self, stored: &Stored, what: &str) {
        self.mem_last_step = self.mem_last_step.max(stored.last_step);
        self.mem_fails = stored.fails;
        self.mem_locked_until = stored.locked_until;
        if let Err(e) = write_state(&self.path, stored) {
            tracing::warn!(error = %e, what, "two-factor: could not keep the state");
        }
    }

    /// Check the code a request carried. `Ok` when two-factor is off.
    ///
    /// A recovery code is accepted even while 6-digit codes are locked (it is high-entropy,
    /// and it is how the owner gets past a lock a guesser caused); it resets the lock.
    pub fn check(&mut self, code: Option<&str>, unix: u64) -> Result<(), Refusal> {
        let mut stored = match self.load() {
            Loaded::Off => return Ok(()),
            Loaded::Unreadable => return Err(Refusal::Unavailable),
            Loaded::On(s) => s,
        };
        let Some(code) = code.map(normalize).filter(|c| !c.is_empty()) else {
            return Err(Refusal::Required);
        };
        if let Some(i) = recovery_index(&stored.recovery, &code) {
            stored.recovery.remove(i);
            stored.fails = 0;
            stored.locked_until = 0;
            stored.next_lock = 0;
            tracing::info!(
                left = stored.recovery.len(),
                "two-factor: a recovery code was used"
            );
            self.keep(&stored, "a used recovery code");
            return Ok(());
        }
        // The file's lock and the mirror's, whichever is further along.
        stored.fails = stored.fails.max(self.mem_fails);
        stored.locked_until = stored.locked_until.max(self.mem_locked_until);
        if stored.fails >= HARD_CAP {
            return Err(Refusal::Blocked);
        }
        if stored.locked_until > unix {
            return Err(Refusal::Locked(stored.locked_until - unix));
        }
        let secret = hex::decode(&stored.secret).map_err(|_| Refusal::Unavailable)?;
        let last = stored.last_step.max(self.mem_last_step);
        if let Some(step) = totp_step(&secret, &code, unix, last) {
            stored.last_step = step;
            stored.fails = 0;
            stored.locked_until = 0;
            stored.next_lock = 0;
            self.keep(&stored, "a used code");
            return Ok(());
        }
        stored.fails += 1;
        let verdict = if stored.fails >= HARD_CAP {
            tracing::warn!(
                fails = stored.fails,
                "two-factor: too many wrong codes in a row; only a recovery code works now"
            );
            Refusal::Blocked
        } else if stored.fails.is_multiple_of(MAX_FAILURES) {
            let lock = if stored.next_lock == 0 {
                FIRST_LOCK.as_secs()
            } else {
                stored.next_lock
            };
            stored.locked_until = unix + lock;
            stored.next_lock = (lock * 2).min(MAX_LOCK.as_secs());
            tracing::warn!(
                secs = lock,
                "two-factor: too many wrong codes; checking is locked"
            );
            Refusal::Locked(lock)
        } else {
            Refusal::Invalid
        };
        self.keep(&stored, "a wrong code");
        Err(verdict)
    }

    /// Start switching on: a fresh secret, confirmable for 10 min. `account` is what the app
    /// shows under the issuer (the device's name).
    pub fn begin(&mut self, account: &str, now: Instant) -> Result<Begun, SetupRefusal> {
        if self.active() {
            return Err(SetupRefusal::AlreadyOn);
        }
        let mut secret = vec![0u8; SECRET_LEN];
        rand::fill(&mut secret[..]);
        let mut id = [0u8; 16];
        rand::fill(&mut id[..]);
        let setup_id = hex::encode(id);
        let b32 = base32(&secret);
        let uri = otpauth_uri(account, &b32);
        self.pending = Some((secret, setup_id.clone(), now + PENDING));
        Ok(Begun {
            secret: b32,
            otpauth_uri: uri,
            setup_id,
        })
    }

    /// Finish switching on with a code from the app; answers the recovery codes (shown once).
    pub fn confirm(
        &mut self,
        code: &str,
        setup_id: &str,
        unix: u64,
        now: Instant,
    ) -> Result<Vec<String>, SetupRefusal> {
        if self.active() {
            return Err(SetupRefusal::AlreadyOn);
        }
        let Some((secret, id, until)) = self.pending.clone() else {
            return Err(SetupRefusal::NoPending);
        };
        if now >= until {
            self.pending = None;
            return Err(SetupRefusal::NoPending);
        }
        if id != setup_id {
            tracing::warn!("two-factor: a confirm for a setup that is no longer the pending one");
            return Err(SetupRefusal::NoPending);
        }
        if let Some(r) = self.locked(now) {
            return Err(SetupRefusal::Code(r));
        }
        let Some(step) = totp_step(&secret, &normalize(code), unix, 0) else {
            return Err(SetupRefusal::Code(self.fail(now)));
        };
        self.succeed();
        let codes: Vec<String> = (0..RECOVERY_CODES).map(|_| recovery_code()).collect();
        let stored = Stored {
            v: 1,
            secret: hex::encode(&secret),
            enabled_at: unix,
            last_step: step,
            recovery: codes.iter().map(|c| digest(&normalize(c))).collect(),
            fails: 0,
            locked_until: 0,
            next_lock: 0,
        };
        write_state(&self.path, &stored).map_err(|e| SetupRefusal::Storage(e.to_string()))?;
        self.pending = None;
        tracing::info!("two-factor: switched on");
        Ok(codes)
    }

    /// Switch off with a code or a recovery code (checked here, like any other way in).
    pub fn disable(&mut self, code: &str, unix: u64) -> Result<(), SetupRefusal> {
        if !self.active() {
            return Err(SetupRefusal::AlreadyOff);
        }
        self.check(Some(code), unix).map_err(SetupRefusal::Code)?;
        std::fs::remove_file(&self.path).map_err(|e| SetupRefusal::Storage(e.to_string()))?;
        self.mem_last_step = 0;
        self.mem_fails = 0;
        self.mem_locked_until = 0;
        tracing::info!("two-factor: switched off");
        Ok(())
    }

    /// How many recovery codes are left (`None` when off or unreadable).
    pub fn recovery_left(&self) -> Option<usize> {
        match self.load() {
            Loaded::On(s) => Some(s.recovery.len()),
            _ => None,
        }
    }

    /// FR-141 — opaque fingerprint of the current 2FA enrollment (`None` when off).
    /// Changes whenever 2FA is turned on, disabled, or re-enrolled with a new secret.
    pub fn enrollment_fingerprint(&self) -> Option<String> {
        match self.load() {
            Loaded::Off => None,
            Loaded::On(s) => Some(digest(&format!("fr141-2fa:{}:{}", s.secret, s.enabled_at))),
            Loaded::Unreadable => Some("unreadable".to_string()),
        }
    }
}

static ENGINE: OnceLock<Mutex<Engine>> = OnceLock::new();

/// The state file for the daemon whose config is at `config_path`.
pub fn state_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default()
        .join(FILE)
}

/// Point the daemon's two-factor state at the file beside its config. Once, at start.
pub fn init(config_path: &Path) {
    let path = state_path(config_path);
    let on = path.exists();
    if ENGINE.set(Mutex::new(Engine::new(path))).is_ok() && on {
        tracing::info!("two-factor: on — every session into this device asks for a code");
    }
}

fn with<T>(f: impl FnOnce(&mut Engine) -> T) -> Option<T> {
    ENGINE
        .get()
        .map(|m| f(&mut m.lock().unwrap_or_else(|e| e.into_inner())))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Two-factor is on for this device.
pub fn active() -> bool {
    with(|e| e.active()).unwrap_or(false)
}

/// FR-141 — opaque fingerprint of the active two-factor enrollment, or `None` when off.
pub fn enrollment_fingerprint() -> Option<String> {
    with(|e| e.enrollment_fingerprint()).flatten()
}

/// Check the code a way in carried. `Ok` when two-factor is off (or never initialised: a
/// process that is not the daemon).
pub fn check(code: Option<&str>) -> Result<(), Refusal> {
    with(|e| e.check(code, unix_now())).unwrap_or(Ok(()))
}

pub fn begin(account: &str) -> Result<Begun, SetupRefusal> {
    with(|e| e.begin(account, Instant::now()))
        .unwrap_or_else(|| Err(SetupRefusal::Storage("not initialised".into())))
}

pub fn confirm(code: &str, setup_id: &str) -> Result<Vec<String>, SetupRefusal> {
    with(|e| e.confirm(code, setup_id, unix_now(), Instant::now()))
        .unwrap_or_else(|| Err(SetupRefusal::Storage("not initialised".into())))
}

static ADMITTED: Mutex<Option<std::collections::HashMap<String, Instant>>> = Mutex::new(None);

/// A session this device admitted on its own check (a right code in its `rc:request`). Only
/// such a session gets a peer on a two-factor device: an offer for any other session is
/// refused, so a centre that skips the request (and the check with it) gets nothing.
pub fn admit(session: &str) {
    let mut g = ADMITTED.lock().unwrap_or_else(|e| e.into_inner());
    let map = g.get_or_insert_with(Default::default);
    map.retain(|_, at| at.elapsed() < ADMITTED_FOR);
    map.insert(session.to_string(), Instant::now());
}

/// This device admitted `session` (see [`admit`]).
pub fn admitted(session: &str) -> bool {
    ADMITTED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(session))
        .is_some_and(|at| at.elapsed() < ADMITTED_FOR)
}

pub fn disable(code: &str) -> Result<(), SetupRefusal> {
    with(|e| e.disable(code, unix_now()))
        .unwrap_or_else(|| Err(SetupRefusal::Storage("not initialised".into())))
}

/// Codes are typed with spaces or dashes; recovery codes in either case.
fn normalize(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .take(64)
        .collect()
}

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC takes any key");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(h[off] & 0x7f) << 24)
        | (u32::from(h[off + 1]) << 16)
        | (u32::from(h[off + 2]) << 8)
        | u32::from(h[off + 3]);
    bin % 1_000_000
}

/// The step a 6-digit `code` is right for: the current one ±1, strictly after `last_step`.
fn totp_step(secret: &[u8], code: &str, unix: u64, last_step: u64) -> Option<u64> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let want: u32 = code.parse().ok()?;
    let now = unix / STEP_SECS;
    let mut hit = None;
    // Every candidate is computed, so the time taken does not say which one matched.
    for step in [now.saturating_sub(1), now, now + 1] {
        if step > last_step && hotp(secret, step) == want && hit.is_none() {
            hit = Some(step);
        }
    }
    hit
}

fn digest(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn recovery_index(kept: &[String], code: &str) -> Option<usize> {
    if code.len() != 8 {
        return None;
    }
    let d = digest(code);
    kept.iter().position(|k| k == &d)
}

fn recovery_code() -> String {
    let mut raw = [0u8; 8];
    rand::fill(&mut raw[..]);
    let n = RECOVERY_ALPHABET.len();
    let s: String = raw
        .iter()
        .map(|b| RECOVERY_ALPHABET[usize::from(*b) % n] as char)
        .collect();
    format!("{}-{}", &s[..4], &s[4..])
}

/// RFC 4648 base32, no padding: what an authenticator app takes as the key.
fn base32(bytes: &[u8]) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for b in bytes {
        buf = (buf << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn uri_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn otpauth_uri(account: &str, secret_b32: &str) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret_b32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
        issuer = uri_escape(ISSUER),
        account = uri_escape(account),
    )
}

fn write_state(path: &Path, s: &Stored) -> std::io::Result<()> {
    let body = serde_json::to_vec(s).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_KEY: &[u8] = b"12345678901234567890";
    const T: u64 = 1_800_000_000;

    fn engine() -> (tempfile::TempDir, Engine) {
        let d = tempfile::tempdir().unwrap();
        let e = Engine::new(d.path().join(FILE));
        (d, e)
    }

    fn code_at(secret_b32: &str, unix: u64) -> String {
        format!("{:06}", hotp(&decode32(secret_b32), unix / STEP_SECS))
    }

    fn decode32(s: &str) -> Vec<u8> {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let (mut buf, mut bits, mut out) = (0u32, 0u32, Vec::new());
        for c in s.bytes() {
            buf = (buf << 5) | A.iter().position(|a| *a == c).unwrap() as u32;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        }
        out
    }

    /// Switched on at `T`; answers the secret and the recovery codes.
    fn switched_on(e: &mut Engine) -> (String, Vec<String>) {
        let now = Instant::now();
        let b = e.begin("box", now).unwrap();
        let codes = e
            .confirm(&code_at(&b.secret, T), &b.setup_id, T, now)
            .unwrap();
        (b.secret, codes)
    }

    #[test]
    fn the_rfc_6238_sha1_vectors_hold_in_six_digits() {
        for (t, want) in [
            (59u64, 287_082u32),
            (1_111_111_109, 81_804),
            (1_111_111_111, 50_471),
            (1_234_567_890, 5_924),
            (2_000_000_000, 279_037),
        ] {
            assert_eq!(hotp(RFC_KEY, t / 30), want, "t={t}");
        }
        assert_eq!(base32(RFC_KEY), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(decode32(&base32(RFC_KEY)), RFC_KEY);
    }

    #[test]
    fn off_lets_everything_through_and_on_asks_for_a_fresh_code_each_time() {
        let (_d, mut e) = engine();
        let now = Instant::now();
        assert_eq!(e.check(None, T), Ok(()));

        let b = e.begin("gpu-box", now).unwrap();
        assert!(
            b.otpauth_uri
                .starts_with("otpauth://totp/MeshHarbor:gpu-box?secret=")
        );
        assert!(b.otpauth_uri.contains("&issuer=MeshHarbor&"));
        assert_eq!(b.secret.len(), 32);
        assert_eq!(b.setup_id.len(), 32);
        let codes = e
            .confirm(&code_at(&b.secret, T), &b.setup_id, T, now)
            .unwrap();
        assert_eq!(codes.len(), 10);
        assert!(e.active());

        assert_eq!(e.check(None, T), Err(Refusal::Required));
        assert_eq!(e.check(Some(""), T), Err(Refusal::Required));
        // The confirming code was used: the same step is refused.
        assert_eq!(
            e.check(Some(&code_at(&b.secret, T)), T),
            Err(Refusal::Invalid)
        );
        let next = T + 30;
        let c = code_at(&b.secret, next);
        assert_eq!(e.check(Some(&c), next), Ok(()));
        // Used once: a replay of the same code is refused.
        assert_eq!(e.check(Some(&c), next), Err(Refusal::Invalid));
        // Spaces as an app shows them are fine; one step of clock skew is fine.
        let skewed = code_at(&b.secret, next + 60);
        let spaced = format!("{} {}", &skewed[..3], &skewed[3..]);
        assert_eq!(e.check(Some(&spaced), next + 30), Ok(()));
    }

    #[test]
    fn wrong_codes_lock_then_double_and_the_lock_survives_a_restart() {
        let (d, mut e) = engine();
        let (secret, _) = switched_on(&mut e);
        for _ in 0..4 {
            assert_eq!(e.check(Some("000000"), T), Err(Refusal::Invalid));
        }
        assert_eq!(e.check(Some("000000"), T), Err(Refusal::Locked(60)));
        // Locked: even a right code waits.
        let good = code_at(&secret, T + 30);
        assert_eq!(e.check(Some(&good), T + 10), Err(Refusal::Locked(50)));
        // A restart (an update) does not reset it.
        let mut e = Engine::new(d.path().join(FILE));
        assert_eq!(e.check(Some(&good), T + 20), Err(Refusal::Locked(40)));
        for _ in 0..4 {
            assert_eq!(e.check(Some("111111"), T + 61), Err(Refusal::Invalid));
        }
        assert_eq!(e.check(Some("111111"), T + 61), Err(Refusal::Locked(120)));
        let later = T + 61 + 121;
        assert_eq!(e.check(Some(&code_at(&secret, later)), later), Ok(()));
        // A right code resets the doubling.
        for _ in 0..4 {
            assert_eq!(e.check(Some("222222"), later), Err(Refusal::Invalid));
        }
        assert_eq!(e.check(Some("222222"), later), Err(Refusal::Locked(60)));
    }

    #[test]
    fn a_hundred_wrong_codes_leave_only_a_recovery_code_which_works_once() {
        let (_d, mut e) = engine();
        let (secret, codes) = switched_on(&mut e);
        let mut at = T + 1_000;
        for n in 1..=HARD_CAP {
            let got = e.check(Some("000000"), at);
            if n == HARD_CAP {
                assert_eq!(got, Err(Refusal::Blocked));
            }
            // Past every lock before the next guess.
            at += 1_000;
        }
        assert_eq!(
            e.check(Some(&code_at(&secret, at)), at),
            Err(Refusal::Blocked),
            "a right 6-digit code no longer opens it"
        );
        assert_eq!(Refusal::Blocked.wire(), "two_factor_locked");
        let rc = codes[3].to_uppercase();
        assert_eq!(e.check(Some(&rc), at), Ok(()), "a recovery code does");
        assert_eq!(e.recovery_left(), Some(9));
        assert_eq!(e.check(Some(&rc), at), Err(Refusal::Invalid), "once");
        assert_eq!(e.check(Some(&code_at(&secret, at + 30)), at + 30), Ok(()));
    }

    #[test]
    fn a_recovery_code_gets_past_a_lock() {
        let (_d, mut e) = engine();
        let (_, codes) = switched_on(&mut e);
        for _ in 0..5 {
            let _ = e.check(Some("000000"), T);
        }
        assert_eq!(e.check(Some("000000"), T), Err(Refusal::Locked(60)));
        assert_eq!(e.check(Some(&codes[0]), T), Ok(()));
    }

    #[test]
    fn it_cannot_be_replaced_or_switched_off_without_a_code() {
        let (_d, mut e) = engine();
        let now = Instant::now();
        assert_eq!(e.disable("123456", T), Err(SetupRefusal::AlreadyOff));
        assert_eq!(
            e.confirm("123456", "x", T, now),
            Err(SetupRefusal::NoPending)
        );
        let b = e.begin("box", now).unwrap();
        assert_eq!(
            e.confirm("000000", &b.setup_id, T, now),
            Err(SetupRefusal::Code(Refusal::Invalid))
        );
        assert!(!e.active(), "a wrong confirming code switches nothing on");
        e.confirm(&code_at(&b.secret, T), &b.setup_id, T, now)
            .unwrap();

        assert_eq!(e.begin("box", now), Err(SetupRefusal::AlreadyOn));
        assert_eq!(e.disable("", T), Err(SetupRefusal::Code(Refusal::Required)));
        assert_eq!(
            e.disable("999999", T + 30),
            Err(SetupRefusal::Code(Refusal::Invalid))
        );
        assert!(e.active());
        e.disable(&code_at(&b.secret, T + 30), T + 30).unwrap();
        assert!(!e.active());
        assert_eq!(e.check(None, T + 60), Ok(()));
    }

    #[test]
    fn a_confirm_is_bound_to_its_own_begin() {
        let (_d, mut e) = engine();
        let now = Instant::now();
        let mine = e.begin("box", now).unwrap();
        // Someone else's begin in between replaces the pending secret.
        let theirs = e.begin("box", now).unwrap();
        assert_eq!(
            e.confirm(&code_at(&mine.secret, T), &mine.setup_id, T, now),
            Err(SetupRefusal::NoPending),
            "the page that started first sees it fail"
        );
        assert!(!e.active());
        e.confirm(&code_at(&theirs.secret, T), &theirs.setup_id, T, now)
            .unwrap();
    }

    #[test]
    fn a_pending_secret_expires_and_an_unreadable_file_refuses_every_code() {
        let (d, mut e) = engine();
        let now = Instant::now();
        let b = e.begin("box", now).unwrap();
        assert_eq!(
            e.confirm(&code_at(&b.secret, T), &b.setup_id, T, now + PENDING),
            Err(SetupRefusal::NoPending)
        );
        std::fs::write(d.path().join(FILE), b"{not json").unwrap();
        assert!(e.active());
        assert_eq!(e.check(None, T), Err(Refusal::Unavailable));
        assert_eq!(e.check(Some("123456"), T), Err(Refusal::Unavailable));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::remove_file(d.path().join(FILE)).unwrap();
            switched_on(&mut e);
            let mode = std::fs::metadata(d.path().join(FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn a_used_code_stays_used_when_the_state_cannot_be_written() {
        let (d, mut e) = engine();
        let (secret, _) = switched_on(&mut e);
        let c = code_at(&secret, T + 30);
        // A directory where the new state is written first: the write fails, as on a full
        // disk, whoever runs the test (root included).
        std::fs::create_dir(d.path().join(FILE).with_extension("json.tmp")).unwrap();
        assert_eq!(e.check(Some(&c), T + 30), Ok(()));
        assert_eq!(e.check(Some(&c), T + 30), Err(Refusal::Invalid));
        for _ in 0..4 {
            let _ = e.check(Some("000000"), T + 30);
        }
        assert_eq!(
            e.check(Some(&code_at(&secret, T + 60)), T + 60),
            Err(Refusal::Locked(30)),
            "the lock holds in this process too"
        );
    }

    #[test]
    fn only_a_session_this_device_admitted_is_known() {
        let id = format!("s-{}", std::process::id());
        assert!(!admitted(&id));
        admit(&id);
        assert!(admitted(&id));
        assert!(!admitted("another"));
    }

    #[test]
    fn the_wire_spellings_are_locked() {
        assert_eq!(Refusal::Required.wire(), "two_factor_required");
        assert_eq!(Refusal::Invalid.wire(), "two_factor_invalid");
        assert_eq!(Refusal::Locked(1).wire(), "two_factor_locked");
        assert_eq!(Refusal::Unavailable.wire(), "two_factor_unavailable");
    }
}
