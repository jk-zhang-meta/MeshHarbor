// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Fleet RPC — the agent-side execution engine.
//!
//! Runs ONE bounded shell command on behalf of a `rc:rpc.exec` frame the
//! server has already gated (org kill-switch, caller permission, the device's
//! `ExecPolicy`) and answers with a `rc:rpc.result`.
//!
//! ## What this module is responsible for
//!
//! The server owns *who may ask*. This module owns *what actually happens on
//! the box*, which is four things the server cannot enforce from a distance:
//!
//! * **Gate 4** — the agent's own `exec_enabled` config key. A device owner
//!   can refuse execution even when the server says yes, and that refusal
//!   survives a compromised control plane. Checked by the caller in
//!   `signaling.rs` before we are reached.
//! * **Bounds** — wall-clock timeout, a combined stdout+stderr ceiling, and a
//!   concurrency cap. Re-enforced here rather than trusted from the wire, so
//!   a forged or replayed frame can't ask for an unbounded run.
//! * **Redaction** — output is swept for the agent token, `Bearer …` headers
//!   and JWT-shaped strings BEFORE it leaves the host. Command output is
//!   persisted in `exec_audit`, so a secret a command happens to echo would
//!   otherwise outlive the session by 90 days.
//! * **Process-tree kill** — a timeout or cancel must not leave orphans. On
//!   Windows that's `taskkill /T /F`; on Unix the child leads its own process
//!   group and we signal the group.
//!
//! ## Injection
//!
//! The command is passed as a SINGLE argv element to the shell
//! (`pwsh -Command <cmd>`, `bash -c <cmd>`). There is no string concatenation
//! at the spawn boundary, so nothing the caller writes can escape into the
//! agent's own argv — the shell then interprets it, which is the whole point
//! of the feature.
//!
//! ## Privilege
//!
//! Under systemd the daemon runs as root, and commands inherit that. On
//! Windows they inherit the console-session WORKER's identity, because the
//! worker holds the agent socket: the signed-in user on an attended install
//! (their elevated token if they are an admin), SYSTEM in SystemContext mode.
//! FR-94 (#2035) makes SYSTEM the default. Root/SYSTEM is the intent and it is
//! deliberate — `Get-NetFirewallRule`, `netsh`, route tables and service state
//! are exactly what remote diagnosis needs — and is surfaced in the admin UI's
//! opt-in copy rather than hidden.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::sync::{Mutex, Semaphore, oneshot};
use tracing::{info, warn};

use roomler_ai_remote_control::models::exec_limits;

/// Bytes for a command's stdin, in order; dropping the sender is end-of-input.
/// Roomler SSH feeds a client's stdin through this. Fleet RPC passes none, so
/// its commands keep reading NUL / `/dev/null` exactly as before.
pub type StdinFeed = tokio::sync::mpsc::Receiver<Vec<u8>>;

// ─── Streaming (FR-89) ──────────────────────────────────────────────────────
//
// Roomler SSH's `ssh <node> 'cmd'` wants a command's output AS IT IS PRODUCED,
// with no ceiling: `cat bigfile`, `tar c`, `journalctl -f`. Fleet RPC wants
// the opposite — one bounded answer it can persist. Both go through the same
// spawn, identity model, concurrency cap, redaction and tree kill; only the
// shape of the output differs, which is why the output mode is ONE enum on
// the shared spawn path rather than a second engine.

/// Which of a command's two output streams a chunk came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutStream {
    Stdout,
    Stderr,
}

/// One piece of a streamed command's output, redacted. Chunks of ONE stream
/// arrive in the order the command wrote them; the two streams interleave in
/// the order they were read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub stream: OutStream,
    pub bytes: Vec<u8>,
}

/// Where a streamed run's output goes. BOUNDED on purpose: a consumer that
/// stops taking chunks stops the command — the readers stop reading, the OS
/// pipe fills, the child blocks on `write` — instead of growing the daemon's
/// memory. See [`ExecEngine::run_streamed`].
pub type ChunkSink = tokio::sync::mpsc::Sender<Chunk>;

/// What a streamed run reports once the command is gone. Its output went to
/// the sink; nothing of it is retained here.
#[derive(Debug, Clone, Default)]
pub struct StreamedOutcome {
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    /// Bytes handed to the sink, both streams, after redaction.
    pub bytes: u64,
    /// Set when the command never ran, or was cancelled.
    pub error: Option<String>,
}

impl StreamedOutcome {
    fn failed(error: impl Into<String>) -> Self {
        Self {
            error: Some(error.into()),
            ..Default::default()
        }
    }
}

/// One execution request, already clamped by the server and re-clamped here.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    pub request_id: String,
    /// `pwsh` | `powershell` | `cmd` | `bash` | `sh`, or empty for the host
    /// default.
    pub shell: String,
    pub command: String,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
    pub cwd: Option<String>,
    /// Display name of the acting principal, for the local log.
    pub caller: String,
    /// Which local account to run as.
    ///
    /// Fleet RPC leaves this [`RunAs::Daemon`] — its whole purpose is
    /// privileged diagnostics — unless the device's policy names the person
    /// at the screen, which the frame's `run_as` says (FR-97 P5a, Linux and
    /// macOS). Roomler SSH sets it from the device's policy.
    #[allow(dead_code)]
    pub run_as: RunAs,
    /// FR-97 P5b — with no [`Self::cwd`], start in the account's home, as
    /// sshd starts a session. Roomler SSH's exec channel sets it; Fleet RPC
    /// never does, so its commands start where they always have. Only a
    /// person's identity has a home to start in ([`apply_run_as_at_home`]).
    pub start_in_home: bool,
}

/// What came back. Mirrors `ClientMsg::RpcResult` one-for-one.
#[derive(Debug, Clone, Default)]
pub struct ExecOutcome {
    pub exit_code: Option<i32>,
    /// `stdout_bytes`, decoded for the JSON wire (fleet RPC, LocalAPI), which
    /// carries text. Lossy: a byte that is not UTF-8 becomes U+FFFD here.
    pub stdout: String,
    pub stderr: String,
    /// The output as the command wrote it, redacted the same way. A byte
    /// stream (Roomler SSH) sends THESE: decoding first turned a binary file
    /// fetched with `ssh <node> cat f > f` into U+FFFD soup (2026-10-06).
    pub stdout_bytes: Vec<u8>,
    pub stderr_bytes: Vec<u8>,
    pub truncated: bool,
    pub duration_ms: u64,
    /// Set when the command never ran, timed out, or was cancelled.
    pub error: Option<String>,
}

impl ExecOutcome {
    /// A refusal / failure that never reached a process.
    fn failed(error: impl Into<String>) -> Self {
        Self {
            error: Some(error.into()),
            ..Default::default()
        }
    }

    /// SHA-256 over the full redacted output, so a truncated audit sample can
    /// still be tied to what actually ran.
    ///
    /// The streams are domain-separated: without the `\0`, `("one", "two")`
    /// and `("onetwo", "")` would hash identically, and two materially
    /// different runs would be indistinguishable in the audit log.
    pub fn output_sha256(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.stdout.as_bytes());
        h.update([0u8]);
        h.update(self.stderr.as_bytes());
        hex::encode(h.finalize())
    }

    /// Combined output size in bytes.
    pub fn output_bytes(&self) -> u64 {
        (self.stdout.len() + self.stderr.len()) as u64
    }
}

/// Masks secrets out of command output before it leaves the host.
///
/// Deliberately dependency-free (no `regex` in a binary that ships to the
/// fleet) and deliberately over-eager: a false positive costs a reader some
/// context, a false negative persists a credential for 90 days.
#[derive(Clone, Default)]
pub struct Redactor {
    /// Literal secrets known to this process — the agent token(s).
    literals: Vec<String>,
}

/// What a masked span is replaced with.
const MASK: &str = "[redacted]";
/// Shortest literal we'll mask. Below this, matches are noise rather than
/// secrets and blanking them would shred ordinary output.
const MIN_LITERAL_LEN: usize = 8;

impl Redactor {
    pub fn new(literals: impl IntoIterator<Item = String>) -> Self {
        Self {
            literals: literals
                .into_iter()
                .filter(|s| s.len() >= MIN_LITERAL_LEN)
                .collect(),
        }
    }

    pub fn apply(&self, input: &str) -> String {
        mask_patterns(&self.mask_literals(input))
    }

    /// The literal pass alone: every registered secret, replaced.
    fn mask_literals(&self, input: &str) -> String {
        let mut out = input.to_string();
        for lit in &self.literals {
            if out.contains(lit.as_str()) {
                out = out.replace(lit.as_str(), MASK);
            }
        }
        out
    }

    /// [`Self::apply`] over raw output: each valid UTF-8 run is redacted as
    /// text and every other byte passes through untouched, so text is masked
    /// exactly as `apply` masks it and binary output stays byte-exact. A
    /// secret is ASCII, so it can never straddle a byte that is not UTF-8.
    pub fn apply_bytes(&self, input: &[u8]) -> Vec<u8> {
        map_utf8_runs(input, |s| self.apply(s))
    }
}

/// The two pattern masks, in the order [`Redactor::apply`] runs them.
fn mask_patterns(input: &str) -> String {
    mask_jwt_shaped(&mask_bearer(input))
}

/// [`mask_patterns`] over raw bytes — see [`Redactor::apply_bytes`].
fn mask_patterns_bytes(input: &[u8]) -> Vec<u8> {
    map_utf8_runs(input, mask_patterns)
}

/// `f` over each valid UTF-8 run of `input`; every other byte passes through
/// untouched, in place.
fn map_utf8_runs(input: &[u8], f: impl Fn(&str) -> String) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.utf8_chunks() {
        let valid = chunk.valid();
        if !valid.is_empty() {
            out.extend_from_slice(f(valid).as_bytes());
        }
        out.extend_from_slice(chunk.invalid());
    }
    out
}

/// [`Redactor`] over a STREAM (FR-89): the same three masks, applied to
/// output that arrives in pipe-sized pieces, without ever letting a secret
/// slip through the gap between two of them.
///
/// # The rule
///
/// Every masked shape is whitespace-free — a registered literal is an agent
/// token, `mask_bearer` ends a token at whitespace, a JWT is base64url — so
/// bytes are **settled only at a word boundary**: the position right after
/// the last ASCII whitespace byte. The word in progress stays in the carry
/// until something ends it, and a token is therefore always masked whole.
/// Three refinements, each closing a hole a plain word-boundary rule leaves:
///
/// * the **literal pass runs over everything visible** (carry + new bytes)
///   before the cut, so a literal that straddles the previous cut is masked
///   the moment it is complete;
/// * a settled prefix ending in `bearer ` is **pulled back** to the word
///   boundary before it — settled alone, `Bearer ` leaves its token to the
///   next chunk, where `mask_bearer` sees no prefix and masks nothing;
/// * a literal that itself contains whitespace (none is registered today)
///   adds a hold-back of its own length.
///
/// # The bounds
///
/// A whitespace-free run longer than [`CARRY_CAP`] (`base64 -w0`, minified
/// JSON, a binary with few whitespace bytes) would grow the carry without
/// bound, so it is **force-settled**: the pattern pass runs over the whole
/// buffer first (a fully visible token straddling the cut is masked anyway),
/// then all but the last max([`FORCED_HOLD`], longest literal − 1) bytes
/// are emitted. A literal can never leak at a forced cut; a pattern token
/// leaks only if more than `FORCED_HOLD` of it is visible and it is still
/// unfinished.
///
/// A prompt with no trailing newline (`Continue? [y/N]`) would otherwise sit
/// in the carry until EOF, so the owner flushes a carry that has waited
/// ([`idle_flush`](Self::idle_flush)) — holding back only a tail that is a
/// proper prefix of a literal, and a `bearer ` context whose token is in
/// progress. A pattern token is then split only if the WRITER pauses
/// mid-token, which a secret written with one `write()` never does.
///
/// Binary passes through byte-exact: the masks run on valid-UTF-8 runs only
/// ([`map_utf8_runs`]), a multi-byte character split by a chunk boundary is
/// an invalid run on both sides, and no cut lands inside one.
pub struct StreamRedactor {
    redactor: Redactor,
    /// Bytes not yet settled: the word in progress (plus whatever a
    /// pull-back kept), already literal-masked.
    carry: Vec<u8>,
    /// Longest registered literal, for the hold-back at a forced cut.
    longest_literal: usize,
    /// Hold-back for literals that contain whitespace: such a literal could
    /// straddle a word boundary. 0 when none is registered.
    whitespace_literal_hold: usize,
    /// The carry was already offered to an idle flush and nothing more can
    /// settle without new bytes — the owner need not time it again.
    idle_settled: bool,
}

/// A whitespace-free run longer than this is settled in pieces.
const CARRY_CAP: usize = 64 * 1024;
/// How much of such a run stays unsettled at a forced cut, so a token that
/// straddles the cut is still seen whole (unless it is longer than this).
const FORCED_HOLD: usize = 8 * 1024;
/// The prefix `mask_bearer` keys on, for the pull-back.
const BEARER: &[u8] = b"bearer ";

impl StreamRedactor {
    pub fn new(redactor: &Redactor) -> Self {
        let longest_literal = redactor.literals.iter().map(|l| l.len()).max().unwrap_or(0);
        let whitespace_literal_hold = redactor
            .literals
            .iter()
            .filter(|l| l.bytes().any(|b| b.is_ascii_whitespace()))
            .map(|l| l.len() - 1)
            .max()
            .unwrap_or(0);
        Self {
            redactor: redactor.clone(),
            carry: Vec::new(),
            longest_literal,
            whitespace_literal_hold,
            idle_settled: false,
        }
    }

    /// Is something waiting for more bytes that an idle flush could release?
    pub fn is_holding(&self) -> bool {
        !self.carry.is_empty() && !self.idle_settled
    }

    /// Take the next piece of the stream; get back what can be emitted now.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<u8> {
        if bytes.is_empty() {
            return Vec::new();
        }
        self.idle_settled = false;
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(bytes);
        // Literals over everything visible: one that straddled the previous
        // cut is complete now; one still arriving is wholly in the carry.
        let mut buf = map_utf8_runs(&buf, |s| self.redactor.mask_literals(s));
        let p = self.settle_point(&buf);
        if buf.len() - p > CARRY_CAP {
            return self.force_settle(buf);
        }
        self.carry = buf.split_off(p);
        mask_patterns_bytes(&buf)
    }

    /// Flush a carry that has waited for more bytes long enough.
    pub fn idle_flush(&mut self) -> Vec<u8> {
        if self.carry.is_empty() {
            return Vec::new();
        }
        self.idle_settled = true;
        let mut buf = std::mem::take(&mut self.carry);
        // A tail that is a proper prefix of a literal stays: the rest of the
        // secret may be the very next thing written.
        let mut p = buf.len() - longest_literal_prefix_suffix(&self.redactor.literals, &buf);
        // A `bearer ` context whose token is in progress stays whole.
        let word_start = word_boundary_at_or_before(&buf, buf.len());
        if word_start >= BEARER.len()
            && buf[word_start - BEARER.len()..word_start].eq_ignore_ascii_case(BEARER)
        {
            p = p.min(word_boundary_at_or_before(&buf, word_start - BEARER.len()));
        }
        p = char_boundary_at_or_before(&buf, p);
        self.carry = buf.split_off(p);
        mask_patterns_bytes(&buf)
    }

    /// End of stream: everything left, masked.
    pub fn finish(&mut self) -> Vec<u8> {
        self.idle_settled = false;
        let buf = std::mem::take(&mut self.carry);
        self.redactor.apply_bytes(&buf)
    }

    /// The largest prefix of `buf` that can be emitted without cutting a
    /// token: a word boundary, pulled back past a trailing `bearer ` and
    /// past the hold-back for whitespace-bearing literals.
    fn settle_point(&self, buf: &[u8]) -> usize {
        let mut p = word_boundary_at_or_before(buf, buf.len());
        if self.whitespace_literal_hold > 0 {
            let limit = buf.len().saturating_sub(self.whitespace_literal_hold);
            if p > limit {
                p = word_boundary_at_or_before(buf, limit);
            }
        }
        while p >= BEARER.len() && buf[p - BEARER.len()..p].eq_ignore_ascii_case(BEARER) {
            p = word_boundary_at_or_before(buf, p - BEARER.len());
        }
        p
    }

    /// A whitespace-free run past [`CARRY_CAP`]: settle most of it.
    fn force_settle(&mut self, buf: Vec<u8>) -> Vec<u8> {
        // Patterns over everything visible, so a token straddling the cut is
        // masked wherever it is complete; the carry comes back through this
        // pass again later, which is harmless — `[redacted]` matches nothing.
        let mut buf = mask_patterns_bytes(&buf);
        let hold = FORCED_HOLD.max(self.longest_literal.saturating_sub(1));
        let p = char_boundary_at_or_before(&buf, buf.len().saturating_sub(hold));
        self.carry = buf.split_off(p);
        buf
    }
}

/// The largest word boundary — 0, or the position right after an ASCII
/// whitespace byte — that is ≤ `at`.
fn word_boundary_at_or_before(buf: &[u8], at: usize) -> usize {
    buf[..at]
        .iter()
        .rposition(|b| b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(0)
}

/// `at`, moved back off any UTF-8 continuation byte so a cut there never
/// splits a character.
fn char_boundary_at_or_before(buf: &[u8], mut at: usize) -> usize {
    while at > 0 && at < buf.len() && (buf[at] & 0xC0) == 0x80 {
        at -= 1;
    }
    at
}

/// Length of the longest suffix of `buf` that is a PROPER prefix of some
/// literal — the part of a secret that may already have been written.
fn longest_literal_prefix_suffix(literals: &[String], buf: &[u8]) -> usize {
    let mut best = 0;
    for lit in literals {
        let lit = lit.as_bytes();
        let max_k = lit.len().saturating_sub(1).min(buf.len());
        for k in (best + 1..=max_k).rev() {
            if buf.ends_with(&lit[..k]) {
                best = k;
                break;
            }
        }
    }
    best
}

/// Mask the token after a `Bearer ` / `bearer ` prefix, up to the next
/// whitespace.
fn mask_bearer(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    loop {
        let Some(pos) = find_ignore_ascii_case(rest, "bearer ") else {
            out.push_str(rest);
            return out;
        };
        let after = pos + "bearer ".len();
        out.push_str(&rest[..after]);
        let tail = &rest[after..];
        let end = tail.find(|c: char| c.is_whitespace()).unwrap_or(tail.len());
        if end >= MIN_LITERAL_LEN {
            out.push_str(MASK);
        } else {
            out.push_str(&tail[..end]);
        }
        rest = &tail[end..];
    }
}

fn find_ignore_ascii_case(haystack: &str, needle_lower: &str) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = needle_lower.as_bytes();
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    (0..=h.len() - n.len()).find(|&i| {
        h[i..i + n.len()]
            .iter()
            .zip(n)
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
    })
}

/// Mask `xxx.yyy.zzz` runs of base64url characters — the JWT shape. Three
/// segments of ≥8 base64url chars each is not a thing ordinary command output
/// produces, so this is safe to be blunt about.
fn mask_jwt_shaped(input: &str) -> String {
    const MIN_SEG: usize = 8;
    let is_b64 = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';

    let mut out = String::with_capacity(input.len());
    let bytes: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if !is_b64(bytes[i]) {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        // Try to consume seg '.' seg '.' seg starting at i.
        let start = i;
        let mut cursor = i;
        let mut segs = 0;
        let mut ok = true;
        while segs < 3 {
            let seg_start = cursor;
            while cursor < bytes.len() && is_b64(bytes[cursor]) {
                cursor += 1;
            }
            if cursor - seg_start < MIN_SEG {
                ok = false;
                break;
            }
            segs += 1;
            if segs < 3 {
                if cursor < bytes.len() && bytes[cursor] == '.' {
                    cursor += 1;
                } else {
                    ok = false;
                    break;
                }
            }
        }
        if ok && segs == 3 {
            out.push_str(MASK);
            i = cursor;
        } else {
            // Not a JWT — emit the first run verbatim and re-scan from there.
            let mut run_end = start;
            while run_end < bytes.len() && is_b64(bytes[run_end]) {
                run_end += 1;
            }
            out.extend(&bytes[start..run_end]);
            i = run_end;
        }
    }
    out
}

/// Which program + fixed args implement a shell name on this host.
///
/// The caller's command is appended as ONE further argv element — never
/// concatenated — so it cannot escape into the agent's own argv.
/// Prefix that forces a Windows shell to emit UTF-8.
///
/// PowerShell writes its pipe in the host's ANSI/OEM codepage, not UTF-8. On a
/// German-locale host `whoami` returns `nt-autorität\system`, which arrives as
/// `nt-autorit<?>t\system` after our lossy decode — field-caught on WINHOST-A,
/// 2026-08-06. Setting the console output encoding per-process is the standard
/// fix; it does not leak outside this child, and an assignment before the
/// caller's command does not affect the exit code PowerShell reports.
#[cfg(windows)]
const PS_UTF8_PREFIX: &str = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; ";
/// `cmd.exe` equivalent — switch the console codepage to UTF-8 first.
#[cfg(windows)]
const CMD_UTF8_PREFIX: &str = "chcp 65001>nul&";

/// Wrap the caller's command so the shell emits UTF-8. Still ONE argv element,
/// so the injection story is unchanged.
#[cfg(windows)]
fn utf8_wrapped(shell_program: &str, command: &str) -> String {
    if shell_program.eq_ignore_ascii_case("cmd.exe") {
        format!("{CMD_UTF8_PREFIX}{command}")
    } else {
        format!("{PS_UTF8_PREFIX}{command}")
    }
}

fn resolve_shell(requested: &str) -> Result<(&'static str, Vec<&'static str>), String> {
    let want = requested.trim().to_ascii_lowercase();
    #[cfg(windows)]
    {
        // `powershell` is the auto default: it is present on every supported
        // Windows since Vista, whereas `pwsh` is an optional install. A
        // caller who wants pwsh asks for it by name and gets a clean
        // "not installed" if it is absent.
        match want.as_str() {
            "" | "auto" | "powershell" => Ok((
                "powershell.exe",
                vec!["-NoProfile", "-NonInteractive", "-NoLogo", "-Command"],
            )),
            "pwsh" => Ok((
                "pwsh.exe",
                vec!["-NoProfile", "-NonInteractive", "-NoLogo", "-Command"],
            )),
            "cmd" => Ok(("cmd.exe", vec!["/C"])),
            other => Err(format!(
                "unsupported shell {other:?} on this device (have: powershell, pwsh, cmd)"
            )),
        }
    }
    #[cfg(not(windows))]
    {
        // `-c`, not `-lc`: a login shell sources profiles that print banners
        // into stdout and make output non-deterministic across hosts. A
        // command that needs profile PATH can source it explicitly.
        match want.as_str() {
            "" | "auto" | "bash" => Ok(("bash", vec!["-c"])),
            "sh" => Ok(("sh", vec!["-c"])),
            other => Err(format!(
                "unsupported shell {other:?} on this device (have: bash, sh)"
            )),
        }
    }
}

/// Literal secrets every exec's output is swept for. Process-wide because a
/// multi-org daemon holds one agent token PER ORG and a command's output must
/// not leak org B's token just because org A asked for it.
static SECRETS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Register a literal secret to mask out of every future exec's output. Each
/// org's signalling loop calls this with its own agent token on connect.
pub fn register_secret(secret: &str) {
    if secret.len() < MIN_LITERAL_LEN {
        return;
    }
    let mut g = match SECRETS.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if !g.iter().any(|s| s == secret) {
        g.push(secret.to_string());
    }
}

/// A [`Redactor`] over every secret registered so far.
pub fn redactor() -> Redactor {
    let g = match SECRETS.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    Redactor::new(g.clone())
}

/// The process-wide engine. Concurrency is a property of the DEVICE, not of
/// an org's WS connection, so a multi-org daemon must not multiply its own
/// exec cap by the number of orgs it has joined.
static ENGINE: std::sync::OnceLock<ExecEngine> = std::sync::OnceLock::new();

pub fn shared() -> &'static ExecEngine {
    ENGINE.get_or_init(ExecEngine::new)
}

// ─── Outbound leg: commands THIS device asks other devices to run ────────
//
// `meshharbor exec <device> …` goes CLI → LocalAPI → this daemon's agent WS →
// server → target. The answer arrives asynchronously on the WS receive path,
// which has no way back to the parked LocalAPI call — hence this registry.

type PendingMap = std::sync::Mutex<HashMap<String, oneshot::Sender<ExecOutcome>>>;

fn pending() -> &'static PendingMap {
    static PENDING: std::sync::OnceLock<PendingMap> = std::sync::OnceLock::new();
    PENDING.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn lock_pending() -> std::sync::MutexGuard<'static, HashMap<String, oneshot::Sender<ExecOutcome>>> {
    match pending().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Park a slot for `request_id` before sending the request, and get the
/// receiver to await the answer on. Dropping the returned guard deregisters,
/// so a caller that times out leaves nothing behind.
pub fn expect_response(request_id: &str) -> (PendingGuard, oneshot::Receiver<ExecOutcome>) {
    let (tx, rx) = oneshot::channel();
    lock_pending().insert(request_id.to_string(), tx);
    (
        PendingGuard {
            request_id: request_id.to_string(),
        },
        rx,
    )
}

/// Deregisters its request id on drop, so an abandoned caller can't leak a
/// slot that a later id-reuse would deliver into.
pub struct PendingGuard {
    request_id: String,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        lock_pending().remove(&self.request_id);
    }
}

/// Hand a `rc:rpc.response` to whoever is parked on it. Returns whether a
/// waiter was found — `false` just means that caller already gave up.
pub fn deliver_response(request_id: &str, outcome: ExecOutcome) -> bool {
    match lock_pending().remove(request_id) {
        Some(tx) => tx.send(outcome).is_ok(),
        None => false,
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Privilege — which local account a command runs as
// ────────────────────────────────────────────────────────────────────────────

/// The identity a command should run under.
///
/// [`Daemon`](RunAs::Daemon) is what Fleet RPC has always done and stays the
/// default, so nothing about exec changes. Roomler SSH sets the others from
/// the device's `SshPolicy`.
///
/// # The rule this type exists to enforce
///
/// **Never silently run as something more privileged than was asked for.** A
/// policy that says `console_user` on a host where the daemon cannot obtain
/// that token must FAIL, not quietly fall back to SYSTEM. Falling back is how
/// an operator ends up believing sessions are unprivileged while they are
/// root — the worst possible outcome, because it is invisible until it isn't.
/// Every unsupported combination below returns an error that names what was
/// asked for and why it could not be done.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RunAs {
    /// The daemon's own identity — root under systemd; on Windows the
    /// console-session worker's (the signed-in user on an attended install,
    /// SYSTEM in SystemContext mode; FR-94).
    #[default]
    Daemon,
    /// A named local account. Unix only: Windows has no way to become an
    /// arbitrary local user without that user's credentials.
    Named(String),
    /// The person signed in at this machine's screen. On Windows by their
    /// session token: spawned through `CreateProcessAsUserW` (`win_console`)
    /// for exec, the pty, and since FR-97 P4b the `sftp` subsystem, never
    /// configured on a `tokio::process::Command`. On Linux and macOS (FR-97
    /// P5a) the account at logind's seat0 or owning `/dev/console`, by the
    /// drop a [`Self::Named`] account takes. Refused when nobody is there
    /// (see [`apply_run_as`]).
    ConsoleUser,
}

impl RunAs {
    /// Parse the wire spelling the server sends in `rc:ssh.grant`.
    ///
    /// An unknown mode resolves to an ERROR, never to `Daemon`: a newer server
    /// naming a mode this agent does not understand must not have its
    /// intent downgraded into "run as root".
    pub fn from_wire(mode: &str, account: Option<&str>) -> Result<Self, String> {
        match mode {
            "daemon" => Ok(Self::Daemon),
            "console_user" => Ok(Self::ConsoleUser),
            "named" => match account.map(str::trim).filter(|a| !a.is_empty()) {
                Some(a) => Ok(Self::Named(a.to_string())),
                None => Err("account_mode `named` was requested without an account".into()),
            },
            other => Err(format!(
                "unknown account_mode {other:?} — refusing rather than guessing"
            )),
        }
    }

    /// A short label for logs and audit records.
    pub fn label(&self) -> String {
        match self {
            Self::Daemon => "daemon".into(),
            Self::ConsoleUser => "console_user".into(),
            Self::Named(a) => format!("named:{a}"),
        }
    }

    /// Does this ask for the daemon's own (privileged) identity?
    pub fn is_privileged(&self) -> bool {
        matches!(self, Self::Daemon)
    }
}

/// Configure `cmd` to run as `who`, or explain why it cannot.
///
/// Returns `Err` rather than silently doing something else — see [`RunAs`].
///
/// `pub(crate)` so the PTY path ([`crate::pty`]) applies the SAME rules rather
/// than growing a second identity model for interactive sessions. Every
/// refusal here — `console_user` with nobody at the screen, `named` on
/// Windows — is a refusal there too, in the same words.
pub(crate) fn apply_run_as(cmd: &mut tokio::process::Command, who: &RunAs) -> Result<(), String> {
    // Only the Unix drop path configures the command. On Windows every
    // non-daemon mode is currently a refusal, so nothing is set — which is the
    // point: refusing configures nothing and spawns nothing.
    #[cfg(not(unix))]
    let _ = &cmd;
    match who {
        RunAs::Daemon => Ok(()),

        #[cfg(unix)]
        RunAs::Named(account) => unix_priv::drop_to(cmd, account),
        #[cfg(not(unix))]
        RunAs::Named(account) => Err(format!(
            "cannot run as the local account {account:?}: becoming an arbitrary user on Windows \
             requires that user's credentials, which this daemon does not have and will not ask \
             for. Use account_mode `console_user` for the signed-in user, or `daemon` to accept \
             running as SYSTEM."
        )),

        // Handled before this point by the `win_console` branch in
        // `spawn_and_wait` — the token must be supplied to
        // `CreateProcessAsUserW`, so there is nothing to configure on a
        // `tokio::process::Command`. Reaching here would mean that branch was
        // removed, and running as the daemon instead is exactly the silent
        // escalation this type exists to prevent.
        #[cfg(windows)]
        RunAs::ConsoleUser => Err(
            "internal: console-user sessions must be dispatched to the CreateProcessAsUserW \
             path, not configured on a Command"
                .into(),
        ),
        // FR-97 P5a (D7) — the person at this machine's screen, by the drop a
        // named account takes. A drop, never a gain: refused when nobody is
        // there, when that person is root, and by a daemon that is neither
        // root nor them.
        #[cfg(unix)]
        RunAs::ConsoleUser => unix_priv::drop_to_console(cmd, &console_account()?, false),
        #[cfg(not(any(windows, unix)))]
        RunAs::ConsoleUser => {
            Err("account_mode `console_user` has no console to read on this platform".into())
        }
    }
}

/// FR-97 P5b — [`apply_run_as`] for an SSH session, which sshd starts in the
/// account's home: a person (`named`, `console_user`) starts there, the
/// daemon where it is, as before. The `chdir` runs in the child after the
/// drop, as the person, so their own rights decide (a root-squashed NFS home
/// refuses root), and a home they cannot enter leaves the child where it
/// was, `/`, which is sshd's fallback too. Off with
/// `ROOMLERD_SSH_START_IN_HOME=0`. Windows' `console_user` starts in the
/// profile through its own spawn (`win_console`, `pty::windows`).
pub(crate) fn apply_run_as_at_home(
    cmd: &mut tokio::process::Command,
    who: &RunAs,
) -> Result<(), String> {
    #[cfg(unix)]
    if ssh_starts_in_home() {
        return match who {
            RunAs::Daemon => Ok(()),
            RunAs::Named(account) => unix_priv::drop_to_in(cmd, account, true),
            RunAs::ConsoleUser => unix_priv::drop_to_console(cmd, &console_account()?, true),
        };
    }
    apply_run_as(cmd, who)
}

/// FR-97 P5b — does a person's SSH session start in their home? Default on;
/// `ROOMLERD_SSH_START_IN_HOME=0` keeps the old start, the daemon's own
/// directory.
pub(crate) fn ssh_starts_in_home() -> bool {
    tunnel_core::env::flag("SSH_START_IN_HOME", true)
}

/// FR-97 P5a — the account of the person at this machine's screen, for
/// `console_user` off Windows (D7): logind's seat0 on Linux
/// (`companion::seat0_user`), the owner of `/dev/console` on macOS
/// (`companion::console_user_name`). The error names the mode and why
/// nobody is there.
#[cfg(unix)]
fn console_account() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    let who = crate::companion::console_user_name();
    #[cfg(not(target_os = "macos"))]
    let who = crate::companion::seat0_user();
    who.map_err(|e| {
        format!(
            "account_mode `console_user` runs as the person at this machine's screen, and cannot \
             here: {e:#}"
        )
    })
}

/// FR-90 — a Hive session's state lives under its account's home, and FR-97 P3d's
/// received file under the person's: the lookup that refuses uid 0 finds both.
#[cfg(any(target_os = "linux", all(hive_host, unix)))]
pub(crate) use unix_priv::account_home;
/// The recorder's and received files' (FR-97 P3d). FR-90 reads [`session_account_ids`] instead.
#[cfg(target_os = "linux")]
pub(crate) use unix_priv::account_ids;
/// FR-90 decision 13 — an agent session's account as the session holds it,
/// without its administrator groups: what the toolbelt's socket is handed to,
/// and what the relay check reads.
#[cfg(all(hive_host, unix))]
pub(crate) use unix_priv::session_account_ids;

/// FR-90 decision 13 — drop to `account` as an agent session runs: without its
/// administrator groups, and on Linux unable to gain a privilege by exec
/// ([`unix_priv::drop_to_session`]).
#[cfg(all(hive_host, unix))]
pub(crate) fn apply_session_run_as(
    cmd: &mut tokio::process::Command,
    account: &str,
) -> Result<(), String> {
    unix_priv::drop_to_session(cmd, account)
}

/// FR-97 P4b — run `program` itself, with no shell and no command argument, as
/// the user signed in at the console, its stdio raw: `stdin` feeds its input,
/// and both outputs reach `raw` as they are read, UNREDACTED, with no ceiling
/// and no wall clock. `abort` kills its process tree. It starts in the user's
/// profile, where OpenSSH starts it.
///
/// For Roomler SSH's `sftp` subsystem on Windows, where `tokio::process`
/// cannot take a user token. The bytes are a binary protocol, which redaction
/// (`run_streamed`'s stage) would corrupt, and the program is `sftp-server`
/// itself, which no shell may stand in front of. The token is the console
/// session's (`WTSQueryUserToken`), so this works only where the daemon is
/// SYSTEM, the SystemContext worker, and says why anywhere else.
#[cfg(all(windows, feature = "ssh-server"))]
pub(crate) async fn run_console_user_program(
    program: &str,
    stdin: StdinFeed,
    raw: ChunkSink,
    abort: tokio_util::sync::CancellationToken,
) -> ExecOutcome {
    win_console::run_program(
        program,
        Output::Streamed { raw },
        async move { abort.cancelled().await },
        Some(stdin),
    )
    .await
}

/// FR-85 P1e-unix — the recorder's identity on Linux resolves accounts here
/// too, so there is one way an account becomes ids (and uid 0 is refused).
/// FR-90 P1j: and the adopt socket, which names the account its peer runs as.
#[cfg(any(all(target_os = "linux", feature = "recording"), all(hive_host, unix)))]
pub(crate) use unix_priv::account_name;
/// Unix privilege drop.
///
/// Split into a "resolve everything first, then apply" shape for one specific
/// reason: the code that runs between `fork` and `exec` must be
/// async-signal-safe, and in a multithreaded process it must not allocate — a
/// malloc lock held by another thread at fork time never gets released in the
/// child. So `getpwnam`/`getgrouplist` (both of which allocate) happen in the
/// parent, and the child only makes bare syscalls over already-owned memory.
/// FR-45's portal helper spawns a *synchronous* child that must become the
/// console user, so the one verified drop is re-exported rather than copied.
/// Deliberately re-exported instead of widening the module: everything else in
/// here — `resolve`, `Account`, `drop_body` — stays private, so the crate has
/// exactly one way to drop privilege and no way to assemble a partial one.
///
/// ⚠️ The cfg mirrors its ONE consumer (`capture::portal`) exactly. A helper
/// gated more loosely than the code that uses it is dead on every other lane,
/// and `-D warnings` turns that into a build failure in CI rather than here —
/// the same trap FR-36 hit when a shared helper moved out of a feature-gated
/// module and lost its implicit gate. Widen this only alongside a caller.
///
/// Widened for FR-56 P1: `apps::linux` needs it too, and `apps` is compiled on
/// every Linux build rather than behind `portal-capture` — so the gate is now
/// the platform alone. Both callers are Linux-only, so no other lane sees it.
#[cfg(target_os = "linux")]
pub(crate) use unix_priv::drop_to_std;

#[cfg(unix)]
mod unix_priv {
    use std::ffi::CString;

    /// A resolved local account: everything the child needs, pre-computed.
    ///
    /// `Debug` is for the tests' `unwrap_err()`; nothing secret lives here —
    /// uid, gid, group list and home path are all readable from `/etc/passwd`
    /// by anyone on the box.
    #[derive(Debug)]
    struct Account {
        uid: libc::uid_t,
        gid: libc::gid_t,
        groups: Vec<libc::gid_t>,
        home: String,
        name: String,
    }

    /// Look up an account by name.
    fn resolve(account: &str) -> Result<Account, String> {
        let c_name = CString::new(account)
            .map_err(|_| format!("account name {account:?} contains a NUL byte"))?;

        // `getpwnam_r` with a buffer we grow rather than `getpwnam`, which
        // returns a pointer into static storage another thread can overwrite.
        // `libc::c_char`, NOT `i8`: it is `u8` on aarch64 Linux, and the fleet
        // ships an aarch64 .deb. That target is only built at RELEASE-TAG
        // time, so hardcoding `i8` here would compile clean in CI and break a
        // release.
        let mut buf = vec![0 as libc::c_char; 1024];
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        loop {
            let rc = unsafe {
                libc::getpwnam_r(
                    c_name.as_ptr(),
                    &mut pwd,
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut result,
                )
            };
            if rc == libc::ERANGE && buf.len() < 64 * 1024 {
                buf.resize(buf.len() * 2, 0);
                continue;
            }
            if rc != 0 {
                return Err(format!(
                    "looking up local account {account:?} failed: {}",
                    std::io::Error::from_raw_os_error(rc)
                ));
            }
            break;
        }
        if result.is_null() {
            return Err(format!("no local account named {account:?} on this host"));
        }

        let uid = pwd.pw_uid;
        let gid = pwd.pw_gid;

        // Refuse uid 0 through this path. Not because running as root is
        // impossible — `RunAs::Daemon` already is root here — but because it
        // must be an explicit choice in the policy rather than a side effect
        // of naming an account that happens to be uid 0.
        if uid == 0 {
            return Err(format!(
                "account {account:?} is uid 0; use account_mode `daemon` if running as root is \
                 really intended"
            ));
        }

        let home = unsafe { cstr_to_string(pwd.pw_dir) };

        // Supplementary groups, resolved HERE because getgrouplist allocates.
        let mut ngroups: libc::c_int = 32;
        let mut groups: Vec<libc::gid_t> = vec![0; ngroups as usize];
        loop {
            let rc = unsafe {
                libc::getgrouplist(
                    c_name.as_ptr(),
                    gid as _,
                    groups.as_mut_ptr() as *mut _,
                    &mut ngroups,
                )
            };
            if rc >= 0 {
                groups.truncate(ngroups.max(0) as usize);
                break;
            }
            if ngroups as usize <= groups.len() || ngroups > 4096 {
                // No progress, or an unreasonable answer: fall back to the
                // primary group alone rather than looping. A session with only
                // its primary group is degraded, not unsafe.
                groups = vec![gid];
                break;
            }
            groups.resize(ngroups as usize, 0);
        }
        // SAFETY: sysconf takes a constant and touches no memory of ours.
        let groups = within_ngroups_max(groups, unsafe { libc::sysconf(libc::_SC_NGROUPS_MAX) });

        Ok(Account {
            uid,
            gid,
            groups,
            home,
            name: account.to_string(),
        })
    }

    /// FR-90 P1h-3 — no more supplementary groups than this system's
    /// `setgroups` takes (`max`, its `NGROUPS_MAX`): it refuses the whole list
    /// when it is longer. That is 16 on macOS, where an account's list easily
    /// runs past it: a tart VM's `admin` is in 17 groups. Field-found: every
    /// agent session on a Mac failed "starting the harness: Invalid argument
    /// (os error 22)", and so would exec, SSH and the PTY as such an account.
    /// The list keeps its order (`getgrouplist` puts the primary group first)
    /// and loses its tail, so the child holds fewer groups, never more. A
    /// `max` the system did not give (sysconf's -1, or 0) changes nothing.
    fn within_ngroups_max(mut groups: Vec<libc::gid_t>, max: libc::c_long) -> Vec<libc::gid_t> {
        if let Ok(max) = usize::try_from(max)
            && max > 0
            && groups.len() > max
        {
            groups.truncate(max);
        }
        groups
    }

    /// FR-90 decision 13 — the groups whose members can become root, or act
    /// as it: root's own, the sudoers groups (`wheel`, `sudo`, `admin`, which
    /// is macOS's and old Ubuntu's), and those whose socket or device is root
    /// by another door (`docker`, `lxd`, `incus`, `libvirt`, `disk`). An agent
    /// session holds none of them, as Windows makes its administrator groups
    /// deny-only. A name this system has no group for is skipped; gid 0 is
    /// always one.
    #[cfg(hive_host)]
    const ADMIN_EQUIVALENT_GROUPS: &[&str] = &[
        "root", "wheel", "sudo", "admin", "docker", "lxd", "incus", "libvirt", "disk",
    ];

    /// The gids of [`ADMIN_EQUIVALENT_GROUPS`] on this system, 0 included.
    #[cfg(hive_host)]
    fn admin_gids() -> Vec<libc::gid_t> {
        let mut gids = vec![0];
        for name in ADMIN_EQUIVALENT_GROUPS {
            if let Some(gid) = group_gid(name)
                && !gids.contains(&gid)
            {
                gids.push(gid);
            }
        }
        gids
    }

    /// A group's gid by name (`getgrnam_r`, its buffer grown as [`resolve`]
    /// grows its own); `None` when there is no such group, or on an error.
    #[cfg(hive_host)]
    fn group_gid(name: &str) -> Option<libc::gid_t> {
        let c_name = CString::new(name).ok()?;
        let mut buf = vec![0 as libc::c_char; 1024];
        // SAFETY: a plain C struct; all-zero is a valid, empty value.
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        loop {
            // SAFETY: every pointer is to memory this frame owns, sized as
            // passed; the answer points into `buf`, read before it moves.
            let rc = unsafe {
                libc::getgrnam_r(
                    c_name.as_ptr(),
                    &mut grp,
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut result,
                )
            };
            if rc == libc::ERANGE && buf.len() < 1024 * 1024 {
                buf.resize(buf.len() * 2, 0);
                continue;
            }
            if rc != 0 || result.is_null() {
                return None;
            }
            return Some(grp.gr_gid);
        }
    }

    /// FR-90 decision 13 — the account as an agent session holds it.
    #[cfg(hive_host)]
    fn resolve_session(account: &str) -> Result<Account, String> {
        session_view(resolve(account)?, &admin_gids())
    }

    /// The pure half of [`resolve_session`]: none of the administrator
    /// groups, so the kernel grants the session nothing by them: a docker or
    /// libvirt socket, a disk device, macOS's admin-writable `/Applications`.
    /// They are not what stops `sudo`. On Linux `no_new_privs` does that; on
    /// macOS nothing does, because its `sudo` reads the account's groups from
    /// the directory, never from the process (field-measured, FR-90 §8). An
    /// account whose PRIMARY group is an administrator group is refused, since
    /// everything its session made would be that group's.
    #[cfg(hive_host)]
    fn session_view(mut a: Account, admin: &[libc::gid_t]) -> Result<Account, String> {
        if admin.contains(&a.gid) {
            return Err(format!(
                "{}'s primary group (gid {}) is an administrator group, and an agent session \
                 never holds one",
                a.name, a.gid
            ));
        }
        a.groups.retain(|g| !admin.contains(g));
        Ok(a)
    }

    /// FR-90 decision 13 — what an agent session's account is: its uid,
    /// primary gid and the groups it holds ([`resolve_session`]).
    #[cfg(hive_host)]
    pub(crate) fn session_account_ids(
        account: &str,
    ) -> Result<(libc::uid_t, libc::gid_t, Vec<libc::gid_t>), String> {
        let a = resolve_session(account)?;
        Ok((a.uid, a.gid, a.groups))
    }

    /// FR-90 decision 13 — [`drop_to`] as an agent session runs: the account
    /// without its administrator groups, and on Linux with `no_new_privs` set,
    /// so nothing the session starts gains a privilege by exec. No setuid
    /// `sudo`, whatever sudoers says of the account, and no file capability.
    /// macOS has no such switch, and its `sudo` reads groups from the
    /// directory: a session there may use any rule its account may use
    /// without a password, whether the rule names the account or a group.
    #[cfg(hive_host)]
    pub(super) fn drop_to_session(
        cmd: &mut tokio::process::Command,
        account: &str,
    ) -> Result<(), String> {
        let acct = resolve_session(account)?;
        cmd.env("HOME", &acct.home)
            .env("USER", &acct.name)
            .env("LOGNAME", &acct.name);
        let mut as_account = drop_body(&acct);
        // SAFETY: see `drop_body`; `no_new_privs` is one more bare syscall.
        unsafe {
            cmd.pre_exec(move || {
                as_account()?;
                #[cfg(target_os = "linux")]
                no_new_privs()?;
                Ok(())
            })
        };
        Ok(())
    }

    /// `PR_SET_NO_NEW_PRIVS` on the calling process: from here on, no exec
    /// gains a privilege, whether by setuid, setgid or a file capability, and
    /// every child inherits it. Async-signal-safe: one syscall, no memory.
    /// The arguments go as `c_ulong`, because `prctl` is variadic and the
    /// kernel refuses this option unless the unused ones are exactly 0.
    #[cfg(all(hive_host, target_os = "linux"))]
    fn no_new_privs() -> std::io::Result<()> {
        // SAFETY: a constant option and four integer arguments.
        let rc = unsafe {
            libc::prctl(
                libc::PR_SET_NO_NEW_PRIVS,
                1 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// FR-85 P1e-unix — an account's uid, primary gid and supplementary
    /// groups, resolved as [`resolve`] resolves them (uid 0 refused).
    #[cfg(target_os = "linux")]
    pub(crate) fn account_ids(
        account: &str,
    ) -> Result<(libc::uid_t, libc::gid_t, Vec<libc::gid_t>), String> {
        let a = resolve(account)?;
        Ok((a.uid, a.gid, a.groups))
    }

    /// FR-90 — an account's home directory, resolved as [`resolve`] resolves
    /// it (uid 0 refused, so a session can never be pointed at root's home).
    #[cfg(any(target_os = "linux", hive_host))]
    pub(crate) fn account_home(account: &str) -> Result<std::path::PathBuf, String> {
        Ok(std::path::PathBuf::from(resolve(account)?.home))
    }

    /// FR-85 P1e-unix — the name of the account with `uid` (`getpwuid_r`,
    /// the buffer grown as [`resolve`] grows its own).
    #[cfg(any(all(target_os = "linux", feature = "recording"), hive_host))]
    pub(crate) fn account_name(uid: libc::uid_t) -> Result<String, String> {
        let mut buf = vec![0 as libc::c_char; 1024];
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        loop {
            // SAFETY: every pointer is to memory this frame owns, sized as
            // passed; the answer points into `buf`, read before it moves.
            let rc = unsafe {
                libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result)
            };
            if rc == libc::ERANGE && buf.len() < 64 * 1024 {
                buf.resize(buf.len() * 2, 0);
                continue;
            }
            if rc != 0 {
                return Err(format!(
                    "looking up uid {uid} failed: {}",
                    std::io::Error::from_raw_os_error(rc)
                ));
            }
            break;
        }
        if result.is_null() {
            return Err(format!("no local account has uid {uid}"));
        }
        // SAFETY: `pw_name` points into `buf`, which is still alive.
        Ok(unsafe { cstr_to_string(pwd.pw_name) })
    }

    unsafe fn cstr_to_string(p: *const libc::c_char) -> String {
        if p.is_null() {
            return String::new();
        }
        unsafe { std::ffi::CStr::from_ptr(p) }
            .to_string_lossy()
            .into_owned()
    }

    /// The drop itself, as a closure a `Command` of either flavour installs.
    ///
    /// Extracted so this body exists exactly ONCE. A second copy would be a
    /// second place to get the ordering below wrong, and — worse — a fix
    /// applied to one copy would silently miss the other, in code whose
    /// failure mode is a child that runs with more privilege than intended
    /// while looking entirely healthy.
    ///
    /// SAFETY: every statement is an async-signal-safe syscall over memory
    /// owned by the closure. No allocation, no locks — see the module docs.
    fn drop_body(acct: &Account) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
        let (uid, gid) = (acct.uid, acct.gid);
        let groups = acct.groups.clone();
        move || {
            // ORDER IS LOAD-BEARING. Supplementary groups and the primary
            // gid must be set BEFORE the uid: after `setuid` the process
            // no longer has the privilege to change either, so a reversed
            // order silently leaves the child in root's groups. That is
            // the classic privilege-retention bug, and it looks like a
            // successful drop from the outside.
            // `as _` on the count: Linux takes `size_t`, macOS takes
            // `c_int`. Same release-only-build reasoning as the buffer
            // above — macOS agent builds happen at tag time, not in CI.
            if unsafe { libc::setgroups(groups.len() as _, groups.as_ptr()) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if unsafe { libc::setgid(gid) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if unsafe { libc::setuid(uid) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Verify rather than assume. `setuid` can succeed partially in
            // some configurations, and a command that runs with more
            // privilege than intended must never start.
            if unsafe { libc::getuid() } != uid || unsafe { libc::geteuid() } != uid {
                return Err(std::io::Error::other("privilege drop did not take effect"));
            }
            Ok(())
        }
    }

    /// The environment a shell needs to behave as that user. Without HOME the
    /// shell writes history and dotfiles into the daemon's home — as the wrong
    /// user, usually failing, occasionally succeeding, which is worse.
    ///
    /// Two near-identical copies below rather than a generic: `tokio`'s and
    /// `std`'s `Command` share no trait, and the three lines carry no
    /// invariant. The part that DOES carry one is `drop_body`, and that is
    /// shared.
    ///
    /// Resolve `account` and arrange for the child to become it.
    /// `pre_exec` here is tokio's own inherent method on `Command`; the
    /// `CommandExt` import that `drop_to_std` needs does not affect it,
    /// because an inherent method wins over a trait method.
    pub(super) fn drop_to(cmd: &mut tokio::process::Command, account: &str) -> Result<(), String> {
        drop_to_in(cmd, account, false)
    }

    /// [`drop_to`], and with `at_home` (FR-97 P5b) the child starts in the
    /// account's home ([`start_in_home`]).
    pub(super) fn drop_to_in(
        cmd: &mut tokio::process::Command,
        account: &str,
        at_home: bool,
    ) -> Result<(), String> {
        let acct = resolve(account)?;
        cmd.env("HOME", &acct.home)
            .env("USER", &acct.name)
            .env("LOGNAME", &acct.name);
        // SAFETY: see `drop_body`.
        unsafe { cmd.pre_exec(drop_body(&acct)) };
        if at_home {
            start_in_home(cmd, &acct);
        }
        Ok(())
    }

    /// FR-97 P5a — [`drop_to`] for `console_user`: `account` is the person at
    /// the screen. A root daemon drops to them. A daemon already running as
    /// them (a per-user install whose owner is at the screen) runs the
    /// command as itself, which changes no identity, and could not drop
    /// anyway: `setgroups` needs root even to keep its own groups. Any other
    /// daemon cannot become them, and says so. uid 0 is refused by
    /// [`resolve`], as for a named account. With `at_home` (P5b) the child
    /// starts in their home.
    pub(super) fn drop_to_console(
        cmd: &mut tokio::process::Command,
        account: &str,
        at_home: bool,
    ) -> Result<(), String> {
        let acct = resolve(account)?;
        // SAFETY: `geteuid` reads the caller's own credentials; it cannot fail.
        let must_drop = console_drop(unsafe { libc::geteuid() }, &acct)?;
        cmd.env("HOME", &acct.home)
            .env("USER", &acct.name)
            .env("LOGNAME", &acct.name);
        if must_drop {
            // SAFETY: see `drop_body`.
            unsafe { cmd.pre_exec(drop_body(&acct)) };
        }
        if at_home {
            start_in_home(cmd, &acct);
        }
        Ok(())
    }

    /// FR-97 P5b — the child starts in `acct`'s home, as sshd starts a
    /// session. Registered AFTER the drop, so it runs as the person: their
    /// own rights decide whether they may enter it (a root-squashed NFS home
    /// refuses root, and would have failed the spawn had the parent's
    /// `current_dir` tried it as root). A home they cannot enter leaves the
    /// child where it was, the daemon's directory, which is sshd's fallback
    /// too; the parent says so in the log when the home is plainly missing.
    /// Async-signal-safe: one syscall over memory the closure owns.
    fn start_in_home(cmd: &mut tokio::process::Command, acct: &Account) {
        if acct.home.is_empty() {
            return;
        }
        if !std::path::Path::new(&acct.home).is_dir() {
            tracing::warn!(
                account = %acct.name, home = %acct.home,
                "the account's home is missing: the session starts in the daemon's directory"
            );
        }
        let Ok(home) = CString::new(acct.home.as_str()) else {
            return;
        };
        // SAFETY: `chdir` over a string the closure owns; its result is
        // deliberately ignored (the fallback above).
        unsafe {
            cmd.pre_exec(move || {
                let _ = libc::chdir(home.as_ptr());
                Ok(())
            })
        };
    }

    /// The pure half of [`drop_to_console`]: must a daemon running as
    /// `daemon` drop to `acct` (`true`), or is it already them (`false`)?
    fn console_drop(daemon: libc::uid_t, acct: &Account) -> Result<bool, String> {
        if daemon == 0 {
            return Ok(true);
        }
        if daemon == acct.uid {
            return Ok(false);
        }
        Err(format!(
            "account_mode `console_user` would run as {}, the person at this machine's screen, \
             and this daemon runs as uid {daemon}, not root, so it cannot become them",
            acct.name
        ))
    }

    /// The same drop for a synchronous `std::process::Command`.
    ///
    /// FR-45's portal helper needs it: that spawn happens on the capture
    /// cascade's synchronous path, and it must reach the console user's
    /// session bus. Going through this rather than a bare `CommandExt::uid`
    /// is the whole point — `uid()` alone leaves the child holding root's
    /// supplementary groups, which is precisely the retention bug `drop_body`
    /// documents. One privilege story, as with exec / pty / sftp.
    ///
    /// Gated to match its consumer — see the re-export above for why.
    #[cfg(target_os = "linux")]
    pub(crate) fn drop_to_std(
        cmd: &mut std::process::Command,
        account: &str,
    ) -> Result<(), String> {
        use std::os::unix::process::CommandExt as _;
        let acct = resolve(account)?;
        cmd.env("HOME", &acct.home)
            .env("USER", &acct.name)
            .env("LOGNAME", &acct.name);
        // SAFETY: see `drop_body`.
        unsafe { cmd.pre_exec(drop_body(&acct)) };
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// FR-97 P5b — a session's child starts in its account's home, and a
        /// home it cannot enter leaves it where it was rather than failing the
        /// spawn (sshd's fallback). The real `chdir`, in a real child.
        #[tokio::test]
        async fn a_session_starts_in_its_home_or_where_it_was() {
            async fn pwd(home: &str) -> String {
                let acct = Account {
                    uid: 0,
                    gid: 0,
                    groups: vec![],
                    home: home.into(),
                    name: "p5b".into(),
                };
                let mut cmd = tokio::process::Command::new("/bin/sh");
                cmd.args(["-c", "pwd -P"]).current_dir("/");
                start_in_home(&mut cmd, &acct);
                let out = cmd.output().await.expect("spawn");
                assert!(out.status.success(), "{out:?}");
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            }
            let home = std::env::temp_dir().join(format!("p5b-home-{}", std::process::id()));
            std::fs::create_dir_all(&home).unwrap();
            let real = std::fs::canonicalize(&home).unwrap();
            assert_eq!(pwd(home.to_str().unwrap()).await, real.to_str().unwrap());
            assert_eq!(
                pwd("/definitely/not/a/home-p5b").await,
                "/",
                "a home it cannot enter leaves it where it was"
            );
            std::fs::remove_dir_all(&home).ok();
        }

        /// FR-97 P5a — `console_user` is a drop, never a gain: a root daemon
        /// drops to the person at the screen, a daemon that is that person
        /// runs as itself, and any other daemon is refused in words that name
        /// the mode and the person.
        #[test]
        fn console_user_drops_from_root_runs_as_itself_and_refuses_otherwise() {
            let person = Account {
                uid: 1000,
                gid: 1000,
                groups: vec![1000, 27],
                home: "/home/ana".into(),
                name: "ana".into(),
            };
            assert_eq!(console_drop(0, &person), Ok(true), "root drops");
            assert_eq!(console_drop(1000, &person), Ok(false), "ana is ana");
            let refused = console_drop(1001, &person).unwrap_err();
            assert!(refused.contains("`console_user`"), "{refused}");
            assert!(refused.contains("would run as ana"), "{refused}");
            assert!(refused.contains("uid 1001, not root"), "{refused}");
        }

        /// FR-90 decision 13 — an agent session holds none of its account's
        /// administrator groups and every other group, in order, and an
        /// account whose primary group is one is refused; gid 0 is always
        /// one, and this host's own root group resolves to it.
        #[cfg(hive_host)]
        #[test]
        fn an_agent_session_holds_no_administrator_group() {
            let acct = |gid, groups: Vec<libc::gid_t>| Account {
                uid: 501,
                gid,
                groups,
                home: "/Users/a".into(),
                name: "a".into(),
            };
            let admin = [0, 80, 27];
            let a = session_view(acct(20, vec![20, 12, 61, 80, 0, 33]), &admin).unwrap();
            assert_eq!(
                a.groups,
                vec![20, 12, 61, 33],
                "macOS's admin and gid 0 leave, in order"
            );
            let refused = session_view(acct(80, vec![80, 20]), &admin).unwrap_err();
            assert!(
                refused.contains("primary group (gid 80) is an administrator group"),
                "{refused}"
            );
            // A full list keeps every group: sudo never reads this list on
            // macOS, so cutting one more would cost a group and stop nothing.
            let sixteen: Vec<libc::gid_t> = (100..116).collect();
            let full = session_view(acct(20, sixteen.clone()), &admin).unwrap();
            assert_eq!(
                full.groups, sixteen,
                "no group but an administrator one leaves"
            );

            assert!(admin_gids().contains(&0));
            assert_eq!(group_gid("roomler-no-such-group-p1h3"), None);
            #[cfg(target_os = "linux")]
            assert_eq!(group_gid("root"), Some(0));
            #[cfg(target_os = "macos")]
            assert_eq!(group_gid("wheel"), Some(0));
        }

        /// FR-90 decision 13 — a child given `no_new_privs` in its pre-exec
        /// runs with the kernel's NoNewPrivs flag set; one without it does
        /// not. The check is the kernel's own word (`/proc/self/status`), so
        /// a call the kernel refused, such as one with wrong arguments, fails
        /// the spawn rather than passing quietly.
        #[cfg(all(hive_host, target_os = "linux"))]
        #[test]
        fn a_session_child_cannot_gain_a_privilege_by_exec() {
            use std::os::unix::process::CommandExt;
            let flag = |set: bool| {
                let mut cmd = std::process::Command::new("/bin/sh");
                cmd.args(["-c", "grep NoNewPrivs /proc/self/status"]);
                if set {
                    // SAFETY: one syscall, as `drop_to_session` makes it.
                    unsafe { cmd.pre_exec(no_new_privs) };
                }
                let out = cmd.output().expect("spawn");
                assert!(out.status.success(), "{out:?}");
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            };
            assert_eq!(flag(true), "NoNewPrivs:\t1");
            // A runner that already runs with the flag (some containers do)
            // hands it to every child, so the control means nothing there.
            let ours = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            if ours.contains("NoNewPrivs:\t0") {
                assert_eq!(flag(false), "NoNewPrivs:\t0");
            }
        }

        /// FR-90 P1h-3 — a group list longer than the system's NGROUPS_MAX
        /// (16 on macOS) loses its tail, in order; a shorter one, or a limit
        /// the system did not give, is untouched; and this host's own limit
        /// is one `setgroups` takes.
        #[test]
        fn a_group_list_is_cut_to_what_setgroups_takes() {
            let seventeen: Vec<libc::gid_t> = (100..117).collect();
            assert_eq!(
                within_ngroups_max(seventeen.clone(), 16),
                (100..116).collect::<Vec<_>>()
            );
            assert_eq!(within_ngroups_max(seventeen.clone(), 65536), seventeen);
            assert_eq!(within_ngroups_max(seventeen.clone(), -1), seventeen);
            assert_eq!(within_ngroups_max(seventeen.clone(), 0), seventeen);
            assert_eq!(within_ngroups_max(vec![20], 16), vec![20]);
            // SAFETY: sysconf takes a constant and touches no memory of ours.
            let here = unsafe { libc::sysconf(libc::_SC_NGROUPS_MAX) };
            assert!(here > 0, "this host gives an NGROUPS_MAX: {here}");
            #[cfg(target_os = "macos")]
            assert_eq!(here, 16, "macOS's NGROUPS_MAX");
        }

        #[test]
        fn root_is_refused_through_the_named_path() {
            // uid 0 by any name must be an explicit `daemon`, never a side
            // effect of naming an account.
            match resolve("root") {
                Err(e) => assert!(e.contains("uid 0"), "unexpected refusal: {e}"),
                Ok(_) => panic!("resolving root as a named account must be refused"),
            }
        }

        #[test]
        fn a_missing_account_is_named_in_the_error() {
            let e = resolve("definitely-not-a-real-account-xyz").unwrap_err();
            assert!(e.contains("no local account"), "unexpected error: {e}");
        }

        #[test]
        fn an_account_with_a_nul_byte_is_refused() {
            let e = resolve("na\0me").unwrap_err();
            assert!(e.contains("NUL"), "unexpected error: {e}");
        }

        /// The primary group is always in the list handed to `setgroups`, so a
        /// child can never end up with fewer privileges than its own group.
        #[test]
        fn a_resolvable_account_carries_its_primary_group() {
            // `nobody` exists on essentially every Linux image, including the
            // CI runner. Skip rather than fail where it doesn't.
            let Ok(acct) = resolve("nobody") else {
                return;
            };
            assert!(acct.uid != 0);
            assert!(
                acct.groups.contains(&acct.gid),
                "primary gid {} missing from {:?}",
                acct.gid,
                acct.groups
            );
        }
    }
}

/// Serialises + bounds every exec on this device.
pub struct ExecEngine {
    sem: Arc<Semaphore>,
    inflight: Mutex<HashMap<String, oneshot::Sender<()>>>,
}

impl Default for ExecEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecEngine {
    pub fn new() -> Self {
        Self {
            sem: Arc::new(Semaphore::new(exec_limits::MAX_CONCURRENT_PER_AGENT)),
            inflight: Mutex::new(HashMap::new()),
        }
    }

    /// Cancel an in-flight request. Returns whether one was found. The run
    /// itself still answers with an `ExecOutcome` carrying `error`, so a
    /// cancelled caller is never left waiting.
    pub async fn cancel(&self, request_id: &str) -> bool {
        match self.inflight.lock().await.remove(request_id) {
            Some(tx) => {
                let _ = tx.send(());
                true
            }
            None => false,
        }
    }

    /// Run one command to completion (or timeout / cancel). Its stdin is
    /// empty (NUL / `/dev/null`), which is what Fleet RPC has always given.
    pub async fn run(&self, req: ExecRequest, redactor: &Redactor) -> ExecOutcome {
        self.run_fed(req, redactor, None).await
    }

    /// [`run`](Self::run), with the command's stdin fed from `stdin` when it
    /// is `Some`: every chunk in order, then end-of-input when the sender is
    /// dropped. Roomler SSH passes the client's stdin here, so
    /// `ssh node 'cat > f' < file` and `tar c . | ssh node 'tar x'` work.
    /// Before, the command read NUL and the client's bytes were dropped
    /// without a word.
    ///
    /// Everything else is unchanged: the same timeout, output ceiling,
    /// redaction and tree-kill. Output is still buffered, so a command that
    /// PROMPTS waits for input the caller cannot see; `ssh -n` is the answer
    /// for commands that must not read stdin.
    pub async fn run_fed(
        &self,
        req: ExecRequest,
        redactor: &Redactor,
        stdin: Option<StdinFeed>,
    ) -> ExecOutcome {
        // FR-55 — hold the machine awake for as long as this command runs.
        // Dropped on EVERY return below (timeout, refusal, spawn failure, a
        // clean exit), which is why it is a guard and not a pair of calls.
        let _awake = crate::power::ActivityGuard::new(crate::power::shared_activity());
        // Re-clamp rather than trust the wire: the server clamps too, but a
        // forged frame reaching a compromised control plane must not be able
        // to ask for an unbounded run.
        let timeout_ms = exec_limits::clamp_timeout_ms(req.timeout_ms);
        let max_output = exec_limits::clamp_output_bytes(req.max_output_bytes);

        let (program, args) = match resolve_shell(&req.shell) {
            Ok(v) => v,
            Err(e) => return ExecOutcome::failed(e),
        };

        // Refuse rather than queue: a caller blocked on a deadline would
        // rather get a fast "busy" than a slow timeout.
        let Ok(_permit) = self.sem.clone().try_acquire_owned() else {
            return ExecOutcome::failed(format!(
                "device is already running {} commands (the per-device limit)",
                exec_limits::MAX_CONCURRENT_PER_AGENT
            ));
        };

        let (cancel_tx, cancel_rx) = oneshot::channel();
        self.inflight
            .lock()
            .await
            .insert(req.request_id.clone(), cancel_tx);

        info!(
            request_id = %req.request_id,
            caller = %req.caller,
            shell = %req.shell,
            timeout_ms,
            "fleet-rpc: running command"
        );

        let started = std::time::Instant::now();
        let cancel = async move {
            let _ = cancel_rx.await;
        };
        let mut outcome = self
            .spawn_and_wait(
                &req,
                program,
                &args,
                Some(timeout_ms),
                Output::Buffered { max_output },
                cancel,
                stdin,
            )
            .await;
        outcome.duration_ms = started.elapsed().as_millis() as u64;

        self.inflight.lock().await.remove(&req.request_id);

        // Redact the bytes, then decode once for the text wire: both views
        // stay the same output, and the byte view stays byte-exact.
        outcome.stdout_bytes = redactor.apply_bytes(&outcome.stdout_bytes);
        outcome.stderr_bytes = redactor.apply_bytes(&outcome.stderr_bytes);
        outcome.stdout = String::from_utf8_lossy(&outcome.stdout_bytes).into_owned();
        outcome.stderr = String::from_utf8_lossy(&outcome.stderr_bytes).into_owned();
        // The error string leaves the host too — it is streamed to an SSH
        // client's stderr and persisted in `exec_audit` for 90 days — so it
        // gets the same treatment as the output. It is agent-generated today
        // and unlikely to carry a secret, but "unlikely" is not a property
        // worth relying on when the redactor is already in hand: an error that
        // interpolates a command line, a path or an env value is one edit away.
        if let Some(err) = outcome.error.take() {
            outcome.error = Some(redactor.apply(&err));
        }

        info!(
            request_id = %req.request_id,
            exit_code = ?outcome.exit_code,
            duration_ms = outcome.duration_ms,
            truncated = outcome.truncated,
            error = ?outcome.error,
            "fleet-rpc: command finished"
        );
        outcome
    }

    /// FR-89 — [`run_fed`](Self::run_fed)'s streaming twin, for Roomler SSH:
    /// the command's output goes to `sink` as it is read, redacted on the
    /// way, with **no ceiling and no wall clock**. `req.timeout_ms` and
    /// `req.max_output_bytes` are ignored; what bounds the run is the caller:
    /// `abort` (the SSH channel closing, the client disconnecting) or
    /// [`cancel`](Self::cancel), either of which kills the process tree. A
    /// sink that is not drained does not end the run either — it stops the
    /// command, which blocks on a full pipe at no cost to the daemon.
    ///
    /// Everything else is `run_fed`'s: the same shell resolution, the same
    /// `RunAs` refusals, the same per-device permit (refuse, never queue), the
    /// same redaction — now over the stream — and the same tree kill. Fleet
    /// RPC never calls this; its wire is one bounded answer.
    pub async fn run_streamed(
        &self,
        req: ExecRequest,
        redactor: &Redactor,
        stdin: Option<StdinFeed>,
        sink: ChunkSink,
        abort: tokio_util::sync::CancellationToken,
    ) -> StreamedOutcome {
        // FR-55 — as in `run_fed`: held for the whole run, dropped on every
        // return below.
        let _awake = crate::power::ActivityGuard::new(crate::power::shared_activity());

        let (program, args) = match resolve_shell(&req.shell) {
            Ok(v) => v,
            Err(e) => return StreamedOutcome::failed(e),
        };
        // The caller went away while this was queued (an SSH channel closed
        // during the consent wait): a command nobody is reading must not
        // start, let alone run to completion as SYSTEM/root.
        if abort.is_cancelled() {
            return StreamedOutcome::failed("the caller went away before the command started");
        }
        let Ok(_permit) = self.sem.clone().try_acquire_owned() else {
            return StreamedOutcome::failed(format!(
                "device is already running {} commands (the per-device limit)",
                exec_limits::MAX_CONCURRENT_PER_AGENT
            ));
        };

        let (cancel_tx, cancel_rx) = oneshot::channel();
        self.inflight
            .lock()
            .await
            .insert(req.request_id.clone(), cancel_tx);

        info!(
            request_id = %req.request_id,
            caller = %req.caller,
            shell = %req.shell,
            "exec: streaming command"
        );

        // Readers → raw (bounded) → the redaction stage → sink (bounded, the
        // caller's). Each bound is small, so a stalled consumer stops the
        // readers within a few chunks and the child blocks on its pipe.
        let (raw_tx, raw_rx) = tokio::sync::mpsc::channel::<Chunk>(RAW_QUEUE);
        let stage = tokio::spawn(redact_stage(raw_rx, redactor.clone(), sink));
        let cancel = async move {
            tokio::select! {
                _ = cancel_rx => {}
                _ = abort.cancelled() => {}
            }
        };

        let started = std::time::Instant::now();
        let outcome = self
            .spawn_and_wait(
                &req,
                program,
                &args,
                None,
                Output::Streamed { raw: raw_tx },
                cancel,
                stdin,
            )
            .await;
        let duration_ms = started.elapsed().as_millis() as u64;
        // Every reader has returned (`spawn_and_wait` joins them) and the last
        // raw sender went with the output mode, so the stage now sees EOF,
        // flushes what it held and drops the sink. Awaited BEFORE the outcome
        // is reported: the consumer must see the last chunk before the exit
        // status.
        let bytes = stage.await.unwrap_or(0);

        self.inflight.lock().await.remove(&req.request_id);

        // The error string leaves the host — see `run_fed`.
        let error = outcome.error.map(|e| redactor.apply(&e));

        info!(
            request_id = %req.request_id,
            exit_code = ?outcome.exit_code,
            duration_ms,
            bytes,
            error = ?error,
            "exec: streamed command finished"
        );
        StreamedOutcome {
            exit_code: outcome.exit_code,
            duration_ms,
            bytes,
            error,
        }
    }

    // 8 params: the resolved shell, the bounds, the output mode, the cancel
    // and the stdin feed are each decided by the caller; a struct would only
    // rename them.
    #[allow(clippy::too_many_arguments)]
    async fn spawn_and_wait(
        &self,
        req: &ExecRequest,
        program: &str,
        args: &[&str],
        timeout_ms: Option<u64>,
        output: Output,
        cancel: impl std::future::Future<Output = ()>,
        stdin: Option<StdinFeed>,
    ) -> ExecOutcome {
        #[cfg(windows)]
        let command = utf8_wrapped(program, &req.command);
        #[cfg(not(windows))]
        let command = req.command.clone();

        // Console-user sessions cannot go through `tokio::process`: on Windows
        // the identity is chosen at `CreateProcessAsUserW` time, so the token
        // has to be supplied at spawn. Everything around this — the permit,
        // the cancel registration, redaction, the duration — is the caller's
        // and is unaffected; the branch only replaces the spawn, and the
        // replacement enforces the same timeout, ceiling and tree-kill.
        #[cfg(windows)]
        if matches!(req.run_as, RunAs::ConsoleUser) {
            // FR-97 P5b — an SSH session with no directory of its own starts
            // in the person's profile, as OpenSSH starts it.
            let start_in = if req.start_in_home && req.cwd.is_none() && ssh_starts_in_home() {
                win_console::StartIn::Profile
            } else {
                win_console::StartIn::Dir(req.cwd.clone())
            };
            return win_console::run(
                program, args, &command, start_in, timeout_ms, output, cancel, stdin,
            )
            .await;
        }

        let mut cmd = tokio::process::Command::new(program);
        cmd.args(args)
            // The caller's command is ONE argv element. Nothing in it can
            // escape into our own argv.
            .arg(&command)
            // A pipe only when someone feeds it; otherwise NUL, as ever, so a
            // command that reads stdin sees end-of-input at once.
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(dir) = &req.cwd {
            cmd.current_dir(dir);
        }
        #[cfg(windows)]
        {
            // CREATE_NO_WINDOW — the daemon may run in an interactive
            // session; a console flashing on the user's desktop for every
            // diagnostic would be its own bug report.
            cmd.creation_flags(0x0800_0000);
        }
        #[cfg(unix)]
        {
            // Lead a new process group so a timeout can signal the whole
            // tree, not just the shell that spawned it.
            cmd.process_group(0);
        }

        // Privilege LAST, so nothing configured after it could quietly undo
        // the drop, and so a refusal costs nothing that was already spawned.
        // FR-97 P5b — an SSH session with no directory of its own starts in
        // the person's home, as sshd starts it.
        let applied = if req.start_in_home && req.cwd.is_none() {
            apply_run_as_at_home(&mut cmd, &req.run_as)
        } else {
            apply_run_as(&mut cmd, &req.run_as)
        };
        if let Err(e) = applied {
            warn!(
                request_id = %req.request_id, caller = %req.caller,
                run_as = %req.run_as.label(),
                "exec: refusing to run — the requested identity is unavailable"
            );
            return ExecOutcome::failed(e);
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return ExecOutcome::failed(format!(
                    "shell {program:?} is not installed on this device"
                ));
            }
            Err(e) => return ExecOutcome::failed(format!("failed to start {program:?}: {e}")),
        };
        let pid = child.id();

        let feeder = stdin.map(|feed| tokio::spawn(feed_child_stdin(child.stdin.take(), feed)));

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let (out_task, err_task) = match output {
            // One shared budget across both streams — "combined ceiling" is
            // what the wire promises, so per-stream caps would silently
            // double it.
            Output::Buffered { max_output } => {
                let budget = Arc::new(AtomicU64::new(max_output));
                (
                    tokio::spawn(read_capped(stdout, budget.clone())),
                    tokio::spawn(read_capped(stderr, budget)),
                )
            }
            Output::Streamed { raw } => (
                tokio::spawn(read_streamed(stdout, OutStream::Stdout, raw.clone())),
                tokio::spawn(read_streamed(stderr, OutStream::Stderr, raw)),
            ),
        };

        // No wall clock (`None`) is an arm that never fires, not a long one:
        // a streamed command's lifetime is its caller's.
        let timeout = async move {
            match timeout_ms {
                Some(ms) => tokio::time::sleep(std::time::Duration::from_millis(ms)).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(timeout);
        tokio::pin!(cancel);

        let (status, error) = tokio::select! {
            res = child.wait() => match res {
                Ok(s) => (Some(s), None),
                Err(e) => (None, Some(format!("waiting for the command failed: {e}"))),
            },
            _ = &mut timeout => {
                kill_tree(&mut child, pid).await;
                (None, Some(format!("timed out after {}ms", timeout_ms.unwrap_or_default())))
            }
            _ = &mut cancel => {
                kill_tree(&mut child, pid).await;
                (None, Some("cancelled by the caller".to_string()))
            }
        };
        // The command is gone. A feeder still waiting on a client that has
        // not sent EOF has nothing left to write to: end it here rather than
        // leaving it parked until the session drops its sender.
        if let Some(feeder) = feeder {
            feeder.abort();
        }

        let (stdout_bytes, out_trunc) = out_task.await.unwrap_or_default();
        let (stderr_bytes, err_trunc) = err_task.await.unwrap_or_default();

        // The text views are filled after redaction (`run_fed`).
        ExecOutcome {
            exit_code: status.and_then(|s| s.code()),
            stdout: String::new(),
            stderr: String::new(),
            stdout_bytes,
            stderr_bytes,
            truncated: out_trunc || err_trunc,
            duration_ms: 0,
            error,
        }
    }
}

/// Copy `feed` into the command's stdin, then close it (end-of-input).
///
/// A failed write means the command stopped reading (it exited, or closed its
/// stdin): the rest of the caller's bytes have nowhere to go, and are dropped
/// with the pipe. The caller aborts this task once the command is gone, so it
/// never waits on a client that never sends EOF.
async fn feed_child_stdin(sin: Option<tokio::process::ChildStdin>, mut feed: StdinFeed) {
    use tokio::io::AsyncWriteExt;
    let Some(mut sin) = sin else {
        return;
    };
    while let Some(chunk) = feed.recv().await {
        if sin.write_all(&chunk).await.is_err() {
            return;
        }
    }
    let _ = sin.flush().await;
    drop(sin);
}

/// How a run's output leaves the spawn path.
enum Output {
    /// Fleet RPC: collect both streams up to ONE combined ceiling, then hand
    /// them back in the outcome.
    Buffered { max_output: u64 },
    /// Roomler SSH (FR-89): hand each read to the redaction stage as it
    /// arrives; the outcome carries no bytes.
    Streamed {
        raw: tokio::sync::mpsc::Sender<Chunk>,
    },
}

/// One pipe read, and so one chunk at most. 32 KiB matches the sftp pump.
const STREAM_READ: usize = 32 * 1024;
/// Raw chunks, both streams, waiting for the redaction stage.
const RAW_QUEUE: usize = 4;
/// How long a held partial word waits for more bytes before the stage
/// flushes it anyway — so a prompt with no trailing newline reaches the
/// caller while the command waits for an answer.
const IDLE_FLUSH: std::time::Duration = std::time::Duration::from_millis(150);

/// Drain one pipe into the raw channel, one chunk per read, with no ceiling.
///
/// A full channel parks this reader, and that IS the backpressure: the OS
/// pipe fills and the child blocks on `write`. Once the receiver is gone the
/// rest is read and discarded, so the child can still finish — or be killed —
/// rather than hang forever on a pipe nobody drains. The return shape matches
/// [`read_capped`] so the two are interchangeable at the join.
async fn read_streamed<R>(
    reader: Option<R>,
    stream: OutStream,
    raw: tokio::sync::mpsc::Sender<Chunk>,
) -> (Vec<u8>, bool)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let Some(mut reader) = reader else {
        return (Vec::new(), false);
    };
    let mut buf = vec![0u8; STREAM_READ];
    let mut delivering = true;
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if delivering
                    && raw
                        .send(Chunk {
                            stream,
                            bytes: buf[..n].to_vec(),
                        })
                        .await
                        .is_err()
                {
                    delivering = false;
                }
            }
        }
    }
    (Vec::new(), false)
}

/// The one place a streamed run's bytes are redacted: raw chunks in, masked
/// chunks out, one [`StreamRedactor`] per stream. Returns the bytes it sent.
///
/// Sitting between the readers and the sink keeps it platform-neutral — the
/// tokio pipes and the Windows console-user drain threads feed the same
/// channel — and gives the idle flush one timer instead of one per reader.
/// Ends when the raw channel closes (every reader is done) or when the sink
/// is gone, in which case it stops at once: a consumer that left is not
/// worth masking for, and dropping the raw receiver is what tells the
/// readers to discard.
async fn redact_stage(
    mut raw: tokio::sync::mpsc::Receiver<Chunk>,
    redactor: Redactor,
    sink: ChunkSink,
) -> u64 {
    let mut out = StreamRedactor::new(&redactor);
    let mut err = StreamRedactor::new(&redactor);
    let mut sent = 0u64;
    loop {
        let next = if out.is_holding() || err.is_holding() {
            match tokio::time::timeout(IDLE_FLUSH, raw.recv()).await {
                Ok(next) => next,
                Err(_waited) => {
                    for (stream, r) in
                        [(OutStream::Stdout, &mut out), (OutStream::Stderr, &mut err)]
                    {
                        let bytes = r.idle_flush();
                        if !bytes.is_empty() {
                            sent += bytes.len() as u64;
                            if sink.send(Chunk { stream, bytes }).await.is_err() {
                                return sent;
                            }
                        }
                    }
                    continue;
                }
            }
        } else {
            raw.recv().await
        };
        match next {
            Some(Chunk { stream, bytes }) => {
                let r = match stream {
                    OutStream::Stdout => &mut out,
                    OutStream::Stderr => &mut err,
                };
                let bytes = r.push(&bytes);
                if !bytes.is_empty() {
                    sent += bytes.len() as u64;
                    if sink.send(Chunk { stream, bytes }).await.is_err() {
                        return sent;
                    }
                }
            }
            None => {
                for (stream, r) in [(OutStream::Stdout, &mut out), (OutStream::Stderr, &mut err)] {
                    let bytes = r.finish();
                    if !bytes.is_empty() {
                        sent += bytes.len() as u64;
                        if sink.send(Chunk { stream, bytes }).await.is_err() {
                            return sent;
                        }
                    }
                }
                return sent;
            }
        }
    }
}

/// Drain one pipe, stopping once the shared budget is spent. Returns
/// `(bytes, truncated)`: the bytes exactly as written, never decoded here.
async fn read_capped<R>(reader: Option<R>, budget: Arc<AtomicU64>) -> (Vec<u8>, bool)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let Some(mut reader) = reader else {
        return (Vec::new(), false);
    };
    let mut collected: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                // Claim from the shared budget; whatever we can't claim is
                // the truncation point.
                let allowed = loop {
                    let left = budget.load(Ordering::Relaxed);
                    let take = (n as u64).min(left);
                    if budget
                        .compare_exchange_weak(
                            left,
                            left - take,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        break take as usize;
                    }
                };
                collected.extend_from_slice(&chunk[..allowed]);
                if allowed < n {
                    truncated = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }
    (collected, truncated)
}

/// Kill the child AND everything it spawned. A diagnostic that shells out
/// must not leave a detached process behind when it times out.
/// Kill a process tree by pid alone.
///
/// Split out of [`kill_tree`] for the console-user path, which owns a raw
/// `OwnedProcess` rather than a `tokio::process::Child` — the tree still has to
/// die, and `TerminateProcess` on the parent alone leaves grandchildren behind.
#[cfg(windows)]
async fn kill_tree_pid(pid: u32) {
    let _ = tokio::process::Command::new("taskkill.exe")
        .args(["/T", "/F", "/PID", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}

async fn kill_tree(child: &mut tokio::process::Child, pid: Option<u32>) {
    #[cfg(windows)]
    {
        if let Some(pid) = pid {
            // `taskkill /T` is the only way to reach grandchildren without
            // building a Job Object around every spawn.
            kill_tree_pid(pid).await;
        }
    }
    #[cfg(unix)]
    {
        if let Some(pid) = pid {
            // Negative pid = the process group we created with
            // `process_group(0)`.
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
    }
    #[cfg(not(any(windows, unix)))]
    let _ = pid;

    if let Err(e) = child.kill().await {
        warn!(%e, "fleet-rpc: killing the command failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> ExecEngine {
        ExecEngine::new()
    }

    // ── Privilege: the identity a command runs as ─────────────────────────

    /// The wire spellings the server sends, and the one rule that matters:
    /// anything we do not understand is an ERROR, never a downgrade to the
    /// daemon's identity.
    #[test]
    fn an_unknown_account_mode_is_refused_not_downgraded() {
        assert_eq!(RunAs::from_wire("daemon", None).unwrap(), RunAs::Daemon);
        assert_eq!(
            RunAs::from_wire("console_user", None).unwrap(),
            RunAs::ConsoleUser
        );
        assert_eq!(
            RunAs::from_wire("named", Some("goran")).unwrap(),
            RunAs::Named("goran".into())
        );

        // A newer server naming a mode this agent has never heard of must not
        // have its intent silently reinterpreted as "run as root".
        let e = RunAs::from_wire("some_future_mode", None).unwrap_err();
        assert!(e.contains("unknown account_mode"), "got {e:?}");

        // `named` with nothing to name is unsatisfiable, and says so.
        let e = RunAs::from_wire("named", None).unwrap_err();
        assert!(e.contains("without an account"), "got {e:?}");
        let e = RunAs::from_wire("named", Some("   ")).unwrap_err();
        assert!(e.contains("without an account"), "got {e:?}");
    }

    #[test]
    fn only_the_daemon_identity_reports_as_privileged() {
        assert!(RunAs::Daemon.is_privileged());
        assert!(!RunAs::Named("nobody".into()).is_privileged());
        assert!(!RunAs::ConsoleUser.is_privileged());
        assert_eq!(RunAs::Named("goran".into()).label(), "named:goran");
    }

    /// A command that cannot be run as the requested identity must FAIL, and
    /// the failure must reach the caller as an error rather than as output
    /// from a process that ran as somebody else.
    #[tokio::test]
    async fn an_unavailable_identity_refuses_instead_of_running_as_the_daemon() {
        let engine = ExecEngine::new();

        // `named` on Windows is structurally impossible. On Unix (FR-97 P5a)
        // `console_user` is impossible wherever nobody is at the screen,
        // which is every CI runner; a desktop running the tests as the
        // person at it can honour it, so there this half proves nothing and
        // says so rather than pass.
        #[cfg(unix)]
        if console_account().is_ok() {
            eprintln!("skipped: someone is at this machine's screen, so console_user can run");
            return;
        }
        let impossible = if cfg!(windows) {
            RunAs::Named("nobody".into())
        } else {
            RunAs::ConsoleUser
        };

        let mut r = req("echo should-never-run");
        r.run_as = impossible;
        let outcome = engine.run(r, &Redactor::default()).await;

        assert!(
            outcome.error.is_some(),
            "an unavailable identity must be an error, got {outcome:?}"
        );
        assert!(
            outcome.exit_code.is_none(),
            "nothing should have been spawned"
        );
        assert!(
            !outcome.stdout.contains("should-never-run"),
            "the command ran despite an unavailable identity — this is the silent-escalation bug"
        );
    }

    /// The default is unchanged, so Fleet RPC behaves exactly as before.
    #[tokio::test]
    async fn the_daemon_identity_still_runs_normally() {
        let engine = ExecEngine::new();
        let outcome = engine
            .run(req("echo run-as-daemon-ok"), &Redactor::default())
            .await;
        assert!(outcome.error.is_none(), "{outcome:?}");
        assert!(outcome.stdout.contains("run-as-daemon-ok"), "{outcome:?}");
    }

    /// On Unix, naming an account that does not exist must be refused BEFORE
    /// anything is spawned — not discovered as a confusing exec failure in the
    /// child.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_nonexistent_unix_account_refuses_before_spawning() {
        let engine = ExecEngine::new();
        let mut r = req("echo should-never-run");
        r.run_as = RunAs::Named("definitely-not-a-real-account-xyz".into());
        let outcome = engine.run(r, &Redactor::default()).await;

        assert!(outcome.error.is_some(), "{outcome:?}");
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("no local account"),
            "the refusal should name the problem, got {:?}",
            outcome.error
        );
        assert!(!outcome.stdout.contains("should-never-run"));
    }

    /// Naming root is refused through the `named` path even though the daemon
    /// IS root — running as root has to be the policy's explicit choice.
    #[cfg(unix)]
    #[tokio::test]
    async fn naming_root_is_refused_even_though_the_daemon_is_root() {
        let engine = ExecEngine::new();
        let mut r = req("echo should-never-run");
        r.run_as = RunAs::Named("root".into());
        let outcome = engine.run(r, &Redactor::default()).await;

        assert!(outcome.error.is_some(), "{outcome:?}");
        assert!(!outcome.stdout.contains("should-never-run"));
    }

    fn req(command: &str) -> ExecRequest {
        ExecRequest {
            request_id: "t1".into(),
            shell: String::new(),
            command: command.into(),
            timeout_ms: 10_000,
            max_output_bytes: 0,
            cwd: None,
            caller: "test".into(),
            run_as: RunAs::Daemon,
            start_in_home: false,
        }
    }

    /// A command that prints `hello` on either platform's auto shell.
    fn echo_hello() -> &'static str {
        if cfg!(windows) {
            "Write-Output hello"
        } else {
            "echo hello"
        }
    }

    /// A command that prints its whole stdin, on either platform's auto shell.
    fn cat_stdin() -> &'static str {
        if cfg!(windows) {
            "[Console]::In.ReadToEnd()"
        } else {
            "cat"
        }
    }

    /// The caller's stdin reaches the command in order, and the caller's
    /// end-of-input ends it (roomler SSH's `ssh node 'cat > f' < file`).
    #[tokio::test]
    async fn a_fed_stdin_reaches_the_command_in_order() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tx.send(b"roomler-".to_vec()).await.unwrap();
        tx.send(b"stdin-ok".to_vec()).await.unwrap();
        drop(tx); // end-of-input
        let out = engine()
            .run_fed(req(cat_stdin()), &Redactor::default(), Some(rx))
            .await;
        assert_eq!(out.error, None, "stderr was: {}", out.stderr);
        assert!(
            out.stdout.contains("roomler-stdin-ok"),
            "the fed bytes never reached the command: stdout {:?}",
            out.stdout
        );
    }

    /// The control, and Fleet RPC's contract: with no feed the command reads
    /// NUL, sees end-of-input at once and prints nothing.
    #[tokio::test]
    async fn without_a_feed_the_command_reads_nothing() {
        let out = engine().run(req(cat_stdin()), &Redactor::default()).await;
        assert_eq!(out.error, None, "stderr was: {}", out.stderr);
        assert_eq!(out.stdout.trim(), "", "stdout was: {:?}", out.stdout);
    }

    /// A feed whose sender stays open must not hold up a command that never
    /// reads it: the command exits and the engine returns.
    #[tokio::test]
    async fn an_open_feed_does_not_hold_up_a_command_that_ignores_it() {
        let (_tx, rx) = tokio::sync::mpsc::channel(4);
        let started = std::time::Instant::now();
        let out = engine()
            .run_fed(req(echo_hello()), &Redactor::default(), Some(rx))
            .await;
        assert_eq!(out.error, None, "stderr was: {}", out.stderr);
        assert!(out.stdout.contains("hello"), "stdout was: {:?}", out.stdout);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(8),
            "the engine waited on the feed: {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn runs_a_command_and_captures_stdout() {
        let out = engine().run(req(echo_hello()), &Redactor::default()).await;
        assert_eq!(out.error, None, "stderr was: {}", out.stderr);
        assert_eq!(out.exit_code, Some(0));
        assert!(out.stdout.contains("hello"), "stdout was: {:?}", out.stdout);
        assert!(!out.truncated);
    }

    #[tokio::test]
    async fn reports_a_nonzero_exit_code() {
        // `exit 3` happens to be spelled the same in PowerShell and bash.
        let out = engine().run(req("exit 3"), &Redactor::default()).await;
        assert_eq!(out.exit_code, Some(3));
        assert_eq!(out.error, None);
    }

    #[tokio::test]
    async fn timeout_kills_and_reports() {
        let cmd = if cfg!(windows) {
            "Start-Sleep -Seconds 30"
        } else {
            "sleep 30"
        };
        let mut r = req(cmd);
        r.timeout_ms = 500;
        let out = engine().run(r, &Redactor::default()).await;
        assert_eq!(out.exit_code, None);
        assert!(
            out.error
                .as_deref()
                .unwrap_or_default()
                .contains("timed out"),
            "error was {:?}",
            out.error
        );
        // The bound is what's promised — a 30 s sleep must not have run to
        // completion.
        assert!(out.duration_ms < 10_000, "took {}ms", out.duration_ms);
    }

    #[tokio::test]
    async fn cancel_stops_an_inflight_command() {
        let cmd = if cfg!(windows) {
            "Start-Sleep -Seconds 30"
        } else {
            "sleep 30"
        };
        let eng = Arc::new(engine());
        let mut r = req(cmd);
        r.request_id = "cancel-me".into();
        r.timeout_ms = 30_000;

        let runner = {
            let eng = eng.clone();
            tokio::spawn(async move { eng.run(r, &Redactor::default()).await })
        };
        // Let it get as far as registering itself.
        for _ in 0..100 {
            if eng.inflight.lock().await.contains_key("cancel-me") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(eng.cancel("cancel-me").await, "request should be in flight");

        let out = runner.await.unwrap();
        assert!(
            out.error
                .as_deref()
                .unwrap_or_default()
                .contains("cancelled"),
            "error was {:?}",
            out.error
        );
        assert!(out.duration_ms < 10_000, "took {}ms", out.duration_ms);
        assert!(!eng.cancel("cancel-me").await, "should be deregistered");
    }

    #[tokio::test]
    async fn output_is_capped_and_flagged() {
        // Emit far more than the cap allows.
        let cmd = if cfg!(windows) {
            "1..2000 | ForEach-Object { 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' }"
        } else {
            "for i in $(seq 1 2000); do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done"
        };
        let mut r = req(cmd);
        r.max_output_bytes = 4096;
        let out = engine().run(r, &Redactor::default()).await;
        assert!(out.truncated, "expected truncation");
        assert!(
            out.output_bytes() <= 4096,
            "captured {} bytes, cap was 4096",
            out.output_bytes()
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn non_ascii_output_survives_a_non_utf8_console_codepage() {
        // Field-caught on WINHOST-A (German locale): `whoami` returns
        // `nt-autorität\system`, which PowerShell wrote in the host ANSI
        // codepage and our lossy decode turned into `nt-autorit<?>t\system`.
        // A diagnostic that garbles the machine's own output is worse than
        // useless — it invites the reader to doubt the tool, not the finding.
        let out = engine()
            .run(req("Write-Output 'ä ö ü ß — 日本'"), &Redactor::default())
            .await;
        assert_eq!(out.error, None, "stderr: {}", out.stderr);
        assert!(
            out.stdout.contains("ä ö ü ß"),
            "non-ASCII was mangled: {:?}",
            out.stdout
        );
        assert!(
            !out.stdout.contains('\u{FFFD}'),
            "replacement chars in output: {:?}",
            out.stdout
        );
    }

    #[cfg(windows)]
    #[test]
    fn utf8_prefix_is_shell_appropriate() {
        assert!(utf8_wrapped("powershell.exe", "X").starts_with("[Console]::OutputEncoding"));
        assert!(utf8_wrapped("pwsh.exe", "X").starts_with("[Console]::OutputEncoding"));
        assert!(utf8_wrapped("cmd.exe", "X").starts_with("chcp 65001"));
        // The caller's command is still there, unmodified, at the end.
        assert!(utf8_wrapped("cmd.exe", "echo hi").ends_with("echo hi"));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn utf8_prefix_does_not_disturb_the_exit_code() {
        // The prefix is an assignment before the caller's command; PowerShell
        // must still report the command's own exit code.
        let out = engine().run(req("exit 7"), &Redactor::default()).await;
        assert_eq!(out.exit_code, Some(7), "error: {:?}", out.error);
    }

    #[tokio::test]
    async fn unknown_shell_is_a_clean_error_not_a_panic() {
        let mut r = req("whatever");
        r.shell = "zsh-from-buildhost".into();
        let out = engine().run(r, &Redactor::default()).await;
        assert!(
            out.error
                .as_deref()
                .unwrap_or_default()
                .contains("unsupported shell"),
            "error was {:?}",
            out.error
        );
        assert_eq!(out.exit_code, None);
    }

    #[tokio::test]
    async fn concurrency_cap_refuses_rather_than_queues() {
        let cmd = if cfg!(windows) {
            "Start-Sleep -Seconds 5"
        } else {
            "sleep 5"
        };
        let eng = Arc::new(engine());
        let mut runners = Vec::new();
        for i in 0..exec_limits::MAX_CONCURRENT_PER_AGENT {
            let eng = eng.clone();
            let mut r = req(cmd);
            r.request_id = format!("hog-{i}");
            runners.push(tokio::spawn(async move {
                eng.run(r, &Redactor::default()).await
            }));
        }
        // Wait for the slots to actually be taken.
        for _ in 0..200 {
            if eng.inflight.lock().await.len() == exec_limits::MAX_CONCURRENT_PER_AGENT {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let mut extra = req(echo_hello());
        extra.request_id = "one-too-many".into();
        let refused = eng.run(extra, &Redactor::default()).await;
        assert!(
            refused
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("already running"),
            "error was {:?}",
            refused.error
        );

        for i in 0..exec_limits::MAX_CONCURRENT_PER_AGENT {
            eng.cancel(&format!("hog-{i}")).await;
        }
        for r in runners {
            let _ = r.await;
        }
    }

    // ─── Redaction ───────────────────────────────────────────────────
    //
    // Every fixture below is ASSEMBLED AT RUNTIME rather than written as a
    // string literal. These tests are about secret-SHAPED text by definition,
    // and a secret-shaped literal in the source trips repo scanners on every
    // push — a permanently red security check trains people to ignore
    // security checks. The shape is what the tests need, never the payload.

    /// A secret-shaped string of `n` characters, built so no literal in this
    /// file ever looks like a credential.
    fn shaped(seed: &str, n: usize) -> String {
        seed.chars().cycle().take(n).collect()
    }

    #[test]
    fn apply_bytes_leaves_binary_output_byte_exact() {
        // The 2026-10-06 bug: an MP4 fetched with `ssh <node> cat f > f`
        // arrived as U+FFFD noise, because the output was decoded to text
        // before it went down the channel.
        let r = Redactor::new(["a-registered-secret".to_string()]);
        let binary: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        assert_eq!(r.apply_bytes(&binary), binary);
    }

    #[test]
    fn apply_bytes_masks_text_exactly_like_apply() {
        let r = Redactor::new(["a-registered-secret".to_string()]);
        // Built at run time, as in `redacts_jwt_shaped_strings`: a token-shaped
        // LITERAL in the source is what a secret scanner flags on every commit.
        let jwt = [
            shaped("headerpart", 20),
            shaped("payloadpart", 19),
            shaped("signaturepart", 28),
        ]
        .join(".");
        for sample in [
            "plain output".to_string(),
            "token a-registered-secret here".to_string(),
            format!("Authorization: Bearer {}", shaped("bearertoken", 24)),
            format!("token: {jwt} end"),
        ] {
            assert_eq!(
                r.apply_bytes(sample.as_bytes()),
                r.apply(&sample).into_bytes(),
                "{sample}"
            );
        }
    }

    #[test]
    fn apply_bytes_masks_a_secret_between_binary_bytes() {
        let r = Redactor::new(["a-registered-secret".to_string()]);
        let mut input = vec![0xff, 0xfe, 0x00];
        input.extend_from_slice(b"key=a-registered-secret;");
        input.extend_from_slice(&[0x80, 0xc3]);
        let mut want = vec![0xff, 0xfe, 0x00];
        want.extend_from_slice(b"key=[redacted];");
        want.extend_from_slice(&[0x80, 0xc3]);
        assert_eq!(r.apply_bytes(&input), want);
    }

    /// End to end: the byte view of a real run is what the command wrote, and
    /// the text view is its lossy decode for the JSON wire.
    #[cfg(unix)]
    #[tokio::test]
    async fn binary_output_survives_the_engine_byte_exact() {
        let engine = ExecEngine::new();
        let outcome = engine
            .run(req(r"printf '\377\000\200ok'"), &Redactor::default())
            .await;
        assert_eq!(outcome.stdout_bytes, b"\xff\x00\x80ok", "{outcome:?}");
        assert!(outcome.stdout.contains('\u{fffd}'), "{outcome:?}");
    }

    #[test]
    fn redacts_literal_secrets() {
        let token = shaped("agenttoken", 24);
        let r = Redactor::new([token.clone()]);
        let out = r.apply(&format!("token={token} trailing"));
        assert!(!out.contains(&token), "{out}");
        assert!(out.contains(MASK), "{out}");
        assert!(out.contains("trailing"), "surrounding text survives: {out}");
    }

    #[test]
    fn short_literals_are_not_masked() {
        // Masking a 3-char "secret" would shred ordinary output for no gain.
        let r = Redactor::new(["abc".to_string()]);
        assert_eq!(r.apply("abc def"), "abc def");
    }

    #[test]
    fn redacts_bearer_tokens_case_insensitively() {
        let r = Redactor::default();
        let token = shaped("bearervalue", 16);
        let out = r.apply(&format!("Authorization: Bearer {token}\nnext line"));
        assert!(!out.contains(&token), "{out}");
        assert!(out.contains("Bearer [redacted]"), "{out}");
        assert!(out.contains("next line"), "{out}");

        let out = r.apply(&format!("authorization: bearer {token}"));
        assert!(!out.contains(&token), "{out}");
    }

    #[test]
    fn redacts_jwt_shaped_strings() {
        let r = Redactor::default();
        let jwt = [
            shaped("headerpart", 20),
            shaped("payloadpart", 19),
            shaped("signaturepart", 28),
        ]
        .join(".");
        let out = r.apply(&format!("token: {jwt} end"));
        assert!(!out.contains(&jwt), "{out}");
        assert!(out.contains(MASK), "{out}");
        assert!(out.contains("end"), "{out}");
    }

    #[test]
    fn ordinary_output_survives_redaction() {
        // The redactor is over-eager by design; it still must not mangle a
        // route table or a version string.
        let r = Redactor::default();
        for sample in [
            "0.0.0.0/0 via 192.168.68.1 dev eth0",
            "roomlerd 0.3.0-rc.310",
            "Ethernet 2   Up   00-15-5D-01-02-03",
            "a.b.c",
            "file.tar.gz",
        ] {
            assert_eq!(r.apply(sample), sample, "mangled: {sample}");
        }
    }

    // ─── Streaming redaction (FR-89) ─────────────────────────────────────
    //
    // The one property that matters: a secret must not slip through the gap
    // between two chunks. So every case drives a secret through a 2-chunk
    // split at EVERY offset and through fine chunking, and asserts the
    // concatenated stream equals the whole-input redaction.

    /// Feed `input` to a fresh `StreamRedactor` in pieces of `size`, then
    /// finish; return everything it emitted.
    fn stream_in_pieces(r: &Redactor, input: &[u8], size: usize) -> Vec<u8> {
        let mut sr = StreamRedactor::new(r);
        let mut out = Vec::new();
        for piece in input.chunks(size.max(1)) {
            out.extend_from_slice(&sr.push(piece));
        }
        out.extend_from_slice(&sr.finish());
        out
    }

    /// Feed `input` as exactly two chunks split at `at`.
    fn stream_split_at(r: &Redactor, input: &[u8], at: usize) -> Vec<u8> {
        let mut sr = StreamRedactor::new(r);
        let mut out = sr.push(&input[..at]);
        out.extend_from_slice(&sr.push(&input[at..]));
        out.extend_from_slice(&sr.finish());
        out
    }

    #[test]
    fn stream_masks_a_literal_split_at_every_offset() {
        let token = shaped("agenttoken", 24);
        let r = Redactor::new([token.clone()]);
        let whole = format!("prefix {token} suffix");
        let want = r.apply_bytes(whole.as_bytes());
        assert!(!want.windows(token.len()).any(|w| w == token.as_bytes()));
        for at in 0..=whole.len() {
            assert_eq!(
                stream_split_at(&r, whole.as_bytes(), at),
                want,
                "a 2-chunk split at offset {at} leaked or mangled the secret"
            );
        }
    }

    #[test]
    fn stream_masks_a_bearer_token_split_at_every_offset() {
        let r = Redactor::default();
        let token = shaped("bearervalue", 20);
        // The space after `Bearer` is the exact boundary the pull-back
        // exists for: settled alone, the token would reach the next chunk
        // with no prefix to key on.
        let whole = format!("Authorization: Bearer {token}\r\nnext");
        let want = r.apply_bytes(whole.as_bytes());
        assert!(want.windows(token.len()).all(|w| w != token.as_bytes()));
        for at in 0..=whole.len() {
            assert_eq!(
                stream_split_at(&r, whole.as_bytes(), at),
                want,
                "bearer token leaked at split offset {at}"
            );
        }
    }

    #[test]
    fn stream_masks_a_jwt_split_at_every_offset() {
        let r = Redactor::default();
        let jwt = [
            shaped("headerpart", 20),
            shaped("payloadpart", 19),
            shaped("signaturepart", 28),
        ]
        .join(".");
        let whole = format!("token: {jwt} end");
        let want = r.apply_bytes(whole.as_bytes());
        assert!(want.windows(16).all(|w| w != &jwt.as_bytes()[..16]));
        for at in 0..=whole.len() {
            assert_eq!(
                stream_split_at(&r, whole.as_bytes(), at),
                want,
                "jwt leaked at split offset {at}"
            );
        }
        // And through 1..7-byte chunking, the worst case for a carry.
        for size in 1..=7 {
            assert_eq!(
                stream_in_pieces(&r, whole.as_bytes(), size),
                want,
                "size {size}"
            );
        }
    }

    #[test]
    fn stream_leaves_binary_byte_exact_through_a_split() {
        let r = Redactor::new([shaped("agenttoken", 16)]);
        // Every byte value, no whitespace run a cut could settle on cleanly,
        // and not valid UTF-8 — the passthrough path.
        let binary: Vec<u8> = (0u8..=255).cycle().take(5000).collect();
        let want = r.apply_bytes(&binary);
        assert_eq!(want, binary, "binary must be identity under redaction");
        for size in [1usize, 7, 64, 4096] {
            assert_eq!(
                stream_in_pieces(&r, &binary, size),
                binary,
                "binary mangled at chunk size {size}"
            );
        }
    }

    #[test]
    fn stream_force_settles_a_long_whitespace_free_run_without_leaking_a_literal() {
        // A run longer than CARRY_CAP must settle in pieces rather than grow
        // the carry forever — and a literal inside it, wherever it falls,
        // must still be masked.
        let token = shaped("agenttoken", 24);
        let r = Redactor::new([token.clone()]);
        let mut whole = vec![b'x'; CARRY_CAP + 50_000];
        // Drop the token in two places: early (settled in an early forced
        // cut) and late (still in the carry at EOF).
        whole[10_000..10_000 + token.len()].copy_from_slice(token.as_bytes());
        let tail = whole.len() - token.len();
        whole[tail..].copy_from_slice(token.as_bytes());
        let streamed = stream_in_pieces(&r, &whole, 8192);
        assert_eq!(
            streamed,
            r.apply_bytes(&whole),
            "the forced-cut path diverged from a whole-input redaction"
        );
        assert!(
            streamed.windows(token.len()).all(|w| w != token.as_bytes()),
            "a literal leaked through a forced cut"
        );
    }

    #[test]
    fn stream_holds_a_partial_literal_at_a_forced_cut() {
        // The test above never ends a forcing push mid-literal: both of its
        // tokens are complete by the time a cut happens, so the literal pass
        // masks them and the hold-back is never consulted. Here the first
        // part of a literal ENDS the push that forces the cut, at every split
        // offset. Only the hold-back keeps that part off the wire: the
        // literal pass can mask only what is complete.
        let token = shaped("agenttoken", 24);
        let r = Redactor::new([token.clone()]);
        for k in 1..token.len() {
            let mut first = vec![b'x'; CARRY_CAP + 100];
            first.extend_from_slice(&token.as_bytes()[..k]);
            let mut rest = token.as_bytes()[k..].to_vec();
            rest.extend_from_slice(b" tail\n");

            let mut sr = StreamRedactor::new(&r);
            let mut out = sr.push(&first);
            assert!(
                !out.is_empty(),
                "the push did not force a cut, so this case proves nothing"
            );
            out.extend_from_slice(&sr.push(&rest));
            out.extend_from_slice(&sr.finish());

            let mut whole = first.clone();
            whole.extend_from_slice(&rest);
            assert_eq!(out, r.apply_bytes(&whole), "split at {k}");
            assert!(
                !out.windows(token.len()).any(|w| w == token.as_bytes()),
                "the literal leaked through a forced cut split at {k}"
            );
        }
    }

    #[test]
    fn stream_idle_flush_releases_a_prompt_but_holds_a_partial_secret() {
        let token = shaped("agenttoken", 24);
        let r = Redactor::new([token.clone()]);
        let mut sr = StreamRedactor::new(&r);

        // A prompt whose last word has no trailing whitespace would sit in
        // the carry forever without the idle flush. `push` settles only up to
        // the last whitespace — here, up to and including the space after
        // "Continue?" — and holds the trailing "[y/N]"; the idle flush then
        // releases the rest, so the whole prompt reaches the caller.
        let prompt = b"Continue? [y/N]";
        let mut got = sr.push(prompt);
        assert!(
            sr.is_holding(),
            "the trailing word with no whitespace after it must wait"
        );
        got.extend_from_slice(&sr.idle_flush());
        assert_eq!(
            got,
            r.apply_bytes(prompt),
            "the prompt must reach the caller whole after an idle flush"
        );
        assert!(!sr.is_holding(), "a second idle timer would be pointless");

        // But a token still arriving is held: the first half of the literal
        // must NOT be flushed, or the second half arrives unmatched.
        let mut sr = StreamRedactor::new(&r);
        let half = &token.as_bytes()[..token.len() / 2];
        let shown = sr.push(half);
        let flushed = sr.idle_flush();
        let mut got = shown;
        got.extend_from_slice(&flushed);
        assert!(
            !got.windows(half.len()).any(|w| w == half),
            "the idle flush emitted the start of a secret: it must hold a literal prefix"
        );
        // …and it completes correctly once the rest arrives: the whole token
        // ends up masked, with no half of it left in the clear.
        let rest = &token.as_bytes()[token.len() / 2..];
        got.extend_from_slice(&sr.push(rest));
        got.extend_from_slice(&sr.finish());
        let got_text = String::from_utf8_lossy(&got);
        assert!(
            got_text.contains(MASK),
            "the completed token should have been masked: {got_text:?}"
        );
        assert!(
            !got.windows(token.len()).any(|w| w == token.as_bytes()),
            "the token leaked across the idle flush: {got_text:?}"
        );
    }

    #[test]
    fn stream_matches_apply_bytes_on_ordinary_output() {
        // The redactor is over-eager by design; streaming it must not mangle
        // a route table, a version string or a path any worse than `apply`.
        let r = Redactor::new([shaped("agenttoken", 16)]);
        for sample in [
            "0.0.0.0/0 via 192.168.68.1 dev eth0\nroomlerd 0.4.116\n".as_bytes(),
            b"a.b.c file.tar.gz\n",
            b"line one\nline two\nline three\n",
        ] {
            let want = r.apply_bytes(sample);
            for size in [1usize, 3, 13, 64] {
                assert_eq!(
                    stream_in_pieces(&r, sample, size),
                    want,
                    "ordinary output diverged at chunk size {size}"
                );
            }
        }
    }

    // ─── The streaming engine (FR-89) ────────────────────────────────────

    /// Collect a streamed run's output and outcome, with no abort.
    async fn run_streamed_collect(
        eng: &ExecEngine,
        req: ExecRequest,
    ) -> (StreamedOutcome, Vec<u8>, Vec<u8>) {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Chunk>(8);
        let collector = tokio::spawn(async move {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            while let Some(c) = rx.recv().await {
                match c.stream {
                    OutStream::Stdout => out.extend_from_slice(&c.bytes),
                    OutStream::Stderr => err.extend_from_slice(&c.bytes),
                }
            }
            (out, err)
        });
        let outcome = eng
            .run_streamed(
                req,
                &Redactor::default(),
                None,
                tx,
                tokio_util::sync::CancellationToken::new(),
            )
            .await;
        let (out, err) = collector.await.unwrap();
        (outcome, out, err)
    }

    #[tokio::test]
    async fn streamed_run_delivers_stdout_and_a_zero_exit() {
        let (outcome, out, _err) = run_streamed_collect(&engine(), req(echo_hello())).await;
        assert_eq!(outcome.error, None, "{outcome:?}");
        assert_eq!(outcome.exit_code, Some(0));
        assert!(
            String::from_utf8_lossy(&out).contains("hello"),
            "stdout was {out:?}"
        );
        assert!(outcome.bytes > 0);
    }

    #[tokio::test]
    async fn streamed_run_ignores_the_output_ceiling() {
        // Far more than MAX_OUTPUT_BYTES: the buffered path would truncate at
        // 1 MiB, the streamed path must deliver all of it.
        let cmd = if cfg!(windows) {
            "1..40000 | ForEach-Object { 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' }"
        } else {
            "for i in $(seq 1 40000); do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; done"
        };
        let mut r = req(cmd);
        // Even a tiny requested ceiling must be ignored by the streamed path.
        r.max_output_bytes = 4096;
        let (outcome, out, _err) = run_streamed_collect(&engine(), r).await;
        assert_eq!(outcome.error, None, "{outcome:?}");
        assert!(
            out.len() > 1024 * 1024,
            "streamed output was capped at {} bytes — the ceiling was not ignored",
            out.len()
        );
    }

    #[tokio::test]
    async fn streamed_run_has_no_wall_clock() {
        // A command that sleeps well past MAX_TIMEOUT_MS would be killed by
        // the buffered path; the streamed path must let it finish. (Kept
        // short in wall-clock terms — the point is that `timeout_ms` is not
        // consulted, which a 2 s sleep with a 10 ms requested timeout proves.)
        let cmd = if cfg!(windows) {
            "Start-Sleep -Milliseconds 1500; Write-Output done"
        } else {
            "sleep 1.5; echo done"
        };
        let mut r = req(cmd);
        r.timeout_ms = 10; // would kill it instantly if it were honoured
        let (outcome, out, _err) = run_streamed_collect(&engine(), r).await;
        assert_eq!(outcome.error, None, "{outcome:?}");
        assert_eq!(outcome.exit_code, Some(0));
        assert!(String::from_utf8_lossy(&out).contains("done"), "{out:?}");
    }

    #[tokio::test]
    async fn streamed_run_is_redacted() {
        let token = shaped("agenttoken", 24);
        let redactor = Redactor::new([token.clone()]);
        let cmd = if cfg!(windows) {
            format!("Write-Output 'tok={token} end'")
        } else {
            format!("echo 'tok={token} end'")
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Chunk>(8);
        let collector = tokio::spawn(async move {
            let mut out = Vec::new();
            while let Some(c) = rx.recv().await {
                out.extend_from_slice(&c.bytes);
            }
            out
        });
        let outcome = engine()
            .run_streamed(
                req(&cmd),
                &redactor,
                None,
                tx,
                tokio_util::sync::CancellationToken::new(),
            )
            .await;
        let out = collector.await.unwrap();
        assert_eq!(outcome.error, None, "{outcome:?}");
        assert!(
            !out.windows(token.len()).any(|w| w == token.as_bytes()),
            "the secret reached the sink unredacted: {:?}",
            String::from_utf8_lossy(&out)
        );
        assert!(String::from_utf8_lossy(&out).contains(MASK));
    }

    #[tokio::test]
    async fn streamed_run_aborts_and_kills_the_command() {
        let cmd = if cfg!(windows) {
            "Start-Sleep -Seconds 30"
        } else {
            "sleep 30"
        };
        let (tx, _rx) = tokio::sync::mpsc::channel::<Chunk>(8);
        let abort = tokio_util::sync::CancellationToken::new();
        let eng = Arc::new(engine());
        let runner = {
            let eng = eng.clone();
            let abort = abort.clone();
            tokio::spawn(async move {
                eng.run_streamed(req(cmd), &Redactor::default(), None, tx, abort)
                    .await
            })
        };
        // Let it reach the process, then abort as the SSH channel-close path
        // does.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        abort.cancel();
        let started = std::time::Instant::now();
        let outcome = runner.await.unwrap();
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("cancelled"),
            "error was {:?}",
            outcome.error
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "abort did not stop the 30 s sleep promptly ({:?})",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_streamed_run_refuses_an_already_cancelled_caller() {
        // The SSH channel closed during the consent wait: the command must
        // not start at all.
        let (tx, _rx) = tokio::sync::mpsc::channel::<Chunk>(8);
        let abort = tokio_util::sync::CancellationToken::new();
        abort.cancel();
        let outcome = engine()
            .run_streamed(req(echo_hello()), &Redactor::default(), None, tx, abort)
            .await;
        assert!(
            outcome.error.is_some(),
            "a cancelled caller must not run the command"
        );
        assert_eq!(outcome.exit_code, None, "nothing should have been spawned");
    }

    #[tokio::test]
    async fn streamed_stdin_reaches_the_command() {
        let (sin_tx, sin_rx) = tokio::sync::mpsc::channel(4);
        sin_tx.send(b"streamed-".to_vec()).await.unwrap();
        sin_tx.send(b"stdin-ok".to_vec()).await.unwrap();
        drop(sin_tx);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Chunk>(8);
        let collector = tokio::spawn(async move {
            let mut out = Vec::new();
            while let Some(c) = rx.recv().await {
                if c.stream == OutStream::Stdout {
                    out.extend_from_slice(&c.bytes);
                }
            }
            out
        });
        let outcome = engine()
            .run_streamed(
                req(cat_stdin()),
                &Redactor::default(),
                Some(sin_rx),
                tx,
                tokio_util::sync::CancellationToken::new(),
            )
            .await;
        let out = collector.await.unwrap();
        assert_eq!(outcome.error, None, "{outcome:?}");
        assert!(
            String::from_utf8_lossy(&out).contains("streamed-stdin-ok"),
            "fed stdin did not reach the command: {out:?}"
        );
    }

    #[test]
    fn outcome_hash_separates_the_two_streams() {
        let a = ExecOutcome {
            stdout: "one".into(),
            stderr: "two".into(),
            ..Default::default()
        };
        let b = ExecOutcome {
            stdout: "onetwo".into(),
            stderr: String::new(),
            ..Default::default()
        };
        // Identical concatenation, materially different runs: "printed two on
        // stderr" vs "printed nothing on stderr". The audit hash must tell
        // them apart.
        assert_eq!(a.output_bytes(), b.output_bytes());
        assert_ne!(a.output_sha256(), b.output_sha256());
        assert_eq!(a.output_sha256().len(), 64);
    }
}

/// Running a command as the signed-in console user (roomler SSH P5b).
///
/// Windows has no way to hand `tokio::process::Command` a token — the identity
/// is chosen at `CreateProcessAsUserW` time — so this path cannot reuse the
/// ordinary spawn. It reuses everything else: the caller has already taken the
/// concurrency permit and registered the cancel channel, and it enforces the
/// same wall-clock timeout, the same COMBINED output ceiling and the same
/// process-tree kill, so a session here is bounded exactly like Fleet RPC.
///
/// Requires the caller to be SYSTEM (`WTSQueryUserToken` returns
/// `ERROR_PRIVILEGE_NOT_HELD` otherwise): the SYSTEM service, or a
/// SystemContext worker. An attended worker runs as the signed-in user even
/// under a perMachine install (FR-94 §2), so on such a device Fleet RPC
/// reaches this through the anchored service (`crate::exec_service`). That is
/// reported as a refusal, not a fallback — see [`RunAs`].
#[cfg(windows)]
mod win_console {
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;

    use super::{Chunk, ExecOutcome, OutStream, Output};
    use crate::win_service::supervisor;

    /// Build the command line `CreateProcessAsUserW` receives.
    ///
    /// Quoting matters more here than in the ordinary path: there is no argv
    /// array, only one string the child re-parses. The command itself is
    /// wrapped in double quotes with any embedded `"` doubled, which is what
    /// both `cmd` and PowerShell expect for a single argument.
    pub(super) fn build_cmdline(program: &str, args: &[&str], command: &str) -> String {
        let mut s = String::with_capacity(program.len() + command.len() + 32);
        s.push('"');
        s.push_str(program);
        s.push('"');
        for a in args {
            s.push(' ');
            s.push_str(a);
        }
        s.push(' ');
        s.push('"');
        s.push_str(&command.replace('"', "\"\""));
        s.push('"');
        s
    }

    /// FR-97 P4b — the command line for running `program` itself: the quoted
    /// path and nothing else. No shell stands in front of it and no command
    /// argument follows, so nothing a caller sends can become an argument. A
    /// path that holds a `"` (Windows allows none) is refused rather than
    /// escaped.
    #[cfg(feature = "ssh-server")]
    pub(super) fn build_program_cmdline(program: &str) -> Option<String> {
        (!program.contains('"')).then(|| format!("\"{program}\""))
    }

    /// Where the child starts.
    pub(super) enum StartIn {
        /// The caller's directory, or (`None`) this process's own.
        Dir(Option<String>),
        /// FR-97 P4b — the console user's profile, read from the token the
        /// child runs under. OpenSSH starts `sftp-server` in the user's home,
        /// and an SFTP client resolves every relative path against wherever
        /// it started: inheriting this process's directory (System32, for a
        /// service) would send a bare `put` somewhere the user cannot write.
        /// P5b: an SSH command with no directory of its own starts there too.
        Profile,
    }

    /// The console user, as [`run_cmdline`] does for a shell command, but for
    /// `program` itself (FR-97 P4b, `sftp-server`), started in their profile.
    #[cfg(feature = "ssh-server")]
    pub(super) async fn run_program(
        program: &str,
        output: Output,
        cancel: impl std::future::Future<Output = ()>,
        stdin: Option<super::StdinFeed>,
    ) -> ExecOutcome {
        let Some(cmdline) = build_program_cmdline(program) else {
            return ExecOutcome::failed(format!("not a program path: {program}"));
        };
        run_cmdline(cmdline, StartIn::Profile, None, output, cancel, stdin).await
    }

    /// Spawn a shell command as the console user ([`run_cmdline`]), started
    /// in `start_in`.
    // 8 params: the same set `spawn_and_wait` hands over, one for one.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn run(
        program: &str,
        args: &[&str],
        command: &str,
        start_in: StartIn,
        timeout_ms: Option<u64>,
        output: Output,
        cancel: impl std::future::Future<Output = ()>,
        stdin: Option<super::StdinFeed>,
    ) -> ExecOutcome {
        let cmdline = build_cmdline(program, args, command);
        run_cmdline(cmdline, start_in, timeout_ms, output, cancel, stdin).await
    }

    /// Spawn as the console user, drain both pipes, enforce the bounds.
    ///
    /// FR-89: `output` decides the drain — to a `Vec` against the combined
    /// budget (Fleet RPC), or chunk by chunk into the redaction stage's raw
    /// channel (Roomler SSH), through the very same three pipes. The
    /// `docs/roomler-ssh.md` note that `CreateProcessAsUserW` had "no pipes
    /// variant" was outdated the day this module shipped (P5b); what was
    /// missing was a drain that hands bytes on instead of collecting them.
    async fn run_cmdline(
        cmdline: String,
        start_in: StartIn,
        timeout_ms: Option<u64>,
        output: Output,
        cancel: impl std::future::Future<Output = ()>,
        stdin: Option<super::StdinFeed>,
    ) -> ExecOutcome {
        let with_stdin = stdin.is_some();

        let Some(session) = supervisor::active_console_session_id() else {
            return ExecOutcome::failed(
                "no user is signed in at the console, so there is no session to run as. \
                 Set the device's SSH policy to `daemon` if a SYSTEM session is intended.",
            );
        };

        let token = match supervisor::query_user_token(session) {
            Ok(Some(t)) => t,
            Ok(None) => {
                return ExecOutcome::failed(format!(
                    "console session {session} has no user token (nobody is signed in at the \
                     console); nothing to run as"
                ));
            }
            Err(e) => {
                // The overwhelmingly likely cause is this process not running
                // as SYSTEM, so say that rather than echoing a bare error
                // number — and not "install perMachine": an attended
                // perMachine worker is the signed-in user too (FR-94 §2).
                return ExecOutcome::failed(format!(
                    "cannot obtain the console user's token ({e}): only a process running as \
                     SYSTEM may. On an attended Windows install the worker runs as the signed-in \
                     user; anchor the device (`roomlerd anchor create`) so commands run through \
                     its SYSTEM service."
                ));
            }
        };

        let cwd = match start_in {
            StartIn::Dir(dir) => dir,
            // The same token, so the directory is the profile of the account
            // the child becomes even if the console changes hands meanwhile.
            // Unreadable, it starts where this process is: the child is still
            // the user, so that costs a relative path, never a privilege.
            StartIn::Profile => {
                let dir = crate::win_identity::profile_dir_of_token(token.raw());
                if dir.is_none() {
                    tracing::warn!(session, "console user's profile directory unreadable");
                }
                dir
            }
        };

        // Everything Win32 happens on ONE blocking thread that owns the child,
        // and hands back the pieces the async side needs. `spawn_blocking`
        // rather than inline: `CreateProcessAsUserW`, `ReadFile` and
        // `WaitForSingleObject` all block, and blocking the runtime here would
        // stall every other session on this device.
        let spawned = tokio::task::spawn_blocking(move || {
            // SAFETY: `token` is a live user token, alive for the call.
            let child = unsafe {
                supervisor::spawn_in_session_captured(
                    token.raw(),
                    &cmdline,
                    cwd.as_deref().map(std::path::Path::new),
                    with_stdin,
                )
            }?;
            let supervisor::CapturedChild {
                process,
                stdout,
                stderr,
                stdin: stdin_pipe,
            } = child;
            let pid = process.pid;

            // BOTH pipes must be drained concurrently. Reading one to EOF
            // first deadlocks as soon as the child fills the other's buffer —
            // the classic two-pipe hang, and it would look like a timeout.
            // Both drains return `read_pipe_to_end`'s shape; the streamed one
            // carries nothing back because it handed everything on.
            let (out_t, err_t) = match output {
                Output::Buffered { max_output } => {
                    let budget = Arc::new(AtomicU64::new(max_output));
                    let budget_err = budget.clone();
                    (
                        std::thread::spawn(move || supervisor::read_pipe_to_end(&stdout, &budget)),
                        std::thread::spawn(move || {
                            supervisor::read_pipe_to_end(&stderr, &budget_err)
                        }),
                    )
                }
                // `blocking_send` is legal here — these are plain threads,
                // not runtime workers — and it is the backpressure: a full
                // raw channel parks the thread, the pipe fills, the child
                // blocks on `WriteFile`.
                Output::Streamed { raw } => {
                    let raw_err = raw.clone();
                    (
                        std::thread::spawn(move || {
                            supervisor::read_pipe_streamed(&stdout, |bytes| {
                                raw.blocking_send(Chunk {
                                    stream: OutStream::Stdout,
                                    bytes,
                                })
                                .is_ok()
                            });
                            (Vec::new(), false)
                        }),
                        std::thread::spawn(move || {
                            supervisor::read_pipe_streamed(&stderr, |bytes| {
                                raw_err
                                    .blocking_send(Chunk {
                                        stream: OutStream::Stderr,
                                        bytes,
                                    })
                                    .is_ok()
                            });
                            (Vec::new(), false)
                        }),
                    )
                }
            };

            Ok::<_, anyhow::Error>((process, pid, out_t, err_t, stdin_pipe))
        })
        .await;

        let (process, pid, out_t, err_t, stdin_pipe) = match spawned {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return ExecOutcome::failed(format!("spawn as console user failed: {e}")),
            Err(e) => return ExecOutcome::failed(format!("spawn task panicked: {e}")),
        };

        // The caller's stdin, into the pipe the child reads. Anonymous pipes
        // are synchronous, so each write is a short blocking call; the
        // forwarder itself stays async so it can be aborted below.
        let feeder = match (stdin, stdin_pipe) {
            (Some(feed), Some(pipe)) => Some(tokio::spawn(feed_pipe(Arc::new(pipe), feed))),
            _ => None,
        };

        let process = Arc::new(process);
        let waiter = process.clone();
        // The blocking wait is a BACKSTOP, not the deadline: the `select!`
        // below owns the timeout and the cancel, and every one of its exits
        // either saw the process end or terminated it — so this thread always
        // returns, and waiting in hour-long slices only bounds how long one
        // call sits. It used to give up after ONE hour, sized against
        // `MAX_TIMEOUT_MS`; a streamed command (FR-89) has no wall clock and
        // may run longer, and a waiter that returned early would report an
        // exit that had not happened.
        let wait = tokio::task::spawn_blocking(move || {
            while !waiter.wait_for_exit(std::time::Duration::from_secs(3600)) {}
        });
        tokio::pin!(wait);

        // `None` is an arm that never fires — see `spawn_and_wait`.
        let timeout = async move {
            match timeout_ms {
                Some(ms) => tokio::time::sleep(std::time::Duration::from_millis(ms)).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(timeout);
        tokio::pin!(cancel);

        let error = tokio::select! {
            _ = &mut wait => None,
            _ = &mut timeout => {
                super::kill_tree_pid(pid).await;
                process.terminate();
                Some(format!("timed out after {}ms", timeout_ms.unwrap_or_default()))
            }
            _ = &mut cancel => {
                super::kill_tree_pid(pid).await;
                process.terminate();
                Some("cancelled by the caller".to_string())
            }
        };
        // As on the other path: the command is gone, so a feeder still
        // waiting for the client's EOF ends here. A write in flight fails on
        // its own (the reader died) and drops the last copy of the pipe.
        if let Some(feeder) = feeder {
            feeder.abort();
        }

        // The drain threads end when the pipes hit EOF, which the kill above
        // guarantees even in the timeout path — the child's handles close when
        // it dies. Joining on a blocking pool keeps the runtime free.
        let joined = tokio::task::spawn_blocking(move || {
            let (o, ot) = out_t.join().unwrap_or_default();
            let (e, et) = err_t.join().unwrap_or_default();
            (o, ot, e, et)
        })
        .await
        .unwrap_or_default();
        let (out_bytes, out_trunc, err_bytes, err_trunc) = joined;

        let exit_code = match process.try_wait() {
            Ok(Some(code)) => Some(code as i32),
            _ => None,
        };

        // The text views are filled after redaction (`run_fed`).
        ExecOutcome {
            exit_code: if error.is_some() { None } else { exit_code },
            stdout: String::new(),
            stderr: String::new(),
            stdout_bytes: out_bytes,
            stderr_bytes: err_bytes,
            truncated: out_trunc || err_trunc,
            duration_ms: 0,
            error,
        }
    }

    /// Copy `feed` into the child's stdin pipe, then let the pipe close
    /// (end-of-input) when the last reference drops. Each write is its own
    /// short blocking call, so this task stays abortable.
    async fn feed_pipe(pipe: Arc<supervisor::OwnedHandle>, mut feed: super::StdinFeed) {
        while let Some(chunk) = feed.recv().await {
            let p = pipe.clone();
            let wrote =
                tokio::task::spawn_blocking(move || supervisor::write_all_to_pipe(&p, &chunk))
                    .await;
            if !matches!(wrote, Ok(Ok(()))) {
                // The child stopped reading (exited, or closed its stdin).
                return;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn the_command_is_one_quoted_argument() {
            let line = build_cmdline("powershell", &["-NoProfile", "-Command"], "echo hi");
            assert_eq!(line, r#""powershell" -NoProfile -Command "echo hi""#);
        }

        /// There is no argv array here — only a string the child re-parses — so
        /// an embedded quote that escaped the wrapper would let the caller's
        /// text become additional ARGUMENTS to the shell rather than its
        /// command. Doubling is what both cmd and PowerShell expect.
        #[test]
        fn embedded_quotes_cannot_break_out_of_the_argument() {
            let line = build_cmdline("cmd", &["/c"], r#"echo "a" & whoami"#);
            assert_eq!(line, r#""cmd" /c "echo ""a"" & whoami""#);
            // The payload stays inside exactly one quoted run: count the quote
            // characters after the program+flags and confirm they pair up.
            let payload = &line[line.find("/c ").unwrap() + 3..];
            assert!(payload.starts_with('"') && payload.ends_with('"'));
            assert_eq!(payload.matches('"').count() % 2, 0);
        }

        /// FR-97 P4b — `sftp-server` runs itself: its quoted path, no shell, no
        /// argument. A path with a quote in it is refused, never escaped.
        #[cfg(feature = "ssh-server")]
        #[test]
        fn a_program_runs_itself_with_nothing_after_it() {
            assert_eq!(
                build_program_cmdline(r"C:\Windows\System32\OpenSSH\sftp-server.exe").as_deref(),
                Some(r#""C:\Windows\System32\OpenSSH\sftp-server.exe""#)
            );
            assert_eq!(build_program_cmdline(r#"C:\a" -x "b.exe"#), None);
        }
    }
}
