// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-90 P3-4c-1 — `vault_exec`: one command, run as the session's account,
//! with values from the vault in its environment, and its output scrubbed.
//!
//! | Step | What holds |
//! |---|---|
//! | the request | `argv` (1 to 64 items, `argv[0]` a program's BARE name), `env` (1 to 8 `NAME: handle`), `timeout_s` (1 to 300) |
//! | the program | found only in the system's own directories ([`SYSTEM_DIRS`]), and refused unless root (or this daemon) owns it and neither group nor other can write it: a program the session's account could replace is never handed a value |
//! | the leases | one per env entry, mode `exec`, audience the program's name: the vault's `exec-only-allowed-programs` guardrail refuses a program off the secret's `exec_allow`, and `windows-proxy-only` refuses every exec on Windows (AC13). P3-6b-2b — every entry naming one dynamic secret shares one lease of it in `short-lived`, and the credential minted for that lease ([`leased_values`]) |
//! | the run | as the session's account (decision 13), from its folder, in its own process group, with a clean environment, stdin closed, output capped, the group killed at the timeout |
//! | the answer | the exit, stdout and stderr, each value replaced by `[vault:<NAME>]`, then the daemon's own redactor |
//! | after | every lease let go at once, whatever happened |
//!
//! ⚠️ `exec` is a MATERIALIZING mode (design §8.5): the program holds the
//! value, so a program that prints or sends it can leak it. That is why it
//! needs a permit, `exec_allow`, and a person's approval of the call: the
//! settings never allow this tool, so Claude Code asks `approve` first.
//!
//! ⚠️ Scrubbing is a seatbelt, not a boundary: a value printed in another
//! encoding (base64, split across lines) passes it.

use std::collections::HashMap;
use std::time::Duration;

use bson::oid::ObjectId;
use serde_json::Value;
use zeroize::Zeroizing;

use super::toolbelt::VaultTools;
use crate::vault::SHORT_LIVED;

/// How long a command may run when its call names no timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// The longest a command may run.
const MAX_TIMEOUT_SECS: u64 = 300;
/// The most argv items, and the longest one.
const MAX_ARGS: usize = 64;
const MAX_ARG_LEN: usize = 4096;
/// The most values one command is handed.
const MAX_ENV: usize = 8;
/// The longest env name.
const MAX_NAME_LEN: usize = 64;
/// The most of each stream an answer carries; the rest is cut and said to
/// be.
#[cfg(unix)]
const MAX_STREAM: usize = 64 * 1024;
/// How long the output may still drain once the command is gone: a process
/// that left its group can hold the pipes open for ever.
#[cfg(unix)]
const DRAIN: Duration = Duration::from_secs(2);
/// A value shorter than this is not scrubbed (it would shred the output),
/// and the answer says so.
#[cfg(unix)]
const MIN_SCRUB_LEN: usize = 4;

/// Where a program handed a value is looked for, and nowhere else.
#[cfg(unix)]
pub(crate) const SYSTEM_DIRS: [&str; 6] = [
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
];

/// Names a child must not be handed: they steer the shell, the loader or
/// where a program is found, so a value there would change what runs.
const RESERVED: [&str; 8] = [
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "IFS", "ENV", "BASH_ENV",
];

/// A secret, as a call names it: a path or this org's RRN, and `#field` for
/// a structured secret's field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Handle {
    pub(crate) secret: String,
    pub(crate) field: String,
}

/// As a call names it: `secret`, or `secret#field`.
impl std::fmt::Display for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.field.is_empty() {
            f.write_str(&self.secret)
        } else {
            write!(f, "{}#{}", self.secret, self.field)
        }
    }
}

/// One `vault_exec` call, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecRequest {
    pub(crate) argv: Vec<String>,
    /// `NAME`, and the secret whose value it is handed.
    pub(crate) env: Vec<(String, Handle)>,
    pub(crate) timeout: Duration,
}

/// Where and as whom a session's commands run: its account (`None`: as this
/// daemon, which only a test does), the account's home, the session's
/// folder. Made only where commands run (Unix).
#[derive(Debug, Clone)]
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct ExecTarget {
    pub(crate) account: Option<String>,
    pub(crate) home: std::path::PathBuf,
    pub(crate) folder: std::path::PathBuf,
    /// P3-4c-2 — the session's daemon-owned runtime directory, where its
    /// secrets directory is made, and the account's ids the files there are
    /// handed to (`None`: kept as this daemon's, which only a test does).
    pub(crate) session_dir: std::path::PathBuf,
    pub(crate) owner: Option<(u32, u32)>,
}

fn env_name_ok(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    name.len() <= MAX_NAME_LEN
        && (first.is_ascii_uppercase() || first == b'_')
        && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && !RESERVED.contains(&name)
        && !name.starts_with("LD_")
        && !name.starts_with("DYLD_")
}

/// A secret as a call names it: a path or this org's RRN, `#field` for a
/// structured secret's field. Shared with `vault_render`'s placeholders.
pub(crate) fn handle_of(raw: &str) -> Result<Handle, String> {
    let (secret, field) = match raw.split_once('#') {
        Some((s, f)) => (s, f),
        None => (raw, ""),
    };
    use meshharbor_remote_control::vault::lease_limits::{MAX_FIELD_LEN, MAX_SECRET_LEN};
    if secret.is_empty()
        || secret.len() > MAX_SECRET_LEN
        || field.len() > MAX_FIELD_LEN
        || raw.chars().any(char::is_control)
    {
        return Err(format!(
            "{raw:?} is not a secret: name it by its path or rrn:<org>:secret:<path>, with \
             #<field> for a structured secret's field"
        ));
    }
    Ok(Handle {
        secret: secret.to_string(),
        field: field.to_string(),
    })
}

/// Check a call's arguments: what is refused here never reaches the vault.
pub(crate) fn parse(args: &Value) -> Result<ExecRequest, String> {
    let argv: Vec<String> = match args.get("argv").and_then(Value::as_array) {
        Some(a) if !a.is_empty() && a.len() <= MAX_ARGS => a
            .iter()
            .map(|v| v.as_str().map(String::from))
            .collect::<Option<_>>()
            .ok_or("every argv item must be a string")?,
        _ => return Err(format!("argv must hold 1 to {MAX_ARGS} strings")),
    };
    if argv
        .iter()
        .any(|a| a.len() > MAX_ARG_LEN || a.contains('\0'))
    {
        return Err(format!(
            "an argv item is longer than {MAX_ARG_LEN} bytes or holds a NUL"
        ));
    }
    if !meshharbor_remote_control::vault::program_name_ok(&argv[0]) {
        return Err(format!(
            "argv[0] must be a program's bare name, as the secret's exec_allow names it \
             (no path): got {:?}",
            argv[0]
        ));
    }
    let env = match args.get("env").and_then(Value::as_object) {
        Some(m) if !m.is_empty() && m.len() <= MAX_ENV => m,
        _ => return Err(format!("env must map 1 to {MAX_ENV} NAMEs to secrets")),
    };
    let mut pairs = Vec::with_capacity(env.len());
    for (name, raw) in env {
        if !env_name_ok(name) {
            return Err(format!(
                "{name:?} cannot be handed a value: an env name is A-Z, 0-9 and _, and never \
                 one that steers the shell, the loader or the search path"
            ));
        }
        let raw = raw
            .as_str()
            .ok_or_else(|| format!("env {name} must name a secret"))?;
        pairs.push((name.clone(), handle_of(raw)?));
    }
    let timeout = match args.get("timeout_s") {
        None | Some(Value::Null) => DEFAULT_TIMEOUT,
        Some(v) => match v.as_u64() {
            Some(s) if (1..=MAX_TIMEOUT_SECS).contains(&s) => Duration::from_secs(s),
            _ => return Err(format!("timeout_s must be 1 to {MAX_TIMEOUT_SECS}")),
        },
    };
    Ok(ExecRequest {
        argv,
        env: pairs,
        timeout,
    })
}

/// Find `program` in `dirs`, and refuse a file the session's account could
/// have put there or could change: it must be a regular, executable file,
/// owned by root or by this daemon, that neither group nor other can write.
#[cfg(unix)]
pub(crate) fn resolve(program: &str, dirs: &[&str]) -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: getuid reads our own credentials.
    let me = unsafe { libc::getuid() };
    for dir in dirs {
        let path = std::path::Path::new(dir).join(program);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() || meta.mode() & 0o111 == 0 {
            continue;
        }
        if meta.uid() != 0 && meta.uid() != me {
            return Err(format!(
                "{} is not owned by root: a program the session's account could replace is \
                 never handed a value",
                path.display()
            ));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(format!(
                "{} can be written by others: it is never handed a value",
                path.display()
            ));
        }
        return Ok(path);
    }
    Err(format!(
        "{program} was not found in {}: a value is handed only to a program installed there",
        dirs.join(", ")
    ))
}

/// What a command did.
#[cfg(unix)]
#[derive(Debug, Default)]
pub(crate) struct Ran {
    pub(crate) exit_code: Option<i32>,
    pub(crate) signal: Option<i32>,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) truncated: bool,
    pub(crate) timed_out: bool,
}

/// Kills the process group a command leads when dropped.
#[cfg(unix)]
struct KillGroup(u32);

#[cfg(unix)]
impl Drop for KillGroup {
    fn drop(&mut self) {
        if let Ok(pgid) = i32::try_from(self.0) {
            // SAFETY: a negative pid signals the group the child leads; a
            // group already gone is an error nothing reads.
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
        }
    }
}

/// Read `reader` to its end, keeping at most `cap` bytes.
#[cfg(unix)]
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(
    reader: Option<R>,
    cap: usize,
) -> (Vec<u8>, bool) {
    use tokio::io::AsyncReadExt;
    let Some(mut r) = reader else {
        return (Vec::new(), false);
    };
    let mut kept = Vec::new();
    let mut cut = false;
    let mut buf = [0u8; 16 * 1024];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = cap.saturating_sub(kept.len());
                kept.extend_from_slice(&buf[..n.min(room)]);
                cut |= n > room;
            }
        }
    }
    (kept, cut)
}

/// Run `program` with `args` as `target`'s account, from its folder, with a
/// clean environment, the base names and `values` set.
#[cfg(unix)]
pub(crate) async fn run(
    program: &std::path::Path,
    args: &[String],
    values: &[(String, Zeroizing<Vec<u8>>)],
    target: &ExecTarget,
    timeout: Duration,
) -> Result<Ran, String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;

    let account = target
        .account
        .clone()
        .unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "root".to_string()));
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .env_clear()
        .env("HOME", &target.home)
        .env("USER", &account)
        .env("LOGNAME", &account)
        .env("PATH", SYSTEM_DIRS.join(":"))
        .env("LANG", "C.UTF-8")
        .current_dir(&target.folder)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        // Its own group, so the timeout reaches what it started too.
        .process_group(0);
    for (name, value) in values {
        cmd.env(name, std::ffi::OsStr::from_bytes(value));
    }
    // Privilege LAST, so nothing set after it could undo the drop.
    if let Some(account) = &target.account {
        crate::exec::apply_session_run_as(&mut cmd, account)?;
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("{} did not start: {e}", program.display()))?;
    // However the command ends (its exit, the timeout, the call cancelled),
    // its group goes with it: nothing it started keeps a value.
    let group = child.id().map(KillGroup);
    let out = tokio::spawn(read_capped(child.stdout.take(), MAX_STREAM));
    let err = tokio::spawn(read_capped(child.stderr.take(), MAX_STREAM));
    let mut ran = Ran::default();
    tokio::select! {
        status = child.wait() => {
            let status = status.map_err(|e| format!("waiting for the command failed: {e}"))?;
            ran.exit_code = status.code();
            ran.signal = status.signal();
        }
        _ = tokio::time::sleep(timeout) => {
            let _ = child.kill().await;
            ran.timed_out = true;
        }
    }
    // The rest of the group now, so a pipe it held closes and the output
    // drains.
    drop(group);
    // A process that left the group can keep a pipe open after the command
    // is gone: what drained by then is the answer, and the rest is cut.
    let drained = |task: tokio::task::JoinHandle<(Vec<u8>, bool)>| async move {
        let abort = task.abort_handle();
        match tokio::time::timeout(DRAIN, task).await {
            Ok(Ok(read)) => read,
            Ok(Err(_)) => (Vec::new(), true),
            Err(_) => {
                abort.abort();
                (Vec::new(), true)
            }
        }
    };
    let (stdout, out_cut) = drained(out).await;
    let (stderr, err_cut) = drained(err).await;
    ran.stdout = stdout;
    ran.stderr = stderr;
    ran.truncated = out_cut || err_cut;
    Ok(ran)
}

/// Every value in `values` replaced by `[vault:<NAME>]`, the longest first so
/// a value inside another is not left half-masked; then the daemon's own
/// redactor (agent tokens, bearer and JWT shapes).
#[cfg(unix)]
pub(crate) fn scrub(bytes: &[u8], values: &[(String, Zeroizing<Vec<u8>>)]) -> Vec<u8> {
    let mut order: Vec<&(String, Zeroizing<Vec<u8>>)> = values
        .iter()
        .filter(|(_, v)| v.len() >= MIN_SCRUB_LEN)
        .collect();
    order.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
    let mut out = bytes.to_vec();
    for (name, value) in order {
        out = replace_all(&out, value, format!("[vault:{name}]").as_bytes());
    }
    crate::exec::redactor().apply_bytes(&out)
}

#[cfg(unix)]
fn replace_all(hay: &[u8], needle: &[u8], with: &[u8]) -> Vec<u8> {
    if needle.is_empty() || hay.len() < needle.len() {
        return hay.to_vec();
    }
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if hay[i..].starts_with(needle) {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

/// What a session's `vault_exec` call answers: the command's outcome as
/// JSON, or why nothing ran.
pub(crate) async fn call(
    vault: &dyn VaultTools,
    session: ObjectId,
    fence: u64,
    target: Option<&ExecTarget>,
    args: &Value,
) -> Result<Value, String> {
    let req = parse(args)?;
    let program = req.argv[0].clone();
    // Found before anything is leased: a call that cannot run asks nothing.
    // On Windows nothing is run, and the vault is asked anyway: its refusal
    // is the one that is recorded (AC13).
    #[cfg(unix)]
    let path = resolve(&program, &SYSTEM_DIRS)?;
    #[cfg(not(unix))]
    let path = ();
    let ttl = u32::try_from(req.timeout.as_secs() + 30).unwrap_or(u32::MAX);
    // However the call ends, a cancelled one included: no lease it asked for
    // itself outlives it.
    let mut held = Releasing {
        vault,
        leases: Vec::with_capacity(req.env.len()),
    };
    // P3-4c-3 — a lease asked for ahead for this program, covering the
    // command's whole run, is taken as it is: kept when the call ends.
    // P3-6b-2b — a dynamic secret's names share one lease and its credential.
    let handles: Vec<(&str, &Handle)> = req.env.iter().map(|(n, h)| (n.as_str(), h)).collect();
    let to = Use {
        mode: "exec",
        audience: &program,
        ttl,
        covers: req.timeout,
        before: "the command ran",
    };
    let (leases, leased) = leased_values(vault, session, fence, &handles, &to, &mut held).await?;
    let mut values = Vec::with_capacity(req.env.len());
    for ((name, _), value) in req.env.iter().zip(leased) {
        if value.contains(&0) {
            return Err(format!(
                "{name}: the value holds a NUL and cannot go in an environment"
            ));
        }
        values.push((name.clone(), value));
    }
    let answer = run_with(target, &req, &values, &path).await?;
    // P3-4d-2 — the command ran with these values: reported where the
    // device's owner has it report, with how it ended, never a value.
    vault.report(crate::vault::Report {
        session_id: session,
        fence,
        kind: meshharbor_remote_control::vault::VaultActivityKind::Exec,
        lease_ids: leases,
        target: program,
        exit_code: answer["exit_code"]
            .as_i64()
            .and_then(|c| i32::try_from(c).ok()),
        timed_out: answer["timed_out"].as_bool().unwrap_or(false),
    });
    Ok(answer)
}

/// Lets go of a call's leases when dropped.
pub(crate) struct Releasing<'a> {
    pub(crate) vault: &'a dyn VaultTools,
    pub(crate) leases: Vec<String>,
}

impl Releasing<'_> {
    /// P3-4c-2 — the leases outlive the call after all (a rendered file
    /// lives with them): nothing is let go here.
    pub(crate) fn keep(mut self) {
        self.leases.clear();
    }
}

impl Drop for Releasing<'_> {
    fn drop(&mut self) {
        if !self.leases.is_empty() {
            self.vault.release(&self.leases);
        }
    }
}

/// P3-6b-2b — a dynamic secret, as a session's tools learn it from its
/// metadata: its provider, and the fields its minted credential has, the
/// only ones a session may name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Dynamic {
    pub(crate) provider: String,
    pub(crate) fields: Vec<String>,
}

/// P3-6b-2b — whether `secret` is dynamic, by its metadata (decided and
/// recorded by the vault's `secret:list`). `None` for a stored secret, or
/// for one the session's role may not describe: its lease is asked for and
/// decided as before. Err for a dynamic secret of a provider this build
/// mints nothing for.
pub(crate) async fn dynamic_of(
    vault: &dyn VaultTools,
    session: ObjectId,
    fence: u64,
    secret: &str,
) -> Result<Option<Dynamic>, String> {
    let Ok(meta) = vault.describe(session, fence, secret).await else {
        return Ok(None);
    };
    let Some(provider) = meta.get("provider").and_then(Value::as_str) else {
        return Ok(None);
    };
    if !crate::vault::MINTS.contains(&provider) {
        return Err(format!(
            "{secret} is a dynamic secret of {provider}, a provider this device mints nothing for"
        ));
    }
    let fields = meta
        .get("fields")
        .and_then(Value::as_array)
        .map(|f| {
            f.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(Dynamic {
        provider: provider.to_string(),
        fields,
    }))
}

/// P3-6b-2b — what a call leases toward: a stored secret's `mode` and
/// `audience`, the TTL it asks for, how long a lease asked for ahead must
/// still cover, and what a lease that ends too soon came before (for its
/// error).
pub(crate) struct Use<'a> {
    pub(crate) mode: &'a str,
    pub(crate) audience: &'a str,
    pub(crate) ttl: u32,
    pub(crate) covers: Duration,
    pub(crate) before: &'a str,
}

/// P3-6b-2b — the leases a call's values come from, each once, and each
/// handle's value in the order of `handles` (`(label, handle)`, the label
/// what an error names). Each secret is described first ([`dynamic_of`]).
/// A stored secret's handle takes a lease asked for ahead that covers the
/// call, or one of its own in `to.mode` toward `to.audience`. Every handle of
/// one dynamic secret shares ONE lease of the secret as a whole, in
/// `short-lived`, and the credential minted for it (design §3e: one
/// credential per lease). The leases the call asks for itself go in `held`.
pub(crate) async fn leased_values(
    vault: &dyn VaultTools,
    session: ObjectId,
    fence: u64,
    handles: &[(&str, &Handle)],
    to: &Use<'_>,
    held: &mut Releasing<'_>,
) -> Result<(Vec<String>, Vec<Zeroizing<Vec<u8>>>), String> {
    let mut kinds: HashMap<&str, Option<Dynamic>> = HashMap::new();
    for (_, h) in handles {
        if !kinds.contains_key(h.secret.as_str()) {
            let kind = dynamic_of(vault, session, fence, &h.secret).await?;
            kinds.insert(&h.secret, kind);
        }
    }
    let mut leases = Vec::with_capacity(handles.len());
    // A dynamic secret's one lease in this call, by secret.
    let mut whole: HashMap<&str, String> = HashMap::new();
    let mut sources = Vec::with_capacity(handles.len());
    for (label, h) in handles {
        let (asked, mode, audience) = match &kinds[h.secret.as_str()] {
            Some(d) => {
                if !d.fields.contains(&h.field) {
                    return Err(format!(
                        "{label}: {} is a dynamic secret: name a field of the credential minted \
                         for it, #{}",
                        h.secret,
                        d.fields.join(", #")
                    ));
                }
                if let Some(lease) = whole.get(h.secret.as_str()) {
                    sources.push(lease.clone());
                    continue;
                }
                let all = Handle {
                    secret: h.secret.clone(),
                    field: String::new(),
                };
                (all, SHORT_LIVED, "")
            }
            None => ((*h).clone(), to.mode, to.audience),
        };
        let lease = match vault.ahead(session, fence, &asked, mode, audience, to.covers) {
            Some(lease) => lease,
            None => {
                let lease = vault
                    .lease(session, fence, &asked, mode, audience, to.ttl)
                    .await
                    .map_err(|why| format!("{label}: {why}"))?;
                held.leases.push(lease.clone());
                lease
            }
        };
        if mode == SHORT_LIVED {
            vault
                .mint(&lease)
                .await
                .map_err(|why| format!("{label}: {why}"))?;
            whole.insert(&h.secret, lease.clone());
        }
        leases.push(lease.clone());
        sources.push(lease);
    }
    let mut values = Vec::with_capacity(handles.len());
    for ((label, h), lease) in handles.iter().zip(&sources) {
        let value = if kinds[h.secret.as_str()].is_some() {
            vault.minted(lease, &h.field)
        } else {
            vault.value(lease)
        };
        values.push(value.ok_or_else(|| format!("{label}: the lease ended before {}", to.before))?);
    }
    Ok((leases, values))
}

/// Run the checked call with its values, and answer it.
#[cfg(unix)]
async fn run_with(
    target: Option<&ExecTarget>,
    req: &ExecRequest,
    values: &[(String, Zeroizing<Vec<u8>>)],
    path: &std::path::Path,
) -> Result<Value, String> {
    let target = target.ok_or("this device runs no command for a session")?;
    let ran = run(path, &req.argv[1..], values, target, req.timeout).await?;
    let unmasked: Vec<&str> = values
        .iter()
        .filter(|(_, v)| v.len() < MIN_SCRUB_LEN)
        .map(|(n, _)| n.as_str())
        .collect();
    let mut answer = serde_json::json!({
        "exit_code": ran.exit_code,
        "stdout": String::from_utf8_lossy(&scrub(&ran.stdout, values)),
        "stderr": String::from_utf8_lossy(&scrub(&ran.stderr, values)),
        "truncated": ran.truncated,
        "timed_out": ran.timed_out,
    });
    if let Some(s) = ran.signal {
        answer["signal"] = serde_json::json!(s);
    }
    if !unmasked.is_empty() {
        answer["not_scrubbed"] = serde_json::json!(unmasked);
    }
    Ok(answer)
}

/// A Windows daemon never runs a materialized value: it has no sandbox for
/// one (AC13). The vault refuses `exec` there first; this holds even if it
/// ever did not.
#[cfg(not(unix))]
async fn run_with(
    _target: Option<&ExecTarget>,
    _req: &ExecRequest,
    _values: &[(String, Zeroizing<Vec<u8>>)],
    _path: &(),
) -> Result<Value, String> {
    Err("this device has no sandbox for a value: it runs no command with one".into())
}

#[cfg(all(test, unix))]
mod tests;
