// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Windows Defender Firewall rules for THIS binary — the ONE definition of
//! the inbound-UDP allow rule, and the cleanup of the Block rules a Windows
//! Security prompt writes when it beats us to the first bind (#1698).
//!
//! Two consumers, one rule:
//!
//! * `overlay::tun::SystemTun::up` — every TUN bring-up, on a detached
//!   thread: the self-heal that keeps the recorded program path current
//!   across upgrades (P9, field-hit 2026-07-28: a fresh install had no rule,
//!   so unsolicited WG dials — LAN direct, srflx punch — died at the Public
//!   profile's default-deny).
//! * `meshharbord`'s SCM service host (`win_service`), LocalSystem, which
//!   installs the same rule BEFORE it spawns the worker the first time.
//!
//! Why the host must do it (#1698, measured on a 0.4.104 attended guest): on
//! an ATTENDED perMachine install the worker runs in the signed-in user's
//! session, and a session process that binds off-loopback UDP with no rule
//! for its path gets the interactive "Allow access?" prompt. The prompt
//! writes per-profile **Block** rules for the exe the moment it appears, and
//! in Defender an explicit Block beats an Allow — so the overlay's own rule,
//! added a few hundred ms later by the detached hygiene thread, lost on every
//! Public-profile network until someone clicked Allow. P9's premise ("a
//! Windows *service* never gets the prompt") holds for a SYSTEM worker only.
//!
//! The pure parts — the rule's shape and argument lists, the store parser,
//! the cleanup predicate, the PowerShell literal — compile on every platform
//! so the Linux CI lane runs their tests; only the effectful functions
//! (`netsh`, the registry read, `powershell`) are `#[cfg(windows)]`.

use std::path::Path;

/// Opt-in installer rules. Kept separate from the legacy SCM/TUN rule:
/// installation defaults to Private + Domain and includes TCP as well as UDP.
#[cfg(any(windows, test))]
pub mod install;

/// Display-name prefix of every binary's rule; the exe stem follows in
/// parentheses so `meshharbord` and the `meshharbor` tunnel client never fight over
/// one rule. The measured guest and the field notes both name this spelling.
pub const RULE_NAME_PREFIX: &str = "MeshHarbor UDP-In";

/// P9 — is the Windows net-hygiene pass disabled? Only an explicit
/// `0`/`false`/`no`/`off` disables (`MESHHARBORD_TUN_HYGIENE`); unset / anything
/// else keeps the default ON. Pure so the parse is testable. Honoured by the
/// overlay's per-bring-up pass AND by the service host's pre-spawn prep — one
/// kill switch for both halves of the same rule.
pub fn hygiene_disabled(v: Option<&str>) -> bool {
    matches!(
        v.map(|s| s.trim().to_ascii_lowercase()),
        Some(t) if t == "0" || t == "false" || t == "no" || t == "off"
    )
}

/// The ONE definition of the inbound-UDP allow rule for a binary: its display
/// name and the program path it records. Both consumers build their `netsh`
/// invocations from here, so the rule cannot drift between them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpInAllowRule {
    /// `MeshHarbor UDP-In (<exe stem>)`.
    pub name: String,
    /// The full path of the binary, as `netsh … program=` records it.
    pub program: String,
}

impl UdpInAllowRule {
    /// The rule for `exe`. A path with no stem (never the case for a real
    /// binary) falls back to the `meshharbor` stem rather than an empty one.
    pub fn for_exe(exe: &Path) -> Self {
        let text = exe.to_string_lossy();
        let stem = windows_file_stem(&text).unwrap_or("meshharbor");
        Self {
            name: format!("{RULE_NAME_PREFIX} ({stem})"),
            program: text.into_owned(),
        }
    }
}

/// The file stem of a Windows path, from the text rather than
/// `Path::file_stem`: on a non-Windows host `Path` treats `\` as an ordinary
/// character, and the pure half of this module runs — and is tested — on the
/// Linux CI lane. The rule's name must come out the same everywhere. Either
/// separator is accepted; a leading dot is part of the name, not an extension.
fn windows_file_stem(path: &str) -> Option<&str> {
    let file = path.rsplit(['\\', '/']).next()?.trim();
    if file.is_empty() {
        return None;
    }
    let stem = match file.rfind('.') {
        Some(0) | None => file,
        Some(i) => &file[..i],
    };
    (!stem.is_empty()).then_some(stem)
}

impl UdpInAllowRule {
    /// The rule for the running binary; `None` only if the OS cannot say
    /// what that is.
    pub fn for_current_exe() -> Option<Self> {
        std::env::current_exe().ok().map(|p| Self::for_exe(&p))
    }

    /// `netsh advfirewall firewall delete rule name=<name>` — by display
    /// name, which is what netsh offers. Run BEFORE the add: netsh dedupes
    /// nothing, so the delete is what makes the pair idempotent, and it is
    /// also what refreshes a stale program path after a moved install.
    pub fn netsh_delete_args(&self) -> Vec<String> {
        vec![
            "advfirewall".into(),
            "firewall".into(),
            "delete".into(),
            "rule".into(),
            format!("name={}", self.name),
        ]
    }

    /// `netsh advfirewall firewall add rule name=<name> dir=in action=allow
    /// protocol=udp program=<exe>` — all profiles, every port: the WG socket,
    /// the disco/STUN probes and the WebRTC candidates all bind ephemeral
    /// UDP ports on the physical adapters.
    pub fn netsh_add_args(&self) -> Vec<String> {
        vec![
            "advfirewall".into(),
            "firewall".into(),
            "add".into(),
            "rule".into(),
            format!("name={}", self.name),
            "dir=in".into(),
            "action=allow".into(),
            "protocol=udp".into(),
            format!("program={}", self.program),
        ]
    }
}

/// `Dir=` of a stored rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

/// `Action=` of a stored rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Block,
}

/// One rule as the local persistent store holds it —
/// `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules`.
/// The value NAME is the rule's unique id (PowerShell's `Name`, distinct from
/// its `DisplayName`); the value DATA is the `v2.NN|Key=Value|…|` string the
/// [MS-FASP] rule grammar defines. Only the keys the two decisions here need
/// are lifted into fields; `keys` keeps every key seen so the strict
/// "exactly ours" check can refuse a rule carrying clauses it does not know.
///
/// The store is read, never written: the firewall service owns writes, and a
/// value deleted behind its back is not a rule removed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StoredRule {
    pub id: String,
    /// `Name=` — the display name.
    pub display_name: Option<String>,
    pub direction: Option<Direction>,
    pub action: Option<Action>,
    /// `App=` — the program path, verbatim (may carry `%VAR%` forms).
    pub program: Option<String>,
    /// `Protocol=` — IANA number (6 TCP, 17 UDP).
    pub protocol: Option<u32>,
    /// `Active=`.
    pub active: Option<bool>,
    /// Every `Profile=` token; empty means all profiles.
    pub profiles: Vec<String>,
    /// Every key the string carried, in order.
    pub keys: Vec<String>,
}

/// Parse one store value. `None` when the data is not a rule string at all
/// (no leading `vN.N` version token) — never a guess. Unknown tokens are
/// skipped (the format is additive across Windows releases) and an
/// unrecognised enum value stays `None`, so a rule this code cannot classify
/// can never satisfy a predicate that keys on that field.
pub fn parse_stored_rule(id: &str, value: &str) -> Option<StoredRule> {
    let mut tokens = value.split('|');
    let version = tokens.next()?.trim();
    let is_version = version.len() >= 2
        && version.starts_with('v')
        && version[1..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit());
    if !is_version {
        return None;
    }
    let mut r = StoredRule {
        id: id.to_string(),
        ..Default::default()
    };
    for tok in tokens {
        let Some((k, v)) = tok.split_once('=') else {
            continue;
        };
        r.keys.push(k.to_string());
        let lower = v.trim().to_ascii_lowercase();
        match k.to_ascii_lowercase().as_str() {
            "name" if r.display_name.is_none() => r.display_name = Some(v.to_string()),
            "dir" if r.direction.is_none() => {
                r.direction = match lower.as_str() {
                    "in" => Some(Direction::In),
                    "out" => Some(Direction::Out),
                    _ => None,
                }
            }
            "action" if r.action.is_none() => {
                r.action = match lower.as_str() {
                    "allow" => Some(Action::Allow),
                    "block" => Some(Action::Block),
                    _ => None,
                }
            }
            "app" if r.program.is_none() => r.program = Some(v.to_string()),
            "protocol" if r.protocol.is_none() => r.protocol = lower.parse().ok(),
            "active" if r.active.is_none() => {
                r.active = match lower.as_str() {
                    "true" => Some(true),
                    "false" => Some(false),
                    _ => None,
                }
            }
            "profile" => r.profiles.push(v.to_string()),
            _ => {}
        }
    }
    Some(r)
}

/// Normalise a program path for equality: trim, strip one pair of quotes,
/// expand `%VAR%` (case-insensitive lookup, unknown left as-is), `/`→`\`,
/// drop a `\\?\` prefix, lower-case (NTFS is case-insensitive). Never touches
/// the disk: a stale rule for a path that no longer exists must still compare.
pub fn normalize_program_path(raw: &str) -> String {
    normalize_program_path_with(raw, |k| {
        std::env::var_os(k).map(|v| v.to_string_lossy().into_owned())
    })
}

/// [`normalize_program_path`] with an injected `%VAR%` lookup (tests; the
/// production lookup is the process environment, which on Windows is itself
/// case-insensitive).
pub fn normalize_program_path_with(raw: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
    let mut s = raw.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s = &s[1..s.len() - 1];
    }
    let expanded = expand_env(s, &lookup);
    let slashed = expanded.replace('/', "\\");
    let unprefixed = slashed.strip_prefix("\\\\?\\").unwrap_or(&slashed);
    unprefixed.to_lowercase()
}

/// `%NAME%` → value; an unknown name (or a lone `%`) is left verbatim.
fn expand_env(s: &str, lookup: &impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) if end > 0 => {
                let name = &after[..end];
                match lookup(name) {
                    Some(v) => out.push_str(&v),
                    None => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The store-id prefixes the Windows Security notification prompt gives the
/// rules it writes: `TCP Query User{<GUID>}<path>` and
/// `UDP Query User{<GUID>}<path>` (the field guest in #1698 carried exactly
/// these). Rules from `netsh`, `wf.msc`, `New-NetFirewallRule` or a GPO get a
/// `{GUID}` or the caller's own string, never this shape.
pub const PROMPT_ID_PREFIXES: [&str; 2] = ["TCP Query User{", "UDP Query User{"];

/// Does this store id carry the prompt's signature? Case-sensitive: it is an
/// internal id the firewall service writes, not a display string.
pub fn is_prompt_written_id(id: &str) -> bool {
    PROMPT_ID_PREFIXES.iter().any(|p| id.starts_with(p))
}

/// The cleanup's whole decision — four conditions, all required: the rule is
/// **inbound**, its action is **Block**, its recorded program is **exactly**
/// `our_exe`, and its store id is one **the Windows Security prompt wrote**
/// ([`is_prompt_written_id`]). Nothing else.
///
/// * The id condition is what keeps this from being tampering. A Block an
///   administrator placed deliberately — `netsh … add rule name="Block
///   meshharbor" dir=in action=block program=<our exe>`, `wf.msc`,
///   `New-NetFirewallRule` — has a `{GUID}` or the caller's own id and is
///   left exactly where it is, at every start. The device owner's local
///   setting is a floor (compare `consent::strictest_of`); only the prompt's
///   own leftovers are ours to clear.
/// * Display name is deliberately NOT part of it. A prompt-written rule is
///   named after the exe's FileDescription ("MeshHarbor Daemon"), and any other
///   program can carry that name.
/// * Allow rules are never selected, whatever their id, name or program —
///   including the prompt's own Allow pair when someone clicked Allow.
/// * A rule for any other path — including a same-named binary in another
///   directory — is never selected.
/// * A rule missing any of the fields is left alone: what cannot be
///   classified is not ours to remove.
pub fn prompt_block_rules_for_program<'a>(
    rules: &'a [StoredRule],
    our_exe: &str,
) -> Vec<&'a StoredRule> {
    prompt_block_rules_for_program_with(rules, our_exe, |k| {
        std::env::var_os(k).map(|v| v.to_string_lossy().into_owned())
    })
}

/// [`prompt_block_rules_for_program`] with an injected `%VAR%` lookup.
pub fn prompt_block_rules_for_program_with<'a>(
    rules: &'a [StoredRule],
    our_exe: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Vec<&'a StoredRule> {
    let ours = normalize_program_path_with(our_exe, &lookup);
    rules
        .iter()
        .filter(|r| {
            is_prompt_written_id(&r.id)
                && r.direction == Some(Direction::In)
                && r.action == Some(Action::Block)
                && r.program
                    .as_deref()
                    .is_some_and(|p| normalize_program_path_with(p, &lookup) == ours)
        })
        .collect()
}

/// Is the store's copy of `rule` exactly what [`UdpInAllowRule::netsh_add_args`]
/// writes — present once, Allow, In, UDP, our program, Active, all profiles,
/// no clause netsh did not write? The per-bring-up self-heal skips its
/// delete+add when this holds: that pair is not atomic, and in the gap between
/// the two an attended worker's next off-loopback bind has no rule for its
/// path — the #1698 prompt again. Anything unexpected reads as NOT current
/// (→ delete+add, the pre-#1698 behaviour), so a wrong answer here can only
/// cost a netsh spawn, never a rule.
pub fn rule_is_current(store: &[StoredRule], rule: &UdpInAllowRule) -> bool {
    rule_is_current_with(store, rule, |k| {
        std::env::var_os(k).map(|v| v.to_string_lossy().into_owned())
    })
}

/// [`rule_is_current`] with an injected `%VAR%` lookup.
pub fn rule_is_current_with(
    store: &[StoredRule],
    rule: &UdpInAllowRule,
    lookup: impl Fn(&str) -> Option<String>,
) -> bool {
    // The keys `netsh … add rule` writes for our argument list, plus the
    // optional ones a harmless edit adds. A key outside this set is a
    // clause (port, address, interface, security) that narrows the rule.
    const EXPECTED_KEYS: [&str; 9] = [
        "action",
        "active",
        "dir",
        "protocol",
        "app",
        "name",
        "desc",
        "embedctxt",
        "profile",
    ];
    let named: Vec<&StoredRule> = store
        .iter()
        .filter(|r| r.display_name.as_deref() == Some(rule.name.as_str()))
        .collect();
    let [r] = named.as_slice() else {
        return false;
    };
    if r.keys
        .iter()
        .any(|k| !EXPECTED_KEYS.contains(&k.to_ascii_lowercase().as_str()))
    {
        return false;
    }
    let all_profiles = r.profiles.is_empty() || {
        let mut p: Vec<String> = r.profiles.iter().map(|s| s.to_ascii_lowercase()).collect();
        p.sort();
        p.dedup();
        p == ["domain", "private", "public"]
    };
    r.action == Some(Action::Allow)
        && r.direction == Some(Direction::In)
        && r.protocol == Some(17)
        && r.active == Some(true)
        && all_profiles
        && r.program.as_deref().is_some_and(|p| {
            normalize_program_path_with(p, &lookup)
                == normalize_program_path_with(&rule.program, &lookup)
        })
}

/// `Remove-NetFirewallRule -PolicyStore PersistentStore -Name @(<ids…>)
/// -ErrorAction Stop` — by the store's unique id, never by display name.
/// `-Name` accepts wildcards, so each id is escaped for the wildcard grammar
/// (backtick) as well as for the single-quoted string (`''` for `'`).
/// PowerShell rather than `netsh delete`: netsh selects by name+dir+program
/// and cannot filter on action, so it would take an Allow rule of the same
/// name and program along with the Blocks.
pub fn powershell_remove_args(ids: &[&str]) -> Vec<String> {
    let list = ids
        .iter()
        .map(|id| format!("'{}'", ps_wildcard_literal(id)))
        .collect::<Vec<_>>()
        .join(",");
    vec![
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-Command".into(),
        format!(
            "Remove-NetFirewallRule -PolicyStore PersistentStore -Name @({list}) -ErrorAction Stop"
        ),
    ]
}

/// A string literal that survives both a PowerShell single-quoted string and
/// the wildcard grammar `-Name` applies to it, so the id matches itself and
/// nothing else.
fn ps_wildcard_literal(id: &str) -> String {
    let mut out = String::with_capacity(id.len() + 8);
    for c in id.chars() {
        match c {
            '\'' => out.push_str("''"),
            '`' | '*' | '?' | '[' | ']' => {
                out.push('`');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

#[cfg(windows)]
pub use win::*;

/// The effectful half: `netsh`, the registry read, `powershell`. Every
/// spawn is hidden (`CREATE_NO_WINDOW`) and bounded — the service host runs
/// these on its start path, and a firewall service that does not answer
/// must cost a deadline, not the daemon.
#[cfg(windows)]
mod win {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Output, Stdio};
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_EXPAND_SZ, REG_SZ, RegCloseKey, RegEnumValueW,
        RegOpenKeyExW,
    };

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    /// The local persistent store (under `HKLM`). GPO-delivered rules live
    /// elsewhere (`SOFTWARE\Policies\…`) and are deliberately not read: we
    /// could not remove them, and must not try.
    pub const FIREWALL_RULES_SUBKEY: &str =
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

    /// Why a bounded spawn produced no `Output`.
    #[derive(Debug)]
    pub enum RunError {
        /// The program could not be started (or the helper thread could not).
        Spawn(std::io::Error),
        /// The deadline passed. The child is left to finish on its own —
        /// netsh and PowerShell always do — so its effect still lands, late;
        /// callers log it as such.
        TimedOut,
    }

    impl std::fmt::Display for RunError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                RunError::Spawn(e) => write!(f, "spawn failed: {e}"),
                RunError::TimedOut => f.write_str("timed out"),
            }
        }
    }

    /// Run `program args…` hidden, with a deadline. `Command::output` has
    /// none, so it runs on a helper thread and the deadline sits on the
    /// channel.
    pub fn run_bounded(
        program: &str,
        args: &[String],
        timeout: Duration,
    ) -> Result<Output, RunError> {
        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("meshharbor-winfw".into())
            .spawn(move || {
                let _ = tx.send(cmd.output());
            })
            .map_err(RunError::Spawn)?;
        match rx.recv_timeout(timeout) {
            Ok(Ok(o)) => Ok(o),
            Ok(Err(e)) => Err(RunError::Spawn(e)),
            Err(_) => Err(RunError::TimedOut),
        }
    }

    /// stderr if any, else stdout — lossy, trimmed, capped for a log line.
    fn output_text(o: &Output) -> String {
        let raw = if o.stderr.is_empty() {
            &o.stdout
        } else {
            &o.stderr
        };
        let s = String::from_utf8_lossy(raw);
        let s = s.trim();
        if s.len() <= 300 {
            return s.to_string();
        }
        let mut cut = 300;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…", &s[..cut])
    }

    /// What [`ensure_udp_in_allow`] achieved.
    #[derive(Debug)]
    pub enum EnsureOutcome {
        /// `netsh add` returned success — the rule exists with our path.
        Installed,
        /// `netsh add` ran and refused (unelevated, or a firewall service
        /// that will not take local rules).
        AddFailed { status: Option<i32>, stderr: String },
        /// netsh could not be run, or did not answer within the deadline.
        Failed(RunError),
    }

    /// delete + add, each `netsh` call bounded by `per_call_timeout`. A
    /// delete that fails is the normal first-run case (no such rule) and is
    /// ignored; a delete that TIMES OUT skips the add — netsh is unhealthy
    /// and a second wait buys nothing.
    pub fn ensure_udp_in_allow(rule: &UdpInAllowRule, per_call_timeout: Duration) -> EnsureOutcome {
        if let Err(RunError::TimedOut) =
            run_bounded("netsh", &rule.netsh_delete_args(), per_call_timeout)
        {
            return EnsureOutcome::Failed(RunError::TimedOut);
        }
        match run_bounded("netsh", &rule.netsh_add_args(), per_call_timeout) {
            Ok(o) if o.status.success() => EnsureOutcome::Installed,
            Ok(o) => EnsureOutcome::AddFailed {
                status: o.status.code(),
                stderr: output_text(&o),
            },
            Err(e) => EnsureOutcome::Failed(e),
        }
    }

    /// RAII wrapper so the HKEY is closed on every exit path.
    struct OpenKey(HKEY);
    impl Drop for OpenKey {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the handle came from RegOpenKeyExW and is closed once.
                unsafe { RegCloseKey(self.0) };
            }
        }
    }

    /// Read every rule in the local persistent store. Read-only; values
    /// that are not rule strings are skipped.
    pub fn read_local_store() -> std::io::Result<Vec<StoredRule>> {
        let wpath: Vec<u16> = FIREWALL_RULES_SUBKEY
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut raw: HKEY = std::ptr::null_mut();
        // SAFETY: wpath is NUL-terminated and outlives the call; `raw` is a
        // valid out-pointer.
        let rc =
            unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, wpath.as_ptr(), 0, KEY_READ, &mut raw) };
        if rc != ERROR_SUCCESS || raw.is_null() {
            return Err(std::io::Error::from_raw_os_error(rc as i32));
        }
        let key = OpenKey(raw);

        let mut out = Vec::new();
        // A value name is at most 16 383 chars; rule strings are a few
        // hundred bytes, grown on ERROR_MORE_DATA.
        let mut name_buf = vec![0u16; 16_384];
        let mut data_buf = vec![0u8; 8 * 1024];
        let mut index = 0u32;
        loop {
            let mut name_len = name_buf.len() as u32;
            let mut data_len = data_buf.len() as u32;
            let mut value_type = 0u32;
            // SAFETY: every pointer is to a live buffer of the length passed
            // beside it (chars for the name, bytes for the data), per the
            // RegEnumValueW contract; lpReserved is null as required.
            let rc = unsafe {
                RegEnumValueW(
                    key.0,
                    index,
                    name_buf.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null_mut(),
                    &mut value_type,
                    data_buf.as_mut_ptr(),
                    &mut data_len,
                )
            };
            if rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            if rc == ERROR_MORE_DATA {
                // `data_len` now holds the required size. Grow and retry the
                // same index; a value nothing reasonable could hold is skipped.
                let need = (data_len as usize).max(data_buf.len() * 2);
                if need > 4 * 1024 * 1024 {
                    index += 1;
                    continue;
                }
                data_buf.resize(need, 0);
                continue;
            }
            if rc != ERROR_SUCCESS {
                return Err(std::io::Error::from_raw_os_error(rc as i32));
            }
            index += 1;
            if value_type != REG_SZ && value_type != REG_EXPAND_SZ {
                continue;
            }
            let id = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let wide: Vec<u16> = data_buf[..data_len as usize]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&w| w != 0)
                .collect();
            let value = String::from_utf16_lossy(&wide);
            if let Some(rule) = parse_stored_rule(&id, &value) {
                out.push(rule);
            }
        }
        Ok(out)
    }

    /// The self-heal's question: does the store already hold exactly our
    /// rule ([`rule_is_current`])? `None` when the store cannot be read, in
    /// which case the caller heals unconditionally.
    pub fn current_rule_present(rule: &UdpInAllowRule) -> Option<bool> {
        read_local_store().ok().map(|s| rule_is_current(&s, rule))
    }

    /// What [`remove_prompt_block_rules_for`] achieved.
    #[derive(Debug)]
    pub enum CleanupOutcome {
        /// The store holds no prompt-written inbound Block rule for this path.
        NothingToRemove,
        /// PowerShell returned success for these ids; `remaining` is how
        /// many matching rules a re-read of the store still saw (`None` if
        /// the re-read failed).
        Removed {
            ids: Vec<String>,
            remaining: Option<usize>,
        },
        /// PowerShell ran and refused.
        RemoveFailed {
            ids: Vec<String>,
            status: Option<i32>,
            stderr: String,
        },
        /// PowerShell could not be run, or did not answer within the deadline.
        Failed { ids: Vec<String>, error: RunError },
        /// The store could not be read — nothing was attempted.
        StoreUnreadable(std::io::Error),
    }

    /// Remove every **prompt-written** inbound Block rule whose program is
    /// exactly `exe` ([`prompt_block_rules_for_program`] is the whole
    /// decision — a deliberate Block is never selected), by store id, through
    /// the firewall service. One bounded PowerShell spawn, and only when there
    /// is something to remove — the steady state costs a registry read.
    pub fn remove_prompt_block_rules_for(exe: &Path, timeout: Duration) -> CleanupOutcome {
        let store = match read_local_store() {
            Ok(s) => s,
            Err(e) => return CleanupOutcome::StoreUnreadable(e),
        };
        let exe_str = exe.to_string_lossy();
        let ids: Vec<String> = prompt_block_rules_for_program(&store, &exe_str)
            .into_iter()
            .map(|r| r.id.clone())
            .collect();
        if ids.is_empty() {
            return CleanupOutcome::NothingToRemove;
        }
        let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        match run_bounded("powershell", &powershell_remove_args(&id_refs), timeout) {
            Ok(o) if o.status.success() => {
                let remaining = read_local_store()
                    .ok()
                    .map(|s| prompt_block_rules_for_program(&s, &exe_str).len());
                CleanupOutcome::Removed { ids, remaining }
            }
            Ok(o) => CleanupOutcome::RemoveFailed {
                ids,
                status: o.status.code(),
                stderr: output_text(&o),
            },
            Err(error) => CleanupOutcome::Failed { ids, error },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// The value strings the local store holds, verbatim in shape
    /// ([MS-FASP] rule-string grammar: a `vMAJOR.MINOR` token, then
    /// `Key=Value` tokens, `|`-separated, trailing `|`). Ids are the value
    /// NAMES — what PowerShell calls `Name`, distinct from the display name.
    const OUR_EXE: &str = r"C:\Program Files\MeshHarbor\meshharbord.exe";

    /// The two Block rules a fresh 0.4.104 attended guest held while its
    /// prompt was up (#1712 review, field-read): ids and program spelled
    /// exactly as the store had them — the prompt lower-cases the path in
    /// both the id and `App=`.
    fn prompt_block(proto: u32) -> StoredRule {
        let (tag, guid) = if proto == 6 {
            ("TCP", "C7351DFF-C214-482C-83AB-2C48537B62E8")
        } else {
            ("UDP", "9A4DA9F2-F9BF-4137-913A-0165EF107A8F")
        };
        let id =
            format!("{tag} Query User{{{guid}}}C:\\program files\\meshharbor\\meshharbord.exe");
        let value = format!(
            "v2.33|Action=Block|Active=TRUE|Dir=In|Protocol={proto}|Profile=Public|App=C:\\program files\\meshharbor\\meshharbord.exe|Name=MeshHarbor Daemon|Desc=MeshHarbor Daemon|Defer=User|"
        );
        parse_stored_rule(&id, &value).expect("fixture parses")
    }

    /// Our own rule as netsh wrote it on the same guest: a `{GUID}` id, the
    /// display name, no `Profile=` token (= all profiles).
    fn our_allow() -> StoredRule {
        parse_stored_rule(
            "{F5EF881B-E1FF-4064-8704-30B2B9E8FDC4}",
            &format!(
                "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|App={OUR_EXE}|Name=MeshHarbor UDP-In (meshharbord)|Desc=|EmbedCtxt=|"
            ),
        )
        .expect("fixture parses")
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    // ── the rule ────────────────────────────────────────────────────────

    #[test]
    fn rule_name_carries_the_exe_stem_and_the_program_is_the_full_path() {
        let r = UdpInAllowRule::for_exe(Path::new(OUR_EXE));
        assert_eq!(r.name, "MeshHarbor UDP-In (meshharbord)");
        assert_eq!(r.program, OUR_EXE);
        // The tunnel client gets its own rule — the two never fight.
        let c = UdpInAllowRule::for_exe(Path::new(r"C:\Tools\meshharbor.exe"));
        assert_eq!(c.name, "MeshHarbor UDP-In (meshharbor)");
    }

    /// The rule's stem comes from the text of the path, so the Ubuntu CI lane
    /// — where `Path::file_stem` would read `C:\…\meshharbord` as one component
    /// — names the rule exactly as a Windows host does. (The first CI run of
    /// #1712 caught precisely that.)
    #[test]
    fn rule_stem_is_derived_from_the_text_so_a_windows_path_reads_the_same_everywhere() {
        assert_eq!(
            windows_file_stem(r"C:\Program Files\MeshHarbor\meshharbord.exe"),
            Some("meshharbord")
        );
        assert_eq!(
            windows_file_stem("C:/Tools/meshharbor.exe"),
            Some("meshharbor")
        );
        assert_eq!(windows_file_stem("meshharbord.exe"), Some("meshharbord"));
        assert_eq!(windows_file_stem(r"C:\x\noext"), Some("noext"));
        assert_eq!(windows_file_stem(r"C:\x\.hidden"), Some(".hidden"));
        assert_eq!(windows_file_stem(r"C:\x\a.b.exe"), Some("a.b"));
        assert_eq!(windows_file_stem(r"C:\x\"), None);
        assert_eq!(windows_file_stem(""), None);
        assert_eq!(
            UdpInAllowRule::for_exe(Path::new(r"C:\x\")).name,
            "MeshHarbor UDP-In (meshharbor)"
        );
    }

    /// The exact netsh argument lists `overlay::tun` has shipped since P9 —
    /// the extraction must not change one token, because the field notes and
    /// the measured guest both name this rule shape.
    #[test]
    fn netsh_argument_lists_are_the_historical_ones() {
        let r = UdpInAllowRule::for_exe(Path::new(OUR_EXE));
        assert_eq!(
            r.netsh_delete_args(),
            [
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=MeshHarbor UDP-In (meshharbord)"
            ]
        );
        assert_eq!(
            r.netsh_add_args(),
            [
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=MeshHarbor UDP-In (meshharbord)",
                "dir=in",
                "action=allow",
                "protocol=udp",
                &format!("program={OUR_EXE}"),
            ]
        );
    }

    // ── the store parser ─────────────────────────────────────────────────

    #[test]
    fn store_parser_reads_a_prompt_written_block_rule() {
        let r = prompt_block(17);
        assert!(r.id.starts_with("UDP Query User{"));
        assert_eq!(r.display_name.as_deref(), Some("MeshHarbor Daemon"));
        assert_eq!(r.direction, Some(Direction::In));
        assert_eq!(r.action, Some(Action::Block));
        assert_eq!(r.protocol, Some(17));
        assert_eq!(r.active, Some(true));
        assert_eq!(r.profiles, ["Public"]);
        assert_eq!(
            r.program.as_deref(),
            Some(r"C:\program files\meshharbor\meshharbord.exe")
        );
        // Every key, in order — the strict "is this exactly ours" check reads it.
        assert_eq!(
            r.keys,
            [
                "Action", "Active", "Dir", "Protocol", "Profile", "App", "Name", "Desc", "Defer"
            ]
        );
    }

    #[test]
    fn store_parser_tolerates_unknown_tokens_and_rejects_non_rule_values() {
        // Additive format: a newer Windows adds tokens we have never seen.
        let r = parse_stored_rule(
            "{x}",
            "v2.40|Action=Allow|Dir=Out|Platform=2:6:2|LUAuth=whatever=with=equals|App=%SystemRoot%\\x.exe|",
        )
        .expect("parses");
        assert_eq!(r.direction, Some(Direction::Out));
        assert_eq!(r.action, Some(Action::Allow));
        assert_eq!(r.program.as_deref(), Some("%SystemRoot%\\x.exe"));
        assert_eq!(r.protocol, None);
        // Not a rule string at all (no version token) → None, never a guess.
        assert!(parse_stored_rule("{x}", "Action=Block|Dir=In|").is_none());
        assert!(parse_stored_rule("{x}", "").is_none());
        // Unrecognised enum values stay None rather than defaulting.
        let odd = parse_stored_rule("{x}", "v2.33|Action=Bypass|Dir=Sideways|Active=maybe|")
            .expect("parses");
        assert_eq!(odd.action, None);
        assert_eq!(odd.direction, None);
        assert_eq!(odd.active, None);
    }

    // ── path normalisation ───────────────────────────────────────────────

    #[test]
    fn program_paths_compare_case_insensitively_after_normalisation() {
        let lookup = |k: &str| match k.to_ascii_lowercase().as_str() {
            "programfiles" => Some(r"C:\Program Files".to_string()),
            _ => None,
        };
        let want = normalize_program_path_with(OUR_EXE, lookup);
        for raw in [
            r"C:\program files\meshharbor\meshharbord.exe",
            r#""C:\Program Files\MeshHarbor\meshharbord.exe""#,
            r"  C:\Program Files\MeshHarbor\meshharbord.exe  ",
            r"C:/Program Files/MeshHarbor/meshharbord.exe",
            r"\\?\C:\Program Files\MeshHarbor\meshharbord.exe",
            r"%ProgramFiles%\MeshHarbor\meshharbord.exe",
            r"%PROGRAMFILES%\MeshHarbor\meshharbord.exe",
        ] {
            assert_eq!(normalize_program_path_with(raw, lookup), want, "{raw:?}");
        }
        // An unknown %VAR% is left alone (and therefore never equal to ours).
        assert_ne!(
            normalize_program_path_with(r"%NoSuchVar%\MeshHarbor\meshharbord.exe", lookup),
            want
        );
        // A different directory is a different program, whatever the file name.
        assert_ne!(
            normalize_program_path_with(r"C:\Users\x\Downloads\meshharbord.exe", lookup),
            want
        );
    }

    // ── the cleanup predicate ────────────────────────────────────────────

    /// The prompt's id signature, and only that: case-sensitive, both
    /// protocols, nothing that merely mentions the words.
    #[test]
    fn prompt_written_ids_are_recognised_by_their_exact_prefix() {
        for id in [
            "TCP Query User{C7351DFF-C214-482C-83AB-2C48537B62E8}C:\\program files\\meshharbor\\meshharbord.exe",
            "UDP Query User{9A4DA9F2-F9BF-4137-913A-0165EF107A8F}C:\\program files\\meshharbor\\meshharbord.exe",
            "TCP Query User{",
        ] {
            assert!(is_prompt_written_id(id), "{id:?}");
        }
        for id in [
            "{8C1F3A5B-2D4E-4F60-9A7B-1C2D3E4F5A6B}", // netsh / wf.msc
            "Block meshharbor",                       // New-NetFirewallRule -Name
            "tcp query user{1}x",                     // wrong case
            "TCP Query User 1",                       // no brace
            " TCP Query User{1}",                     // not a prefix
            "ICMP Query User{1}",
            "",
        ] {
            assert!(!is_prompt_written_id(id), "{id:?}");
        }
    }

    /// The whole decision, against a store that holds everything the
    /// predicate must NOT touch next to the rules it must. Every row that is
    /// a Block for our exact path but NOT prompt-written is the tampering
    /// case the id condition exists for.
    #[test]
    fn cleanup_selects_only_prompt_written_inbound_blocks_for_our_exact_path() {
        let other_exe_same_name = parse_stored_rule(
            "TCP Query User{1}C:\\users\\x\\downloads\\meshharbord.exe",
            "v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|App=C:\\users\\x\\downloads\\meshharbord.exe|Name=MeshHarbor Daemon|",
        )
        .unwrap();
        let other_program_our_display_name = parse_stored_rule(
            "{2}",
            "v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|App=C:\\other\\thing.exe|Name=MeshHarbor Daemon|",
        )
        .unwrap();
        let outbound_block_ours = parse_stored_rule(
            "UDP Query User{3}C:\\program files\\meshharbor\\meshharbord.exe",
            &format!("v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=17|App={OUR_EXE}|Name=x|"),
        )
        .unwrap();
        let block_without_program = parse_stored_rule(
            "UDP Query User{4}",
            "v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=5000|Name=MeshHarbor Daemon|",
        )
        .unwrap();
        let block_missing_action = parse_stored_rule(
            "UDP Query User{5}C:\\program files\\meshharbor\\meshharbord.exe",
            &format!("v2.33|Active=TRUE|Dir=In|Protocol=17|App={OUR_EXE}|Name=x|"),
        )
        .unwrap();
        // The prompt's own Allow pair — someone clicked Allow. Never touched.
        let prompt_allow_ours_udp = parse_stored_rule(
            "UDP Query User{6}C:\\program files\\meshharbor\\meshharbord.exe",
            "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|Profile=Private|App=C:\\program files\\meshharbor\\meshharbord.exe|Name=MeshHarbor Daemon|",
        )
        .unwrap();
        let prompt_allow_ours_tcp = parse_stored_rule(
            "TCP Query User{6}C:\\program files\\meshharbor\\meshharbord.exe",
            "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|App=C:\\program files\\meshharbor\\meshharbord.exe|Name=MeshHarbor Daemon|",
        )
        .unwrap();
        // A prompt-written Block an admin later disabled: still the prompt's.
        let disabled_prompt_block_ours = parse_stored_rule(
            "UDP Query User{7}C:\\program files\\meshharbor\\meshharbord.exe",
            "v2.33|Action=Block|Active=FALSE|Dir=In|Protocol=17|Profile=Public|App=C:\\program files\\meshharbor\\meshharbord.exe|Name=MeshHarbor Daemon|",
        )
        .unwrap();
        // Synthetic: a prompt-shaped id whose path uses the %VAR% spelling,
        // to lock normalisation under the full predicate.
        let env_form_prompt_block_ours = parse_stored_rule(
            "TCP Query User{8}C:\\program files\\meshharbor\\meshharbord.exe",
            "v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|App=%ProgramFiles%\\MeshHarbor\\meshharbord.exe|Name=MeshHarbor Daemon|",
        )
        .unwrap();
        // DELIBERATE Blocks for our exact program — an administrator's
        // decision, in every id shape the tools produce. Never selected.
        let deliberate_block_netsh = parse_stored_rule(
            "{8C1F3A5B-2D4E-4F60-9A7B-1C2D3E4F5A6B}",
            &format!("v2.33|Action=Block|Active=TRUE|Dir=In|App={OUR_EXE}|Name=Block meshharbor|"),
        )
        .unwrap();
        let deliberate_block_powershell = parse_stored_rule(
            "Block meshharbor",
            &format!(
                "v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|App={OUR_EXE}|Name=Block meshharbor|Desc=security team|"
            ),
        )
        .unwrap();
        let deliberate_block_lowercase_lookalike = parse_stored_rule(
            "udp query user{9}c:\\program files\\meshharbor\\meshharbord.exe",
            &format!("v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|App={OUR_EXE}|Name=MeshHarbor Daemon|"),
        )
        .unwrap();

        let store = vec![
            our_allow(),
            prompt_block(6),
            other_exe_same_name,
            deliberate_block_netsh,
            prompt_block(17),
            other_program_our_display_name,
            outbound_block_ours,
            block_without_program,
            deliberate_block_powershell,
            block_missing_action,
            prompt_allow_ours_udp,
            prompt_allow_ours_tcp,
            disabled_prompt_block_ours,
            env_form_prompt_block_ours,
            deliberate_block_lowercase_lookalike,
        ];
        let lookup = |k: &str| {
            (k.eq_ignore_ascii_case("ProgramFiles")).then(|| r"C:\Program Files".to_string())
        };
        let picked: Vec<&str> = prompt_block_rules_for_program_with(&store, OUR_EXE, lookup)
            .into_iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(
            picked,
            [
                "TCP Query User{C7351DFF-C214-482C-83AB-2C48537B62E8}C:\\program files\\meshharbor\\meshharbord.exe",
                "UDP Query User{9A4DA9F2-F9BF-4137-913A-0165EF107A8F}C:\\program files\\meshharbor\\meshharbord.exe",
                // A disabled prompt Block for our path is still the prompt's.
                "UDP Query User{7}C:\\program files\\meshharbor\\meshharbord.exe",
                // An env-var spelling of our path IS our path.
                "TCP Query User{8}C:\\program files\\meshharbor\\meshharbord.exe",
            ]
        );
        // And with nothing of the prompt's in the store, nothing is picked.
        let picked = prompt_block_rules_for_program_with(&store[..1], OUR_EXE, lookup);
        assert!(picked.is_empty());
    }

    /// The store of a fresh 0.4.104 attended guest, read in the field while
    /// its prompt was up (#1712 review): exactly three rules named
    /// `meshharbord.exe`. Both decisions this module makes, against that store
    /// verbatim — the cleanup takes the prompt's two Blocks and nothing else,
    /// and the self-heal sees our netsh-written Allow as current.
    #[test]
    fn field_guest_store_from_1698_drives_both_decisions() {
        let store = [
            parse_stored_rule(
                "TCP Query User{C7351DFF-C214-482C-83AB-2C48537B62E8}C:\\program files\\meshharbor\\meshharbord.exe",
                "v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|App=C:\\program files\\meshharbor\\meshharbord.exe|Name=MeshHarbor Daemon|Desc=MeshHarbor Daemon|Defer=User|",
            )
            .unwrap(),
            parse_stored_rule(
                "UDP Query User{9A4DA9F2-F9BF-4137-913A-0165EF107A8F}C:\\program files\\meshharbor\\meshharbord.exe",
                "v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Public|App=C:\\program files\\meshharbor\\meshharbord.exe|Name=MeshHarbor Daemon|Desc=MeshHarbor Daemon|Defer=User|",
            )
            .unwrap(),
            parse_stored_rule(
                "{F5EF881B-E1FF-4064-8704-30B2B9E8FDC4}",
                &format!(
                    "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|App={OUR_EXE}|Name=MeshHarbor UDP-In (meshharbord)|"
                ),
            )
            .unwrap(),
        ];
        // The id signature separates the prompt's rules from ours.
        assert!(is_prompt_written_id(&store[0].id));
        assert!(is_prompt_written_id(&store[1].id));
        assert!(!is_prompt_written_id(&store[2].id));
        // The cleanup: the prompt's two Blocks, by id, nothing else — even
        // though their `App=` is lower-cased and ours is not.
        let picked: Vec<&str> = prompt_block_rules_for_program_with(&store, OUR_EXE, no_env)
            .into_iter()
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(
            picked,
            [
                "TCP Query User{C7351DFF-C214-482C-83AB-2C48537B62E8}C:\\program files\\meshharbor\\meshharbord.exe",
                "UDP Query User{9A4DA9F2-F9BF-4137-913A-0165EF107A8F}C:\\program files\\meshharbor\\meshharbord.exe",
            ]
        );
        // The self-heal: our Allow is present once, unrestricted, current.
        let rule = UdpInAllowRule::for_exe(Path::new(OUR_EXE));
        assert!(rule_is_current_with(&store, &rule, no_env));
        // And after the cleanup has run (the two Blocks gone), still current,
        // and nothing left to remove.
        assert!(rule_is_current_with(&store[2..], &rule, no_env));
        assert!(prompt_block_rules_for_program_with(&store[2..], OUR_EXE, no_env).is_empty());
    }

    // ── the PowerShell removal ───────────────────────────────────────────

    #[test]
    fn removal_targets_the_store_id_and_escapes_the_powershell_literal() {
        let ids = [
            "UDP Query User{5B2C}C:\\program files\\meshharbor\\meshharbord.exe",
            // Everything PowerShell would otherwise interpret: the string
            // quote, and the four wildcard characters plus their escape.
            "odd 'name' [1] *?`x",
        ];
        let args = powershell_remove_args(&ids);
        assert_eq!(&args[..3], ["-NoProfile", "-NonInteractive", "-Command"]);
        assert_eq!(args.len(), 4);
        let cmd = &args[3];
        assert!(cmd.starts_with("Remove-NetFirewallRule "), "{cmd}");
        assert!(cmd.contains("-PolicyStore PersistentStore"), "{cmd}");
        assert!(cmd.contains("-ErrorAction Stop"), "{cmd}");
        // By id (`-Name`), never by display name.
        assert!(!cmd.contains("DisplayName"), "{cmd}");
        assert!(
            cmd.contains(
                "-Name @('UDP Query User{5B2C}C:\\program files\\meshharbor\\meshharbord.exe','odd ''name'' `[1`] `*`?``x')"
            ),
            "{cmd}"
        );
    }

    // ── the self-heal's "already current" check ──────────────────────────

    #[test]
    fn rule_is_current_only_for_exactly_what_netsh_wrote() {
        let rule = UdpInAllowRule::for_exe(Path::new(OUR_EXE));
        let ok = |store: &[StoredRule]| rule_is_current_with(store, &rule, no_env);

        // Exactly ours, present once → current (the self-heal may skip).
        assert!(ok(&[our_allow(), prompt_block(6)]));
        // All-three-profiles spelling is "all profiles" too.
        let all_profiles = parse_stored_rule(
            "{a}",
            &format!(
                "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|Profile=Domain|Profile=Private|Profile=Public|App={OUR_EXE}|Name=MeshHarbor UDP-In (meshharbord)|"
            ),
        )
        .unwrap();
        assert!(ok(&[all_profiles]));

        // Absent → heal.
        assert!(!ok(&[prompt_block(6)]));
        // Stale program path (a moved install) → heal.
        let stale = parse_stored_rule(
            "{b}",
            "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|App=D:\\old\\meshharbord.exe|Name=MeshHarbor UDP-In (meshharbord)|",
        )
        .unwrap();
        assert!(!ok(&[stale]));
        // Disabled → heal.
        let disabled = parse_stored_rule(
            "{c}",
            &format!("v2.33|Action=Allow|Active=FALSE|Dir=In|Protocol=17|App={OUR_EXE}|Name=MeshHarbor UDP-In (meshharbord)|"),
        )
        .unwrap();
        assert!(!ok(&[disabled]));
        // Restricted to one profile → heal.
        let one_profile = parse_stored_rule(
            "{d}",
            &format!("v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|Profile=Private|App={OUR_EXE}|Name=MeshHarbor UDP-In (meshharbord)|"),
        )
        .unwrap();
        assert!(!ok(&[one_profile]));
        // An extra clause someone edited in (a port, an address) → heal.
        let narrowed = parse_stored_rule(
            "{e}",
            &format!("v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=41641|App={OUR_EXE}|Name=MeshHarbor UDP-In (meshharbord)|"),
        )
        .unwrap();
        assert!(!ok(&[narrowed]));
        // Duplicates → heal (delete+add collapses them into one).
        assert!(!ok(&[our_allow(), our_allow()]));
        // Same display name, wrong action/protocol → heal.
        let tcp = parse_stored_rule(
            "{f}",
            &format!("v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App={OUR_EXE}|Name=MeshHarbor UDP-In (meshharbord)|"),
        )
        .unwrap();
        assert!(!ok(&[tcp]));
    }

    /// Read-only smoke against the LIVE store of the Windows box running the
    /// tests: the registry walk and the parser against real data, and the
    /// verdicts the two production callers would reach for `meshharbord.exe`
    /// there. Adds nothing, removes nothing. Ignored because it reads machine
    /// state; run by hand with `--ignored --nocapture` on a Windows dev box.
    #[cfg(windows)]
    #[test]
    #[ignore = "reads the live firewall rule store; run by hand on a Windows box"]
    fn live_store_smoke_read_only() {
        let store = read_local_store().expect("the local store is readable");
        let inbound_blocks_with_program = store
            .iter()
            .filter(|r| {
                r.direction == Some(Direction::In)
                    && r.action == Some(Action::Block)
                    && r.program.is_some()
            })
            .count();
        println!(
            "store: {} rules; {} inbound Block rules carry a program",
            store.len(),
            inbound_blocks_with_program
        );
        for exe in [
            r"C:\Program Files\MeshHarbor\meshharbord.exe",
            r"C:\Program Files\MeshHarbor\meshharbor.exe",
        ] {
            let rule = UdpInAllowRule::for_exe(Path::new(exe));
            let named: Vec<_> = store
                .iter()
                .filter(|r| r.display_name.as_deref() == Some(rule.name.as_str()))
                .collect();
            println!(
                "{}: {} rule(s) named {:?}; current={}; prompt-written inbound Block rules for this path: {:?}",
                exe,
                named.len(),
                rule.name,
                rule_is_current(&store, &rule),
                prompt_block_rules_for_program(&store, exe)
                    .iter()
                    .map(|r| (&r.id, &r.display_name, r.protocol))
                    .collect::<Vec<_>>()
            );
            for r in named {
                println!("  {:?}", r);
            }
        }
        // Every parsed rule has an id and a version-led string parsed into
        // at least one key; the store is never empty on a Windows box.
        assert!(!store.is_empty());
        assert!(store.iter().all(|r| !r.id.is_empty() && !r.keys.is_empty()));
    }

    /// P9 — the net-hygiene kill-switch parse (moved here from
    /// `overlay::tun`, where it ran only on Windows): only an explicit falsy
    /// value disables; unset / anything else keeps the default ON.
    #[test]
    fn hygiene_kill_switch_parse() {
        assert!(!hygiene_disabled(None));
        assert!(!hygiene_disabled(Some("1")));
        assert!(!hygiene_disabled(Some("weird")));
        assert!(hygiene_disabled(Some("0")));
        assert!(hygiene_disabled(Some(" FALSE ")));
        assert!(hygiene_disabled(Some("no")));
        assert!(hygiene_disabled(Some("off")));
    }
}
