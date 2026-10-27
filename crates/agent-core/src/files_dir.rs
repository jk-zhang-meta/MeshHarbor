// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-84 D4 — `files_dir`: where files dropped onto a remote-control session
//! land on this device, and the rules that make it safe to let a person set.
//!
//! ## Why a folder setting is a security control here
//!
//! The daemon writes dropped files as WHATEVER IDENTITY IT RUNS UNDER — on a
//! machine-wide Windows install that is `LocalSystem`, inside the interactive
//! user's session. And the LocalAPI that carries `ConfigSet` admits every
//! interactive user: the pipe's SDDL grants `IU`
//! (`crates/localapi/src/lib.rs`, `LOCALAPI_SDDL`), so a non-admin at the
//! keyboard can drive the verb. Without a rule, that person could point
//! `files_dir` at `C:\Windows\…` and have SYSTEM write remote-supplied bytes
//! there on the next drop. Hence three checks, in this order:
//!
//! 1. **Shape** — absolute, or `~`-relative; no device / kernel-namespace
//!    paths (`\\?\`, `\\.\`, `\??\`, `\Device\`, anything naming
//!    `GLOBALROOT`); no administrative or device UNC shares (`\\host\C$`,
//!    `\\host\ADMIN$`, `\\host\pipe`, `\\host\IPC$`); no `..` component;
//!    on Windows no component the OS would silently rewrite (a trailing dot
//!    or space — `C:\Windows.\Temp` IS `C:\Windows\Temp`) or read as
//!    something other than a folder name (`name:stream`).
//! 2. **Placement** — never under a system root (`%WINDIR%`,
//!    `%ProgramFiles%`, `%ProgramFiles(x86)%`; `/etc`, `/usr`, `/bin`,
//!    `/sbin`, `/System`, `/Library`, …) and — **when the writer is SYSTEM or
//!    root** — inside the ACTIVE user's profile. `~` expands against that
//!    same profile at USE time, so one machine-global config stays right for
//!    whoever is logged in.
//! 3. **Reality** — the folder must exist or be creatable, and be writable (a
//!    probe file is written and removed). Junctions and symlinks are followed
//!    before the placement rule is re-checked, so a link inside the profile
//!    that points at `C:\Windows` is refused too — and for a privileged
//!    writer a path whose real location cannot be determined is refused
//!    rather than assumed to be where it is spelled.
//!
//! The same validator runs at SET time (the daemon refuses a `ConfigSet` it
//! would not honour, with the reason verbatim) and at USE time (every drop
//! re-validates the configured value and falls back to the default folder with
//! a warning). **Use time is the load-bearing gate**: the desktop's
//! direct-file fallback and a hand edit write the config AS THE USER, with no
//! daemon in the path to refuse.
//!
//! `config_surface::apply` runs only the SHAPE check ([`check_shape`]) — it has
//! no writer identity and must not touch the disk. The daemon owns placement
//! and reality ([`validate`]), and reports the effective folder on
//! `NodeStatus.files_dir`.
//!
//! Everything but [`ensure_writable`] and the on-disk re-check is pure string
//! work parameterised on [`Rules::windows`], so the Windows rules are
//! unit-tested on every CI host and the Unix rules on Windows.

use std::path::{Path, PathBuf};

/// Who is going to write into the folder — the daemon describes itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Writer {
    /// SYSTEM (Windows) or root (Unix): the folder must sit inside
    /// `active_home`.
    pub privileged: bool,
    /// The ACTIVE user's profile / home directory, as this process can best
    /// determine it right now: the WTS session's user under a SystemContext
    /// worker, the process owner's home otherwise. `None` = unknown (nobody
    /// logged in), which refuses every `~` path and — for a privileged
    /// writer — every path at all.
    pub active_home: Option<String>,
}

impl Writer {
    /// An unprivileged writer: the folder rules apply, the profile rule does
    /// not — this process can only ever write where its own user can.
    pub fn unprivileged(active_home: Option<String>) -> Self {
        Self {
            privileged: false,
            active_home,
        }
    }
}

/// Path semantics plus the roots nothing may land under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rules {
    /// Windows semantics: `\` and `/` both separate, drive-letter and UNC
    /// prefixes, case-insensitive comparison.
    pub windows: bool,
    /// Absolute roots (in the same semantics) under which no drop folder may
    /// sit, however it was spelled.
    pub denied_roots: Vec<String>,
}

/// The Unix roots a drop folder may never sit under. `/System` and
/// `/Library` are macOS; the rest are every Unix. A user's own `~/Library`
/// is NOT matched — the check is on the absolute path's leading components.
const UNIX_DENIED_ROOTS: &[&str] = &[
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/System",
    "/Library",
    "/private/etc",
];

impl Rules {
    /// The rules for THIS host: Windows reads the system roots from the
    /// environment (`%WINDIR%` / `%SystemRoot%`, `%ProgramFiles%`,
    /// `%ProgramFiles(x86)%`, `%ProgramW6432%`) with the stock locations as
    /// fallbacks, so a host that unset one still refuses the stock folder.
    pub fn from_env() -> Self {
        if cfg!(windows) {
            let mut denied_roots: Vec<String> = Vec::new();
            for (var, fallback) in [
                ("WINDIR", Some(r"C:\Windows")),
                ("SystemRoot", None),
                ("ProgramFiles", Some(r"C:\Program Files")),
                ("ProgramFiles(x86)", Some(r"C:\Program Files (x86)")),
                ("ProgramW6432", None),
            ] {
                match std::env::var(var) {
                    Ok(v) if !v.trim().is_empty() => denied_roots.push(v.trim().to_string()),
                    _ => {
                        if let Some(f) = fallback {
                            denied_roots.push(f.to_string());
                        }
                    }
                }
            }
            Rules {
                windows: true,
                denied_roots,
            }
        } else {
            Rules {
                windows: false,
                denied_roots: UNIX_DENIED_ROOTS.iter().map(|s| s.to_string()).collect(),
            }
        }
    }
}

/// A path taken apart: the absolute prefix and its components, with `.` and
/// empty components dropped and `..` refused. `tilde` = `~`-relative, with
/// `prefix` empty until the writer's home is known.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Parsed {
    tilde: bool,
    /// `C:\`, `\\host\share\` or `/` — already in display form.
    prefix: String,
    /// Original casing, for display and the rendered path.
    comps: Vec<String>,
}

/// Shape only: what `config_surface::apply` can check without a writer
/// identity and without touching the disk — the syntax rules, and for an
/// absolute path the system roots (those need no identity). `~/…` is
/// accepted unexpanded; whose profile it lands in, and whether that profile
/// is itself somewhere forbidden, is the daemon's question at set and use
/// time.
pub fn check_shape(raw: &str, rules: &Rules) -> Result<(), String> {
    let parsed = parse(raw, rules)?;
    if parsed.tilde {
        return Ok(());
    }
    place(&parsed, &Writer::unprivileged(None), rules).map(|_| ())
}

/// Shape + placement: the folder this value names for THIS writer, right
/// now (`~` expanded against the active profile; system roots and the
/// SYSTEM/root profile rule enforced). No disk access.
pub fn resolve(raw: &str, writer: &Writer, rules: &Rules) -> Result<PathBuf, String> {
    place(&parse(raw, rules)?, writer, rules)
}

/// Everything: [`resolve`], then the on-disk re-check through any link on the
/// way, then create-if-missing + a write probe, then the re-check again on
/// the now-existing folder. This is what the daemon runs at set time and at
/// every drop.
pub fn validate(raw: &str, writer: &Writer, rules: &Rules) -> Result<PathBuf, String> {
    let path = resolve(raw, writer, rules)?;
    check_placement_on_disk(&path, writer, rules)?;
    ensure_writable(&path)?;
    check_placement_on_disk(&path, writer, rules)?;
    Ok(path)
}

/// `path` re-spelled against `home` — `~`, `~\Drops`, `~/Drops` — when it
/// sits inside it, by the same component rules the placement check uses;
/// `None` when it does not (or either is not a plain absolute path). The
/// desktop stores a picked folder this way: on a machine-wide install the
/// config is one file for everyone, and `~` then lands each signed-in user
/// in their OWN folder, where an absolute path inside one user's profile
/// would be refused for every other user by the SYSTEM rule.
pub fn tilde_form(path: &str, home: &str, rules: &Rules) -> Option<String> {
    let p = parse(path, rules).ok()?;
    let h = parse(home, rules).ok()?;
    if p.tilde || h.tilde || !is_under(&p, &h, rules.windows) {
        return None;
    }
    let rest = &p.comps[h.comps.len()..];
    let sep = if rules.windows { "\\" } else { "/" };
    Some(if rest.is_empty() {
        "~".to_string()
    } else {
        format!("~{sep}{}", rest.join(sep))
    })
}

/// Follow junctions / symlinks on the deepest EXISTING part of `path` and
/// re-run the placement rules on where it really goes. A path with nothing
/// on disk yet has nothing to follow and passes; the caller re-checks after
/// creating it.
///
/// When an existing part cannot be resolved (the OS will not open it for
/// `GetFinalPathNameByHandle` / `realpath`), a PRIVILEGED writer is refused:
/// the placement rule is the only thing between it and a link it cannot
/// see through. An unprivileged writer passes — the OS enforces its own
/// rights on the write, and some network redirectors cannot answer the
/// question at all for a folder the user can perfectly well write to.
pub fn check_placement_on_disk(path: &Path, writer: &Writer, rules: &Rules) -> Result<(), String> {
    let real = match canonical_form(path) {
        Canonical::NothingExists => return Ok(()),
        Canonical::Unresolvable(e) => return unresolvable_verdict(path, &e, writer),
        Canonical::Real(real) => real,
    };
    let shown = path.to_string_lossy();
    let real_s = real.to_string_lossy();
    if same_path(&shown, &real_s, rules.windows) {
        return Ok(());
    }
    // The profile may itself sit behind a link (macOS's `/var` →
    // `/private/var` is the everyday case), so the real path is judged
    // against the real profile as well as the spelled one.
    let real_home_writer = Writer {
        privileged: writer.privileged,
        active_home: writer
            .active_home
            .as_deref()
            .map(|h| match canonical_form(Path::new(h)) {
                Canonical::Real(c) => c.to_string_lossy().into_owned(),
                _ => h.to_string(),
            }),
    };
    let parsed = parse(&real_s, rules)
        .map_err(|e| format!("{shown} resolves through a link to {real_s}: {e}"))?;
    match place(&parsed, &real_home_writer, rules) {
        Ok(_) => Ok(()),
        Err(first) => place(&parsed, writer, rules)
            .map(|_| ())
            .map_err(|_| format!("{shown} resolves through a link to {real_s}: {first}")),
    }
}

/// The verdict on a path whose existing part the OS would not resolve.
fn unresolvable_verdict(path: &Path, e: &std::io::Error, writer: &Writer) -> Result<(), String> {
    if writer.privileged {
        Err(format!(
            "cannot tell where {} really points ({e}), and the service runs as SYSTEM/root, so it is refused",
            path.display()
        ))
    } else {
        Ok(())
    }
}

/// Would [`ensure_writable`] get as far as the write probe — WITHOUT creating
/// or writing anything: the folder exists as a folder, or its deepest
/// existing ancestor is a folder it could be created under. For a caller
/// that must not touch the disk beyond looking (a status answer). What it
/// cannot see — permissions — the drop itself finds out, and falls back.
pub fn check_creatable(dir: &Path) -> Result<(), String> {
    for ancestor in dir.ancestors() {
        match std::fs::metadata(ancestor) {
            Ok(meta) if meta.is_dir() => return Ok(()),
            Ok(_) => {
                return Err(format!("{} exists but is not a folder", ancestor.display()));
            }
            // Missing — or, on Unix, a FILE higher up (`ENOTDIR` for
            // `file/under`): keep walking, the file itself answers below.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                continue;
            }
            // Cannot look (permissions, an unreachable share): the drop
            // itself will tell.
            Err(_) => return Ok(()),
        }
    }
    Ok(())
}

/// Create the folder if it is missing and prove it is writable by creating
/// and removing a probe file. Errors carry the folder and the OS's reason.
pub fn ensure_writable(dir: &Path) -> Result<(), String> {
    match std::fs::metadata(dir) {
        Ok(meta) if !meta.is_dir() => {
            return Err(format!("{} exists but is not a folder", dir.display()));
        }
        Ok(_) => {}
        Err(_) => std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?,
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let probe = dir.join(format!(
        ".roomler-write-probe-{}-{nanos}",
        std::process::id()
    ));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(file) => {
            drop(file);
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => Err(format!("{} is not writable: {e}", dir.display())),
    }
}

// ---------------------------------------------------------------------------
// The pure core

fn parse(raw: &str, rules: &Rules) -> Result<Parsed, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("files_dir is empty".to_string());
    }
    if raw.len() > 4096 {
        return Err("files_dir is longer than 4096 bytes".to_string());
    }
    if raw.contains('\0') {
        return Err("files_dir contains a NUL byte".to_string());
    }
    // The Win32 device / NT kernel namespaces, in every spelling. Checked
    // on every OS: none of these is a folder anywhere, and the `files:get`
    // path already refuses `GLOBALROOT` for the same reason.
    let lowered = raw.to_ascii_lowercase().replace('/', "\\");
    if lowered.starts_with(r"\\?\")
        || lowered.starts_with(r"\\.\")
        || lowered.starts_with(r"\??\")
        || lowered.starts_with(r"\device\")
        || lowered.contains("globalroot")
    {
        return Err(format!(
            "files_dir must be a plain folder path, not a device or kernel-namespace path ({raw})"
        ));
    }

    if raw == "~" || raw.starts_with("~/") || (rules.windows && raw.starts_with("~\\")) {
        let comps = components(&raw[1..], rules)?;
        return Ok(Parsed {
            tilde: true,
            prefix: String::new(),
            comps,
        });
    }
    if raw.starts_with('~') {
        return Err(
            "files_dir may start with `~/` (the active user's profile) but not `~user`".to_string(),
        );
    }

    if rules.windows {
        let b = raw.as_bytes();
        if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && is_sep(b[2], true) {
            let comps = components(&raw[3..], rules)?;
            return Ok(Parsed {
                tilde: false,
                prefix: format!("{}:\\", (b[0] as char).to_ascii_uppercase()),
                comps,
            });
        }
        if b.len() >= 2 && is_sep(b[0], true) && is_sep(b[1], true) {
            let mut parts = raw[2..].split(|c| is_sep_char(c, true));
            let host = parts.next().unwrap_or("");
            let share = parts.next().unwrap_or("");
            if host.is_empty() || share.is_empty() {
                return Err(format!(
                    "files_dir must name a share (\\\\server\\share\\folder), got {raw}"
                ));
            }
            check_windows_component(host)?;
            check_windows_component(share)?;
            let share_l = share.to_ascii_lowercase();
            let admin_share = share_l.len() == 2
                && share_l.ends_with('$')
                && share_l.as_bytes()[0].is_ascii_alphabetic();
            if admin_share || matches!(share_l.as_str(), "pipe" | "ipc$" | "admin$" | "print$") {
                return Err(format!(
                    "files_dir must not be an administrative or device share (\\\\{host}\\{share})"
                ));
            }
            let rest: Vec<&str> = parts.collect();
            let comps = components(&rest.join("\\"), rules)?;
            return Ok(Parsed {
                tilde: false,
                prefix: format!("\\\\{host}\\{share}\\"),
                comps,
            });
        }
        return Err(format!(
            "files_dir must be an absolute path (C:\\… or \\\\server\\share\\…) or start with `~\\`, got {raw}"
        ));
    }

    if let Some(rest) = raw.strip_prefix('/') {
        let comps = components(rest, rules)?;
        return Ok(Parsed {
            tilde: false,
            prefix: "/".to_string(),
            comps,
        });
    }
    Err(format!(
        "files_dir must be an absolute path (/…) or start with `~/`, got {raw}"
    ))
}

fn is_sep(b: u8, windows: bool) -> bool {
    b == b'/' || (windows && b == b'\\')
}

/// [`is_sep`] for a `char` — compared as a char, NEVER narrowed with
/// `as u8`: that truncates, and `į` (U+012F) would become `/` and `Ŝ`
/// (U+015C) `\`, splitting a perfectly good folder name in two.
fn is_sep_char(c: char, windows: bool) -> bool {
    c == '/' || (windows && c == '\\')
}

/// Split the part after the prefix, dropping `.` and empty components and
/// refusing `..` — a drop folder never needs to climb, and a `~/../..` that
/// leaves the profile is exactly what the profile rule must not be talked
/// out of.
fn components(rest: &str, rules: &Rules) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for c in rest.split(|c| is_sep_char(c, rules.windows)) {
        match c {
            "" | "." => {}
            ".." => return Err("files_dir must not contain `..`".to_string()),
            other => {
                if rules.windows {
                    check_windows_component(other)?;
                }
                out.push(other.to_string())
            }
        }
    }
    Ok(out)
}

/// Win32 path normalisation rewrites what the string comparisons compare:
/// it strips a component's trailing dots and spaces (`C:\Windows.\Temp` IS
/// `C:\Windows\Temp`), and `name:stream` names an alternate data stream,
/// not a folder. A component the OS would rewrite could walk straight past
/// the system-root and profile checks, so it is refused outright — as are
/// the characters no Windows folder name may contain.
fn check_windows_component(c: &str) -> Result<(), String> {
    if c.ends_with('.') || c.ends_with(' ') {
        return Err(format!(
            "files_dir: the folder name {c:?} ends with a dot or a space, which Windows silently strips"
        ));
    }
    if let Some(bad) = c
        .chars()
        .find(|ch| matches!(ch, ':' | '*' | '?' | '"' | '<' | '>' | '|') || ch.is_control())
    {
        return Err(format!(
            "files_dir: the folder name {c:?} contains {bad:?}, which a Windows folder name cannot"
        ));
    }
    Ok(())
}

fn place(p: &Parsed, writer: &Writer, rules: &Rules) -> Result<PathBuf, String> {
    let full = if p.tilde {
        let Some(home) = writer.active_home.as_deref() else {
            return Err("`~` in files_dir needs an active user profile to expand against, and none is known right now (nobody logged in?)".to_string());
        };
        let base = parse(home, rules)
            .map_err(|e| format!("the active user's profile path {home} is unusable: {e}"))?;
        if base.tilde {
            return Err(format!(
                "the active user's profile path {home} is not absolute"
            ));
        }
        let mut comps = base.comps;
        comps.extend(p.comps.iter().cloned());
        Parsed {
            tilde: false,
            prefix: base.prefix,
            comps,
        }
    } else {
        p.clone()
    };
    let shown = render(&full, rules.windows);

    for root in &rules.denied_roots {
        if let Ok(r) = parse(root, rules)
            && !r.tilde
            && is_under(&full, &r, rules.windows)
        {
            return Err(format!("files_dir must not be under {root} ({shown})"));
        }
    }

    if writer.privileged {
        let Some(home) = writer.active_home.as_deref() else {
            return Err("the service runs as SYSTEM/root and no active user profile is known right now, so files_dir cannot be honoured".to_string());
        };
        let h = parse(home, rules)
            .map_err(|e| format!("the active user's profile path {home} is unusable: {e}"))?;
        if h.tilde || !is_under(&full, &h, rules.windows) {
            return Err(format!(
                "the service runs as SYSTEM/root, so files_dir must be inside the active user's profile ({home}); {shown} is outside it"
            ));
        }
    }

    Ok(PathBuf::from(shown))
}

fn eq_comp(a: &str, b: &str, ci: bool) -> bool {
    if ci {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// `a` is `b` or sits below it — same prefix, `b`'s components lead `a`'s.
fn is_under(a: &Parsed, b: &Parsed, ci: bool) -> bool {
    eq_comp(&a.prefix, &b.prefix, ci)
        && b.comps.len() <= a.comps.len()
        && a.comps.iter().zip(&b.comps).all(|(x, y)| eq_comp(x, y, ci))
}

fn render(p: &Parsed, windows: bool) -> String {
    let sep = if windows { "\\" } else { "/" };
    format!("{}{}", p.prefix, p.comps.join(sep))
}

fn same_path(a: &str, b: &str, windows: bool) -> bool {
    if windows {
        a.replace('/', "\\")
            .trim_end_matches('\\')
            .eq_ignore_ascii_case(b.replace('/', "\\").trim_end_matches('\\'))
    } else {
        a.trim_end_matches('/') == b.trim_end_matches('/')
    }
}

/// What [`canonical_form`] found on disk.
enum Canonical {
    /// Nothing of the path exists (not even its root) — nothing to follow.
    NothingExists,
    /// The deepest existing part exists but could not be resolved.
    Unresolvable(std::io::Error),
    /// Where the path really points.
    Real(PathBuf),
}

/// Where `path` really points: its deepest EXISTING ancestor canonicalised
/// (links followed, Windows' `\\?\` prefix removed) with the not-yet-existing
/// remainder appended.
fn canonical_form(path: &Path) -> Canonical {
    for ancestor in path.ancestors() {
        if std::fs::metadata(ancestor).is_err() {
            continue;
        }
        let canon = match std::fs::canonicalize(ancestor) {
            Ok(c) => c,
            Err(e) => return Canonical::Unresolvable(e),
        };
        let mut real = strip_verbatim(canon);
        if let Ok(rest) = path.strip_prefix(ancestor)
            && !rest.as_os_str().is_empty()
        {
            real.push(rest);
        }
        return Canonical::Real(real);
    }
    Canonical::NothingExists
}

/// `\\?\C:\x` → `C:\x`, `\\?\UNC\host\share` → `\\host\share`. A no-op for
/// anything else, including every Unix path.
pub fn strip_verbatim(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn win() -> Rules {
        Rules {
            windows: true,
            denied_roots: vec![
                r"C:\Windows".into(),
                r"C:\Program Files".into(),
                r"C:\Program Files (x86)".into(),
            ],
        }
    }

    fn nix() -> Rules {
        Rules {
            windows: false,
            denied_roots: UNIX_DENIED_ROOTS.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn alice() -> Writer {
        Writer::unprivileged(Some(r"C:\Users\alice".into()))
    }

    fn system_for_alice() -> Writer {
        Writer {
            privileged: true,
            active_home: Some(r"C:\Users\alice".into()),
        }
    }

    fn bob() -> Writer {
        Writer::unprivileged(Some("/home/bob".into()))
    }

    fn root_on_bobs_box() -> Writer {
        Writer {
            privileged: true,
            active_home: Some("/home/bob".into()),
        }
    }

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn absolute_paths_pass_and_render_normalised() {
        assert_eq!(
            resolve(r"C:/Users/alice/Drops/", &alice(), &win()).unwrap(),
            p(r"C:\Users\alice\Drops")
        );
        assert_eq!(
            resolve(r"c:\users\alice\.\Drops\\x", &alice(), &win()).unwrap(),
            p(r"C:\users\alice\Drops\x"),
            "separators and `.` normalise; the drive letter is upper-cased, the rest keeps its case"
        );
        assert_eq!(
            resolve(r"\\nas\public\drops", &alice(), &win()).unwrap(),
            p(r"\\nas\public\drops")
        );
        assert_eq!(
            resolve("/home/bob//drops/./x/", &bob(), &nix()).unwrap(),
            p("/home/bob/drops/x")
        );
        assert_eq!(resolve("/", &bob(), &nix()).unwrap(), p("/"));
    }

    #[test]
    fn relative_empty_and_tilde_user_forms_are_refused() {
        for bad in [
            "", "   ", "drops", "./drops", "C:drops", r"\drops", "~alice/x", "~user",
        ] {
            assert!(
                resolve(bad, &alice(), &win()).is_err(),
                "{bad:?} must be refused on Windows rules"
            );
        }
        for bad in ["", "drops", "./drops", "~bob/x", r"~\drops"] {
            assert!(
                resolve(bad, &bob(), &nix()).is_err(),
                "{bad:?} must be refused on Unix rules (`~\\x` is a `~user` form there)"
            );
        }
    }

    #[test]
    fn device_and_kernel_namespace_paths_are_refused() {
        for bad in [
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\x",
            r"\\?\C:\Users\alice\Drops",
            r"\\.\pipe\roomler",
            r"\??\C:\x",
            r"\Device\HarddiskVolume1",
            "//?/C:/x",
            "//./pipe/x",
            r"C:\Users\alice\GLOBALROOT\y",
            r"C:\Users\alice\globalroot",
        ] {
            let err = resolve(bad, &alice(), &win()).unwrap_err();
            assert!(err.contains("device or kernel-namespace"), "{bad:?}: {err}");
        }
        // The same spellings are no folder on Unix either.
        assert!(resolve(r"\\?\GLOBALROOT\x", &bob(), &nix()).is_err());
        assert!(resolve("/home/bob/GLOBALROOT", &bob(), &nix()).is_err());
    }

    #[test]
    fn administrative_and_device_unc_shares_are_refused() {
        for bad in [
            r"\\localhost\C$\Windows",
            r"\\127.0.0.1\d$",
            r"\\host\ADMIN$\x",
            r"\\host\IPC$",
            r"\\host\pipe\roomler",
            r"\\host\print$\x",
            r"\\host",
            r"\\host\",
        ] {
            assert!(
                resolve(bad, &alice(), &win()).is_err(),
                "{bad:?} must be refused"
            );
        }
        assert!(resolve(r"\\host\Public\drops", &alice(), &win()).is_ok());
        assert!(
            resolve(r"\\host\Public$\drops", &alice(), &win()).is_ok(),
            "a hidden share is not an administrative one"
        );
    }

    #[test]
    fn dotdot_is_refused_everywhere() {
        for (bad, w, r) in [
            (r"C:\Users\alice\..\..\Windows", alice(), win()),
            (r"~\..\..\Windows\Temp", alice(), win()),
            ("~/../../etc", bob(), nix()),
            ("/home/bob/../../etc", bob(), nix()),
        ] {
            let err = resolve(bad, &w, &r).unwrap_err();
            assert!(err.contains("`..`"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn system_roots_are_refused_component_wise() {
        for bad in [
            r"C:\Windows\Temp",
            r"c:/windows/temp",
            r"C:\Windows",
            r"C:\Program Files\Roomler\drops",
            r"C:\Program Files (x86)\x",
        ] {
            let err = resolve(bad, &alice(), &win()).unwrap_err();
            assert!(err.contains("must not be under"), "{bad:?}: {err}");
        }
        // A LONGER name that merely starts with the root's spelling is a
        // different folder.
        assert!(resolve(r"C:\Windowsx\drops", &alice(), &win()).is_ok());
        assert!(resolve(r"C:\Program Filesx\drops", &alice(), &win()).is_ok());

        for bad in [
            "/etc/meshharbor",
            "/usr/local/drops",
            "/System/x",
            "/Library/x",
            "/dev/shm/x",
        ] {
            let err = resolve(bad, &bob(), &nix()).unwrap_err();
            assert!(err.contains("must not be under"), "{bad:?}: {err}");
        }
        assert!(resolve("/usrdata/drops", &bob(), &nix()).is_ok());
        assert!(
            resolve("/home/bob/Library/drops", &bob(), &nix()).is_ok(),
            "a user's own Library is not the system one"
        );
        assert!(resolve("/srv/drops", &bob(), &nix()).is_ok());
    }

    #[test]
    fn tilde_expands_per_user() {
        // The same config value lands in a different folder for each user —
        // the point of expanding at USE time against the ACTIVE profile.
        assert_eq!(
            resolve(r"~/Drops", &alice(), &win()).unwrap(),
            p(r"C:\Users\alice\Drops")
        );
        let carol = Writer::unprivileged(Some(r"C:\Users\carol".into()));
        assert_eq!(
            resolve(r"~/Drops", &carol, &win()).unwrap(),
            p(r"C:\Users\carol\Drops")
        );
        assert_eq!(
            resolve(r"~\Drops\in", &alice(), &win()).unwrap(),
            p(r"C:\Users\alice\Drops\in")
        );
        assert_eq!(
            resolve("~", &alice(), &win()).unwrap(),
            p(r"C:\Users\alice")
        );
        assert_eq!(
            resolve("~/drops", &bob(), &nix()).unwrap(),
            p("/home/bob/drops")
        );
        let dave = Writer::unprivileged(Some("/home/dave/".into()));
        assert_eq!(
            resolve("~/drops", &dave, &nix()).unwrap(),
            p("/home/dave/drops")
        );
    }

    #[test]
    fn tilde_without_an_active_home_is_refused() {
        let nobody = Writer::unprivileged(None);
        let err = resolve("~/Drops", &nobody, &win()).unwrap_err();
        assert!(err.contains("active user profile"), "{err}");
        // A profile that is not itself absolute cannot anchor anything.
        let odd = Writer::unprivileged(Some("relative".into()));
        assert!(resolve("~/Drops", &odd, &win()).is_err());
        // An absolute path needs no home at all for an unprivileged writer.
        assert!(resolve(r"D:\drops", &nobody, &win()).is_ok());
    }

    /// The security rule: when SYSTEM/root writes, the folder must be inside
    /// the ACTIVE user's profile. The LocalAPI admits interactive non-admin
    /// users, so without this a non-admin could make SYSTEM write
    /// remote-supplied files anywhere the system roots do not cover.
    #[test]
    fn system_context_rejects_outside_profile() {
        let sys = system_for_alice();
        for bad in [
            r"C:\Windows\Temp",
            r"D:\Drops",
            r"C:\Users\bob\Drops",
            r"C:\Users",
            r"C:\ProgramData\roomler\drops",
            r"\\nas\public\drops",
        ] {
            let err = resolve(bad, &sys, &win()).unwrap_err();
            assert!(
                err.contains("outside") || err.contains("must not be under"),
                "{bad:?}: {err}"
            );
        }
        assert_eq!(
            resolve(r"C:\Users\alice\Drops", &sys, &win()).unwrap(),
            p(r"C:\Users\alice\Drops")
        );
        assert_eq!(
            resolve(r"C:\Users\alice", &sys, &win()).unwrap(),
            p(r"C:\Users\alice"),
            "the profile itself is inside the profile"
        );
        assert_eq!(
            resolve("~/Drops", &sys, &win()).unwrap(),
            p(r"C:\Users\alice\Drops")
        );
        // SYSTEM with nobody logged in: nothing is inside a profile that
        // does not exist — refuse, never guess.
        let sys_nobody = Writer {
            privileged: true,
            active_home: None,
        };
        let err = resolve(r"C:\Users\alice\Drops", &sys_nobody, &win()).unwrap_err();
        assert!(err.contains("no active user profile"), "{err}");

        // root on Unix, same rule against the home it knows.
        let root = root_on_bobs_box();
        assert!(resolve("/srv/drops", &root, &nix()).is_err());
        assert!(resolve("/home/carol/drops", &root, &nix()).is_err());
        assert_eq!(
            resolve("/home/bob/drops", &root, &nix()).unwrap(),
            p("/home/bob/drops")
        );
        assert_eq!(
            resolve("~/drops", &root, &nix()).unwrap(),
            p("/home/bob/drops")
        );
    }

    #[test]
    fn comparison_is_case_and_separator_insensitive_on_windows_only() {
        let sys = Writer {
            privileged: true,
            active_home: Some(r"C:\Users\Alice".into()),
        };
        assert!(resolve("c:/users/ALICE/drops", &sys, &win()).is_ok());
        let root = Writer {
            privileged: true,
            active_home: Some("/home/bob".into()),
        };
        assert!(
            resolve("/home/Bob/drops", &root, &nix()).is_err(),
            "Unix paths are case-sensitive: /home/Bob is another directory"
        );
        // A user's profile that merely STARTS with the active one's name.
        assert!(resolve(r"C:\Users\alice2\drops", &system_for_alice(), &win()).is_err());
    }

    /// A non-ASCII folder name is ONE component. The first version split on
    /// `c as u8`, which truncates a char: `į` (U+012F) became `/` and `Ŝ`
    /// (U+015C) became `\`, so `C:\Users\alice\Dįr` resolved to
    /// `C:\Users\alice\D\r` — a drop into the wrong folder, and a profile
    /// named with such a letter compared as a different path.
    #[test]
    fn non_ascii_folder_names_stay_one_component() {
        assert_eq!(
            resolve(r"C:\Users\alice\Dįr\Ŝx", &alice(), &win()).unwrap(),
            p(r"C:\Users\alice\Dįr\Ŝx")
        );
        assert_eq!(
            resolve(r"\\nas\Dįr\x", &alice(), &win()).unwrap(),
            p(r"\\nas\Dįr\x"),
            "the share name too"
        );
        assert_eq!(
            resolve("/home/bob/Dįr/Ŝx", &bob(), &nix()).unwrap(),
            p("/home/bob/Dįr/Ŝx")
        );
        // The profile rule compares the same components, whatever script
        // the user's name is written in.
        let sys = Writer {
            privileged: true,
            active_home: Some(r"C:\Users\Łukasz".into()),
        };
        assert_eq!(
            resolve("~/Pobrane", &sys, &win()).unwrap(),
            p(r"C:\Users\Łukasz\Pobrane")
        );
        assert!(resolve(r"C:\Users\Łukasz\Pobrane", &sys, &win()).is_ok());
        assert!(resolve(r"C:\Users\Łukaszį\x", &sys, &win()).is_err());
    }

    /// Win32 strips trailing dots and spaces from a component, so
    /// `C:\Windows.\Temp` IS `C:\Windows\Temp` — a spelling the string
    /// comparison would call "not under C:\Windows". `name:stream` is an
    /// alternate data stream. None of these is a folder name the checks can
    /// reason about, so all are refused — on Windows rules only.
    #[test]
    fn windows_components_the_os_would_rewrite_are_refused() {
        for bad in [
            r"C:\Windows.\Temp",
            r"C:\Windows \Temp",
            r"C:\Users\alice\Drops.",
            // (A trailing space at the very END is input whitespace, trimmed
            // like every surface value; inside the path it is a component.)
            r"C:\Users\alice\Drops \in",
            r"C:\Users\alice\Drops:hidden",
            r"C:\Users\alice\a*b",
            r"C:\Users\alice\a?b",
            r"C:\Users\alice\a|b",
            r"~\Drops.",
            r"\\nas.\share\x",
            r"\\nas\share.\x",
        ] {
            let err = resolve(bad, &alice(), &win()).unwrap_err();
            assert!(
                err.contains("strips") || err.contains("cannot"),
                "{bad:?}: {err}"
            );
        }
        // The SYSTEM writer: the rewritten spelling must not pass as "inside
        // the profile" either.
        assert!(resolve(r"C:\Users\alice.\Drops", &system_for_alice(), &win()).is_err());
        // Unix has no such rewriting: a trailing dot is part of the name.
        assert_eq!(
            resolve("/home/bob/drops.", &bob(), &nix()).unwrap(),
            p("/home/bob/drops.")
        );
    }

    /// A path whose existing part the OS would not resolve: a SYSTEM/root
    /// writer cannot see where it really goes, so it is refused; an
    /// unprivileged writer is not (the OS enforces its rights on the write).
    #[test]
    fn an_unresolvable_path_is_refused_only_for_a_privileged_writer() {
        let e = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let path = Path::new(r"C:\Users\alice\Drops");
        let err = unresolvable_verdict(path, &e, &system_for_alice()).unwrap_err();
        assert!(err.contains("cannot tell where"), "{err}");
        assert!(unresolvable_verdict(path, &e, &alice()).is_ok());
    }

    #[test]
    fn tilde_form_respells_only_what_is_inside_home() {
        let home = r"C:\Users\Alice";
        assert_eq!(
            tilde_form(r"C:\Users\Alice\Desktop\Drops", home, &win()).as_deref(),
            Some(r"~\Desktop\Drops")
        );
        assert_eq!(
            tilde_form(r"c:/users/alice/Desktop", home, &win()).as_deref(),
            Some(r"~\Desktop"),
            "Windows compares case- and separator-insensitively, keeps the picked spelling"
        );
        assert_eq!(
            tilde_form(r"C:\Users\Alice", home, &win()).as_deref(),
            Some("~")
        );
        assert_eq!(
            tilde_form(r"C:\Users\Alice2\x", home, &win()),
            None,
            "a sibling"
        );
        assert_eq!(tilde_form(r"D:\Drops", home, &win()), None);
        assert_eq!(tilde_form(r"\\nas\share\x", home, &win()), None);
        assert_eq!(tilde_form("~/x", home, &win()), None, "already relative");
        assert_eq!(
            tilde_form("/home/bob/in/box", "/home/bob", &nix()).as_deref(),
            Some("~/in/box")
        );
        assert_eq!(tilde_form("/home/Bob/in", "/home/bob", &nix()), None);
        // The re-spelled value resolves back to the picked folder.
        let back = resolve(
            &tilde_form(r"C:\Users\Alice\Desktop\Drops", home, &win()).unwrap(),
            &Writer::unprivileged(Some(home.into())),
            &win(),
        )
        .unwrap();
        assert_eq!(back, p(r"C:\Users\Alice\Desktop\Drops"));
    }

    #[test]
    fn check_shape_accepts_tilde_without_a_home_and_refuses_bad_shapes() {
        assert!(check_shape("~/Drops", &win()).is_ok());
        assert!(check_shape("~", &win()).is_ok());
        assert!(check_shape(r"D:\drops", &win()).is_ok());
        assert!(check_shape("~/../x", &win()).is_err());
        assert!(check_shape("drops", &win()).is_err());
        assert!(check_shape(r"\\?\GLOBALROOT\x", &win()).is_err());
        assert!(check_shape(r"\\host\C$\x", &win()).is_err());
        assert!(check_shape("/srv/drops", &nix()).is_ok());
        assert!(check_shape("srv/drops", &nix()).is_err());
        // The system roots need no identity, so the shape check refuses
        // them too — the surface never stores a value the daemon would
        // refuse for a reason it could already see.
        assert!(check_shape(r"C:\Windows\Temp", &win()).is_err());
        assert!(check_shape("/etc/meshharbor", &nix()).is_err());
    }

    #[test]
    fn from_env_rules_match_the_host() {
        let r = Rules::from_env();
        assert_eq!(r.windows, cfg!(windows));
        assert!(!r.denied_roots.is_empty());
        if cfg!(windows) {
            assert!(
                r.denied_roots
                    .iter()
                    .any(|d| d.to_ascii_lowercase().ends_with("windows"))
            );
            assert!(
                r.denied_roots
                    .iter()
                    .any(|d| d.to_ascii_lowercase().contains("program files"))
            );
        } else {
            assert!(r.denied_roots.iter().any(|d| d == "/etc"));
        }
    }

    // ---- on disk -----------------------------------------------------------

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "roomler-files-dir-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn creatable_and_writable_folder_passes_and_leaves_no_probe() {
        let root = scratch("ok");
        let target = root.join("a").join("b").join("drops");
        let raw = target.to_string_lossy().into_owned();
        let rules = Rules::from_env();
        // Unprivileged: creatable + writable is all that is asked.
        let got = validate(&raw, &Writer::unprivileged(None), &rules).unwrap();
        assert!(got.is_dir(), "{got:?} must have been created");
        assert_eq!(
            std::fs::read_dir(&got).unwrap().count(),
            0,
            "the write probe must be removed"
        );
        // Privileged, with the scratch root as the active profile: inside
        // it, so it passes.
        let sys = Writer {
            privileged: true,
            active_home: Some(root.to_string_lossy().into_owned()),
        };
        assert!(validate(&raw, &sys, &rules).is_ok());
        // …and a sibling of the profile does not.
        let other = scratch("other");
        let err = validate(&other.to_string_lossy(), &sys, &rules).unwrap_err();
        assert!(err.contains("outside"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&other);
    }

    #[test]
    fn check_creatable_looks_without_touching() {
        let root = scratch("creatable");
        let missing = root.join("a").join("b");
        assert!(
            check_creatable(&missing).is_ok(),
            "creatable under a folder"
        );
        assert!(!root.join("a").exists(), "and nothing was created");
        assert!(check_creatable(&root).is_ok(), "an existing folder");
        let file = root.join("f");
        std::fs::write(&file, b"x").unwrap();
        let err = check_creatable(&file).unwrap_err();
        assert!(err.contains("not a folder"), "{err}");
        let err = check_creatable(&file.join("under")).unwrap_err();
        assert!(err.contains("not a folder"), "a file on the way: {err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_in_the_way_is_refused() {
        let root = scratch("file");
        let file = root.join("not-a-folder");
        std::fs::write(&file, b"x").unwrap();
        let err = validate(
            &file.to_string_lossy(),
            &Writer::unprivileged(None),
            &Rules::from_env(),
        )
        .unwrap_err();
        assert!(err.contains("not a folder"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A link INSIDE the profile pointing OUTSIDE it must not launder the
    /// destination past the profile rule.
    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_profile_is_caught() {
        let root = scratch("link");
        let home = root.join("home");
        let outside = root.join("outside");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, home.join("link")).unwrap();
        let sys = Writer {
            privileged: true,
            active_home: Some(home.to_string_lossy().into_owned()),
        };
        let raw = home
            .join("link")
            .join("drops")
            .to_string_lossy()
            .into_owned();
        // Shape + placement alone cannot see the link…
        assert!(resolve(&raw, &sys, &Rules::from_env()).is_ok());
        // …the on-disk check can.
        let err = validate(&raw, &sys, &Rules::from_env()).unwrap_err();
        assert!(err.contains("resolves through a link"), "{err}");
        assert!(
            !outside.join("drops").exists(),
            "nothing may be created on the far side of the link"
        );
        // A plain folder inside the same profile is fine.
        assert!(
            validate(
                &home.join("drops").to_string_lossy(),
                &sys,
                &Rules::from_env()
            )
            .is_ok()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strip_verbatim_only_touches_windows_verbatim_prefixes() {
        assert_eq!(strip_verbatim(p(r"\\?\C:\x")), p(r"C:\x"));
        assert_eq!(
            strip_verbatim(p(r"\\?\UNC\host\share\x")),
            p(r"\\host\share\x")
        );
        assert_eq!(strip_verbatim(p("/home/bob")), p("/home/bob"));
        assert_eq!(strip_verbatim(p(r"C:\x")), p(r"C:\x"));
    }
}
